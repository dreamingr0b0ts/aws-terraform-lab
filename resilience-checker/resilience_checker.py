#!/usr/bin/env python3
"""Resilience Checker — Flag single-AZ Auto Scaling Groups and health-check gaps.

Read-only reliability analyzer over Auto Scaling Groups and their load-balancer
target health. Flags:
  - SINGLE_AZ_ASG: an ASG spanning fewer than 2 AZs (an AZ outage = full outage)
  - NO_REDUNDANCY: desired capacity < 2 (a single instance, no spare)
  - LB_HEALTH_CHECK_DISABLED: ASG behind an LB but using EC2-only health checks
    (won't replace an instance whose app is broken but whose VM is up)
  - UNHEALTHY_TARGET: registered targets failing their load-balancer health check

Conventions (shared across the toolkit):
  - read-only; remediation emits CLI, never mutates live state
  - severity model LOW/MEDIUM/HIGH/CRITICAL + --fail-on (exit code 3 when met)
  - --format text|json
  - adaptive-retry botocore Config; describe_auto_scaling_groups is paginated
  - logic lives in pure methods (ResilienceChecker.audit) for offline testing
"""

import argparse
import json
import sys

import boto3
from botocore.config import Config

RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

HEALTHY = "healthy"


class ResilienceChecker:
    """Fetches ASGs + target health and flags reliability gaps.

    Fetching is separated from classification (audit) so logic is unit-testable.
    """

    def __init__(self, session=None):
        sess = session or boto3.Session()
        self.asg = sess.client("autoscaling", config=RETRY_CONFIG)
        self.elbv2 = sess.client("elbv2", config=RETRY_CONFIG)

    # ── Fetching ────────────────────────────────────────────────────────────
    def fetch_asgs(self) -> list:
        out = []
        for page in self.asg.get_paginator("describe_auto_scaling_groups").paginate():
            out.extend(page.get("AutoScalingGroups", []))
        return out

    def fetch_target_health(self, target_group_arns) -> list:
        """Return [{target_group_arn, descriptions:[...]}] for each TG ARN."""
        out = []
        for arn in sorted(set(target_group_arns)):
            resp = self.elbv2.describe_target_health(TargetGroupArn=arn)
            out.append({
                "target_group_arn": arn,
                "descriptions": resp.get("TargetHealthDescriptions", []),
            })
        return out

    # ── Classification (pure — unit tested) ─────────────────────────────────
    @staticmethod
    def _asg_azs(asg: dict) -> set:
        """Distinct AZs an ASG is configured to span."""
        azs = set(asg.get("AvailabilityZones", []))
        if azs:
            return azs
        # Fall back to AZs of current instances if AZ list is empty.
        return {i.get("AvailabilityZone") for i in asg.get("Instances", []) if i.get("AvailabilityZone")}

    @staticmethod
    def _behind_lb(asg: dict) -> bool:
        return bool(asg.get("TargetGroupARNs") or asg.get("LoadBalancerNames"))

    @classmethod
    def audit_asgs(cls, asgs: list) -> list:
        findings = []
        for asg in asgs:
            name = asg.get("AutoScalingGroupName", "")
            azs = cls._asg_azs(asg)

            if len(azs) < 2:
                findings.append({
                    "severity": "HIGH", "type": "SINGLE_AZ_ASG",
                    "resource_id": name, "availability_zones": sorted(azs),
                    "detail": f"ASG spans only {len(azs)} AZ ({', '.join(sorted(azs)) or 'none'}) — "
                              "an AZ outage takes the whole group down",
                    "remediation": "Add subnets in ≥2 AZs to the ASG's VPCZoneIdentifier",
                })

            if asg.get("DesiredCapacity", 0) < 2:
                findings.append({
                    "severity": "LOW", "type": "NO_REDUNDANCY",
                    "resource_id": name,
                    "desired_capacity": asg.get("DesiredCapacity", 0),
                    "detail": "Desired capacity < 2 — no instance redundancy",
                    "remediation": "Raise min/desired capacity to ≥2 across AZs",
                })

            if cls._behind_lb(asg) and asg.get("HealthCheckType") != "ELB":
                findings.append({
                    "severity": "MEDIUM", "type": "LB_HEALTH_CHECK_DISABLED",
                    "resource_id": name,
                    "health_check_type": asg.get("HealthCheckType"),
                    "detail": "ASG is behind a load balancer but uses EC2-only health checks — "
                              "app-level failures won't trigger replacement",
                    "remediation": "Set the ASG health check type to ELB",
                })
        return findings

    @classmethod
    def audit_target_health(cls, target_health: list) -> list:
        findings = []
        for tg in target_health:
            arn = tg.get("target_group_arn", "")
            for desc in tg.get("descriptions", []):
                state = desc.get("TargetHealth", {}).get("State", "")
                if state and state != HEALTHY:
                    target = desc.get("Target", {})
                    findings.append({
                        "severity": "MEDIUM", "type": "UNHEALTHY_TARGET",
                        "resource_id": target.get("Id", ""),
                        "target_group_arn": arn,
                        "state": state,
                        "detail": f"Target {target.get('Id', '')} is '{state}' in {arn.split('/')[-2] if '/' in arn else arn}",
                        "remediation": "Investigate the target's health-check path / app status",
                    })
        return findings

    @classmethod
    def audit(cls, asgs: list, target_health=None) -> list:
        findings = cls.audit_asgs(asgs)
        findings += cls.audit_target_health(target_health or [])
        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["resource_id"]))
        return findings


def _print_text(findings: list) -> None:
    if not findings:
        print("✓ No resilience issues found.")
        return
    print(f"\n🛡️  {len(findings)} resilience finding(s):\n")
    for f in findings:
        icon = SEVERITY_ICON[f["severity"]]
        print(f"  {icon} [{f['severity']}] {f['type']}: {f['resource_id']}")
        print(f"       └─ {f['detail']}")
        print(f"          fix: {f['remediation']}")


def main():
    parser = argparse.ArgumentParser(
        description="Resilience Checker — single-AZ ASGs, health-check gaps, unhealthy targets.")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                        help="Exit with code 3 if any finding meets or exceeds this severity.")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    checker = ResilienceChecker(session)
    try:
        asgs = checker.fetch_asgs()
        tg_arns = [arn for asg in asgs for arn in asg.get("TargetGroupARNs", [])]
        target_health = checker.fetch_target_health(tg_arns) if tg_arns else []
    except Exception as e:  # noqa: BLE001 — surface AWS/client errors cleanly
        print(f"Error querying AWS: {e}", file=sys.stderr)
        sys.exit(1)

    findings = ResilienceChecker.audit(asgs, target_health)

    if args.format == "json":
        print(json.dumps({"findings": findings, "total": len(findings)}, indent=2, default=str))
    else:
        _print_text(findings)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f["severity"]] >= threshold for f in findings):
            print(f"\n✗ Findings met --fail-on {args.fail_on} threshold.", file=sys.stderr)
            sys.exit(3)


if __name__ == "__main__":
    main()
