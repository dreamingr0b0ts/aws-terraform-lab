#!/usr/bin/env python3
"""IMDS Inspector — Find EC2 instances that still allow IMDSv1 (token-optional).

IMDSv1 is the SSRF → credential-theft vector: a server-side request forgery bug
in an app can reach 169.254.169.254 and read the instance's IAM role credentials
without a session token. IMDSv2 (HttpTokens=required) closes it. This tool flags
running instances whose metadata service still accepts v1, and scores each by
blast radius (an instance with an IAM role AND a public IP is the worst case).

Conventions (shared across the toolkit):
  - read-only; remediation emits CLI, never mutates live state
  - severity model LOW/MEDIUM/HIGH/CRITICAL + --fail-on (exit code 3 when met)
  - --format text|json
  - adaptive-retry botocore Config; describe_instances is paginated
  - logic lives in pure methods (IMDSInspector.audit) for offline testing
"""

import argparse
import json
import sys

import boto3
from botocore.config import Config

RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

# Instance states worth auditing (don't nag about terminated/shutting-down).
LIVE_STATES = {"running", "stopped", "stopping", "pending"}


class IMDSInspector:
    """Fetches EC2 instances and flags IMDSv1-permitting metadata configs.

    Fetching is separated from classification (audit) so logic can be tested
    with fake data and no AWS calls.
    """

    def __init__(self, session=None):
        sess = session or boto3.Session()
        self.ec2 = sess.client("ec2", config=RETRY_CONFIG)

    # ── Fetching (paginated) ────────────────────────────────────────────────
    def fetch_instances(self) -> list:
        """Flatten all reservations into a list of instance dicts."""
        instances = []
        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
        return instances

    # ── Classification (pure — unit tested) ─────────────────────────────────
    @staticmethod
    def _name_tag(instance: dict) -> str:
        for t in instance.get("Tags", []):
            if t.get("Key") == "Name":
                return t.get("Value", "")
        return ""

    @staticmethod
    def _imdsv1_allowed(meta: dict) -> bool:
        """True if the metadata endpoint is on AND v1 (no-token) is accepted."""
        endpoint = meta.get("HttpEndpoint", "enabled")
        tokens = meta.get("HttpTokens", "optional")
        return endpoint == "enabled" and tokens == "optional"

    @classmethod
    def _severity(cls, has_role: bool, has_public_ip: bool) -> str:
        """Score IMDSv1 exposure by blast radius."""
        if has_role and has_public_ip:
            return "CRITICAL"  # public-facing app + harvestable role creds
        if has_role:
            return "HIGH"      # role creds reachable via SSRF from inside
        if has_public_ip:
            return "MEDIUM"    # public, but no creds to steal yet
        return "LOW"           # internal, no role — still a latent risk

    @classmethod
    def audit(cls, instances: list) -> list:
        """Return IMDSv1 findings for the given instances. Pure function."""
        findings = []
        for inst in instances:
            state = inst.get("State", {}).get("Name", "")
            if state not in LIVE_STATES:
                continue

            meta = inst.get("MetadataOptions", {})
            if not cls._imdsv1_allowed(meta):
                continue  # IMDSv2 enforced or endpoint disabled → fine

            has_role = bool(inst.get("IamInstanceProfile"))
            has_public_ip = bool(inst.get("PublicIpAddress"))
            severity = cls._severity(has_role, has_public_ip)

            instance_id = inst.get("InstanceId", "")
            findings.append({
                "severity": severity,
                "type": "IMDSV1_ALLOWED",
                "instance_id": instance_id,
                "name": cls._name_tag(inst),
                "state": state,
                "has_iam_role": has_role,
                "has_public_ip": has_public_ip,
                "http_tokens": meta.get("HttpTokens", "optional"),
                "hop_limit": meta.get("HttpPutResponseHopLimit"),
                "detail": "IMDSv1 (token-optional) permitted — SSRF credential-theft vector",
                "remediation": (
                    f"aws ec2 modify-instance-metadata-options --instance-id {instance_id} "
                    f"--http-tokens required --http-endpoint enabled"
                ),
            })

        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["instance_id"]))
        return findings


def _print_text(findings: list) -> None:
    if not findings:
        print("✓ No IMDSv1-permitting instances found. All metadata services enforce IMDSv2.")
        return
    print(f"\n⚠️  {len(findings)} instance(s) allow IMDSv1:\n")
    for f in findings:
        icon = SEVERITY_ICON[f["severity"]]
        name = f.get("name", "")
        label = f["instance_id"] + (f" ({name})" if name else "")
        flags = []
        if f["has_iam_role"]:
            flags.append("IAM role")
        if f["has_public_ip"]:
            flags.append("public IP")
        suffix = f" [{', '.join(flags)}]" if flags else ""
        print(f"  {icon} [{f['severity']}] {label}{suffix}")
        print(f"       └─ {f['detail']}")
        print(f"          fix: {f['remediation']}")


def main():
    parser = argparse.ArgumentParser(
        description="IMDS Inspector — find EC2 instances that still allow IMDSv1.")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                        help="Exit with code 3 if any finding meets or exceeds this severity "
                             "(for CI gating). Default: never fail on findings.")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    inspector = IMDSInspector(session)
    try:
        instances = inspector.fetch_instances()
    except Exception as e:  # noqa: BLE001 — surface AWS/client errors cleanly
        print(f"Error querying EC2: {e}", file=sys.stderr)
        sys.exit(1)

    findings = IMDSInspector.audit(instances)

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
