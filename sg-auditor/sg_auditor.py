#!/usr/bin/env python3
"""Security Group Auditor — Audit EC2 security groups for risky and unused rules.

Read-only. Flags ingress rules open to the world (0.0.0.0/0 or ::/0) on sensitive
ports (SSH/RDP/databases), all-traffic-open rules, and security groups that no
network interface uses (and that no other SG references) — the classic forgotten
SG. Maps SG → ENI usage via describe_network_interfaces.

Conventions (shared across the toolkit):
  - read-only; remediation would emit Terraform/CLI, never mutate live state
  - severity model LOW/MEDIUM/HIGH/CRITICAL + --fail-on (exit code 3 when met)
  - --format text|json
  - adaptive-retry botocore Config; every describe_* call is paginated
  - logic lives in pure methods (SecurityGroupAuditor.audit) for offline testing
"""

import argparse
import json
import sys

import boto3
from botocore.config import Config

# Adaptive retries so large accounts don't fail on throttling.
RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}

# Sensitive ports → (human label, severity when exposed to the world).
SENSITIVE_PORTS = {
    22: ("SSH", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    3306: ("MySQL/Aurora", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    1433: ("MSSQL", "HIGH"),
    1521: ("Oracle", "HIGH"),
    5439: ("Redshift", "HIGH"),
    27017: ("MongoDB", "HIGH"),
    6379: ("Redis", "HIGH"),
    11211: ("Memcached", "HIGH"),
    9200: ("Elasticsearch", "HIGH"),
    2049: ("NFS", "HIGH"),
    5985: ("WinRM-HTTP", "HIGH"),
    5986: ("WinRM-HTTPS", "HIGH"),
}

# Ports where world exposure is common/acceptable (public web). Noted, not alarming.
WEB_PORTS = {80, 443}

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


class SecurityGroupAuditor:
    """Fetches EC2 security groups + ENIs and classifies risky/unused rules.

    Fetching (fetch_*) is separated from classification (audit) so the logic can
    be unit-tested with fake data and no AWS calls.
    """

    def __init__(self, session=None):
        sess = session or boto3.Session()
        self.ec2 = sess.client("ec2", config=RETRY_CONFIG)

    # ── Fetching (paginated) ────────────────────────────────────────────────
    def fetch_security_groups(self) -> list:
        groups = []
        paginator = self.ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            groups.extend(page.get("SecurityGroups", []))
        return groups

    def fetch_network_interfaces(self) -> list:
        enis = []
        paginator = self.ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            enis.extend(page.get("NetworkInterfaces", []))
        return enis

    # ── Classification (pure — unit tested) ─────────────────────────────────
    @staticmethod
    def _ports_in_rule(perm: dict):
        """Yield individual sensitive ports a rule covers, or 'ALL' if all-ports.

        Returns a tuple (is_all_ports, set_of_sensitive_ports_covered).
        """
        proto = str(perm.get("IpProtocol", "-1"))
        # "-1" means all protocols / all ports.
        if proto == "-1":
            return True, set()

        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        # Missing port bounds on tcp/udp effectively means the full range.
        if from_port is None or to_port is None:
            return True, set()
        if from_port == 0 and to_port == 65535:
            return True, set()

        covered = {p for p in SENSITIVE_PORTS if from_port <= p <= to_port}
        return False, covered

    @staticmethod
    def _world_open(perm: dict) -> bool:
        for r in perm.get("IpRanges", []):
            if r.get("CidrIp") in WORLD_CIDRS:
                return True
        for r in perm.get("Ipv6Ranges", []):
            if r.get("CidrIpv6") in WORLD_CIDRS:
                return True
        return False

    @classmethod
    def _classify_ingress(cls, sg: dict) -> list:
        """Return findings for a single SG's ingress permissions."""
        findings = []
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")

        for perm in sg.get("IpPermissions", []):
            if not cls._world_open(perm):
                continue  # only world-open ingress is in scope here

            is_all, sensitive = cls._ports_in_rule(perm)

            if is_all:
                findings.append({
                    "severity": "CRITICAL",
                    "type": "WORLD_OPEN_ALL_PORTS",
                    "group_id": sg_id,
                    "group_name": sg_name,
                    "detail": "All ports/protocols open to 0.0.0.0/0 (or ::/0)",
                })
                continue

            if sensitive:
                for port in sorted(sensitive):
                    label, sev = SENSITIVE_PORTS[port]
                    findings.append({
                        "severity": sev,
                        "type": "WORLD_OPEN_SENSITIVE_PORT",
                        "group_id": sg_id,
                        "group_name": sg_name,
                        "port": port,
                        "detail": f"{label} (port {port}) open to the world",
                    })
            else:
                # World-open on a non-sensitive port. Web ports are informational;
                # anything else is a medium over-broad rule.
                fp, tp = perm.get("FromPort"), perm.get("ToPort")
                only_web = fp == tp and fp in WEB_PORTS
                findings.append({
                    "severity": "LOW" if only_web else "MEDIUM",
                    "type": "WORLD_OPEN_PORT",
                    "group_id": sg_id,
                    "group_name": sg_name,
                    "port": fp,
                    "detail": f"Port range {fp}-{tp} open to the world",
                })
        return findings

    @staticmethod
    def _used_group_ids(network_interfaces: list) -> set:
        used = set()
        for eni in network_interfaces:
            for g in eni.get("Groups", []):
                if g.get("GroupId"):
                    used.add(g["GroupId"])
        return used

    @staticmethod
    def _referenced_group_ids(security_groups: list) -> set:
        """SG IDs referenced by other SGs' rules (ingress + egress)."""
        referenced = set()
        for sg in security_groups:
            for direction in ("IpPermissions", "IpPermissionsEgress"):
                for perm in sg.get(direction, []):
                    for pair in perm.get("UserIdGroupPairs", []):
                        if pair.get("GroupId"):
                            referenced.add(pair["GroupId"])
        return referenced

    @classmethod
    def audit(cls, security_groups: list, network_interfaces: list) -> list:
        """Classify all findings across the given SGs + ENIs. Pure function."""
        findings = []

        # Risky world-open ingress rules.
        for sg in security_groups:
            findings.extend(cls._classify_ingress(sg))

        # Unused / unattached security groups.
        used = cls._used_group_ids(network_interfaces)
        referenced = cls._referenced_group_ids(security_groups)
        for sg in security_groups:
            sg_id = sg.get("GroupId", "")
            # The 'default' SG always exists and can't be deleted — don't nag.
            if sg.get("GroupName") == "default":
                continue
            if sg_id not in used and sg_id not in referenced:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "UNUSED_SECURITY_GROUP",
                    "group_id": sg_id,
                    "group_name": sg.get("GroupName", ""),
                    "detail": "Security group is attached to no ENI and referenced by no other SG",
                })

        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["group_id"]))
        return findings


def _print_text(findings: list) -> None:
    if not findings:
        print("✓ No risky or unused security-group findings.")
        return
    print(f"\n⚠️  {len(findings)} security-group finding(s):\n")
    for f in findings:
        icon = SEVERITY_ICON[f["severity"]]
        name = f.get("group_name", "")
        label = f"{f['group_id']}" + (f" ({name})" if name else "")
        print(f"  {icon} [{f['severity']}] {f['type']}: {label}")
        print(f"       └─ {f['detail']}")


def main():
    parser = argparse.ArgumentParser(
        description="Security Group Auditor — flag world-open and unused security groups.")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                        help="Exit with code 3 if any finding meets or exceeds this severity "
                             "(for CI gating). Default: never fail on findings.")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    auditor = SecurityGroupAuditor(session)
    try:
        groups = auditor.fetch_security_groups()
        enis = auditor.fetch_network_interfaces()
    except Exception as e:  # noqa: BLE001 — surface AWS/client errors cleanly
        print(f"Error querying EC2: {e}", file=sys.stderr)
        sys.exit(1)

    findings = SecurityGroupAuditor.audit(groups, enis)

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
