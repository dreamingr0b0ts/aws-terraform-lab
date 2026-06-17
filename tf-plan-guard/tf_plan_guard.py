#!/usr/bin/env python3
"""Terraform Plan Guard — Fail CI on risky EC2/SG changes before `terraform apply`.

Parses the JSON form of a Terraform plan (`terraform show -json plan.tfplan`) and
flags risky create/update changes *before* they reach AWS:

  - a security group opening a sensitive port to 0.0.0.0/0 (or ::/0)
  - an EBS volume / root device with encryption disabled
  - an instance / launch template that allows IMDSv1 (http_tokens != "required")
  - an instance getting a public IP

No AWS calls and no third-party deps — pure standard library, so it runs anywhere
in CI. Reads the plan from a file (--plan-file) or stdin.

Conventions (shared across the toolkit):
  - severity model LOW/MEDIUM/HIGH/CRITICAL + --fail-on (exit code 3 when met)
  - --format text|json
  - logic lives in pure methods (PlanGuard.analyze) for offline testing
"""

import argparse
import json
import sys

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}

# Sensitive ports → (label, severity) when opened to the world.
SENSITIVE_PORTS = {
    22: ("SSH", "CRITICAL"), 3389: ("RDP", "CRITICAL"),
    3306: ("MySQL", "HIGH"), 5432: ("PostgreSQL", "HIGH"), 1433: ("MSSQL", "HIGH"),
    1521: ("Oracle", "HIGH"), 5439: ("Redshift", "HIGH"), 27017: ("MongoDB", "HIGH"),
    6379: ("Redis", "HIGH"), 11211: ("Memcached", "HIGH"), 9200: ("Elasticsearch", "HIGH"),
    2049: ("NFS", "HIGH"),
}
WEB_PORTS = {80, 443}

# Change actions that introduce/keep a configuration (worth inspecting).
ACTIVE_ACTIONS = {"create", "update"}


def _ensure_list(value):
    """Terraform nested blocks decode as a list (or sometimes a single dict)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class PlanGuard:
    """Pure analyzer over a parsed `terraform show -json` document."""

    # ── Port helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _classify_ports(from_port, to_port, protocol):
        """Return (all_ports, list_of_(port,label,severity)) for a world-open rule."""
        proto = str(protocol).lower() if protocol is not None else "-1"
        if proto in ("-1", "all"):
            return True, []
        if from_port is None or to_port is None:
            return True, []
        try:
            fp, tp = int(from_port), int(to_port)
        except (TypeError, ValueError):
            return True, []
        if fp == 0 and tp == 65535:
            return True, []
        out = [(p, *SENSITIVE_PORTS[p]) for p in SENSITIVE_PORTS if fp <= p <= tp]
        # Track non-sensitive web exposure too: a single web port (80/443) open
        # to the world is informational (LOW), not a sensitive-port finding.
        if fp == tp and fp in WEB_PORTS:
            out.append((fp, "web", "LOW"))
        return False, out

    @classmethod
    def _world_rule_findings(cls, address, from_port, to_port, protocol, cidrs):
        if not any(c in WORLD_CIDRS for c in cidrs):
            return []
        all_ports, ports = cls._classify_ports(from_port, to_port, protocol)
        if all_ports:
            return [{
                "severity": "CRITICAL", "type": "SG_WORLD_OPEN_ALL_PORTS", "address": address,
                "detail": "Plan opens ALL ports/protocols to the world",
            }]
        findings = []
        for port, label, sev in ports:
            findings.append({
                "severity": sev, "type": "SG_WORLD_OPEN_PORT", "address": address,
                "port": port, "detail": f"Plan opens {label} (port {port}) to the world",
            })
        if not ports:
            findings.append({
                "severity": "MEDIUM", "type": "SG_WORLD_OPEN_PORT", "address": address,
                "detail": f"Plan opens port {from_port}-{to_port} to the world",
            })
        return findings

    # ── Per-resource-type checks ───────────────────────────────────────────────
    @classmethod
    def _check_sg_modern_rule(cls, address, after):
        """aws_vpc_security_group_ingress_rule."""
        cidrs = [c for c in (after.get("cidr_ipv4"), after.get("cidr_ipv6")) if c]
        return cls._world_rule_findings(
            address, after.get("from_port"), after.get("to_port"),
            after.get("ip_protocol"), cidrs)

    @classmethod
    def _check_security_group(cls, address, after):
        """aws_security_group with inline ingress blocks."""
        findings = []
        for rule in _ensure_list(after.get("ingress")):
            cidrs = (rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or [])
            findings += cls._world_rule_findings(
                address, rule.get("from_port"), rule.get("to_port"),
                rule.get("protocol"), cidrs)
        return findings

    @classmethod
    def _check_security_group_rule(cls, address, after):
        """aws_security_group_rule (legacy standalone)."""
        if after.get("type") != "ingress":
            return []
        cidrs = (after.get("cidr_blocks") or []) + (after.get("ipv6_cidr_blocks") or [])
        return cls._world_rule_findings(
            address, after.get("from_port"), after.get("to_port"),
            after.get("protocol"), cidrs)

    @staticmethod
    def _imdsv1_findings(address, after):
        findings = []
        for meta in _ensure_list(after.get("metadata_options")):
            endpoint = meta.get("http_endpoint", "enabled")
            tokens = meta.get("http_tokens", "optional")
            if endpoint != "disabled" and tokens != "required":
                findings.append({
                    "severity": "HIGH", "type": "IMDSV1_ALLOWED", "address": address,
                    "detail": f"Plan sets http_tokens='{tokens}' (IMDSv1 allowed) — require IMDSv2",
                })
        return findings

    @staticmethod
    def _unencrypted_block_findings(address, blocks, what):
        findings = []
        for blk in blocks:
            if blk.get("encrypted") is False:
                findings.append({
                    "severity": "HIGH", "type": "EBS_UNENCRYPTED", "address": address,
                    "detail": f"Plan creates an unencrypted {what}",
                })
        return findings

    @classmethod
    def _check_instance(cls, address, after):
        findings = []
        findings += cls._imdsv1_findings(address, after)
        findings += cls._unencrypted_block_findings(
            address, _ensure_list(after.get("root_block_device")), "root volume")
        findings += cls._unencrypted_block_findings(
            address, _ensure_list(after.get("ebs_block_device")), "EBS block device")
        if after.get("associate_public_ip_address") is True:
            findings.append({
                "severity": "LOW", "type": "PUBLIC_IP_ASSIGNED", "address": address,
                "detail": "Plan assigns a public IP to the instance",
            })
        return findings

    @classmethod
    def _check_launch_template(cls, address, after):
        findings = []
        findings += cls._imdsv1_findings(address, after)
        for bdm in _ensure_list(after.get("block_device_mappings")):
            findings += cls._unencrypted_block_findings(
                address, _ensure_list(bdm.get("ebs")), "EBS device in launch template")
        return findings

    @classmethod
    def _check_ebs_volume(cls, address, after):
        # A standalone aws_ebs_volume defaults to UNENCRYPTED when `encrypted` is
        # omitted, so treat a missing key the same as an explicit false. (Inline
        # instance/launch-template blocks keep the stricter explicit-false check,
        # where plan JSON reliably materializes the attribute.)
        if after.get("encrypted") is False or "encrypted" not in after:
            return [{
                "severity": "HIGH", "type": "EBS_UNENCRYPTED", "address": address,
                "detail": "Plan creates an unencrypted EBS volume",
            }]
        return []

    _DISPATCH = {
        "aws_vpc_security_group_ingress_rule": "_check_sg_modern_rule",
        "aws_security_group": "_check_security_group",
        "aws_security_group_rule": "_check_security_group_rule",
        "aws_instance": "_check_instance",
        "aws_launch_template": "_check_launch_template",
        "aws_ebs_volume": "_check_ebs_volume",
    }

    @classmethod
    def analyze(cls, plan: dict) -> list:
        """Return findings for all risky create/update changes in the plan. Pure."""
        findings = []
        for rc in plan.get("resource_changes", []):
            change = rc.get("change", {})
            actions = set(change.get("actions", []))
            if not (actions & ACTIVE_ACTIONS):
                continue  # delete / no-op — nothing risky being introduced
            after = change.get("after") or {}
            handler = cls._DISPATCH.get(rc.get("type"))
            if not handler:
                continue
            for f in getattr(cls, handler)(rc.get("address", ""), after):
                f.setdefault("resource_type", rc.get("type"))
                findings.append(f)

        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["address"]))
        return findings


def _load_plan(path):
    if path in (None, "-"):
        raw = sys.stdin.read()
    else:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    return json.loads(raw)


def _print_text(findings: list) -> None:
    if not findings:
        print("✓ No risky EC2/SG changes in the plan.")
        return
    print(f"\n⚠️  {len(findings)} risky change(s) in the plan:\n")
    for f in findings:
        icon = SEVERITY_ICON[f["severity"]]
        print(f"  {icon} [{f['severity']}] {f['type']}: {f['address']}")
        print(f"       └─ {f['detail']}")


def main():
    parser = argparse.ArgumentParser(
        description="Terraform Plan Guard — gate risky EC2/SG changes before apply.")
    parser.add_argument("--plan-file", "-f", default="-",
                        help="Path to `terraform show -json` output (default: stdin)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                        help="Exit with code 3 if any finding meets or exceeds this severity.")
    args = parser.parse_args()

    try:
        plan = _load_plan(args.plan_file)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error reading plan JSON: {e}", file=sys.stderr)
        sys.exit(1)

    findings = PlanGuard.analyze(plan)

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
