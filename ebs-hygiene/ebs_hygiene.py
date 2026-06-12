#!/usr/bin/env python3
"""EBS Hygiene — Find unattached/unencrypted EBS volumes and stale/orphaned snapshots.

Read-only cost + resilience analyzer. Flags:
  - unencrypted volumes (data-at-rest risk)
  - unattached ("available") volumes still being billed
  - old snapshots (older than --max-snapshot-age days)
  - orphaned snapshots whose source volume no longer exists

Conventions (shared across the toolkit):
  - read-only; remediation emits CLI, never mutates live state
  - severity model LOW/MEDIUM/HIGH/CRITICAL + --fail-on (exit code 3 when met)
  - --format text|json
  - adaptive-retry botocore Config; every describe_* call is paginated
  - logic lives in pure methods (EBSHygiene.audit) for offline testing
"""

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.config import Config

RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

# Approximate us-east-1 $/GB-month for gp3 (storage estimate for idle volumes).
GP3_GB_MONTH = 0.08


def _name_tag(resource: dict) -> str:
    for t in resource.get("Tags", []):
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


class EBSHygiene:
    """Fetches EBS volumes + snapshots and flags hygiene issues.

    Fetching is separated from classification (audit) so logic is unit-testable.
    """

    def __init__(self, session=None):
        sess = session or boto3.Session()
        self.ec2 = sess.client("ec2", config=RETRY_CONFIG)
        self._account_id = None

    # ── Fetching (paginated) ────────────────────────────────────────────────
    def fetch_volumes(self) -> list:
        out = []
        for page in self.ec2.get_paginator("describe_volumes").paginate():
            out.extend(page.get("Volumes", []))
        return out

    def fetch_snapshots(self, owner_id: str) -> list:
        out = []
        for page in self.ec2.get_paginator("describe_snapshots").paginate(OwnerIds=[owner_id]):
            out.extend(page.get("Snapshots", []))
        return out

    def account_id(self) -> str:
        # sts:GetCallerIdentity scopes snapshot listing to self-owned snapshots.
        if self._account_id is None:
            sts = boto3.Session().client("sts", config=RETRY_CONFIG)
            self._account_id = sts.get_caller_identity()["Account"]
        return self._account_id

    # ── Classification (pure — unit tested) ─────────────────────────────────
    @staticmethod
    def _age_days(timestamp, now) -> int:
        if timestamp is None:
            return 0
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return (now - timestamp).days

    @classmethod
    def audit_volumes(cls, volumes: list) -> list:
        findings = []
        for v in volumes:
            vol_id = v.get("VolumeId", "")
            name = _name_tag(v)
            size = v.get("Size", 0)
            attached = bool(v.get("Attachments"))
            state = v.get("State", "")

            if not v.get("Encrypted", False):
                findings.append({
                    "severity": "HIGH", "type": "UNENCRYPTED_VOLUME",
                    "resource_id": vol_id, "name": name,
                    "detail": "Volume is not encrypted at rest",
                    "remediation": "Snapshot → copy with --encrypted → recreate from the encrypted snapshot",
                })

            if not attached or state == "available":
                findings.append({
                    "severity": "MEDIUM", "type": "UNATTACHED_VOLUME",
                    "resource_id": vol_id, "name": name,
                    "size_gib": size,
                    "estimated_monthly_cost_usd": round(size * GP3_GB_MONTH, 2),
                    "detail": f"Volume is unattached ({size} GiB) and still billed",
                    "remediation": f"aws ec2 delete-volume --volume-id {vol_id} (snapshot first if needed)",
                })

        return findings

    @classmethod
    def audit_snapshots(cls, snapshots: list, volume_ids: set, max_age_days: int, now=None) -> list:
        now = now or datetime.now(timezone.utc)
        findings = []
        for s in snapshots:
            snap_id = s.get("SnapshotId", "")
            source_vol = s.get("VolumeId")
            age = cls._age_days(s.get("StartTime"), now)

            # Orphaned: source volume no longer exists (ignore the all-zero placeholder).
            if source_vol and source_vol != "vol-ffffffff" and source_vol not in volume_ids:
                findings.append({
                    "severity": "MEDIUM", "type": "ORPHANED_SNAPSHOT",
                    "resource_id": snap_id, "name": _name_tag(s),
                    "source_volume": source_vol, "age_days": age,
                    "detail": f"Snapshot's source volume {source_vol} no longer exists",
                    "remediation": f"aws ec2 delete-snapshot --snapshot-id {snap_id}",
                })
            elif age > max_age_days:
                findings.append({
                    "severity": "LOW", "type": "STALE_SNAPSHOT",
                    "resource_id": snap_id, "name": _name_tag(s),
                    "age_days": age,
                    "detail": f"Snapshot is {age} days old (> {max_age_days})",
                    "remediation": f"aws ec2 delete-snapshot --snapshot-id {snap_id}",
                })
        return findings

    @classmethod
    def audit(cls, volumes: list, snapshots: list, max_age_days: int = 90, now=None) -> list:
        volume_ids = {v.get("VolumeId") for v in volumes}
        findings = cls.audit_volumes(volumes)
        findings += cls.audit_snapshots(snapshots, volume_ids, max_age_days, now=now)
        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["resource_id"]))
        return findings


def _print_text(findings: list) -> None:
    if not findings:
        print("✓ No EBS hygiene issues found.")
        return
    cost = sum(f.get("estimated_monthly_cost_usd", 0) or 0 for f in findings)
    print(f"\n🧹 {len(findings)} EBS hygiene finding(s):\n")
    for f in findings:
        icon = SEVERITY_ICON[f["severity"]]
        name = f.get("name", "")
        label = f["resource_id"] + (f" ({name})" if name else "")
        print(f"  {icon} [{f['severity']}] {f['type']}: {label}")
        print(f"       └─ {f['detail']}")
        print(f"          fix: {f['remediation']}")
    if cost:
        print(f"\n  Estimated idle-storage monthly cost: ~${round(cost, 2)}")


def main():
    parser = argparse.ArgumentParser(
        description="EBS Hygiene — unattached/unencrypted volumes + stale/orphaned snapshots.")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--max-snapshot-age", type=int, default=90,
                        help="Flag snapshots older than this many days (default 90)")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                        help="Exit with code 3 if any finding meets or exceeds this severity.")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    hygiene = EBSHygiene(session)
    try:
        volumes = hygiene.fetch_volumes()
        snapshots = hygiene.fetch_snapshots(hygiene.account_id())
    except Exception as e:  # noqa: BLE001 — surface AWS/client errors cleanly
        print(f"Error querying EC2: {e}", file=sys.stderr)
        sys.exit(1)

    findings = EBSHygiene.audit(volumes, snapshots, max_age_days=args.max_snapshot_age)

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
