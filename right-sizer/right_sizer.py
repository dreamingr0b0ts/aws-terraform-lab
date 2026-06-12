#!/usr/bin/env python3
"""Right-Sizer — Recommend right-sized or Graviton instances from CloudWatch utilization.

Read-only cost analyzer. Pulls CPUUtilization for each running instance over a
look-back window, flags the ones running well under capacity, and recommends a
smaller same-family type and/or a Graviton equivalent — with an estimated
monthly on-demand saving (built-in static us-east-1 price table; approximate).

Conventions (shared across the toolkit):
  - read-only; remediation emits Terraform/CLI, never mutates live state
  - severity model LOW/MEDIUM/HIGH/CRITICAL + --fail-on (exit code 3 when met)
  - --format text|json
  - adaptive-retry botocore Config; describe_instances is paginated
  - logic lives in pure methods (RightSizer.analyze + helpers) for offline testing
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config

RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

LIVE_STATES = {"running"}  # only running instances emit CPU metrics worth judging

# Size ladder used to step a type down one notch (family is kept, size shrinks).
SIZE_ORDER = [
    "nano", "micro", "small", "medium", "large", "xlarge", "2xlarge",
    "4xlarge", "8xlarge", "12xlarge", "16xlarge", "24xlarge", "32xlarge", "48xlarge",
]

# Map x86 families → their Graviton (ARM) equivalent family.
GRAVITON_FAMILY = {
    "t3": "t4g", "t3a": "t4g", "t2": "t4g",
    "m5": "m7g", "m5a": "m7g", "m6i": "m7g", "m6a": "m7g",
    "c5": "c7g", "c5a": "c7g", "c6i": "c7g", "c6a": "c7g",
    "r5": "r7g", "r5a": "r7g", "r6i": "r7g", "r6a": "r7g",
}

# Approximate us-east-1 Linux on-demand $/hour. Built-in + intentionally small;
# this is a study estimate, NOT the live Pricing API. Unknown types → no $ figure.
ON_DEMAND_HOURLY = {
    "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832,
    "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
    "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336, "t4g.large": 0.0672,
    "t4g.xlarge": 0.1344, "t4g.2xlarge": 0.2688,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384, "m5.4xlarge": 0.768,
    "m7g.large": 0.0816, "m7g.xlarge": 0.1632, "m7g.2xlarge": 0.3264, "m7g.4xlarge": 0.6528,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34, "c5.4xlarge": 0.68,
    "c7g.large": 0.0725, "c7g.xlarge": 0.145, "c7g.2xlarge": 0.29, "c7g.4xlarge": 0.58,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504,
    "r7g.large": 0.1071, "r7g.xlarge": 0.2142, "r7g.2xlarge": 0.4284,
}

HOURS_PER_MONTH = 730


def split_type(instance_type: str):
    """'m5.xlarge' → ('m5', 'xlarge'). Returns (None, None) if malformed."""
    if "." not in instance_type:
        return None, None
    family, size = instance_type.split(".", 1)
    return family, size


def downsize(instance_type: str):
    """Step one size down within the same family. None if already smallest/unknown."""
    family, size = split_type(instance_type)
    if family is None or size not in SIZE_ORDER:
        return None
    idx = SIZE_ORDER.index(size)
    if idx == 0:
        return None
    return f"{family}.{SIZE_ORDER[idx - 1]}"


def graviton_equiv(instance_type: str):
    """Graviton equivalent of the same size, e.g. 'm5.xlarge' → 'm7g.xlarge'. None if n/a."""
    family, size = split_type(instance_type)
    if family is None or family not in GRAVITON_FAMILY:
        return None
    return f"{GRAVITON_FAMILY[family]}.{size}"


def price(instance_type) -> float:
    """Static $/hour, or None if unknown."""
    if instance_type is None:
        return None
    return ON_DEMAND_HOURLY.get(instance_type)


def monthly_savings(current_type: str, target_type: str):
    """Estimated monthly $ saved switching current → target. None if a price is unknown."""
    cur, tgt = price(current_type), price(target_type)
    if cur is None or tgt is None:
        return None
    return round((cur - tgt) * HOURS_PER_MONTH, 2)


class RightSizer:
    """Fetches instances + CPU stats and recommends right-sizing.

    Fetching is separated from analysis (analyze) so logic is unit-testable.
    """

    def __init__(self, session=None):
        sess = session or boto3.Session()
        self.ec2 = sess.client("ec2", config=RETRY_CONFIG)
        self.cw = sess.client("cloudwatch", config=RETRY_CONFIG)

    # ── Fetching ────────────────────────────────────────────────────────────
    def fetch_instances(self) -> list:
        instances = []
        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": list(LIVE_STATES)}]
        ):
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
        return instances

    def fetch_cpu_stats(self, instance_id: str, days: int) -> dict:
        """Return {'cpu_avg', 'cpu_max', 'datapoints'} for an instance over `days`."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        resp = self.cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=["Average", "Maximum"],
        )
        points = resp.get("Datapoints", [])
        if not points:
            return {"cpu_avg": None, "cpu_max": None, "datapoints": 0}
        avg = sum(p["Average"] for p in points) / len(points)
        mx = max(p["Maximum"] for p in points)
        return {"cpu_avg": round(avg, 2), "cpu_max": round(mx, 2), "datapoints": len(points)}

    @staticmethod
    def _name_tag(instance: dict) -> str:
        for t in instance.get("Tags", []):
            if t.get("Key") == "Name":
                return t.get("Value", "")
        return ""

    def build_records(self, instances: list, days: int) -> list:
        """Combine instance metadata with CPU stats into analyze() input records."""
        records = []
        for inst in instances:
            iid = inst.get("InstanceId", "")
            stats = self.fetch_cpu_stats(iid, days)
            records.append({
                "instance_id": iid,
                "instance_type": inst.get("InstanceType", ""),
                "name": self._name_tag(inst),
                **stats,
            })
        return records

    # ── Analysis (pure — unit tested) ────────────────────────────────────────
    @staticmethod
    def _severity(cpu_max: float) -> str:
        if cpu_max < 5:
            return "HIGH"      # effectively idle
        if cpu_max < 20:
            return "MEDIUM"
        return "LOW"           # 20–threshold: mild over-provisioning

    @classmethod
    def analyze(cls, records: list, cpu_threshold: float = 40.0, min_datapoints: int = 24) -> list:
        """Flag over-provisioned instances and recommend a target type. Pure."""
        findings = []
        for r in records:
            if r.get("datapoints", 0) < min_datapoints:
                continue  # not enough signal to judge (new/just-launched)
            cpu_max = r.get("cpu_max")
            if cpu_max is None or cpu_max >= cpu_threshold:
                continue  # busy enough — leave it alone

            current = r["instance_type"]
            smaller = downsize(current)
            graviton = graviton_equiv(smaller) if smaller else graviton_equiv(current)
            # Prefer the recommendation that actually exists.
            recommended = smaller or graviton
            if recommended is None:
                continue  # already smallest in family with no Graviton path

            findings.append({
                "severity": cls._severity(cpu_max),
                "type": "OVER_PROVISIONED",
                "instance_id": r["instance_id"],
                "name": r.get("name", ""),
                "instance_type": current,
                "cpu_avg": r.get("cpu_avg"),
                "cpu_max": cpu_max,
                "recommended_type": recommended,
                "graviton_alternative": graviton,
                "estimated_monthly_savings_usd": monthly_savings(current, recommended),
                "detail": (
                    f"{current} peaked at {cpu_max}% CPU (avg {r.get('cpu_avg')}%) — "
                    f"recommend {recommended}"
                ),
            })

        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["instance_id"]))
        return findings


def _print_text(findings: list, days: int) -> None:
    if not findings:
        print(f"✓ No over-provisioned instances over the last {days} days.")
        return
    total = sum(f["estimated_monthly_savings_usd"] or 0 for f in findings)
    print(f"\n💸 {len(findings)} over-provisioned instance(s) over the last {days} days:\n")
    for f in findings:
        icon = SEVERITY_ICON[f["severity"]]
        name = f.get("name", "")
        label = f["instance_id"] + (f" ({name})" if name else "")
        save = f["estimated_monthly_savings_usd"]
        save_str = f"~${save}/mo" if save is not None else "savings n/a"
        print(f"  {icon} [{f['severity']}] {label}: {f['instance_type']} → {f['recommended_type']} ({save_str})")
        print(f"       └─ {f['detail']}")
        if f.get("graviton_alternative"):
            print(f"          graviton option: {f['graviton_alternative']}")
    print(f"\n  Estimated total monthly saving (known prices): ~${round(total, 2)}")


def main():
    parser = argparse.ArgumentParser(
        description="Right-Sizer — recommend smaller/Graviton instances from CloudWatch CPU.")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--days", type=int, default=14, help="Look-back window in days (default 14)")
    parser.add_argument("--cpu-threshold", type=float, default=40.0,
                        help="Flag instances whose peak CPU%% is below this (default 40)")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                        help="Exit with code 3 if any finding meets or exceeds this severity.")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sizer = RightSizer(session)
    try:
        instances = sizer.fetch_instances()
        records = sizer.build_records(instances, args.days)
    except Exception as e:  # noqa: BLE001 — surface AWS/client errors cleanly
        print(f"Error querying AWS: {e}", file=sys.stderr)
        sys.exit(1)

    findings = RightSizer.analyze(records, cpu_threshold=args.cpu_threshold)

    if args.format == "json":
        print(json.dumps({"findings": findings, "total": len(findings)}, indent=2, default=str))
    else:
        _print_text(findings, args.days)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f["severity"]] >= threshold for f in findings):
            print(f"\n✗ Findings met --fail-on {args.fail_on} threshold.", file=sys.stderr)
            sys.exit(3)


if __name__ == "__main__":
    main()
