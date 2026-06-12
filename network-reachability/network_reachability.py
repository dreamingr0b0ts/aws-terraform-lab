#!/usr/bin/env python3
"""Network Reachability — Is this instance reachable from the internet? Compose the full path.

The EC2 analog of an IAM blast-radius tool. For each instance it composes the four
layers that together decide internet exposure and emits a single verdict:

    public IP  →  subnet routes 0.0.0.0/0 to an IGW  →  a security group allows
    the world inbound on a port  →  the subnet's NACL allows that port inbound
    AND allows ephemeral return traffic outbound (NACLs are stateless).

Only when ALL four line up is the instance actually reachable. The tool reports
the exposed ports, the severity (worst port wins), and the reasoning path.

Conventions (shared across the toolkit):
  - read-only; remediation emits Terraform/CLI, never mutates live state
  - severity model LOW/MEDIUM/HIGH/CRITICAL + --fail-on (exit code 3 when met)
  - --format text|json
  - adaptive-retry botocore Config; every describe_* call is paginated
  - logic lives in pure methods (ReachabilityAnalyzer) for offline testing
"""

import argparse
import json
import sys

import boto3
from botocore.config import Config

RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})

WORLD = "0.0.0.0/0"
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

# Sensitive ports → (label, severity) when reachable from the internet.
SENSITIVE_PORTS = {
    22: ("SSH", "CRITICAL"), 3389: ("RDP", "CRITICAL"),
    3306: ("MySQL", "HIGH"), 5432: ("PostgreSQL", "HIGH"), 1433: ("MSSQL", "HIGH"),
    1521: ("Oracle", "HIGH"), 5439: ("Redshift", "HIGH"), 27017: ("MongoDB", "HIGH"),
    6379: ("Redis", "HIGH"), 11211: ("Memcached", "HIGH"), 9200: ("Elasticsearch", "HIGH"),
    2049: ("NFS", "HIGH"),
}
WEB_PORTS = {80: ("HTTP", "LOW"), 443: ("HTTPS", "LOW")}
OTHER_PORTS = {8080: ("HTTP-alt", "MEDIUM"), 8443: ("HTTPS-alt", "MEDIUM")}

# The concrete ports we probe through the path (plus an "all ports" shortcut).
PORT_CATALOG = {**SENSITIVE_PORTS, **WEB_PORTS, **OTHER_PORTS}

# A representative ephemeral port used to confirm NACL return traffic is allowed.
EPHEMERAL_PROBE = 50000


class ReachabilityAnalyzer:
    """Composes SG + NACL + route table + public IP into an exposure verdict.

    Fetching/topology-building is separated from the pure path evaluation so the
    composition logic can be unit-tested with fake data.
    """

    def __init__(self, session=None):
        sess = session or boto3.Session()
        self.ec2 = sess.client("ec2", config=RETRY_CONFIG)

    # ── Fetching (paginated) ────────────────────────────────────────────────
    def _paginate(self, op, key, **kwargs):
        out = []
        paginator = self.ec2.get_paginator(op)
        for page in paginator.paginate(**kwargs):
            out.extend(page.get(key, []))
        return out

    def fetch_instances(self) -> list:
        instances = []
        for res in self._paginate("describe_instances", "Reservations"):
            instances.extend(res.get("Instances", []))
        return instances

    def fetch_security_groups(self) -> dict:
        return {sg["GroupId"]: sg for sg in self._paginate("describe_security_groups", "SecurityGroups")}

    def fetch_route_tables(self) -> list:
        return self._paginate("describe_route_tables", "RouteTables")

    def fetch_network_acls(self) -> list:
        return self._paginate("describe_network_acls", "NetworkAcls")

    def fetch_subnets(self) -> list:
        return self._paginate("describe_subnets", "Subnets")

    # ── Topology builders (pure) ─────────────────────────────────────────────
    @staticmethod
    def build_subnet_route_map(route_tables: list) -> dict:
        """subnet_id → route table dict, honoring explicit assoc then VPC main RT."""
        main_by_vpc, explicit = {}, {}
        for rt in route_tables:
            vpc = rt.get("VpcId")
            for assoc in rt.get("Associations", []):
                if assoc.get("Main"):
                    main_by_vpc[vpc] = rt
                elif assoc.get("SubnetId"):
                    explicit[assoc["SubnetId"]] = rt
        return {"explicit": explicit, "main_by_vpc": main_by_vpc}

    @staticmethod
    def build_subnet_nacl_map(network_acls: list) -> dict:
        """subnet_id → NACL dict (each subnet has exactly one associated NACL)."""
        out = {}
        for nacl in network_acls:
            for assoc in nacl.get("Associations", []):
                if assoc.get("SubnetId"):
                    out[assoc["SubnetId"]] = nacl
        return out

    # ── Layer predicates (pure) ──────────────────────────────────────────────
    @staticmethod
    def route_to_igw(route_table: dict) -> bool:
        if not route_table:
            return False
        for r in route_table.get("Routes", []):
            if r.get("DestinationCidrBlock") == WORLD and str(r.get("GatewayId", "")).startswith("igw-"):
                return True
        return False

    @staticmethod
    def sg_world_ports(security_groups: list):
        """Return (all_ports_open, set_of_world_open_catalog_ports) across the SGs."""
        all_open = False
        ports = set()
        for sg in security_groups:
            for perm in sg.get("IpPermissions", []):
                world = any(r.get("CidrIp") == WORLD for r in perm.get("IpRanges", []))
                if not world:
                    continue
                proto = str(perm.get("IpProtocol", "-1"))
                fp, tp = perm.get("FromPort"), perm.get("ToPort")
                if proto == "-1" or fp is None or tp is None or (fp == 0 and tp == 65535):
                    all_open = True
                    continue
                ports |= {p for p in PORT_CATALOG if fp <= p <= tp}
        return all_open, ports

    @staticmethod
    def nacl_allows(nacl: dict, egress: bool, port: int) -> bool:
        """Evaluate world-sourced/destined NACL rules in order for a TCP port.

        Stateless: caller checks inbound (egress=False) and ephemeral outbound
        (egress=True) separately. No NACL (None) is treated as default-allow,
        matching AWS behavior where a subnet always has an (allow-all) default.
        """
        if nacl is None:
            return True
        entries = sorted(
            [e for e in nacl.get("Entries", []) if bool(e.get("Egress")) == egress],
            key=lambda e: e.get("RuleNumber", 32767),
        )
        for e in entries:
            if e.get("CidrBlock") != WORLD:
                continue  # only world rules matter for internet reachability
            proto = str(e.get("Protocol", "-1"))
            if proto not in ("-1", "6"):  # all or tcp
                continue
            pr = e.get("PortRange")
            if proto == "-1" or pr is None:
                port_match = True
            else:
                port_match = pr.get("From", 0) <= port <= pr.get("To", 65535)
            if port_match:
                return e.get("RuleAction") == "allow"
        return False  # implicit deny

    @staticmethod
    def _severity_for_ports(ports) -> str:
        worst = "LOW"
        for p in ports:
            sev = PORT_CATALOG.get(p, ("", "MEDIUM"))[1]
            if SEVERITY_RANK[sev] > SEVERITY_RANK[worst]:
                worst = sev
        return worst

    @classmethod
    def evaluate_instance(cls, ctx: dict):
        """Return an exposure verdict dict, or None if not internet-reachable.

        ctx = {instance_id, name, public_ip, route_table, nacl, security_groups}
        """
        public_ip = ctx.get("public_ip")
        if not public_ip:
            return None  # no public IP → not directly internet-reachable

        rt_ok = cls.route_to_igw(ctx.get("route_table"))
        if not rt_ok:
            return None  # subnet is private (no IGW route)

        all_open, sg_ports = cls.sg_world_ports(ctx.get("security_groups", []))
        nacl = ctx.get("nacl")

        # Return traffic must be allowed outbound (ephemeral). If not, nothing works.
        if not cls.nacl_allows(nacl, egress=True, port=EPHEMERAL_PROBE):
            return None

        candidate_ports = set(PORT_CATALOG) if all_open else sg_ports
        exposed = sorted(p for p in candidate_ports if cls.nacl_allows(nacl, egress=False, port=p))
        if not exposed:
            return None

        severity = "CRITICAL" if all_open else cls._severity_for_ports(exposed)
        labeled = [f"{p}/{PORT_CATALOG[p][0]}" for p in exposed]
        return {
            "severity": severity,
            "type": "INTERNET_EXPOSED",
            "instance_id": ctx.get("instance_id", ""),
            "name": ctx.get("name", ""),
            "public_ip": public_ip,
            "exposed_ports": exposed,
            "all_ports_open": all_open,
            "path": {
                "has_public_ip": True,
                "subnet_routes_to_igw": True,
                "security_group_world_open": True,
                "nacl_allows_inbound_and_return": True,
            },
            "detail": (
                f"Reachable from the internet ({public_ip}) on "
                + ("ALL ports" if all_open else ", ".join(labeled))
            ),
        }

    # ── Orchestration ─────────────────────────────────────────────────────────
    @classmethod
    def build_contexts(cls, instances, sgs_by_id, route_tables, network_acls, subnets) -> list:
        subnet_vpc = {s["SubnetId"]: s.get("VpcId") for s in subnets}
        rt_map = cls.build_subnet_route_map(route_tables)
        nacl_map = cls.build_subnet_nacl_map(network_acls)

        contexts = []
        for inst in instances:
            if inst.get("State", {}).get("Name") == "terminated":
                continue
            subnet_id = inst.get("SubnetId")
            vpc = subnet_vpc.get(subnet_id)
            route_table = rt_map["explicit"].get(subnet_id) or rt_map["main_by_vpc"].get(vpc)

            sgs = [sgs_by_id[g["GroupId"]] for g in inst.get("SecurityGroups", [])
                   if g.get("GroupId") in sgs_by_id]

            name = ""
            for t in inst.get("Tags", []):
                if t.get("Key") == "Name":
                    name = t.get("Value", "")

            contexts.append({
                "instance_id": inst.get("InstanceId", ""),
                "name": name,
                "public_ip": cls._instance_public_ip(inst),
                "subnet_id": subnet_id,
                "route_table": route_table,
                "nacl": nacl_map.get(subnet_id),
                "security_groups": sgs,
            })
        return contexts

    @staticmethod
    def _instance_public_ip(inst: dict):
        if inst.get("PublicIpAddress"):
            return inst["PublicIpAddress"]
        for eni in inst.get("NetworkInterfaces", []):
            assoc = eni.get("Association", {})
            if assoc.get("PublicIp"):
                return assoc["PublicIp"]
        return None

    @classmethod
    def analyze(cls, instances, sgs_by_id, route_tables, network_acls, subnets) -> list:
        contexts = cls.build_contexts(instances, sgs_by_id, route_tables, network_acls, subnets)
        findings = [v for v in (cls.evaluate_instance(c) for c in contexts) if v]
        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["instance_id"]))
        return findings


def _print_text(findings: list) -> None:
    if not findings:
        print("✓ No instances are reachable from the internet via the composed network path.")
        return
    print(f"\n🌐 {len(findings)} internet-reachable instance(s):\n")
    for f in findings:
        icon = SEVERITY_ICON[f["severity"]]
        name = f.get("name", "")
        label = f["instance_id"] + (f" ({name})" if name else "")
        print(f"  {icon} [{f['severity']}] {label} @ {f['public_ip']}")
        print(f"       └─ {f['detail']}")
        print("          path: public IP ✓ → IGW route ✓ → SG world-open ✓ → NACL allows ✓")


def main():
    parser = argparse.ArgumentParser(
        description="Network Reachability — compose SG + NACL + route + public IP into a verdict.")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None,
                        help="Exit with code 3 if any finding meets or exceeds this severity.")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    analyzer = ReachabilityAnalyzer(session)
    try:
        instances = analyzer.fetch_instances()
        sgs = analyzer.fetch_security_groups()
        route_tables = analyzer.fetch_route_tables()
        nacls = analyzer.fetch_network_acls()
        subnets = analyzer.fetch_subnets()
    except Exception as e:  # noqa: BLE001 — surface AWS/client errors cleanly
        print(f"Error querying EC2: {e}", file=sys.stderr)
        sys.exit(1)

    findings = ReachabilityAnalyzer.analyze(instances, sgs, route_tables, nacls, subnets)

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
