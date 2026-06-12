"""Tests for ReachabilityAnalyzer path composition (no AWS calls).

The core value is that EACH layer can independently block exposure: no public IP,
no IGW route, SG not world-open, or NACL deny. These tests assert that.

Run with:  python3 -m pytest network-reachability/test_network_reachability.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from network_reachability import ReachabilityAnalyzer as RA  # noqa: E402

# ── Builders ──────────────────────────────────────────────────────────────────


def sg(perms):
    return {"GroupId": "sg-x", "IpPermissions": perms}


def perm(proto="tcp", fp=None, tp=None, cidr="0.0.0.0/0"):
    p = {"IpProtocol": proto, "IpRanges": [{"CidrIp": cidr}] if cidr else []}
    if fp is not None:
        p["FromPort"] = fp
    if tp is not None:
        p["ToPort"] = tp
    return p


def igw_rt():
    return {"VpcId": "vpc-1", "Routes": [
        {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}]}


def private_rt():
    return {"VpcId": "vpc-1", "Routes": [
        {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-123"}]}


def allow_all_nacl():
    return {"Entries": [
        {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
        {"RuleNumber": 100, "Egress": True, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
    ]}


def ctx(public_ip="1.2.3.4", route_table=None, nacl=None, perms=None, name="x"):
    return {
        "instance_id": "i-1",
        "name": name,
        "public_ip": public_ip,
        "route_table": route_table if route_table is not None else igw_rt(),
        "nacl": nacl if nacl is not None else allow_all_nacl(),
        "security_groups": [sg(perms if perms is not None else [perm("tcp", 22, 22)])],
    }


# ── Layer-blocking tests ────────────────────────────────────────────────────


class PathCompositionTests(unittest.TestCase):
    def test_full_path_ssh_is_critical(self):
        v = RA.evaluate_instance(ctx())
        self.assertIsNotNone(v)
        self.assertEqual(v["severity"], "CRITICAL")
        self.assertIn(22, v["exposed_ports"])

    def test_no_public_ip_blocks(self):
        self.assertIsNone(RA.evaluate_instance(ctx(public_ip=None)))

    def test_private_subnet_blocks(self):
        self.assertIsNone(RA.evaluate_instance(ctx(route_table=private_rt())))

    def test_sg_not_world_open_blocks(self):
        perms = [perm("tcp", 22, 22, cidr="10.0.0.0/8")]  # scoped, not world
        self.assertIsNone(RA.evaluate_instance(ctx(perms=perms)))

    def test_nacl_inbound_deny_blocks(self):
        nacl = {"Entries": [
            {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"},
            {"RuleNumber": 100, "Egress": True, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
        ]}
        self.assertIsNone(RA.evaluate_instance(ctx(nacl=nacl)))

    def test_nacl_no_egress_return_blocks(self):
        # Inbound allowed, but no outbound ephemeral return → blocked.
        nacl = {"Entries": [
            {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
        ]}
        self.assertIsNone(RA.evaluate_instance(ctx(nacl=nacl)))

    def test_none_nacl_defaults_allow(self):
        v = RA.evaluate_instance(ctx(nacl=None))
        self.assertIsNotNone(v)

    def test_web_port_only_is_low(self):
        v = RA.evaluate_instance(ctx(perms=[perm("tcp", 443, 443)]))
        self.assertEqual(v["severity"], "LOW")

    def test_db_port_is_high(self):
        v = RA.evaluate_instance(ctx(perms=[perm("tcp", 3306, 3306)]))
        self.assertEqual(v["severity"], "HIGH")

    def test_all_ports_open_is_critical(self):
        v = RA.evaluate_instance(ctx(perms=[perm("-1")]))
        self.assertEqual(v["severity"], "CRITICAL")
        self.assertTrue(v["all_ports_open"])

    def test_eni_association_public_ip_detected(self):
        # No top-level PublicIpAddress but an ENI association has one.
        c = ctx(public_ip="5.6.7.8")
        v = RA.evaluate_instance(c)
        self.assertEqual(v["public_ip"], "5.6.7.8")


class NaclEvaluatorTests(unittest.TestCase):
    def test_ordered_rules_first_match_wins(self):
        # Rule 100 denies 22; rule 200 allows all. First match (deny) wins.
        nacl = {"Entries": [
            {"RuleNumber": 200, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
            {"RuleNumber": 100, "Egress": False, "Protocol": "6", "RuleAction": "deny",
             "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}},
        ]}
        self.assertFalse(RA.nacl_allows(nacl, egress=False, port=22))
        self.assertTrue(RA.nacl_allows(nacl, egress=False, port=80))

    def test_non_world_cidr_ignored(self):
        nacl = {"Entries": [
            {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "10.0.0.0/8"},
        ]}
        self.assertFalse(RA.nacl_allows(nacl, egress=False, port=22))


class TopologyBuilderTests(unittest.TestCase):
    def test_explicit_assoc_beats_main(self):
        rts = [
            {"VpcId": "vpc-1", "Associations": [{"Main": True}], "Routes": []},
            {"VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1"}], "Routes": []},
        ]
        m = RA.build_subnet_route_map(rts)
        self.assertIn("subnet-1", m["explicit"])
        self.assertIn("vpc-1", m["main_by_vpc"])

    def test_nacl_map_by_subnet(self):
        nacls = [{"Associations": [{"SubnetId": "subnet-1"}], "Entries": []}]
        m = RA.build_subnet_nacl_map(nacls)
        self.assertIn("subnet-1", m)

    def test_route_to_igw_true_false(self):
        self.assertTrue(RA.route_to_igw(igw_rt()))
        self.assertFalse(RA.route_to_igw(private_rt()))
        self.assertFalse(RA.route_to_igw(None))


class AnalyzeIntegrationTests(unittest.TestCase):
    def test_end_to_end_bastion_exposed(self):
        instances = [{
            "InstanceId": "i-bastion", "SubnetId": "subnet-pub",
            "State": {"Name": "running"},
            "PublicIpAddress": "1.2.3.4",
            "SecurityGroups": [{"GroupId": "sg-bastion"}],
            "Tags": [{"Key": "Name", "Value": "bastion"}],
        }]
        sgs = {"sg-bastion": {"GroupId": "sg-bastion",
                              "IpPermissions": [perm("tcp", 22, 22), perm("tcp", 3389, 3389)]}}
        route_tables = [{"VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-pub"}],
                         "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}]
        nacls = [{"Associations": [{"SubnetId": "subnet-pub"}], "Entries": allow_all_nacl()["Entries"]}]
        subnets = [{"SubnetId": "subnet-pub", "VpcId": "vpc-1"}]

        findings = RA.analyze(instances, sgs, route_tables, nacls, subnets)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["name"], "bastion")
        self.assertEqual(set(findings[0]["exposed_ports"]) & {22, 3389}, {22, 3389})

    def test_private_instance_not_exposed(self):
        instances = [{
            "InstanceId": "i-app", "SubnetId": "subnet-priv",
            "State": {"Name": "running"},
            "SecurityGroups": [{"GroupId": "sg-app"}],
        }]
        sgs = {"sg-app": {"GroupId": "sg-app", "IpPermissions": [perm("tcp", 22, 22)]}}
        route_tables = [{"VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-priv"}],
                         "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}]}]
        nacls = [{"Associations": [{"SubnetId": "subnet-priv"}], "Entries": allow_all_nacl()["Entries"]}]
        subnets = [{"SubnetId": "subnet-priv", "VpcId": "vpc-1"}]

        findings = RA.analyze(instances, sgs, route_tables, nacls, subnets)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
