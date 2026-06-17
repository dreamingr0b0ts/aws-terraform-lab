"""Tests for SecurityGroupAuditor classification logic (no AWS calls).

Exercises the pure `audit`/classification methods with fake describe_* shapes,
plus a fake paginator to confirm fetch_* concatenates pages.

Run with:  python3 -m pytest sg-auditor/test_sg_auditor.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sg_auditor import SecurityGroupAuditor  # noqa: E402


def ingress(proto="tcp", from_port=None, to_port=None, cidr=None, cidr6=None, group_id=None):
    """Build one IpPermissions entry."""
    perm = {"IpProtocol": proto}
    if from_port is not None:
        perm["FromPort"] = from_port
    if to_port is not None:
        perm["ToPort"] = to_port
    perm["IpRanges"] = [{"CidrIp": cidr}] if cidr else []
    perm["Ipv6Ranges"] = [{"CidrIpv6": cidr6}] if cidr6 else []
    perm["UserIdGroupPairs"] = [{"GroupId": group_id}] if group_id else []
    return perm


def sg(gid, name="sg", ingress_perms=None, egress_perms=None):
    return {
        "GroupId": gid,
        "GroupName": name,
        "IpPermissions": ingress_perms or [],
        "IpPermissionsEgress": egress_perms or [],
    }


def eni(group_ids):
    return {"Groups": [{"GroupId": g} for g in group_ids]}


def by_type(findings, ftype):
    return [f for f in findings if f["type"] == ftype]


class ClassifyIngressTests(unittest.TestCase):
    def test_ssh_open_to_world_is_critical(self):
        groups = [sg("sg-1", "bastion", [ingress("tcp", 22, 22, "0.0.0.0/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        crit = by_type(findings, "WORLD_OPEN_SENSITIVE_PORT")
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "CRITICAL")
        self.assertEqual(crit[0]["port"], 22)

    def test_rdp_over_ipv6_is_critical(self):
        groups = [sg("sg-1", "win", [ingress("tcp", 3389, 3389, cidr6="::/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        crit = by_type(findings, "WORLD_OPEN_SENSITIVE_PORT")
        self.assertEqual(crit[0]["severity"], "CRITICAL")
        self.assertEqual(crit[0]["port"], 3389)

    def test_database_port_to_world_is_high(self):
        groups = [sg("sg-1", "db", [ingress("tcp", 3306, 3306, "0.0.0.0/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        f = by_type(findings, "WORLD_OPEN_SENSITIVE_PORT")[0]
        self.assertEqual(f["severity"], "HIGH")

    def test_all_ports_to_world_is_critical(self):
        groups = [sg("sg-1", "wide", [ingress("-1", cidr="0.0.0.0/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        f = by_type(findings, "WORLD_OPEN_ALL_PORTS")[0]
        self.assertEqual(f["severity"], "CRITICAL")

    def test_full_range_tcp_to_world_is_all_ports(self):
        groups = [sg("sg-1", "wide", [ingress("tcp", 0, 65535, "0.0.0.0/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        self.assertEqual(len(by_type(findings, "WORLD_OPEN_ALL_PORTS")), 1)

    def test_web_port_to_world_is_low(self):
        groups = [sg("sg-1", "web", [ingress("tcp", 443, 443, "0.0.0.0/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        f = by_type(findings, "WORLD_OPEN_PORT")[0]
        self.assertEqual(f["severity"], "LOW")

    def test_nonsensitive_port_to_world_is_medium(self):
        groups = [sg("sg-1", "app", [ingress("tcp", 8080, 8080, "0.0.0.0/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        f = by_type(findings, "WORLD_OPEN_PORT")[0]
        self.assertEqual(f["severity"], "MEDIUM")

    def test_range_covering_ssh_flags_ssh(self):
        # A 20-30 range covers SSH (22) — should be flagged.
        groups = [sg("sg-1", "range", [ingress("tcp", 20, 30, "0.0.0.0/0")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        ports = {f.get("port") for f in by_type(findings, "WORLD_OPEN_SENSITIVE_PORT")}
        self.assertIn(22, ports)

    def test_internal_rule_not_flagged(self):
        # Ingress from another SG (not world) must NOT be flagged as world-open.
        groups = [sg("sg-1", "app", [ingress("tcp", 22, 22, group_id="sg-2")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        self.assertEqual(by_type(findings, "WORLD_OPEN_SENSITIVE_PORT"), [])

    def test_scoped_cidr_not_flagged(self):
        groups = [sg("sg-1", "app", [ingress("tcp", 22, 22, "10.0.0.0/16")])]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        self.assertEqual(by_type(findings, "WORLD_OPEN_SENSITIVE_PORT"), [])


class AllPortsLabelTests(unittest.TestCase):
    def test_all_protocols_label(self):
        groups = [sg("sg-1", "wide", [ingress("-1", cidr="0.0.0.0/0")])]
        f = by_type(SecurityGroupAuditor.audit(groups, [eni(["sg-1"])]), "WORLD_OPEN_ALL_PORTS")[0]
        self.assertIn("protocol", f["detail"].lower())

    def test_all_tcp_ports_label(self):
        groups = [sg("sg-1", "wide", [ingress("tcp", 0, 65535, "0.0.0.0/0")])]
        f = by_type(SecurityGroupAuditor.audit(groups, [eni(["sg-1"])]), "WORLD_OPEN_ALL_PORTS")[0]
        self.assertIn("TCP", f["detail"])
        self.assertNotIn("protocol", f["detail"].lower())


class WebRangeTests(unittest.TestCase):
    def test_single_web_port_low(self):
        groups = [sg("sg-1", "web", [ingress("tcp", 80, 80, "0.0.0.0/0")])]
        f = by_type(SecurityGroupAuditor.audit(groups, [eni(["sg-1"])]), "WORLD_OPEN_PORT")[0]
        self.assertEqual(f["severity"], "LOW")

    def test_broad_range_covering_web_is_medium_and_notes_web(self):
        # 80-443 is broad (360+ ports) → MEDIUM, but detail surfaces the web ports.
        groups = [sg("sg-1", "broad", [ingress("tcp", 80, 443, "0.0.0.0/0")])]
        f = by_type(SecurityGroupAuditor.audit(groups, [eni(["sg-1"])]), "WORLD_OPEN_PORT")[0]
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertIn("80", f["detail"])
        self.assertIn("443", f["detail"])


class RedundantRuleTests(unittest.TestCase):
    def test_specific_port_redundant_under_all_traffic(self):
        # tcp/443 from the world is redundant when -1 (all) from the world exists.
        perms = [ingress("-1", cidr="0.0.0.0/0"), ingress("tcp", 443, 443, "0.0.0.0/0")]
        findings = SecurityGroupAuditor.audit([sg("sg-1", "x", perms)], [eni(["sg-1"])])
        self.assertEqual(len(by_type(findings, "REDUNDANT_RULE")), 1)

    def test_narrow_range_redundant_under_wider_range(self):
        # tcp/8080 is contained in tcp/8000-9000 from the same source.
        perms = [ingress("tcp", 8000, 9000, "0.0.0.0/0"), ingress("tcp", 8080, 8080, "0.0.0.0/0")]
        findings = SecurityGroupAuditor.audit([sg("sg-1", "x", perms)], [eni(["sg-1"])])
        red = by_type(findings, "REDUNDANT_RULE")
        self.assertEqual(len(red), 1)
        self.assertEqual(red[0]["severity"], "LOW")

    def test_exact_duplicate_flags_one(self):
        perms = [ingress("tcp", 22, 22, "10.0.0.0/8"), ingress("tcp", 22, 22, "10.0.0.0/8")]
        findings = SecurityGroupAuditor.audit([sg("sg-1", "x", perms)], [eni(["sg-1"])])
        self.assertEqual(len(by_type(findings, "REDUNDANT_RULE")), 1)

    def test_different_sources_not_redundant(self):
        perms = [ingress("tcp", 443, 443, "10.0.0.0/8"), ingress("tcp", 443, 443, "192.168.0.0/16")]
        findings = SecurityGroupAuditor.audit([sg("sg-1", "x", perms)], [eni(["sg-1"])])
        self.assertEqual(by_type(findings, "REDUNDANT_RULE"), [])

    def test_disjoint_ports_not_redundant(self):
        perms = [ingress("tcp", 80, 80, "10.0.0.0/8"), ingress("tcp", 443, 443, "10.0.0.0/8")]
        findings = SecurityGroupAuditor.audit([sg("sg-1", "x", perms)], [eni(["sg-1"])])
        self.assertEqual(by_type(findings, "REDUNDANT_RULE"), [])

    def test_referenced_sg_source_redundancy(self):
        # Two ingress rules referencing the same SG, one subsumed by the other.
        perms = [ingress("-1", group_id="sg-9"), ingress("tcp", 22, 22, group_id="sg-9")]
        findings = SecurityGroupAuditor.audit([sg("sg-1", "x", perms)], [eni(["sg-1"])])
        self.assertEqual(len(by_type(findings, "REDUNDANT_RULE")), 1)


class UnusedGroupTests(unittest.TestCase):
    def test_unattached_unreferenced_group_flagged(self):
        groups = [sg("sg-orphan", "orphan")]
        findings = SecurityGroupAuditor.audit(groups, [])  # no ENIs
        self.assertEqual(len(by_type(findings, "UNUSED_SECURITY_GROUP")), 1)

    def test_attached_group_not_flagged(self):
        groups = [sg("sg-1", "app")]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        self.assertEqual(by_type(findings, "UNUSED_SECURITY_GROUP"), [])

    def test_referenced_group_not_flagged(self):
        # sg-2 is unattached but referenced by sg-1's rule → not "unused".
        groups = [
            sg("sg-1", "app", [ingress("tcp", 22, 22, group_id="sg-2")]),
            sg("sg-2", "ref-only"),
        ]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"])])
        unused_ids = {f["group_id"] for f in by_type(findings, "UNUSED_SECURITY_GROUP")}
        self.assertNotIn("sg-2", unused_ids)

    def test_default_group_never_flagged_unused(self):
        groups = [sg("sg-def", "default")]
        findings = SecurityGroupAuditor.audit(groups, [])
        self.assertEqual(by_type(findings, "UNUSED_SECURITY_GROUP"), [])


class SortingTests(unittest.TestCase):
    def test_findings_sorted_critical_first(self):
        groups = [
            sg("sg-1", "web", [ingress("tcp", 443, 443, "0.0.0.0/0")]),   # LOW
            sg("sg-2", "ssh", [ingress("tcp", 22, 22, "0.0.0.0/0")]),     # CRITICAL
        ]
        findings = SecurityGroupAuditor.audit(groups, [eni(["sg-1"]), eni(["sg-2"])])
        self.assertEqual(findings[0]["severity"], "CRITICAL")


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class FakeEc2:
    def __init__(self, sg_pages, eni_pages):
        self._map = {
            "describe_security_groups": sg_pages,
            "describe_network_interfaces": eni_pages,
        }

    def get_paginator(self, name):
        return FakePaginator(self._map[name])


class FetchTests(unittest.TestCase):
    def _auditor(self, sg_pages, eni_pages):
        a = SecurityGroupAuditor.__new__(SecurityGroupAuditor)
        a.ec2 = FakeEc2(sg_pages, eni_pages)
        return a

    def test_fetch_concatenates_pages(self):
        a = self._auditor(
            sg_pages=[{"SecurityGroups": [sg("sg-1")]}, {"SecurityGroups": [sg("sg-2")]}],
            eni_pages=[{"NetworkInterfaces": [eni(["sg-1"])]}],
        )
        self.assertEqual(len(a.fetch_security_groups()), 2)
        self.assertEqual(len(a.fetch_network_interfaces()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
