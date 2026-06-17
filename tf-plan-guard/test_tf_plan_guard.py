"""Tests for PlanGuard analysis over terraform show -json shapes (no AWS, no deps).

Run with:  python3 -m pytest tf-plan-guard/test_tf_plan_guard.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tf_plan_guard import PlanGuard  # noqa: E402


def change(rtype, after, actions=("create",), address=None):
    return {
        "address": address or f"{rtype}.test",
        "type": rtype,
        "change": {"actions": list(actions), "before": None, "after": after},
    }


def plan(*changes):
    return {"resource_changes": list(changes)}


def types(findings):
    return [f["type"] for f in findings]


class SecurityGroupTests(unittest.TestCase):
    def test_modern_ingress_ssh_world_critical(self):
        c = change("aws_vpc_security_group_ingress_rule",
                   {"cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["type"], "SG_WORLD_OPEN_PORT")

    def test_modern_ingress_scoped_cidr_clean(self):
        c = change("aws_vpc_security_group_ingress_rule",
                   {"cidr_ipv4": "10.0.0.0/8", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"})
        self.assertEqual(PlanGuard.analyze(plan(c)), [])

    def test_inline_sg_block_db_world_high(self):
        c = change("aws_security_group", {"ingress": [
            {"cidr_blocks": ["0.0.0.0/0"], "from_port": 3306, "to_port": 3306, "protocol": "tcp"}]})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_all_ports_world_critical(self):
        c = change("aws_security_group", {"ingress": [
            {"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 0, "protocol": "-1"}]})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["type"], "SG_WORLD_OPEN_ALL_PORTS")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_ipv6_world_open(self):
        c = change("aws_vpc_security_group_ingress_rule",
                   {"cidr_ipv6": "::/0", "from_port": 3389, "to_port": 3389, "ip_protocol": "tcp"})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_legacy_sg_rule_egress_ignored(self):
        c = change("aws_security_group_rule",
                   {"type": "egress", "cidr_blocks": ["0.0.0.0/0"], "from_port": 22,
                    "to_port": 22, "protocol": "tcp"})
        self.assertEqual(PlanGuard.analyze(plan(c)), [])

    def test_web_port_world_is_low(self):
        c = change("aws_vpc_security_group_ingress_rule",
                   {"cidr_ipv4": "0.0.0.0/0", "from_port": 443, "to_port": 443, "ip_protocol": "tcp"})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["severity"], "LOW")


class InstanceTests(unittest.TestCase):
    def test_imdsv1_optional_flagged(self):
        c = change("aws_instance", {"metadata_options": [{"http_endpoint": "enabled", "http_tokens": "optional"}]})
        findings = PlanGuard.analyze(plan(c))
        self.assertIn("IMDSV1_ALLOWED", types(findings))

    def test_imdsv2_required_clean(self):
        c = change("aws_instance", {"metadata_options": [{"http_endpoint": "enabled", "http_tokens": "required"}]})
        self.assertEqual(PlanGuard.analyze(plan(c)), [])

    def test_unencrypted_root_volume(self):
        c = change("aws_instance", {"root_block_device": [{"encrypted": False}]})
        findings = PlanGuard.analyze(plan(c))
        self.assertIn("EBS_UNENCRYPTED", types(findings))

    def test_encrypted_root_clean(self):
        c = change("aws_instance", {"root_block_device": [{"encrypted": True}]})
        self.assertEqual(PlanGuard.analyze(plan(c)), [])

    def test_public_ip_low(self):
        c = change("aws_instance", {"associate_public_ip_address": True})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["type"], "PUBLIC_IP_ASSIGNED")
        self.assertEqual(findings[0]["severity"], "LOW")


class LaunchTemplateAndVolumeTests(unittest.TestCase):
    def test_launch_template_imdsv1_and_unencrypted(self):
        c = change("aws_launch_template", {
            "metadata_options": [{"http_tokens": "optional"}],
            "block_device_mappings": [{"ebs": [{"encrypted": False}]}],
        })
        t = types(PlanGuard.analyze(plan(c)))
        self.assertIn("IMDSV1_ALLOWED", t)
        self.assertIn("EBS_UNENCRYPTED", t)

    def test_ebs_volume_unencrypted(self):
        c = change("aws_ebs_volume", {"encrypted": False, "size": 20})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["type"], "EBS_UNENCRYPTED")

    def test_ebs_volume_encrypted_clean(self):
        c = change("aws_ebs_volume", {"encrypted": True, "size": 20})
        self.assertEqual(PlanGuard.analyze(plan(c)), [])

    def test_ebs_volume_missing_encrypted_key_flagged(self):
        # aws_ebs_volume defaults to unencrypted when `encrypted` is omitted.
        c = change("aws_ebs_volume", {"size": 20})
        findings = PlanGuard.analyze(plan(c))
        self.assertEqual(findings[0]["type"], "EBS_UNENCRYPTED")
        self.assertEqual(findings[0]["severity"], "HIGH")


class ActionFilterTests(unittest.TestCase):
    def test_delete_action_ignored(self):
        c = change("aws_vpc_security_group_ingress_rule",
                   {"cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"},
                   actions=("delete",))
        self.assertEqual(PlanGuard.analyze(plan(c)), [])

    def test_noop_ignored(self):
        c = change("aws_instance", {"root_block_device": [{"encrypted": False}]}, actions=("no-op",))
        self.assertEqual(PlanGuard.analyze(plan(c)), [])

    def test_update_action_inspected(self):
        c = change("aws_instance", {"root_block_device": [{"encrypted": False}]}, actions=("update",))
        self.assertEqual(len(PlanGuard.analyze(plan(c))), 1)

    def test_unknown_resource_type_skipped(self):
        c = change("aws_s3_bucket", {"acl": "public-read"})
        self.assertEqual(PlanGuard.analyze(plan(c)), [])


class SortingTests(unittest.TestCase):
    def test_critical_sorted_first(self):
        findings = PlanGuard.analyze(plan(
            change("aws_instance", {"associate_public_ip_address": True}, address="aws_instance.a"),
            change("aws_vpc_security_group_ingress_rule",
                   {"cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"},
                   address="aws_vpc_security_group_ingress_rule.b"),
        ))
        self.assertEqual(findings[0]["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
