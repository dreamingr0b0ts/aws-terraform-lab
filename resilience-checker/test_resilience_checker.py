"""Tests for ResilienceChecker classification (no AWS calls).

Run with:  python3 -m pytest resilience-checker/test_resilience_checker.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resilience_checker import ResilienceChecker as RC  # noqa: E402


def asg(name="asg", azs=("us-east-1a", "us-east-1b"), desired=2, health="EC2",
        target_groups=None, lbs=None, instances=None):
    a = {
        "AutoScalingGroupName": name,
        "AvailabilityZones": list(azs),
        "DesiredCapacity": desired,
        "HealthCheckType": health,
    }
    if target_groups:
        a["TargetGroupARNs"] = target_groups
    if lbs:
        a["LoadBalancerNames"] = lbs
    if instances:
        a["Instances"] = instances
    return a


def by_type(findings, ftype):
    return [f for f in findings if f["type"] == ftype]


class AsgTests(unittest.TestCase):
    def test_single_az_high(self):
        findings = RC.audit_asgs([asg(azs=("us-east-1a",), desired=1)])
        f = by_type(findings, "SINGLE_AZ_ASG")[0]
        self.assertEqual(f["severity"], "HIGH")

    def test_multi_az_not_flagged_single_az(self):
        findings = RC.audit_asgs([asg(azs=("us-east-1a", "us-east-1b"))])
        self.assertEqual(by_type(findings, "SINGLE_AZ_ASG"), [])

    def test_no_redundancy_low(self):
        findings = RC.audit_asgs([asg(desired=1, azs=("us-east-1a", "us-east-1b"))])
        f = by_type(findings, "NO_REDUNDANCY")[0]
        self.assertEqual(f["severity"], "LOW")

    def test_desired_two_no_redundancy_finding(self):
        findings = RC.audit_asgs([asg(desired=2)])
        self.assertEqual(by_type(findings, "NO_REDUNDANCY"), [])

    def test_lb_with_ec2_health_check_medium(self):
        findings = RC.audit_asgs([asg(target_groups=["arn:tg/x"], health="EC2")])
        f = by_type(findings, "LB_HEALTH_CHECK_DISABLED")[0]
        self.assertEqual(f["severity"], "MEDIUM")

    def test_lb_with_elb_health_check_clean(self):
        findings = RC.audit_asgs([asg(target_groups=["arn:tg/x"], health="ELB")])
        self.assertEqual(by_type(findings, "LB_HEALTH_CHECK_DISABLED"), [])

    def test_no_lb_ec2_health_check_clean(self):
        findings = RC.audit_asgs([asg(health="EC2")])
        self.assertEqual(by_type(findings, "LB_HEALTH_CHECK_DISABLED"), [])

    def test_seeded_single_az_pinned_asg(self):
        # Mirrors the lab's seeded ASG: one AZ, desired=min=max=1.
        findings = RC.audit_asgs([asg(name="ec2-lab-app-asg", azs=("us-east-1a",), desired=1)])
        kinds = {f["type"] for f in findings}
        self.assertIn("SINGLE_AZ_ASG", kinds)
        self.assertIn("NO_REDUNDANCY", kinds)

    def test_az_fallback_to_instances(self):
        # Empty AvailabilityZones → derive from instances.
        a = asg(azs=(), instances=[{"AvailabilityZone": "us-east-1a"}])
        findings = RC.audit_asgs([a])
        self.assertEqual(len(by_type(findings, "SINGLE_AZ_ASG")), 1)


class TargetHealthTests(unittest.TestCase):
    def test_unhealthy_target_medium(self):
        th = [{"target_group_arn": "arn:aws:.../targetgroup/app/abc",
               "descriptions": [{"Target": {"Id": "i-1"}, "TargetHealth": {"State": "unhealthy"}}]}]
        findings = RC.audit_target_health(th)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["resource_id"], "i-1")

    def test_healthy_target_clean(self):
        th = [{"target_group_arn": "arn:tg", "descriptions": [
            {"Target": {"Id": "i-1"}, "TargetHealth": {"State": "healthy"}}]}]
        self.assertEqual(RC.audit_target_health(th), [])

    def test_draining_flagged(self):
        th = [{"target_group_arn": "arn:tg", "descriptions": [
            {"Target": {"Id": "i-2"}, "TargetHealth": {"State": "draining"}}]}]
        self.assertEqual(len(RC.audit_target_health(th)), 1)


class AuditTests(unittest.TestCase):
    def test_combined_sorted_high_first(self):
        asgs = [asg(name="single", azs=("us-east-1a",), desired=1)]
        th = [{"target_group_arn": "arn:tg", "descriptions": [
            {"Target": {"Id": "i-1"}, "TargetHealth": {"State": "unhealthy"}}]}]
        findings = RC.audit(asgs, th)
        self.assertEqual(findings[0]["severity"], "HIGH")


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class FakeAsgClient:
    def __init__(self, pages):
        self._pages = pages

    def get_paginator(self, name):
        assert name == "describe_auto_scaling_groups"
        return FakePaginator(self._pages)


class FakeElbv2:
    def __init__(self, health_by_arn):
        self._health = health_by_arn

    def describe_target_health(self, TargetGroupArn):
        return {"TargetHealthDescriptions": self._health.get(TargetGroupArn, [])}


class FetchTests(unittest.TestCase):
    def _checker(self, asg_pages, health_by_arn):
        c = RC.__new__(RC)
        c.asg = FakeAsgClient(asg_pages)
        c.elbv2 = FakeElbv2(health_by_arn)
        return c

    def test_fetch_asgs_concatenates(self):
        c = self._checker([{"AutoScalingGroups": [asg("a")]}, {"AutoScalingGroups": [asg("b")]}], {})
        self.assertEqual(len(c.fetch_asgs()), 2)

    def test_fetch_target_health_dedupes(self):
        c = self._checker([], {"arn:tg/x": [{"Target": {"Id": "i-1"},
                                             "TargetHealth": {"State": "healthy"}}]})
        out = c.fetch_target_health(["arn:tg/x", "arn:tg/x"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["target_group_arn"], "arn:tg/x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
