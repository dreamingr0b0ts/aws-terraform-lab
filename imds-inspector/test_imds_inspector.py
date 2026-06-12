"""Tests for IMDSInspector classification logic (no AWS calls).

Run with:  python3 -m pytest imds-inspector/test_imds_inspector.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from imds_inspector import IMDSInspector  # noqa: E402


def instance(iid="i-1", tokens="optional", endpoint="enabled", role=False,
             public_ip=None, state="running", hop=1, name=None):
    inst = {
        "InstanceId": iid,
        "State": {"Name": state},
        "MetadataOptions": {
            "HttpTokens": tokens,
            "HttpEndpoint": endpoint,
            "HttpPutResponseHopLimit": hop,
        },
    }
    if role:
        inst["IamInstanceProfile"] = {"Arn": "arn:aws:iam::111122223333:instance-profile/app"}
    if public_ip:
        inst["PublicIpAddress"] = public_ip
    if name:
        inst["Tags"] = [{"Key": "Name", "Value": name}]
    return inst


class ClassificationTests(unittest.TestCase):
    def test_imdsv2_required_not_flagged(self):
        findings = IMDSInspector.audit([instance(tokens="required")])
        self.assertEqual(findings, [])

    def test_endpoint_disabled_not_flagged(self):
        findings = IMDSInspector.audit([instance(tokens="optional", endpoint="disabled")])
        self.assertEqual(findings, [])

    def test_imdsv1_optional_is_flagged(self):
        findings = IMDSInspector.audit([instance(tokens="optional")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "IMDSV1_ALLOWED")

    def test_role_plus_public_ip_is_critical(self):
        findings = IMDSInspector.audit([instance(role=True, public_ip="1.2.3.4")])
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_role_only_is_high(self):
        findings = IMDSInspector.audit([instance(role=True)])
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_public_ip_only_is_medium(self):
        findings = IMDSInspector.audit([instance(public_ip="1.2.3.4")])
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_internal_no_role_is_low(self):
        findings = IMDSInspector.audit([instance()])
        self.assertEqual(findings[0]["severity"], "LOW")

    def test_terminated_instance_skipped(self):
        findings = IMDSInspector.audit([instance(state="terminated")])
        self.assertEqual(findings, [])

    def test_name_tag_extracted(self):
        findings = IMDSInspector.audit([instance(name="legacy")])
        self.assertEqual(findings[0]["name"], "legacy")

    def test_remediation_targets_instance(self):
        findings = IMDSInspector.audit([instance(iid="i-abc")])
        self.assertIn("i-abc", findings[0]["remediation"])
        self.assertIn("--http-tokens required", findings[0]["remediation"])

    def test_sorted_critical_first(self):
        findings = IMDSInspector.audit([
            instance(iid="i-low"),
            instance(iid="i-crit", role=True, public_ip="1.2.3.4"),
        ])
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["instance_id"], "i-crit")

    def test_default_metadata_options_assumed_v1(self):
        # An instance with no MetadataOptions defaults to endpoint enabled + v1.
        inst = {"InstanceId": "i-x", "State": {"Name": "running"}}
        findings = IMDSInspector.audit([inst])
        self.assertEqual(len(findings), 1)


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class FakeEc2:
    def __init__(self, pages):
        self._pages = pages

    def get_paginator(self, name):
        assert name == "describe_instances"
        return FakePaginator(self._pages)


class FetchTests(unittest.TestCase):
    def _inspector(self, pages):
        i = IMDSInspector.__new__(IMDSInspector)
        i.ec2 = FakeEc2(pages)
        return i

    def test_fetch_flattens_reservations_and_pages(self):
        pages = [
            {"Reservations": [{"Instances": [instance(iid="i-1")]},
                              {"Instances": [instance(iid="i-2")]}]},
            {"Reservations": [{"Instances": [instance(iid="i-3")]}]},
        ]
        insp = self._inspector(pages)
        got = insp.fetch_instances()
        self.assertEqual({i["InstanceId"] for i in got}, {"i-1", "i-2", "i-3"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
