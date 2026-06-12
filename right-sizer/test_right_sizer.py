"""Tests for RightSizer logic + helpers (no AWS calls).

Run with:  python3 -m pytest right-sizer/test_right_sizer.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from right_sizer import (  # noqa: E402
    RightSizer,
    downsize,
    graviton_equiv,
    monthly_savings,
    split_type,
)


def record(iid="i-1", itype="m5.xlarge", cpu_max=3.0, cpu_avg=1.5, datapoints=300, name=""):
    return {
        "instance_id": iid,
        "instance_type": itype,
        "name": name,
        "cpu_max": cpu_max,
        "cpu_avg": cpu_avg,
        "datapoints": datapoints,
    }


class HelperTests(unittest.TestCase):
    def test_split_type(self):
        self.assertEqual(split_type("m5.xlarge"), ("m5", "xlarge"))
        self.assertEqual(split_type("garbage"), (None, None))

    def test_downsize_one_notch(self):
        self.assertEqual(downsize("m5.xlarge"), "m5.large")
        self.assertEqual(downsize("t3.medium"), "t3.small")

    def test_downsize_smallest_returns_none(self):
        self.assertIsNone(downsize("t3.nano"))

    def test_graviton_equiv(self):
        self.assertEqual(graviton_equiv("m5.xlarge"), "m7g.xlarge")
        self.assertEqual(graviton_equiv("t3.large"), "t4g.large")

    def test_graviton_equiv_unknown_family(self):
        self.assertIsNone(graviton_equiv("x1.large"))

    def test_monthly_savings_known_prices(self):
        # m5.xlarge 0.192 → m5.large 0.096 = 0.096/hr * 730 = 70.08
        self.assertAlmostEqual(monthly_savings("m5.xlarge", "m5.large"), 70.08, places=2)

    def test_monthly_savings_unknown_price_is_none(self):
        self.assertIsNone(monthly_savings("m5.xlarge", "z9.weird"))


class AnalyzeTests(unittest.TestCase):
    def test_idle_instance_flagged_high(self):
        findings = RightSizer.analyze([record(cpu_max=3.0)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["recommended_type"], "m5.large")

    def test_mid_utilization_is_medium(self):
        findings = RightSizer.analyze([record(cpu_max=12.0)])
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_mild_over_provisioning_is_low(self):
        findings = RightSizer.analyze([record(cpu_max=30.0)])
        self.assertEqual(findings[0]["severity"], "LOW")

    def test_busy_instance_not_flagged(self):
        findings = RightSizer.analyze([record(cpu_max=75.0)])
        self.assertEqual(findings, [])

    def test_threshold_boundary_not_flagged(self):
        # Exactly at threshold (40) → not flagged (must be below).
        findings = RightSizer.analyze([record(cpu_max=40.0)])
        self.assertEqual(findings, [])

    def test_insufficient_datapoints_skipped(self):
        findings = RightSizer.analyze([record(datapoints=5)])
        self.assertEqual(findings, [])

    def test_savings_estimate_present(self):
        findings = RightSizer.analyze([record(itype="m5.xlarge", cpu_max=2.0)])
        self.assertAlmostEqual(findings[0]["estimated_monthly_savings_usd"], 70.08, places=2)

    def test_graviton_alternative_offered(self):
        findings = RightSizer.analyze([record(itype="m5.xlarge", cpu_max=2.0)])
        # downsized m5.large → graviton equiv m7g.large
        self.assertEqual(findings[0]["graviton_alternative"], "m7g.large")

    def test_custom_threshold(self):
        # With a low threshold, a 30% instance is no longer flagged.
        findings = RightSizer.analyze([record(cpu_max=30.0)], cpu_threshold=20.0)
        self.assertEqual(findings, [])

    def test_sorted_high_first(self):
        findings = RightSizer.analyze([
            record(iid="i-low", cpu_max=30.0),
            record(iid="i-high", cpu_max=2.0),
        ])
        self.assertEqual(findings[0]["instance_id"], "i-high")


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


class FakeCw:
    def __init__(self, datapoints):
        self._datapoints = datapoints

    def get_metric_statistics(self, **kwargs):
        return {"Datapoints": self._datapoints}


class FetchTests(unittest.TestCase):
    def _sizer(self, pages, datapoints):
        s = RightSizer.__new__(RightSizer)
        s.ec2 = FakeEc2(pages)
        s.cw = FakeCw(datapoints)
        return s

    def test_build_records_combines_metadata_and_stats(self):
        pages = [{"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "InstanceType": "m5.xlarge",
             "Tags": [{"Key": "Name", "Value": "oversized"}]},
        ]}]}]
        dps = [{"Average": 2.0, "Maximum": 4.0}, {"Average": 3.0, "Maximum": 5.0}]
        sizer = self._sizer(pages, dps)
        records = sizer.build_records(sizer.fetch_instances(), days=14)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["name"], "oversized")
        self.assertEqual(records[0]["cpu_max"], 5.0)
        self.assertEqual(records[0]["datapoints"], 2)

    def test_no_datapoints_yields_zero(self):
        pages = [{"Reservations": [{"Instances": [{"InstanceId": "i-1", "InstanceType": "t3.micro"}]}]}]
        sizer = self._sizer(pages, [])
        records = sizer.build_records(sizer.fetch_instances(), days=14)
        self.assertEqual(records[0]["datapoints"], 0)
        self.assertIsNone(records[0]["cpu_max"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
