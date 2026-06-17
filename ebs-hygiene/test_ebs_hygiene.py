"""Tests for EBSHygiene classification (no AWS calls).

Run with:  python3 -m pytest ebs-hygiene/test_ebs_hygiene.py
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ebs_hygiene import EBSHygiene  # noqa: E402

NOW = datetime(2026, 6, 12, tzinfo=timezone.utc)


def volume(vid="vol-1", encrypted=True, attached=True, state=None, size=20, name=None):
    v = {
        "VolumeId": vid,
        "Encrypted": encrypted,
        "Size": size,
        "Attachments": [{"InstanceId": "i-1"}] if attached else [],
        "State": state or ("in-use" if attached else "available"),
    }
    if name:
        v["Tags"] = [{"Key": "Name", "Value": name}]
    return v


def snapshot(sid="snap-1", volume_id="vol-1", age_days=10):
    return {
        "SnapshotId": sid,
        "VolumeId": volume_id,
        "StartTime": NOW - timedelta(days=age_days),
    }


def by_type(findings, ftype):
    return [f for f in findings if f["type"] == ftype]


class VolumeTests(unittest.TestCase):
    def test_unencrypted_volume_high(self):
        findings = EBSHygiene.audit_volumes([volume(encrypted=False)])
        f = by_type(findings, "UNENCRYPTED_VOLUME")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "HIGH")

    def test_encrypted_attached_clean(self):
        findings = EBSHygiene.audit_volumes([volume(encrypted=True, attached=True)])
        self.assertEqual(findings, [])

    def test_unattached_volume_medium_with_cost(self):
        findings = EBSHygiene.audit_volumes([volume(attached=False, size=100)])
        f = by_type(findings, "UNATTACHED_VOLUME")[0]
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertAlmostEqual(f["estimated_monthly_cost_usd"], 8.0, places=2)  # 100 * 0.08

    def test_unencrypted_and_unattached_two_findings(self):
        findings = EBSHygiene.audit_volumes([volume(encrypted=False, attached=False)])
        kinds = {f["type"] for f in findings}
        self.assertEqual(kinds, {"UNENCRYPTED_VOLUME", "UNATTACHED_VOLUME"})

    def test_available_state_counts_as_unattached(self):
        findings = EBSHygiene.audit_volumes([volume(attached=True, state="available")])
        self.assertEqual(len(by_type(findings, "UNATTACHED_VOLUME")), 1)


class SnapshotTests(unittest.TestCase):
    def test_orphaned_snapshot_flagged(self):
        snaps = [snapshot(volume_id="vol-gone")]
        findings = EBSHygiene.audit_snapshots(snaps, volume_ids={"vol-1"}, max_age_days=90, now=NOW)
        f = by_type(findings, "ORPHANED_SNAPSHOT")[0]
        self.assertEqual(f["severity"], "MEDIUM")

    def test_snapshot_with_live_source_not_orphaned(self):
        snaps = [snapshot(volume_id="vol-1", age_days=5)]
        findings = EBSHygiene.audit_snapshots(snaps, volume_ids={"vol-1"}, max_age_days=90, now=NOW)
        self.assertEqual(findings, [])

    def test_stale_snapshot_low(self):
        snaps = [snapshot(volume_id="vol-1", age_days=200)]
        findings = EBSHygiene.audit_snapshots(snaps, volume_ids={"vol-1"}, max_age_days=90, now=NOW)
        f = by_type(findings, "STALE_SNAPSHOT")[0]
        self.assertEqual(f["severity"], "LOW")
        self.assertEqual(f["age_days"], 200)

    def test_orphaned_takes_precedence_over_stale(self):
        # Old AND orphaned → reported once as the more actionable ORPHANED.
        snaps = [snapshot(volume_id="vol-gone", age_days=300)]
        findings = EBSHygiene.audit_snapshots(snaps, volume_ids={"vol-1"}, max_age_days=90, now=NOW)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "ORPHANED_SNAPSHOT")

    def test_string_timestamp_parsed(self):
        snaps = [{"SnapshotId": "snap-x", "VolumeId": "vol-1", "StartTime": "2025-01-01T00:00:00Z"}]
        findings = EBSHygiene.audit_snapshots(snaps, volume_ids={"vol-1"}, max_age_days=90, now=NOW)
        self.assertEqual(findings[0]["type"], "STALE_SNAPSHOT")


class AuditTests(unittest.TestCase):
    def test_combined_sorted_high_first(self):
        volumes = [volume(vid="vol-1", encrypted=False, attached=False)]
        snaps = [snapshot(sid="snap-1", volume_id="vol-1", age_days=200)]
        findings = EBSHygiene.audit(volumes, snaps, max_age_days=90, now=NOW)
        self.assertEqual(findings[0]["severity"], "HIGH")  # unencrypted volume first


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class FakeEc2:
    def __init__(self, vol_pages, snap_pages):
        self._map = {"describe_volumes": vol_pages, "describe_snapshots": snap_pages}

    def get_paginator(self, name):
        return FakePaginator(self._map[name])


class FetchTests(unittest.TestCase):
    def _hygiene(self, vol_pages, snap_pages):
        h = EBSHygiene.__new__(EBSHygiene)
        h.ec2 = FakeEc2(vol_pages, snap_pages)
        h._account_id = "111122223333"
        return h

    def test_fetch_concatenates(self):
        h = self._hygiene(
            vol_pages=[{"Volumes": [volume("vol-1")]}, {"Volumes": [volume("vol-2")]}],
            snap_pages=[{"Snapshots": [snapshot("snap-1")]}],
        )
        self.assertEqual(len(h.fetch_volumes()), 2)
        self.assertEqual(len(h.fetch_snapshots("111122223333")), 1)


class FakeSts:
    def __init__(self, account_id):
        self._account_id = account_id

    def get_caller_identity(self):
        return {"Account": self._account_id}


class FakeSession:
    """Minimal session double recording which clients were requested."""

    def __init__(self, account_id="999988887777"):
        self._account_id = account_id
        self.clients_requested = []

    def client(self, name, **kwargs):
        self.clients_requested.append(name)
        if name == "sts":
            return FakeSts(self._account_id)
        return FakeEc2([], [])


class SessionScopingTests(unittest.TestCase):
    def test_account_id_uses_injected_session(self):
        # account_id must resolve via the SAME session (honoring --profile/--region),
        # not a fresh default boto3.Session().
        sess = FakeSession(account_id="123456789012")
        hygiene = EBSHygiene(session=sess)
        self.assertEqual(hygiene.account_id(), "123456789012")
        self.assertIn("sts", sess.clients_requested)

    def test_account_id_cached(self):
        sess = FakeSession(account_id="123456789012")
        hygiene = EBSHygiene(session=sess)
        hygiene.account_id()
        hygiene.account_id()
        # sts client created once; ec2 was created in __init__.
        self.assertEqual(sess.clients_requested.count("sts"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
