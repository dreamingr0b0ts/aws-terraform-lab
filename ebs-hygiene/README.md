# EBS Hygiene

**Find unattached/unencrypted EBS volumes and stale/orphaned snapshots.**

Read-only cost + resilience analyzer. Idle volumes bill silently, unencrypted volumes are a
data-at-rest risk, and old/orphaned snapshots pile up cost and clutter. This tool surfaces all
four and emits a copy-paste cleanup command for each (it never deletes anything itself).

## Domain
Cost optimization + resilience

## Usage
```bash
python ebs_hygiene.py [--profile P] [--region R] [--format text|json]
                      [--max-snapshot-age DAYS] [--fail-on SEVERITY]
```

Examples:
```bash
python ebs_hygiene.py --region us-east-1
python ebs_hygiene.py --max-snapshot-age 30 --fail-on MEDIUM
python ebs_hygiene.py --format json | jq '.findings[] | select(.type=="UNATTACHED_VOLUME")'
```

## What it detects

| Finding | Trigger | Severity |
|---------|---------|:--------:|
| `UNENCRYPTED_VOLUME` | `Encrypted = false` | **HIGH** |
| `UNATTACHED_VOLUME` | No attachments / `available` state (still billed) | **MEDIUM** |
| `ORPHANED_SNAPSHOT` | Snapshot's source volume no longer exists | **MEDIUM** |
| `STALE_SNAPSHOT` | Snapshot older than `--max-snapshot-age` (default 90 days) | **LOW** |

A snapshot that is both old *and* orphaned is reported once, as the more actionable
`ORPHANED_SNAPSHOT`. Unattached volumes include an estimated monthly cost (gp3 $0.08/GiB-month,
us-east-1 — a study estimate, not the live Pricing API).

`--fail-on SEVERITY` → **exit code 3** when any finding meets/exceeds the threshold (CI gating).

## Seeded findings it catches in the lab
- `legacy` instance root volume — `encrypted = false` → **HIGH** `UNENCRYPTED_VOLUME`.
- `orphan-vol` — a 20 GiB unattached, unencrypted volume → **HIGH** + **MEDIUM** (two findings).

## Required IAM permissions
```
ec2:DescribeVolumes
ec2:DescribeSnapshots
sts:GetCallerIdentity      # scopes snapshot listing to your own account
```

## Limitations
- Snapshot listing is scoped to self-owned snapshots (via the caller's account ID) to avoid
  pulling the entire public/AWS-owned snapshot catalogue.
- "Orphaned" means the source volume is absent in the same region; a snapshot intentionally kept
  for restore/DR will show up — tune with tags/`--max-snapshot-age` and human review before
  deleting.
- Cost figures are a flat gp3 estimate; io1/io2/st1/sc1 and provisioned IOPS pricing differ.
- Single region per run.
