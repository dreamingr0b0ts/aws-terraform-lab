# Right-Sizer

**Recommend right-sized or Graviton instances from CloudWatch utilization.**

Read-only cost analyzer. For every running instance it pulls `CPUUtilization` over a look-back
window, flags the ones running well under capacity, and recommends a smaller same-family type
and/or a Graviton (ARM) equivalent — with an estimated monthly on-demand saving.

## Cert domain
Cost optimization (SAA-C03).

## Usage
```bash
python right_sizer.py [--profile P] [--region R] [--format text|json]
                      [--days N] [--cpu-threshold PCT] [--fail-on SEVERITY]
```

Examples:
```bash
python right_sizer.py --region us-east-1 --days 14
python right_sizer.py --cpu-threshold 25 --fail-on MEDIUM   # stricter + CI gate
python right_sizer.py --format json | jq '.findings[].estimated_monthly_savings_usd'
```

## How it decides

An instance is flagged `OVER_PROVISIONED` when its **peak** CPU over the window stays below
`--cpu-threshold` (default 40%). Severity reflects how idle it is:

| Peak CPU | Severity |
|:--:|:--:|
| `< 5%` (effectively idle) | **HIGH** |
| `5–20%` | **MEDIUM** |
| `20%–threshold` | **LOW** |

Recommendation = one size down in the same family (`m5.xlarge → m5.large`); a Graviton equivalent
(`m7g.large`) is offered alongside when the family maps to one. Instances with fewer than
`min_datapoints` (24 hourly points) are skipped — not enough signal to judge.

`--fail-on SEVERITY` → **exit code 3** when any finding meets/exceeds the threshold (CI gating).

## Savings estimate — read this
Savings come from a **built-in static us-east-1 Linux on-demand price table**, not the live AWS
Pricing API. Treat the dollar figures as ballpark study numbers. Types not in the table report
`savings n/a` (the right-sizing recommendation is still made). Real decisions should also weigh
memory/network/disk, RIs/Savings Plans, and architecture-compatibility for Graviton (recompile
needed for some workloads).

## Seeded finding it catches in the lab
- `oversized` instance — an `m5.xlarge` running a trivial web server. Near-idle CPU → flagged
  **HIGH**, recommend `m5.large` (or `m7g.large`), ~$70/mo saving.

## Required IAM permissions
```
ec2:DescribeInstances
cloudwatch:GetMetricStatistics
```

## Limitations
- CPU-only. A right-sizing decision ideally also considers memory (needs the CloudWatch agent),
  network, and EBS throughput. This tool intentionally stays on the metric every instance emits.
- Peak-based: a single short spike above the threshold keeps an otherwise-idle instance unflagged
  (conservative by design — avoids recommending a downsize that would throttle a real burst).
- Static price table (see above); single region per run.
- Does not account for burstable (T-family) CPU credits — a low-CPU `t3` may already be optimal.
