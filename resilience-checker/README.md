# Resilience Checker

**Flag single-AZ Auto Scaling Groups and health-check gaps.**

Read-only reliability analyzer over Auto Scaling Groups and their load-balancer target health.
High availability on EC2 means spreading across AZs and letting the load balancer (not just the
hypervisor) decide what's healthy — this tool flags where that breaks down.

## Cert domain
Reliability (SAA-C03).

## Usage
```bash
python resilience_checker.py [--profile P] [--region R] [--format text|json] [--fail-on SEVERITY]
```

Examples:
```bash
python resilience_checker.py --region us-east-1
python resilience_checker.py --fail-on HIGH        # CI gate on single-AZ ASGs
python resilience_checker.py --format json | jq '.findings[]'
```

## What it detects

| Finding | Trigger | Severity |
|---------|---------|:--------:|
| `SINGLE_AZ_ASG` | ASG spans fewer than 2 AZs | **HIGH** |
| `LB_HEALTH_CHECK_DISABLED` | ASG behind an ELB/target group but using EC2-only health checks | **MEDIUM** |
| `UNHEALTHY_TARGET` | A registered target is not `healthy` (unhealthy/draining/…) | **MEDIUM** |
| `NO_REDUNDANCY` | Desired capacity < 2 (a single instance, no spare) | **LOW** |

`SINGLE_AZ_ASG` uses the ASG's configured `AvailabilityZones`, falling back to the AZs of its
running instances when that list is empty.

`--fail-on SEVERITY` → **exit code 3** when any finding meets/exceeds the threshold (CI gating).

## Seeded finding it catches in the lab
- `ec2-lab-app-asg` — pinned to a single private subnet with `desired = min = max = 1` →
  **HIGH** `SINGLE_AZ_ASG` + **LOW** `NO_REDUNDANCY`. Fix is to give the ASG subnets in ≥2 AZs and
  raise capacity.

## Required IAM permissions
```
autoscaling:DescribeAutoScalingGroups
elasticloadbalancing:DescribeTargetHealth
```

## Limitations
- Covers Auto Scaling Groups + their target health. Standalone instances pinned to one AZ are not
  evaluated here (an ASG is the unit of EC2 resilience).
- Target health is queried per target group attached to an ASG; target groups not associated with
  any ASG aren't inspected.
- Does not assess RDS Multi-AZ, cross-Region DR, or quorum/stateful-service placement — it's an
  EC2/ASG reliability check, not a whole-architecture review.
- Single region per run.
