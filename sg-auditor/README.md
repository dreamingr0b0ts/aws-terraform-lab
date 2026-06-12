# Security Group Auditor

**Audit EC2 security groups for risky and unused rules.**

Read-only analyzer that flags ingress rules open to the world (`0.0.0.0/0` / `::/0`) on sensitive
ports, all-traffic-open rules, and security groups that nothing uses. It maps each SG to its ENI
usage (via `describe_network_interfaces`) and also treats an SG as "in use" if another SG
references it, so cross-SG references aren't false-flagged as orphans.

## Cert domain
Security (SCS), with SysOps (SOA) overlap.

## Usage
```bash
python sg_auditor.py [--profile P] [--region R] [--format text|json] [--fail-on SEVERITY]
```

Examples:
```bash
# Human-readable audit of us-east-1
python sg_auditor.py --region us-east-1

# CI gate: non-zero exit (3) if anything HIGH or worse is found
python sg_auditor.py --region us-east-1 --fail-on HIGH

# Machine-readable for piping into jq / dashboards
python sg_auditor.py --format json
```

## What it detects

| Finding type | Trigger | Severity |
|--------------|---------|:--------:|
| `WORLD_OPEN_SENSITIVE_PORT` | `0.0.0.0/0`/`::/0` reaches SSH(22) or RDP(3389) | **CRITICAL** |
| `WORLD_OPEN_SENSITIVE_PORT` | `0.0.0.0/0`/`::/0` reaches a DB / admin port (3306, 5432, 1433, 1521, 5439, 27017, 6379, 11211, 9200, 2049, 5985/6) | **HIGH** |
| `WORLD_OPEN_ALL_PORTS` | All ports/protocols (`-1` or `0-65535`) open to the world | **CRITICAL** |
| `WORLD_OPEN_PORT` | World-open on a non-sensitive, non-web port | **MEDIUM** |
| `WORLD_OPEN_PORT` | World-open on a web port (80/443) — informational | **LOW** |
| `UNUSED_SECURITY_GROUP` | SG used by no ENI and referenced by no other SG (the `default` SG is ignored) | **MEDIUM** |

A port *range* that spans a sensitive port (e.g. `20-30` covering SSH) is flagged for that port.

## Severity model + CI gating
Findings carry `LOW | MEDIUM | HIGH | CRITICAL`. `--fail-on SEVERITY` returns **exit code 3** when
any finding meets or exceeds the threshold (other non-zero = error, `0` = clean). Read-only by
default; this tool never mutates AWS.

## Seeded findings it catches in the lab
- `bastion-sg` — SSH(22) + RDP(3389) open to `0.0.0.0/0` → two CRITICALs.
- `orphan-sg` — unattached, unreferenced, with a broad `8080` rule → `UNUSED_SECURITY_GROUP` +
  `WORLD_OPEN_PORT`.
- `alb-sg` — world-open 80/443 → two LOWs (expected for an internet-facing ALB; signal-vs-noise check).

## Required IAM permissions
Read-only:
```
ec2:DescribeSecurityGroups
ec2:DescribeNetworkInterfaces
```

## Limitations
- Single region per run (EC2 is regional). Loop over `--region` for an account-wide sweep.
- "Unused" is scoped to ENI attachment + SG-to-SG references. An SG referenced only from a
  launch template / config that has never launched an ENI may still show as unused.
- Egress rules are read (for reference detection) but not classified as findings; the focus is
  inbound exposure.
- Prefix-list-based rules are not expanded to member CIDRs.
