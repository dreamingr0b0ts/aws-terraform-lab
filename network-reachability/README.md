# Network Reachability

**"What can reach this instance?" — compose SG + NACL + route table + public IP into a verdict.**

The EC2 analog of an IAM blast-radius tool, and the showpiece of the suite. A single open security
group does *not* mean an instance is exposed — the traffic also has to survive routing and the
(stateless) NACL. This tool composes all four layers and only reports an instance as reachable
when every one of them lines up:

```
public IP  →  subnet routes 0.0.0.0/0 to an IGW  →  a security group allows the
world inbound on a port  →  the NACL allows that port inbound AND allows the
ephemeral return traffic outbound
```

## Cert domain
Security + Networking (SCS / Advanced Networking).

## Usage
```bash
python network_reachability.py [--profile P] [--region R] [--format text|json] [--fail-on SEVERITY]
```

Examples:
```bash
python network_reachability.py --region us-east-1
python network_reachability.py --fail-on HIGH         # CI gate on real exposure
python network_reachability.py --format json | jq '.findings[].exposed_ports'
```

## What it reports

Each reachable instance gets an `INTERNET_EXPOSED` finding listing the exposed ports, the verdict
path, and a severity set by the worst exposed port:

| Reachable on | Severity |
|--------------|:--------:|
| SSH(22) / RDP(3389) | **CRITICAL** |
| Any port (SG opens all ports + path allows) | **CRITICAL** |
| Database / admin port (3306, 5432, 1433, 1521, 5439, 27017, 6379, 11211, 9200, 2049) | **HIGH** |
| Non-web alt ports (8080, 8443) | **MEDIUM** |
| Web (80/443) | **LOW** |

The power is in the *negatives*: an instance with a world-open SSH SG but sitting in a private
subnet (no IGW route), or behind a deny-ing NACL, or with no public IP, is correctly reported as
**not** reachable — no false alarm.

`--fail-on SEVERITY` → **exit code 3** when any finding meets/exceeds the threshold (CI gating).

## Seeded finding it catches in the lab
- `bastion` — public IP, public subnet (IGW route), `bastion-sg` open to `0.0.0.0/0` on 22+3389,
  default allow-all NACL → **CRITICAL**, exposed on SSH + RDP.
- The `legacy`, `oversized`, and ASG app instances live in private subnets with no public IP →
  correctly reported as not reachable (signal-vs-noise check).

## Required IAM permissions
```
ec2:DescribeInstances
ec2:DescribeSecurityGroups
ec2:DescribeRouteTables
ec2:DescribeNetworkAcls
ec2:DescribeSubnets
```

## Limitations
- Models **direct** internet reachability (public IP + IGW). It does not yet trace exposure via an
  ALB/NLB target, VPC peering, Transit Gateway, VPN, or PrivateLink — an instance behind a public
  ALB shows as not-directly-reachable even though the service is public.
- IPv4 `0.0.0.0/0` only; IPv6 (`::/0`) and prefix-list rules are not yet evaluated.
- NACL evaluation assumes TCP and a representative ephemeral return port (50000). Non-standard
  ephemeral ranges or UDP-only services are not modeled.
- Single region per run. This is a study/triage tool — for authoritative path analysis use the
  VPC Reachability Analyzer.
