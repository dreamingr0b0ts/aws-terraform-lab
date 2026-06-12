# Terraform Lab — EC2 proving ground

The environment the analyzer tools run against, and your hands-on IaC practice. **Fully built and
`terraform validate`-clean** — three modules (`network → compute → alb`) wired together in
`main.tf`, with the intentional findings seeded and clearly labeled.

## What it provisions

A two-AZ, multi-tier setup:

- **network module** — VPC (`10.20.0.0/16`), 2 public + 2 private subnets across 2 AZs, IGW, a
  cost-conscious single shared NAT gateway (toggle with `single_nat_gateway = false` for one per
  AZ), public + per-AZ private route tables, and a custom stateless NACL on the private subnets.
  This module is the hardened "good citizen" — no intentional flaws.
- **compute module** — an IMDSv2-enforcing launch template + Auto Scaling Group (app tier) in
  private subnets, a public bastion, two standalone instances, tiered security groups
  (`alb-sg`, `app-sg`, `db-sg`, `bastion-sg`), and an orphan EBS volume. **This module seeds the
  intentional findings** (see below).
- **alb module** — an internet-facing Application Load Balancer + target group + HTTP listener
  fronting the ASG. The ASG→target-group attachment lives here so module dependencies stay
  one-directional (`compute → alb`, no cycle).

## Seeded findings (intentional — each is clearly labeled)

Every intentional flaw carries a `SEEDED FINDING` comment **and** a `Seeded = "<tool>"` resource
tag, so it's never mistaken for accidental insecure code. The root `outputs.tf` also publishes a
`seeded_findings` map.

| Seeded misconfiguration | Resource | Detected by |
|-------------------------|----------|-------------|
| SG allowing `0.0.0.0/0` on ports 22 + 3389 | `bastion-sg` | `sg-auditor`, `network-reachability` |
| Unused / unattached security group | `orphan-sg` (ingress 8080) | `sg-auditor` |
| Instance with `http_tokens = "optional"` (IMDSv1) | `legacy` instance | `imds-inspector` |
| Unencrypted root volume + an unattached unencrypted volume | `legacy` root + `orphan-vol` | `ebs-hygiene` |
| ASG pinned to a single AZ with `desired=min=max=1` | `app-asg` | `resilience-checker` |
| Oversized instance type running near-idle | `oversized` (`m5.xlarge`) | `right-sizer` |
| Bastion with a public IP reachable from `0.0.0.0/0` | `bastion` instance | `network-reachability` |

The "good" resources are correctly configured (IMDSv2 required, encrypted volumes, SGs scoped to
peer SGs, no public IPs on the app tier) so the tools can distinguish signal from noise.

## Layout

```
terraform/
├── versions.tf      # terraform + provider version pins
├── providers.tf     # AWS provider, region, default tags
├── variables.tf     # inputs (region, cidr, az_count, key_name, instance_type, single_nat_gateway)
├── main.tf          # root composition (wires network → compute → alb)
├── outputs.tf       # vpc/subnets, alb_dns_name, bastion_public_ip, asg_name, seeded_findings map
└── modules/
    ├── network/     # VPC, subnets, IGW, NAT, route tables, NACL (hardened)
    ├── compute/     # SGs, launch template + ASG, bastion, standalone instances, EBS (seeds findings)
    └── alb/         # ALB, target group, listener, ASG attachment
```

## Usage

```bash
cd terraform
terraform init
terraform fmt -recursive          # keep CI's fmt -check happy
terraform validate
terraform plan  -var="key_name=my-keypair"
terraform apply -var="key_name=my-keypair"
# ... run the analyzers against the live lab ...
terraform destroy -var="key_name=my-keypair"   # tear down to stop billing
```

`key_name` is optional — leave it unset to skip SSH key assignment (the lab still applies).

## Validate the toolkit end-to-end (optional, billable)

Once applied, point each analyzer at the lab to watch the seeded findings light up, e.g.:

```bash
python ../sg-auditor/sg_auditor.py --region us-east-1                 # bastion-sg + orphan-sg
python ../imds-inspector/imds_inspector.py --region us-east-1         # legacy instance
python ../network-reachability/network_reachability.py --region us-east-1  # bastion exposure
python ../resilience-checker/resilience_checker.py --region us-east-1 # single-AZ app-asg
python ../ebs-hygiene/ebs_hygiene.py --region us-east-1               # unencrypted + orphan vols
python ../right-sizer/right_sizer.py --region us-east-1 --days 14     # oversized m5.xlarge
```

`right-sizer` needs a few hours of CloudWatch data before the oversized instance shows as idle.

> **Cost warning:** the NAT gateway, ALB, and EC2 instances (including an `m5.xlarge`) are billable.
> Use a sandbox account, `terraform destroy` when done, and set a budget alarm. Set
> `single_nat_gateway = true` (the default) to keep NAT cost to one gateway.
