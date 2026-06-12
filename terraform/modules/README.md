# Terraform modules

Three modules, composed in `../main.tf` as `network → compute → alb`. Each exposes clean outputs
the next consumes.

- **network/** — VPC, IGW, single shared (or per-AZ) NAT gateway, public + per-AZ private route
  tables, and a custom stateless NACL on the private subnets. Hardened baseline, no intentional
  findings. Outputs: `vpc_id`, `vpc_cidr`, `public_subnet_ids`, `private_subnet_ids`,
  `availability_zones`.
- **compute/** — tiered security groups (`alb-sg`, `app-sg`, `db-sg`, `bastion-sg`), an
  IMDSv2-enforcing launch template + Auto Scaling Group, the bastion, two standalone instances, and
  an orphan EBS volume. **Seeds the intentional findings** — see the table in `../README.md`. Each
  flaw is labeled with a `SEEDED FINDING` comment and a `Seeded` tag. Outputs: `asg_name`, the
  security group IDs, and instance IDs/IPs.
- **alb/** — internet-facing ALB + target group + HTTP listener, and the ASG→target-group
  attachment (kept here to avoid a module dependency cycle). Output: `alb_dns_name`, `alb_arn`,
  `target_group_arn`.

The `alb-sg` security group is created in **compute/** (not alb/) and passed into the alb module so
the app tier can reference it without a `compute ↔ alb` cycle.
