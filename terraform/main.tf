# Root composition for the EC2 lab.
#
# Wires the three modules together: network → compute → alb.
#
#   1. modules/network   — VPC, subnets (2 AZs), IGW, NAT, route tables, NACL
#   2. modules/compute   — security groups, launch template + ASG, standalone
#                          instances, bastion. SEEDS the intentional findings.
#   3. modules/alb       — ALB + target group + listener, attaches the ASG.
#
# ⚠️  The compute module intentionally seeds misconfigurations (world-open SG,
#     IMDSv1 instance, unencrypted/orphan EBS, single-AZ ASG, oversized type).
#     They are clearly labeled with `SEEDED FINDING` comments. See
#     terraform/README.md for the full catalogue and which tool detects each.
#
# Cost warning: applying this creates a NAT gateway, an ALB, and several EC2
# instances (including an m5.xlarge). Use a sandbox account and `terraform
# destroy` when done. Do NOT apply without reviewing cost.

module "network" {
  source = "./modules/network"

  project            = var.project
  vpc_cidr           = var.vpc_cidr
  az_count           = var.az_count
  single_nat_gateway = var.single_nat_gateway
}

module "compute" {
  source = "./modules/compute"

  project            = var.project
  vpc_id             = module.network.vpc_id
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids
  availability_zones = module.network.availability_zones
  instance_type      = var.instance_type
  key_name           = var.key_name
}

module "alb" {
  source = "./modules/alb"

  project               = var.project
  vpc_id                = module.network.vpc_id
  public_subnet_ids     = module.network.public_subnet_ids
  alb_security_group_id = module.compute.alb_security_group_id
  asg_name              = module.compute.asg_name
}
