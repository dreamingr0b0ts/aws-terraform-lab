# ──────────────────────────────────────────────────────────────────────────
# network module — VPC, public/private subnets across AZs, IGW, NAT, routing,
# and a custom (hardened) network ACL.
#
# This module is the "good citizen" of the lab: it is deliberately configured
# to best practice so the analyzers can distinguish signal (the seeded findings
# in modules/compute) from noise. There are NO intentional misconfigurations
# here.
# ──────────────────────────────────────────────────────────────────────────

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Slice the requested number of AZs.
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Deterministic /24 subnets carved from the VPC CIDR.
  #   public  subnets: x.x.0.0/24, x.x.1.0/24, ...
  #   private subnets: x.x.10.0/24, x.x.11.0/24, ...
  public_subnets  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnets = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 10)]
}

# ─── VPC ────────────────────────────────────────────────────────────────────
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project}-vpc"
  }
}

# ─── Internet Gateway ─────────────────────────────────────────────────────────
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project}-igw"
  }
}

# ─── Subnets ──────────────────────────────────────────────────────────────────
resource "aws_subnet" "public" {
  count = var.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.public_subnets[count.index]
  availability_zone = local.azs[count.index]

  # Public subnets auto-assign public IPs (this tier is meant to be internet-facing).
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project}-public-${local.azs[count.index]}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count = var.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.private_subnets[count.index]
  availability_zone = local.azs[count.index]

  # Private subnets must NOT auto-assign public IPs.
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-private-${local.azs[count.index]}"
    Tier = "private"
  }
}

# ─── NAT Gateway ──────────────────────────────────────────────────────────────
# Cost note: one NAT GW per AZ is the resilient choice but doubles cost. The lab
# defaults to a single shared NAT GW (var.single_nat_gateway = true) to keep
# study costs down; set it to false for true multi-AZ egress.
locals {
  nat_count = var.single_nat_gateway ? 1 : var.az_count
}

resource "aws_eip" "nat" {
  count  = local.nat_count
  domain = "vpc"

  tags = {
    Name = "${var.project}-nat-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "this" {
  count = local.nat_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.project}-nat-${count.index}"
  }

  depends_on = [aws_internet_gateway.this]
}

# ─── Route tables ─────────────────────────────────────────────────────────────
# Public route table: default route to the IGW.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project}-public-rt"
  }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private route tables: default route to a NAT gateway (one per AZ, or all to the
# single shared NAT GW).
resource "aws_route_table" "private" {
  count  = var.az_count
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project}-private-rt-${local.azs[count.index]}"
  }
}

resource "aws_route" "private_default" {
  count                  = var.az_count
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[var.single_nat_gateway ? 0 : count.index].id
}

resource "aws_route_table_association" "private" {
  count          = var.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ─── Custom Network ACL (defense in depth on the private subnets) ──────────────
# NACLs are stateless, so we must allow ephemeral return traffic explicitly.
# This is a hardened baseline: allow intra-VPC traffic + ephemeral return, deny
# the rest implicitly.
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.project}-private-nacl"
  }
}

# Inbound: allow all traffic originating inside the VPC (app<->db, bastion->app).
resource "aws_network_acl_rule" "private_in_vpc" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
}

# Inbound: allow ephemeral ports for return traffic from the internet (via NAT).
resource "aws_network_acl_rule" "private_in_ephemeral" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Outbound: allow all (egress to internet via NAT for updates, etc.).
resource "aws_network_acl_rule" "private_out_all" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
