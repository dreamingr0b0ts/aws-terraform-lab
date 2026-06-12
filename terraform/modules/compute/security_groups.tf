# ──────────────────────────────────────────────────────────────────────────
# compute module — security groups, launch template + ASG (app tier), a couple
# of standalone instances, and the bastion.
#
# ⚠️  THIS MODULE INTENTIONALLY SEEDS MISCONFIGURATIONS for the analyzers to
#     detect. Every intentional flaw is tagged with a `SEEDED FINDING` comment
#     and a `Seeded = "<tool>"` resource tag. DO NOT "fix" these — they are the
#     proving-ground signal. Everything NOT marked that way is meant to be a
#     hardened, best-practice baseline (the "good" control group).
# ──────────────────────────────────────────────────────────────────────────

# Latest Amazon Linux 2023 AMI (x86_64).
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ════════════════════════════════════════════════════════════════════════════
# SECURITY GROUPS
# ════════════════════════════════════════════════════════════════════════════

# ─── alb-sg (GOOD) ────────────────────────────────────────────────────────────
# Internet-facing on 80/443 only. Created here (not in the alb module) so the
# app tier can reference it without a module dependency cycle.
resource "aws_security_group" "alb" {
  name        = "${var.project}-alb-sg"
  description = "ALB: allow HTTP/HTTPS from the internet"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project}-alb-sg"
    Tier = "alb"
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_all_out" {
  security_group_id = aws_security_group.alb.id
  description       = "All outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ─── app-sg (GOOD) ────────────────────────────────────────────────────────────
# App tier accepts traffic ONLY from the ALB SG (no public exposure), and SSH
# ONLY from the bastion SG. This is the well-configured counter-example.
resource "aws_security_group" "app" {
  name        = "${var.project}-app-sg"
  description = "App tier: traffic from ALB and SSH from bastion only"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project}-app-sg"
    Tier = "app"
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "App HTTP from ALB only"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "app_ssh_from_bastion" {
  security_group_id            = aws_security_group.app.id
  description                  = "SSH from bastion only"
  referenced_security_group_id = aws_security_group.bastion.id
  from_port                    = 22
  to_port                      = 22
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_all_out" {
  security_group_id = aws_security_group.app.id
  description       = "All outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ─── db-sg (GOOD) ─────────────────────────────────────────────────────────────
# DB tier accepts MySQL ONLY from the app SG. No public exposure.
resource "aws_security_group" "db" {
  name        = "${var.project}-db-sg"
  description = "DB tier: MySQL from app tier only"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project}-db-sg"
    Tier = "db"
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "MySQL from app tier only"
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 3306
  to_port                      = 3306
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "db_all_out" {
  security_group_id = aws_security_group.db.id
  description       = "All outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ─── bastion-sg (SEEDED FINDING) ───────────────────────────────────────────────
# SEEDED FINDING (sg-auditor / network-reachability): SSH (22) and RDP (3389)
# open to 0.0.0.0/0. A real bastion should restrict SSH to a known admin CIDR.
# This is intentional so sg-auditor flags CRITICAL world-open admin ports.
resource "aws_security_group" "bastion" {
  name        = "${var.project}-bastion-sg"
  description = "SEEDED FINDING: bastion SSH/RDP open to the world"
  vpc_id      = var.vpc_id

  tags = {
    Name   = "${var.project}-bastion-sg"
    Tier   = "bastion"
    Seeded = "sg-auditor,network-reachability"
  }
}

resource "aws_vpc_security_group_ingress_rule" "bastion_ssh_world" {
  # SEEDED FINDING: 0.0.0.0/0 on port 22.
  security_group_id = aws_security_group.bastion.id
  description       = "SEEDED: SSH open to the world"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "bastion_rdp_world" {
  # SEEDED FINDING: 0.0.0.0/0 on port 3389.
  security_group_id = aws_security_group.bastion.id
  description       = "SEEDED: RDP open to the world"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "bastion_all_out" {
  security_group_id = aws_security_group.bastion.id
  description       = "All outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ─── orphan-sg (SEEDED FINDING) ────────────────────────────────────────────────
# SEEDED FINDING (sg-auditor): a security group attached to nothing. Has a
# broad ingress rule but no ENI references it — the classic forgotten SG.
resource "aws_security_group" "orphan" {
  name        = "${var.project}-orphan-sg"
  description = "SEEDED FINDING: unused/unattached security group"
  vpc_id      = var.vpc_id

  tags = {
    Name   = "${var.project}-orphan-sg"
    Seeded = "sg-auditor"
  }
}

resource "aws_vpc_security_group_ingress_rule" "orphan_wide" {
  # SEEDED FINDING: overly-broad rule on an unused SG.
  security_group_id = aws_security_group.orphan.id
  description       = "SEEDED: broad ingress on an unused SG"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
}
