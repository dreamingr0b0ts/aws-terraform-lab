# ──────────────────────────────────────────────────────────────────────────
# compute module — launch template + ASG (app tier), standalone instances,
# bastion, and EBS volumes.
#
# See security_groups.tf for the SG-related seeded findings. Seeded findings in
# this file are tagged `SEEDED FINDING` + `Seeded = "<tool>"`.
# ──────────────────────────────────────────────────────────────────────────

locals {
  app_user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail
    dnf -y install httpd
    systemctl enable --now httpd
    echo "<h1>${var.project} app tier — $(hostname -f)</h1>" > /var/www/html/index.html
  EOF
  )
}

# ════════════════════════════════════════════════════════════════════════════
# APP TIER — Launch Template + Auto Scaling Group (GOOD baseline)
# ════════════════════════════════════════════════════════════════════════════

# GOOD: IMDSv2 required (http_tokens = "required"), encrypted EBS, no public IP.
resource "aws_launch_template" "app" {
  name_prefix   = "${var.project}-app-"
  image_id      = data.aws_ami.al2023.id
  instance_type = var.instance_type
  user_data     = local.app_user_data

  key_name = var.key_name != "" ? var.key_name : null

  vpc_security_group_ids = [aws_security_group.app.id]

  # GOOD: IMDSv2 enforced — tokens required blocks the SSRF/IMDSv1 vector.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # GOOD: encrypted root volume.
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 8
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project}-app"
      Tier = "app"
    }
  }

  tags = {
    Name = "${var.project}-app-lt"
  }
}

# SEEDED FINDING (resilience-checker): ASG pinned to a SINGLE AZ / single private
# subnet, with desired=min=max=1. A resilient ASG spans all private subnets and
# has headroom. This is intentional single-AZ fragility.
resource "aws_autoscaling_group" "app" {
  name = "${var.project}-app-asg"

  # SEEDED FINDING: only the first private subnet → single AZ, no spread.
  vpc_zone_identifier = [var.private_subnet_ids[0]]

  desired_capacity = 1
  min_size         = 1
  max_size         = 1

  health_check_type         = "EC2"
  health_check_grace_period = 60

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project}-app-asg"
    propagate_at_launch = true
  }

  tag {
    key                 = "Seeded"
    value               = "resilience-checker"
    propagate_at_launch = false
  }
}

# NOTE: the ASG↔target-group attachment lives in the alb module (it consumes
# this ASG's name) to keep the module dependency one-directional: compute → alb.

# ════════════════════════════════════════════════════════════════════════════
# BASTION (public SSH host)
# ════════════════════════════════════════════════════════════════════════════

# The instance itself is hardened (IMDSv2 required, encrypted disk). Its EXPOSURE
# is the seeded finding — it sits in a public subnet with a public IP behind the
# world-open bastion-sg (see security_groups.tf). network-reachability composes
# those facts into the verdict.
resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  subnet_id                   = var.public_subnet_ids[0]
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  associate_public_ip_address = true # SEEDED FINDING (network-reachability): public IP + world-open SG
  key_name                    = var.key_name != "" ? var.key_name : null

  # GOOD: even the bastion enforces IMDSv2.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name   = "${var.project}-bastion"
    Tier   = "bastion"
    Seeded = "network-reachability"
  }
}

# ════════════════════════════════════════════════════════════════════════════
# STANDALONE INSTANCES (seeded findings for imds-inspector / right-sizer)
# ════════════════════════════════════════════════════════════════════════════

# SEEDED FINDING (imds-inspector): IMDSv1 allowed (http_tokens = "optional").
# Also seeds an UNENCRYPTED root volume (ebs-hygiene). Lives in a private subnet.
resource "aws_instance" "legacy" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  subnet_id              = var.private_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.app.id]
  key_name               = var.key_name != "" ? var.key_name : null

  # SEEDED FINDING: IMDSv1 permitted — the SSRF credential-theft vector.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # SEEDED FINDING (ebs-hygiene): unencrypted root volume.
  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = false
  }

  tags = {
    Name   = "${var.project}-legacy"
    Tier   = "app"
    Seeded = "imds-inspector,ebs-hygiene"
  }
}

# SEEDED FINDING (right-sizer): oversized instance type for an idle workload.
# An m5.xlarge running a trivial web server is over-provisioned; right-sizer
# should recommend a smaller / Graviton type.
resource "aws_instance" "oversized" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "m5.xlarge" # SEEDED FINDING: oversized
  subnet_id              = var.private_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.app.id]
  key_name               = var.key_name != "" ? var.key_name : null

  # GOOD: this one enforces IMDSv2 (so imds-inspector does NOT flag it — keeps
  # signal-vs-noise honest).
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name   = "${var.project}-oversized"
    Tier   = "app"
    Seeded = "right-sizer"
  }
}

# ════════════════════════════════════════════════════════════════════════════
# EBS — orphaned / unattached volume (ebs-hygiene)
# ════════════════════════════════════════════════════════════════════════════

# SEEDED FINDING (ebs-hygiene): an unattached, unencrypted volume left behind.
resource "aws_ebs_volume" "orphan" {
  availability_zone = var.availability_zones[0]
  size              = 20
  type              = "gp3"
  encrypted         = false # SEEDED FINDING: unencrypted + unattached

  tags = {
    Name   = "${var.project}-orphan-vol"
    Seeded = "ebs-hygiene"
  }
}
