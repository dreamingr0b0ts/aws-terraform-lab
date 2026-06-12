# ──────────────────────────────────────────────────────────────────────────
# alb module — internet-facing Application Load Balancer + target group +
# listener fronting the app-tier ASG.
#
# GOOD baseline: the ALB SG (scoped to 80/443) is created in the compute module
# and passed in here, keeping module dependencies one-directional (compute → alb).
# No intentional findings live here.
# ──────────────────────────────────────────────────────────────────────────

resource "aws_lb" "this" {
  name               = "${var.project}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_security_group_id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true

  tags = {
    Name = "${var.project}-alb"
  }
}

resource "aws_lb_target_group" "app" {
  name     = "${var.project}-app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path                = "/"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${var.project}-app-tg"
  }
}

# HTTP listener. (A production setup would add an HTTPS listener with an ACM
# cert and redirect 80→443; left as HTTP-only for a no-cost study lab.)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Attach the app-tier ASG to the target group (one-directional dependency).
resource "aws_autoscaling_attachment" "app" {
  autoscaling_group_name = var.asg_name
  lb_target_group_arn    = aws_lb_target_group.app.arn
}
