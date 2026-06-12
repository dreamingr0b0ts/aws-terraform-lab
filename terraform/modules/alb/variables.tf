variable "project" {
  description = "Name prefix for ALB resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC the ALB / target group live in."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for the internet-facing ALB (>= 2 AZs)."
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "SG ID for the ALB (created in the compute module)."
  type        = string
}

variable "asg_name" {
  description = "Name of the app-tier ASG to attach to the target group."
  type        = string
}
