variable "region" {
  description = "AWS region to deploy the lab into."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project tag / name prefix for lab resources."
  type        = string
  default     = "ec2-lab"
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "az_count" {
  description = "Number of Availability Zones to spread subnets across."
  type        = number
  default     = 2
}

variable "key_name" {
  description = "Existing EC2 key pair name for SSH access (bastion). Leave empty to skip."
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "Instance type for the app tier."
  type        = string
  default     = "t3.micro"
}

variable "single_nat_gateway" {
  description = "Use one shared NAT gateway (cheaper) instead of one per AZ."
  type        = bool
  default     = true
}
