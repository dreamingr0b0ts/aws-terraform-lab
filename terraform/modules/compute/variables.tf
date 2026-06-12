variable "project" {
  description = "Name prefix for compute resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC the compute resources live in."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs (bastion lands in the first)."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs (app tier / standalone instances)."
  type        = list(string)
}

variable "availability_zones" {
  description = "AZs matching the subnets (used for the orphan EBS volume)."
  type        = list(string)
}

variable "instance_type" {
  description = "Instance type for the app-tier launch template."
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "Existing EC2 key pair name for SSH. Empty disables key assignment."
  type        = string
  default     = ""
}
