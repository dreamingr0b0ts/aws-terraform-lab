# Root outputs — handy values for running the analyzers against the live lab.

output "vpc_id" {
  description = "Lab VPC ID."
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnet IDs."
  value       = module.network.private_subnet_ids
}

output "alb_dns_name" {
  description = "Public DNS name of the ALB (browse the app tier here)."
  value       = module.alb.alb_dns_name
}

output "bastion_public_ip" {
  description = "Bastion public IP (SEEDED: world-open SSH/RDP)."
  value       = module.compute.bastion_public_ip
}

output "asg_name" {
  description = "App-tier Auto Scaling Group name."
  value       = module.compute.asg_name
}

output "seeded_findings" {
  description = "Map of intentional findings → the analyzer that detects each."
  value = {
    sg_open_world_ssh_rdp = "sg-auditor / network-reachability (bastion-sg)"
    unused_security_group = "sg-auditor (orphan-sg)"
    imdsv1_instance       = "imds-inspector (legacy instance)"
    unencrypted_volume    = "ebs-hygiene (legacy root + orphan-vol)"
    orphan_volume         = "ebs-hygiene (orphan-vol)"
    single_az_asg         = "resilience-checker (app-asg)"
    oversized_instance    = "right-sizer (oversized instance)"
    public_bastion        = "network-reachability (bastion)"
  }
}
