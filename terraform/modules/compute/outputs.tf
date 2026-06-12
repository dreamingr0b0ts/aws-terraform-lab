output "alb_security_group_id" {
  description = "SG ID for the ALB (created here to avoid a module cycle)."
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "SG ID for the app tier."
  value       = aws_security_group.app.id
}

output "db_security_group_id" {
  description = "SG ID for the DB tier."
  value       = aws_security_group.db.id
}

output "bastion_security_group_id" {
  description = "SG ID for the bastion (SEEDED: world-open)."
  value       = aws_security_group.bastion.id
}

output "asg_name" {
  description = "Name of the app-tier Auto Scaling Group."
  value       = aws_autoscaling_group.app.name
}

output "bastion_public_ip" {
  description = "Public IP of the bastion host."
  value       = aws_instance.bastion.public_ip
}

output "bastion_instance_id" {
  description = "Instance ID of the bastion host."
  value       = aws_instance.bastion.id
}

output "legacy_instance_id" {
  description = "Instance ID of the IMDSv1 (SEEDED) instance."
  value       = aws_instance.legacy.id
}

output "oversized_instance_id" {
  description = "Instance ID of the oversized (SEEDED) instance."
  value       = aws_instance.oversized.id
}
