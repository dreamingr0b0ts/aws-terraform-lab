output "alb_dns_name" {
  description = "Public DNS name of the ALB."
  value       = aws_lb.this.dns_name
}

output "alb_arn" {
  description = "ARN of the ALB."
  value       = aws_lb.this.arn
}

output "target_group_arn" {
  description = "ARN of the app target group."
  value       = aws_lb_target_group.app.arn
}
