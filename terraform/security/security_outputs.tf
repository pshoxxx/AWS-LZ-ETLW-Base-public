# terraform/security/siem_outputs.tf
# New outputs added for the SIEM stack.
# The base outputs (vpc_id, vpc_cidr, etc.) remain in outputs.tf.

output "siem_sns_topic_arn" {
  description = "ARN of the SIEM alerts SNS topic in the security account."
  value       = aws_sns_topic.siem_alerts.arn
}

output "siem_lambda_name" {
  description = "Name of the SIEM detector Lambda function. Invoke manually for on-demand detection runs."
  value       = aws_lambda_function.siem_detector.function_name
}

output "monitoring_sink_arn" {
  description = "ARN of the central OAM sink in the security account. Source accounts (networking, corporate, web) create aws_oam_link resources pointing at this ARN so their CloudWatch metrics + logs become visible in security's dashboards."
  value       = aws_oam_sink.central.arn
}

output "monitoring_sink_id" {
  description = "ID portion of the OAM sink. Convenience output for consumers that need the bare ID."
  value       = aws_oam_sink.central.id
}
