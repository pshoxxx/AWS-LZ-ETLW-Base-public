# terraform/web/outputs.tf

output "vpc_id" {
  description = "ID of the web VPC"
  value       = aws_vpc.main.id
}

output "tgw_attachment_id" {
  description = "Web TGW VPC attachment ID. Pass to the networking account as TF_VAR_web_tgw_attachment_id to complete Phase 3 RT associations."
  value       = aws_ec2_transit_gateway_vpc_attachment.main.id
}

output "endpoint_service_name" {
  description = "VPC Endpoint Service name for the web NLB. Pass to networking account as TF_VAR_web_endpoint_service_name to create the consumer VPC endpoint and ALB in Phase 3."
  value       = aws_vpc_endpoint_service.main.service_name
}

output "aurora_endpoint" {
  description = "Aurora cluster writer endpoint"
  value       = aws_rds_cluster.main.endpoint
}
