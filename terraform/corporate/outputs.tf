output "vpc_id" {
  description = "ID of the corporate VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the corporate VPC"
  value       = aws_vpc.main.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the two private subnets"
  value       = aws_subnet.private[*].id
}

output "tgw_attachment_id" {
  description = "Corporate TGW VPC attachment ID. Pass to the networking account as TF_VAR_corporate_tgw_attachment_id to complete Phase 3 RT associations."
  value       = aws_ec2_transit_gateway_vpc_attachment.main.id
}

output "dc_instance_id" {
  description = "Domain controller instance ID"
  value       = aws_instance.dc.id
}

output "dc_private_ip" {
  description = "Domain controller private IP - needed for DNS server config on other DCs"
  value       = aws_instance.dc.private_ip
}

output "ad_resolver_rule_id" {
  description = "Route 53 Resolver forwarding rule ID for the AD domain. Created by terraform-identity.yaml after DC promotion. Null when identity_enabled=false."
  value       = try(aws_route53_resolver_rule.ad_forward[0].id, null)
}