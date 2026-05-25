# terraform/networking/outputs.tf

output "transit_gateway_id" {
  description = "TGW ID - set as TF_VAR_transit_gateway_id in corporate and security accounts."
  value       = aws_ec2_transit_gateway.main.id
}

output "transit_gateway_arn" {
  description = "TGW ARN."
  value       = aws_ec2_transit_gateway.main.arn
}

output "egress_vpc_id" {
  description = "Egress VPC ID."
  value       = aws_vpc.egress.id
}

output "nat_gateway_public_ips" {
  description = "EIPs attached to NAT Gateways. Add to on-premises firewall allowlists for AWS-originated traffic."
  value       = aws_eip.nat[*].public_ip
}

output "dns_firewall_rule_group_arn" {
  description = "Baseline DNS Firewall rule group ARN. Pass to spoke accounts as TF_VAR_dns_firewall_rule_group_arn - used by aws_route53_resolver_firewall_rule_group_association."
  value       = aws_route53_resolver_firewall_rule_group.baseline.arn
}

output "dns_firewall_rule_group_id" {
  description = "Baseline DNS Firewall rule group ID. Used by the workflow to construct the full ARN for TF_VAR_dns_firewall_rule_group_arn in spoke accounts."
  value       = aws_route53_resolver_firewall_rule_group.baseline.id
}

output "public_subnet_ids" {
  description = "ALB ingress subnet IDs in the egress VPC (one per AZ) -- consumed by the networking-web workspace via remote state. Name retained for backward compatibility; these are the dedicated ALB subnets in the split-tier ingress/egress design."
  value       = aws_subnet.alb[*].id
}

# -- VPN Tunnel Details -----------------------------------------------

output "vpn_tunnel1_address" {
  description = "Outside IP of tunnel 1 - pfSense Remote Gateway field."
  value       = aws_vpn_connection.on_prem.tunnel1_address
}

output "vpn_tunnel1_preshared_key" {
  description = "Pre-shared key for tunnel 1."
  value       = aws_vpn_connection.on_prem.tunnel1_preshared_key
  sensitive   = true
}

output "vpn_tunnel1_cgw_inside_address" {
  description = "Tunnel 1 inside IP for the pfSense side."
  value       = aws_vpn_connection.on_prem.tunnel1_cgw_inside_address
}

output "vpn_tunnel1_vgw_inside_address" {
  description = "Tunnel 1 inside IP for the AWS side."
  value       = aws_vpn_connection.on_prem.tunnel1_vgw_inside_address
}
