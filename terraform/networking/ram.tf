# terraform/networking/ram.tf
# TGW share (existing) + DNS Firewall rule group share (new).

# -- TGW Share --------------------------------------------------------

resource "aws_ram_resource_share" "tgw" {
  name                      = "hub-tgw-share"
  allow_external_principals = false

  tags = merge(local.common_tags, {
    Name = "hub-tgw-share"
  })
}

resource "aws_ram_resource_association" "tgw" {
  resource_arn       = aws_ec2_transit_gateway.main.arn
  resource_share_arn = aws_ram_resource_share.tgw.id
}

resource "aws_ram_principal_association" "tgw_corporate" {
  principal          = var.corporate_account_id
  resource_share_arn = aws_ram_resource_share.tgw.id
}

resource "aws_ram_principal_association" "tgw_security" {
  principal          = var.security_account_id
  resource_share_arn = aws_ram_resource_share.tgw.id
}

resource "aws_ram_principal_association" "tgw_management" {
  count              = var.management_account_id != "" ? 1 : 0
  principal          = var.management_account_id
  resource_share_arn = aws_ram_resource_share.tgw.id
}

# -- DNS Firewall Share -----------------------------------------------
# After this share is accepted in each spoke account, a single resource
# block in each spoke's Terraform associates the rule group with their VPC:
#
#   resource "aws_route53_resolver_firewall_rule_group_association" "baseline" {
#     firewall_rule_group_id = var.dns_firewall_rule_group_arn  # from output below
#     vpc_id                 = aws_vpc.main.id
#     priority               = 100
#     name                   = "baseline-dns-firewall"
#   }

resource "aws_ram_resource_share" "dns_firewall" {
  name                      = "dns-firewall-share"
  allow_external_principals = false

  tags = merge(local.common_tags, {
    Name = "dns-firewall-share"
  })
}

resource "aws_ram_resource_association" "dns_firewall" {
  resource_arn       = aws_route53_resolver_firewall_rule_group.baseline.arn
  resource_share_arn = aws_ram_resource_share.dns_firewall.id
}

resource "aws_ram_principal_association" "dns_firewall_corporate" {
  principal          = var.corporate_account_id
  resource_share_arn = aws_ram_resource_share.dns_firewall.id
}

resource "aws_ram_principal_association" "dns_firewall_security" {
  principal          = var.security_account_id
  resource_share_arn = aws_ram_resource_share.dns_firewall.id
}

resource "aws_ram_principal_association" "tgw_web" {
  count              = var.web_account_id != "" ? 1 : 0
  principal          = var.web_account_id
  resource_share_arn = aws_ram_resource_share.tgw.id
}

resource "aws_ram_principal_association" "dns_firewall_web" {
  count              = var.web_account_id != "" ? 1 : 0
  principal          = var.web_account_id
  resource_share_arn = aws_ram_resource_share.dns_firewall.id
}