# terraform/security/main.tf
# =====================================================================
# Security Account - Spoke VPC, Centralized Logging and Detection Hub
# =====================================================================
# The security VPC is a restricted, minimal-footprint account that hosts
# org-wide audit infrastructure: GuardDuty, SecurityHub, Inspector,
# Macie, KMS CMK, org-logs S3 bucket, and the Lambda-based SIEM.
#
# There are no compute workloads (EC2, domain controllers) in this
# account. All resources are either serverless or AWS-managed services.
# Access for security analysts is via IAM Identity Center (SSO), not
# domain-joined machines.
#
# Routing is hub-and-spoke: private subnet -> TGW -> egress VPC -> NAT.
# Spoke-to-spoke traffic (security <-> corporate) traverses the TGW hub.
# SSM traffic is kept off the internet via Interface VPC Endpoints.
# =====================================================================

data "aws_availability_zones" "available" {
  state = "available"
}

# -- Security VPC -----------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "security-vpc"
  })
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "security-private-${count.index + 1}"
  })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "security-private-rt"
  })
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

resource "aws_route" "private_to_corporate" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = var.corporate_vpc_cidr
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

resource "aws_route" "private_to_on_prem" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = var.on_prem_subnet_cidr
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

# -- TGW Attachment ---------------------------------------------------

resource "aws_ec2_transit_gateway_vpc_attachment" "main" {
  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.main.id
  subnet_ids         = aws_subnet.private[*].id

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = merge(local.common_tags, {
    Name = "security-tgw-attachment"
  })
}

# -- SSM Interface VPC Endpoints --------------------------------------
# Keeps all SSM traffic within the AWS private network.
# Requires enable_dns_support + enable_dns_hostnames on the VPC (both set above)
# and private_dns_enabled = true so the regional SSM hostnames resolve
# to the endpoint ENI IPs rather than public addresses.

resource "aws_security_group" "ssm_endpoints" {
  name        = "security-ssm-endpoints-sg"
  description = "Allow HTTPS inbound from VPC to SSM interface endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "HTTPS responses to VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(local.common_tags, {
    Name = "security-ssm-endpoints-sg"
  })
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "security-ssm-endpoint"
  })
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "security-ssmmessages-endpoint"
  })
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "security-ec2messages-endpoint"
  })
}

# The firewall_rule_group_id field requires the rule group ID (max 64 chars),
# not the full ARN. Extract the ID from the ARN by taking the last path segment.
locals {
  dns_firewall_rule_group_id = element(split("/", var.dns_firewall_rule_group_arn), length(split("/", var.dns_firewall_rule_group_arn)) - 1)
}

resource "aws_route53_resolver_firewall_rule_group_association" "baseline" {
  name                   = "security-baseline-dns-firewall"
  firewall_rule_group_id = local.dns_firewall_rule_group_id
  vpc_id                 = aws_vpc.main.id
  priority               = 101

  tags = merge(local.common_tags, {
    Name = "security-baseline-dns-firewall"
  })
}
