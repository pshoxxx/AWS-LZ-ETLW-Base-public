# terraform/networking/transit_gateway.tf
# =====================================================================
# TGW with custom route tables (defaults disabled).
#
# Two route tables:
#
#   Spoke RT   Associations: corporate, security, VPN attachments
#              Routes: 0.0.0.0/0 -> egress attachment (static, ONLY route)
#              Propagations: none
#                All traffic -- internet, east-west, spoke<->on-prem --
#                hits this default and is forced through the Network
#                Firewall in the egress VPC. Spoke CIDRs are intentionally
#                NOT propagated here: a more-specific propagated route
#                would win over 0.0.0.0/0 and bypass the firewall for
#                east-west and on-prem traffic.
#
#   Egress RT  Associations: egress VPC attachment
#              Routes: on-prem CIDR -> VPN attachment (static)
#              Propagations: corporate CIDR, security CIDR
#                Post-firewall packets re-enter TGW and use these routes
#                to reach the correct spoke or exit via VPN.
#
# DEPLOYMENT ORDER:
#   Phase 1: Apply with corporate/security_tgw_attachment_id = ""
#            (TGW, egress attachment, VPN, Spoke/Egress RTs all created)
#   Phase 2: Deploy corporate + security accounts
#            (creates attachments; VPC routes work once associations added)
#   Phase 3: Add attachment IDs to tfvars, re-apply
#            (adds associations + propagations; traffic flows end-to-end)
# =====================================================================

# terraform/networking/imports.tf
# import {
#   to = aws_ec2_transit_gateway_route_table_association.vpn
#   id = "tgw-rtb-02c93127d96f4cff5_tgw-attach-03b8add42685cacc8"
# }

resource "aws_ec2_transit_gateway" "main" {
  description                     = "Hub Transit Gateway - hub-and-spoke topology"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  auto_accept_shared_attachments  = "enable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = merge(local.common_tags, {
    Name = "hub-tgw"
  })
}

# Egress VPC attachment.
# Opt out of default RT handling explicitly even though it's globally disabled.
resource "aws_ec2_transit_gateway_vpc_attachment" "egress" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.egress.id
  subnet_ids         = aws_subnet.tgw_attachment[*].id

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  # Required for stateful east-west inspection: ensures forward and return
  # flows between the same pair of spokes always use the same AZ's firewall
  # endpoint, preserving stateful connection tracking.
  appliance_mode_support = "enable"

  tags = merge(local.common_tags, {
    Name = "networking-egress-tgw-attachment"
  })
}

# -- Custom Route Tables ----------------------------------------------

resource "aws_ec2_transit_gateway_route_table" "spoke" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = merge(local.common_tags, {
    Name = "tgw-spoke-rt"
  })
}

resource "aws_ec2_transit_gateway_route_table" "egress" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = merge(local.common_tags, {
    Name = "tgw-egress-rt"
  })
}

# -- Route Table Associations -----------------------------------------

resource "aws_ec2_transit_gateway_route_table_association" "egress" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

# Phase 3: created once spoke attachment IDs are known.
# count = 0 during Phase 1 so the resource block is valid but inactive.
resource "aws_ec2_transit_gateway_route_table_association" "corporate" {
  count = var.corporate_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.corporate_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

resource "aws_ec2_transit_gateway_route_table_association" "security" {
  count = var.security_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.security_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

# VPN association is in vpn.tf alongside the connection resource.

# -- Route Table Propagations -----------------------------------------
# Spoke CIDRs propagate into the Egress RT ONLY.
# The Spoke RT has NO propagations -- all traffic (east-west, on-prem,
# internet) exits via the single 0.0.0.0/0 -> egress static route and
# is inspected by the Network Firewall before reaching any destination.
# corporate_to_spoke and security_to_spoke propagations were deliberately
# removed: they would create more-specific routes that bypass the firewall.

resource "aws_ec2_transit_gateway_route_table_propagation" "corporate_to_egress" {
  count = var.corporate_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.corporate_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "security_to_egress" {
  count = var.security_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.security_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

resource "aws_ec2_transit_gateway_route_table_association" "management" {
  count = var.management_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.management_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "management_to_egress" {
  count = var.management_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.management_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

resource "aws_ec2_transit_gateway_route_table_association" "web" {
  count = var.web_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.web_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "web_to_egress" {
  count = var.web_tgw_attachment_id != "" ? 1 : 0

  transit_gateway_attachment_id  = var.web_tgw_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

# -- Spoke RT Static Routes -------------------------------------------

# Single default route -- all spoke traffic (internet, east-west, on-prem)
# goes to the egress VPC and through the Network Firewall.
# The previous spoke_to_on_prem static route was removed: it was more
# specific than 0.0.0.0/0 and caused on-prem traffic to bypass the
# firewall by jumping directly to the VPN attachment.
resource "aws_ec2_transit_gateway_route" "spoke_default_egress" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

# -- Egress RT Static Routes ------------------------------------------
# Spoke CIDRs are handled by propagation above.
# On-prem return traffic via VPN.

resource "aws_ec2_transit_gateway_route" "egress_to_on_prem" {
  destination_cidr_block         = var.on_prem_subnet_cidr
  transit_gateway_attachment_id  = aws_vpn_connection.on_prem.transit_gateway_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}