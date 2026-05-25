# terraform/networking/vpn.tf

resource "aws_customer_gateway" "on_prem" {
  bgp_asn    = var.on_prem_bgp_asn
  ip_address = var.on_prem_wan_ip
  type       = "ipsec.1"

  tags = merge(local.common_tags, {
    Name = "on-prem-pfsense"
  })
}

resource "aws_vpn_connection" "on_prem" {
  customer_gateway_id = aws_customer_gateway.on_prem.id
  transit_gateway_id  = aws_ec2_transit_gateway.main.id
  type                = "ipsec.1"
  static_routes_only  = true

  # When the customer gateway is replaced (e.g. WAN IP change), force
  # replacement of the VPN connection rather than an in-place update.
  # Without this, Terraform attempts an impossible in-place update of
  # customer_gateway_id and then fails to delete the old CGW while the
  # VPN connection still holds a reference to it.
  lifecycle {
    replace_triggered_by = [aws_customer_gateway.on_prem]
  }

  tags = merge(local.common_tags, {
    Name = "on-prem-vpn"
  })
}

# Associate the VPN attachment with the Spoke RT.
# transit_gateway.tf adds the static routes that use this attachment.
#
# Import handling: the workflow's Resolve Networking Import State step
# detects whether this association already exists in AWS and runs
# terraform import before plan/apply if so. The Reconcile Drifted TGW
# VPN Association step provides a second safety net by reading from
# Terraform state after the VPN connection is created.
resource "aws_ec2_transit_gateway_route_table_association" "vpn" {
  transit_gateway_attachment_id  = aws_vpn_connection.on_prem.transit_gateway_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}
