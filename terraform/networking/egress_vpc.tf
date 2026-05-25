# terraform/networking/egress_vpc.tf
# =====================================================================
# Inspection / Egress VPC - two Network Firewalls split by TRAFFIC CLASS:
#
#   external NF (north-south)  -- web ALB inbound + return
#   internal NF (east-west + spoke egress) -- mirrors the May 2026
#       single-NF layout that AD replication is known to work against:
#       spoke<->on-prem (VPN/AD), spoke<->spoke, spoke->internet via NAT,
#       and internet->spoke return.
#
# Subnet tiers (per AZ x 2 AZs):
#   tgw_attachment    /28  TGW ENIs only
#   firewall_external /28  external NF endpoints (web north-south only)
#   firewall_internal /28  internal NF endpoints (east-west + spoke egress)
#   alb               /24  Internet-facing ALB ENIs only
#   nat               /24  NAT Gateways only
#
# Inbound web (internet -> ALB):
#   IGW -> IGW edge RT (alb_cidr -> external NF)
#       -> external NF -> ALB subnet -> ALB
#
# Web ALB return (ALB -> internet):
#   ALB -> alb RT (0.0.0.0/0 -> external NF)
#       -> external NF -> firewall_external RT (0.0.0.0/0 -> IGW)
#       -> IGW (1:1 NAT on ALB public IP) -> internet
#
# Spoke -> on-prem (VPN/AD, east-west):
#   TGW -> tgw_attachment RT (0.0.0.0/0 -> internal NF)
#       -> internal NF -> firewall_internal RT (on_prem_cidr -> TGW)
#       -> TGW -> VPN attachment -> on-prem
#
# Spoke -> spoke (east-west):
#   TGW -> tgw_attachment RT (0.0.0.0/0 -> internal NF)
#       -> internal NF -> firewall_internal RT (spoke_cidr -> TGW)
#       -> TGW -> spoke
#
# Spoke -> internet (north-south egress):
#   TGW -> tgw_attachment RT (0.0.0.0/0 -> internal NF)
#       -> internal NF -> firewall_internal RT (0.0.0.0/0 -> NAT GW)
#       -> NAT GW (SNAT) -> nat RT (0.0.0.0/0 -> IGW) -> internet
#
# Internet -> spoke return:
#   IGW -> IGW edge RT (nat_cidr -> internal NF)
#       -> internal NF -> NAT GW (DNAT to spoke private IP)
#       -> nat RT (spoke_cidr -> internal NF)
#       -> internal NF -> firewall_internal RT (spoke_cidr -> TGW)
#       -> TGW -> spoke
#
# All flows are symmetric through their respective NF endpoint, so
# stateful connection tracking works correctly.
# =====================================================================

# -- VPC + IGW --------------------------------------------------------

resource "aws_vpc" "egress" {
  cidr_block           = var.egress_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "networking-egress-vpc"
  })
}

resource "aws_internet_gateway" "egress" {
  vpc_id = aws_vpc.egress.id

  tags = merge(local.common_tags, {
    Name = "networking-igw"
  })
}

# -- Subnets ----------------------------------------------------------

resource "aws_subnet" "tgw_attachment" {
  count             = 2
  vpc_id            = aws_vpc.egress.id
  cidr_block        = var.egress_tgw_attachment_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(local.common_tags, {
    Name = "networking-tgw-attach-${count.index + 1}"
  })
}

resource "aws_subnet" "firewall_external" {
  count             = 2
  vpc_id            = aws_vpc.egress.id
  cidr_block        = var.egress_firewall_external_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(local.common_tags, {
    Name = "networking-firewall-external-${count.index + 1}"
  })
}

resource "aws_subnet" "firewall_internal" {
  count             = 2
  vpc_id            = aws_vpc.egress.id
  cidr_block        = var.egress_firewall_internal_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(local.common_tags, {
    Name = "networking-firewall-internal-${count.index + 1}"
  })
}

# Hosts only the internet-facing ALB ENIs. NAT GWs are in aws_subnet.nat.
resource "aws_subnet" "alb" {
  count                   = 2
  vpc_id                  = aws_vpc.egress.id
  cidr_block              = var.egress_alb_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "networking-alb-${count.index + 1}"
  })
}

# Hosts NAT Gateways only. Isolated from ALB subnets so each has its own
# route table - the ALB tier routes 0.0.0.0/0 through the external NF
# (symmetric), the NAT tier routes 0.0.0.0/0 directly to IGW (NAT GW has
# already SNAT'd, post-NAT inspection isn't useful and the dst CIDR
# would conflict with the firewall_internal RT's 0.0.0.0/0 -> NAT GW route).
resource "aws_subnet" "nat" {
  count                   = 2
  vpc_id                  = aws_vpc.egress.id
  cidr_block              = var.egress_nat_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "networking-nat-${count.index + 1}"
  })
}

# -- NAT Gateways (one per AZ) ----------------------------------------

resource "aws_eip" "nat" {
  count  = 2
  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "networking-nat-eip-${count.index + 1}"
  })

  depends_on = [aws_internet_gateway.egress]
}

resource "aws_nat_gateway" "main" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.nat[count.index].id

  tags = merge(local.common_tags, {
    Name = "networking-nat-${count.index + 1}"
  })

  depends_on = [aws_internet_gateway.egress]
}

# -- IGW Gateway Route Table (Ingress Routing) -------------------------
# Forces every inbound web-ingress packet through the external NF endpoint:
#   - ALB subnet CIDRs -> external NF (for internet -> ALB inspection)
#
# NOTE: The previous iteration also routed NAT subnet CIDRs through the
# internal NF on inbound (for "symmetric inspection" of spoke-return
# traffic). This was removed because it broke the SYN-ACK return path:
# NF saw the pre-DNAT 5-tuple (internet -> NAT_EIP), which didn't
# correlate with the outbound flow it had tracked (web_ec2 -> internet),
# so the return SYN-ACK was dropped as an unrelated SYN-ACK without a
# matching pass rule, leaving NAT GW's ConnectionEstablishedCount at 0.
#
# Meaningful return-path inspection still happens AFTER the NAT GW does
# DNAT: the nat subnet RT routes spoke CIDRs (post-DNAT, real spoke IPs
# visible) back through the internal NF endpoint. NF can correlate that
# with the outbound flow's 5-tuple and pass it correctly.
#
# Net effect: every flow is still inspected on both legs, but at the
# packet points where NF can see real source/dest IPs instead of the
# obfuscated NAT_EIP.

resource "aws_route_table" "igw" {
  vpc_id = aws_vpc.egress.id

  tags = merge(local.common_tags, {
    Name = "networking-igw-rt"
  })
}

resource "aws_route_table_association" "igw" {
  gateway_id     = aws_internet_gateway.egress.id
  route_table_id = aws_route_table.igw.id
}

resource "aws_route" "igw_to_firewall_external" {
  count                  = 2
  route_table_id         = aws_route_table.igw.id
  destination_cidr_block = var.egress_alb_subnet_cidrs[count.index]
  vpc_endpoint_id        = local.fw_external_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.external]
}

# -- Route Tables: TGW Attachment Subnets -----------------------------
# All spoke traffic (egress to internet, east-west to other spokes, and
# east-west to on-prem via VPN) arrives here. Send 0.0.0.0/0 through the
# internal NF -- this single catch-all is the May 2026 working pattern:
# the internal NF decides next hop based on the inspected packet's dst.

resource "aws_route_table" "tgw_attachment" {
  count  = 2
  vpc_id = aws_vpc.egress.id

  tags = merge(local.common_tags, {
    Name = "networking-tgw-attach-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "tgw_attachment" {
  count          = 2
  subnet_id      = aws_subnet.tgw_attachment[count.index].id
  route_table_id = aws_route_table.tgw_attachment[count.index].id
}

resource "aws_route" "tgw_attach_to_firewall_internal" {
  count                  = 2
  route_table_id         = aws_route_table.tgw_attachment[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = local.fw_internal_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.internal]
}

# -- Route Tables: Firewall External Subnets --------------------------
# Post-inspection on the ALB north-south path. The packet arrives here
# after NF inspects either an inbound internet -> ALB request or an
# outbound ALB return. For inbound, the implicit VPC-local route
# delivers the packet to the ALB subnet. For outbound ALB return,
# 0.0.0.0/0 -> IGW.

resource "aws_route_table" "firewall_external" {
  count  = 2
  vpc_id = aws_vpc.egress.id

  tags = merge(local.common_tags, {
    Name = "networking-firewall-external-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "firewall_external" {
  count          = 2
  subnet_id      = aws_subnet.firewall_external[count.index].id
  route_table_id = aws_route_table.firewall_external[count.index].id
}

resource "aws_route" "firewall_external_to_igw" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_external[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.egress.id
}

# -- Route Tables: Firewall Internal Subnets --------------------------
# Post-inspection on the east-west + spoke-egress paths. Mirrors the
# May 2026 single-NF layout:
#   spoke -> internet:   0.0.0.0/0 -> NAT GW (SNAT, then IGW)
#   spoke -> spoke:      <spoke_cidr> -> TGW
#   spoke -> on-prem:    <on_prem_cidr> -> TGW (VPN attachment)
#   internet -> spoke return: <spoke_cidr> -> TGW (post-DNAT)

resource "aws_route_table" "firewall_internal" {
  count  = 2
  vpc_id = aws_vpc.egress.id

  tags = merge(local.common_tags, {
    Name = "networking-firewall-internal-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "firewall_internal" {
  count          = 2
  subnet_id      = aws_subnet.firewall_internal[count.index].id
  route_table_id = aws_route_table.firewall_internal[count.index].id
}

resource "aws_route" "firewall_internal_to_nat" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_internal[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

resource "aws_route" "firewall_internal_to_corporate" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_internal[count.index].id
  destination_cidr_block = var.corporate_vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

resource "aws_route" "firewall_internal_to_security" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_internal[count.index].id
  destination_cidr_block = var.security_vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

resource "aws_route" "firewall_internal_to_on_prem" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_internal[count.index].id
  destination_cidr_block = var.on_prem_subnet_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

resource "aws_route" "firewall_internal_to_management" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_internal[count.index].id
  destination_cidr_block = var.management_vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

resource "aws_route" "firewall_internal_to_web" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_internal[count.index].id
  destination_cidr_block = var.web_vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

# -- Route Tables: ALB Subnets ----------------------------------------
# Symmetric outbound through the external NF endpoint. The ALB sends its
# response to the internet via NF, which then forwards to IGW per the
# firewall_external RT. This keeps the flow symmetric so stateful
# tracking works correctly. ALB -> VPC endpoint (PrivateLink) is local
# VPC routing and is unaffected by this 0.0.0.0/0 route.

resource "aws_route_table" "alb" {
  count  = 2
  vpc_id = aws_vpc.egress.id

  tags = merge(local.common_tags, {
    Name = "networking-alb-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "alb" {
  count          = 2
  subnet_id      = aws_subnet.alb[count.index].id
  route_table_id = aws_route_table.alb[count.index].id
}

resource "aws_route" "alb_to_firewall_external" {
  count                  = 2
  route_table_id         = aws_route_table.alb[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = local.fw_external_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.external]
}

# -- Route Tables: NAT Subnets ----------------------------------------
# 0.0.0.0/0 -> IGW because the NAT GW has already done SNAT and the
# packet's source is now the NAT GW EIP (a public IP); re-inspecting it
# through NF would conflict with the firewall_internal RT's 0.0.0.0/0
# route. Spoke CIDRs are sent back through internal NF for the return
# path (post-DNAT, the packet's dst is a spoke private IP).

resource "aws_route_table" "nat" {
  count  = 2
  vpc_id = aws_vpc.egress.id

  tags = merge(local.common_tags, {
    Name = "networking-nat-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "nat" {
  count          = 2
  subnet_id      = aws_subnet.nat[count.index].id
  route_table_id = aws_route_table.nat[count.index].id
}

resource "aws_route" "nat_to_igw" {
  count                  = 2
  route_table_id         = aws_route_table.nat[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.egress.id
}

resource "aws_route" "nat_corporate_return" {
  count                  = 2
  route_table_id         = aws_route_table.nat[count.index].id
  destination_cidr_block = var.corporate_vpc_cidr
  vpc_endpoint_id        = local.fw_internal_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.internal]
}

resource "aws_route" "nat_security_return" {
  count                  = 2
  route_table_id         = aws_route_table.nat[count.index].id
  destination_cidr_block = var.security_vpc_cidr
  vpc_endpoint_id        = local.fw_internal_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.internal]
}

resource "aws_route" "nat_on_prem_return" {
  count                  = 2
  route_table_id         = aws_route_table.nat[count.index].id
  destination_cidr_block = var.on_prem_subnet_cidr
  vpc_endpoint_id        = local.fw_internal_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.internal]
}

resource "aws_route" "nat_management_return" {
  count                  = 2
  route_table_id         = aws_route_table.nat[count.index].id
  destination_cidr_block = var.management_vpc_cidr
  vpc_endpoint_id        = local.fw_internal_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.internal]
}

resource "aws_route" "nat_web_return" {
  count                  = 2
  route_table_id         = aws_route_table.nat[count.index].id
  destination_cidr_block = var.web_vpc_cidr
  vpc_endpoint_id        = local.fw_internal_endpoint_ids[count.index]

  depends_on = [aws_networkfirewall_firewall.internal]
}
