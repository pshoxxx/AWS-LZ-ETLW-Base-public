# terraform/security/security_dns.tf
# =====================================================================
# Split-horizon DNS - Route 53 Resolver forwarding for corp.internal
# =====================================================================
#
# The security VPC has no local domain controller. DNS queries for
# corp.internal are forwarded cross-VPC via TGW to the corporate DC
# replica at var.corporate_dc_ip (10.1.10.4).
#
# This is the correct enterprise pattern: the security account is a
# restricted logging and detection hub with no compute workloads, so
# it does not warrant a dedicated DC. The corporate DC replica is
# reachable via the TGW hub and is authoritative for corp.internal
# by virtue of replicating from the on-prem forest root.
#
# The corporate DC security group explicitly allows DNS (port 53 UDP/TCP)
# inbound from var.security_vpc_cidr (10.2.0.0/16), so the resolver
# endpoint ENIs in this VPC can reach it without additional rules.
#
# Query flows
# -----------
# corp.internal query from a resource in the security VPC:
#   Resource -> VPC Resolver (.2) -> DNS Firewall check
#   -> Forwarding rule matches corp.internal
#   -> Outbound endpoint ENI (10.2.x.x) -> TGW -> corporate VPC
#   -> Corporate DC (10.1.10.4):53 answers authoritatively
#
# Public query (e.g. amazonaws.com):
#   Resource -> VPC Resolver (.2) -> DNS Firewall check
#   -> No forwarding rule matches -> Resolver resolves via public DNS
# =====================================================================

locals {
  vpc_resolver_ip = cidrhost(var.vpc_cidr, 2)
}

# -- Resolver Outbound Endpoint ----------------------------------------
# Two ENIs required (one per AZ) for high availability.
# Egress is scoped to the corporate DC IP only -- the security VPC
# has no other DNS forwarding targets.

resource "aws_security_group" "resolver_outbound" {
  name        = "security-resolver-outbound-sg"
  description = "Route 53 Resolver outbound endpoint - DNS egress to corporate DC via TGW"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "DNS UDP to corporate DC replica via TGW"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["${var.corporate_dc_ip}/32"]
  }

  egress {
    description = "DNS TCP to corporate DC replica via TGW"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["${var.corporate_dc_ip}/32"]
  }

  tags = merge(local.common_tags, {
    Name = "security-resolver-outbound-sg"
  })
}

resource "aws_route53_resolver_endpoint" "outbound" {
  name      = "security-resolver-outbound"
  direction = "OUTBOUND"

  security_group_ids = [aws_security_group.resolver_outbound.id]

  ip_address {
    subnet_id = aws_subnet.private[0].id
  }

  ip_address {
    subnet_id = aws_subnet.private[1].id
  }

  tags = merge(local.common_tags, {
    Name = "security-resolver-outbound"
  })
}

# -- AD Zone Forwarding Rule -------------------------------------------
# Forwards corp.internal (and all subdomains: _msdcs, _sites, etc.)
# to the corporate DC replica via TGW. Route 53 Resolver uses
# most-specific-match, so this rule takes precedence over the default
# recursive resolver for AD names only.

resource "aws_route53_resolver_rule" "ad_forward" {
  domain_name          = var.ad_domain_name
  name                 = "security-forward-ad-zone"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.outbound.id

  target_ip {
    ip   = var.corporate_dc_ip
    port = 53
  }

  tags = merge(local.common_tags, {
    Name = "security-ad-forward"
  })
}

resource "aws_route53_resolver_rule_association" "ad_forward" {
  resolver_rule_id = aws_route53_resolver_rule.ad_forward.id
  vpc_id           = aws_vpc.main.id
}
