# terraform/corporate/corporate_identity.tf
# =====================================================================
# Identity Resources: Route 53 Resolver Forwarding + AD Connector
# =====================================================================
#
# ENTERPRISE PATTERN: AWS as a Named AD Site
# ------------------------------------------
# In large enterprises each AWS region is treated as a discrete Active
# Directory site with its own replica DCs.  This mirrors how branch
# offices or data centres are modelled on-premises.
#
#   On-prem site (corp.internal)           AWS site (AWS-US-WEST-1)
#   +---------------------------+           +--------------------------+
#   |  DC  192.168.1.200        |<--------->|  dc01-corporate          |
#   |  PDC Emulator + FSMO      |  AD repl  |  10.1.10.4               |
#   |  (authoritative)          |  via VPN  |  read/write replica      |
#   +---------------------------+           +--------------------------+
#                                                    |
#                                      Route 53 Resolver endpoint
#                                      (forwards corp.internal -> DC)
#                                                    |
#                                            AD Connector
#                                                    |
#                                        IAM Identity Center
#
# All resources in this file are gated by var.identity_enabled (default=false).
# They are created by the terraform-identity.yaml on-demand workflow,
# which must be run AFTER all of the following are complete:
#
#   1. Main deploy: corporate VPC, DC instance, VPN all provisioned
#   2. VPN tunnel: pfSense Phase 1 + Phase 2 showing Established
#   3. DC promoted: see promotion steps below
#   4. AD replication verified: repadmin /replsummary on on-prem DC
#   5. GitHub secret TF_VAR_AD_CONNECTOR_PASSWORD set
#
# WHY THE RESOLVER IS GATED (circular dependency fix)
# ----------------------------------------------------
# If the Route 53 Resolver forwarding rule existed BEFORE promotion,
# the promotion wizard would fail with "server is not operational":
#
#   Wizard resolves corp.internal -> VPC Resolver -> forwarding rule
#   -> query sent to 10.1.10.4 -> DC not yet authoritative -> NXDOMAIN
#   -> wizard cannot locate the existing forest -> fails
#
# By gating the rule on identity_enabled, no forwarding rule exists
# during promotion. The wizard uses the DNS server set directly on the
# adapter (192.168.1.200) to find the on-prem domain, independently of
# the VPC Resolver.
#
# DC Promotion Steps (via SSM Session Manager on dc01-corporate)
# ---------------------------------------------------------------
# Before starting - enable EC2 Serial Console on the corporate account.
# If adapter DNS is ever left pointing at the on-prem DC, SSM cannot
# reconnect after a reboot and Serial Console is the only break-glass.
#   EC2 console -> Account attributes -> EC2 Serial Console -> Allow
#   OR: aws ec2 enable-serial-console-access --region us-west-1
#
# Step 0 - Paste and run user-scripts/domain-controller/cloud-dc-promo-prep.ps1 in the SSM session.
#   It sets adapter DNS to 192.168.1.200, registers a one-shot startup task
#   to reset DNS back to DHCP after the promotion reboot (so SSM reconnects
#   automatically), and verifies corp.internal SRV records resolve.
#
# Step 1 - Open Server Manager -> flag notification ->
#   "Promote this server to a domain controller"
#
#   Page 1 - Deployment Configuration:
#     * Add a domain controller to an existing domain
#     Domain: corp.internal
#     Credentials: Administrator@corp.internal  (UPN format)
#
#   Page 2 - Domain Controller Options:
#     [x] Domain Name System (DNS) server
#     [x] Global Catalog (GC)
#     [ ] Read only domain controller (RODC)
#     DSRM Password: <strong password - store in password manager>
#
#   Page 3 - DNS Options: ignore delegation warning (expected)
#
#   Page 4 - Additional Options:
#     Replicate from: 192.168.1.200
#
#   Page 5 - Paths: accept defaults -> Install -> reboot
#
# Post-Promotion: AD Site Configuration (on the on-prem DC)
# ----------------------------------------------------------
# Active Directory Sites and Services:
#   1. New Site: "AWS-US-WEST-1", link: DEFAULTIPSITELINK
#   2. New Subnet: 10.1.0.0/16 -> site: AWS-US-WEST-1
#   3. Move dc01-corporate to AWS-US-WEST-1
#   4. New Site Link: ONPREM-AWS-LINK
#        Sites: DEFAULT-FIRST-SITE-NAME + AWS-US-WEST-1
#        Replication interval: 15 minutes
#
# After running terraform-identity.yaml
# --------------------------------------
# 1. Note the ad_connector_id from the job summary
# 2. IAM Identity Center -> Settings -> Identity source ->
#    Change to Active Directory -> select the connector ID
# 3. Configure attribute mappings and optionally Entra ID SAML federation
# =====================================================================

# -- Route 53 Resolver Outbound Endpoint ------------------------------
# Forwards corp.internal DNS queries from within the corporate VPC to
# the local replica DC. Two ENIs required (one per AZ) for HA.
# Created only after the DC is promoted and authoritative for the zone.

resource "aws_security_group" "resolver_outbound" {
  count       = var.identity_enabled ? 1 : 0
  name        = "corporate-resolver-outbound-sg"
  description = "Route 53 Resolver outbound endpoint - DNS egress to DC only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "DNS UDP to domain controller"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["${var.dc_private_ip}/32"]
  }

  egress {
    description = "DNS TCP to domain controller"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["${var.dc_private_ip}/32"]
  }

  tags = merge(local.common_tags, {
    Name = "corporate-resolver-outbound-sg"
  })
}

resource "aws_route53_resolver_endpoint" "outbound" {
  count     = var.identity_enabled ? 1 : 0
  name      = "corporate-resolver-outbound"
  direction = "OUTBOUND"

  security_group_ids = [aws_security_group.resolver_outbound[0].id]

  ip_address {
    subnet_id = aws_subnet.private[0].id
  }

  ip_address {
    subnet_id = aws_subnet.private[1].id
  }

  tags = merge(local.common_tags, {
    Name = "corporate-resolver-outbound"
  })
}

# -- AD Zone Forwarding Rule ------------------------------------------
# Matches corp.internal and all subdomains (_msdcs, _sites, etc.).
# Route 53 Resolver uses most-specific-match, so this rule takes
# precedence over the default recursive resolver for AD names only.
# The DC is authoritative for the zone by virtue of replicating from
# the on-prem forest root -- no VPN hop required for AD name resolution.

resource "aws_route53_resolver_rule" "ad_forward" {
  count                = var.identity_enabled ? 1 : 0
  domain_name          = var.ad_domain_name
  name                 = "corporate-forward-ad-zone"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.outbound[0].id

  target_ip {
    ip   = var.dc_private_ip
    port = 53
  }

  tags = merge(local.common_tags, {
    Name = "corporate-ad-forward"
  })
}

resource "aws_route53_resolver_rule_association" "ad_forward" {
  count            = var.identity_enabled ? 1 : 0
  resolver_rule_id = aws_route53_resolver_rule.ad_forward[0].id
  vpc_id           = aws_vpc.main.id
}

# NOTE: AD Connector was moved to the management account workspace
# (terraform/management/management_identity.tf). AWS requires the AD
# Connector to reside in the same account as IAM Identity Center, which
# lives in the management account. See management_identity.tf for the
# full architecture justification and resource definitions.
