# terraform/management/management_identity.tf
# =====================================================================
# AD Connector VPC + AD Connector for IAM Identity Center
# =====================================================================
#
# ARCHITECTURE JUSTIFICATION: AD Connector in Management Account
# --------------------------------------------------------------
# AWS documentation mandates that the AD Connector (or AWS Managed
# Microsoft AD) must reside in the same account as IAM Identity Center.
# Three independent AWS sources state this requirement:
#
# 1. "Using Active Directory as an identity source" (gs-ad.html):
#      "You must have an existing AD Connector or AWS Managed Microsoft
#       AD directory set up in AWS Directory Service, and it must reside
#       within your AWS Organizations management account."
#
# 2. "IAM Identity Center prerequisites" (prereqs.html):
#      "As a prerequisite step, make sure your AD Connector or directory
#       in AWS Managed Microsoft AD in Directory Service resides within
#       your AWS Organizations management account."
#
# 3. "Delegated administration" (delegated-admin.html) -- the ONLY
#    documented alternative to the management account:
#      "The directory must reside in (be owned by) the IAM Identity
#       Center delegated administrator member account if one exists;
#       otherwise, it must be in the management account."
#
# DESIGN DECISION: management account vs. delegated-admin account
# ---------------------------------------------------------------
# The delegated-admin pattern moves IAM Identity Center (and therefore
# the AD Connector) into a separate member account -- the correct
# enterprise pattern at scale because it avoids long-lived access to
# the management account. However, it requires a 5th AWS account,
# an additional VPC + TGW attachment, delegated-admin registration,
# and cross-account IAM policies for permission set management.
#
# For a two-site, single-workload-spoke environment that already
# concentrates governance (CloudTrail, Config, Macie, SCPs) in the
# management account, the delegated-admin overhead adds no meaningful
# security benefit. Colocating the AD Connector in the management
# account is the simpler, fully AWS-documented design choice.
#
# IDENTITY SOURCE DECISION: AD Connector vs. SCIM
# ---------------------------------------------------------------
# IAM Identity Center supports three identity sources:
#   - Built-in Identity Center directory (manual user management)
#   - External IdP via SAML + SCIM (Okta, Entra ID, etc.)
#   - Active Directory via AD Connector or AWS Managed Microsoft AD
#
# AD Connector is the correct choice for this environment because:
#
# 1. Single authoritative source. corp.internal AD is the system of
#    record for all identities. AD Connector proxies authentication
#    directly to it -- no duplicate user stores, no sync pipeline,
#    no provisioning step before assignments can be made.
#    -- https://docs.aws.amazon.com/singlesignon/latest/userguide/manage-your-identity-source.html
#      "If you are already managing users and groups in...your
#       self-managed directory in Active Directory, we recommend
#       that you connect that directory when you enable IAM
#       Identity Center."
#
# 2. Pass-through authentication. Passwords never leave the DC.
#    Users authenticate with their actual AD credentials; the
#    AD Connector forwards the bind to dc01-corporate over the
#    private TGW path. Password policy and lockout are enforced
#    at the AD layer, not duplicated in a cloud IdP.
#
# 3. No external IdP required. SCIM is a provisioning protocol
#    layered on top of an external IdP (Entra ID, Okta, etc.).
#    Introducing an external IdP solely to push users into IAM
#    Identity Center would add a third identity plane with no
#    benefit over the direct AD Connector path.
#    -- https://docs.aws.amazon.com/singlesignon/latest/userguide/provision-automatically.html
#      "When using an external IdP, you must provision all
#       applicable users and groups into IAM Identity Center
#       before you can make any assignments to AWS accounts
#       or applications."
#    AD Connector has no such pre-provisioning requirement --
#    group membership is read live from AD on each login.
#
# 4. Single-region deployment. SCIM/external IdP is required only
#    when IAM Identity Center is replicated across regions.
#    -- https://docs.aws.amazon.com/singlesignon/latest/userguide/manage-your-identity-source-idp.html
#      "If you have replicated IAM Identity Center to additional
#       Regions or plan to do so, you must use an external
#       identity provider as the identity source."
#    This is a single-region (us-west-1) deployment; the
#    constraint does not apply.
#
# When SCIM/external IdP would be the better choice:
#   - Multi-region IAM Identity Center replication is required
#   - The authoritative store is already a cloud IdP (Entra ID
#     cloud-only or hybrid) rather than on-prem AD
#   - Multiple AD domains/forests are needed -- AD Connector
#     supports only a single domain:
#     -- https://docs.aws.amazon.com/singlesignon/latest/userguide/gs-ad.html
#       "IAM Identity Center can access only the users and groups
#        of the single domain that's attached to the AD Connector"
#     In that case, AWS Managed Microsoft AD with trusts or an
#     external IdP would be required instead
#
# All resources in this file are gated by var.identity_enabled (default=false).
# Run terraform-identity.yaml after DC promotion to provision them.
# =====================================================================

data "aws_availability_zones" "identity" {
  count = var.identity_enabled ? 1 : 0
  state = "available"
}

# -- Stub VPC ---------------------------------------------------------
# No IGW, no NAT gateway. Single purpose: host the AD Connector ENIs
# that reach the corporate DC at var.dc_private_ip via the TGW.

resource "aws_vpc" "identity" {
  count                = var.identity_enabled ? 1 : 0
  cidr_block           = var.identity_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "management-identity-vpc"
  })
}

resource "aws_subnet" "identity" {
  count             = var.identity_enabled ? 2 : 0
  vpc_id            = aws_vpc.identity[0].id
  cidr_block        = cidrsubnet(var.identity_vpc_cidr, 1, count.index)
  availability_zone = data.aws_availability_zones.identity[0].names[count.index]

  tags = merge(local.common_tags, {
    Name = "management-identity-subnet-${count.index + 1}"
  })
}

resource "aws_route_table" "identity" {
  count  = var.identity_enabled ? 1 : 0
  vpc_id = aws_vpc.identity[0].id

  route {
    cidr_block         = "0.0.0.0/0"
    transit_gateway_id = var.transit_gateway_id
  }

  tags = merge(local.common_tags, {
    Name = "management-identity-rt"
  })
}

resource "aws_route_table_association" "identity" {
  count          = var.identity_enabled ? 2 : 0
  subnet_id      = aws_subnet.identity[count.index].id
  route_table_id = aws_route_table.identity[0].id
}

# -- TGW Attachment ---------------------------------------------------

resource "aws_ec2_transit_gateway_vpc_attachment" "identity" {
  count              = var.identity_enabled ? 1 : 0
  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.identity[0].id
  subnet_ids         = aws_subnet.identity[*].id

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = merge(local.common_tags, {
    Name = "management-identity-tgw-attachment"
  })
}

# -- AD Connector Security Group --------------------------------------
# Restricts egress to only the protocols AD Connector needs to reach
# the corporate DC. No inbound rules -- AWS Directory Service manages
# the AD Connector ENIs internally.

locals {
  ad_connector_egress_rules = {
    "dns-udp"      = { from = 53, to = 53, proto = "udp", desc = "DNS UDP to corporate DC" }
    "kerberos-tcp" = { from = 88, to = 88, proto = "tcp", desc = "Kerberos TCP to corporate DC" }
    "kerberos-udp" = { from = 88, to = 88, proto = "udp", desc = "Kerberos UDP to corporate DC" }
    "ldap-tcp"     = { from = 389, to = 389, proto = "tcp", desc = "LDAP TCP to corporate DC" }
    "ldap-udp"     = { from = 389, to = 389, proto = "udp", desc = "LDAP UDP to corporate DC" }
    "smb"          = { from = 445, to = 445, proto = "tcp", desc = "SMB to corporate DC" }
    "kpasswd"      = { from = 464, to = 464, proto = "tcp", desc = "Kerberos password change to corporate DC" }
    "ldaps"        = { from = 636, to = 636, proto = "tcp", desc = "LDAPS to corporate DC" }
    "rpc-dynamic"  = { from = 1024, to = 65535, proto = "tcp", desc = "RPC dynamic ports to corporate DC" }
  }
}

resource "aws_security_group" "ad_connector" {
  count       = var.identity_enabled ? 1 : 0
  name        = "management-ad-connector-sg"
  description = "AD Connector - egress to corporate DC only"
  vpc_id      = aws_vpc.identity[0].id

  dynamic "egress" {
    for_each = local.ad_connector_egress_rules
    content {
      description = egress.value.desc
      from_port   = egress.value.from
      to_port     = egress.value.to
      protocol    = egress.value.proto
      cidr_blocks = ["${var.dc_private_ip}/32"]
    }
  }

  tags = merge(local.common_tags, {
    Name = "management-ad-connector-sg"
  })
}

# -- AD Connector -----------------------------------------------------
# Connects IAM Identity Center to the corp.internal forest via the
# AWS replica DC. Auth traffic stays inside the AWS network; VPN
# carries only AD replication traffic.
#
# customer_username = "Administrator". In production, use a dedicated
# service account with delegated read permissions only.
#
# lifecycle ignore_changes = [password] prevents regular deploys with
# an empty TF_VAR_ad_connector_password from triggering replacement of
# the connector, which would break all active SSO sessions.

resource "aws_directory_service_directory" "ad_connector" {
  count    = var.identity_enabled ? 1 : 0
  name     = var.ad_domain_name
  password = var.ad_connector_password
  size     = "Small"
  type     = "ADConnector"

  connect_settings {
    customer_dns_ips  = [var.dc_private_ip]
    customer_username = "Administrator"
    subnet_ids        = aws_subnet.identity[*].id
    vpc_id            = aws_vpc.identity[0].id
  }

  lifecycle {
    ignore_changes = [password]
  }

  tags = merge(local.common_tags, {
    Name = "management-ad-connector"
  })
}
