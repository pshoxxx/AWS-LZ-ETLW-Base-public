# terraform/corporate/corporate_dns.tf
# =====================================================================
# Split-horizon DNS - VPC Resolver local
# =====================================================================
#
# The Route 53 Resolver outbound endpoint, forwarding rule, and rule
# association for corp.internal are defined in corporate_identity.tf,
# gated by var.identity_enabled. They are not created until the DC has
# been promoted and is authoritative for the zone.
#
# Why defer the forwarding rule?
# ------------------------------
# Creating the forwarding rule before DC promotion causes a circular
# dependency during the "Add a domain controller to an existing domain"
# promotion wizard:
#
#   1. Wizard tries to resolve corp.internal to locate the on-prem forest
#   2. VPC Resolver sees the forwarding rule → sends query to 10.1.10.4
#   3. AWS DC at 10.1.10.4 is not yet authoritative → query fails
#   4. Wizard reports "server is not operational"
#
# By gating the rule on identity_enabled, the VPC Resolver has no
# forwarding rule during promotion and returns NXDOMAIN for corp.internal.
# The promotion wizard uses the DNS server configured directly on the
# adapter (set to 192.168.1.200 before running the wizard) to find the
# domain, bypassing the VPC Resolver entirely.
#
# After promotion the DC is authoritative for corp.internal. Running
# terraform-identity.yaml (identity_enabled=true) creates the forwarding
# rule, pointing all subsequent VPC corp.internal queries at the local
# replica DC rather than crossing the VPN to the on-prem DC.
#
# The vpc_resolver_ip local is kept here because corporate_main.tf
# references it in the DC user data (global DNS forwarder configuration).
# =====================================================================

locals {
  vpc_resolver_ip = cidrhost(var.vpc_cidr, 2)
}
