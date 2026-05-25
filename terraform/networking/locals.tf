# terraform/networking/locals.tf

locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  security_account_id = var.security_account_id

  # Pin to exactly 2 AZs for consistent index-based referencing.
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # AWS Network Firewall limits one endpoint per AZ per firewall, so the
  # external (north-south web) and internal (east-west + spoke egress)
  # traffic classes use separate firewall resources. Each has its own
  # sync_states; we map subnet_id -> endpoint_id and then order the
  # results by subnet index so [0] always corresponds to AZ[0].

  fw_external_endpoint_by_subnet = {
    for ss in tolist(aws_networkfirewall_firewall.external.firewall_status[0].sync_states) :
    ss.attachment[0].subnet_id => ss.attachment[0].endpoint_id
  }

  fw_internal_endpoint_by_subnet = {
    for ss in tolist(aws_networkfirewall_firewall.internal.firewall_status[0].sync_states) :
    ss.attachment[0].subnet_id => ss.attachment[0].endpoint_id
  }

  fw_external_endpoint_ids = [
    for sid in aws_subnet.firewall_external[*].id : local.fw_external_endpoint_by_subnet[sid]
  ]

  fw_internal_endpoint_ids = [
    for sid in aws_subnet.firewall_internal[*].id : local.fw_internal_endpoint_by_subnet[sid]
  ]
}
