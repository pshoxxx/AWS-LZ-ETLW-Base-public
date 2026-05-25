# /terraform/management/locals.tf

# Fetching Management and Member Account IDs, then storing for later use.

locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  management_account_id = data.aws_organizations_organization.org.master_account_id

  management_account = {
    id = data.aws_organizations_organization.org.master_account_id
    email = one([
      for acct in data.aws_organizations_organization.org.accounts
      : acct.email if acct.id == data.aws_organizations_organization.org.master_account_id
    ])
    name = one([
      for acct in data.aws_organizations_organization.org.accounts
      : acct.name if acct.id == data.aws_organizations_organization.org.master_account_id
    ])
  }

  corporate_account = one([
    for acct in data.aws_organizations_organization.org.accounts
    : {
      id     = acct.id
      name   = acct.name
      email  = acct.email
      status = acct.status
    }
    if can(regex("corporate-main", acct.name)) && acct.status == "ACTIVE"
    && acct.id != data.aws_organizations_organization.org.master_account_id
  ])

  networking_account = one([
    for acct in data.aws_organizations_organization.org.accounts
    : {
      id     = acct.id
      name   = acct.name
      email  = acct.email
      status = acct.status
    }
    if can(regex("networking", acct.name)) && acct.status == "ACTIVE"
    && acct.id != data.aws_organizations_organization.org.master_account_id
  ])

  security_account = one([
    for acct in data.aws_organizations_organization.org.accounts
    : {
      id     = acct.id
      name   = acct.name
      email  = acct.email
      status = acct.status
    }
    if can(regex("security", acct.name)) && acct.status == "ACTIVE"
    && acct.id != data.aws_organizations_organization.org.master_account_id
  ])

  shared_services_account = one([
    for acct in data.aws_organizations_organization.org.accounts
    : {
      id     = acct.id
      name   = acct.name
      email  = acct.email
      status = acct.status
    }
    if can(regex("shared-services", acct.name)) && acct.status == "ACTIVE"
    && acct.id != data.aws_organizations_organization.org.master_account_id
  ])
}