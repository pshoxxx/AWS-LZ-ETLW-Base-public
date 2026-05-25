# terraform/corporate/locals.tf

locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  security_account_id = var.security_account_id
}
