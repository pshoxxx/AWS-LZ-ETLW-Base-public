# terraform/web/locals.tf

locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
