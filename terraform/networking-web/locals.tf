locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  web_ingress_enabled = var.web_endpoint_service_name != ""
}
