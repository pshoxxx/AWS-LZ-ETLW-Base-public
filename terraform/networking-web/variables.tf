variable "account_id" {
  description = "Networking account ID -- forms the OrganizationAccountAccessRole ARN in providers.tf."
  type        = string
}

variable "environment" {
  description = "Environment tag applied to all resources."
  type        = string
  default     = "dev"
}

variable "state_bucket_name" {
  description = "S3 bucket holding Terraform remote state -- used to read networking workspace outputs."
  type        = string
}

variable "web_endpoint_service_name" {
  description = "VPC Endpoint Service name from the web account NLB. Empty string disables all web ingress resources."
  type        = string
  default     = ""
}

variable "egress_vpc_cidr" {
  description = "CIDR of the egress VPC -- used for the ALB-to-endpoint SG CIDR rule."
  type        = string
  default     = "10.0.0.0/16"
}
