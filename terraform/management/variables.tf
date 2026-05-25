# terraform/management/variables.tf

variable "account_id" {
  description = "AWS account ID of the management account -- supplied as TF_VAR_account_id by the deploy workflow. Used for explicit account-ID references without depending on a data source at plan time."
  type        = string
}

variable "environment" {
  description = "Environment name used for tagging"
  type        = string
  default     = "dev"
}

variable "alarm_email" {
  description = "Email address for security alarm notifications. Leave empty to skip subscription."
  type        = string
  default     = ""
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket used for Terraform remote state. Used to read security account outputs."
  type        = string
}

variable "security_account_id" {
  description = "AWS account ID of the security-environment account."
  type        = string
}

variable "networking_account_id" {
  description = "AWS account ID of the networking-environment account. Used by management to assume into networking and provision the cross-account OAM link pointing at security's observability sink. Optional -- if empty, the management workspace skips OAM link creation (used by the SCPs-only early apply where these IDs aren't yet resolved)."
  type        = string
  default     = ""
}

variable "corporate_account_id" {
  description = "AWS account ID of the corporate-environment account. See networking_account_id for details."
  type        = string
  default     = ""
}

variable "web_account_id" {
  description = "AWS account ID of the web-environment account. See networking_account_id for details."
  type        = string
  default     = ""
}

variable "import_access_analyzer_slr" {
  description = "Set to true to import a pre-existing AWSServiceRoleForAccessAnalyzer SLR rather than creating it. Use when Access Analyzer was enabled manually in this account before Terraform."
  type        = bool
  default     = false
}

variable "enable_identity_center" {
  description = "Set to true after IAM Identity Center has been manually enabled in the management account. Creates all Permission Sets and policy attachments."
  type        = bool
  default     = true
}

variable "enable_sso_assignments" {
  description = "Set to true after AD Connector is configured and the Cloud-Access AD groups are synced into Identity Center. Creates account assignments linking AD groups to Permission Sets."
  type        = bool
  default     = true
}

variable "identity_enabled" {
  description = "Set to true to provision the management identity stub VPC and AD Connector. Run terraform-identity.yaml after DC promotion."
  type        = bool
  default     = false
}

variable "ad_connector_password" {
  description = "Password for the AD Connector service account. Required when identity_enabled=true. Sourced from TF_VAR_AD_CONNECTOR_PASSWORD secret."
  type        = string
  sensitive   = true
  default     = ""
}

variable "transit_gateway_id" {
  description = "ID of the Transit Gateway. Required when identity_enabled=true to attach the management identity VPC."
  type        = string
  default     = ""
}

variable "dc_private_ip" {
  description = "Private IP of the corporate domain controller (dc01-corporate). AD Connector points at this IP."
  type        = string
  default     = "10.1.10.4"
}

variable "ad_domain_name" {
  description = "Active Directory domain FQDN for the AD Connector."
  type        = string
  default     = "corp.internal"
}

variable "identity_vpc_cidr" {
  description = "CIDR block for the management identity stub VPC that hosts the AD Connector ENIs. Must not overlap with corporate, security, or networking VPC ranges."
  type        = string
  default     = "10.3.0.0/24"
}
