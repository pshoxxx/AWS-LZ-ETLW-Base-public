# terraform/security/variables.tf

variable "account_id" {
  description = "AWS account ID of the security account - supplied as TF_VAR_account_id by the deploy workflow and used to form the OrganizationAccountAccessRole ARN in providers.tf"
  type        = string
}

variable "environment" {
  description = "Environment name used for tagging"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the security VPC"
  type        = string
  default     = "10.2.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDRs for the two private subnets (one per AZ; both required for the Route 53 Resolver outbound endpoint)"
  type        = list(string)
  default     = ["10.2.10.0/24", "10.2.11.0/24"]
}

variable "ad_domain_name" {
  description = "Active Directory domain name. Queries for this zone are forwarded to the corporate DC replica by the Route 53 Resolver forwarding rule."
  type        = string
  default     = "corp.internal"
}

variable "corporate_dc_ip" {
  description = "Private IP of the corporate DC replica (10.1.10.4). The security VPC Route 53 Resolver forwards corp.internal queries across the TGW to this DC rather than hosting a local DC. The corporate DC security group already permits DNS inbound from the security VPC CIDR (10.2.0.0/16)."
  type        = string
  default     = "10.1.10.4"
}

variable "transit_gateway_id" {
  description = "ID of the Transit Gateway in the network account"
  type        = string
}

variable "corporate_vpc_cidr" {
  description = "CIDR of the corporate spoke VPC - used for explicit routing"
  type        = string
  default     = "10.1.0.0/16"
}

variable "on_prem_subnet_cidr" {
  description = "On-premises LAN subnet behind the pfSense appliance"
  type        = string
  default     = "192.168.1.0/24"
}


variable "import_existing_log_buckets" {
  description = "Set to true to import pre-existing org log S3 buckets rather than creating new ones"
  type        = bool
  default     = false
}

variable "dns_firewall_rule_group_arn" {
  description = "Baseline DNS Firewall rule group ARN shared from the networking account via RAM. Set as TF_VAR_dns_firewall_rule_group_arn in the deploy workflow."
  type        = string
}

variable "networking_account_id" {
  description = "AWS account ID of the networking account, used to scope the org-logs bucket policy for Network Firewall log delivery."
  type        = string
}

# FIX (Bug 13): controls whether the Config service-linked role is imported
# from an existing account rather than created fresh.
# Set to true for the security account where Config was enabled manually
# before Terraform was introduced. Leave false for brand-new accounts.
variable "import_config_slr" {
  description = "Set to true to import a pre-existing AWSServiceRoleForConfig SLR rather than creating it. Use when Config was enabled manually in this account before Terraform."
  type        = bool
  default     = false
}

# -- SIEM Variables ---------------------------------------------------

variable "corporate_account_id" {
  description = "AWS account ID of the corporate account. Used to scope the VPC Flow Logs bucket policy for cross-account delivery."
  type        = string
}

variable "web_account_id" {
  description = "AWS account ID of the web account. Used together with the other account IDs to build the enum partition-projection list on the vpc_flow_logs Glue table so Athena queries don't need a static aws_account_id filter."
  type        = string
  default     = ""
}

variable "siem_alert_email" {
  description = "Email address for SIEM detection alerts. Leave empty to skip SNS email subscription."
  type        = string
  default     = ""
}

variable "siem_schedule_enabled" {
  description = "Set to true to enable the EventBridge 15-minute schedule for the SIEM Lambda. Leave false to invoke manually."
  type        = bool
  default     = false
}

variable "org_logs_bucket_arn" {
  description = "ARN of the org-logs S3 bucket. Exported as an output from this module and consumed by other modules (e.g. corporate flow logs)."
  type        = string
  default     = ""
}
