# terraform/corporate/variables.tf

variable "account_id" {
  description = "AWS account ID of the corporate account - supplied as TF_VAR_account_id by the deploy workflow and used to form the OrganizationAccountAccessRole ARN in providers.tf"
  type        = string
}

variable "environment" {
  description = "Environment name used for tagging"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the corporate VPC"
  type        = string
  default     = "10.1.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDRs for the two private subnets (one per AZ; both required for the Route 53 Resolver outbound endpoint)"
  type        = list(string)
  default     = ["10.1.10.0/24", "10.1.11.0/24"]
}

variable "ad_domain_name" {
  description = "Active Directory domain name. Queries for this zone are forwarded to the DC by the Route 53 Resolver forwarding rule."
  type        = string
  default     = "corp.internal"
}

variable "dc_private_ip" {
  description = "Static private IP for the corporate domain controller. Used as the Route 53 Resolver forwarding target and pinned on the EC2 instance."
  type        = string
  default     = "10.1.10.4"
}

# Set via TF_VAR_transit_gateway_id in GitHub Actions after the
# network account deploy outputs the TGW ID.
variable "transit_gateway_id" {
  description = "ID of the Transit Gateway in the network account"
  type        = string
}

variable "security_vpc_cidr" {
  description = "CIDR of the security spoke VPC - used for explicit routing"
  type        = string
  default     = "10.2.0.0/16"
}

variable "on_prem_subnet_cidr" {
  description = "On-premises LAN subnet behind the pfSense appliance (pfSense LAN is 192.168.1.x)."
  type        = string
  default     = "192.168.1.0/24"
}

variable "dc_instance_type" {
  description = "EC2 instance type for the domain controller"
  type        = string
  default     = "t3.medium"
}

variable "dns_firewall_rule_group_arn" {
  description = "Baseline DNS Firewall rule group ARN shared from the networking account via RAM. Set as TF_VAR_dns_firewall_rule_group_arn in the deploy workflow."
  type        = string
}

variable "org_logs_bucket_arn" {
  description = "ARN of the org-logs S3 bucket in the security account. Used for cross-account VPC Flow Log delivery."
  type        = string
}

variable "org_logs_bucket_exists" {
  description = "Set to true in Phase 3 once the security account org-logs S3 bucket and its cross-account write policy exist. Resources that deliver logs to org-logs (VPC flow log, Route53 query log config, Config delivery channel + recorder status) are skipped when false so Phase 2 never races against the security account deployment."
  type        = bool
  default     = false
}

variable "on_prem_dc_ip" {
  description = "IP address of the on-premises domain controller (192.168.1.200). Used as the replication source when promoting the AWS DC as a replica in corp.local -- entered manually in the promotion wizard under Additional Options → Replicate from. Not referenced by Terraform resources directly; the AD Connector targets the AWS replica DC (dc_private_ip) for locality. Stored here as the authoritative record of the on-prem DC address for operational reference."
  type        = string
  default     = "192.168.1.200"
}

variable "dc_ami_id" {
  description = "Optional AMI ID of a previously saved corporate DC (created by the cleanup preserve_domain_controllers option). When provided, the DC instance is launched from this AMI instead of the latest Windows Server 2025 base image, preserving AD promotion and domain join state. Pass via the corporate_dc_ami_id workflow dispatch input in terraform-deploy.yaml. Leave empty for a fresh deployment."
  type        = string
  default     = ""
}

variable "security_account_id" {
  description = "AWS account ID of the security account. Used to construct the org-logs S3 bucket name. Supplied as TF_VAR_security_account_id by the deploy workflow."
  type        = string
}

variable "management_identity_cidr" {
  description = "CIDR of the management account identity stub VPC (hosts the AD Connector ENIs). Added to DC security group ingress so the AD Connector can reach the DC over the TGW path."
  type        = string
  default     = "10.3.0.0/24"
}

variable "identity_enabled" {
  description = "Set to true to provision the AD Connector. Requires VPN tunnel up and DC promoted. Applied by the terraform-identity.yaml on-demand workflow; detected and preserved by the regular deploy workflow."
  type        = bool
  default     = false
}

variable "ad_connector_password" {
  description = "Password of the AD account used by the AD Connector (the domain Admin or a delegated service account). Required when identity_enabled=true on the first apply. Subsequent deploys may pass an empty string -- the password field has lifecycle ignore_changes after creation."
  type        = string
  sensitive   = true
  default     = ""
}
