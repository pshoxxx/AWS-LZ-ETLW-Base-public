# terraform/networking/variables.tf

variable "account_id" {
  description = "AWS account ID of the networking account. Used to form the OrganizationAccountAccessRole ARN in providers.tf."
  type        = string
}

variable "environment" {
  description = "Environment name applied to all resource tags."
  type        = string
  default     = "dev"
}

# -- Egress VPC -------------------------------------------------------

variable "egress_vpc_cidr" {
  description = "CIDR block for the Inspection/Egress VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "egress_alb_subnet_cidrs" {
  description = "Two CIDR blocks for the ALB ingress subnets (one per AZ). Hosts the internet-facing ALB ENIs only; NAT Gateways are in egress_nat_subnet_cidrs."
  type        = list(string)
  default     = ["10.0.0.0/24", "10.0.1.0/24"]

  validation {
    condition     = length(var.egress_alb_subnet_cidrs) == 2
    error_message = "Exactly 2 ALB subnet CIDRs required."
  }
}

variable "egress_nat_subnet_cidrs" {
  description = "Two CIDR blocks for the NAT Gateway egress subnets (one per AZ). Isolated from ALB subnets so each tier can have its own route table for symmetric NF inspection."
  type        = list(string)
  default     = ["10.0.2.0/24", "10.0.3.0/24"]

  validation {
    condition     = length(var.egress_nat_subnet_cidrs) == 2
    error_message = "Exactly 2 NAT subnet CIDRs required."
  }
}

variable "egress_tgw_attachment_subnet_cidrs" {
  description = "Two /28 CIDR blocks for TGW ENI subnets."
  type        = list(string)
  default     = ["10.0.10.0/28", "10.0.10.16/28"]

  validation {
    condition     = length(var.egress_tgw_attachment_subnet_cidrs) == 2
    error_message = "Exactly 2 TGW attachment subnet CIDRs required."
  }
}

variable "egress_firewall_external_subnet_cidrs" {
  description = "Two /28 CIDR blocks for the external (north-south) Network Firewall endpoints handling the web ALB ingress path (internet -> ALB and ALB return -> internet)."
  type        = list(string)
  default     = ["10.0.10.32/28", "10.0.10.48/28"]

  validation {
    condition     = length(var.egress_firewall_external_subnet_cidrs) == 2
    error_message = "Exactly 2 external firewall subnet CIDRs required."
  }
}

variable "egress_firewall_internal_subnet_cidrs" {
  description = "Two /28 CIDR blocks for the internal (east-west + spoke egress) Network Firewall endpoints handling spoke<->spoke, spoke<->on-prem (VPN), and spoke -> NAT -> internet (and return)."
  type        = list(string)
  default     = ["10.0.10.64/28", "10.0.10.80/28"]

  validation {
    condition     = length(var.egress_firewall_internal_subnet_cidrs) == 2
    error_message = "Exactly 2 internal firewall subnet CIDRs required."
  }
}

# -- Spoke VPC CIDRs --------------------------------------------------

variable "corporate_vpc_cidr" {
  description = "CIDR of the corporate spoke VPC."
  type        = string
  default     = "10.1.0.0/16"
}

variable "security_vpc_cidr" {
  description = "CIDR of the security spoke VPC."
  type        = string
  default     = "10.2.0.0/16"
}

# -- Cross-Account TGW Attachment IDs (Phase 3) -----------------------

variable "corporate_tgw_attachment_id" {
  description = "TGW attachment ID from the corporate account. Leave empty until Phase 3."
  type        = string
  default     = ""
}

variable "security_tgw_attachment_id" {
  description = "TGW attachment ID from the security account. Leave empty until Phase 3."
  type        = string
  default     = ""
}

# -- Account IDs ------------------------------------------------------

variable "corporate_account_id" {
  description = "AWS account ID of the corporate account."
  type        = string
}

variable "security_account_id" {
  description = "AWS account ID of the security account."
  type        = string
}

variable "management_account_id" {
  description = "AWS account ID of the management account. Used to share the TGW via RAM for the management identity stub VPC attachment."
  type        = string
  default     = ""
}

variable "management_tgw_attachment_id" {
  description = "TGW attachment ID for the management identity stub VPC. Leave empty until after terraform-identity.yaml has run."
  type        = string
  default     = ""
}

variable "management_vpc_cidr" {
  description = "CIDR of the management identity stub VPC. Used in the Network Firewall pass rule for management-to-corporate AD traffic."
  type        = string
  default     = "10.3.0.0/24"
}

variable "web_account_id" {
  description = "AWS account ID of the web account. Used to share the TGW and DNS Firewall rule group via RAM."
  type        = string
  default     = ""
}

variable "web_vpc_cidr" {
  description = "CIDR of the web spoke VPC. Propagated into the Egress RT so post-firewall return traffic can reach the web account."
  type        = string
  default     = "10.4.0.0/16"
}

variable "web_tgw_attachment_id" {
  description = "TGW attachment ID from the web account. Leave empty until Phase 3."
  type        = string
  default     = ""
}

# -- On-Premises ------------------------------------------------------

variable "on_prem_subnet_cidr" {
  description = "On-premises LAN subnet reachable via Site-to-Site VPN. Matches the pfSense LAN subnet (192.168.1.x)."
  type        = string
  default     = "192.168.1.0/24"
}

variable "on_prem_wan_ip" {
  description = "Public WAN IP of the on-premises pfSense firewall."
  type        = string
}

variable "on_prem_bgp_asn" {
  description = "BGP ASN for the customer gateway."
  type        = number
  default     = 65000
}

# -- Network Firewall -------------------------------------------------

variable "allowed_egress_domains" {
  description = "Domains permitted outbound through Network Firewall (HTTP_HOST + TLS_SNI). Per AWS NF docs, a leading '.' is a wildcard prefix that matches the bare domain AND all subdomains (e.g., '.github.com' matches both 'github.com' and 'api.github.com'). Bare-domain entries without the dot match ONLY the bare form, so the dotted form is preferred when both are wanted. AWS NF rejects entries that are functionally duplicates. The architecture is allowlist-enforced -- anything not on this list is dropped by the internal Network Firewall."
  type        = list(string)
  default = [
    # AWS service endpoints (yum updates from regional package mirrors,
    # other AWS API egress not already routed via VPC endpoints)
    ".amazonaws.com",
    # GitHub (API + raw content + bare github.com via wildcard prefix)
    ".github.com",
    ".githubusercontent.com",
    # Package / registry sources commonly hit by EC2 software update flows
    ".docker.io",
    ".docker.com",
    ".pypi.org",
    ".python.org",
    ".fedoraproject.org",
    # IANA reserved test domain (RFC 2606) -- useful for verifying egress
    ".example.com",
  ]
}

variable "security_log_bucket_name" {
  description = "S3 bucket name in the Security account for Network Firewall logs."
  type        = string
}

variable "org_logs_bucket_exists" {
  description = "Set to true in Phase 3 once the security account org-logs S3 bucket and its cross-account write policy exist. Resources that deliver logs to org-logs (Network Firewall logging config, VPC flow logs, Config delivery channel + recorder status) are skipped when false so Phase 1 never races against the security account deployment."
  type        = bool
  default     = false
}

# -- DNS Firewall -----------------------------------------------------

variable "dns_firewall_blocked_domains" {
  description = "Custom domain list to block via DNS Firewall (NXDOMAIN)."
  type        = list(string)
  default     = []
}

variable "dns_firewall_alert_domains" {
  description = "Domain list to alert on (not block) via DNS Firewall."
  type        = list(string)
  default     = []
}

variable "aws_managed_domain_list_aggregate_id" {
  description = "ID of the AWSManagedDomainsAggregateThreatList for the deployment region."
  type        = string
}
