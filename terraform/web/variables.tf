variable "account_id" {
  description = "AWS account ID of the web account - supplied as TF_VAR_account_id by the deploy workflow"
  type        = string
}

variable "environment" {
  description = "Environment name used for tagging"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the web VPC"
  type        = string
  default     = "10.4.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "Two CIDR blocks for private subnets (EC2 and Aurora, one per AZ)"
  type        = list(string)
  default     = ["10.4.10.0/24", "10.4.11.0/24"]

  validation {
    condition     = length(var.private_subnet_cidrs) == 2
    error_message = "Exactly 2 private subnet CIDRs required."
  }
}

variable "tgw_attachment_subnet_cidrs" {
  description = "Two /28 CIDR blocks for TGW ENI subnets"
  type        = list(string)
  default     = ["10.4.20.0/28", "10.4.21.0/28"]

  validation {
    condition     = length(var.tgw_attachment_subnet_cidrs) == 2
    error_message = "Exactly 2 TGW attachment subnet CIDRs required."
  }
}

variable "transit_gateway_id" {
  description = "ID of the Transit Gateway in the networking account"
  type        = string
}

variable "networking_account_id" {
  description = "AWS account ID of the networking account. Used to restrict the VPC Endpoint Service to the networking account only."
  type        = string
}

variable "dns_firewall_rule_group_arn" {
  description = "Baseline DNS Firewall rule group ARN shared from the networking account via RAM"
  type        = string
}

variable "org_logs_bucket_arn" {
  description = "ARN of the org-logs S3 bucket in the security account. Used for VPC Flow Log delivery."
  type        = string
}

variable "org_logs_bucket_exists" {
  description = "Set to true in Phase 3 once the org-logs bucket and its cross-account write policy exist. VPC flow logs are skipped when false."
  type        = bool
  default     = false
}

variable "web_instance_type" {
  description = "EC2 instance type for the web servers"
  type        = string
  default     = "t2.micro"
}

variable "aurora_min_capacity" {
  description = "Aurora Serverless v2 minimum ACU capacity"
  type        = number
  default     = 0.5
}

variable "aurora_max_capacity" {
  description = "Aurora Serverless v2 maximum ACU capacity"
  type        = number
  default     = 1
}
