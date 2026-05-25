# data.tf

data "aws_organizations_organization" "org" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Reads security account's state to get the KMS key ARN and log bucket
# name that CloudTrail and the CloudWatch log group depend on.
# Security must be fully deployed before management can plan successfully.
data "terraform_remote_state" "security" {
  backend = "s3"
  config = {
    bucket = var.state_bucket_name
    key    = "security/terraform.tfstate"
    region = data.aws_region.current.name
  }

  # Static fallback values for when security has not yet fully deployed.
  # CloudTrail and CloudWatch log group use ignore_changes on the fields
  # that reference these outputs, so empty fallbacks will not trigger
  # updates to live infrastructure.
  defaults = {
    org_logs_cmk_arn    = ""
    org_logs_bucket_id  = ""
    org_logs_bucket_arn = ""
    vpc_id              = ""
    vpc_cidr            = ""
    private_subnet_ids  = []
    tgw_attachment_id   = ""
    dc_instance_id      = ""
    dc_private_ip       = ""
    siem_sns_topic_arn  = ""
    siem_lambda_name    = ""
  }
}

locals {
  # Looks up the security account ID by name from the org account list
  # rather than requiring it to be hardcoded or passed as a variable.
  security_account_id = [
    for account in data.aws_organizations_organization.org.accounts :
    account.id if account.name == "security-environment" && account.status == "ACTIVE"
  ][0]
}
