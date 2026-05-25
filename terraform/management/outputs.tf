# outputs.tf

output "management_account" {
  value = local.management_account
}

output "corporate_account" {
  value = local.corporate_account
}

output "networking_account" {
  value = local.networking_account
}

output "security_account" {
  value = local.security_account
}

output "org_id" {
  value = data.aws_organizations_organization.org.id
}

output "security_alarms_sns_arn" {
  description = "ARN of the SNS topic that receives security alarm notifications"
  value       = aws_sns_topic.security_alarms.arn
}

output "org_cloudtrail_id" {
  description = "Name of the organization-wide CloudTrail trail"
  value       = aws_cloudtrail.org.id
}

output "org_cloudtrail_arn" {
  description = "ARN of the organization-wide CloudTrail trail"
  value       = aws_cloudtrail.org.arn
}

output "cloudtrail_log_group_name" {
  description = "Name of the CloudWatch Logs log group receiving CloudTrail events"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "ad_connector_id" {
  description = "AD Connector directory ID. Pass to IAM Identity Center (Settings -> Identity source -> Active Directory). Null when identity_enabled=false."
  value       = try(aws_directory_service_directory.ad_connector[0].id, null)
}

output "management_tgw_attachment_id" {
  description = "Management identity VPC TGW attachment ID. Used by networking Phase 3 for RT association. Empty when identity_enabled=false."
  value       = try(aws_ec2_transit_gateway_vpc_attachment.identity[0].id, "")
}

# Reference later with following examples:

# local.corporate_account.id
# local.networking_account.email
# local.security_account.name