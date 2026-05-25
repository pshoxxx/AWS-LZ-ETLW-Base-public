# terraform/corporate/flowlogs.tf
# =====================================================================
# VPC Flow Logs - Corporate Account
#
# Publishes flow logs for the corporate VPC to the centralized org-logs
# S3 bucket in the security account under vpc-flow-logs/corporate/.
#
# Cross-account S3 delivery:
# The delivery.logs.amazonaws.com service writes on behalf of the
# corporate account. The org-logs bucket policy in the security account
# (s3_logbucket.tf) includes a statement allowing this service principal
# from the corporate account ID. That statement is added in the security
# module via var.corporate_account_id.
#
# No IAM role is needed for S3-destination flow logs - the service uses
# the bucket policy directly. An IAM role is only required for
# CloudWatch Logs destinations.
# =====================================================================

resource "aws_flow_log" "corporate_vpc" {
  count           = var.org_logs_bucket_exists ? 1 : 0
  vpc_id          = aws_vpc.main.id
  log_destination = "${var.org_logs_bucket_arn}/vpc-flow-logs/corporate/"
  traffic_type    = "ALL"

  log_destination_type = "s3"
  log_format           = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = merge(local.common_tags, {
    Name = "corporate-vpc-flow-logs"
  })
}
