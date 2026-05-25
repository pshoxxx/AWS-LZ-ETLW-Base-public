# terraform/security/siem_flowlogs.tf
# =====================================================================
# VPC Flow Logs - Security Account
#
# Publishes flow logs for the security VPC to the org-logs S3 bucket
# under vpc-flow-logs/security/ in Parquet format.
#
# S3-destination flow logs use the bucket policy for authorization --
# no IAM role is required or accepted (DeliverLogsPermissionArn is
# only valid for CloudWatch Logs destinations).
# =====================================================================

resource "aws_flow_log" "security_vpc" {
  vpc_id               = aws_vpc.main.id
  log_destination      = "${aws_s3_bucket.org_logs.arn}/vpc-flow-logs/security/"
  log_destination_type = "s3"
  traffic_type         = "ALL"

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = merge(local.common_tags, {
    Name = "security-vpc-flow-logs"
  })
}
