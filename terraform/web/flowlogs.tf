# terraform/web/flowlogs.tf
# =====================================================================
# VPC Flow Logs - Web Account
#
# Gated by org_logs_bucket_exists (Phase 3) so the first deploy never
# races against the security account S3 bucket creation.
# delivery.logs.amazonaws.com is already allowed by the org-logs bucket
# policy (aws:SourceOrgID condition covers all org accounts).
# =====================================================================

resource "aws_flow_log" "web_vpc" {
  count           = var.org_logs_bucket_exists ? 1 : 0
  vpc_id          = aws_vpc.main.id
  log_destination = "${var.org_logs_bucket_arn}/vpc-flow-logs/web/"
  traffic_type    = "ALL"

  log_destination_type = "s3"
  log_format           = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = merge(local.common_tags, {
    Name = "web-vpc-flow-logs"
  })
}
