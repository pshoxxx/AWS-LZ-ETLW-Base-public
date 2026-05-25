# terraform/networking/flowlogs_s3gw.tf
# =====================================================================
# Egress VPC Flow Logs + S3 Gateway Endpoints
#
# Flow Logs: captures all traffic traversing the egress/inspection VPC.
# This is the most valuable flow log position in the topology since every
# spoke-to-internet and spoke-to-spoke packet passes through here.
# Logs go to org-logs in the security account under vpc-flow-logs/networking/.
#
# S3 Gateway Endpoints: free, keeps S3 traffic (Config snapshots,
# CloudTrail delivery, SSM agent downloads) off the NAT Gateway and
# avoids data transfer charges. One endpoint per VPC.
# =====================================================================

# -- Egress VPC Flow Logs ---------------------------------------------
# S3-destination flow logs use the bucket policy for auth - no IAM role.

resource "aws_flow_log" "egress_vpc" {
  count                = var.org_logs_bucket_exists ? 1 : 0
  vpc_id               = aws_vpc.egress.id
  log_destination      = "arn:aws:s3:::org-logs-${var.security_account_id}-v2/vpc-flow-logs/networking/"
  log_destination_type = "s3"
  traffic_type         = "ALL"

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = merge(local.common_tags, {
    Name = "networking-egress-vpc-flow-logs"
  })
}

# -- S3 Gateway Endpoint - Egress VPC ---------------------------------
# Routes S3 API calls from the egress VPC through the AWS backbone.
# Attach to all route tables in the VPC so every subnet benefits.

resource "aws_vpc_endpoint" "s3_egress" {
  vpc_id            = aws_vpc.egress.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    aws_route_table.tgw_attachment[*].id,
    aws_route_table.firewall_external[*].id,
    aws_route_table.firewall_internal[*].id,
    aws_route_table.alb[*].id,
    aws_route_table.nat[*].id,
  )

  tags = merge(local.common_tags, {
    Name = "networking-s3-gateway-endpoint"
  })
}
