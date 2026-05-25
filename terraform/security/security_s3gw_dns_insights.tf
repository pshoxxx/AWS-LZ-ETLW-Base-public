# terraform/security/s3gw_dns_insights.tf
# =====================================================================
# S3 Gateway Endpoint, DNS Query Logging, CloudTrail Insights
# =====================================================================

# -- S3 Gateway Endpoint ----------------------------------------------
# Keeps S3 traffic (Config delivery, SSM, Glue catalog reads) off NAT.
# Attached to the private route table used by workloads and endpoints.

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = merge(local.common_tags, {
    Name = "security-s3-gateway-endpoint"
  })
}

# -- Route 53 Resolver Query Logging ----------------------------------
# Captures every DNS query made from the security VPC.
# Destination is a same-account CloudWatch Logs group. Route53 Resolver
# appends bucket-owner-full-control ACL to every S3 PutObject it makes;
# BucketOwnerEnforced rejects that header with AccessControlListNotSupported,
# which surfaces as RSLVR-01605 regardless of bucket policy. CWL avoids
# all S3/ACL/cross-account KMS complexity and never produces RSLVR-01306.

resource "aws_cloudwatch_log_group" "resolver_query_logs" {
  name              = "/aws/route53resolver/queries"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.org_logs_cmk.arn

  tags = merge(local.common_tags, {
    Name = "security-vpc-dns-query-logs"
  })
}

resource "aws_route53_resolver_query_log_config" "security" {
  name            = "security-vpc-dns-query-logs"
  destination_arn = aws_cloudwatch_log_group.resolver_query_logs.arn

  tags = merge(local.common_tags, {
    Name = "security-vpc-dns-query-logs"
  })
}

resource "aws_route53_resolver_query_log_config_association" "security" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.security.id
  resource_id                  = aws_vpc.main.id
}
