# terraform/corporate/corporate_s3gw_dns.tf
# =====================================================================
# S3 Gateway Endpoint and DNS Query Logging - Corporate Account
# =====================================================================

# -- S3 Gateway Endpoint ----------------------------------------------

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = merge(local.common_tags, {
    Name = "corporate-s3-gateway-endpoint"
  })
}

# -- Route 53 Resolver Query Logging ----------------------------------
# DNS query logs from the corporate VPC go to a CloudWatch Logs group
# in this account. Route53 Resolver appends bucket-owner-full-control
# ACL to every S3 PutObject it makes; BucketOwnerEnforced rejects that
# header with AccessControlListNotSupported, which surfaces as RSLVR-01605
# regardless of how permissive the bucket policy is. CloudWatch Logs is
# same-account and avoids all cross-account S3/KMS permission complexity.

resource "aws_cloudwatch_log_group" "resolver_query_logs" {
  name              = "/aws/route53resolver/queries"
  retention_in_days = 365

  # checkov:skip=CKV_AWS_158: CloudWatch Logs KMS encryption with a cross-account
  # CMK (org-logs-cmk in the security account) is not supported by the CW Logs
  # service. A dedicated CMK per account would be required in production. Omitted
  # here to keep the corporate workspace self-contained for this portfolio environment.

  tags = merge(local.common_tags, {
    Name = "corporate-vpc-dns-query-logs"
  })
}

resource "aws_route53_resolver_query_log_config" "corporate" {
  name            = "corporate-vpc-dns-query-logs"
  destination_arn = aws_cloudwatch_log_group.resolver_query_logs.arn

  tags = merge(local.common_tags, {
    Name = "corporate-vpc-dns-query-logs"
  })
}

resource "aws_route53_resolver_query_log_config_association" "corporate" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.corporate.id
  resource_id                  = aws_vpc.main.id
}
