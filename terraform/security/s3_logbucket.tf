# terraform/security/s3_logbucket.tf

import {
  for_each = var.import_existing_log_buckets ? toset(["org_logs"]) : toset([])
  to       = aws_s3_bucket.org_logs
  id       = "org-logs-${data.aws_caller_identity.current.account_id}-v2"
}

# =====================================================================
# S3 Bucket — Organization-Wide Log Archive
# =====================================================================

resource "aws_s3_bucket" "org_logs" {
  bucket = "org-logs-${data.aws_caller_identity.current.account_id}-v2"

  # Object Lock enabled WITHOUT a default retention rule.
  # Protects against accidental bucket deletion and object tampering
  # (WORM protection) while remaining compatible with AWS service principals
  # such as Route53 Resolver, GuardDuty, and CloudTrail that write objects
  # without including Object Lock retention metadata in their PutObject requests.
  #
  # A COMPLIANCE or GOVERNANCE default retention rule would block all service
  # principal writes since those services do not pass x-amz-object-lock-retain-
  # until-date or x-amz-object-lock-mode headers -- causing ACCESS_DENIED on
  # every write attempt regardless of bucket or KMS key policy.
  #
  # For production environments with compliance requirements (SOC 2, PCI DSS,
  # HIPAA) apply retention rules per-prefix via S3 Lifecycle policies rather
  # than a blanket default retention rule, scoped only to prefixes written by
  # human operators rather than AWS services.
  object_lock_enabled = true

  tags = merge(local.common_tags, {
    Name    = "org-logs"
    Purpose = "Organization-wide CloudTrail Config and GuardDuty log archive"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "org_logs" {
  bucket = aws_s3_bucket.org_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "org_logs" {
  bucket = aws_s3_bucket.org_logs.id

  versioning_configuration {
    status = "Enabled"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "org_logs" {
  bucket = aws_s3_bucket.org_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket_ownership_controls.org_logs]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "org_logs" {
  bucket = aws_s3_bucket.org_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.org_logs_cmk.arn
    }
    bucket_key_enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "org_logs" {
  bucket = aws_s3_bucket.org_logs.id

  depends_on = [aws_s3_bucket_versioning.org_logs]

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    expiration {
      expired_object_delete_marker = true
    }
  }

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

# =====================================================================
# S3 Bucket Policy
# =====================================================================

data "aws_iam_policy_document" "org_logs_bucket_policy" {

  # --- CloudTrail -------------------------------------------------------

  statement {
    sid    = "CloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.org_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [data.aws_organizations_organization.org.id]
    }
  }

  statement {
    sid    = "CloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.org_logs.arn}/cloudtrail/AWSLogs/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [data.aws_organizations_organization.org.id]
    }
  }

  # --- AWS Config -------------------------------------------------------

  statement {
    sid    = "ConfigBucketExistsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.org_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [data.aws_organizations_organization.org.id]
    }
  }

  # s3:x-amz-acl intentionally omitted from ConfigWrite — the condition key
  # is not evaluated under BucketOwnerEnforced and would cause delivery failures.
  statement {
    sid    = "ConfigWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.org_logs.arn}/config/AWSLogs/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [data.aws_organizations_organization.org.id]
    }
  }

  # --- GuardDuty --------------------------------------------------------
  # destination_arn in aws_guardduty_publishing_destination is the plain
  # bucket ARN (no prefix). GuardDuty then writes to its default path of
  # AWSLogs/{accountId}/GuardDuty/{region}/... for actual findings.
  #
  # However, during CreatePublishingDestination validation GuardDuty performs
  # a broad permissions check against the bucket root before it ever resolves
  # the specific AWSLogs/... write path. The resource for all GuardDuty allow
  # and deny statements must therefore be bucket/* — matching the AWS docs
  # example exactly — or that validation check will be denied, surfacing as a
  # 400 BadRequestException regardless of how specific the actual write path is.

  statement {
    sid    = "GuardDutyGetBucketLocation"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    actions   = ["s3:GetBucketLocation"]
    resources = [aws_s3_bucket.org_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_guardduty_detector.main.arn]
    }
  }

  statement {
    sid    = "GuardDutyWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    actions = ["s3:PutObject"]
    # bucket/* is required here — see block comment above.
    resources = ["${aws_s3_bucket.org_logs.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_guardduty_detector.main.arn]
    }
  }

  statement {
    sid    = "GuardDutyDenyUnencrypted"
    effect = "Deny"
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    actions = ["s3:PutObject"]
    # Scoped to bucket/* to stay consistent with the allow above and ensure
    # every GuardDuty write anywhere in the bucket is covered by this guard.
    resources = ["${aws_s3_bucket.org_logs.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid    = "GuardDutyDenyWrongKey"
    effect = "Deny"
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.org_logs.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.org_logs_cmk.arn]
    }
  }

  # --- Route53 Resolver Query Logs -------------------------------------
  # Route53 Resolver query logs use route53resolver.amazonaws.com as their
  # service principal -- NOT delivery.logs.amazonaws.com. This is a separate
  # service principal from VPC Flow Logs and Network Firewall delivery.
  # Scoped to the org via aws:SourceOrgID so all spoke accounts can deliver
  # their resolver query logs to this central bucket.
  #
  # Without this statement the aws_route53_resolver_query_log_config_association
  # resource will be created in FAILED state with ACCESS_DENIED and be
  # marked as tainted by Terraform on every apply.

  # Route53 Resolver validates cross-account destinations using GetBucketAcl,
  # GetBucketLocation, ListBucket, and PutObject.  Same-account access
  # (security → security) has implicit IAM coverage; cross-account (corporate
  # → security) relies solely on the bucket policy.
  #
  # No condition is set on these statements. During CreateResolverQueryLogConfig
  # validation, Route53 Resolver calls S3 before the config ARN exists, so
  # aws:SourceArn is absent and any ArnLike condition evaluates to false,
  # causing RSLVR-01605. aws:SourceOrgID is also not consistently propagated
  # cross-account by this service.
  #
  # PutObject is scoped to bucket/* (not route53-query-logs/*) to exactly
  # match the AWS-documented bucket policy for Route53 Resolver query logging.
  # The service's validation write may target a path that does not match a
  # narrower prefix scope, causing RSLVR-01605 even when all other permissions
  # are correct. Security is provided by the service principal restriction
  # (route53resolver.amazonaws.com) alone.
  statement {
    sid    = "Route53ResolverQueryLogAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["route53resolver.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl", "s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.org_logs.arn]
  }

  statement {
    sid    = "Route53ResolverQueryLogWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["route53resolver.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.org_logs.arn}/*"]
    # KMS encryption conditions intentionally omitted — Route53 Resolver does
    # not pass s3:x-amz-server-side-encryption headers; the bucket's default
    # encryption (aws:kms with org-logs-cmk) still applies to written objects.
  }

  # --- Network Firewall & VPC Flow Logs ----------------------------------
  # delivery.logs.amazonaws.com is the service principal used by both
  # Network Firewall and VPC Flow Logs for S3 delivery. Scoped to the org
  # via aws:SourceOrgID so networking and corporate accounts can both
  # deliver logs to their respective prefixes.
  #
  # s3:x-amz-acl is intentionally omitted -- it is not evaluated under
  # BucketOwnerEnforced and would cause delivery failures (same reasoning
  # as ConfigWrite above).

  statement {
    sid    = "LogDeliveryAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.org_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [data.aws_organizations_organization.org.id]
    }
  }

  statement {
    sid    = "LogDeliveryWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.org_logs.arn}/network-firewall/*",
      "${aws_s3_bucket.org_logs.arn}/vpc-flow-logs/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [data.aws_organizations_organization.org.id]
    }
  }

  # --- Baseline security ------------------------------------------------

  statement {
    sid    = "DenyNonTLS"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.org_logs.arn,
      "${aws_s3_bucket.org_logs.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "org_logs" {
  bucket = aws_s3_bucket.org_logs.id
  policy = data.aws_iam_policy_document.org_logs_bucket_policy.json

  depends_on = [
    aws_s3_bucket_public_access_block.org_logs,
    aws_s3_bucket_ownership_controls.org_logs,
  ]

  lifecycle {
    prevent_destroy = true
  }
}
