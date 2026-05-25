# terraform/management/cloudtrail.tf

# Import for resources that already exist
import {
  to = aws_cloudwatch_log_group.cloudtrail
  id = "/aws/cloudtrail/org"
}

import {
  to = aws_iam_role.cloudtrail_cloudwatch
  id = "cloudtrail-to-cloudwatch-logs"
}

import {
  to = aws_iam_role_policy.cloudtrail_cloudwatch
  id = "cloudtrail-to-cloudwatch-logs:cloudtrail-to-cloudwatch-logs"
}
# =====================================================================
# CloudWatch Log Group — CloudTrail
# =====================================================================

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/org"
  retention_in_days = 365
  kms_key_id        = data.terraform_remote_state.security.outputs.org_logs_cmk_arn

  tags = merge(local.common_tags, {
  })

  lifecycle {
    prevent_destroy = true
    # kms_key_id comes from security remote state. When security has not
    # fully deployed, the default is the real key ARN looked up directly.
    # ignore_changes prevents accidental removal of encryption.
    ignore_changes = [kms_key_id]
  }
}

# =====================================================================
# IAM Role — CloudTrail → CloudWatch Logs
# =====================================================================

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "cloudtrail-to-cloudwatch-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.management_account_id
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "cloudtrail-to-cloudwatch-logs"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogStreamAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

# =====================================================================
# Organization-Wide CloudTrail Trail
# =====================================================================

resource "aws_cloudtrail" "org" {
  name           = "org-cloudtrail"
  s3_bucket_name = data.terraform_remote_state.security.outputs.org_logs_bucket_id
  s3_key_prefix  = "cloudtrail"

  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true

  kms_key_id = data.terraform_remote_state.security.outputs.org_logs_cmk_arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  tags = merge(local.common_tags, {
  })

  depends_on = [
    aws_iam_role_policy.cloudtrail_cloudwatch,
  ]

  lifecycle {
    prevent_destroy = true
    # s3_bucket_name and kms_key_id come from security remote state.
    # ignore_changes prevents the trail from being updated with fallback
    # values when security state outputs are temporarily unavailable.
    ignore_changes = [s3_bucket_name, kms_key_id]
  }
}
