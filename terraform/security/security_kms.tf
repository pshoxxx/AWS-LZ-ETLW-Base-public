# terraform/security/kms.tf

resource "aws_kms_key" "org_logs_cmk" {
  description             = "CMK for encrypting organization-wide CloudTrail, Config, and GuardDuty logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityAccountKeyAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "ManagementAccountKeyDelegation"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_organizations_organization.org.master_account_id}:root"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            # Covers org trail (trail/*) and Insights event data stores (eventdatastore/*)
            # in the management account. Both use the cloudtrail service principal with
            # an ARN in the encryption context.
            "kms:EncryptionContext:aws:cloudtrail:arn" = [
              "arn:aws:cloudtrail:*:${data.aws_organizations_organization.org.master_account_id}:trail/*",
              "arn:aws:cloudtrail:*:${data.aws_organizations_organization.org.master_account_id}:eventdatastore/*",
            ]
          }
          StringEquals = {
            "aws:SourceOrgID" = data.aws_organizations_organization.org.id
          }
        }
      },
      {
        Sid    = "CloudTrailValidationDecrypt"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          Null = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "false"
          }
        }
      },
      {
        Sid    = "ConfigEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceOrgID" = data.aws_organizations_organization.org.id
          }
        }
      },
      {
        Sid    = "CloudWatchLogsEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            # Management account: CloudTrail log group.
            # Security account: Route53 Resolver query log group.
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:aws:logs:${data.aws_region.current.name}:${data.aws_organizations_organization.org.master_account_id}:log-group:*",
              "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*",
            ]
          }
        }
      },
      {
        # Allows GuardDuty to encrypt findings exported to the CMK-encrypted
        # S3 bucket. Scoped to both the security account and the specific
        # detector ARN as required by the GuardDuty export findings docs.
        Sid    = "GuardDutyEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
            "aws:SourceArn"     = aws_guardduty_detector.main.arn
          }
        }
      },
      {
        # Allows the SIEM Lambda and Glue crawler roles to decrypt objects
        # from the CMK-encrypted S3 bucket for Athena queries and crawling.
        Sid    = "AthenaAndLambdaDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/siem-detector-lambda-role",
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/siem-glue-catalog-role",
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      {
        # Allows Athena to decrypt objects when running queries against
        # the CMK-encrypted S3 bucket.
        Sid    = "AthenaServiceDecrypt"
        Effect = "Allow"
        Principal = {
          Service = "athena.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        # Allows Route53 Resolver to encrypt query logs written to the
        # CMK-encrypted S3 bucket. Route53 Resolver does not pass SSE
        # headers directly -- instead it calls kms:GenerateDataKey via
        # the S3 encryption context when writing objects. Without this
        # statement the query log config association reaches FAILED state
        # with ACCESS_DENIED even when the bucket policy is correct.
        #
        # No condition is set here. During CreateResolverQueryLogConfig
        # validation, aws:SourceArn is absent (the config ARN doesn't exist
        # yet) so any ArnLike condition evaluates to false and KMS denies
        # the call silently -- surfacing only as RSLVR-01605 on the S3 side.
        # aws:SourceOrgID is also not consistently propagated cross-account
        # by this service. Security is provided by the service principal
        # restriction (route53resolver.amazonaws.com) alone.
        Sid    = "Route53ResolverEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "route53resolver.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
      },
      {
        # Allows VPC Flow Logs and Network Firewall (both use the
        # delivery.logs.amazonaws.com service principal) to encrypt objects
        # written to the CMK-encrypted org-logs S3 bucket.  Without this,
        # the S3 PutObject call from the delivery service is denied by KMS
        # even when the bucket policy is correct, surfacing as
        # "Access Denied for LogDestination" in the Flow Logs / Firewall API.
        # Scoped to the org so all spoke accounts can deliver logs.
        Sid    = "LogDeliveryEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceOrgID" = data.aws_organizations_organization.org.id
          }
        }
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "org-logs-cmk"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "org_logs_cmk" {
  name          = "alias/org-logs-cmk"
  target_key_id = aws_kms_key.org_logs_cmk.key_id

  lifecycle {
    prevent_destroy = true
  }
}
