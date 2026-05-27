# terraform/management/security_delegations.tf

# SNS alarm topic for CloudWatch security alarms (CIS/FSBP controls).
# Receives notifications from all metric alarms defined in alarms.tf.

resource "aws_sns_topic" "security_alarms" {
  name              = "security-alarms"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(local.common_tags, {
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_sns_topic_policy" "security_alarms" {
  arn = aws_sns_topic.security_alarms.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alarms.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.management_account_id
          }
        }
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

# prevent_destroy intentionally omitted — conditionally created via count,
# must be destroyable if alarm_email is later cleared.
resource "aws_sns_topic_subscription" "security_alarms_email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# =====================================================================
# Macie — Management Account Enablement + Org Admin Delegation
#
# Macie must be enabled in the management account before the security
# account can be registered as the delegated administrator.
#
# aws_macie2_account.main  → enables Macie in the management account
#   (this module's provider targets the management account)
# aws_macie2_organization_admin_account.main → delegates admin to security
#
# The aws_macie2_account resource in terraform/security/security_services.tf
# is a separate resource in a separate module that enables Macie in the
# security account itself. There is no conflict — they target different
# AWS accounts via different provider configurations.
# =====================================================================

resource "aws_macie2_account" "main" {}

resource "aws_macie2_organization_admin_account" "main" {
  admin_account_id = var.security_account_id

  depends_on = [aws_macie2_account.main]
}

# =====================================================================
# GuardDuty — Management Account Enablement + Org Admin Delegation
#
# GuardDuty must be enabled in the management account (detector created)
# before the security account can be designated as the GuardDuty org admin.
# aws_guardduty_organization_admin_account calls EnableOrganizationAdminAccount
# via the GuardDuty service API, which is distinct from and required in
# addition to the Organizations API delegation in config.tf.
# Without this, aws_guardduty_organization_configuration in the security
# account fails with: "delegated administrator account has not been enabled".
# Import is handled in management-import-state.sh and the deploy-management-scps
# pre-import step to cover accounts where GuardDuty was previously enabled.
# =====================================================================

resource "aws_guardduty_detector" "management" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

resource "aws_guardduty_organization_admin_account" "main" {
  admin_account_id = local.security_account_id

  depends_on = [aws_guardduty_detector.management]
}

# =====================================================================
# Security Hub — Management Account Enablement + Org Admin Delegation
#
# SecurityHub must be enabled in the management account before the security
# account can be designated as SecurityHub org admin. The service API
# (EnableOrganizationAdminAccount) is required in addition to the
# Organizations API delegation in config.tf.
# =====================================================================

resource "aws_securityhub_account" "management" {
  enable_default_standards  = false
  control_finding_generator = "STANDARD_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_organization_admin_account" "main" {
  admin_account_id = local.security_account_id

  depends_on = [aws_securityhub_account.management]
}

# =====================================================================
# Inspector v2 — Org Admin Delegation
#
# Inspector2 delegated admin is set via AWS CLI in deploy-management-scps
# rather than a Terraform resource. aws_inspector2_delegate_admin_account
# triggers a schema validation bug in Terraform 1.11.0 ("no schema
# available ... to validate for self-references") whenever terraform import
# CLI loads the config graph containing this resource type.  Moving to CLI
# avoids the bug while preserving the idempotent enablement behaviour.
# The Organizations-level delegation for inspector2.amazonaws.com remains
# managed by aws_organizations_delegated_administrator.inspector in config.tf.
# =====================================================================
