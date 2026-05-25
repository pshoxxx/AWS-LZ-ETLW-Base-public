# terraform/security/security_services.tf
# =====================================================================
# Organization Security Services — Security Account (Delegated Admin)
#
# Services configured here:
#   - GuardDuty
#   - Security Hub
#   - IAM Access Analyzer
#   - Macie
#   - Inspector v2
#
# Each service follows the same two-step pattern:
#   1. Enable the service in the security account itself.
#   2. Configure org-level auto-enablement so every current and future
#      member account is covered the moment it joins the org.
#
# Service-level org admin designations (GuardDuty, SecurityHub, Inspector2)
# are applied in deploy-management-scps (before this job runs) via targeted
# apply of aws_guardduty_organization_admin_account, aws_securityhub_organization_admin_account,
# and aws_inspector2_delegate_admin_account in terraform/management/security_delegations.tf.
# The Organizations-level delegated admin records live in terraform/management/config.tf.
# =====================================================================

# =====================================================================
# Import handling for GuardDuty, Security Hub, and Macie is done via
# terraform import CLI in the deploy-member-accounts workflow step.
# This avoids the count/for_each restriction on import blocks targeting
# singleton resources. The GuardDuty detector ID is resolved dynamically
# in the import script via aws guardduty list-detectors.

# =====================================================================
# GuardDuty
# =====================================================================
# auto_enable_organization_members = "ALL" covers both existing members
# and every new account going forward.

resource "aws_guardduty_detector" "main" {
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

resource "aws_guardduty_organization_configuration" "main" {
  # ALL = enable for existing members and every new account going forward.
  # NEW = only new accounts (use this if onboarding existing accounts
  #       manually to avoid disrupting pre-existing detector configs).
  auto_enable_organization_members = "ALL"
  detector_id                      = aws_guardduty_detector.main.id

  datasources {
    s3_logs {
      auto_enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = true
        }
      }
    }
  }
}

# Wait for the KMS key policy and S3 bucket policy to fully propagate
# through AWS before GuardDuty validates them during
# CreatePublishingDestination. Without this, the apply intermittently
# fails with a 400 BadRequestException even when the policies are correct.
#
# Dependency chain (strictly one-directional — no cycles):
#   aws_kms_key.org_logs_cmk      ──┐
#   aws_s3_bucket_policy.org_logs ──┴─► time_sleep ──► aws_guardduty_publishing_destination
resource "time_sleep" "guardduty_policy_propagation" {
  create_duration = "30s"

  depends_on = [
    aws_kms_key.org_logs_cmk,
    aws_s3_bucket_policy.org_logs,
  ]
}

resource "aws_guardduty_publishing_destination" "s3" {
  detector_id = aws_guardduty_detector.main.id

  # Use the plain bucket ARN with no prefix. GuardDuty then writes to its
  # default path of AWSLogs/{account_id}/GuardDuty/{region}/..., which is
  # exactly what the GuardDutyWrite allow statement in the S3 bucket policy
  # covers via AWSLogs/*/GuardDuty/*.
  #
  # Do NOT append a custom prefix (e.g. /guardduty). GuardDuty physically
  # checks that the prefix folder exists in S3 before accepting the request.
  # Since S3 has no real folders, a fresh bucket will always fail that check
  # with: "the resource folder specified in the destinationArn does not exist".
  destination_arn = aws_s3_bucket.org_logs.arn
  kms_key_arn     = aws_kms_key.org_logs_cmk.arn

  depends_on = [
    time_sleep.guardduty_policy_propagation,
  ]
}

# =====================================================================
# Security Hub
# =====================================================================
# auto_enable = true enrolls new member accounts automatically.
# auto_enable_standards = "DEFAULT" activates FSBP in each new account
# immediately on enrollment.
# control_finding_generator = "STANDARD_CONTROL" generates a separate
# finding per standard per resource. Switch to "SECURITY_CONTROL" to
# de-duplicate findings across standards if cross-standard consolidation
# is preferred.

resource "aws_securityhub_account" "main" {
  enable_default_standards  = false
  control_finding_generator = "STANDARD_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_organization_configuration" "main" {
  auto_enable           = true
  auto_enable_standards = "DEFAULT"

  depends_on = [aws_securityhub_account.main]
}

# Explicit standard subscriptions give Terraform ownership over which
# standards are active and prevent manual drift.

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}

# =====================================================================
# IAM Access Analyzer
# =====================================================================
# ORGANIZATION type means the analyzer covers all accounts in the org,
# not just the security account. Findings surface cross-account and
# public resource access automatically for every current and future
# member account with no additional configuration required.

resource "aws_accessanalyzer_analyzer" "org" {
  analyzer_name = "org-analyzer"
  type          = "ORGANIZATION"
}

# =====================================================================
# Inspector v2
# =====================================================================
# Enables EC2, ECR, and Lambda scanning in the security account, then
# configures the org so every new member account automatically receives
# the same coverage on join.

resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

resource "aws_inspector2_organization_configuration" "main" {
  auto_enable {
    ec2    = true
    ecr    = true
    lambda = true
  }

  depends_on = [aws_inspector2_enabler.main]
}

# =====================================================================
# Macie
# =====================================================================
# Enables Macie in the security account. The security account acts as
# the Macie delegated administrator for the organization (delegation is
# configured in terraform/management/security_delegations.tf).
# aws_macie2_organization_admin_account in the management module requires
# Macie to be enabled in the management account first — that separate
# resource lives in security_delegations.tf and targets the management
# account via the management module's provider.

resource "aws_macie2_account" "main" {}
