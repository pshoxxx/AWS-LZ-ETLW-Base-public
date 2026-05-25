# scps.tf

# -------------------------------------------------------
# Service Control Policies (SCPs)
#
# PROVIDER NOTE: All resources here use the DEFAULT (unaliased)
# provider, which must be authenticated to the management
# (payer) account.  AWS SCPs are management-account-only
# resources and cannot be created from a member account.
#
# ATTACHMENT NOTE: Both SCPs are attached to the organization
# root.  By AWS design, SCPs attached to the root never apply
# to the management account itself, so this is functionally
# equivalent to "all non-management accounts and OUs."
#
# If you need per-OU attachment instead, look up each OU with
# a data "aws_organizations_organizational_unit" block and
# create a separate aws_organizations_policy_attachment per OU.
# -------------------------------------------------------

locals {
  # roots is a list attribute exposed directly by the
  # aws_organizations_organization data source. aws_organizations_roots
  # does not exist as a standalone data source in the AWS provider.
  org_root_id = data.aws_organizations_organization.org.roots[0].id
}

# Import for existing SCPs
import {
  to = aws_organizations_policy.baseline_guardrails
  id = "p-fih6qweb"
}

import {
  to = aws_organizations_policy.region_restriction
  id = "p-51sm37gv"
}

# ===============================================================
# 1.  Baseline Guardrails SCP
#
# Denies the following across all member accounts:
#   - Leaving the AWS Organization
#   - Disabling or tampering with CloudTrail
#   - Deleting/disassociating GuardDuty detectors or memberships
#   - Creating or updating IAM console login profiles
#     (prevents new IAM users from getting console access)
#   - ALL actions performed as the root user of any account
# ===============================================================

resource "aws_organizations_policy" "baseline_guardrails" {
  name        = "baseline-guardrails"
  description = "Baseline security guardrails applied org-wide to all non-management accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # -------------------------------------------------------
      # Prevent an account from removing itself from the org.
      # -------------------------------------------------------
      {
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = ["organizations:LeaveOrganization"]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Protect CloudTrail.
      #
      # DeleteTrail   — removes a trail entirely.
      # StopLogging   — pauses log delivery without deleting.
      # UpdateTrail   — could redirect logs to an attacker-controlled bucket.
      # -------------------------------------------------------
      {
        Sid    = "DenyCloudTrailModification"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
        ]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Protect GuardDuty.
      #
      # Blocking delete/disassociate actions prevents an attacker
      # who has gained member-account access from silencing threat
      # detection before escalating their activity.
      # -------------------------------------------------------
      {
        Sid    = "DenyGuardDutyDisabling"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DeleteMembers",
          "guardduty:DisassociateFromAdministratorAccount",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DisassociateMembers",
          "guardduty:StopMonitoringMembers",
        ]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Prevent IAM users from being given console credentials.
      #
      # CreateLoginProfile — creates the initial console password.
      # UpdateLoginProfile — resets/changes an existing password.
      #
      # Programmatic (access-key) IAM users are still permitted.
      # If you need human console access, use IAM Identity Center
      # (SSO) with federated identities instead.
      # -------------------------------------------------------
      {
        Sid    = "DenyIAMConsoleLoginProfiles"
        Effect = "Deny"
        Action = [
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
        ]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Deny ALL actions by the root user of any member account.
      #
      # The ArnLike condition matches "arn:aws:iam::<any-account-id>:root".
      # Because SCPs never apply to the management account, the
      # management account's root user is not affected.
      # -------------------------------------------------------
      {
        Sid      = "DenyRootUserAllActions"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          ArnLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
  })
}

resource "aws_organizations_policy_attachment" "baseline_guardrails_root" {
  policy_id = aws_organizations_policy.baseline_guardrails.id
  target_id = local.org_root_id
}

# ===============================================================
# 2.  Region Restriction SCP
#
# Denies any API call whose target region is not us-west-1.
#
# Global / IAM-plane services are listed under NotAction and are
# fully exempt.  These services either have no regional endpoint
# or always route through the us-east-1 global endpoint regardless
# of where the caller is located; blocking them would break normal
# IAM, billing, and support workflows.
#
# To also allow us-west-2, add "us-west-2" to the
# aws:RequestedRegion list in the Condition block below.
# ===============================================================

resource "aws_organizations_policy" "region_restriction" {
  name        = "region-restriction-us-west-1"
  description = "Restricts workload API calls to us-west-1; exempts global AWS services"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyOutsideUsWest1"
        Effect = "Deny"

        # Services exempt from region gating.
        # These all operate on global/IAM-plane endpoints and would
        # break if restricted by aws:RequestedRegion.
        NotAction = [
          "a4b:*",
          "account:*",
          "acm:*",
          "aws-marketplace-management:*",
          "aws-marketplace:*",
          "aws-portal:*",
          "budgets:*",
          "ce:*",
          "cloudfront:*",
          "cur:*",
          "directconnect:*",
          "ec2:DescribeRegions",
          "ec2:DescribeTransitGateways",
          "ec2:DescribeVpnGateways",
          "fms:*",
          "globalaccelerator:*",
          "health:*",
          "iam:*",
          "importexport:*",
          "kms:*",
          "mobileanalytics:*",
          "networkmanager:*",
          "organizations:*",
          "pricing:*",
          "route53:*",
          "route53domains:*",
          "route53resolver:*",
          "s3:GetAccountPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:PutAccountPublicAccessBlock",
          "shield:*",
          "sts:*",
          "support:*",
          "trustedadvisor:*",
          "waf:*",
          "wafv2:*",
          "wellarchitected:*",
        ]

        Resource = "*"

        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = [
              "us-west-1",
              # "us-west-2",  # Uncomment to expand to a second US West region
            ]
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
  })
}

resource "aws_organizations_policy_attachment" "region_restriction_root" {
  policy_id = aws_organizations_policy.region_restriction.id
  target_id = local.org_root_id
}

# ===============================================================
# 3.  Enforce EBS Encryption SCP
#
# Denies CreateVolume if the Encrypted parameter is not true.
# This enforces EBS encryption at the API level across all member
# accounts regardless of the account-level default encryption
# setting. Applies to all principals including automation and
# service roles.
#
# Why SCP rather than account-level default:
#   - Account-level default encryption (aws_ebs_encryption_by_default)
#     can be disabled by anyone with ec2:DisableEbsEncryptionByDefault.
#   - This SCP cannot be overridden by any member account principal
#     regardless of their IAM permissions.
#   - Covers any new accounts added to the org automatically.
#
# The management account is exempt by AWS Organizations design --
# SCPs attached to the root never apply to the management account.
# ===============================================================

resource "aws_organizations_policy" "enforce_ebs_encryption" {
  name        = "enforce-ebs-encryption"
  description = "Denies creation of unencrypted EBS volumes across all member accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # -------------------------------------------------------
      # Deny CreateVolume without encryption.
      #
      # ec2:Encrypted is a condition key that maps directly to
      # the Encrypted parameter in the CreateVolume API call.
      # A value of false (or absence of the parameter) means
      # the volume will be unencrypted -- both are denied.
      #
      # Snapshots restored via CreateVolume inherit the source
      # snapshot encryption state. If the snapshot is unencrypted
      # this SCP will block restoration unless the caller explicitly
      # sets Encrypted=true and provides a KMS key.
      #
      # SIEM SIMULATION NOTE:
      # Scenario 3 of user-scripts/threat-sim/siem-threat-simulation.sh creates an unencrypted
      # EBS volume to trigger the UnencryptedResourceCreation detection.
      # This SCP will block that API call. To run the simulation:
      #   1. Comment out the DenyUnencryptedEBSVolumes statement below
      #   2. Comment out the DenyRunInstancesWithUnencryptedVolumes statement below
      #   3. Comment out the aws_ebs_encryption_by_default block in each
      #      member account main.tf (corporate, security, networking)
      #   4. Push to main and redeploy to apply the SCP change
      #   5. Run the simulation script
      #   6. Uncomment all blocks and redeploy to restore posture
      # -------------------------------------------------------
      {
        Sid      = "DenyUnencryptedEBSVolumes"
        Effect   = "Deny"
        Action   = ["ec2:CreateVolume"]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "ec2:Encrypted" = "false"
          }
        }
      },

      # -------------------------------------------------------
      # Deny RunInstances if any block device mapping specifies
      # an unencrypted volume.
      #
      # ec2:Encrypted also applies to the RunInstances API for
      # block device mappings. Without this statement an EC2
      # instance can be launched with unencrypted root or data
      # volumes even if CreateVolume is blocked separately.
      # -------------------------------------------------------
      {
        Sid      = "DenyRunInstancesWithUnencryptedVolumes"
        Effect   = "Deny"
        Action   = ["ec2:RunInstances"]
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          BoolIfExists = {
            "ec2:Encrypted" = "false"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
  })
}

resource "aws_organizations_policy_attachment" "enforce_ebs_encryption_root" {
  policy_id = aws_organizations_policy.enforce_ebs_encryption.id
  target_id = local.org_root_id
}

# ===============================================================
# 5.  Security Service Protection SCP
#
# Denies disabling or destroying the security services that were
# manually enabled in the management/security accounts:
#   - Security Hub
#   - AWS Config (irreversible Delete* actions only)
#   - Macie
#   - Inspector
#   - Access Analyzer
#
# Note: config:StopConfigurationRecorder is NOT blocked by this SCP.
# Terraform calls it internally during Config recorder management.
# It is monitored via SIEM (SecurityServiceTampering detection) instead.
#
# GuardDuty and CloudTrail are already protected by the
# baseline-guardrails SCP above.
#
# Portfolio note: In a production environment the Terraform
# resources for these services would also carry:
#   lifecycle { prevent_destroy = true }
# to prevent accidental removal via IaC in addition to the
# API-level deny provided by this SCP. That block is omitted
# here to allow on-demand environment teardown.
# ===============================================================

resource "aws_organizations_policy" "security_service_protection" {
  name        = "security-service-protection"
  description = "Denies disabling Security Hub, Config, Macie, Inspector, and Access Analyzer across all member accounts"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # -------------------------------------------------------
      # Protect Security Hub.
      #
      # DisableSecurityHub removes the service entirely.
      # DeleteInvitations / DisassociateFromAdministratorAccount
      # would sever the member-to-delegated-admin relationship,
      # silencing central findings aggregation.
      # -------------------------------------------------------
      {
        Sid    = "DenySecurityHubDisabling"
        Effect = "Deny"
        Action = [
          "securityhub:DisableSecurityHub",
          "securityhub:DeleteInvitations",
          "securityhub:DisassociateFromAdministratorAccount",
          "securityhub:DisassociateMembers",
          "securityhub:DeleteMembers",
        ]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Protect AWS Config.
      #
      # DeleteConfigurationRecorder removes the recorder entirely.
      # DeleteDeliveryChannel removes the S3/SNS destination.
      # DeleteRetentionConfiguration removes retention settings.
      #
      # StopConfigurationRecorder is intentionally NOT blocked here.
      # The Terraform AWS provider calls StopConfigurationRecorder
      # internally when destroying aws_config_configuration_recorder_status
      # resources during normal IaC operations (e.g. recorder replacement).
      # Blocking it here causes AccessDeniedException in Terraform apply.
      # StopConfigurationRecorder is a reversible action and is monitored
      # by the SIEM SecurityServiceTampering detection via CloudTrail --
      # the appropriate detection layer for reversible service operations.
      # -------------------------------------------------------
      {
        Sid    = "DenyConfigDisabling"
        Effect = "Deny"
        Action = [
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:DeleteRetentionConfiguration",
        ]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Protect Macie.
      #
      # DisableMacie removes the service and purges findings.
      # DisableOrganizationAdminAccount removes the delegated
      # admin designation, breaking centralized Macie management.
      # -------------------------------------------------------
      {
        Sid    = "DenyMacieDisabling"
        Effect = "Deny"
        Action = [
          "macie2:DisableMacie",
          "macie2:DisableOrganizationAdminAccount",
          "macie2:DisassociateFromAdministratorAccount",
          "macie2:DisassociateFromMasterAccount",
        ]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Protect Inspector.
      #
      # Disable removes coverage for EC2 and ECR scanning.
      # DisassociateMember severs member account from the
      # delegated admin, removing central visibility.
      # -------------------------------------------------------
      {
        Sid    = "DenyInspectorDisabling"
        Effect = "Deny"
        Action = [
          "inspector2:Disable",
          "inspector2:DisableOrganizationAdminAccount",
          "inspector2:DisassociateMember",
        ]
        Resource = "*"
      },

      # -------------------------------------------------------
      # Protect Access Analyzer.
      #
      # DeleteAnalyzer removes an analyzer and all its findings.
      # Without an analyzer, IAM Access Analyzer cannot detect
      # public or cross-account resource access.
      # -------------------------------------------------------
      {
        Sid    = "DenyAccessAnalyzerDisabling"
        Effect = "Deny"
        Action = [
          "access-analyzer:DeleteAnalyzer",
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, {
  })
}

resource "aws_organizations_policy_attachment" "security_service_protection_root" {
  policy_id = aws_organizations_policy.security_service_protection.id
  target_id = local.org_root_id
}

# ===============================================================
# FullAWSAccess Cleanup
#
# FullAWSAccess (p-FullAWSAccess) is automatically attached by
# AWS at every level when SCPs are first enabled. This results
# in redundant attachments at the Root, OUs, and individual
# accounts that accumulate as the org grows.
#
# This section:
#   1. Brings the Root-level FullAWSAccess attachment under
#      Terraform management so it is not accidentally removed.
#   2. Uses a local-exec provisioner to detach FullAWSAccess
#      from all non-root targets (OUs and accounts) dynamically,
#      without hardcoding any OU or account IDs.
#
# The Root attachment must remain -- removing it without explicit
# Allow statements elsewhere would deny all actions org-wide.
#
# The local-exec runs on every apply but is idempotent -- if
# FullAWSAccess is not attached to a target the detach call
# returns a PolicyNotAttachedException which is suppressed.
# ===============================================================

# Import the Root FullAWSAccess attachment so Terraform manages
# it and does not attempt to create or destroy it.
# Format: <root_id>:p-FullAWSAccess
#
# NOTE: Terraform 1.6+ supports expressions in import block id fields.
# This requires >= 1.11 which is enforced in providers.tf.
# If import fails, replace ${local.org_root_id} with your literal
# root ID (e.g. "r-xxxx") for the first apply, then revert.
import {
  to = aws_organizations_policy_attachment.full_aws_access_root
  id = "${local.org_root_id}:p-FullAWSAccess"
}

resource "aws_organizations_policy_attachment" "full_aws_access_root" {
  # Retains the Root-level FullAWSAccess attachment.
  # This is required -- without it no actions are permitted
  # in any account regardless of IAM permissions.
  policy_id = "p-FullAWSAccess"
  target_id = local.org_root_id
}

resource "terraform_data" "detach_full_aws_access_non_root" {
  # Detaches FullAWSAccess from all OUs and accounts except the Root.
  # Uses terraform_data (built into Terraform >= 1.4, no extra provider needed).
  # Runs on every apply. Suppresses PolicyNotAttachedException so it
  # is safe to run when attachments are already clean.
  #
  # Requires the AWS CLI to be available in the Terraform runner.
  # Available on the GitHub Actions ubuntu-latest runner by default.

  triggers_replace = [
    # Re-run if the org root ID changes (org recreation)
    local.org_root_id
  ]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-BASH
      set -euo pipefail

      POLICY_ID="p-FullAWSAccess"
      ROOT_ID="${local.org_root_id}"

      echo "Checking for non-root FullAWSAccess attachments..."

      # List all targets FullAWSAccess is currently attached to
      # excluding the Root which must retain the attachment.
      TARGETS=$(aws organizations list-targets-for-policy         --policy-id "$POLICY_ID"         --query "Targets[?TargetId!='$ROOT_ID'].TargetId"         --output text 2>/dev/null || echo "")

      if [[ -z "$TARGETS" || "$TARGETS" == "None" ]]; then
        echo "No non-root FullAWSAccess attachments found -- nothing to clean up."
        exit 0
      fi

      for TARGET in $TARGETS; do
        echo "Detaching FullAWSAccess from: $TARGET"
        aws organizations detach-policy           --policy-id "$POLICY_ID"           --target-id "$TARGET" 2>/dev/null &&           echo "  Detached: $TARGET" ||           echo "  Skipped (already detached or insufficient permissions): $TARGET"
      done

      echo "FullAWSAccess cleanup complete."
    BASH
  }
}

# ===============================================================
# 4.  Tag Policy
#
# Enforces tag key capitalization and allowed values across all
# member accounts. Uses soft enforcement -- non-compliant resources
# are flagged in AWS Config but API calls are not denied.
#
# Keys enforced:
#   Name        -- free-form string, case enforced
#   Environment -- allowed values: dev, staging, prod
#   ManagedBy   -- allowed values: Terraform, Manual
#
# To enable hard enforcement (deny resource creation without
# required tags) see the commented-out SCP below this resource.
#
# Tag policies require TAG_POLICY type to be enabled in the org.
# This is separate from SERVICE_CONTROL_POLICY and is enabled
# automatically when the first tag policy is attached.
# ===============================================================

resource "aws_organizations_policy" "tag_policy" {
  name        = "org-tag-standards"
  description = "Enforces tag key casing and allowed values for Environment and ManagedBy across all accounts"
  type        = "TAG_POLICY"

  content = jsonencode({
    tags = merge(local.common_tags, {

      # -------------------------------------------------------
      # Name tag
      # Enforces capitalization of the key only.
      # Value is free-form since Name varies per resource.
      # -------------------------------------------------------
      Name = {
        tag_key = {
          "@@assign" = "Name"
        }
      }

      # -------------------------------------------------------
      # Environment tag
      # Restricts values to known deployment environments.
      # Add values here as new environments are onboarded.
      # -------------------------------------------------------
      Environment = {
        tag_key = {
          "@@assign" = "Environment"
        }
        tag_value = {
          "@@assign" = [
            "dev",
            "staging",
            "prod"
          ]
        }
      }

      # -------------------------------------------------------
      # ManagedBy tag
      # Indicates whether the resource is managed by Terraform
      # or was created manually. Used for drift detection and
      # audit reporting.
      # -------------------------------------------------------
      ManagedBy = {
        tag_key = {
          "@@assign" = "ManagedBy"
        }
        tag_value = {
          "@@assign" = [
            "Terraform",
            "Manual"
          ]
        }
      }
    })
  })

  tags = merge(local.common_tags, {
  })
}

resource "aws_organizations_policy_attachment" "tag_policy_root" {
  policy_id = aws_organizations_policy.tag_policy.id
  target_id = local.org_root_id
}

# ===============================================================
# COMMENTED OUT -- Hard Tag Enforcement SCP
#
# This SCP pairs with the tag policy above to deny resource
# creation if the required tags are missing or use incorrect
# values. Moves enforcement from soft (Config flagging) to
# hard (API deny).
#
# WHY THIS IS COMMENTED OUT:
#   Hard tag enforcement is operationally aggressive. Any AWS
#   service that creates resources on your behalf (Lambda,
#   Auto Scaling, ECS, CloudFormation, etc.) must also pass
#   the required tags or its API calls will be denied. This
#   can break service-linked roles, automated remediation, and
#   managed services that don't support tagging at creation time.
#
#   For a portfolio/dev environment this is too disruptive.
#   For production, scope the Deny to specific resource types
#   you control (e.g. ec2:RunInstances, rds:CreateDBInstance)
#   rather than using a broad Resource = "*".
#
# HOW TO ENABLE WHEN READY:
#   1. Audit all resource creation paths (manual, automated,
#      service-linked) to confirm they pass required tags.
#   2. Test in a non-production OU first by scoping the
#      attachment to that OU rather than the Root.
#   3. Uncomment the resource blocks below.
#   4. Push to main and deploy.
#
# ===============================================================

# resource "aws_organizations_policy" "require_tags" {
#   name        = "require-standard-tags"
#   description = "Denies resource creation if Environment or ManagedBy tags are missing"
#   type        = "SERVICE_CONTROL_POLICY"
#
#   content = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#
#       # -------------------------------------------------------
#       # Deny EC2 resource creation without required tags.
#       # Scoped to EC2 instance and volume creation only --
#       # not all EC2 actions -- to reduce blast radius.
#       # -------------------------------------------------------
#       {
#         Sid    = "DenyEC2WithoutRequiredTags"
#         Effect = "Deny"
#         Action = [
#           "ec2:RunInstances",
#           "ec2:CreateVolume",
#           "ec2:CreateSnapshot"
#         ]
#         Resource = "*"
#         Condition = {
#           "Null" = {
#             "aws:RequestTag/Environment" = "true"
#             "aws:RequestTag/ManagedBy"   = "true"
#           }
#         }
#       },
#
#       # -------------------------------------------------------
#       # Deny RDS instance creation without required tags.
#       # -------------------------------------------------------
#       {
#         Sid    = "DenyRDSWithoutRequiredTags"
#         Effect = "Deny"
#         Action = [
#           "rds:CreateDBInstance",
#           "rds:CreateDBCluster"
#         ]
#         Resource = "*"
#         Condition = {
#           "Null" = {
#             "aws:RequestTag/Environment" = "true"
#             "aws:RequestTag/ManagedBy"   = "true"
#           }
#         }
#       },
#
#       # -------------------------------------------------------
#       # Deny S3 bucket creation without required tags.
#       # -------------------------------------------------------
#       {
#         Sid    = "DenyS3WithoutRequiredTags"
#         Effect = "Deny"
#         Action = ["s3:CreateBucket"]
#         Resource = "*"
#         Condition = {
#           "Null" = {
#             "aws:RequestTag/Environment" = "true"
#             "aws:RequestTag/ManagedBy"   = "true"
#           }
#         }
#       }
#     ]
#   })
#
#   tags = {
#     ManagedBy = "Terraform"
#   }
# }
#
# resource "aws_organizations_policy_attachment" "require_tags_root" {
#   policy_id = aws_organizations_policy.require_tags.id
#   target_id = local.org_root_id
# }

# S3 Block Public Access at the organization level is a one-time manual step
# in the AWS Organizations console (under Policies -> S3 Block Public Access).
# It cannot be managed by the management account Terraform workspace because
# the setting is applied by the Organizations service principal, not by an IAM
# role. Enable it after initial deployment: Organizations console ->
# Policies -> S3 Block Public Access -> Configure -> Block all public access.
