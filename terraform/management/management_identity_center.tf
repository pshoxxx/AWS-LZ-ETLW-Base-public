# terraform/management/management_identity_center.tf
# =====================================================================
# IAM Identity Center — Permission Sets and Account Assignments
#
# Deploy sequence:
#   1. Manually enable IAM Identity Center in the management account
#      (console: IAM Identity Center → Enable).
#   2. Set var.enable_identity_center = true and redeploy management.
#      This creates all Permission Sets and policy attachments.
#   3. Deploy AD Connector (management_ad_connector.tf) after VPN is up.
#   4. Connect Identity Center to the AD directory in the console
#      (IAM Identity Center → Settings → Identity source → AD directory).
#   5. Confirm the nine Cloud-Access groups appear in Identity Center.
#   6. Set var.enable_sso_assignments = true and redeploy management.
#      This creates all account assignments.
#
# Permission Set → AD Group → Account mapping:
#   PlatformAdmin        aws-iam-engineers       all 5 accounts
#   DevOps               aws-devops              all 5 accounts
#   SecurityAnalyst      aws-security-analysts   all 5 accounts
#   SecurityEngineer     aws-security-engineers  security + shared-services
#   NetworkAdministrator aws-network-admins      networking only
#   SystemAdministrator  aws-system-admins       corporate + management
#   DatabaseAdministrator aws-database-admins    corporate
#   DataScientist        aws-data-scientists     corporate
#   Developer            aws-developers          corporate + shared-services
# =====================================================================

# -- SSO Instance ---------------------------------------------------------
# data source returns empty lists when Identity Center is not yet enabled;
# try() prevents index-out-of-range errors during plan.

data "aws_ssoadmin_instances" "main" {}

locals {
  sso_instance_arn   = try(tolist(data.aws_ssoadmin_instances.main.arns)[0], "")
  sso_identity_store = try(tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0], "")
}

# -- Permission Sets -------------------------------------------------------

resource "aws_ssoadmin_permission_set" "platform_admin" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "PlatformAdmin"
  description      = "Full administrator access - platform engineers and break-glass only"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT1H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "network_admin" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "NetworkAdministrator"
  description      = "AWS NetworkAdministrator job function"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "system_admin" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "SystemAdministrator"
  description      = "AWS SystemAdministrator job function"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "database_admin" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "DatabaseAdministrator"
  description      = "AWS DatabaseAdministrator job function"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "data_scientist" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "DataScientist"
  description      = "AWS DataScientist job function"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT8H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "developer" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "Developer"
  description      = "PowerUserAccess - workload developers in corporate account"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT8H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "security_analyst" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "SecurityAnalyst"
  description      = "SecurityAudit read-only access across all accounts"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT8H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "security_engineer" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "SecurityEngineer"
  description      = "Active management of GuardDuty, SecurityHub, Inspector, Macie, and Access Analyzer"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H"
  tags             = local.common_tags
}

resource "aws_ssoadmin_permission_set" "devops" {
  count            = var.enable_identity_center ? 1 : 0
  name             = "DevOps"
  description      = "Landing zone deployment - EC2, VPC, RDS, Glue, WAF, Route53, DirectoryService, CloudTrail"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H"
  tags             = local.common_tags
}

# -- Managed Policy Attachments --------------------------------------------

resource "aws_ssoadmin_managed_policy_attachment" "platform_admin" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.platform_admin[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_ssoadmin_managed_policy_attachment" "network_admin" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.network_admin[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/NetworkAdministrator"
}

resource "aws_ssoadmin_managed_policy_attachment" "system_admin" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.system_admin[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/SystemAdministrator"
}

resource "aws_ssoadmin_managed_policy_attachment" "database_admin" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.database_admin[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/DatabaseAdministrator"
}

resource "aws_ssoadmin_managed_policy_attachment" "data_scientist" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.data_scientist[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/DataScientist"
}

resource "aws_ssoadmin_managed_policy_attachment" "developer" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.developer[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_ssoadmin_managed_policy_attachment" "security_analyst" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_analyst[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# DevOps — five AWS managed policies covering the main service areas
resource "aws_ssoadmin_managed_policy_attachment" "devops_ec2" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.devops[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_ssoadmin_managed_policy_attachment" "devops_vpc" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.devops[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AmazonVPCFullAccess"
}

resource "aws_ssoadmin_managed_policy_attachment" "devops_rds" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.devops[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

resource "aws_ssoadmin_managed_policy_attachment" "devops_glue" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.devops[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess"
}

resource "aws_ssoadmin_managed_policy_attachment" "devops_guardduty" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.devops[0].arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess_v2"
}

# -- Inline Policies -------------------------------------------------------

resource "aws_ssoadmin_permission_set_inline_policy" "security_engineer" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_engineer[0].arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityServicesManagement"
        Effect = "Allow"
        Action = [
          "guardduty:*",
          "securityhub:*",
          "inspector2:*",
          "macie2:*",
          "access-analyzer:*",
          "cloudshell:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AuditRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:Get*",
          "cloudtrail:List*",
          "cloudtrail:Describe*",
          "cloudtrail:LookupEvents",
          "config:Get*",
          "config:List*",
          "config:Describe*",
          "config:Select*",
          "iam:Get*",
          "iam:List*",
          "iam:GenerateCredentialReport",
          "iam:GenerateServiceLastAccessedDetails",
          "kms:Describe*",
          "kms:List*",
          "kms:Get*",
          "s3:GetBucketLogging",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetEncryptionConfiguration",
          "s3:ListAllMyBuckets",
          "s3:GetObject",
          "sns:List*",
          "sns:Get*",
          "logs:Describe*",
          "logs:Get*",
          "logs:FilterLogEvents",
          "logs:ListLogDeliveries"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "devops" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.devops[0].arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudFrontAndWAF"
        Effect = "Allow"
        Action = [
          "cloudfront:*",
          "wafv2:*",
          "waf-regional:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Route53AndDNS"
        Effect = "Allow"
        Action = [
          "route53:*",
          "route53resolver:*",
          "route53domains:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DirectoryAndSSM"
        Effect = "Allow"
        Action = [
          "ds:*",
          "ssm:*",
          "cloudshell:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailAndLogs"
        Effect = "Allow"
        Action = [
          "cloudtrail:*",
          "logs:*"
        ]
        Resource = "*"
      },
      {
        Sid      = "S3AndStorageManagement"
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Sid    = "KMSManagement"
        Effect = "Allow"
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
          "kms:CreateGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMServiceRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:ListRoles",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:ListInstanceProfiles",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:PassRole",
          "iam:CreateServiceLinkedRole",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:CreatePolicy",
          "iam:DeletePolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "LoadBalancerAndTagging"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:*",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          "rds:AddTagsToResource",
          "rds:RemoveTagsFromResource",
          "rds:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "developer" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.developer[0].arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "CloudShellAccess"
      Effect   = "Allow"
      Action   = ["cloudshell:*"]
      Resource = "*"
    }]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "network_admin" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.network_admin[0].arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "CloudShellAccess"
      Effect   = "Allow"
      Action   = ["cloudshell:*"]
      Resource = "*"
    }]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "system_admin" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.system_admin[0].arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "CloudShellAccess"
      Effect   = "Allow"
      Action   = ["cloudshell:*"]
      Resource = "*"
    }]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "data_scientist" {
  count              = var.enable_identity_center ? 1 : 0
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.data_scientist[0].arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "CloudShellAccess"
      Effect   = "Allow"
      Action   = ["cloudshell:*"]
      Resource = "*"
    }]
  })
}

# -- AD Group Lookups -------------------------------------------------------
# Requires Identity Center to be connected to AD and groups to be synced.
# Gated by var.enable_sso_assignments — set to true only after AD Connector
# is configured and the nine Cloud-Access groups appear in Identity Center.

data "aws_identitystore_group" "groups" {
  for_each = var.enable_identity_center && var.enable_sso_assignments ? toset([
    "aws-iam-engineers",
    "aws-network-admins",
    "aws-system-admins",
    "aws-database-admins",
    "aws-data-scientists",
    "aws-developers",
    "aws-security-analysts",
    "aws-security-engineers",
    "aws-devops"
  ]) : toset([])

  identity_store_id = local.sso_identity_store

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = "${each.key}@${var.ad_domain_name}"
    }
  }
}

# -- Account Assignment Map ------------------------------------------------

# one() returns null on an empty list (count=0) and the ARN on a single-element
# list (count=1). This is type-safe under Terraform's eager branch evaluation,
# unlike [0] which raises Invalid index when count=0 even in the non-selected
# branch of a conditional expression.
locals {
  _ps = {
    platform_admin    = one(aws_ssoadmin_permission_set.platform_admin[*].arn)
    network_admin     = one(aws_ssoadmin_permission_set.network_admin[*].arn)
    system_admin      = one(aws_ssoadmin_permission_set.system_admin[*].arn)
    database_admin    = one(aws_ssoadmin_permission_set.database_admin[*].arn)
    data_scientist    = one(aws_ssoadmin_permission_set.data_scientist[*].arn)
    developer         = one(aws_ssoadmin_permission_set.developer[*].arn)
    security_analyst  = one(aws_ssoadmin_permission_set.security_analyst[*].arn)
    security_engineer = one(aws_ssoadmin_permission_set.security_engineer[*].arn)
    devops            = one(aws_ssoadmin_permission_set.devops[*].arn)
  }

  sso_assignments = var.enable_identity_center && var.enable_sso_assignments ? {

    # PlatformAdmin — all 5 accounts
    "iam-engineers/platform-admin/management" = {
      group          = "aws-iam-engineers"
      permission_set = local._ps.platform_admin
      account_id     = local.management_account.id
    }
    "iam-engineers/platform-admin/security" = {
      group          = "aws-iam-engineers"
      permission_set = local._ps.platform_admin
      account_id     = local.security_account.id
    }
    "iam-engineers/platform-admin/networking" = {
      group          = "aws-iam-engineers"
      permission_set = local._ps.platform_admin
      account_id     = local.networking_account.id
    }
    "iam-engineers/platform-admin/corporate" = {
      group          = "aws-iam-engineers"
      permission_set = local._ps.platform_admin
      account_id     = local.corporate_account.id
    }
    "iam-engineers/platform-admin/shared-services" = {
      group          = "aws-iam-engineers"
      permission_set = local._ps.platform_admin
      account_id     = local.shared_services_account.id
    }

    # DevOps — all 5 accounts
    "devops/devops/management" = {
      group          = "aws-devops"
      permission_set = local._ps.devops
      account_id     = local.management_account.id
    }
    "devops/devops/security" = {
      group          = "aws-devops"
      permission_set = local._ps.devops
      account_id     = local.security_account.id
    }
    "devops/devops/networking" = {
      group          = "aws-devops"
      permission_set = local._ps.devops
      account_id     = local.networking_account.id
    }
    "devops/devops/corporate" = {
      group          = "aws-devops"
      permission_set = local._ps.devops
      account_id     = local.corporate_account.id
    }
    "devops/devops/shared-services" = {
      group          = "aws-devops"
      permission_set = local._ps.devops
      account_id     = local.shared_services_account.id
    }

    # SecurityAnalyst — all 5 accounts (read-only audit)
    "security-analysts/security-analyst/management" = {
      group          = "aws-security-analysts"
      permission_set = local._ps.security_analyst
      account_id     = local.management_account.id
    }
    "security-analysts/security-analyst/security" = {
      group          = "aws-security-analysts"
      permission_set = local._ps.security_analyst
      account_id     = local.security_account.id
    }
    "security-analysts/security-analyst/networking" = {
      group          = "aws-security-analysts"
      permission_set = local._ps.security_analyst
      account_id     = local.networking_account.id
    }
    "security-analysts/security-analyst/corporate" = {
      group          = "aws-security-analysts"
      permission_set = local._ps.security_analyst
      account_id     = local.corporate_account.id
    }
    "security-analysts/security-analyst/shared-services" = {
      group          = "aws-security-analysts"
      permission_set = local._ps.security_analyst
      account_id     = local.shared_services_account.id
    }

    # SecurityEngineer — security + shared-services
    # Management account access is intentionally excluded: security services
    # (GuardDuty, SecurityHub, Inspector, Macie) run from the security account
    # as delegated admin. Management account activity is auditable via the org
    # CloudTrail trail which flows to the security account S3. Any change to
    # management account resources goes through PlatformAdmin (break-glass).
    # Shared-services access allows security engineers to audit the state bucket
    # and bootstrap infrastructure without requiring PlatformAdmin elevation.
    "security-engineers/security-engineer/security" = {
      group          = "aws-security-engineers"
      permission_set = local._ps.security_engineer
      account_id     = local.security_account.id
    }
    "security-engineers/security-engineer/shared-services" = {
      group          = "aws-security-engineers"
      permission_set = local._ps.security_engineer
      account_id     = local.shared_services_account.id
    }

    # NetworkAdministrator — networking only
    "network-admins/network-admin/networking" = {
      group          = "aws-network-admins"
      permission_set = local._ps.network_admin
      account_id     = local.networking_account.id
    }

    # SystemAdministrator — corporate + management
    "system-admins/system-admin/corporate" = {
      group          = "aws-system-admins"
      permission_set = local._ps.system_admin
      account_id     = local.corporate_account.id
    }
    "system-admins/system-admin/management" = {
      group          = "aws-system-admins"
      permission_set = local._ps.system_admin
      account_id     = local.management_account.id
    }

    # DatabaseAdministrator — corporate only
    "database-admins/database-admin/corporate" = {
      group          = "aws-database-admins"
      permission_set = local._ps.database_admin
      account_id     = local.corporate_account.id
    }

    # DataScientist — corporate only
    "data-scientists/data-scientist/corporate" = {
      group          = "aws-data-scientists"
      permission_set = local._ps.data_scientist
      account_id     = local.corporate_account.id
    }

    # Developer — corporate + shared-services
    "developers/developer/corporate" = {
      group          = "aws-developers"
      permission_set = local._ps.developer
      account_id     = local.corporate_account.id
    }
    "developers/developer/shared-services" = {
      group          = "aws-developers"
      permission_set = local._ps.developer
      account_id     = local.shared_services_account.id
    }

  } : {}
}

# -- Account Assignments ---------------------------------------------------

resource "aws_ssoadmin_account_assignment" "assignments" {
  for_each = local.sso_assignments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = each.value.permission_set
  principal_id       = data.aws_identitystore_group.groups[each.value.group].group_id
  principal_type     = "GROUP"
  target_id          = each.value.account_id
  target_type        = "AWS_ACCOUNT"
}
