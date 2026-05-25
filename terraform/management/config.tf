# terraform/management/config.tf

# =====================================================================
# AWS Config — Management Account Recorder
# =====================================================================
# The org conformance pack deploys to every account in the organization,
# including the management account itself. Without a running recorder
# here the conformance pack fails with NoAvailableConfigurationRecorder
# for this account, blocking the entire pack deployment.

import {
  to = aws_iam_service_linked_role.config
  id = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
}

resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"

  lifecycle {
    ignore_changes = all
  }
}

resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = "org-logs-${local.security_account.id}-v2"
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# =====================================================================
# Delegated Administrators
# =====================================================================
# Import blocks cover registrations that already existed in AWS before
# this configuration was applied. Without them Terraform tries to call
# RegisterDelegatedAdministrator again and receives AccountAlreadyRegisteredException.
#
# Format: <account_id>/<service_principal>

import {
  to = aws_organizations_delegated_administrator.guardduty
  id = "${local.security_account_id}/guardduty.amazonaws.com"
}

import {
  to = aws_organizations_delegated_administrator.securityhub
  id = "${local.security_account_id}/securityhub.amazonaws.com"
}

import {
  to = aws_organizations_delegated_administrator.macie
  id = "${local.security_account_id}/macie.amazonaws.com"
}

import {
  to = aws_organizations_delegated_administrator.inspector
  id = "${local.security_account_id}/inspector2.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "config_setup" {
  account_id        = local.security_account_id
  service_principal = "config-multiaccountsetup.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "config" {
  account_id        = local.security_account_id
  service_principal = "config.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "guardduty" {
  account_id        = local.security_account_id
  service_principal = "guardduty.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "securityhub" {
  account_id        = local.security_account_id
  service_principal = "securityhub.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "access_analyzer" {
  account_id        = local.security_account_id
  service_principal = "access-analyzer.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "macie" {
  account_id        = local.security_account_id
  service_principal = "macie.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "inspector" {
  account_id        = local.security_account_id
  service_principal = "inspector2.amazonaws.com"
}

# =====================================================================
# Organization Conformance Pack — AWS Foundational Security Best Practices
# =====================================================================

resource "aws_config_organization_conformance_pack" "fsbp" {
  name = "AWS-Foundational-Security-Best-Practices"

  depends_on = [
    aws_organizations_delegated_administrator.config_setup,
    aws_config_configuration_recorder_status.main,
  ]

  # AWS does not return template_body (or delivery_s3_bucket/excluded_accounts)
  # in describe calls after creation. Any attribute diff triggers PutOrganizationConformancePack,
  # which AWS executes as an internal delete+recreate cycle. Ignore all changes so
  # the pack is deployed once and left stable across pipeline runs.
  lifecycle {
    ignore_changes = all
  }

  template_body = <<-YAML
    Parameters: {}
    Resources:

      # --- CloudTrail ---

      CloudTrailEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cloud-trail-enabled
          Source:
            Owner: AWS
            SourceIdentifier: CLOUD_TRAIL_ENABLED

      CloudTrailEncryptionEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cloud-trail-encryption-enabled
          Source:
            Owner: AWS
            SourceIdentifier: CLOUD_TRAIL_ENCRYPTION_ENABLED

      CloudTrailLogFileValidationEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cloud-trail-log-file-validation-enabled
          Source:
            Owner: AWS
            SourceIdentifier: CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED

      # --- IAM ---

      IAMRootAccessKeyCheck:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: iam-root-access-key-check
          Source:
            Owner: AWS
            SourceIdentifier: IAM_ROOT_ACCESS_KEY_CHECK

      RootAccountMFAEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: root-account-mfa-enabled
          Source:
            Owner: AWS
            SourceIdentifier: ROOT_ACCOUNT_MFA_ENABLED

      IAMNoInlinePolicyCheck:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: iam-no-inline-policy-check
          Source:
            Owner: AWS
            SourceIdentifier: IAM_NO_INLINE_POLICY_CHECK

      IAMPolicyNoStatementsWithAdminAccess:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: iam-policy-no-statements-with-admin-access
          Source:
            Owner: AWS
            SourceIdentifier: IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS

      MFAEnabledForIAMConsoleAccess:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: mfa-enabled-for-iam-console-access
          Source:
            Owner: AWS
            SourceIdentifier: MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS

      IAMUserUnusedCredentialsCheck:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: iam-user-unused-credentials-check
          InputParameters:
            maxCredentialUsageAge: "90"
          Source:
            Owner: AWS
            SourceIdentifier: IAM_USER_UNUSED_CREDENTIALS_CHECK

      # --- S3 ---

      S3AccountLevelPublicAccessBlocks:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: s3-account-level-public-access-blocks
          Source:
            Owner: AWS
            SourceIdentifier: S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS

      S3BucketPublicReadProhibited:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: s3-bucket-public-read-prohibited
          Source:
            Owner: AWS
            SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED

      S3BucketPublicWriteProhibited:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: s3-bucket-public-write-prohibited
          Source:
            Owner: AWS
            SourceIdentifier: S3_BUCKET_PUBLIC_WRITE_PROHIBITED

      S3BucketServerSideEncryptionEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: s3-bucket-server-side-encryption-enabled
          Source:
            Owner: AWS
            SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED

      # --- KMS ---

      CMKBackingKeyRotationEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cmk-backing-key-rotation-enabled
          Source:
            Owner: AWS
            SourceIdentifier: CMK_BACKING_KEY_ROTATION_ENABLED

      # --- Compute / Networking ---

      VPCDefaultSecurityGroupClosed:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: vpc-default-security-group-closed
          Source:
            Owner: AWS
            SourceIdentifier: VPC_DEFAULT_SECURITY_GROUP_CLOSED

      EBSEncryptionByDefault:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: ec2-ebs-encryption-by-default
          Source:
            Owner: AWS
            SourceIdentifier: EC2_EBS_ENCRYPTION_BY_DEFAULT

      # --- Database ---

      RDSStorageEncrypted:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: rds-storage-encrypted
          Source:
            Owner: AWS
            SourceIdentifier: RDS_STORAGE_ENCRYPTED

      # --- Detective Controls ---

      GuardDutyEnabledCentralized:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: guardduty-enabled-centralized
          Source:
            Owner: AWS
            SourceIdentifier: GUARDDUTY_ENABLED_CENTRALIZED

      SecurityHubEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: securityhub-enabled
          Source:
            Owner: AWS
            SourceIdentifier: SECURITYHUB_ENABLED
  YAML
}