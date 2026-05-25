#!/usr/bin/env bash
set -euo pipefail


ACCOUNT_ID="${IMPORT_ACCOUNT_ID}"
REGION="${AWS_DEFAULT_REGION}"

# Save original OIDC credentials before assuming the security account
# role for the AWS CLI describe calls.
ORIG_KEY_ID="$AWS_ACCESS_KEY_ID"
ORIG_SECRET="$AWS_SECRET_ACCESS_KEY"
ORIG_TOKEN="$AWS_SESSION_TOKEN"

SECURITY_CREDS=$(aws sts assume-role             --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole"             --role-session-name "GitHubActions-SecurityDescribe"             --output json)
echo "::add-mask::$(echo "$SECURITY_CREDS" | jq -r '.Credentials.AccessKeyId')"
echo "::add-mask::$(echo "$SECURITY_CREDS" | jq -r '.Credentials.SecretAccessKey')"
echo "::add-mask::$(echo "$SECURITY_CREDS" | jq -r '.Credentials.SessionToken')"
export AWS_ACCESS_KEY_ID=$(echo "$SECURITY_CREDS"     | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$SECURITY_CREDS" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$SECURITY_CREDS"     | jq -r '.Credentials.SessionToken')

# Check which resources already exist in the security account.
CONFIG_SLR_ARN="arn:aws:iam::${ACCOUNT_ID}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
CONFIG_SLR_EXISTS=false
if aws iam get-role --role-name AWSServiceRoleForConfig               --output text > /dev/null 2>&1; then
  CONFIG_SLR_EXISTS=true
fi

GD_DETECTOR_ID=$(aws guardduty list-detectors \
  --region "$REGION" \
  --query "DetectorIds[0]" \
  --output text 2>/dev/null || echo "")
[[ "$GD_DETECTOR_ID" == "None" ]] && GD_DETECTOR_ID=""
GD_EXISTS=false
if [[ -n "$GD_DETECTOR_ID" ]]; then
  GD_EXISTS=true
  echo "INFO: Existing GuardDuty detector found: ${GD_DETECTOR_ID}"
else
  echo "INFO: No GuardDuty detector found -- Terraform will create it."
fi

SH_EXISTS=false
if aws securityhub describe-hub               --region "$REGION"               --output text > /dev/null 2>&1; then
  SH_EXISTS=true
fi

MACIE_EXISTS=false
if aws macie2 get-macie-session               --region "$REGION"               --output text > /dev/null 2>&1; then
  MACIE_EXISTS=true
fi

ACCESS_ANALYZER_EXISTS=false
if aws accessanalyzer get-analyzer \
  --analyzer-name "org-analyzer" \
  --region "$REGION" \
  --output text > /dev/null 2>&1; then
  ACCESS_ANALYZER_EXISTS=true
fi

INSPECTOR_EXISTS=false
if aws inspector2 batch-get-account-status \
  --account-ids "$ACCOUNT_ID" \
  --region "$REGION" \
  --query "accounts[0].state.status" \
  --output text 2>/dev/null | grep -q "ENABLED"; then
  INSPECTOR_EXISTS=true
fi

# Enable Object Lock on the org-logs bucket while security account
# credentials are still active (before OIDC restore below).
#
# Object Lock is enabled WITHOUT a default retention rule.
# This protects the bucket against accidental deletion and object
# tampering (WORM protection) while remaining compatible with AWS
# service principals such as Route53 Resolver, GuardDuty, and
# CloudTrail that write objects without including Object Lock
# retention metadata in their PutObject requests.
#
# A COMPLIANCE or GOVERNANCE default retention rule would block
# all service principal writes since those services do not pass
# x-amz-object-lock-retain-until-date or x-amz-object-lock-mode
# headers -- causing ACCESS_DENIED on every write attempt.
#
# For production environments with compliance requirements
# (SOC 2, PCI DSS, HIPAA) apply retention rules per-prefix via
# S3 Lifecycle policies rather than a blanket default retention
# rule, scoped only to prefixes written by human operators rather
# than AWS services.
BUCKET_NAME="org-logs-${ACCOUNT_ID}-v2"
LOCK_STATUS=$(aws s3api get-object-lock-configuration             --bucket "$BUCKET_NAME"             --query "ObjectLockConfiguration.ObjectLockEnabled"             --output text 2>/dev/null || echo "Disabled")

if [[ "$LOCK_STATUS" == "Enabled" ]]; then
  echo "INFO: Object Lock already enabled on ${BUCKET_NAME}."
else
  echo "INFO: Enabling Object Lock on ${BUCKET_NAME}..."
  aws s3api put-object-lock-configuration               --bucket "$BUCKET_NAME"               --object-lock-configuration '{"ObjectLockEnabled": "Enabled"}' &&               echo "INFO: Object Lock enabled successfully."               || echo "::warning::Object Lock enablement failed -- enable manually via S3 console."
fi

# Check bucket existence while security credentials are still active.
# The later import section runs with OIDC (management) credentials which
# cannot access the security account bucket, so capture the result here.
BUCKET_EXISTS_IN_ACCOUNT=false
if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
  BUCKET_EXISTS_IN_ACCOUNT=true
  echo "INFO: Bucket ${BUCKET_NAME} found in security account."
else
  echo "INFO: Bucket ${BUCKET_NAME} not found in security account -- will be created."
fi

# Look up existing Route53 query log association while security
# credentials are still active.
SECURITY_VPC_ID=$(aws ec2 describe-vpcs             --region "$REGION"             --filters "Name=tag:Name,Values=security-vpc"             --query "Vpcs[0].VpcId"             --output text 2>/dev/null || echo "")

# Look up Route53 query log config association by config ID.
# Using config ID is more reliable than VPC ID since the VPC may
# have been recreated with a new ID between runs.
# Also handles FAILED state associations -- Route53 Resolver blocks
# new associations if one already exists in FAILED state.
# Delete FAILED associations so Terraform can create a fresh one.
RQLCA_ID=""
RQLC_LOOKUP_ID=$(aws route53resolver list-resolver-query-log-configs             --region "$REGION"             --query "ResolverQueryLogConfigs[?Name=='security-vpc-dns-query-logs'].Id|[0]"             --output text 2>/dev/null || echo "")
[[ "$RQLC_LOOKUP_ID" == "None" ]] && RQLC_LOOKUP_ID=""

if [[ -n "$RQLC_LOOKUP_ID" ]]; then
  ASSOC_JSON=$(aws route53resolver list-resolver-query-log-config-associations               --region "$REGION"               --query "ResolverQueryLogConfigAssociations[?ResolverQueryLogConfigId=='${RQLC_LOOKUP_ID}'].{Id:Id,Status:Status}"               --output json 2>/dev/null || echo "[]")

  RQLCA_STATUS=$(echo "$ASSOC_JSON" | jq -r '.[0].Status // ""')
  RQLCA_ID=$(echo "$ASSOC_JSON" | jq -r '.[0].Id // ""')

  if [[ "$RQLCA_STATUS" == "FAILED" ]]; then
    echo "INFO: Found FAILED Route53 association ${RQLCA_ID} -- deleting before Terraform apply."
    aws route53resolver disassociate-resolver-query-log-config                 --region "$REGION"                 --resolver-query-log-config-id "$RQLC_LOOKUP_ID"                 --resource-id "$SECURITY_VPC_ID" 2>/dev/null &&                 echo "INFO: Deleted FAILED association." ||                 echo "::warning::Could not delete FAILED association -- Terraform may fail."
    echo "INFO: Waiting 30s for disassociation to complete..."
    sleep 30
    RQLCA_ID=""
  elif [[ "$RQLCA_STATUS" == "ACTIVE" ]]; then
    echo "INFO: Found ACTIVE Route53 association: ${RQLCA_ID}"
  else
    echo "INFO: No existing Route53 association found."
    RQLCA_ID=""
  fi
fi


# Look up VPC, subnet and SG IDs while assumed role credentials are active.
# These variables are used by safe_import calls AFTER OIDC restore.
# Must happen before restore -- the assumed role credentials are gone after.
SEC_VPC_ID=$(aws ec2 describe-vpcs \
  --region "$REGION" \
  --filters "Name=tag:Name,Values=security-vpc" \
  --query "Vpcs[0].VpcId" \
  --output text 2>/dev/null || echo "")
[[ "$SEC_VPC_ID" == "None" ]] && SEC_VPC_ID=""
echo "INFO: Security VPC: ${SEC_VPC_ID:-not found}"

SEC_SUBNET_ID=$(aws ec2 describe-subnets \
  --region "$REGION" \
  --filters "Name=tag:Name,Values=security-private-1" \
  --query "Subnets[0].SubnetId" \
  --output text 2>/dev/null || echo "")
[[ "$SEC_SUBNET_ID" == "None" ]] && SEC_SUBNET_ID=""
echo "INFO: Security private subnet: ${SEC_SUBNET_ID:-not found}"

SEC_DC_SG_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters "Name=group-name,Values=security-dc-sg" \
  --query "SecurityGroups[0].GroupId" \
  --output text 2>/dev/null || echo "")
[[ "$SEC_DC_SG_ID" == "None" ]] && SEC_DC_SG_ID=""

SEC_SSM_SG_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters "Name=group-name,Values=security-ssm-endpoints-sg" \
  --query "SecurityGroups[0].GroupId" \
  --output text 2>/dev/null || echo "")
[[ "$SEC_SSM_SG_ID" == "None" ]] && SEC_SSM_SG_ID=""

# Look up KMS key ID via alias while security credentials are active.
KMS_KEY_ID=$(aws kms describe-key \
  --key-id "alias/org-logs-cmk" \
  --region "$REGION" \
  --query "KeyMetadata.KeyId" \
  --output text 2>/dev/null || echo "")
[[ "$KMS_KEY_ID" == "None" ]] && KMS_KEY_ID=""
if [[ -n "$KMS_KEY_ID" ]]; then
  echo "INFO: Found existing KMS key via alias: ${KMS_KEY_ID}"
else
  echo "INFO: No existing KMS key found -- Terraform will create it."
fi

# Restore original OIDC credentials before any terraform call.
export AWS_ACCESS_KEY_ID="$ORIG_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$ORIG_SECRET"
export AWS_SESSION_TOKEN="$ORIG_TOKEN"


# safe_import: import a resource, treating "already managed" as success.
# This handles cases where terraform state list returns empty (e.g. due
# to a transient credentials issue), causing the grep to miss a resource
# that is already in state, and then import firing unnecessarily.
safe_import() {
  local address="$1"
  local id="$2"
  local log
  log=$(mktemp)
  set +e
  terraform import -input=false "$address" "$id" 2>&1 | tee "$log"
  local exit_code=${PIPESTATUS[0]}
  set -e
  if [[ $exit_code -eq 0 ]]; then
    echo "INFO: Import of ${address} succeeded."
  elif grep -q "Resource already managed" "$log"; then
    echo "INFO: ${address} is already managed by Terraform -- skipping."
  else
    echo "::error::Import of ${address} failed:"
    cat "$log"
    exit 1
  fi
}

# Remove the S3 bucket policy from state to force Terraform to
# reapply it on every deploy. The bucket policy document is computed
# from multiple data sources and can drift from live AWS state if
# the state hash matches the config but the live policy differs.
# Removing from state guarantees the full policy is always reapplied.
terraform state rm aws_s3_bucket_policy.org_logs 2>/dev/null || true

# Remove the Route53 query log config from state on every deploy.
# If the config was created against an incorrect bucket policy or
# KMS key policy it may be internally cached in a bad state by AWS.
# Removing from state forces Terraform to delete and recreate it
# fresh against the current (correct) policies on every deploy,
# ensuring the association always succeeds.
terraform state rm aws_route53_resolver_query_log_config.security 2>/dev/null || true
terraform state rm aws_route53_resolver_query_log_config_association.security 2>/dev/null || true

# Import VPC and subnet together using -no-refresh to prevent the
# intermediate refresh that triggers "Invalid count argument".
# When terraform import runs normally it refreshes all state after
# importing -- if the subnet is not yet in state during that refresh
# Terraform cannot resolve length(aws_subnet.private) and fails.
# -no-refresh suppresses the post-import refresh so both can be
# added to state before any refresh occurs. The normal plan/apply
# refresh that follows will see both resources and resolve correctly.
if [[ -n "$SEC_VPC_ID" ]]; then
  if terraform state list 2>/dev/null | grep -q "^aws_vpc.main$"; then
    echo "INFO: aws_vpc.main already in state -- skipping."
  else
    echo "INFO: Importing aws_vpc.main (no-refresh)"
    terraform import -no-refresh -input=false                 aws_vpc.main "$SEC_VPC_ID" 2>&1 | tail -3 || true
  fi
else
  echo "INFO: Security VPC not found in AWS -- Terraform will create it."
fi

if [[ -n "$SEC_SUBNET_ID" ]]; then
  if terraform state list 2>/dev/null | grep -q "^aws_subnet.private\[0\]$"; then
    echo "INFO: aws_subnet.private[0] already in state -- skipping."
  else
    echo "INFO: Importing aws_subnet.private[0] (no-refresh)"
    terraform import -no-refresh -input=false                 'aws_subnet.private[0]' "$SEC_SUBNET_ID" 2>&1 | tail -3 || true
  fi
else
  echo "INFO: Security private subnet not found in AWS -- Terraform will create it."
fi

if [[ -n "$SEC_DC_SG_ID" ]]; then
  if terraform state list 2>/dev/null | grep -q "^aws_security_group.dc$"; then
    echo "INFO: aws_security_group.dc already in state -- skipping."
  else
    echo "INFO: Importing aws_security_group.dc (no-refresh)"
    terraform import -no-refresh -input=false                 aws_security_group.dc "$SEC_DC_SG_ID" 2>&1 | tail -3 || true
  fi
else
  echo "INFO: Security DC SG not found -- Terraform will create it."
fi

if [[ -n "$SEC_SSM_SG_ID" ]]; then
  if terraform state list 2>/dev/null | grep -q "^aws_security_group.ssm_endpoints$"; then
    echo "INFO: aws_security_group.ssm_endpoints already in state -- skipping."
  else
    echo "INFO: Importing aws_security_group.ssm_endpoints (no-refresh)"
    terraform import -no-refresh -input=false                 aws_security_group.ssm_endpoints "$SEC_SSM_SG_ID" 2>&1 | tail -3 || true
  fi
else
  echo "INFO: Security SSM endpoints SG not found -- Terraform will create it."
fi

# Refresh state once after all no-refresh imports so Terraform
# sees all four resources before any subsequent import triggers
# a refresh and hits the count error.
# Only refresh if the subnet was actually imported -- on a fresh
# deploy the subnet doesn't exist yet and refresh would trigger
# the "Invalid count argument" error.
if terraform state list 2>/dev/null | grep -q "aws_subnet.private"; then
  echo "INFO: Refreshing state after VPC/subnet/SG imports..."
  terraform refresh -input=false 2>&1 | tail -5 || true
else
  echo "INFO: Subnet not in state -- skipping refresh (fresh deploy)."
fi

# Determine if this is a fresh deploy (no subnet in state).
# On fresh deploy we skip VPC/subnet/SG imports since safe_import
# triggers a refresh which causes "Invalid count argument" when
# aws_subnet.private is not yet in state.
# However persistent security services (GuardDuty, SecurityHub,
# Macie, Access Analyzer, Config SLR) must ALWAYS be imported
# since they survive account-level and cannot be recreated.
FRESH_DEPLOY="false"
if ! terraform state list 2>/dev/null | grep -q "aws_subnet.private"; then
  echo "INFO: Fresh deploy detected -- skipping VPC/subnet/SG imports."
  FRESH_DEPLOY="true"
fi

# Always import persistent security services regardless of fresh deploy
if [[ "$CONFIG_SLR_EXISTS" == "true" ]]; then
  safe_import aws_iam_service_linked_role.config "$CONFIG_SLR_ARN"
else
  echo "INFO: Config SLR not found -- Terraform will create it."
fi


# Import GuardDuty detector if it exists.
if [[ "$GD_EXISTS" == "true" ]]; then
  safe_import aws_guardduty_detector.main "$GD_DETECTOR_ID"
else
  echo "INFO: GuardDuty detector not found -- Terraform will create it."
fi

# Import Security Hub account if it exists.
if [[ "$SH_EXISTS" == "true" ]]; then
  safe_import aws_securityhub_account.main "$ACCOUNT_ID"
else
  echo "INFO: Security Hub not enabled -- Terraform will enable it."
fi

# Import Macie account if it exists.
if [[ "$MACIE_EXISTS" == "true" ]]; then
  safe_import aws_macie2_account.main "$ACCOUNT_ID"
else
  echo "INFO: Macie not enabled -- Terraform will enable it."
fi

# Import Access Analyzer if it exists.
if [[ "$ACCESS_ANALYZER_EXISTS" == "true" ]]; then
  safe_import aws_accessanalyzer_analyzer.org "org-analyzer"
else
  echo "INFO: Access Analyzer not found -- Terraform will create it."
fi

# Import GuardDuty publishing destination if it exists
# Re-assume security role since OIDC creds were restored above
if [[ -n "$GD_DETECTOR_ID" && "$GD_EXISTS" == "true" ]]; then
  SEC_CREDS_GD=$(aws sts assume-role \
    --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole" \
    --role-session-name "GitHubActions-GDDestLookup" \
    --output json 2>/dev/null || echo "{}")
  GD_DEST_ID=$(AWS_ACCESS_KEY_ID=$(echo "$SEC_CREDS_GD" | jq -r '.Credentials.AccessKeyId // empty') \
    AWS_SECRET_ACCESS_KEY=$(echo "$SEC_CREDS_GD" | jq -r '.Credentials.SecretAccessKey // empty') \
    AWS_SESSION_TOKEN=$(echo "$SEC_CREDS_GD" | jq -r '.Credentials.SessionToken // empty') \
    aws guardduty list-publishing-destinations \
      --detector-id "$GD_DETECTOR_ID" \
      --region "$REGION" \
      --query "Destinations[0].DestinationId" \
      --output text 2>/dev/null || echo "")
  [[ "$GD_DEST_ID" == "None" ]] && GD_DEST_ID=""
  if [[ -n "$GD_DEST_ID" ]]; then
    safe_import aws_guardduty_publishing_destination.s3 "${GD_DETECTOR_ID}:${GD_DEST_ID}"
  else
    echo "INFO: GuardDuty publishing destination not found -- Terraform will create it."
  fi
else
  echo "INFO: GuardDuty detector not found -- skipping publishing destination import."
fi

# Import Athena workgroup if it exists
SEC_CREDS_ATH=$(aws sts assume-role \
  --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole" \
  --role-session-name "GitHubActions-AthenaLookup" \
  --output json 2>/dev/null || echo "{}")
ATHENA_WG=$(AWS_ACCESS_KEY_ID=$(echo "$SEC_CREDS_ATH" | jq -r '.Credentials.AccessKeyId // empty') \
  AWS_SECRET_ACCESS_KEY=$(echo "$SEC_CREDS_ATH" | jq -r '.Credentials.SecretAccessKey // empty') \
  AWS_SESSION_TOKEN=$(echo "$SEC_CREDS_ATH" | jq -r '.Credentials.SessionToken // empty') \
  aws athena get-work-group \
    --work-group org-siem \
    --region "$REGION" \
    --query "WorkGroup.Name" \
    --output text 2>/dev/null || echo "")
[[ "$ATHENA_WG" == "None" ]] && ATHENA_WG=""
if [[ -n "$ATHENA_WG" ]]; then
  safe_import aws_athena_workgroup.siem "org-siem"
else
  echo "INFO: Athena workgroup not found -- Terraform will create it."
fi

# Import KMS key and alias unconditionally -- the alias can pre-exist even on
# a fresh deploy (e.g. leftover from a previous run), so this must run before
# the fresh-deploy gate to avoid AlreadyExistsException during apply.
if [[ -n "$KMS_KEY_ID" ]]; then
  safe_import aws_kms_key.org_logs_cmk "$KMS_KEY_ID"
  safe_import aws_kms_alias.org_logs_cmk "alias/org-logs-cmk"
else
  echo "INFO: No existing KMS key found -- Terraform will create the key."
fi

# Skip VPC/subnet/SG/Route53 imports on fresh deploy
if [[ "$FRESH_DEPLOY" == "true" ]]; then
  echo "INFO: Skipping VPC/subnet/SG/Route53 imports on fresh deploy."
else

  # aws_inspector2_enabler does not support import in the Terraform
# AWS provider. Skip -- Terraform will reconcile on apply.
echo "INFO: Skipping aws_inspector2_enabler import (not supported by provider)."

# Re-import subnet and security group if they were removed from state
# by a previous preserve-DC cleanup run.
SEC_SUBNET_ID=$(aws ec2 describe-subnets             --region "$REGION"             --filters "Name=tag:Name,Values=security-private-1"             --query "Subnets[0].SubnetId"             --output text 2>/dev/null || echo "")
[[ "$SEC_SUBNET_ID" == "None" ]] && SEC_SUBNET_ID=""

if [[ -n "$SEC_SUBNET_ID" ]]; then
  safe_import 'aws_subnet.private[0]' "$SEC_SUBNET_ID"
else
  echo "INFO: Security private subnet not found -- Terraform will create it."
fi

SEC_DC_SG_ID=$(aws ec2 describe-security-groups             --region "$REGION"             --filters "Name=group-name,Values=security-dc-sg"             --query "SecurityGroups[0].GroupId"             --output text 2>/dev/null || echo "")
[[ "$SEC_DC_SG_ID" == "None" ]] && SEC_DC_SG_ID=""

if [[ -n "$SEC_DC_SG_ID" ]]; then
  safe_import aws_security_group.dc "$SEC_DC_SG_ID"
else
  echo "INFO: Security DC SG not found -- Terraform will create it."
fi

SEC_SSM_SG_ID=$(aws ec2 describe-security-groups             --region "$REGION"             --filters "Name=group-name,Values=security-ssm-endpoints-sg"             --query "SecurityGroups[0].GroupId"             --output text 2>/dev/null || echo "")
[[ "$SEC_SSM_SG_ID" == "None" ]] && SEC_SSM_SG_ID=""

if [[ -n "$SEC_SSM_SG_ID" ]]; then
  safe_import aws_security_group.ssm_endpoints "$SEC_SSM_SG_ID"
else
  echo "INFO: Security SSM endpoints SG not found -- Terraform will create it."
fi

# Import Route53 query log config and association if they exist.
# These resources frequently end up in AWS but not in state when
# the waiter times out on FAILED status -- the association actually
# succeeded but Terraform didn't capture it. Importing both prevents
# the "already associated" error on subsequent applies.
RQLC_ID=$(aws route53resolver list-resolver-query-log-configs \
  --region "$REGION" \
  --query "ResolverQueryLogConfigs[?Name=='security-vpc-dns-query-logs'].Id|[0]" \
  --output text 2>/dev/null || echo "")
[[ "$RQLC_ID" == "None" ]] && RQLC_ID=""

if [[ -n "$RQLC_ID" ]]; then
  safe_import aws_route53_resolver_query_log_config.security "$RQLC_ID"
else
  echo "INFO: No existing Route53 query log config found -- Terraform will create it."
fi

fi # end fresh deploy check for VPC/subnet/SG/KMS/Route53 imports

# Always import Route53 query log association regardless of fresh deploy.
# RSLVR-01306 occurs when an association exists in AWS but not in state --
# this can happen on fresh deploys where the association was created by a
# previous run. Import it here so Terraform doesn't try to create a duplicate.
if [[ -n "$RQLCA_ID" && "$RQLCA_ID" != "None" && "$RQLCA_ID" != "null" ]]; then
  safe_import aws_route53_resolver_query_log_config_association.security "$RQLCA_ID"
else
  echo "INFO: No existing Route53 query log association found -- Terraform will create it."
fi

# Import org-logs S3 bucket if it already exists in this account.
# Bucket existence was verified above with security account credentials.
# Using a captured variable avoids set -e + pipefail interaction when
# terraform state list exits non-zero for transient backend reasons.
BUCKET_NAME="org-logs-${ACCOUNT_ID}-v2"
_bucket_state=$(terraform state list 2>/dev/null || true)
if echo "$_bucket_state" | grep -q "^aws_s3_bucket\.org_logs$"; then
  echo "INFO: org-logs bucket already in state -- skipping import."
elif [[ "$BUCKET_EXISTS_IN_ACCOUNT" == "true" ]]; then
  echo "INFO: Bucket ${BUCKET_NAME} exists in security account -- importing into Terraform state..."
  safe_import aws_s3_bucket.org_logs "$BUCKET_NAME"
else
  echo "INFO: Bucket ${BUCKET_NAME} not found in security account -- Terraform will create it."
fi