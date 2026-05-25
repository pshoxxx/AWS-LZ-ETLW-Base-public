#!/usr/bin/env bash
set -euo pipefail

# Script: networking-import-resources.sh
# Step: Import Pre-Existing Networking Account Resources
# Auto-extracted from terraform-deploy.yaml

ACCOUNT_ID="${IMPORT_NETWORKING_ACCOUNT_ID}"

# Save OIDC credentials before assuming the networking account role
ORIG_KEY_ID="$AWS_ACCESS_KEY_ID"
ORIG_SECRET="$AWS_SECRET_ACCESS_KEY"
ORIG_TOKEN="$AWS_SESSION_TOKEN"

CREDS=$(aws sts assume-role \
  --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole" \
  --role-session-name "GitHubActions-NetworkingImport" \
  --output json)
export AWS_ACCESS_KEY_ID=$(echo "$CREDS"     | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS"     | jq -r '.Credentials.SessionToken')

CONFIG_SLR_EXISTS=false
if aws iam get-role --role-name AWSServiceRoleForConfig \
    --output text > /dev/null 2>&1; then
  CONFIG_SLR_EXISTS=true
fi

# Restore original OIDC credentials before any terraform calls
export AWS_ACCESS_KEY_ID="$ORIG_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$ORIG_SECRET"
export AWS_SESSION_TOKEN="$ORIG_TOKEN"

safe_import() {
  local address="$1" id="$2" log
  log=$(mktemp)
  set +e
  terraform import -input=false "$address" "$id" 2>&1 | tee "$log"
  local exit_code=${PIPESTATUS[0]}
  set -e
  if [[ $exit_code -eq 0 ]]; then
    echo "INFO: Import of ${address} succeeded."
  elif grep -q "Resource already managed" "$log"; then
    echo "INFO: ${address} already in state -- skipping."
  else
    echo "::warning::Import of ${address} failed -- Terraform will attempt to create it."
  fi
}

if [[ "$CONFIG_SLR_EXISTS" == "true" ]]; then
  safe_import aws_iam_service_linked_role.config \
    "arn:aws:iam::${ACCOUNT_ID}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
else
  echo "INFO: Config SLR not found -- Terraform will create it."
fi