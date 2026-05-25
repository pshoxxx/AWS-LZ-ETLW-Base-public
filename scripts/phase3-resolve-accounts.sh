#!/usr/bin/env bash
set -euo pipefail

# Script: scripts/phase3-resolve-accounts.sh
# Step: Resolve Account IDs and TGW Attachment IDs
#
# Uses pre-resolved account IDs from IMPORT_*_ACCOUNT_ID env vars when
# available (set by the resolve-accounts job), falling back to API calls.

TGW_ID="${IMPORT_TGW_ID}"
[[ -z "$TGW_ID" ]] && { echo "ERROR: transit_gateway_id is empty"; exit 1; }

if [[ -n "${IMPORT_NETWORKING_ACCOUNT_ID:-}" ]]; then
  NETWORKING_ID="$IMPORT_NETWORKING_ACCOUNT_ID"
else
  NETWORKING_ID=$(aws organizations list-accounts \
    --query "Accounts[?Name=='networking-environment'&&Status=='ACTIVE'].Id|[0]" \
    --output text)
  [[ -z "$NETWORKING_ID" || "$NETWORKING_ID" == "None" ]] && \
    { echo "ERROR: Cannot resolve networking-environment account"; exit 1; }
fi

if [[ -n "${IMPORT_CORPORATE_ACCOUNT_ID:-}" ]]; then
  CORPORATE_ID="$IMPORT_CORPORATE_ACCOUNT_ID"
else
  CORPORATE_ID=$(aws organizations list-accounts \
    --query "Accounts[?Name=='corporate-main-environment'&&Status=='ACTIVE'].Id|[0]" \
    --output text)
  [[ -z "$CORPORATE_ID" || "$CORPORATE_ID" == "None" ]] && \
    { echo "ERROR: Cannot resolve corporate-main-environment account"; exit 1; }
fi

if [[ -n "${IMPORT_SECURITY_ACCOUNT_ID:-}" ]]; then
  SECURITY_ID="$IMPORT_SECURITY_ACCOUNT_ID"
else
  SECURITY_ID=$(aws organizations list-accounts \
    --query "Accounts[?Name=='security-environment'&&Status=='ACTIVE'].Id|[0]" \
    --output text)
  [[ -z "$SECURITY_ID" || "$SECURITY_ID" == "None" ]] && \
    { echo "ERROR: Cannot resolve security-environment account"; exit 1; }
fi

# Assume the networking account role to describe attachments.
NETWORKING_CREDS=$(aws sts assume-role \
  --role-arn "arn:aws:iam::${NETWORKING_ID}:role/OrganizationAccountAccessRole" \
  --role-session-name "GitHubActions-Phase3-AttachmentLookup" \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo "$NETWORKING_CREDS"     | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$NETWORKING_CREDS" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$NETWORKING_CREDS"     | jq -r '.Credentials.SessionToken')

# describe-transit-gateway-vpc-attachments does not support owner-id as a filter.
# Fetch all attachments for the TGW and filter by VpcOwnerId in the JMESPath query.
ALL_ATTACHMENTS=$(aws ec2 describe-transit-gateway-vpc-attachments \
  --filters \
    "Name=transit-gateway-id,Values=$TGW_ID" \
    "Name=state,Values=available,pending,pendingAcceptance" \
  --query "TransitGatewayVpcAttachments[*].{Id:TransitGatewayAttachmentId,Owner:VpcOwnerId}" \
  --output json)

CORPORATE_ATT=$(echo "$ALL_ATTACHMENTS" | jq -r ".[] | select(.Owner==\"$CORPORATE_ID\") | .Id" | head -1)
[[ -z "$CORPORATE_ATT" || "$CORPORATE_ATT" == "None" ]] && \
  { echo "ERROR: Cannot resolve corporate TGW attachment ID for owner $CORPORATE_ID"; exit 1; }

SECURITY_ATT=$(echo "$ALL_ATTACHMENTS" | jq -r ".[] | select(.Owner==\"$SECURITY_ID\") | .Id" | head -1)
[[ -z "$SECURITY_ATT" || "$SECURITY_ATT" == "None" ]] && \
  { echo "ERROR: Cannot resolve security TGW attachment ID for owner $SECURITY_ID"; exit 1; }

# Management TGW attachment is optional -- only present after terraform-identity.yaml
# has run. Non-fatal if missing; the management RT association count stays at 0.
MANAGEMENT_ID="${IMPORT_MANAGEMENT_ACCOUNT_ID:-}"

MANAGEMENT_ATT=""
if [[ -n "$MANAGEMENT_ID" ]]; then
  MANAGEMENT_ATT=$(echo "$ALL_ATTACHMENTS" | jq -r ".[] | select(.Owner==\"$MANAGEMENT_ID\") | .Id" | head -1)
  [[ "$MANAGEMENT_ATT" == "None" ]] && MANAGEMENT_ATT=""
fi

# Web TGW attachment is optional -- only present after deploy-web has run.
# Non-fatal if missing; the web RT association count stays at 0.
WEB_ID="${IMPORT_WEB_ACCOUNT_ID:-}"

WEB_ATT=""
if [[ -n "$WEB_ID" ]]; then
  WEB_ATT=$(echo "$ALL_ATTACHMENTS" | jq -r ".[] | select(.Owner==\"$WEB_ID\") | .Id" | head -1)
  [[ "$WEB_ATT" == "None" ]] && WEB_ATT=""
fi

echo "Resolved:"
echo "  corporate_tgw_attachment_id:  $CORPORATE_ATT"
echo "  security_tgw_attachment_id:   $SECURITY_ATT"
echo "  management_tgw_attachment_id: ${MANAGEMENT_ATT:-(not present yet)}"
echo "  web_tgw_attachment_id:        ${WEB_ATT:-(not present yet)}"

echo "account_id=$NETWORKING_ID"                    >> "$GITHUB_OUTPUT"
echo "corporate_account_id=$CORPORATE_ID"          >> "$GITHUB_OUTPUT"
echo "security_account_id=$SECURITY_ID"            >> "$GITHUB_OUTPUT"
echo "web_account_id=$WEB_ID"                      >> "$GITHUB_OUTPUT"
echo "corporate_tgw_attachment_id=$CORPORATE_ATT"  >> "$GITHUB_OUTPUT"
echo "security_tgw_attachment_id=$SECURITY_ATT"    >> "$GITHUB_OUTPUT"
echo "management_tgw_attachment_id=$MANAGEMENT_ATT" >> "$GITHUB_OUTPUT"
echo "web_tgw_attachment_id=$WEB_ATT"              >> "$GITHUB_OUTPUT"
echo "TF_VAR_account_id=$NETWORKING_ID"            >> "$GITHUB_ENV"
