#!/usr/bin/env bash
set -euo pipefail

# Script: management-import-state.sh
# Step: Management Account Import State
# Auto-extracted from terraform-deploy.yaml

ACCOUNT_ID="${IMPORT_MANAGEMENT_ACCOUNT_ID}"

# Save original OIDC credentials before assuming the management role.
ORIG_KEY_ID="$AWS_ACCESS_KEY_ID"
ORIG_SECRET="$AWS_SECRET_ACCESS_KEY"
ORIG_TOKEN="$AWS_SESSION_TOKEN"

# Check if the Access Analyzer SLR exists.
MGMT_CREDS=$(aws sts assume-role             --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole"             --role-session-name "GitHubActions-ManagementDescribe"             --output json 2>/dev/null || echo "")

AA_SLR_EXISTS=false
if [[ -n "$MGMT_CREDS" ]]; then
  echo "::add-mask::$(echo "$MGMT_CREDS" | jq -r '.Credentials.AccessKeyId')"
  echo "::add-mask::$(echo "$MGMT_CREDS" | jq -r '.Credentials.SecretAccessKey')"
  echo "::add-mask::$(echo "$MGMT_CREDS" | jq -r '.Credentials.SessionToken')"
  TMP_KEY=$(echo "$MGMT_CREDS"    | jq -r '.Credentials.AccessKeyId')
  TMP_SEC=$(echo "$MGMT_CREDS"    | jq -r '.Credentials.SecretAccessKey')
  TMP_TOK=$(echo "$MGMT_CREDS"    | jq -r '.Credentials.SessionToken')
  export AWS_ACCESS_KEY_ID="$TMP_KEY"
  export AWS_SECRET_ACCESS_KEY="$TMP_SEC"
  export AWS_SESSION_TOKEN="$TMP_TOK"
  if aws iam get-role                 --role-name AWSServiceRoleForAccessAnalyzer                 --output text > /dev/null 2>&1; then
    AA_SLR_EXISTS=true
  fi
else
  # Already running as management account via OIDC - check directly.
  if aws iam get-role                 --role-name AWSServiceRoleForAccessAnalyzer                 --output text > /dev/null 2>&1; then
    AA_SLR_EXISTS=true
  fi
fi

# Restore original credentials before terraform calls.
export AWS_ACCESS_KEY_ID="$ORIG_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$ORIG_SECRET"
export AWS_SESSION_TOKEN="$ORIG_TOKEN"

AA_SLR_ARN="arn:aws:iam::${ACCOUNT_ID}:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer"
if [[ "$AA_SLR_EXISTS" == "true" ]]; then
  LOG=$(mktemp)
  set +e
  terraform import -input=false               aws_iam_service_linked_role.access_analyzer "$AA_SLR_ARN" 2>&1 | tee "$LOG"
  EXIT=${PIPESTATUS[0]}
  set -e
  if [[ $EXIT -eq 0 ]]; then
    echo "INFO: Access Analyzer SLR imported."
  elif grep -q "Resource already managed" "$LOG"; then
    echo "INFO: Access Analyzer SLR already in state -- skipping."
  else
    echo "::error::Import of Access Analyzer SLR failed:"
    cat "$LOG"
    exit 1
  fi
else
  echo "INFO: Access Analyzer SLR not found -- Terraform will create it."
fi

# safe_import_mgmt: import management resources idempotently
safe_import_mgmt() {
  local address="$1"
  local id="$2"
  local log
  log=$(mktemp)
  set +e
  terraform import -input=false "$address" "$id" 2>&1 | tee "$log"
  local exit_code=${PIPESTATUS[0]}
  set -e
  if [[ $exit_code -eq 0 ]]; then
    echo "INFO: Imported ${address}"
  elif grep -qiE "Resource already managed|already exists in state" "$log"; then
    echo "INFO: ${address} already in state -- skipping."
  else
    echo "::warning::Import of ${address} skipped: $(tail -1 "$log")"
  fi
}

SECURITY_ACCOUNT_ID="${IMPORT_SECURITY_ACCOUNT_ID}"
ORG_ROOT_ID=$(aws organizations list-roots             --query "Roots[0].Id" --output text 2>/dev/null || echo "")

# Import existing SCPs by name lookup
for POLICY_NAME in baseline-guardrails region-restriction-us-west-1 enforce-ebs-encryption; do
  POLICY_ID=$(aws organizations list-policies               --filter SERVICE_CONTROL_POLICY               --query "Policies[?Name=='${POLICY_NAME}'].Id|[0]"               --output text 2>/dev/null || echo "")
  if [[ -n "$POLICY_ID" && "$POLICY_ID" != "None" ]]; then
    case "$POLICY_NAME" in
      baseline-guardrails)
        safe_import_mgmt aws_organizations_policy.baseline_guardrails "$POLICY_ID"
        [[ -n "$ORG_ROOT_ID" ]] && safe_import_mgmt                     aws_organizations_policy_attachment.baseline_guardrails_root                     "${ORG_ROOT_ID}:${POLICY_ID}"
        ;;
      region-restriction-us-west-1)
        safe_import_mgmt aws_organizations_policy.region_restriction "$POLICY_ID"
        [[ -n "$ORG_ROOT_ID" ]] && safe_import_mgmt                     aws_organizations_policy_attachment.region_restriction_root                     "${ORG_ROOT_ID}:${POLICY_ID}"
        ;;
      enforce-ebs-encryption)
        safe_import_mgmt aws_organizations_policy.enforce_ebs_encryption "$POLICY_ID"
        [[ -n "$ORG_ROOT_ID" ]] && safe_import_mgmt                     aws_organizations_policy_attachment.enforce_ebs_encryption_root                     "${ORG_ROOT_ID}:${POLICY_ID}"
        ;;
    esac
  fi
done

# Import tag policy
TAG_POLICY_ID=$(aws organizations list-policies             --filter TAG_POLICY             --query "Policies[?Name=='org-tag-standards'].Id|[0]"             --output text 2>/dev/null || echo "")
if [[ -n "$TAG_POLICY_ID" && "$TAG_POLICY_ID" != "None" ]]; then
  safe_import_mgmt aws_organizations_policy.tag_policy "$TAG_POLICY_ID"
  [[ -n "$ORG_ROOT_ID" ]] && safe_import_mgmt               aws_organizations_policy_attachment.tag_policy_root               "${ORG_ROOT_ID}:${TAG_POLICY_ID}"
fi

# Import FullAWSAccess root attachment
[[ -n "$ORG_ROOT_ID" ]] && safe_import_mgmt             aws_organizations_policy_attachment.full_aws_access_root             "${ORG_ROOT_ID}:p-FullAWSAccess" || true

          # Import delegated administrators using exact Terraform resource names
declare -A DELEGATED_MAP
DELEGATED_MAP["config.amazonaws.com"]="aws_organizations_delegated_administrator.config"
DELEGATED_MAP["config-multiaccountsetup.amazonaws.com"]="aws_organizations_delegated_administrator.config_setup"
DELEGATED_MAP["access-analyzer.amazonaws.com"]="aws_organizations_delegated_administrator.access_analyzer"
DELEGATED_MAP["guardduty.amazonaws.com"]="aws_organizations_delegated_administrator.guardduty"
DELEGATED_MAP["securityhub.amazonaws.com"]="aws_organizations_delegated_administrator.securityhub"
DELEGATED_MAP["macie.amazonaws.com"]="aws_organizations_delegated_administrator.macie"
DELEGATED_MAP["inspector2.amazonaws.com"]="aws_organizations_delegated_administrator.inspector"

for SERVICE in "${!DELEGATED_MAP[@]}"; do
  RESOURCE_ADDR="${DELEGATED_MAP[$SERVICE]}"
  DELG=$(aws organizations list-delegated-administrators \
    --service-principal "$SERVICE" \
    --query "DelegatedAdministrators[?Id=='${SECURITY_ACCOUNT_ID}'].Id|[0]" \
    --output text 2>/dev/null || echo "")
  if [[ -n "$DELG" && "$DELG" != "None" ]]; then
    safe_import_mgmt "$RESOURCE_ADDR" "${SECURITY_ACCOUNT_ID}/${SERVICE}" || true
  else
    echo "INFO: No delegation found for ${SERVICE} -- skipping."
  fi
done

# Import service-specific admin account designations — GuardDuty, SecurityHub, Inspector2.
# These are distinct from the Organizations-level delegated administrator resources in
# config.tf and are applied early in deploy-management-scps. The imports here cover the
# case where deploy-management-scps succeeded but the state was lost, or where the
# resources were created outside of Terraform.

GD_DETECTOR=$(aws guardduty list-detectors \
  --query "DetectorIds[0]" --output text 2>/dev/null || echo "")
if [[ -n "$GD_DETECTOR" && "$GD_DETECTOR" != "None" ]]; then
  safe_import_mgmt aws_guardduty_detector.management "$GD_DETECTOR"
fi

GD_ADMIN=$(aws guardduty list-organization-admin-accounts \
  --query "AdminAccounts[?AdminAccountId=='${SECURITY_ACCOUNT_ID}'].AdminAccountId|[0]" \
  --output text 2>/dev/null || echo "")
if [[ -n "$GD_ADMIN" && "$GD_ADMIN" != "None" ]]; then
  safe_import_mgmt aws_guardduty_organization_admin_account.main "$SECURITY_ACCOUNT_ID"
fi

SH_ARN=$(aws securityhub describe-hub \
  --query "HubArn" --output text 2>/dev/null || echo "")
if [[ -n "$SH_ARN" && "$SH_ARN" != "None" ]]; then
  safe_import_mgmt aws_securityhub_account.management "$ACCOUNT_ID"
fi

SH_ADMIN=$(aws securityhub list-organization-admin-accounts \
  --query "AdminAccounts[?AccountId=='${SECURITY_ACCOUNT_ID}'].AccountId|[0]" \
  --output text 2>/dev/null || echo "")
if [[ -n "$SH_ADMIN" && "$SH_ADMIN" != "None" ]]; then
  safe_import_mgmt aws_securityhub_organization_admin_account.main "$SECURITY_ACCOUNT_ID"
fi

# Import Macie management account enablement and org admin delegation if active.
# HCL import blocks for these were removed -- they fail hard when Macie is not
# yet enabled. CLI import is graceful: skips when absent, creates when not in state.
MACIE_STATUS=$(aws macie2 get-macie-session \
  --query "status" --output text 2>/dev/null || echo "")
if [[ "$MACIE_STATUS" == "ENABLED" ]]; then
  safe_import_mgmt aws_macie2_account.main "$ACCOUNT_ID"
fi

MACIE_ADMIN=$(aws macie2 list-organization-admin-accounts \
  --query "adminAccounts[?accountId=='${SECURITY_ACCOUNT_ID}'].accountId|[0]" \
  --output text 2>/dev/null || echo "")
if [[ -n "$MACIE_ADMIN" && "$MACIE_ADMIN" != "None" ]]; then
  safe_import_mgmt aws_macie2_organization_admin_account.main "$SECURITY_ACCOUNT_ID"
fi

# Import org conformance pack if it exists
CP_NAME=$(aws configservice describe-organization-conformance-packs \
  --organization-conformance-pack-names "AWS-Foundational-Security-Best-Practices" \
  --query "OrganizationConformancePacks[0].OrganizationConformancePackName" \
  --output text 2>/dev/null || echo "")
if [[ -n "$CP_NAME" && "$CP_NAME" != "None" ]]; then
  safe_import_mgmt aws_config_organization_conformance_pack.fsbp "AWS-Foundational-Security-Best-Practices"
fi

# Import CloudTrail event data store if it exists.
# Restore first if PENDING_DELETION so terraform import succeeds.
EDS_ARN=$(aws cloudtrail list-event-data-stores \
  --query "EventDataStores[?Name=='management-insights-datastore'].EventDataStoreArn|[0]" \
  --output text 2>/dev/null || echo "")
if [[ -n "$EDS_ARN" && "$EDS_ARN" != "None" ]]; then
  EDS_STATUS=$(aws cloudtrail list-event-data-stores \
    --query "EventDataStores[?Name=='management-insights-datastore'].Status|[0]" \
    --output text 2>/dev/null || echo "")
  if [[ "$EDS_STATUS" == "PENDING_DELETION" ]]; then
    echo "INFO: Event data store is PENDING_DELETION -- restoring before import."
    aws cloudtrail restore-event-data-store --event-data-store "$EDS_ARN" > /dev/null 2>&1 || true
    sleep 10
  fi
  safe_import_mgmt aws_cloudtrail_event_data_store.management_insights "$EDS_ARN"
fi

# Import CloudTrail org trail if it exists
TRAIL_ARN=$(aws cloudtrail describe-trails             --query "trailList[?Name=='org-cloudtrail'].TrailARN|[0]"             --output text 2>/dev/null || echo "")
if [[ -n "$TRAIL_ARN" && "$TRAIL_ARN" != "None" ]]; then
  safe_import_mgmt aws_cloudtrail.org "$TRAIL_ARN"
fi
# =====================================================================
# Import existing cross-account OAM links into management TF state.
#
# observability_links.tf creates aws_oam_link resources in networking,
# corporate, and web (via aliased providers) pointing at the security
# observability sink. When those links already exist in AWS (e.g., from
# a previous CLI-based deploy or a prior management apply that succeeded
# but lost state), Terraform's CreateLink call returns 409 ConflictException
# and the apply fails. Import them first so Terraform sees them as managed.
# =====================================================================
echo ""
echo "Checking for pre-existing OAM links to import ..."

SECURITY_ID="${IMPORT_SECURITY_ACCOUNT_ID:-}"
if [[ -z "$SECURITY_ID" ]]; then
  echo "INFO: IMPORT_SECURITY_ACCOUNT_ID not set -- skipping OAM link import."
else
  # Step 1: discover the sink ARN from the security account.
  SEC_CREDS=$(aws sts assume-role \
    --role-arn "arn:aws:iam::${SECURITY_ID}:role/OrganizationAccountAccessRole" \
    --role-session-name "GitHubActions-OAMSinkDiscovery" \
    --output json 2>/dev/null || echo "")

  SINK_ARN=""
  if [[ -n "$SEC_CREDS" ]]; then
    SINK_ARN=$(AWS_ACCESS_KEY_ID="$(echo "$SEC_CREDS" | jq -r '.Credentials.AccessKeyId')" \
               AWS_SECRET_ACCESS_KEY="$(echo "$SEC_CREDS" | jq -r '.Credentials.SecretAccessKey')" \
               AWS_SESSION_TOKEN="$(echo "$SEC_CREDS" | jq -r '.Credentials.SessionToken')" \
               aws oam list-sinks \
               --query "Items[?Name=='security-observability-sink'].Arn|[0]" \
               --output text 2>/dev/null || echo "")
    [[ "$SINK_ARN" == "None" ]] && SINK_ARN=""
  fi

  if [[ -z "$SINK_ARN" ]]; then
    echo "INFO: OAM sink not found in security -- skipping link import (security workspace may not have applied yet)."
  else
    echo "INFO: Discovered sink ARN: ${SINK_ARN}"

    # Step 2: for each source account, look for an existing link to this
    # sink and import it via the matching aliased Terraform resource.
    import_oam_link() {
      local acct="$1" tf_address="$2" label="$3"
      [[ -z "$acct" ]] && { echo "INFO: ${label} account ID empty -- skipping."; return; }

      local creds
      creds=$(aws sts assume-role \
        --role-arn "arn:aws:iam::${acct}:role/OrganizationAccountAccessRole" \
        --role-session-name "GitHubActions-OAMLink-${label}" \
        --output json 2>/dev/null || echo "")
      [[ -z "$creds" ]] && { echo "INFO: Could not assume role in ${label} -- skipping."; return; }

      local link_arn
      link_arn=$(AWS_ACCESS_KEY_ID="$(echo "$creds" | jq -r '.Credentials.AccessKeyId')" \
                 AWS_SECRET_ACCESS_KEY="$(echo "$creds" | jq -r '.Credentials.SecretAccessKey')" \
                 AWS_SESSION_TOKEN="$(echo "$creds" | jq -r '.Credentials.SessionToken')" \
                 aws oam list-links \
                 --query "Items[?SinkArn=='${SINK_ARN}'].Arn|[0]" \
                 --output text 2>/dev/null || echo "")
      [[ "$link_arn" == "None" ]] && link_arn=""

      if [[ -z "$link_arn" ]]; then
        echo "INFO: ${label} has no OAM link to import -- Terraform will create it."
      else
        echo "INFO: ${label} OAM link exists in AWS (${link_arn}) -- importing into TF state."
        safe_import_mgmt "${tf_address}" "${link_arn}"
      fi
    }

    import_oam_link "${IMPORT_NETWORKING_ACCOUNT_ID:-}" "aws_oam_link.networking[0]" "networking"
    import_oam_link "${IMPORT_CORPORATE_ACCOUNT_ID:-}"  "aws_oam_link.corporate[0]"  "corporate"
    import_oam_link "${IMPORT_WEB_ACCOUNT_ID:-}"        "aws_oam_link.web[0]"        "web"
  fi
fi
