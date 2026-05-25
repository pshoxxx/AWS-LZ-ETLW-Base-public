#!/usr/bin/env bash
# =============================================================================
# delegate-administrators.sh
#
# Registers delegated administrators for AWS Organization services.
# Run this from CloudShell in the MANAGEMENT account as a user with
# organizations:RegisterDelegatedAdministrator permissions.
#
# This is a one-time bootstrap operation. Re-running is safe -- already
# delegated accounts are skipped with a notice rather than erroring out.
#
# Usage:
#   chmod +x delegate-administrators.sh
#   ./delegate-administrators.sh
#
# What this script does:
#   - Resolves member account IDs by name from the organization
#   - Delegates each AWS service to the appropriate account
#   - Enables trusted access for services that require it separately
#   - Validates each delegation after registering
#
# =============================================================================
# DELEGATION MAP
# =============================================================================
#
# Security account receives delegation for:
#   - guardduty.amazonaws.com         GuardDuty org-wide detector management
#   - securityhub.amazonaws.com       Security Hub aggregation and standards
#   - macie.amazonaws.com             Macie org-wide discovery management
#   - inspector2.amazonaws.com        Inspector v2 org-wide scanning
#   - access-analyzer.amazonaws.com   IAM Access Analyzer org-wide
#   - config.amazonaws.com            AWS Config aggregation
#   - sso.amazonaws.com               IAM Identity Center (if not in mgmt)
#   - auditmanager.amazonaws.com      Audit Manager (future use)
#   - detective.amazonaws.com         Amazon Detective (future use)
#
# Management account handles directly (no delegation needed):
#   - cloudtrail.amazonaws.com        Org trail is created in management
#   - billing                         Always management account
#   - organizations                   Always management account
#   - scp enforcement                 Always management account
#
# Security account also receives delegation for:
#   - account.amazonaws.com           Locks root credential management to
#                                     security account; prevents reassignment
#                                     on re-runs
#
# NOTE: Centralized root credential management (removing root credentials
# from member accounts) is handled in Step 4 of this script via the IAM
# API (aws iam enable-organizations-root-credentials-management). It
# checks the current status and enables it automatically if not already
# on. This feature requires all features enabled in Organizations.
#
# NOTE: IAM Identity Center (sso.amazonaws.com) delegation is included but
# commented out. For this architecture IAM Identity Center is managed in the
# management account directly, which is the recommended approach for a
# single-org deployment. Uncomment if you move it to a dedicated account.
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log()    { echo -e "${BLUE}[DELEGATE]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
err()    { echo -e "${RED}[ERR]${NC} $*"; }
skip()   { echo -e "${YELLOW}[SKIP]${NC} $*"; }

REGION="${AWS_DEFAULT_REGION:-us-west-1}"

echo ""
echo "============================================================"
echo "  AWS Organizations -- Delegated Administrator Setup"
echo "  Region: ${REGION}"
echo "============================================================"
echo ""

# =============================================================================
# Verify we are in the management account
# =============================================================================
CALLER=$(aws sts get-caller-identity --output json)
CURRENT_ACCOUNT=$(echo "$CALLER" | jq -r '.Account')
MANAGEMENT_ACCOUNT=$(aws organizations describe-organization \
    --query "Organization.MasterAccountId" \
    --output text)

if [[ "$CURRENT_ACCOUNT" != "$MANAGEMENT_ACCOUNT" ]]; then
    err "This script must be run from the management account."
    err "Current account: ${CURRENT_ACCOUNT}"
    err "Management account: ${MANAGEMENT_ACCOUNT}"
    exit 1
fi

ok "Running in management account: ${MANAGEMENT_ACCOUNT}"
echo ""

# =============================================================================
# Resolve member account IDs by name
# Matches the naming convention used in the Terraform modules.
# =============================================================================
log "Resolving member account IDs from organization..."

resolve_account() {
    local name="$1"
    local account_id
    account_id=$(aws organizations list-accounts \
        --query "Accounts[?Name=='${name}'&&Status=='ACTIVE'].Id|[0]" \
        --output text 2>/dev/null || echo "")
    if [[ -z "$account_id" || "$account_id" == "None" ]]; then
        err "Could not resolve account: ${name}"
        echo ""
        return 1
    fi
    echo "$account_id"
}

SECURITY_ACCOUNT_ID=$(resolve_account "security-environment")
CORPORATE_ACCOUNT_ID=$(resolve_account "corporate-main-environment")
NETWORKING_ACCOUNT_ID=$(resolve_account "networking-environment")
SHARED_SERVICES_ACCOUNT_ID=$(resolve_account "shared-services-environment")

ok "Security account:        ${SECURITY_ACCOUNT_ID}"
ok "Corporate account:       ${CORPORATE_ACCOUNT_ID}"
ok "Networking account:      ${NETWORKING_ACCOUNT_ID}"
ok "Shared services account: ${SHARED_SERVICES_ACCOUNT_ID}"
echo ""

# =============================================================================
# Helper functions
# =============================================================================

# enable_trusted_access: enables trusted access for a service principal
# in AWS Organizations. Required before delegating for some services.
# Idempotent -- handles prior enablement via web UI, CLI, or this script.
enable_trusted_access() {
    local service="$1"

    # Check if already enabled before attempting to enable
    EXISTING_TA=$(aws organizations list-aws-service-access-for-organization         --query "EnabledServicePrincipals[?ServicePrincipal=='${service}'].ServicePrincipal|[0]"         --output text 2>/dev/null || echo "")

    if [[ -n "$EXISTING_TA" && "$EXISTING_TA" != "None" ]]; then
        skip "  Trusted access already enabled: ${service}"
        return 0
    fi

    log "Enabling trusted access for: ${service}"
    set +e
    TA_OUTPUT=$(aws organizations enable-aws-service-access         --service-principal "${service}" 2>&1)
    TA_EXIT=$?
    set -e

    if [[ $TA_EXIT -eq 0 ]]; then
        ok "  Trusted access enabled: ${service}"
    elif echo "$TA_OUTPUT" | grep -qiE "AlreadyExists|already enabled|already registered"; then
        ok "  Trusted access already enabled (detected via API): ${service}"
    else
        warn "  Could not enable trusted access for ${service}"
        warn "  Output: ${TA_OUTPUT}"
    fi
}

# delegate: registers a delegated administrator for a service principal.
# Idempotent -- handles prior delegation via web UI, CLI, or this script.
# Distinguishes between already-delegated (skip), not-supported (warn),
# and unexpected errors (err + continue).
delegate() {
    local account_id="$1"
    local service="$2"
    local account_label="$3"

    log "Delegating ${service} to ${account_label} (${account_id})"

    # Check if already delegated before attempting to register
    EXISTING=$(aws organizations list-delegated-administrators         --service-principal "${service}"         --query "DelegatedAdministrators[?Id=='${account_id}'].Id|[0]"         --output text 2>/dev/null || echo "")

    if [[ -n "$EXISTING" && "$EXISTING" != "None" ]]; then
        skip "  Already delegated: ${service} -> ${account_label}"
        return 0
    fi

    set +e
    DEL_OUTPUT=$(aws organizations register-delegated-administrator         --account-id "${account_id}"         --service-principal "${service}" 2>&1)
    DEL_EXIT=$?
    set -e

    if [[ $DEL_EXIT -eq 0 ]]; then
        ok "  Delegated: ${service} -> ${account_label}"
    elif echo "$DEL_OUTPUT" | grep -qiE "AlreadyRegisteredException|already.*delegated|already.*registered"; then
        ok "  Already delegated (detected via API): ${service} -> ${account_label}"
    elif echo "$DEL_OUTPUT" | grep -qiE "InvalidInput|does not support|not supported|UnsupportedOperation"; then
        warn "  Service does not support delegation or is not available in this region: ${service}"
        warn "  Output: ${DEL_OUTPUT}"
    elif echo "$DEL_OUTPUT" | grep -qiE "AccountNotRegisteredException|account.*not.*member"; then
        err "  Account ${account_id} is not a member of this organization: ${service}"
    else
        warn "  Delegation may have failed for ${service} -> ${account_label}"
        warn "  Output: ${DEL_OUTPUT}"
    fi
}

# validate: confirms delegation is in place after registering
validate() {
    local account_id="$1"
    local service="$2"

    RESULT=$(aws organizations list-delegated-administrators \
        --service-principal "${service}" \
        --query "DelegatedAdministrators[?Id=='${account_id}'].Status|[0]" \
        --output text 2>/dev/null || echo "")

    if [[ "$RESULT" == "ACTIVE" ]]; then
        ok "  Validated: ${service} -> ${account_id} (ACTIVE)"
    else
        warn "  Validation failed for ${service} -> ${account_id} (status: ${RESULT:-not found})"
    fi
}

# =============================================================================
# Enable trusted access for all services before delegating
# Some services require this step before delegation will succeed.
# =============================================================================
echo "------------------------------------------------------------"
echo "Step 1 -- Enable trusted access for organization services"
echo "------------------------------------------------------------"
echo ""

enable_trusted_access "guardduty.amazonaws.com"
enable_trusted_access "securityhub.amazonaws.com"
enable_trusted_access "macie.amazonaws.com"
enable_trusted_access "inspector2.amazonaws.com"
enable_trusted_access "access-analyzer.amazonaws.com"
enable_trusted_access "config.amazonaws.com"
enable_trusted_access "config-multiaccountsetup.amazonaws.com"
enable_trusted_access "auditmanager.amazonaws.com"
enable_trusted_access "detective.amazonaws.com"
enable_trusted_access "account.amazonaws.com"
enable_trusted_access "sso.amazonaws.com"

echo ""

# =============================================================================
# Delegate security services to the security account
# =============================================================================
echo "------------------------------------------------------------"
echo "Step 2 -- Delegate security services to security account"
echo "------------------------------------------------------------"
echo ""

# GuardDuty
# Delegation allows the security account to manage detectors, create findings
# filters, and configure threat intelligence across all org accounts without
# needing management account credentials.
delegate "${SECURITY_ACCOUNT_ID}" "guardduty.amazonaws.com" "security"

# Security Hub
# Delegation allows the security account to aggregate findings from all
# accounts, enable standards org-wide, and manage the central findings view.
delegate "${SECURITY_ACCOUNT_ID}" "securityhub.amazonaws.com" "security"

# Macie
# Delegation allows the security account to enable Macie org-wide, configure
# discovery jobs, and view sensitive data findings across all accounts.
delegate "${SECURITY_ACCOUNT_ID}" "macie.amazonaws.com" "security"

# Inspector v2
# Delegation allows the security account to enable Inspector across all org
# accounts and view vulnerability findings centrally.
delegate "${SECURITY_ACCOUNT_ID}" "inspector2.amazonaws.com" "security"

# IAM Access Analyzer
# Delegation allows the security account to create an organization analyzer
# that surfaces cross-account and cross-service access findings.
delegate "${SECURITY_ACCOUNT_ID}" "access-analyzer.amazonaws.com" "security"

# AWS Config
# Delegation allows the security account to act as the aggregation account
# for Config data from all member accounts. The Config aggregator in the
# security account pulls resource configuration history and compliance data.
delegate "${SECURITY_ACCOUNT_ID}" "config.amazonaws.com" "security"
delegate "${SECURITY_ACCOUNT_ID}" "config-multiaccountsetup.amazonaws.com" "security"

# Audit Manager (future use)
# Delegation allows the security account to collect evidence across accounts
# for compliance frameworks (SOC 2, PCI DSS, NIST 800-53).
# Not actively configured in this deployment but delegated for readiness.
delegate "${SECURITY_ACCOUNT_ID}" "auditmanager.amazonaws.com" "security"

# Amazon Detective (future use)
# Delegation allows the security account to enable Detective org-wide for
# security investigation and graph-based threat analysis.
# Requires GuardDuty to be enabled first.
delegate "${SECURITY_ACCOUNT_ID}" "detective.amazonaws.com" "security"

# AWS Account Management (account.amazonaws.com)
# Explicitly delegates account management to the security account to
# ensure centralized root credential management is owned by security
# and not reassigned to another account on re-runs.
delegate "${SECURITY_ACCOUNT_ID}" "account.amazonaws.com" "security"

echo ""

# =============================================================================
# IAM Identity Center
# Kept in management account for this deployment (single-org, simpler trust).
# Uncomment the delegation below if moving to a dedicated Identity account.
# =============================================================================
echo "------------------------------------------------------------"
echo "Step 3 -- IAM Identity Center"
echo "------------------------------------------------------------"
echo ""

log "IAM Identity Center is managed in the management account directly."
log "No delegation required for this architecture."
log "To delegate to a different account, uncomment the line below"
log "and replace IDENTITY_ACCOUNT_ID with the target account ID."
echo ""
# delegate "<IDENTITY_ACCOUNT_ID>" "sso.amazonaws.com" "identity"

# =============================================================================
# Centralized root credential management
# =============================================================================
echo "------------------------------------------------------------"
echo "Step 4 -- Centralized root credential management"
echo "------------------------------------------------------------"
echo ""

log "Checking root credential management status..."

# Check status via IAM API (not Organizations policy type)
set +e
STATUS_OUTPUT=$(aws iam get-organizations-access-report 2>&1)
ROOT_CRED_STATUS=$(aws iam list-organizations-features \
    --query "EnabledFeatures" \
    --output text 2>/dev/null || echo "")
set -e

if echo "$ROOT_CRED_STATUS" | grep -q "RootCredentialsManagement"; then
    ok "Centralized root credential management is ENABLED."
    log "Member account root credentials are centrally managed."
    log "Root sessions for member accounts must be initiated via the management account."
else
    warn "Centralized root credential management is not yet enabled -- enabling now..."
    set +e
    ENABLE_OUTPUT=$(aws iam enable-organizations-root-credentials-management 2>&1)
    ENABLE_EXIT=$?
    set -e

    if [[ $ENABLE_EXIT -eq 0 ]]; then
        ok "Centralized root credential management enabled successfully."
    elif echo "$ENABLE_OUTPUT" | grep -qiE "AlreadyExists|already enabled|already.*active"; then
        ok "Centralized root credential management was already enabled (detected via API)."
    elif echo "$ENABLE_OUTPUT" | grep -qiE "AccessDenied|not authorized"; then
        err "Insufficient permissions to enable centralized root credential management."
        err "This must be run as a principal with iam:EnableOrganizationsRootCredentialsManagement."
        err "Output: ${ENABLE_OUTPUT}"
    else
        err "Failed to enable centralized root credential management."
        err "Output: ${ENABLE_OUTPUT}"
        err "You may need to enable this manually via the AWS console:"
        err "  IAM -> Centralized root access -> Enable"
    fi
fi

echo ""


# =============================================================================
# Validate all delegations
# =============================================================================
echo "------------------------------------------------------------"
echo "Step 5 -- Validate delegations"
echo "------------------------------------------------------------"
echo ""

SERVICES=(
    "guardduty.amazonaws.com"
    "securityhub.amazonaws.com"
    "macie.amazonaws.com"
    "inspector2.amazonaws.com"
    "access-analyzer.amazonaws.com"
    "config.amazonaws.com"
    "auditmanager.amazonaws.com"
    "detective.amazonaws.com"
)

for service in "${SERVICES[@]}"; do
    validate "${SECURITY_ACCOUNT_ID}" "${service}"
done

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "============================================================"
ok "Delegation setup complete."
echo ""
echo "Security account (${SECURITY_ACCOUNT_ID}) is now delegated admin for:"
echo "  - GuardDuty"
echo "  - Security Hub"
echo "  - Macie"
echo "  - Inspector v2"
echo "  - IAM Access Analyzer"
echo "  - AWS Config"
echo "  - Audit Manager"
echo "  - Amazon Detective"
echo ""
echo "Next steps:"
echo "  1. In the security account, enable GuardDuty org-wide:"
echo "     aws guardduty update-organization-configuration \\"
echo "       --detector-id <DETECTOR_ID> \\"
echo "       --auto-enable-organization-members ALL"
echo ""
echo "  2. In the security account, enable Security Hub org-wide:"
echo "     aws securityhub update-organization-configuration \\"
echo "       --auto-enable"
echo ""
echo "  3. In the security account, create a Config aggregator:"
echo "     aws configservice put-configuration-aggregator \\"
echo "       --configuration-aggregator-name org-aggregator \\"
echo "       --organization-aggregation-source \\"
echo "         RoleArn=arn:aws:iam::<SECURITY_ID>:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig,AllAwsRegions=true"
echo "============================================================"
