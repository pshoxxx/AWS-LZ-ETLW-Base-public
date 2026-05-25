#!/usr/bin/env bash
# =============================================================================
# siem-threat-simulation.sh
#
# Simulates threat scenarios to trigger SIEM detections in the security account.
# Run this from CloudShell logged into the SECURITY account as an admin user.
#
# IMPORTANT: This script intentionally performs actions that will appear in
# CloudTrail and trigger SIEM alerts. All actions are reversible. Run the
# companion undo script (siem-threat-simulation-undo.sh) after testing.
#
# Scenarios simulated:
#   1. IAM privilege escalation attempt (attach admin policy to test role)
#   2. Unauthorized S3 access to org-logs bucket
#   3. Unencrypted resource creation (unencrypted EBS volume)
#   4. Security service tampering attempt (try to stop Config recorder)
#   5. Credential exposure in API call (put SSM parameter with 'password' in name)
#
# =============================================================================
# PRE-FLIGHT -- scenario 3 requires two controls to be temporarily disabled
# =============================================================================
#
# Scenario 3 creates an unencrypted EBS volume. Two controls block this
# by default and must be commented out before running:
#
#   A. SCP -- terraform/management/scps.tf
#      Comment out DenyUnencryptedEBSVolumes and
#      DenyRunInstancesWithUnencryptedVolumes in the
#      enforce_ebs_encryption policy content block.
#      Push to main and let the deploy run to apply the change.
#
#   B. Account default -- each member account main.tf
#      Comment out the aws_ebs_encryption_by_default block
#      in corporate, security, and networking main.tf.
#
# All other scenarios (1, 2, 4, 5) run without any pre-flight changes.
#
# =============================================================================
# VERIFYING DETECTIONS IN ATHENA
# =============================================================================
#
# After running the simulation, wait 15-20 minutes for CloudTrail events
# to deliver to the org-logs S3 bucket, then:
#
#   1. Open Athena in the security account
#      Workgroup: org-siem   Database: org-siem
#
#   2. Repair partitions to pick up new data:
#        MSCK REPAIR TABLE cloudtrail;
#
#   3. Run the named detection queries saved in the org-siem workgroup.
#      Each query name matches its detection:
#        IAMPrivilegeEscalation, UnencryptedResourceCreation,
#        SecurityServiceTampering, CredentialExposure,
#        UnauthorizedLogBucketAccess
#
#   4. Invoke the Lambda to trigger automated detection and SNS alert:
#        aws lambda invoke \
#          --function-name siem-detector \
#          --region us-west-1 \
#          --payload '{}' \
#          /tmp/siem-response.json && cat /tmp/siem-response.json
#
#   5. Check your alert email for the SNS notification.
#
# =============================================================================
# RESTORING POSTURE AFTER SIMULATION
# =============================================================================
#
#   1. Run: ./siem-threat-simulation-undo.sh
#   2. Uncomment the SCP statements in management_scps.tf
#   3. Uncomment aws_ebs_encryption_by_default in each member account main.tf
#   4. Push to main and let the deploy run to restore the SCP
#
# =============================================================================
# Usage:
#   chmod +x siem-threat-simulation.sh
#   ./siem-threat-simulation.sh [--scenario N]  # run all or specific scenario
# =============================================================================

set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-west-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%Y%m%d%H%M%S)
SIM_TAG="siem-sim-${TIMESTAMP}"

# Colour output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[SIM]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }

SCENARIO="${1:-all}"
RESOURCES_CREATED=()

echo ""
echo "============================================================"
echo "  SIEM Threat Simulation"
echo "  Account : ${ACCOUNT_ID}"
echo "  Region  : ${REGION}"
echo "  Run ID  : ${SIM_TAG}"
echo "============================================================"
echo ""
warn "This script performs real AWS API calls that will appear in CloudTrail."
warn "Run siem-threat-simulation-undo.sh to clean up resources created here."
echo ""
read -r -p "Continue? [y/N] " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Aborted."; exit 0; }
echo ""

# =============================================================================
# Scenario 1: IAM Privilege Escalation
# Creates a test IAM role then attaches AdministratorAccess to it.
# Triggers: IAMPrivilegeEscalation detection (AttachRolePolicy with admin ARN)
# =============================================================================
run_scenario_1() {
    log "Scenario 1: IAM Privilege Escalation"
    echo "  Creates a test role and attaches AdministratorAccess to it."
    echo "  This triggers the IAMPrivilegeEscalation detection."
    echo ""

    ROLE_NAME="siem-sim-test-role-${TIMESTAMP}"

    aws iam create-role \
        --role-name "${ROLE_NAME}" \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }' \
        --tags Key=SimulationTag,Value="${SIM_TAG}" \
        --output text > /dev/null

    ok "  Created test role: ${ROLE_NAME}"
    RESOURCES_CREATED+=("iam-role:${ROLE_NAME}")

    # This is the trigger: attach AdministratorAccess
    aws iam attach-role-policy \
        --role-name "${ROLE_NAME}" \
        --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

    ok "  Attached AdministratorAccess to ${ROLE_NAME}"
    ok "  CloudTrail event: AttachRolePolicy with AdministratorAccess"
    echo "  Detection: IAMPrivilegeEscalation"
    echo ""
}

# =============================================================================
# Scenario 2: Unauthorized Access to org-logs Audit Bucket
# Attempts to list and read objects in the org-logs bucket.
# Triggers: UnauthorizedLogBucketAccess detection
# =============================================================================
run_scenario_2() {
    log "Scenario 2: Unauthorized Access to org-logs Audit Bucket"
    echo "  Reads and lists objects in the centralized log archive bucket."
    echo "  Simulates an insider attempting to access or exfiltrate audit logs."
    echo ""

    BUCKET="org-logs-${ACCOUNT_ID}-v2"

    # List bucket (generates S3 event in CloudTrail if data events are enabled)
    log "  Attempting to list objects in s3://${BUCKET}/cloudtrail/ ..."
    aws s3 ls "s3://${BUCKET}/cloudtrail/" --region "${REGION}" \
        --recursive --human-readable 2>/dev/null | head -5 || \
        warn "  Access denied or bucket empty (still generates CloudTrail event)"

    # Attempt GetBucketPolicy (always logged)
    log "  Attempting GetBucketPolicy on ${BUCKET} ..."
    aws s3api get-bucket-policy --bucket "${BUCKET}" \
        --region "${REGION}" --output text 2>/dev/null | head -5 || \
        warn "  GetBucketPolicy failed (still generates CloudTrail event)"

    ok "  CloudTrail events: ListBucket, GetBucketPolicy"
    echo "  Detection: UnauthorizedLogBucketAccess"
    echo "  NOTE: Requires S3 data events enabled on CloudTrail for GetObject detection."
    echo ""
}

# =============================================================================
# Scenario 3: Unencrypted Resource Creation
# Creates an unencrypted EBS volume.
# Triggers: UnencryptedResourceCreation detection (CreateVolume without encrypted:true)
# =============================================================================
run_scenario_3() {
    log "Scenario 3: Unencrypted Resource Creation"
    echo "  Attempts to create an unencrypted EBS volume in the region."
    echo "  Simulates misconfigured infrastructure violating encryption posture."
    echo "  SCP may block this -- the ATTEMPT is still logged in CloudTrail."
    echo ""

    set +e
    VOLUME_ID=$(aws ec2 create-volume \
        --availability-zone "${REGION}a" \
        --size 1 \
        --volume-type gp3 \
        --no-encrypted \
        --tag-specifications "ResourceType=volume,Tags=[{Key=SimulationTag,Value=${SIM_TAG}},{Key=Name,Value=siem-sim-unencrypted}]" \
        --region "${REGION}" \
        --query VolumeId \
        --output text 2>&1)
    RESULT=$?
    set -e

    if [[ $RESULT -eq 0 && "$VOLUME_ID" == vol-* ]]; then
        ok "  Created unencrypted EBS volume: ${VOLUME_ID}"
        RESOURCES_CREATED+=("ebs-volume:${VOLUME_ID}")
    else
        ok "  CreateVolume was denied by SCP (as expected -- encryption policy is enforced)"
        echo "  CloudTrail still logs the attempt with errorCode UnauthorizedOperation."
    fi
    echo "  Detection: UnencryptedResourceCreation (catches attempts regardless of outcome)"
    echo ""
}

# =============================================================================
# Scenario 4: Security Service Tampering
# Attempts to stop the Config configuration recorder.
# Expected to fail due to SCP -- but the ATTEMPT is logged in CloudTrail.
# Triggers: SecurityServiceTampering detection
# =============================================================================
run_scenario_4() {
    log "Scenario 4: Security Service Tampering"
    echo "  Attempts to stop the AWS Config configuration recorder."
    echo "  This is blocked by SCP but the attempt appears in CloudTrail."
    echo "  Simulates an attacker trying to blind security controls."
    echo ""

    set +e
    aws configservice stop-configuration-recorder \
        --configuration-recorder-name default \
        --region "${REGION}" 2>&1 | head -5
    RESULT=$?
    set -e

    if [[ $RESULT -ne 0 ]]; then
        ok "  Action was denied (as expected -- SCP is working)"
    else
        warn "  Action succeeded -- SCP may not be applied to this account"
    fi

    ok "  CloudTrail event: StopConfigurationRecorder (with errorcode AccessDenied)"
    echo "  Detection: SecurityServiceTampering (catches attempts regardless of outcome)"
    echo ""
}

# =============================================================================
# Scenario 5: Credential Exposure in API Call
# Creates an SSM parameter with 'password' in the name.
# Triggers: CredentialExposure detection
# =============================================================================
run_scenario_5() {
    log "Scenario 5: Credential Exposure in API Call"
    echo "  Creates an SSM parameter with 'password' in the parameter name."
    echo "  Simulates an application storing plaintext credentials in parameter paths."
    echo ""

    PARAM_NAME="/siem-sim/app/database-password-${TIMESTAMP}"

    aws ssm put-parameter \
        --name "${PARAM_NAME}" \
        --value "SIMULATED-NOT-A-REAL-PASSWORD-${TIMESTAMP}" \
        --type String \
        --region "${REGION}" \
        --description "SIEM simulation parameter -- delete after test" \
        --tags Key=SimulationTag,Value="${SIM_TAG}" \
        --output text > /dev/null

    ok "  Created SSM parameter: ${PARAM_NAME}"
    RESOURCES_CREATED+=("ssm-parameter:${PARAM_NAME}")
    echo "  Detection: CredentialExposure (requestparameters contains 'password')"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

case "${SCENARIO}" in
    1) run_scenario_1 ;;
    2) run_scenario_2 ;;
    3) run_scenario_3 ;;
    4) run_scenario_4 ;;
    5) run_scenario_5 ;;
    all)
        run_scenario_1
        run_scenario_2
        run_scenario_3
        run_scenario_4
        run_scenario_5
        ;;
    *)
        err "Unknown scenario: ${SCENARIO}. Use 1-5 or 'all'."
        exit 1
        ;;
esac

# Save resource manifest for undo script
MANIFEST_FILE="/tmp/siem-sim-manifest-${TIMESTAMP}.txt"
{
    echo "SIM_TAG=${SIM_TAG}"
    echo "TIMESTAMP=${TIMESTAMP}"
    echo "ACCOUNT_ID=${ACCOUNT_ID}"
    echo "REGION=${REGION}"
    for r in "${RESOURCES_CREATED[@]:-}"; do
        echo "RESOURCE=${r}"
    done
} > "${MANIFEST_FILE}"

# Automatically invoke the SIEM Lambda after CloudTrail delivery delay.
# Uses a 90-minute lookback to cover the full window from simulation
# start through CT delivery + Lambda runtime. Runs in the background
# so this script exits immediately.
(
    sleep 900
    if aws lambda invoke \
        --function-name siem-detector \
        --region "${REGION}" \
        --invocation-type Event \
        --cli-binary-format raw-in-base64-out \
        --payload '{"lookback_minutes": 90}' \
        "/tmp/siem-response-${TIMESTAMP}.json" > /dev/null 2>&1; then
        echo ""
        echo "[AUTO] SIEM Lambda triggered. Results will arrive via SNS email in ~5 minutes."
    else
        echo "[AUTO] Lambda invoke failed -- invoke manually with the command below."
    fi
) &
AUTO_PID=$!

echo "============================================================"
ok "Simulation complete. Detection auto-scheduled (PID ${AUTO_PID})."
echo ""
echo "Resources created (will be cleaned up by undo script):"
for r in "${RESOURCES_CREATED[@]:-}"; do
    echo "  - ${r}"
done
echo ""
echo "Manifest saved to: ${MANIFEST_FILE}"
echo ""
echo "The SIEM Lambda will auto-invoke in ~15 minutes (CloudTrail delivery delay)."
echo "Watch for an alert email from SNS."
echo ""
echo "To invoke manually with a custom lookback:"
echo ""
echo "     aws lambda invoke \\"
echo "       --function-name siem-detector \\"
echo "       --region ${REGION} \\"
echo "       --cli-binary-format raw-in-base64-out \\"
echo "       --payload '{\"lookback_minutes\": 90}' \\"
echo "       /tmp/siem-response.json && cat /tmp/siem-response.json"
echo ""
echo "Cleanup:"
echo "     ./siem-threat-simulation-undo.sh ${MANIFEST_FILE}"
echo "============================================================"
