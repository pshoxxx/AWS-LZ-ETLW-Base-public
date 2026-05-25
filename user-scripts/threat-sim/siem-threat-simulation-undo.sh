#!/usr/bin/env bash
# =============================================================================
# siem-threat-simulation-undo.sh
#
# Cleans up all resources created by siem-threat-simulation.sh.
# Run this after verifying the SIEM detections triggered correctly.
#
# Usage:
#   ./siem-threat-simulation-undo.sh /tmp/siem-sim-manifest-TIMESTAMP.txt
#   ./siem-threat-simulation-undo.sh         # discovers most recent manifest
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[UNDO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }

# Resolve manifest file
if [[ $# -ge 1 && -f "$1" ]]; then
    MANIFEST_FILE="$1"
else
    # Find the most recent manifest
    MANIFEST_FILE=$(ls -t /tmp/siem-sim-manifest-*.txt 2>/dev/null | head -1 || echo "")
    if [[ -z "$MANIFEST_FILE" ]]; then
        err "No manifest file found. Pass the manifest path as an argument:"
        err "  ./siem-threat-simulation-undo.sh /tmp/siem-sim-manifest-TIMESTAMP.txt"
        exit 1
    fi
    log "Using most recent manifest: ${MANIFEST_FILE}"
fi

# Parse manifest
SIM_TAG=$(grep '^SIM_TAG=' "${MANIFEST_FILE}" | cut -d= -f2)
REGION=$(grep '^REGION=' "${MANIFEST_FILE}" | cut -d= -f2)
ACCOUNT_ID=$(grep '^ACCOUNT_ID=' "${MANIFEST_FILE}" | cut -d= -f2)
mapfile -t RESOURCES < <(grep '^RESOURCE=' "${MANIFEST_FILE}" | cut -d= -f2-)

echo ""
echo "============================================================"
echo "  SIEM Threat Simulation - UNDO"
echo "  Simulation: ${SIM_TAG}"
echo "  Account   : ${ACCOUNT_ID}"
echo "  Region    : ${REGION}"
echo "============================================================"
echo ""

ERRORS=0

for resource in "${RESOURCES[@]:-}"; do
    TYPE="${resource%%:*}"
    ID="${resource#*:}"

    case "${TYPE}" in
        iam-role)
            log "Removing IAM role: ${ID}"
            # Detach all managed policies first
            POLICIES=$(aws iam list-attached-role-policies \
                --role-name "${ID}" \
                --query "AttachedPolicies[].PolicyArn" \
                --output text 2>/dev/null || echo "")
            for policy_arn in ${POLICIES}; do
                aws iam detach-role-policy \
                    --role-name "${ID}" \
                    --policy-arn "${policy_arn}" && \
                    ok "  Detached ${policy_arn} from ${ID}" || \
                    warn "  Could not detach ${policy_arn}"
            done
            # Delete inline policies
            INLINE=$(aws iam list-role-policies \
                --role-name "${ID}" \
                --query "PolicyNames[]" \
                --output text 2>/dev/null || echo "")
            for policy_name in ${INLINE}; do
                aws iam delete-role-policy \
                    --role-name "${ID}" \
                    --policy-name "${policy_name}" 2>/dev/null || true
            done
            # Delete the role
            aws iam delete-role --role-name "${ID}" && \
                ok "  Deleted IAM role: ${ID}" || \
                { err "  Failed to delete IAM role: ${ID}"; ((ERRORS++)) || true; }
            ;;

        ebs-volume)
            log "Deleting EBS volume: ${ID}"
            # Check state before deleting
            STATE=$(aws ec2 describe-volumes \
                --volume-ids "${ID}" \
                --region "${REGION}" \
                --query "Volumes[0].State" \
                --output text 2>/dev/null || echo "not-found")
            if [[ "${STATE}" == "not-found" || "${STATE}" == "None" ]]; then
                warn "  Volume ${ID} not found -- already deleted"
            elif [[ "${STATE}" != "available" ]]; then
                err "  Volume ${ID} is in state '${STATE}' -- cannot delete"
                ((ERRORS++)) || true
            else
                aws ec2 delete-volume \
                    --volume-id "${ID}" \
                    --region "${REGION}" && \
                    ok "  Deleted EBS volume: ${ID}" || \
                    { err "  Failed to delete EBS volume: ${ID}"; ((ERRORS++)) || true; }
            fi
            ;;

        ssm-parameter)
            log "Deleting SSM parameter: ${ID}"
            aws ssm delete-parameter \
                --name "${ID}" \
                --region "${REGION}" && \
                ok "  Deleted SSM parameter: ${ID}" || \
                { err "  Failed to delete SSM parameter: ${ID}"; ((ERRORS++)) || true; }
            ;;

        *)
            warn "Unknown resource type '${TYPE}' for ID '${ID}' -- skipping"
            ;;
    esac
done

# Also sweep for any simulation-tagged resources not in the manifest
# (catches partial runs or resources created outside manifest tracking)
log "Sweeping for untracked simulation resources with tag: ${SIM_TAG}"

# IAM roles with simulation tag
TAGGED_ROLES=$(aws iam list-roles \
    --query "Roles[].RoleName" \
    --output text 2>/dev/null | tr '\t' '\n' | \
    while read -r role; do
        TAGS=$(aws iam list-role-tags --role-name "$role" \
            --query "Tags[?Key=='SimulationTag'].Value" \
            --output text 2>/dev/null || echo "")
        [[ "$TAGS" == "${SIM_TAG}" ]] && echo "$role" || true
    done || echo "")

for role in ${TAGGED_ROLES}; do
    if ! grep -q "iam-role:${role}" "${MANIFEST_FILE}" 2>/dev/null; then
        warn "  Found untracked role: ${role} -- cleaning up"
        POLICIES=$(aws iam list-attached-role-policies \
            --role-name "${role}" \
            --query "AttachedPolicies[].PolicyArn" \
            --output text 2>/dev/null || echo "")
        for p in ${POLICIES}; do
            aws iam detach-role-policy --role-name "${role}" --policy-arn "${p}" 2>/dev/null || true
        done
        aws iam delete-role --role-name "${role}" 2>/dev/null && \
            ok "  Deleted untracked role: ${role}" || true
    fi
done

# EBS volumes with simulation tag
TAGGED_VOLUMES=$(aws ec2 describe-volumes \
    --region "${REGION}" \
    --filters "Name=tag:SimulationTag,Values=${SIM_TAG}" \
    --query "Volumes[?State=='available'].VolumeId" \
    --output text 2>/dev/null || echo "")

for vol in ${TAGGED_VOLUMES}; do
    if ! grep -q "ebs-volume:${vol}" "${MANIFEST_FILE}" 2>/dev/null; then
        warn "  Found untracked volume: ${vol} -- cleaning up"
        aws ec2 delete-volume --volume-id "${vol}" --region "${REGION}" \
            2>/dev/null && ok "  Deleted: ${vol}" || true
    fi
done

# SSM parameters with simulation prefix
TAGGED_PARAMS=$(aws ssm describe-parameters \
    --region "${REGION}" \
    --parameter-filters "Key=tag:SimulationTag,Values=${SIM_TAG}" \
    --query "Parameters[].Name" \
    --output text 2>/dev/null || echo "")

for param in ${TAGGED_PARAMS}; do
    if ! grep -q "ssm-parameter:${param}" "${MANIFEST_FILE}" 2>/dev/null; then
        warn "  Found untracked SSM parameter: ${param} -- cleaning up"
        aws ssm delete-parameter --name "${param}" --region "${REGION}" \
            2>/dev/null && ok "  Deleted: ${param}" || true
    fi
done

echo ""
echo "============================================================"
if [[ ${ERRORS} -eq 0 ]]; then
    ok "Undo complete. All simulation resources removed."
else
    err "Undo complete with ${ERRORS} error(s). Check output above."
    echo "  Resources that failed to clean up may need manual removal."
fi

echo ""
echo "Security posture verification:"
echo "  1. Verify the IAM role is gone:"
echo "     aws iam get-role --role-name siem-sim-test-role-* 2>&1"
echo ""
echo "  2. Verify no unencrypted test volumes remain:"
echo "     aws ec2 describe-volumes --region ${REGION} \\"
echo "       --filters Name=tag:SimulationTag,Values=${SIM_TAG} \\"
echo "       --query 'Volumes[].{ID:VolumeId,State:State,Encrypted:Encrypted}'"
echo ""
echo "  3. Verify Config recorder is still running:"
echo "     aws configservice describe-configuration-recorder-status \\"
echo "       --region ${REGION}"
echo ""
echo "If you disabled EBS encryption controls for scenario 3:"
echo "  1. Uncomment DenyUnencryptedEBSVolumes and"
echo "     DenyRunInstancesWithUnencryptedVolumes in management_scps.tf"
echo "  2. Uncomment aws_ebs_encryption_by_default in each member account main.tf"
echo "  3. Push to main and redeploy to restore the SCP"
echo "============================================================"

# Remove manifest
rm -f "${MANIFEST_FILE}"
log "Manifest removed: ${MANIFEST_FILE}"
