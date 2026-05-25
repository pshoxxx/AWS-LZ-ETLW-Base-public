#!/usr/bin/env bash
set -euo pipefail

# Script: scripts/phase3-reconcile-vpn.sh
# Step: Reconcile Drifted TGW VPN Association
#
# Uses terraform state show (direct resource lookup) instead of
# state list | grep so the check is never fooled by a failed
# state list command returning no output.  Uses explicit exit-code
# capture (set +e) rather than grepping tee'd log files for
# error strings, which was unreliable against Unicode box-drawing
# characters in Terraform's diagnostic output.

# -- Step 1: is the association already in state? ----------------------
if terraform state show aws_ec2_transit_gateway_route_table_association.vpn \
    > /dev/null 2>&1; then
  echo "INFO: aws_ec2_transit_gateway_route_table_association.vpn is already in Terraform state -- skipping import."
  exit 0
fi

echo "Resource not in state -- reading attachment and route table IDs from state."

TF_JSON=$(terraform show -json 2>/dev/null || echo "{}")

ATTACH_ID=$(echo "$TF_JSON" | jq -r '
  try (
    .values.root_module.resources[]
    | select(.type == "aws_vpn_connection" and .name == "on_prem")
    | .values.transit_gateway_attachment_id
  ) // ""' 2>/dev/null || echo "")

RT_ID=$(echo "$TF_JSON" | jq -r '
  try (
    .values.root_module.resources[]
    | select(.type == "aws_ec2_transit_gateway_route_table" and .name == "spoke")
    | .values.id
  ) // ""' 2>/dev/null || echo "")

if [[ -z "$ATTACH_ID" || "$ATTACH_ID" == "null" || \
      -z "$RT_ID"     || "$RT_ID"     == "null" ]]; then
  echo "VPN connection or spoke route table not yet deployed -- nothing to import."
  exit 0
fi

echo "VPN attachment ID : $ATTACH_ID"
echo "Spoke RT ID       : $RT_ID"
echo "Import ID         : ${RT_ID}_${ATTACH_ID}"

# -- Step 2: attempt import --------------------------------------------
set +e
terraform import \
    -input=false \
    aws_ec2_transit_gateway_route_table_association.vpn \
    "${RT_ID}_${ATTACH_ID}"
TF_EXIT=$?
set -e

if [[ $TF_EXIT -eq 0 ]]; then
  echo "Import successful."
  exit 0
fi

# -- Step 3: import failed -- benign if the resource is now in state ---
# "Resource already managed by Terraform" can race with a concurrent
# apply that created the association between the state-list check above
# and the import call.  Verify by checking state directly.
if terraform state show aws_ec2_transit_gateway_route_table_association.vpn \
    > /dev/null 2>&1; then
  echo "INFO: Resource is already managed by Terraform (import raced with state) -- nothing to do."
  exit 0
fi

echo "::error::terraform import failed and aws_ec2_transit_gateway_route_table_association.vpn is not in state."
exit 1
