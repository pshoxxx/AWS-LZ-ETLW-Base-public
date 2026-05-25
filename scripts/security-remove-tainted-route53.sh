#!/usr/bin/env bash
set -euo pipefail

# Script: security-remove-tainted-route53.sh
# Step: Remove Tainted/Orphaned Route53 Resources Before Apply
#
# Handles three cases:
#
# 1. Tainted association — a previously failed association is still in state
#    as tainted. Removed so Terraform can recreate it cleanly.
#
# 2. Orphaned S3 query log config — if the destination was S3, the config
#    may have been created but the association failed (RSLVR-01306 because
#    the VPC already had an S3-type association from a prior untracked run).
#    Remove it from state so Terraform replaces it with the CWL config.
#
# 3. Untracked-in-AWS association — the security VPC already has a query log
#    association in AWS that Terraform doesn't know about (left over from a
#    prior deploy whose state was lost or never tracked it). Without this
#    cleanup, Terraform's create-association call fails with RSLVR-01306.
#    We discover the security VPC ID from state, list AWS-side associations
#    for that VPC, and disassociate any that aren't in TF state.

# -- Remove tainted associations ---------------------------------------

if terraform state list 2>/dev/null | grep -q "aws_route53_resolver_query_log_config_association"; then
  TAINTED=$(terraform state list 2>/dev/null \
    | grep "aws_route53_resolver_query_log_config_association" || echo "")
  for RESOURCE in $TAINTED; do
    STATUS=$(terraform show -json 2>/dev/null \
      | jq -r --arg addr "$RESOURCE" \
        '.values.root_module.resources[]
         | select(.address == $addr)
         | .tainted' 2>/dev/null || echo "false")
    if [[ "$STATUS" == "true" ]]; then
      echo "Removing tainted association from state: $RESOURCE"
      terraform state rm "$RESOURCE" 2>/dev/null || true
    else
      echo "Association is not tainted -- leaving in state: $RESOURCE"
    fi
  done
else
  echo "No Route53 query log config association in state -- nothing to do."
fi

# -- Remove orphaned S3 query log config -------------------------------
# If the config exists in state but points to S3 (not CloudWatch Logs),
# remove it so Terraform recreates it with the correct CWL destination.

if terraform state list 2>/dev/null | grep -q "aws_route53_resolver_query_log_config.security"; then
  DEST=$(terraform show -json 2>/dev/null \
    | jq -r '.values.root_module.resources[]
              | select(.address == "aws_route53_resolver_query_log_config.security")
              | .values.destination_arn' 2>/dev/null || echo "")
  if [[ "$DEST" == arn:aws:s3:::* ]]; then
    echo "Removing orphaned S3 query log config from state: aws_route53_resolver_query_log_config.security (destination: $DEST)"
    terraform state rm "aws_route53_resolver_query_log_config.security" 2>/dev/null || true
  else
    echo "Query log config destination is not S3 -- leaving in state: $DEST"
  fi
else
  echo "No Route53 query log config in state -- nothing to do."
fi

# -- Remove AWS-side associations not in TF state ---------------------
# Catches the RSLVR-01306 failure mode where the security VPC has an
# association in AWS that Terraform never tracked.

VPC_ID=$(terraform show -json 2>/dev/null \
  | jq -r '.values.root_module.resources[]
            | select(.address == "aws_vpc.main")
            | .values.id' 2>/dev/null || echo "")

if [[ -z "${VPC_ID}" || "${VPC_ID}" == "null" ]]; then
  echo "Security VPC not yet in state -- no AWS-side cleanup needed (first deploy)."
else
  echo "Checking for untracked AWS-side query log associations on VPC ${VPC_ID} ..."
  AWS_ASSOCS=$(aws route53resolver list-resolver-query-log-config-associations \
    --filters Name=ResourceId,Values="${VPC_ID}" \
    --query 'ResolverQueryLogConfigAssociations[].Id' \
    --output text 2>/dev/null || echo "")

  if [[ -z "${AWS_ASSOCS}" ]]; then
    echo "No AWS-side associations found for ${VPC_ID} -- nothing to cleanup."
  else
    # Build list of association IDs Terraform already tracks
    TF_ASSOC_IDS=$(terraform show -json 2>/dev/null \
      | jq -r '.values.root_module.resources[]
                | select(.type == "aws_route53_resolver_query_log_config_association")
                | .values.id' 2>/dev/null | tr '\n' ' ')

    for ASSOC_ID in ${AWS_ASSOCS}; do
      if echo " ${TF_ASSOC_IDS} " | grep -q " ${ASSOC_ID} "; then
        echo "Association ${ASSOC_ID} is tracked in TF state -- leaving alone."
      else
        echo "Disassociating untracked association ${ASSOC_ID} from ${VPC_ID} ..."
        aws route53resolver disassociate-resolver-query-log-config \
          --resolver-query-log-config-association-id "${ASSOC_ID}" >/dev/null 2>&1 \
          && echo "  Disassociated ${ASSOC_ID}." \
          || echo "  Could not disassociate ${ASSOC_ID} (may already be deleting)."
      fi
    done
  fi
fi
