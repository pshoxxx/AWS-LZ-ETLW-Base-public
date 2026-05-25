#!/usr/bin/env bash
set -euo pipefail

# Script: scripts/networking-capture-outputs.sh
# Captures networking Terraform outputs and writes them to GITHUB_OUTPUT
# for consumption by deploy-member-accounts and deploy-networking-phase3.
# Falls back to AWS CLI (via networking account role) if terraform output
# is unavailable.
#
# Uses `terraform output -json` rather than `-raw` to avoid capturing
# multiline diagnostic text on stdout when the state file is empty.

REGION="${AWS_DEFAULT_REGION}"

# One call - parse all needed values from the JSON object.
TF_OUTPUTS=$(terraform output -json 2>/dev/null || echo "{}")

TGW_ID=$(echo "$TF_OUTPUTS" | jq -r '.transit_gateway_id.value // ""' 2>/dev/null || echo "")
DNS_FW_ARN=$(echo "$TF_OUTPUTS" | jq -r '.dns_firewall_rule_group_arn.value // ""' 2>/dev/null || echo "")
DNS_FW_ID=$(echo "$TF_OUTPUTS" | jq -r '.dns_firewall_rule_group_id.value // ""' 2>/dev/null || echo "")

if [[ -z "$TGW_ID" ]]; then
  echo "INFO: terraform output empty for transit_gateway_id -- falling back to AWS CLI"
  NET_CREDS=$(aws sts assume-role \
    --role-arn "arn:aws:iam::${IMPORT_NETWORKING_ACCOUNT_ID}:role/OrganizationAccountAccessRole" \
    --role-session-name "GitHubActions-CaptureOutputs" \
    --output json 2>/dev/null || echo "{}")
  TGW_ID=$(AWS_ACCESS_KEY_ID=$(echo "$NET_CREDS" | jq -r '.Credentials.AccessKeyId // empty') \
    AWS_SECRET_ACCESS_KEY=$(echo "$NET_CREDS" | jq -r '.Credentials.SecretAccessKey // empty') \
    AWS_SESSION_TOKEN=$(echo "$NET_CREDS" | jq -r '.Credentials.SessionToken // empty') \
    aws ec2 describe-transit-gateways \
      --region "$REGION" \
      --filters "Name=state,Values=available" \
      --query "TransitGateways[?Tags[?Key=='Name'&&contains(Value,'networking')]].TransitGatewayId|[0]" \
      --output text 2>/dev/null || echo "")
  [[ "$TGW_ID" == "None" ]] && TGW_ID=""
fi

if [[ -z "$DNS_FW_ARN" ]]; then
  echo "INFO: terraform output empty for dns_firewall_rule_group_arn -- falling back to AWS CLI"
  NET_CREDS=$(aws sts assume-role \
    --role-arn "arn:aws:iam::${IMPORT_NETWORKING_ACCOUNT_ID}:role/OrganizationAccountAccessRole" \
    --role-session-name "GitHubActions-CaptureOutputs-DNS" \
    --output json 2>/dev/null || echo "{}")
  DNS_FW_ARN=$(AWS_ACCESS_KEY_ID=$(echo "$NET_CREDS" | jq -r '.Credentials.AccessKeyId // empty') \
    AWS_SECRET_ACCESS_KEY=$(echo "$NET_CREDS" | jq -r '.Credentials.SecretAccessKey // empty') \
    AWS_SESSION_TOKEN=$(echo "$NET_CREDS" | jq -r '.Credentials.SessionToken // empty') \
    aws route53resolver list-firewall-rule-groups \
      --region "$REGION" \
      --query "FirewallRuleGroups[?Name=='org-baseline-dns-firewall'].Arn|[0]" \
      --output text 2>/dev/null || echo "")
  [[ "$DNS_FW_ARN" == "None" ]] && DNS_FW_ARN=""
  DNS_FW_ID=$(echo "$DNS_FW_ARN" | awk -F'/' '{print $NF}')
fi

[[ -z "$TGW_ID" ]] && echo "::warning::transit_gateway_id could not be resolved."
[[ -z "$DNS_FW_ARN" ]] && echo "::warning::dns_firewall_rule_group_arn could not be resolved."

echo "transit_gateway_id=${TGW_ID}" >> "$GITHUB_OUTPUT"
echo "dns_firewall_rule_group_arn=${DNS_FW_ARN}" >> "$GITHUB_OUTPUT"
echo "dns_firewall_rule_group_id=${DNS_FW_ID}" >> "$GITHUB_OUTPUT"

echo "Networking outputs captured:"
echo "  transit_gateway_id:          ${TGW_ID}"
echo "  dns_firewall_rule_group_arn: ${DNS_FW_ARN}"
echo "  dns_firewall_rule_group_id:  ${DNS_FW_ID}"
