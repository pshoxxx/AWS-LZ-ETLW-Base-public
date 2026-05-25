# terraform/networking/dns_firewall.tf
# =====================================================================
# Route 53 DNS Firewall - baseline rule group created here and shared
# via RAM (see ram.tf) to spoke accounts. Spoke accounts associate
# the rule group with their VPCs via a single resource in their own
# Terraform (aws_route53_resolver_firewall_rule_group_association).
#
# Rule evaluation order (lower priority = first):
#   100  AWS Managed: aggregate threat list  BLOCK NXDOMAIN  (always active)
#   200  Custom org block list               BLOCK NXDOMAIN  (when var non-empty)
#   300  Alert-only list                     ALERT           (when var non-empty)
#
# FIX (Bug 11): The AWS API rejects CreateFirewallDomainList with an
# empty domains list (ValidationException). The two custom domain list
# resources and their associated rules are now conditional on the
# relevant input variable being non-empty. The rule group itself and
# the AWS managed aggregate threat list rule are always created — they
# have no dependency on user-supplied domain lists.
#
# To populate the lists after initial deploy, add domains to the
# relevant tfvars variables and re-apply. Terraform will create the
# domain list and rule resources at that point.
#
# AWS managed domain list IDs are region-specific. Retrieve with:
#   aws route53resolver list-firewall-domain-lists --region <region> \
#     --query 'FirewallDomainLists[?contains(Name,`AWSManaged`)].{Name:Name,Id:Id}'
# =====================================================================

# -- Baseline Rule Group ----------------------------------------------
# Always created. This is the resource whose ARN is shared via RAM and
# referenced by spoke VPC associations. It must exist even when no
# custom domain lists are configured.

resource "aws_route53_resolver_firewall_rule_group" "baseline" {
  name = "org-baseline-dns-firewall"

  tags = merge(local.common_tags, {
    Name = "org-baseline-dns-firewall"
  })
}

# -- AWS Managed Aggregate Threat List Rule ---------------------------
# Always active. Blocks queries matching AWS-curated malware, botnet,
# and threat indicator domains. No custom domain list required.

resource "aws_route53_resolver_firewall_rule" "block_aggregate" {
  name                    = "block-aws-managed-aggregate"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = var.aws_managed_domain_list_aggregate_id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.baseline.id
  priority                = 100
}

# -- Custom Block Domain List -----------------------------------------
# FIX (Bug 11): conditional on var.dns_firewall_blocked_domains being
# non-empty. AWS rejects CreateFirewallDomainList with an empty list.
# Set dns_firewall_blocked_domains in tfvars to activate this rule.

resource "aws_route53_resolver_firewall_domain_list" "custom_block" {
  count   = length(var.dns_firewall_blocked_domains) > 0 ? 1 : 0
  name    = "org-custom-block-list"
  domains = var.dns_firewall_blocked_domains

  tags = merge(local.common_tags, {
    Name = "org-custom-block-list"
  })
}

resource "aws_route53_resolver_firewall_rule" "block_custom" {
  count                   = length(var.dns_firewall_blocked_domains) > 0 ? 1 : 0
  name                    = "block-org-custom-list"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.custom_block[0].id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.baseline.id
  priority                = 200
}

# -- Alert-Only Domain List -------------------------------------------
# FIX (Bug 11): conditional on var.dns_firewall_alert_domains being
# non-empty. ALERT passes the query through but logs the match — useful
# for visibility on suspicious domains before committing to a block.
# Set dns_firewall_alert_domains in tfvars to activate this rule.

resource "aws_route53_resolver_firewall_domain_list" "alert_only" {
  count   = length(var.dns_firewall_alert_domains) > 0 ? 1 : 0
  name    = "org-alert-only-list"
  domains = var.dns_firewall_alert_domains

  tags = merge(local.common_tags, {
    Name = "org-alert-only-list"
  })
}

resource "aws_route53_resolver_firewall_rule" "alert_suspicious" {
  count                   = length(var.dns_firewall_alert_domains) > 0 ? 1 : 0
  name                    = "alert-suspicious-domains"
  action                  = "ALERT"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.alert_only[0].id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.baseline.id
  priority                = 300
}
