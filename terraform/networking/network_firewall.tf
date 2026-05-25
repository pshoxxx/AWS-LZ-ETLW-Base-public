# terraform/networking/network_firewall.tf
# =====================================================================
# AWS Network Firewall - one endpoint per AZ in the firewall subnets.
#
# Policy:
#   Stateless: forward TCP/UDP/ICMP to stateful; drop fragments
#   Stateful:  custom egress domain allowlist
#
# AWS managed threat intel rule groups (ThreatSignaturesIOC etc.) have
# been removed. Neither the StrictOrder nor the standard variants of
# these groups are available in us-west-1, causing
# InvalidRequestException: Resource ARN has an invalid format on policy
# create. The egress domain allowlist provides the primary control --
# all outbound HTTP/HTTPS is blocked unless the destination matches
# var.allowed_egress_domains. Managed groups can be added back if the
# deployment region is changed to one that carries them (e.g. us-west-2).
#
# Logs (FLOW + ALERT) -> S3 in Security account.
# =====================================================================

# -- Stateless Rule Group ---------------------------------------------

resource "aws_networkfirewall_rule_group" "stateless_forward" {
  capacity = 100
  name     = "stateless-forward-to-stateful"
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        # With symmetric NF routing (ingress NF endpoints sit on both the
        # internet->ALB and ALB->internet legs of the flow), stateful
        # connection tracking handles the full TCP handshake correctly,
        # so the prior asymmetric stateless-pass workaround for port 80
        # is no longer needed. All TCP/UDP/ICMP forward to the stateful
        # engine for inspection.
        stateless_rule {
          priority = 10
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              protocols = [6] # TCP
              source { address_definition = "0.0.0.0/0" }
              destination { address_definition = "0.0.0.0/0" }
            }
          }
        }
        stateless_rule {
          priority = 20
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              protocols = [17] # UDP
              source { address_definition = "0.0.0.0/0" }
              destination { address_definition = "0.0.0.0/0" }
            }
          }
        }
        stateless_rule {
          priority = 30
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              protocols = [1] # ICMP
              source { address_definition = "0.0.0.0/0" }
              destination { address_definition = "0.0.0.0/0" }
            }
          }
        }
      }
    }
  }

  tags = merge(local.common_tags, {
    Name = "stateless-forward-to-stateful"
  })
}

# -- Stateful Rule Group - Egress Domain Allowlist --------------------
# All outbound HTTP/HTTPS is blocked unless the destination matches
# var.allowed_egress_domains (HTTP_HOST header + TLS SNI).

resource "aws_networkfirewall_rule_group" "stateful_egress_allowlist" {
  capacity = 1000
  name     = "stateful-egress-domain-allowlist"
  type     = "STATEFUL"

  rule_group {
    # HOME_NET must include every CIDR that originates inspected egress.
    # The Suricata rules AWS generates from the ALLOWLIST rule group use
    # $HOME_NET as the source variable. By default, HOME_NET is set to
    # the CIDR of the VPC where Network Firewall is deployed -- the egress
    # VPC in this architecture. Spoke-originated traffic (10.1/10.2/10.3/
    # 10.4.x.x arriving via TGW with the spoke as source IP) would not
    # match the default HOME_NET, so the allowlist's generated rules
    # would never evaluate against it and the flow would fall through to
    # the firewall policy's aws:drop_strict default -- defeating the
    # purpose of the allowlist for centrally-inspected hub-and-spoke
    # egress.
    #
    # Including every spoke CIDR (plus on-prem) ensures the allowlist
    # actually evaluates every flow, consistent with the architecture's
    # "all traffic centrally inspected, nothing bypassed" posture.
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set {
          definition = [
            var.egress_vpc_cidr,
            var.corporate_vpc_cidr,
            var.security_vpc_cidr,
            var.management_vpc_cidr,
            var.web_vpc_cidr,
            var.on_prem_subnet_cidr,
          ]
        }
      }
    }

    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets              = var.allowed_egress_domains
      }
    }
  }

  tags = merge(local.common_tags, {
    Name = "stateful-egress-domain-allowlist"
  })
}

# -- Stateful Rule Group - Internal Traffic Pass ----------------------
# All spoke<->spoke and spoke<->on-prem traffic is passed at priority 1
# before the domain allowlist is evaluated. Without this, internal
# protocols (Kerberos, LDAP, SMB, DNS between DCs) would not match the
# HTTP_HOST/TLS_SNI domain allowlist and would be dropped by the strict
# default action. IP-level pass rules keep enforcement focused on
# internet egress, where the domain allowlist is meaningful.
#
# sid:200/201: HTTP traffic to/from the ALB ingress subnets. Bidirectional
# (<>) because with symmetric NF routing the stateful engine sees both
# the client->ALB SYN and the ALB->client SYN-ACK on the ingress NF
# endpoint, so connection tracking works correctly.

resource "aws_networkfirewall_rule_group" "stateful_internal_pass" {
  capacity = 100
  name     = "stateful-internal-pass"
  type     = "STATEFUL"

  rule_group {
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      rules_string = <<-RULES
        pass ip ${var.security_vpc_cidr} any <> ${var.corporate_vpc_cidr} any (sid:100; rev:1;)
        pass ip ${var.security_vpc_cidr} any <> ${var.on_prem_subnet_cidr} any (sid:101; rev:1;)
        pass ip ${var.corporate_vpc_cidr} any <> ${var.on_prem_subnet_cidr} any (sid:102; rev:1;)
        pass ip ${var.management_vpc_cidr} any <> ${var.corporate_vpc_cidr} any (sid:103; rev:1;)
        pass tcp any any <> ${var.egress_alb_subnet_cidrs[0]} 80 (sid:200; rev:1;)
        pass tcp any any <> ${var.egress_alb_subnet_cidrs[1]} 80 (sid:201; rev:1;)
      RULES
    }
  }

  tags = merge(local.common_tags, {
    Name = "stateful-internal-pass"
  })
}

# -- Firewall Policy --------------------------------------------------

resource "aws_networkfirewall_firewall_policy" "main" {
  name = "hub-firewall-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:drop"]

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    # Drop any ESTABLISHED packet that isn't explicitly passed by a
    # stateful rule. The "_established" suffix (vs "_strict") is required
    # for the TLS_SNI / HTTP_HOST allowlist to function: the allowlist's
    # generated Suricata rules inspect the SNI extension in the TLS
    # Client Hello, which only arrives AFTER the TCP handshake completes.
    # With aws:drop_strict, the SYN itself would be dropped (no setup
    # rule matches it), preventing the handshake from ever happening
    # and rendering the allowlist unreachable. aws:drop_established
    # allows the TCP setup packets through, lets the allowlist evaluate
    # the SNI on Client Hello, and drops the now-established connection
    # if the domain isn't allowlisted -- identical enforcement outcome,
    # just at a layer where SNI is visible.
    stateful_default_actions = ["aws:drop_established"]

    stateless_rule_group_reference {
      priority     = 10
      resource_arn = aws_networkfirewall_rule_group.stateless_forward.arn
    }

    # Priority 1: pass all spoke<->spoke and spoke<->on-prem traffic.
    stateful_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.stateful_internal_pass.arn
    }

    # Priority 2: allow outbound HTTP/HTTPS to safelisted domains only.
    # Everything else falls through to the drop_strict default.
    stateful_rule_group_reference {
      priority     = 2
      resource_arn = aws_networkfirewall_rule_group.stateful_egress_allowlist.arn
    }
  }

  tags = merge(local.common_tags, {
    Name = "hub-firewall-policy"
  })
}

# -- Firewalls --------------------------------------------------------
# AWS Network Firewall constraint: a single firewall resource can map
# only one endpoint per Availability Zone. We deploy two firewall
# resources -- split by TRAFFIC CLASS, not by direction:
#
#   external (north-south)  --  web ALB inbound from internet + return
#   internal (east-west + spoke egress)  --  spoke<->on-prem (VPN/AD),
#       spoke<->spoke, spoke->internet via NAT
#
# The internal firewall mirrors the May 2026 single-NF layout that AD
# replication is known to work against. The external firewall is purely
# additive for the web spoke's ALB ingress path. Both share the same
# firewall policy.

resource "aws_networkfirewall_firewall" "external" {
  name                = "hub-network-firewall-external"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.egress.id

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall_external[*].id
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = merge(local.common_tags, {
    Name = "hub-network-firewall-external"
  })
}

resource "aws_networkfirewall_firewall" "internal" {
  name                = "hub-network-firewall-internal"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.egress.id

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall_internal[*].id
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = merge(local.common_tags, {
    Name = "hub-network-firewall-internal"
  })
}

# -- Logging ----------------------------------------------------------
# Apply the same logging configuration to both firewalls so external
# (north-south) and internal (east-west + spoke egress) flow/alert
# events both land in the security account log bucket under
# clearly-distinguished prefixes.

resource "aws_networkfirewall_logging_configuration" "external" {
  count        = var.org_logs_bucket_exists ? 1 : 0
  firewall_arn = aws_networkfirewall_firewall.external.arn

  logging_configuration {
    log_destination_config {
      log_destination_type = "S3"
      log_type             = "FLOW"
      log_destination = {
        bucketName = var.security_log_bucket_name
        prefix     = "network-firewall/external/flow"
      }
    }
    log_destination_config {
      log_destination_type = "S3"
      log_type             = "ALERT"
      log_destination = {
        bucketName = var.security_log_bucket_name
        prefix     = "network-firewall/external/alert"
      }
    }
  }
}

resource "aws_networkfirewall_logging_configuration" "internal" {
  count        = var.org_logs_bucket_exists ? 1 : 0
  firewall_arn = aws_networkfirewall_firewall.internal.arn

  logging_configuration {
    log_destination_config {
      log_destination_type = "S3"
      log_type             = "FLOW"
      log_destination = {
        bucketName = var.security_log_bucket_name
        prefix     = "network-firewall/internal/flow"
      }
    }
    log_destination_config {
      log_destination_type = "S3"
      log_type             = "ALERT"
      log_destination = {
        bucketName = var.security_log_bucket_name
        prefix     = "network-firewall/internal/alert"
      }
    }
  }
}
