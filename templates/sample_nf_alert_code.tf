resource "aws_networkfirewall_rule_group" "stateful_egress_alert_observer" {
  capacity = 100
  name     = "stateful-egress-alert-observer"
  type     = "STATEFUL"

  rule_group {
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
      rules_string = <<-RULES
        alert tls $HOME_NET any -> any any (msg:"Spoke egress TLS observed"; flow:to_server,established; tls.sni; sid:900; rev:1;)
      RULES
    }
  }
}
