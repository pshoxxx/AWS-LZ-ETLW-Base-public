# =====================================================================
# Cross-account CloudWatch observability -- security is the monitoring hub
#
# The OAM sink here accepts metric + log shares from source accounts in
# the same organization (networking, corporate, web). Each source account
# creates an aws_oam_link pointing at this sink. Once linked, the
# CloudWatch dashboard below can reference metrics from any linked
# account via the widget's accountId parameter.
#
# Dashboard story: walks a reader sequentially through the hub-and-spoke
# data plane in the same order the architecture diagram does, so screen-
# shotting the dashboard gives an article-ready visual proof that every
# component is actually carrying traffic.
# =====================================================================

resource "aws_oam_sink" "central" {
  name = "security-observability-sink"

  tags = merge(local.common_tags, {
    Name = "security-observability-sink"
  })
}

resource "aws_oam_sink_policy" "central" {
  sink_identifier = aws_oam_sink.central.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["oam:CreateLink", "oam:UpdateLink"]
      Resource  = "*"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = data.aws_organizations_organization.org.id
        }
        "ForAllValues:StringEquals" = {
          "oam:ResourceTypes" = [
            "AWS::CloudWatch::Metric",
            "AWS::Logs::LogGroup",
          ]
        }
      }
    }]
  })
}

# Region-aware dashboard JSON. We use SEARCH() expressions so the
# dashboard works without knowing exact resource IDs at apply time --
# it picks up whatever exists in each linked account in this region.
locals {
  observability_region = data.aws_region.current.name

  dashboard_body = jsonencode({
    widgets = [
      # -----------------------------------------------------------------
      # Header row -- explains the dashboard's flow.
      # -----------------------------------------------------------------
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = <<-EOT
            ## Network Routing -- Traffic Traversal Evidence

            Each panel below corresponds to one architectural component in the order traffic flows through it.
            Sustained activity in every panel confirms the advertised hub-and-spoke routing is actually carrying load.

            **VPN tunnel** → **Transit Gateway** → **Network Firewall (internal / east-west)** → **NAT Gateway** → **Internet Gateway**
            and the parallel ingress path: **IGW** → **Network Firewall (external / north-south)** → **ALB** → **PrivateLink / NLB**
          EOT
        }
      },

      # -----------------------------------------------------------------
      # Layer 1 -- Site-to-Site VPN: hybrid leg.
      # -----------------------------------------------------------------
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 12
        height = 6
        properties = {
          title  = "1. Site-to-Site VPN -- Tunnel Data In/Out (hybrid leg)"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/VPN,VpnId} MetricName=\"TunnelDataIn\"', 'Sum', 60)", label = "Tunnel data in (on-prem → AWS)", id = "vpnIn" }],
            [{ expression = "SEARCH('{AWS/VPN,VpnId} MetricName=\"TunnelDataOut\"', 'Sum', 60)", label = "Tunnel data out (AWS → on-prem)", id = "vpnOut" }],
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 2
        width  = 12
        height = 6
        properties = {
          title  = "1b. Site-to-Site VPN -- Tunnel State (1=UP, 0=DOWN)"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Maximum"
          period = 60
          yAxis = {
            left = { min = 0, max = 1 }
          }
          metrics = [
            [{ expression = "SEARCH('{AWS/VPN,VpnId} MetricName=\"TunnelState\"', 'Maximum', 60)", label = "Tunnel state", id = "vpnState" }],
          ]
        }
      },

      # -----------------------------------------------------------------
      # Layer 2 -- Transit Gateway: hub.
      # -----------------------------------------------------------------
      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 12
        height = 6
        properties = {
          title  = "2. Transit Gateway -- Bytes In per Attachment"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/TransitGateway,TransitGateway} MetricName=\"BytesIn\"', 'Sum', 60)", label = "TGW BytesIn", id = "tgwIn" }],
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 8
        width  = 12
        height = 6
        properties = {
          title  = "2b. Transit Gateway -- Bytes Out per Attachment"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/TransitGateway,TransitGateway} MetricName=\"BytesOut\"', 'Sum', 60)", label = "TGW BytesOut", id = "tgwOut" }],
          ]
        }
      },

      # -----------------------------------------------------------------
      # Layer 3 -- Network Firewall: inspection.
      # -----------------------------------------------------------------
      {
        type   = "metric"
        x      = 0
        y      = 14
        width  = 12
        height = 6
        properties = {
          title  = "3. Network Firewall -- Received Packets per Firewall"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('Namespace=\"AWS/NetworkFirewall\" MetricName=\"ReceivedPackets\"', 'Sum', 60)", label = "Packets received", id = "nfRecv" }],
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 14
        width  = 12
        height = 6
        properties = {
          title  = "3b. Network Firewall -- Dropped vs Passed Packets"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('Namespace=\"AWS/NetworkFirewall\" MetricName=\"DroppedPackets\"', 'Sum', 60)", label = "Dropped", id = "nfDrop" }],
            [{ expression = "SEARCH('Namespace=\"AWS/NetworkFirewall\" MetricName=\"PassedPackets\"', 'Sum', 60)", label = "Passed", id = "nfPass" }],
          ]
        }
      },

      # -----------------------------------------------------------------
      # Layer 4 -- NAT Gateway: spoke egress.
      # -----------------------------------------------------------------
      {
        type   = "metric"
        x      = 0
        y      = 20
        width  = 12
        height = 6
        properties = {
          title  = "4. NAT Gateway -- Bytes Out (spoke → internet)"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/NATGateway,NatGatewayId} MetricName=\"BytesOutToDestination\"', 'Sum', 60)", label = "Bytes out to destination", id = "natOut" }],
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 20
        width  = 12
        height = 6
        properties = {
          title  = "4b. NAT Gateway -- Connection Attempts + Established (cumulative)"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/NATGateway,NatGatewayId} MetricName=\"ConnectionAttemptCount\"', 'Sum', 60)",     label = "Connection attempts",     id = "natAtt" }],
            [{ expression = "SEARCH('{AWS/NATGateway,NatGatewayId} MetricName=\"ConnectionEstablishedCount\"', 'Sum', 60)", label = "Connections established", id = "natEst" }],
          ]
        }
      },

      # -----------------------------------------------------------------
      # Layer 5 -- ALB: ingress chain.
      # -----------------------------------------------------------------
      {
        type   = "metric"
        x      = 0
        y      = 26
        width  = 12
        height = 6
        properties = {
          title  = "5. ALB -- Request Count (internet → ALB)"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/ApplicationELB,LoadBalancer} MetricName=\"RequestCount\"', 'Sum', 60)", label = "ALB requests", id = "albReq" }],
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 26
        width  = 12
        height = 6
        properties = {
          title  = "5b. ALB -- HTTP 2XX Responses (successful inbound)"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/ApplicationELB,LoadBalancer} MetricName=\"HTTPCode_Target_2XX_Count\"', 'Sum', 60)", label = "2XX responses", id = "alb2xx" }],
          ]
        }
      },

      # -----------------------------------------------------------------
      # Layer 6 -- NLB / PrivateLink: producer side of web spoke.
      # -----------------------------------------------------------------
      {
        type   = "metric"
        x      = 0
        y      = 32
        width  = 12
        height = 6
        properties = {
          title  = "6. NLB (PrivateLink producer) -- Processed Bytes"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Sum"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/NetworkELB,LoadBalancer} MetricName=\"ProcessedBytes\"', 'Sum', 60)", label = "NLB processed bytes", id = "nlbBytes" }],
          ]
        }
      },

      {
        type   = "metric"
        x      = 12
        y      = 32
        width  = 12
        height = 6
        properties = {
          title  = "6b. NLB -- Active Flow Count"
          view   = "timeSeries"
          region = local.observability_region
          stat   = "Average"
          period = 60
          metrics = [
            [{ expression = "SEARCH('{AWS/NetworkELB,LoadBalancer} MetricName=\"ActiveFlowCount\"', 'Average', 60)", label = "Active flows", id = "nlbFlow" }],
          ]
        }
      },
    ]
  })
}

resource "aws_cloudwatch_dashboard" "network_routing" {
  dashboard_name = "network-routing-traffic"
  dashboard_body = local.dashboard_body
}
