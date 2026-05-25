# =====================================================================
# Cross-account CloudWatch observability links.
#
# The security workspace (terraform/security/observability.tf) creates
# the central OAM sink ("security-observability-sink") with a sink
# policy that accepts CreateLink requests from any account in this org.
#
# Each member account (networking, corporate, web) needs an
# aws_oam_link pointing at that sink for its CloudWatch metrics + log
# groups to surface in the security account's dashboards.
#
# Provisioning these from the management workspace lets one terraform
# apply create all three links via aliased providers (management is the
# org root, so it can assume OrganizationAccountAccessRole into any
# member). The sink ARN is discovered at apply time from security via
# the aliased security provider -- no TF outputs need to be threaded
# between workspaces.
#
# Ordering: deploy-management runs LAST in the pipeline, so by the time
# this resource applies, security's sink already exists.
# =====================================================================

# Discover the security-observability-sink ARN by listing sinks in the
# security account (via the aliased "security" provider).
data "aws_oam_sinks" "security" {
  provider = aws.security
}

# Resolve which of the returned ARNs is our sink by name. The data
# source returns ARNs only, so we need a per-ARN lookup to filter by
# name. With one sink expected per account this is a single iteration.
data "aws_oam_sink" "security" {
  provider    = aws.security
  for_each    = toset(data.aws_oam_sinks.security.arns)
  sink_identifier = each.value
}

locals {
  monitoring_sink_arns = [
    for arn, sink in data.aws_oam_sink.security :
    arn if sink.name == "security-observability-sink"
  ]

  # If security hasn't applied yet (sink not present), skip link creation.
  # Otherwise pick the one matching ARN.
  monitoring_sink_arn = length(local.monitoring_sink_arns) > 0 ? local.monitoring_sink_arns[0] : ""
}

resource "aws_oam_link" "networking" {
  count           = local.monitoring_sink_arn != "" ? 1 : 0
  provider        = aws.networking
  label_template  = "$AccountName"
  resource_types  = ["AWS::CloudWatch::Metric", "AWS::Logs::LogGroup"]
  sink_identifier = local.monitoring_sink_arn
}

resource "aws_oam_link" "corporate" {
  count           = local.monitoring_sink_arn != "" ? 1 : 0
  provider        = aws.corporate
  label_template  = "$AccountName"
  resource_types  = ["AWS::CloudWatch::Metric", "AWS::Logs::LogGroup"]
  sink_identifier = local.monitoring_sink_arn
}

resource "aws_oam_link" "web" {
  count           = local.monitoring_sink_arn != "" ? 1 : 0
  provider        = aws.web
  label_template  = "$AccountName"
  resource_types  = ["AWS::CloudWatch::Metric", "AWS::Logs::LogGroup"]
  sink_identifier = local.monitoring_sink_arn
}
