# terraform/management/cloudtrail_insights.tf
# =====================================================================
# CloudTrail Insights
#
# Enables anomaly detection on the org-cloudtrail trail for:
#   - ApiCallRateInsight: detects unusual spikes in API call volume
#   - ApiErrorRateInsight: detects unusual spikes in API error rates
#
# Insights findings are delivered to the same S3 bucket and prefix as
# the regular CloudTrail logs, under a separate /CloudTrail-Insight/
# subfolder. They also appear in the CloudTrail event history console.
#
# Cost: ~$0.35 per 100k events analyzed. At low API volumes this is
# negligible. Disable by setting insight_selector to [] if cost
# becomes a concern in a demo environment.
# =====================================================================

resource "aws_cloudtrail_event_data_store" "management_insights" {
  name = "management-insights-datastore"
  # multi_region_enabled cannot be true for Insights-type event data stores.
  # AWS constraint: Insights stores are single-region only.
  multi_region_enabled = false
  organization_enabled = true
  retention_period     = 90

  kms_key_id = data.terraform_remote_state.security.outputs.org_logs_cmk_arn

  advanced_event_selector {
    name = "ManagementInsightEvents"
    field_selector {
      field  = "eventCategory"
      equals = ["Insight"]
    }
  }

  tags = merge(local.common_tags, {
    Name = "management-insights-datastore"
  })

  lifecycle {
    # kms_key_id comes from security remote state; ignore prevents accidental
    # removal of encryption if security state is temporarily unavailable.
    ignore_changes = [kms_key_id]
  }
}
