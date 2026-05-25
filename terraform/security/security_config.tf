# terraform/security/config.tf

# =====================================================================
# IAM Service-Linked Role — AWS Config Recorder
# =====================================================================
# AWS deprecated and removed the AWSConfigRole managed policy.
# The service-linked role replaces it and carries all required
# permissions (S3 delivery, KMS, etc.) automatically.
#
# FIX (Bug 13): Added a conditional import block for the SLR.
#
# The SLR is created automatically by AWS the first time Config is
# enabled in an account — including via the console. If it already
# exists when Terraform runs, the aws_iam_service_linked_role create
# call fails with:
#   InvalidInput: Service role name AWSServiceRoleForConfig is already taken
#
# The conditional import block resolves this:
#   - var.import_config_slr = false (default): no import, Terraform
#     creates the SLR fresh. Safe for brand-new accounts.
#   - var.import_config_slr = true: import block fires and pulls the
#     existing SLR into state before apply. Use this for the security
#     account where Config was enabled manually.
#
# The ignore_changes = all lifecycle rule is retained as a safety net —
# it prevents Terraform from attempting to modify SLR attributes that
# AWS manages and that are not settable via the API anyway.
# =====================================================================

# Import handling for the Config SLR is done via terraform import CLI in
# the deploy-member-accounts workflow step, which runs after terraform init
# and checks whether the SLR exists before importing. This avoids the
# count/for_each restriction on import blocks targeting singleton resources.

resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"

  lifecycle {
    ignore_changes = all
  }
}

# =====================================================================
# Config Recorder — us-west-1
# =====================================================================

resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.org_logs.id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# =====================================================================
# IAM Role — Organization Aggregator
# =====================================================================

resource "aws_iam_role" "config_aggregator" {
  name = "aws-config-aggregator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config_aggregator" {
  role       = aws_iam_role.config_aggregator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

# =====================================================================
# Organization Aggregator — us-west-1 only
# Matches the active SCP region lock.
# =====================================================================

resource "aws_config_configuration_aggregator" "org" {
  name = "org-aggregator"

  organization_aggregation_source {
    regions  = ["us-west-1"]
    role_arn = aws_iam_role.config_aggregator.arn
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy_attachment.config_aggregator]
}
