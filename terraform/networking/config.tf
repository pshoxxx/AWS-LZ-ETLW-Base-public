# terraform/networking/config.tf

# =====================================================================
# AWS Config Service-Linked Role
# =====================================================================
# The SLR frequently pre-exists (created by a prior Config enablement or
# a previous deploy run whose apply was filtered). The native import block
# below idempotently imports it when found; if already in state Terraform
# skips the import silently.

import {
  to = aws_iam_service_linked_role.config
  id = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
}

resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"

  lifecycle {
    ignore_changes = all
  }
}

# =====================================================================
# Config Recorder
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
  count          = var.org_logs_bucket_exists ? 1 : 0
  name           = "default"
  s3_bucket_name = "org-logs-${local.security_account_id}-v2"
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  count      = var.org_logs_bucket_exists ? 1 : 0
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}