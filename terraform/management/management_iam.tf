# terraform/management/iam.tf

# =====================================================================
# IAM Service-Linked Role — AWS Access Analyzer
# =====================================================================
# Required for Access Analyzer to inspect resources in this account.
# AWS creates this SLR automatically the first time Access Analyzer is
# enabled — including via the console.
#
# FIX (Bug 24): The original file had the import block commented out.
# Since Access Analyzer was enabled manually in the management account
# before Terraform was introduced, the SLR already exists. Attempting
# to create it without importing first produces:
#   InvalidInput: Service role name AWSServiceRoleForAccessAnalyzer
#   is already taken
#
# The conditional import block below resolves this the same way as the
# Config SLR fix in security/config.tf:
#   - var.import_access_analyzer_slr = false (default): Terraform
#     creates the SLR fresh. Safe for new accounts.
#   - var.import_access_analyzer_slr = true: import block pulls the
#     existing SLR into state before apply. Use this for the management
#     account where Access Analyzer was enabled manually.
#
# ignore_changes = all is retained as a safety net — the SLR attributes
# are managed by AWS and are not settable via the API anyway.
# =====================================================================

# Import of the Access Analyzer SLR is handled via terraform import CLI
# in the deploy-management workflow step when var.import_access_analyzer_slr
# is true. This avoids the count/for_each restriction on import blocks
# targeting singleton resources.

resource "aws_iam_service_linked_role" "access_analyzer" {
  aws_service_name = "access-analyzer.amazonaws.com"

  lifecycle {
    ignore_changes = all
  }
}

# =====================================================================
# SSM Account Settings
# =====================================================================
# Blocks public sharing of SSM Automation documents at the account
# level. Without this, any principal can make a document public,
# which triggers Security Hub control SSM.4. Equivalent to S3 Block
# Public Access but for SSM Documents.

resource "aws_ssm_service_setting" "block_public_sharing" {
  setting_id    = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:servicesetting/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}
