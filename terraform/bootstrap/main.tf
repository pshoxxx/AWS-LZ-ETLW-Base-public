# terraform/bootstrap/main.tf
#
# Creates the S3 bucket used as the remote backend by all
# other Terraform configurations in this repository.
#
# IMPORTANT: This configuration uses LOCAL state intentionally.
# It cannot use a remote backend because it is the thing that creates the
# remote backend. All resources carry prevent_destroy = true so a re-run
# can never accidentally destroy the backend out from under active state files.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # No backend block -- local state is correct and intentional here.
}

provider "aws" {
  # Assumes OrganizationAccountAccessRole in the shared-services account so
  # all resources are created there, keeping CI/CD tooling isolated from
  # workload accounts.
  assume_role {
    role_arn     = "arn:aws:iam::${var.shared_services_account_id}:role/OrganizationAccountAccessRole"
    session_name = "GitHubActions-Bootstrap"
  }
}

# Looks up the org ID automatically -- no variable or secret needed.
# OrganizationAccountAccessRole (AdministratorAccess) in a member account
# has permission to call organizations:DescribeOrganization.
data "aws_organizations_organization" "current" {}

locals {
  # Scoping the name to the shared-services account ID makes it globally
  # unique without a random suffix and keeps the name deterministic across runs.
  state_bucket_name = "terraform-state-${var.shared_services_account_id}"
}

# -- S3 Bucket ---------------------------------------------------------------

resource "aws_s3_bucket" "terraform_state" {
  bucket = local.state_bucket_name

  tags = {
    Name    = "terraform-state"
    Purpose = "Remote state for all AWS Organization Terraform configurations"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      # AES256 is used deliberately. The org-wide KMS CMK lives in the
      # security account's own state file -- using it here would create a
      # chicken-and-egg dependency on first apply.
      sse_algorithm = "AES256"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_policy" "terraform_state" {
  bucket     = aws_s3_bucket.terraform_state.id
  depends_on = [aws_s3_bucket_public_access_block.terraform_state]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Deny any non-TLS request regardless of caller
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      # Allow any IAM principal that belongs to the AWS Organization to
      # read and write state. Each account's IAM policies still gate
      # which roles can actually assume those permissions.
      {
        Sid       = "AllowOrgTerraformRoles"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
          }
        }
      },
      # Allow the GitHub-OIDC role in any org account to read and write state
      # directly without role-chaining. The ArnLike wildcard covers all current
      # and future accounts automatically -- no per-account secrets or variables
      # are needed. The PrincipalOrgID condition ensures the wildcard is always
      # constrained to principals inside this organisation.
      {
        Sid       = "AllowOrgGitHubOIDCRoles"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ]
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
          }
          ArnLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:role/GitHub-OIDC"
          }
        }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

# -- Outputs -----------------------------------------------------------------

output "state_bucket_name" {
  description = "S3 bucket name -- consumed by bootstrap workflow to set TF_STATE_BUCKET Actions variable"
  value       = aws_s3_bucket.terraform_state.id
}

