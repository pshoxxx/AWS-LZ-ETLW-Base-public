# terraform/management/providers.tf
#
# Default provider: the management account itself. The OIDC role assumed
# at the start of the workflow already authenticates as a management
# principal, so no role chaining is needed.
#
# Aliased providers (security/networking/corporate/web): the management
# account is the org root, so it can assume OrganizationAccountAccessRole
# in any member account by default. We use these aliases to provision
# cross-account resources (currently the OAM links pointing at the
# security observability sink) from a single management apply, avoiding
# the need to thread sink ARNs through multiple workspace boundaries.

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
}

provider "aws" {
  alias = "security"
  assume_role {
    role_arn     = "arn:aws:iam::${var.security_account_id}:role/OrganizationAccountAccessRole"
    session_name = "ManagementOAM-security"
  }
}

provider "aws" {
  alias = "networking"
  assume_role {
    role_arn     = "arn:aws:iam::${var.networking_account_id}:role/OrganizationAccountAccessRole"
    session_name = "ManagementOAM-networking"
  }
}

provider "aws" {
  alias = "corporate"
  assume_role {
    role_arn     = "arn:aws:iam::${var.corporate_account_id}:role/OrganizationAccountAccessRole"
    session_name = "ManagementOAM-corporate"
  }
}

provider "aws" {
  alias = "web"
  assume_role {
    role_arn     = "arn:aws:iam::${var.web_account_id}:role/OrganizationAccountAccessRole"
    session_name = "ManagementOAM-web"
  }
}