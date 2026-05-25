# terraform/<account>/backend.tf
#
# The backend block is intentionally empty of configuration values.
# All values (bucket, key, region, etc.) are supplied at terraform init
# time by role-chaining-deploy.yaml via -backend-config flags.
#
# The bucket name is sourced from the TF_STATE_BUCKET Actions variable,
# which is written automatically by bootstrap-state-backend.yaml after the
# S3 bucket is created.
#
# State file layout in S3:
#   s3://terraform-state-<security-acct-id>/management/terraform.tfstate
#   s3://terraform-state-<security-acct-id>/security/terraform.tfstate
#   s3://terraform-state-<security-acct-id>/corporate/terraform.tfstate
#   s3://terraform-state-<security-acct-id>/networking/terraform.tfstate

terraform {
  backend "s3" {}
}