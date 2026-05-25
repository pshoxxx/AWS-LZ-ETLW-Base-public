# terraform/bootstrap/variables.tf
variable "shared_services_account_id" {
  description = "AWS account ID of the shared-services account (used to name the state bucket and to form the OrganizationAccountAccessRole ARN)"
  type        = string
}