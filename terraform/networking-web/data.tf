data "terraform_remote_state" "networking" {
  backend = "s3"
  config = {
    bucket  = var.state_bucket_name
    key     = "networking/terraform.tfstate"
    region  = "us-west-1"
    encrypt = true
  }
}
