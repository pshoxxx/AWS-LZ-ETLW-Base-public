terraform {
  backend "s3" {
    key          = "networking-web/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
