# terraform/networking/main.tf
# AZ data source + Network Firewall endpoint locals.
# Everything else is split into dedicated files.

data "aws_availability_zones" "available" {
  state = "available"
}

# Enforcing EBS Encryption by default - commented out for threat simulation script

# resource "aws_ebs_encryption_by_default" "main" {
#   enabled = true
# }

