# terraform/security/iam.tf
# =====================================================================
# IAM resources for the security account.
#
# Note: this account contains no EC2 workloads. There is no SSM
# instance profile here -- security analysts access AWS resources via
# IAM Identity Center (SSO), not via domain-joined compute instances.
# The SIEM Lambda execution role is defined in siem_lambda.tf.
# =====================================================================
