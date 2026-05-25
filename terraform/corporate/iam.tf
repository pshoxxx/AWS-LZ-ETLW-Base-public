# terraform/corporate/iam.tf
# IAM role and instance profile granting the domain controller EC2
# instances the minimum permissions required for SSM Session Manager.

resource "aws_iam_role" "dc_ssm" {
  name        = "corporate-dc-ssm-role"
  description = "Allows EC2 domain controller instances to register with SSM"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "corporate-dc-ssm-role"
  })
}

resource "aws_iam_role_policy_attachment" "dc_ssm" {
  role       = aws_iam_role.dc_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "dc_ssm" {
  name = "corporate-dc-ssm-profile"
  role = aws_iam_role.dc_ssm.name

  tags = merge(local.common_tags, {
    Name = "corporate-dc-ssm-profile"
  })
}