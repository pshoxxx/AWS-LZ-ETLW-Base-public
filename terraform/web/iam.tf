# terraform/web/iam.tf

resource "aws_iam_role" "web_ssm" {
  name        = "web-server-ssm-role"
  description = "Allows web server EC2 instances to register with SSM"

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
    Name = "web-server-ssm-role"
  })
}

resource "aws_iam_role_policy_attachment" "web_ssm" {
  role       = aws_iam_role.web_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "web_ssm" {
  name = "web-server-ssm-profile"
  role = aws_iam_role.web_ssm.name

  tags = merge(local.common_tags, {
    Name = "web-server-ssm-profile"
  })
}
