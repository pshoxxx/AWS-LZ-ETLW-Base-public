# terraform/web/main.tf
# =====================================================================
# Web Spoke - VPC, subnets, NLB, EC2 web servers, VPC Endpoint Service
#
# Traffic flow (inbound):
#   Internet → ALB (networking egress VPC) → VPC Endpoint (networking)
#       → PrivateLink → NLB (web private subnets) → EC2
#
# Traffic flow (outbound / egress):
#   EC2 → TGW → Network Firewall (networking) → NAT → Internet
#
# DNS:
#   EC2 resolver → DNS Firewall rule group (shared via RAM)
# =====================================================================

locals {
  vpc_resolver_ip = cidrhost(var.vpc_cidr, 2)

  dns_firewall_rule_group_id = element(
    split("/", var.dns_firewall_rule_group_arn),
    length(split("/", var.dns_firewall_rule_group_arn)) - 1
  )
}

# -- VPC ---------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "web-vpc"
  })
}

# -- Subnets -----------------------------------------------------------

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "web-private-${count.index + 1}"
  })
}

resource "aws_subnet" "tgw_attachment" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.tgw_attachment_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "web-tgw-${count.index + 1}"
  })
}

# -- Route Tables ------------------------------------------------------

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "web-private-rt"
  })
}

# Egress: EC2 → TGW → Network Firewall → NAT → Internet.
resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# TGW attachment subnets use the same private route table.
resource "aws_route_table_association" "tgw" {
  count          = 2
  subnet_id      = aws_subnet.tgw_attachment[count.index].id
  route_table_id = aws_route_table.private.id
}

# -- TGW Attachment ----------------------------------------------------

resource "aws_ec2_transit_gateway_vpc_attachment" "main" {
  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.main.id
  subnet_ids         = aws_subnet.tgw_attachment[*].id

  tags = merge(local.common_tags, {
    Name = "web-tgw-attachment"
  })
}

# -- DNS Firewall Association ------------------------------------------

resource "aws_route53_resolver_firewall_rule_group_association" "baseline" {
  name                   = "web-baseline-dns-firewall"
  firewall_rule_group_id = local.dns_firewall_rule_group_id
  vpc_id                 = aws_vpc.main.id
  priority               = 101

  tags = merge(local.common_tags, {
    Name = "web-baseline-dns-firewall"
  })
}

# -- Security Groups ---------------------------------------------------

resource "aws_security_group" "web" {
  name        = "web-server-sg"
  description = "Web servers - HTTP from NLB (VPC CIDR), egress via TGW"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from NLB nodes (preserve_client_ip disabled)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "All outbound (TGW / Network Firewall / NAT)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "web-server-sg"
  })
}

resource "aws_security_group" "nlb" {
  name        = "web-nlb-sg"
  description = "NLB - HTTP from PrivateLink endpoint service"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from PrivateLink"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "web-nlb-sg"
  })
}

resource "aws_security_group" "aurora" {
  name        = "web-aurora-sg"
  description = "Aurora Serverless v2 - MySQL from web servers only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "MySQL from web servers"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  tags = merge(local.common_tags, {
    Name = "web-aurora-sg"
  })
}

resource "aws_security_group" "ssm_endpoints" {
  name        = "web-ssm-endpoints-sg"
  description = "Allow HTTPS from VPC to SSM interface endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "HTTPS responses to VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(local.common_tags, {
    Name = "web-ssm-endpoints-sg"
  })
}

# -- SSM Interface Endpoints -------------------------------------------
# Keeps SSM traffic off the public internet regardless of firewall rules.

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "web-ssm-endpoint"
  })
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "web-ssmmessages-endpoint"
  })
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "web-ec2messages-endpoint"
  })
}

# -- EC2 Web Servers ---------------------------------------------------

resource "aws_instance" "web" {
  count                  = 2
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.web_instance_type
  subnet_id              = aws_subnet.private[count.index].id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.web_ssm.name

  user_data = base64encode(file("${path.module}/userdata.sh"))

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    delete_on_termination = true

    tags = merge(local.common_tags, {
      Name = "web-server-${count.index + 1}-root"
    })
  }

  lifecycle {
    ignore_changes = [user_data, ami]
  }

  depends_on = [aws_route.private_default]

  tags = merge(local.common_tags, {
    Name = "web-server-${count.index + 1}"
    Role = "WebServer"
  })
}

# -- Internal NLB + VPC Endpoint Service (PrivateLink) -----------------
# The ALB lives in the networking account. It reaches the EC2s here via
# a VPC Endpoint (consumer) → VPC Endpoint Service (producer, this NLB).
# NLB source IP preservation is disabled so EC2 SG can allow from the
# VPC CIDR instead of the networking account's CIDR.

resource "aws_lb" "nlb" {
  name_prefix                      = "webnlb"
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = aws_subnet.private[*].id
  enable_cross_zone_load_balancing = true
  security_groups                  = [aws_security_group.nlb.id]

  lifecycle {
    # create_before_destroy ensures the new NLB exists and the endpoint
    # service is updated to the new ARN before the old NLB is deleted.
    # Without this, AWS rejects the delete with ResourceInUse because the
    # endpoint service still references the old NLB ARN.
    # name_prefix (vs name) allows two NLBs to coexist during the swap.
    create_before_destroy = true
    replace_triggered_by  = [aws_security_group.nlb.id]
  }

  tags = merge(local.common_tags, {
    Name = "web-nlb"
  })
}

resource "aws_lb_target_group" "web_nlb" {
  name               = "web-nlb-tg"
  port               = 80
  protocol           = "TCP"
  vpc_id             = aws_vpc.main.id
  preserve_client_ip = false

  health_check {
    protocol            = "HTTP"
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    matcher             = "200"
  }

  tags = merge(local.common_tags, {
    Name = "web-nlb-tg"
  })
}

resource "aws_lb_listener" "nlb_http" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_nlb.arn
  }

  tags = merge(local.common_tags, {
    Name = "web-nlb-listener"
  })
}

resource "aws_lb_target_group_attachment" "web_nlb" {
  count            = 2
  target_group_arn = aws_lb_target_group.web_nlb.arn
  target_id        = aws_instance.web[count.index].id
  port             = 80
}

resource "aws_vpc_endpoint_service" "main" {
  acceptance_required        = false
  network_load_balancer_arns = [aws_lb.nlb.arn]
  allowed_principals         = ["arn:aws:iam::${var.networking_account_id}:root"]

  tags = merge(local.common_tags, {
    Name = "web-endpoint-service"
  })
}
