# terraform/networking-web/web_ingress.tf
# =====================================================================
# Internet-facing ALB for the web spoke (PrivateLink pattern).
#
# This workspace is applied exclusively in Phase 3, after deploy-web
# has created the NLB and exported its endpoint service name.
# The networking workspace (Phase 1) never touches these resources,
# so the ALB DNS name is stable across pipeline runs.
#
# VPC and subnet IDs are read from the networking workspace remote
# state rather than being re-declared here.
#
# Traffic flow:
#   Internet → ALB (public subnets, egress VPC)
#       → VPC Endpoint ENI (same public subnets)
#       → PrivateLink → NLB (web private subnets)
#       → EC2 web servers
# =====================================================================

locals {
  egress_vpc_id      = data.terraform_remote_state.networking.outputs.egress_vpc_id
  public_subnet_ids  = data.terraform_remote_state.networking.outputs.public_subnet_ids
}

# -- Security Groups ---------------------------------------------------

resource "aws_security_group" "web_alb" {
  count       = local.web_ingress_enabled ? 1 : 0
  name        = "networking-web-alb-sg"
  description = "Internet-facing ALB for web spoke - HTTP inbound from internet"
  vpc_id      = local.egress_vpc_id

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "networking-web-alb-sg"
  })
}

resource "aws_security_group" "web_endpoint" {
  count       = local.web_ingress_enabled ? 1 : 0
  name        = "networking-web-endpoint-sg"
  description = "VPC endpoint ENIs for web PrivateLink - HTTP from ALB only"
  vpc_id      = local.egress_vpc_id

  egress {
    description = "HTTP to NLB via PrivateLink"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "networking-web-endpoint-sg"
  })
}

# Cross-SG rules are defined as separate resources to avoid a Terraform cycle.

resource "aws_security_group_rule" "web_alb_egress_internet" {
  count             = local.web_ingress_enabled ? 1 : 0
  type              = "egress"
  description       = "Return traffic to internet clients"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.web_alb[0].id
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "web_alb_to_endpoint" {
  count                    = local.web_ingress_enabled ? 1 : 0
  type                     = "egress"
  description              = "HTTP to VPC endpoint ENIs"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.web_alb[0].id
  source_security_group_id = aws_security_group.web_endpoint[0].id
}

resource "aws_security_group_rule" "web_endpoint_from_alb" {
  count                    = local.web_ingress_enabled ? 1 : 0
  type                     = "ingress"
  description              = "HTTP from ALB"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.web_endpoint[0].id
  source_security_group_id = aws_security_group.web_alb[0].id
}

# CIDR-based ingress alongside the SG-reference rule above. Source is
# 0.0.0.0/0 because Network Firewall preserves the original client IP
# through to the public subnet (no source NAT), so the source seen at
# the endpoint ENI may be the internet client IP rather than the ALB's
# private IP. The endpoint ENI has no public IP and is only reachable
# from inside the VPC, so 0.0.0.0/0 here does not expose anything externally.
resource "aws_security_group_rule" "web_endpoint_from_egress_vpc" {
  count             = local.web_ingress_enabled ? 1 : 0
  type              = "ingress"
  description       = "HTTP from any source (NF preserves client IP, ALB private IPs)"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  security_group_id = aws_security_group.web_endpoint[0].id
  cidr_blocks       = ["0.0.0.0/0"]
}

# -- VPC Endpoint (consumer side of PrivateLink) -----------------------

resource "aws_vpc_endpoint" "web" {
  count               = local.web_ingress_enabled ? 1 : 0
  vpc_id              = local.egress_vpc_id
  service_name        = var.web_endpoint_service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.public_subnet_ids
  security_group_ids  = [aws_security_group.web_endpoint[0].id]
  private_dns_enabled = false

  tags = merge(local.common_tags, {
    Name = "networking-web-endpoint"
  })
}

# -- ENI IP Discovery --------------------------------------------------
# network_interface_ids is a computed attribute on the endpoint resource,
# populated when the endpoint reaches "available" -- no separate API query.

data "aws_network_interface" "web_endpoint_eni" {
  count = local.web_ingress_enabled ? 2 : 0
  id    = tolist(aws_vpc_endpoint.web[0].network_interface_ids)[count.index]
}

# -- Internet-Facing ALB -----------------------------------------------

resource "aws_lb" "web" {
  count                      = local.web_ingress_enabled ? 1 : 0
  name                       = "networking-web-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.web_alb[0].id]
  subnets                    = local.public_subnet_ids
  drop_invalid_header_fields = true

  tags = merge(local.common_tags, {
    Name = "networking-web-alb"
  })
}

resource "aws_lb_target_group" "web_endpoint" {
  count       = local.web_ingress_enabled ? 1 : 0
  name        = "networking-web-endpoint-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = local.egress_vpc_id
  target_type = "ip"

  health_check {
    path                = "/"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = merge(local.common_tags, {
    Name = "networking-web-endpoint-tg"
  })
}

resource "aws_lb_target_group_attachment" "web_endpoint" {
  count            = local.web_ingress_enabled ? 2 : 0
  target_group_arn = aws_lb_target_group.web_endpoint[0].arn
  target_id        = data.aws_network_interface.web_endpoint_eni[count.index].private_ip
  port             = 80
}

resource "aws_lb_listener" "web_http" {
  count             = local.web_ingress_enabled ? 1 : 0
  load_balancer_arn = aws_lb.web[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_endpoint[0].arn
  }

  tags = merge(local.common_tags, {
    Name = "networking-web-alb-listener-http"
  })
}
