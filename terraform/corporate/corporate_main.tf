# terraform/corporate/main.tf
# =====================================================================
# Corporate Account - Spoke VPC, Domain Controller (Windows Server 2025)
# =====================================================================
# Private subnet traffic routes to TGW for hub-and-spoke egress.
# The DC is bootstrapped with the AD DS role and hardening via user data.
# Active Directory configuration is completed manually via the GUI
# after the instance is accessible through SSM Session Manager.
# SSM traffic is kept off the internet via Interface VPC Endpoints.
# =====================================================================

#  Enforcing EBS Encryption by default - commented out for threat simulation script

# resource "aws_ebs_encryption_by_default" "main" {
#   enabled = true
# }

data "aws_availability_zones" "available" {
  state = "available"
}

# Always resolve the latest Windows Server 2025 full base AMI.
data "aws_ami" "windows_2025" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2025-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# -- Corporate VPC ----------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "corporate-vpc"
  })
}

# Private subnets - DC and workloads. Internet egress via TGW -> NAT GW.
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "corporate-private-${count.index + 1}"
  })
}

# -- Route Tables -----------------------------------------------------

# Private route table - all non-local traffic goes to the TGW hub.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "corporate-private-rt"
  })
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Default route: internet-bound and inter-spoke traffic exits via TGW.
resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

# Explicit spoke-to-spoke route: corporate -> security via TGW.
resource "aws_route" "private_to_security" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = var.security_vpc_cidr
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

# Route to on-prem via TGW -> VPN.
resource "aws_route" "private_to_on_prem" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = var.on_prem_subnet_cidr
  transit_gateway_id     = var.transit_gateway_id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.main]
}

# -- TGW Attachment ---------------------------------------------------
# Attaches the corporate VPC to the shared TGW. The TGW has
# auto_accept_shared_attachments = "enable" so no manual acceptance
# is required in the network account.

resource "aws_ec2_transit_gateway_vpc_attachment" "main" {
  transit_gateway_id = var.transit_gateway_id
  vpc_id             = aws_vpc.main.id
  subnet_ids         = aws_subnet.private[*].id

  tags = merge(local.common_tags, {
    Name = "corporate-tgw-attachment"
  })
}

# -- Security Group - Domain Controller -------------------------------
# All AD service ports are scoped to the corporate VPC, security VPC,
# and on-prem subnet. No inbound rule exposes the DC to the internet.
# RDP is allowed from the VPC CIDR only as a break-glass option;
# the primary access method is SSM Session Manager.

resource "aws_security_group" "dc" {
  name        = "corporate-dc-sg"
  description = "Domain Controller - AD/DNS inbound from VPCs and on-prem only"
  vpc_id      = aws_vpc.main.id

  # DNS
  ingress {
    description = "DNS UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }
  ingress {
    description = "DNS TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # Kerberos
  ingress {
    description = "Kerberos TCP"
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }
  ingress {
    description = "Kerberos UDP"
    from_port   = 88
    to_port     = 88
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # RPC endpoint mapper
  ingress {
    description = "RPC endpoint mapper"
    from_port   = 135
    to_port     = 135
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # LDAP
  ingress {
    description = "LDAP TCP"
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }
  ingress {
    description = "LDAP UDP"
    from_port   = 389
    to_port     = 389
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # SMB / SYSVOL / NETLOGON
  ingress {
    description = "SMB"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # Kerberos password change
  ingress {
    description = "Kerberos password change TCP"
    from_port   = 464
    to_port     = 464
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }
  ingress {
    description = "Kerberos password change UDP"
    from_port   = 464
    to_port     = 464
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # LDAPS
  ingress {
    description = "LDAPS"
    from_port   = 636
    to_port     = 636
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # Global Catalog
  ingress {
    description = "Global Catalog LDAP / LDAPS"
    from_port   = 3268
    to_port     = 3269
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # RDP - break-glass, VPC CIDR only, no internet exposure.
  ingress {
    description = "RDP break-glass from VPC"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Dynamic RPC for AD replication and remote management.
  ingress {
    description = "Dynamic RPC (AD replication)"
    from_port   = 49152
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # ICMP - diagnostic only, RFC1918 sources.
  ingress {
    description = "ICMP from VPCs and on-prem"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr, var.security_vpc_cidr, var.on_prem_subnet_cidr, var.management_identity_cidr]
  }

  # All outbound - DC needs to reach Windows Update, SSM, and the other DC.
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "corporate-dc-sg"
  })
}

# -- Domain Controller EC2 Instance -----------------------------------

locals {
  dc_userdata = <<-USERDATA
    <powershell>
    # -- SSM Agent ----------------------------------------------------
    # Windows Server 2025 ships with SSM Agent; ensure it is running
    # and set to auto-start before any other step.
    Set-Service  -Name AmazonSSMAgent -StartupType Automatic
    Start-Service -Name AmazonSSMAgent

    # -- AD DS and DNS Role -------------------------------------------
    # Role installation only - the user completes forest/domain
    # promotion via Server Manager GUI after the first reboot.
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Install-WindowsFeature -Name DNS                -IncludeManagementTools

    # Configure a global forwarder pointing back at the VPC Resolver so that
    # the DC can resolve AWS service names (e.g. amazonaws.com) and any domain
    # that is not authoritative here. Without this the DC has no upstream for
    # non-AD queries, breaking Windows Update, SSM, and cross-account lookups.
    Set-DnsServerForwarder -IPAddress "${local.vpc_resolver_ip}" `
      -UseRootHint $false -PassThru | Out-Null
    Write-Host "DNS forwarder set to ${local.vpc_resolver_ip}"

    # -- Hardening ----------------------------------------------------
    # Disable SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    # Enforce Windows Firewall on all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    # Disable LLMNR
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty `
      -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
      -Name "EnableMulticast" -Value 0 -Type DWord

    # Disable NetBIOS over TCP/IP on all enabled adapters
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration |
                Where-Object { $_.IPEnabled -eq $true }
    foreach ($a in $adapters) { $a.SetTcpipNetbios(2) }

    # Require NLA for RDP (break-glass only; primary access is SSM)
    Set-ItemProperty `
      -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
      -Name "UserAuthentication" -Value 1

    # Disable the built-in Guest account
    net user Guest /active:no

    # Enable key audit subcategories
    auditpol /set /subcategory:"Logon"                    /success:enable /failure:enable
    auditpol /set /subcategory:"Account Logon"            /success:enable /failure:enable
    auditpol /set /subcategory:"Account Management"       /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
    auditpol /set /subcategory:"Policy Change"            /success:enable /failure:enable
    auditpol /set /subcategory:"Privilege Use"            /success:enable /failure:enable

    # Rename the computer - takes effect after reboot.
    Rename-Computer -NewName "dc01-corporate" -Force

    # Detect a preserved, already-promoted DC (AMI restore path).
    # On a fresh instance NTDS does not exist; on a restored promoted DC it is
    # Running by the time EC2Launch v2 executes userdata.  When promoted, skip
    # the adapter DNS reset and forced reboot -- both would disrupt AD services
    # without benefit.  The adapter must stay at 127.0.0.1 (set by the
    # ResetAdapterDNSAfterPromotion startup task that ran after the original
    # promotion) so the DC can resolve corp.internal for AD operations without
    # requiring a Route 53 Resolver forwarding rule to be in place first.
    $ntds = Get-Service -Name 'NTDS' -ErrorAction SilentlyContinue
    $isPromoted = ($null -ne $ntds -and $ntds.Status -eq 'Running')

    if ($isPromoted) {
      Write-Host "Promoted DC detected -- skipping adapter DNS reset and reboot."
    } else {
      # Reset adapter DNS to DHCP so the VPC Resolver answers AWS service queries.
      # The Set-DnsServerForwarder above is a DNS Server service setting (forwarding
      # for non-authoritative zones). The adapter address is separate: if it points
      # at an on-prem DC (e.g. 192.168.1.200), Windows resolves ssmmessages and
      # ec2messages via the public internet rather than the VPC endpoints, breaking
      # SSM. Forcing the adapter back to DHCP ensures this instance always comes up
      # with the VPC Resolver (${local.vpc_resolver_ip}) on its adapter regardless
      # of any manual changes made during a previous promotion attempt.
      $idx = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).InterfaceIndex
      Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses
      Write-Host "Adapter DNS reset to DHCP (VPC Resolver ${local.vpc_resolver_ip})"

      Write-Host "Bootstrap complete. Rebooting to apply hostname change before DC promotion."
      Restart-Computer -Force
    }
    </powershell>
  USERDATA
}

resource "aws_instance" "dc" {
  ami                    = var.dc_ami_id != "" ? var.dc_ami_id : data.aws_ami.windows_2025.id
  instance_type          = var.dc_instance_type
  subnet_id              = aws_subnet.private[0].id
  private_ip             = var.dc_private_ip
  vpc_security_group_ids = [aws_security_group.dc.id]
  iam_instance_profile   = aws_iam_instance_profile.dc_ssm.name
  ebs_optimized          = true
  monitoring             = true

  # No key pair - use SSM Session Manager for all shell access.
  user_data = local.dc_userdata

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 60
    encrypted             = true
    delete_on_termination = true

    tags = merge(local.common_tags, {
      Name = "corporate-dc01-root"
    })
  }

  # Enforce IMDSv2 - prevents SSRF-based metadata credential theft.
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  # Ignore user_data changes after first apply - re-running bootstrap
  # on a live DC would be destructive.
  lifecycle {
    ignore_changes = [user_data, ami]
  }

  # Ensure routing is in place before the instance boots and attempts
  # to register with the SSM endpoint.
  depends_on = [aws_route.private_default]

  tags = merge(local.common_tags, {
    Name = "corporate-dc01"
    Role = "DomainController"
    OS   = "WindowsServer2025"
  })
}

# -- SSM Interface VPC Endpoints --------------------------------------
# Keeps all SSM traffic within the AWS private network.
# Requires enable_dns_support + enable_dns_hostnames on the VPC (both set above)
# and private_dns_enabled = true so the regional SSM hostnames resolve
# to the endpoint ENI IPs rather than public addresses.

resource "aws_security_group" "ssm_endpoints" {
  name        = "corporate-ssm-endpoints-sg"
  description = "Allow HTTPS inbound from VPC to SSM interface endpoints"
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
    Name = "corporate-ssm-endpoints-sg"
  })
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "corporate-ssm-endpoint"
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
    Name = "corporate-ssmmessages-endpoint"
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
    Name = "corporate-ec2messages-endpoint"
  })
}
# -- DNS Firewall Rule Group Association ------------------------------
# Associates the baseline DNS Firewall rule group (shared via RAM from
# the networking account) with this VPC. All DNS queries from the
# corporate VPC are filtered against the org-baseline-dns-firewall rule
# group before being resolved.

locals {
  dns_firewall_rule_group_id = element(split("/", var.dns_firewall_rule_group_arn), length(split("/", var.dns_firewall_rule_group_arn)) - 1)
}

resource "aws_route53_resolver_firewall_rule_group_association" "baseline" {
  name                   = "corporate-baseline-dns-firewall"
  firewall_rule_group_id = local.dns_firewall_rule_group_id
  vpc_id                 = aws_vpc.main.id
  priority               = 101

  tags = merge(local.common_tags, {
    Name = "corporate-baseline-dns-firewall"
  })
}
