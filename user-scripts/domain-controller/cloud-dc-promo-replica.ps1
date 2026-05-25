# user-scripts/domain-controller/cloud-dc-promo-replica.ps1
#
# Promotes dc01-corporate as a replica DC in the existing corp.internal
# forest. Run this AFTER cloud-dc-promo-prep.ps1 confirms SRV records
# resolve and VPN connectivity is healthy.
#
# Prerequisites:
#   - cloud-dc-promo-prep.ps1 has been run (DNS pointed at 192.168.1.200,
#     startup DNS-reset task registered)
#   - AD DS role is installed (done by Terraform userdata on first boot)
#   - corp.internal SRV records resolve successfully
#
# The server reboots automatically on completion. The startup task
# registered by cloud-dc-promo-prep.ps1 resets adapter DNS back to DHCP
# so SSM reconnects without manual intervention.

param(
    [string]$DomainName = "corp.internal",
    [string]$SiteName   = "Default-First-Site-Name"
)

# Abort if hostname rename hasn't been applied yet.
$activeName = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName").ComputerName
$pendingName = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName").ComputerName
if ($activeName -ne $pendingName) {
    Write-Error "Hostname rename pending ($activeName -> $pendingName). Reboot the instance and reconnect before running this script."
    exit 1
}

# Abort if AD DS role is not installed.
$role = Get-WindowsFeature AD-Domain-Services
if ($role.InstallState -ne 'Installed') {
    Write-Error "AD DS role is not installed. Wait for Terraform userdata to complete and reboot, then re-run."
    exit 1
}

# Abort if DNS isn't pointing at the on-prem DC (prep script not run).
$dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notlike '*Loopback*' }).ServerAddresses
$onPremDnsSet = $dnsServers | Where-Object { $_ -notmatch '^(127\.|169\.254\.)' -and $_ -ne '' }
if (-not $onPremDnsSet) {
    Write-Error "Adapter DNS is not pointing at an on-prem DC. Run cloud-dc-promo-prep.ps1 first."
    exit 1
}

# Discover the replication source DC from SRV records, excluding this machine.
$srv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction SilentlyContinue
if (-not $srv) {
    Write-Error "Cannot resolve $DomainName SRV records. Verify the VPN tunnel is up and adapter DNS points at the on-prem DC."
    exit 1
}
$ReplicationSourceDC = ($srv | Where-Object { $_.NameTarget -notlike "$env:COMPUTERNAME.*" } | Select-Object -First 1).NameTarget
if (-not $ReplicationSourceDC) {
    Write-Error "Could not find a remote DC in SRV records for $DomainName. Only this machine was listed -- ensure the on-prem DC is reachable."
    exit 1
}
Write-Host "OK  Replication source discovered: $ReplicationSourceDC"

# Prompt for domain admin credentials and DSRM password.
# Use Read-Host rather than Get-Credential -- Get-Credential opens a GUI
# dialog that is not visible inside SSM Session Manager / Fleet Manager
# sessions, causing the cmdlet to error with MissingMandatoryParameter
# because no input ever reaches it. Read-Host always prompts in the
# active console where remote sessions can answer.
# Either NetBIOS (corp\Administrator) or UPN (Administrator@corp.internal)
# format works for the username.
Write-Host ""
$adminUser = Read-Host "Enter domain admin username (e.g. corp\Administrator or Administrator@corp.internal)"
$adminPwd  = Read-Host "Enter domain admin password" -AsSecureString
$cred      = New-Object System.Management.Automation.PSCredential($adminUser, $adminPwd)

$dsrm = Read-Host "Set DSRM password" -AsSecureString

Write-Host ""
Write-Host "Promoting $env:COMPUTERNAME as a replica DC in $DomainName ..."
Write-Host "Replication source: $ReplicationSourceDC"
Write-Host "The server will reboot automatically when promotion completes."
Write-Host ""

Install-ADDSDomainController `
    -DomainName            $DomainName `
    -ReplicationSourceDC   $ReplicationSourceDC `
    -SiteName              $SiteName `
    -InstallDns:$true `
    -CreateDnsDelegation:$false `
    -SafeModeAdministratorPassword $dsrm `
    -Credential            $cred `
    -Force:$true `
    -NoRebootOnCompletion:$false
