# user-scripts/domain-controller/cloud-dc-promo-prep.ps1
#
# Run this in an SSM Session Manager session on dc01-corporate BEFORE
# opening the Server Manager promotion wizard.
#
# What it does:
#   1. Registers a one-shot Windows Scheduled Task (SYSTEM, AtStartup) that
#      resets the adapter DNS back to DHCP on the first reboot after promotion.
#      This fires before SSM Agent reconnects, so the session comes back
#      automatically without manual intervention.
#   2. Sets the adapter DNS to 192.168.1.200 (on-prem DC) so the promotion
#      wizard can resolve and contact the corp.internal forest.
#   3. Pins the active NIC's IPv4 MTU to 1350 (persistent) so DCpromo's
#      RPC frames don't exceed the IPsec tunnel MSS, which was a suspected
#      cause of mid-handshake RPC 1722/1749 failures over the Site-to-Site
#      VPN.
#   4. Forces a one-shot w32time sync against the on-prem DC PDC emulator
#      so Kerberos pre-authentication during promotion doesn't fail with
#      "Invalid Security Context" (RPC 1749) due to clock skew. Once the
#      EC2 itself becomes a DC, the domain time hierarchy takes over.
#   5. Verifies corp.internal SRV records resolve -- confirms VPN is up and
#      the on-prem DC is reachable before you touch the wizard.

$taskName = 'ResetAdapterDNSAfterPromotion'

# Register a startup task to reset adapter DNS to DHCP after the promotion
# reboot. Uses -EncodedCommand so there are no nested quoting issues in the
# scheduled task action argument.
$reset = 'Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object { $_.Status -eq ''Up'' }).InterfaceIndex -ServerAddresses "127.0.0.1"; Unregister-ScheduledTask -TaskName ''ResetAdapterDNSAfterPromotion'' -Confirm:$false'
$bytes   = [System.Text.Encoding]::Unicode.GetBytes($reset)
$encoded = [Convert]::ToBase64String($bytes)
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-EncodedCommand $encoded"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -RunLevel Highest -User 'SYSTEM' -Force | Out-Null
Write-Host "OK  Startup task '$taskName' registered -- DNS will be set to 127.0.0.1 after reboot"

# Set adapter DNS to on-prem DC for the duration of the promotion wizard.
$idx   = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }).InterfaceIndex
$alias = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }).Name
Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses '192.168.1.200'
Write-Host 'OK  Adapter DNS set to 192.168.1.200'

# Pin IPv4 MTU on the active NIC to 1350 so RPC frames fit inside the
# Site-to-Site VPN tunnel after IPsec/ESP overhead. Set on both the
# PowerShell NetIPInterface object (live) and via netsh (persistent across
# reboot). 1350 leaves headroom for the 1372-ish IPsec ceiling typically
# seen on a pfSense IKEv2 tunnel.
Set-NetIPInterface -InterfaceIndex $idx -NlMtuBytes 1350 -ErrorAction SilentlyContinue
& netsh interface ipv4 set subinterface "$alias" mtu=1350 store=persistent | Out-Null
$liveMtu = (Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4).NlMtu
Write-Host "OK  NIC '$alias' IPv4 MTU set to $liveMtu"

# Force a one-shot time sync against the on-prem DC PDC emulator. Kerberos
# rejects authentication if the source/dest clocks differ by >5 minutes,
# and the resulting RPC error (1749 -- Invalid Security Context) is exactly
# what dcpromo surfaces. After this machine becomes a DC, the domain
# hierarchy takes over and overrides this manual peer list.
& w32tm /config /manualpeerlist:"192.168.1.200,0x9" /syncfromflags:manual /update | Out-Null
Restart-Service w32time -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
& w32tm /resync /force | Out-Null

# Verify skew against the on-prem DC. A skew of <=  +/- 60s is comfortable;
# >300s will make Kerberos refuse the pre-auth.
$strip = & w32tm /stripchart /computer:192.168.1.200 /samples:1 /dataonly 2>&1
$skewLine = $strip | Where-Object { $_ -match ',\s*[+-]?\d+\.\d+s' } | Select-Object -First 1
if ($skewLine) {
    Write-Host "OK  Time skew vs 192.168.1.200: $skewLine"
} else {
    Write-Host 'WARN w32tm /stripchart did not return a skew sample -- check VPN tunnel and that NTP/UDP 123 is permitted to 192.168.1.200'
}

# Verify corp.internal is resolvable before opening the wizard.
$srv = Resolve-DnsName -Name _ldap._tcp.dc._msdcs.corp.internal -Type SRV `
    -ErrorAction SilentlyContinue
if ($srv) {
    Write-Host 'OK  corp.internal SRV records found -- ready for promotion wizard'
} else {
    Write-Host 'WARN corp.internal SRV lookup failed -- verify VPN tunnel is up and pfSense IPsec rule permits 10.0.0.0/8 -> 192.168.1.0/24'
}
