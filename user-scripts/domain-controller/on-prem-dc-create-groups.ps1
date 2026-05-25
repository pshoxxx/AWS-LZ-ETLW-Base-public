#Requires -Modules ActiveDirectory
# user-scripts/domain-controller/on-prem-dc-create-groups.ps1
#
# Creates the Cloud-Access OU and all IAM Identity Center AD groups.
# Idempotent -- safe to re-run; existing OU and groups are skipped.
#
# Run this in PowerShell on the Domain Controller after promotion.
# Adjust $DomainDN if your domain name differs from corp.internal.

param(
    [string]$DomainDN = "DC=corp,DC=internal",
    [string]$OUName   = "Cloud-Access"
)

$OUPath = "OU=$OUName,$DomainDN"

# -- Create OU if missing --------------------------------------------------
$existingOU = Get-ADOrganizationalUnit `
    -Filter "Name -eq '$OUName'" `
    -SearchBase $DomainDN `
    -ErrorAction SilentlyContinue

if ($existingOU) {
    Write-Host "[SKIP] OU already exists: $OUPath"
} else {
    try {
        New-ADOrganizationalUnit -Name $OUName -Path $DomainDN -ErrorAction Stop
        Write-Host "[OK]   Created OU: $OUPath"
    } catch {
        Write-Error "Failed to create OU: $_"
        exit 1
    }
}

# -- Group definitions ------------------------------------------------------
# AD group name            -> IAM Identity Center Permission Set
$Groups = [ordered]@{
    "aws-iam-engineers"      = "PlatformAdmin (AdministratorAccess) -- all accounts"
    "aws-network-admins"     = "NetworkAdministrator -- networking only"
    "aws-system-admins"      = "SystemAdministrator -- corporate + management"
    "aws-database-admins"    = "DatabaseAdministrator -- corporate"
    "aws-data-scientists"    = "DataScientist -- corporate"
    "aws-developers"         = "Developer (PowerUserAccess) -- corporate"
    "aws-security-analysts"  = "SecurityAnalyst (SecurityAudit read-only) -- all accounts"
    "aws-security-engineers" = "SecurityEngineer (custom: GuardDuty/SecurityHub/Inspector/Macie) -- security + management"
    "aws-devops"             = "DevOps (custom composite: EC2/VPC/RDS/Glue/WAF/Route53/DS) -- all accounts"
}

# -- Create groups (idempotent) ---------------------------------------------
$created = 0
$skipped = 0
$failed  = 0

foreach ($GroupName in $Groups.Keys) {
    $existing = Get-ADGroup `
        -Filter "Name -eq '$GroupName'" `
        -ErrorAction SilentlyContinue

    if ($existing) {
        # Ensure DisplayName is set even on pre-existing groups.
        # IAM Identity Center (AD Connector mode) resolves groups by
        # the AD displayName attribute; New-ADGroup without -DisplayName
        # leaves it unset, causing GetGroupId to return GROUP_NOT_FOUND.
        if (-not $existing.DisplayName) {
            Set-ADGroup -Identity $GroupName -DisplayName $GroupName -ErrorAction SilentlyContinue
            Write-Host "[FIX]  $GroupName -- set missing DisplayName"
        } else {
            Write-Host "[SKIP] $GroupName  ($($Groups[$GroupName]))"
        }
        $skipped++
    } else {
        try {
            New-ADGroup `
                -Name          $GroupName `
                -DisplayName   $GroupName `
                -GroupScope    Global `
                -GroupCategory Security `
                -Path          $OUPath `
                -Description   $Groups[$GroupName] `
                -ErrorAction   Stop
            Write-Host "[OK]   $GroupName"
            $created++
        } catch {
            Write-Warning "[FAIL] $GroupName -- $_"
            $failed++
        }
    }
}

# -- Summary ---------------------------------------------------------------
Write-Host ""
Write-Host "Done. Created: $created  Skipped: $skipped  Failed: $failed"

if ($failed -gt 0) {
    Write-Warning "One or more groups failed to create. Review errors above."
    exit 1
}
