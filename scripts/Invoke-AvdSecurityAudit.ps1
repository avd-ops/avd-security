<#
.SYNOPSIS
    Read-only AVD security posture verifier emitting avd-security-posture/v1.
.DESCRIPTION
    Evaluates AVD session-host hardening and control-plane hygiene against avd-assess
    security claims. Accepts an offline fixture hashtable or JSON file for deterministic
    CI and pre-flight verification.
#>
[CmdletBinding()]
param(
    [hashtable]$InputData,

    [string]$FixturePath,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$mode = 'offline'
$state = $null

if ($null -ne $InputData) {
    $state = $InputData
}
elseif (-not [string]::IsNullOrWhiteSpace($FixturePath)) {
    if (-not (Test-Path $FixturePath)) {
        throw "FixturePath not found: $FixturePath"
    }
    $state = Get-Content -Path $FixturePath -Raw | ConvertFrom-Json -AsHashtable
}
else {
    throw 'Provide -InputData or -FixturePath for read-only posture evaluation.'
}

function New-CheckResult {
    param(
        [string]$Id,
        [string]$Pillar,
        [string]$Status,
        [string]$ClaimRef,
        [string]$Message,
        [string]$RemediationHint = ''
    )
    $item = [ordered]@{
        id       = $Id
        pillar   = $Pillar
        status   = $Status
        claimRef = $ClaimRef
        message  = $Message
    }
    if (-not [string]::IsNullOrWhiteSpace($RemediationHint)) {
        $item.remediationHint = $RemediationHint
    }
    return $item
}

$checks = [System.Collections.Generic.List[object]]::new()

# 1. Trusted Launch / vTPM
$trustedLaunch = [bool]($state.trustedLaunchEnabled)
$checks.Add((New-CheckResult `
    -Id 'sec-host-trusted-launch' `
    -Pillar 'security-posture' `
    -Status ($trustedLaunch ? 'pass' : 'fail') `
    -ClaimRef 'ref:avd-security-guide#trusted-launch' `
    -Message ($trustedLaunch ? 'Session hosts use Trusted Launch with Secure Boot and vTPM.' : 'Trusted Launch is not enabled on session hosts.') `
    -RemediationHint ($trustedLaunch ? '' : 'Enable Trusted Launch (Secure Boot + vTPM) in avd-azure image/VM profile.')))

# 2. RDP device & clipboard redirection
$redirectionRestricted = [bool]($state.rdpRedirectionRestricted)
$checks.Add((New-CheckResult `
    -Id 'sec-host-rdp-redirection' `
    -Pillar 'security-posture' `
    -Status ($redirectionRestricted ? 'pass' : 'fail') `
    -ClaimRef 'ref:avd-security-guide#device-redirection' `
    -Message ($redirectionRestricted ? 'Clipboard, drive, and USB redirection are restricted.' : 'Unrestricted RDP device/clipboard redirection detected.') `
    -RemediationHint ($redirectionRestricted ? '' : 'Restrict RDP clipboard/drive/USB redirection in host pool RDP properties and Intune.')))

# 3. Screen Capture Protection
$screenCapture = [bool]($state.screenCaptureProtectionEnabled)
$checks.Add((New-CheckResult `
    -Id 'sec-host-screen-capture' `
    -Pillar 'security-posture' `
    -Status ($screenCapture ? 'pass' : 'warn') `
    -ClaimRef 'ref:avd-security-guide#screen-capture-protection' `
    -Message ($screenCapture ? 'Screen Capture Protection is enabled.' : 'Screen Capture Protection is not enabled.') `
    -RemediationHint ($screenCapture ? '' : 'Enable Screen Capture Protection policy on session hosts via Intune/GPO.')))

# 4. Defender / EDR present
$edrPresent = [bool]($state.edrPresent)
$checks.Add((New-CheckResult `
    -Id 'sec-host-edr-present' `
    -Pillar 'security-posture' `
    -Status ($edrPresent ? 'pass' : 'fail') `
    -ClaimRef 'ref:avd-security-guide#edr-microsoft-or-third-party' `
    -Message ($edrPresent ? 'Endpoint Detection and Response (EDR) agent is active.' : 'No active EDR agent reported on session hosts.') `
    -RemediationHint ($edrPresent ? '' : 'Onboard session hosts to Microsoft Defender for Endpoint or approved EDR.')))

# 5. FSLogix VHD/VHDX AV exclusions
$fslogixExclusions = [bool]($state.fslogixAvExclusionsConfigured)
$checks.Add((New-CheckResult `
    -Id 'sec-host-fslogix-exclusions' `
    -Pillar 'security-posture' `
    -Status ($fslogixExclusions ? 'pass' : 'warn') `
    -ClaimRef 'ref:avd-security-guide#vhd-exclusions' `
    -Message ($fslogixExclusions ? 'FSLogix VHD/VHDX antivirus exclusions are configured.' : 'FSLogix VHD/VHDX antivirus exclusions are missing.') `
    -RemediationHint ($fslogixExclusions ? '' : 'Apply Microsoft-documented FSLogix VHD/VHDX exclusions via avd-intune.')))

# 6. Key Vault soft-delete and purge protection
$kvProtected = [bool]($state.keyVaultSoftDeleteAndPurgeProtection)
$checks.Add((New-CheckResult `
    -Id 'sec-ctrl-keyvault-protection' `
    -Pillar 'governance' `
    -Status ($kvProtected ? 'pass' : 'fail') `
    -ClaimRef 'ref:caf-avd-security-governance#activity-logging' `
    -Message ($kvProtected ? 'Key Vault soft-delete and purge protection are enabled.' : 'Key Vault lacks soft-delete or purge protection.') `
    -RemediationHint ($kvProtected ? '' : 'Enable soft-delete and purge protection on AVD Key Vaults.')))

# 7. RBAC least privilege (no standing subscription Owner sprawl)
$rbacLeastPriv = [bool]($state.rbacLeastPrivilegeVerified)
$checks.Add((New-CheckResult `
    -Id 'sec-ctrl-rbac-least-privilege' `
    -Pillar 'identity' `
    -Status ($rbacLeastPriv ? 'pass' : 'fail') `
    -ClaimRef 'ref:caf-avd-security-governance#groups-not-users' `
    -Message ($rbacLeastPriv ? 'RBAC assignments use group-based least privilege.' : 'Over-broad or direct user RBAC assignments detected.') `
    -RemediationHint ($rbacLeastPriv ? '' : 'Replace direct user/Owner assignments with PIM-eligible group roles.')))

$passCount = @($checks | Where-Object { $_.status -eq 'pass' }).Count
$warnCount = @($checks | Where-Object { $_.status -eq 'warn' }).Count
$failCount = @($checks | Where-Object { $_.status -eq 'fail' }).Count

$report = [ordered]@{
    schema    = 'avd-security-posture/v1'
    checkedAt = (Get-Date).ToUniversalTime().ToString('o')
    mode      = $mode
    summary   = [ordered]@{
        total = $checks.Count
        pass  = $passCount
        warn  = $warnCount
        fail  = $failCount
    }
    checks    = @($checks)
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding utf8NoBOM
}

return $report
