#Requires -Version 7.0
<#
.SYNOPSIS
    Self-reported AVD security posture verifier emitting avd-security-posture/v1.
.DESCRIPTION
    Validates caller-supplied boolean evidence against contracts/avd-security-input.schema.json
    and evaluates AVD security controls against verified avd-assess claims.
    Rejects string-coerced booleans ("false", "0") and unknown keys.
#>
[CmdletBinding()]
param(
    [hashtable]$InputData,

    [string]$FixturePath,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$inputSchemaPath = Join-Path $repoRoot 'contracts/avd-security-input.schema.json'

$rawJson = $null
$state = $null

if ($null -ne $InputData) {
    $rawJson = $InputData | ConvertTo-Json -Depth 5
    $state = $InputData
}
elseif (-not [string]::IsNullOrWhiteSpace($FixturePath)) {
    if (-not (Test-Path $FixturePath)) {
        throw "FixturePath not found: $FixturePath"
    }
    $rawJson = Get-Content -Path $FixturePath -Raw
    $state = $rawJson | ConvertFrom-Json -AsHashtable
}
else {
    throw 'Provide -InputData or -FixturePath for posture evaluation.'
}

if (-not (Test-Json -Json $rawJson -SchemaFile $inputSchemaPath)) {
    throw "Input failed schema validation against $inputSchemaPath"
}

function Get-StrictBool {
    param(
        [hashtable]$Map,
        [string]$Key
    )
    if (-not $Map.ContainsKey($Key)) {
        throw "Missing required input key: $Key"
    }
    $val = $Map[$Key]
    if ($val -isnot [bool]) {
        throw "Input key '$Key' must be a strict [bool], got $($val.GetType().Name)"
    }
    return $val
}

function New-CheckResult {
    param(
        [string]$Id,
        [string]$AssessCheckId,
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
    if (-not [string]::IsNullOrWhiteSpace($AssessCheckId)) {
        $item.assessCheckId = $AssessCheckId
    }
    if (-not [string]::IsNullOrWhiteSpace($RemediationHint)) {
        $item.remediationHint = $RemediationHint
    }
    return $item
}

$checks = [System.Collections.Generic.List[object]]::new()

# 1. Trusted Launch / vTPM
$trustedLaunch = Get-StrictBool -Map $state -Key 'trustedLaunchEnabled'
$checks.Add((New-CheckResult `
    -Id 'sec-host-trusted-launch' `
    -AssessCheckId 'asm-hosts-trusted-launch' `
    -Pillar 'security-posture' `
    -Status ($trustedLaunch ? 'pass' : 'fail') `
    -ClaimRef 'ref:avd-security-guide#trusted-launch' `
    -Message ($trustedLaunch ? 'Session hosts use Trusted Launch with Secure Boot and vTPM.' : 'Trusted Launch is not enabled on session hosts.') `
    -RemediationHint ($trustedLaunch ? '' : 'Enable Trusted Launch (Secure Boot + vTPM) in the AVD image/VM profile.')))

# 2. RDP device & clipboard redirection
$redirectionRestricted = Get-StrictBool -Map $state -Key 'rdpRedirectionRestricted'
$checks.Add((New-CheckResult `
    -Id 'sec-host-rdp-redirection' `
    -AssessCheckId 'asm-drive-usb-redirection-off' `
    -Pillar 'security-posture' `
    -Status ($redirectionRestricted ? 'pass' : 'fail') `
    -ClaimRef 'ref:avd-security-guide#device-redirection' `
    -Message ($redirectionRestricted ? 'Clipboard, drive, and USB redirection are restricted.' : 'Unrestricted RDP device/clipboard redirection detected.') `
    -RemediationHint ($redirectionRestricted ? '' : 'Restrict RDP clipboard/drive/USB redirection in host pool RDP properties and endpoint policy.')))

# 3. Screen Capture Protection
$screenCapture = Get-StrictBool -Map $state -Key 'screenCaptureProtectionEnabled'
$checks.Add((New-CheckResult `
    -Id 'sec-host-screen-capture' `
    -Pillar 'security-posture' `
    -Status ($screenCapture ? 'pass' : 'warn') `
    -ClaimRef 'ref:screen-capture-protection#host-policy' `
    -Message ($screenCapture ? 'Screen Capture Protection is enabled.' : 'Screen Capture Protection is not enabled.') `
    -RemediationHint ($screenCapture ? '' : 'Enable Screen Capture Protection policy on session hosts.')))

# 4. Defender / EDR present
$edrPresent = Get-StrictBool -Map $state -Key 'edrPresent'
$checks.Add((New-CheckResult `
    -Id 'sec-host-edr-present' `
    -AssessCheckId 'asm-hosts-edr-present' `
    -Pillar 'security-posture' `
    -Status ($edrPresent ? 'pass' : 'fail') `
    -ClaimRef 'ref:avd-security-guide#edr-microsoft-or-third-party' `
    -Message ($edrPresent ? 'Endpoint Detection and Response (EDR) agent is active.' : 'No active EDR agent reported on session hosts.') `
    -RemediationHint ($edrPresent ? '' : 'Onboard session hosts to Microsoft Defender for Endpoint or approved EDR.')))

# 5. FSLogix VHD/VHDX AV exclusions
$fslogixExclusions = Get-StrictBool -Map $state -Key 'fslogixAvExclusionsConfigured'
$checks.Add((New-CheckResult `
    -Id 'sec-host-fslogix-exclusions' `
    -Pillar 'security-posture' `
    -Status ($fslogixExclusions ? 'pass' : 'warn') `
    -ClaimRef 'ref:avd-security-guide#vhd-exclusions' `
    -Message ($fslogixExclusions ? 'FSLogix VHD/VHDX antivirus exclusions are configured.' : 'FSLogix VHD/VHDX antivirus exclusions are missing.') `
    -RemediationHint ($fslogixExclusions ? '' : 'Apply Microsoft-documented FSLogix VHD/VHDX exclusions.')))

# 6. Key Vault soft-delete and purge protection
$kvProtected = Get-StrictBool -Map $state -Key 'keyVaultSoftDeleteAndPurgeProtection'
$checks.Add((New-CheckResult `
    -Id 'sec-ctrl-keyvault-protection' `
    -Pillar 'governance' `
    -Status ($kvProtected ? 'pass' : 'fail') `
    -ClaimRef 'ref:mcsb-avd-baseline#DP-5' `
    -Message ($kvProtected ? 'Key Vault soft-delete and purge protection are enabled.' : 'Key Vault lacks soft-delete or purge protection.') `
    -RemediationHint ($kvProtected ? '' : 'Enable soft-delete and purge protection on AVD Key Vaults.')))

# 7. RBAC least privilege (no direct user RBAC sprawl)
$rbacLeastPriv = Get-StrictBool -Map $state -Key 'rbacLeastPrivilegeVerified'
$checks.Add((New-CheckResult `
    -Id 'sec-ctrl-rbac-least-privilege' `
    -AssessCheckId 'asm-entra-no-direct-user-rbac' `
    -Pillar 'identity' `
    -Status ($rbacLeastPriv ? 'pass' : 'fail') `
    -ClaimRef 'ref:caf-avd-identity#groups-not-users' `
    -Message ($rbacLeastPriv ? 'RBAC assignments use group-based least privilege.' : 'Over-broad or direct user RBAC assignments detected.') `
    -RemediationHint ($rbacLeastPriv ? '' : 'Replace direct user/Owner assignments with PIM-eligible group roles.')))

$passCount = @($checks | Where-Object { $_.status -eq 'pass' }).Count
$warnCount = @($checks | Where-Object { $_.status -eq 'warn' }).Count
$failCount = @($checks | Where-Object { $_.status -eq 'fail' }).Count

$report = [ordered]@{
    schema    = 'avd-security-posture/v1'
    checkedAt = (Get-Date).ToUniversalTime().ToString('o')
    mode      = 'self-reported'
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
