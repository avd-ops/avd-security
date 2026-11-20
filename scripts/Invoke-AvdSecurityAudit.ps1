#Requires -Version 7.0
<#
.SYNOPSIS
    AVD security posture verifier emitting C34 (avd-security-posture/v1).
.DESCRIPTION
    Evaluates AVD security posture either from an avd-current-state C11 fact bundle
    (-C11Facts or -C11FactsPath, mode: "c11-facts") or from caller-supplied boolean
    evidence (-InputData or -FixturePath, mode: "self-reported") validated against
    contracts/avd-security-input.schema.json.
#>
[CmdletBinding()]
param(
    [hashtable]$C11Facts,

    [string]$C11FactsPath,

    [hashtable]$InputData,

    [string]$FixturePath,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$inputSchemaPath = Join-Path $repoRoot 'contracts/avd-security-input.schema.json'

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

$checks = [System.Collections.Generic.List[object]]::new()
$mode = $null

if ($null -ne $C11Facts -or -not [string]::IsNullOrWhiteSpace($C11FactsPath)) {
    $mode = 'c11-facts'
    $facts = if ($null -ne $C11Facts) {
        $C11Facts
    }
    else {
        if (-not (Test-Path $C11FactsPath)) {
            throw "C11FactsPath not found: $C11FactsPath"
        }
        Get-Content -Path $C11FactsPath -Raw | ConvertFrom-Json -AsHashtable
    }

    if ($facts.schema -ne 'avd-current-state-facts/v1') {
        throw "Expected C11 schema 'avd-current-state-facts/v1', got '$($facts.schema)'"
    }

    $subs = @($facts.subscriptions)
    $hostPools = @($subs | ForEach-Object { @($_.hostPools) })

    # 1. Trusted Launch across session hosts
    $totalHosts = 0
    $trustedHosts = 0
    $hasTrustedTelemetry = $false
    foreach ($hp in $hostPools) {
        if ($null -ne $hp.sessionHosts -and $null -ne $hp.sessionHosts.total -and $null -ne $hp.sessionHosts.trustedLaunch) {
            $hasTrustedTelemetry = $true
            $totalHosts += [int]$hp.sessionHosts.total
            $trustedHosts += [int]$hp.sessionHosts.trustedLaunch
        }
    }
    if (-not $hasTrustedTelemetry -or $totalHosts -eq 0) {
        $checks.Add((New-CheckResult -Id 'sec-host-trusted-launch' -AssessCheckId 'asm-hosts-trusted-launch' -Pillar 'security-posture' -Status 'unknown' -ClaimRef 'ref:avd-security-guide#trusted-launch' -Message 'No session host Trusted Launch counts present in C11 facts.'))
    }
    elseif ($trustedHosts -ge $totalHosts) {
        $checks.Add((New-CheckResult -Id 'sec-host-trusted-launch' -AssessCheckId 'asm-hosts-trusted-launch' -Pillar 'security-posture' -Status 'pass' -ClaimRef 'ref:avd-security-guide#trusted-launch' -Message 'All collected session hosts have Trusted Launch enabled.'))
    }
    else {
        $checks.Add((New-CheckResult -Id 'sec-host-trusted-launch' -AssessCheckId 'asm-hosts-trusted-launch' -Pillar 'security-posture' -Status 'fail' -ClaimRef 'ref:avd-security-guide#trusted-launch' -Message 'One or more collected session hosts lack Trusted Launch.' -RemediationHint 'Enable Trusted Launch (Secure Boot + vTPM) on AVD session host VMs.'))
    }

    # 2. Encryption at host
    $encHosts = 0
    $hasEncTelemetry = $false
    foreach ($hp in $hostPools) {
        if ($null -ne $hp.sessionHosts -and $null -ne $hp.sessionHosts.total -and $null -ne $hp.sessionHosts.encryptionAtHost) {
            $hasEncTelemetry = $true
            $encHosts += [int]$hp.sessionHosts.encryptionAtHost
        }
    }
    if (-not $hasEncTelemetry -or $totalHosts -eq 0) {
        $checks.Add((New-CheckResult -Id 'sec-host-encryption-at-host' -Pillar 'security-posture' -Status 'unknown' -ClaimRef 'ref:mcsb-avd-baseline#DP-5' -Message 'No encryptionAtHost counts present in C11 facts.'))
    }
    elseif ($encHosts -ge $totalHosts) {
        $checks.Add((New-CheckResult -Id 'sec-host-encryption-at-host' -Pillar 'security-posture' -Status 'pass' -ClaimRef 'ref:mcsb-avd-baseline#DP-5' -Message 'All collected session hosts have encryptionAtHost enabled.'))
    }
    else {
        $checks.Add((New-CheckResult -Id 'sec-host-encryption-at-host' -Pillar 'security-posture' -Status 'fail' -ClaimRef 'ref:mcsb-avd-baseline#DP-5' -Message 'One or more collected session hosts lack encryptionAtHost.' -RemediationHint 'Enable encryptionAtHost on session host VM profiles.'))
    }

    # 3. RDP device & clipboard redirection
    $redirectionVals = @()
    foreach ($hp in $hostPools) {
        if ($null -ne $hp.redirection) {
            $redirectionVals += @($hp.redirection.drives, $hp.redirection.clipboard, $hp.redirection.usb)
        }
    }
    if ($redirectionVals.Count -eq 0) {
        $checks.Add((New-CheckResult -Id 'sec-host-rdp-redirection' -AssessCheckId 'asm-drive-usb-redirection-off' -Pillar 'security-posture' -Status 'unknown' -ClaimRef 'ref:avd-security-guide#device-redirection' -Message 'No host pool redirection properties present in C11 facts.'))
    }
    elseif ($redirectionVals -contains 'on') {
        $checks.Add((New-CheckResult -Id 'sec-host-rdp-redirection' -AssessCheckId 'asm-drive-usb-redirection-off' -Pillar 'security-posture' -Status 'fail' -ClaimRef 'ref:avd-security-guide#device-redirection' -Message 'Drive, clipboard, or USB redirection is enabled on one or more host pools.' -RemediationHint 'Disable drive, clipboard, and USB redirection in host pool RDP properties.'))
    }
    elseif ($redirectionVals -contains 'default') {
        $checks.Add((New-CheckResult -Id 'sec-host-rdp-redirection' -AssessCheckId 'asm-drive-usb-redirection-off' -Pillar 'security-posture' -Status 'warn' -ClaimRef 'ref:avd-security-guide#device-redirection' -Message 'One or more redirection properties rely on default behavior rather than explicit off.' -RemediationHint 'Explicitly set drives, clipboard, and USB redirection to off in host pool RDP properties.'))
    }
    else {
        $checks.Add((New-CheckResult -Id 'sec-host-rdp-redirection' -AssessCheckId 'asm-drive-usb-redirection-off' -Pillar 'security-posture' -Status 'pass' -ClaimRef 'ref:avd-security-guide#device-redirection' -Message 'Drive, clipboard, and USB redirection are explicitly disabled across collected host pools.'))
    }

    # 4. EDR present (edrMissing == 0)
    $edrMissingTotal = 0
    $hasEdrTelemetry = $false
    foreach ($hp in $hostPools) {
        if ($null -ne $hp.sessionHosts -and $null -ne $hp.sessionHosts.edrMissing) {
            $hasEdrTelemetry = $true
            $edrMissingTotal += [int]$hp.sessionHosts.edrMissing
        }
    }
    if (-not $hasEdrTelemetry) {
        $checks.Add((New-CheckResult -Id 'sec-host-edr-present' -AssessCheckId 'asm-hosts-edr-present' -Pillar 'security-posture' -Status 'unknown' -ClaimRef 'ref:avd-security-guide#edr-microsoft-or-third-party' -Message 'No edrMissing counts present in C11 facts.'))
    }
    elseif ($edrMissingTotal -eq 0) {
        $checks.Add((New-CheckResult -Id 'sec-host-edr-present' -AssessCheckId 'asm-hosts-edr-present' -Pillar 'security-posture' -Status 'pass' -ClaimRef 'ref:avd-security-guide#edr-microsoft-or-third-party' -Message 'Zero session hosts flagged for missing EDR.'))
    }
    else {
        $checks.Add((New-CheckResult -Id 'sec-host-edr-present' -AssessCheckId 'asm-hosts-edr-present' -Pillar 'security-posture' -Status 'fail' -ClaimRef 'ref:avd-security-guide#edr-microsoft-or-third-party' -Message 'One or more session hosts are missing an active EDR agent.' -RemediationHint 'Onboard missing session hosts to Microsoft Defender for Endpoint or approved EDR.'))
    }

    # 5. Defender for Servers plan
    $vmTiers = @($subs | Where-Object { $null -ne $_.defenderPlans -and $null -ne $_.defenderPlans.VirtualMachines } | ForEach-Object { $_.defenderPlans.VirtualMachines })
    if ($vmTiers.Count -eq 0) {
        $checks.Add((New-CheckResult -Id 'sec-ctrl-defender-servers' -AssessCheckId 'asm-defender-servers' -Pillar 'security-posture' -Status 'unknown' -ClaimRef 'ref:avd-security-guide#defender-for-cloud' -Message 'No Defender for Cloud VirtualMachines plan tier present in C11 facts.'))
    }
    elseif ($vmTiers -contains 'Free') {
        $checks.Add((New-CheckResult -Id 'sec-ctrl-defender-servers' -AssessCheckId 'asm-defender-servers' -Pillar 'security-posture' -Status 'fail' -ClaimRef 'ref:avd-security-guide#defender-for-cloud' -Message 'Defender for Cloud VirtualMachines plan is Free on one or more subscriptions.' -RemediationHint 'Enable Standard Defender for Cloud (VirtualMachines P1) in enterprise deployments.'))
    }
    else {
        $checks.Add((New-CheckResult -Id 'sec-ctrl-defender-servers' -AssessCheckId 'asm-defender-servers' -Pillar 'security-posture' -Status 'pass' -ClaimRef 'ref:avd-security-guide#defender-for-cloud' -Message 'Defender for Cloud VirtualMachines plan is Standard across collected subscriptions.'))
    }

    # 6. Azure Policy assignments & enforcement
    $policySubs = @($subs | Where-Object { $null -ne $_.policy -and $null -ne $_.policy.assignments })
    if ($policySubs.Count -eq 0) {
        $checks.Add((New-CheckResult -Id 'sec-ctrl-policy-guardrails' -AssessCheckId 'asm-policy-guardrails-assigned' -Pillar 'governance' -Status 'unknown' -ClaimRef 'ref:mcsb-avd-baseline#PA-7' -Message 'No Azure Policy assignment counts present in C11 facts.'))
    }
    else {
        $zeroAssignments = @($policySubs | Where-Object { [int]$_.policy.assignments -eq 0 })
        $doNotEnforce = @($policySubs | Where-Object { $null -ne $_.policy.doNotEnforce -and [int]$_.policy.doNotEnforce -gt 0 })
        if ($zeroAssignments.Count -gt 0) {
            $checks.Add((New-CheckResult -Id 'sec-ctrl-policy-guardrails' -AssessCheckId 'asm-policy-guardrails-assigned' -Pillar 'governance' -Status 'fail' -ClaimRef 'ref:mcsb-avd-baseline#PA-7' -Message 'One or more subscriptions have zero Azure Policy guardrail assignments.' -RemediationHint 'Deploy avd-security policy-assignments.bicep baseline.'))
        }
        elseif ($doNotEnforce.Count -gt 0) {
            $checks.Add((New-CheckResult -Id 'sec-ctrl-policy-guardrails' -AssessCheckId 'asm-policy-guardrails-assigned' -Pillar 'governance' -Status 'warn' -ClaimRef 'ref:mcsb-avd-baseline#PA-7' -Message 'Policy assignments exist but one or more use DoNotEnforce mode.' -RemediationHint 'Switch policy assignments to Default enforcementMode.'))
        }
        else {
            $checks.Add((New-CheckResult -Id 'sec-ctrl-policy-guardrails' -AssessCheckId 'asm-policy-guardrails-assigned' -Pillar 'governance' -Status 'pass' -ClaimRef 'ref:mcsb-avd-baseline#PA-7' -Message 'Azure Policy guardrail assignments are active and enforced.'))
        }
    }
}
else {
    $mode = 'self-reported'
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
        throw 'Provide -C11Facts/-C11FactsPath or -InputData/-FixturePath for posture evaluation.'
    }

    if (-not (Test-Json -Json $rawJson -SchemaFile $inputSchemaPath)) {
        throw "Input failed schema validation against $inputSchemaPath"
    }

    $trustedLaunch = Get-StrictBool -Map $state -Key 'trustedLaunchEnabled'
    $checks.Add((New-CheckResult -Id 'sec-host-trusted-launch' -AssessCheckId 'asm-hosts-trusted-launch' -Pillar 'security-posture' -Status ($trustedLaunch ? 'pass' : 'fail') -ClaimRef 'ref:avd-security-guide#trusted-launch' -Message ($trustedLaunch ? 'Session hosts use Trusted Launch with Secure Boot and vTPM.' : 'Trusted Launch is not enabled on session hosts.') -RemediationHint ($trustedLaunch ? '' : 'Enable Trusted Launch (Secure Boot + vTPM) in the AVD image/VM profile.')))

    $redirectionRestricted = Get-StrictBool -Map $state -Key 'rdpRedirectionRestricted'
    $checks.Add((New-CheckResult -Id 'sec-host-rdp-redirection' -AssessCheckId 'asm-drive-usb-redirection-off' -Pillar 'security-posture' -Status ($redirectionRestricted ? 'pass' : 'fail') -ClaimRef 'ref:avd-security-guide#device-redirection' -Message ($redirectionRestricted ? 'Clipboard, drive, and USB redirection are restricted.' : 'Unrestricted RDP device/clipboard redirection detected.') -RemediationHint ($redirectionRestricted ? '' : 'Restrict RDP clipboard/drive/USB redirection in host pool RDP properties and endpoint policy.')))

    $screenCapture = Get-StrictBool -Map $state -Key 'screenCaptureProtectionEnabled'
    $checks.Add((New-CheckResult -Id 'sec-host-screen-capture' -AssessCheckId '' -Pillar 'security-posture' -Status ($screenCapture ? 'pass' : 'warn') -ClaimRef 'ref:screen-capture-protection#host-policy' -Message ($screenCapture ? 'Screen Capture Protection is enabled.' : 'Screen Capture Protection is not enabled.') -RemediationHint ($screenCapture ? '' : 'Enable Screen Capture Protection policy on session hosts.')))

    $edrPresent = Get-StrictBool -Map $state -Key 'edrPresent'
    $checks.Add((New-CheckResult -Id 'sec-host-edr-present' -AssessCheckId 'asm-hosts-edr-present' -Pillar 'security-posture' -Status ($edrPresent ? 'pass' : 'fail') -ClaimRef 'ref:avd-security-guide#edr-microsoft-or-third-party' -Message ($edrPresent ? 'Endpoint Detection and Response (EDR) agent is active.' : 'No active EDR agent reported on session hosts.') -RemediationHint ($edrPresent ? '' : 'Onboard session hosts to Microsoft Defender for Endpoint or approved EDR.')))

    $fslogixExclusions = Get-StrictBool -Map $state -Key 'fslogixAvExclusionsConfigured'
    $checks.Add((New-CheckResult -Id 'sec-host-fslogix-exclusions' -AssessCheckId '' -Pillar 'security-posture' -Status ($fslogixExclusions ? 'pass' : 'warn') -ClaimRef 'ref:avd-security-guide#vhd-exclusions' -Message ($fslogixExclusions ? 'FSLogix VHD/VHDX antivirus exclusions are configured.' : 'FSLogix VHD/VHDX antivirus exclusions are missing.') -RemediationHint ($fslogixExclusions ? '' : 'Apply Microsoft-documented FSLogix VHD/VHDX exclusions.')))

    $kvProtected = Get-StrictBool -Map $state -Key 'keyVaultSoftDeleteAndPurgeProtection'
    $checks.Add((New-CheckResult -Id 'sec-ctrl-keyvault-protection' -AssessCheckId '' -Pillar 'governance' -Status ($kvProtected ? 'pass' : 'fail') -ClaimRef 'ref:mcsb-avd-baseline#DP-5' -Message ($kvProtected ? 'Key Vault soft-delete and purge protection are enabled.' : 'Key Vault lacks soft-delete or purge protection.') -RemediationHint ($kvProtected ? '' : 'Enable soft-delete and purge protection on AVD Key Vaults.')))

    $rbacLeastPriv = Get-StrictBool -Map $state -Key 'rbacLeastPrivilegeVerified'
    $checks.Add((New-CheckResult -Id 'sec-ctrl-rbac-least-privilege' -AssessCheckId 'asm-entra-no-direct-user-rbac' -Pillar 'identity' -Status ($rbacLeastPriv ? 'pass' : 'fail') -ClaimRef 'ref:caf-avd-identity#groups-not-users' -Message ($rbacLeastPriv ? 'RBAC assignments use group-based least privilege.' : 'Over-broad or direct user RBAC assignments detected.') -RemediationHint ($rbacLeastPriv ? '' : 'Replace direct user/Owner assignments with PIM-eligible group roles.')))
}

$passCount = @($checks | Where-Object { $_.status -eq 'pass' }).Count
$warnCount = @($checks | Where-Object { $_.status -eq 'warn' }).Count
$failCount = @($checks | Where-Object { $_.status -eq 'fail' }).Count
$unknownCount = @($checks | Where-Object { $_.status -eq 'unknown' }).Count

$report = [ordered]@{
    schema    = 'avd-security-posture/v1'
    checkedAt = (Get-Date).ToUniversalTime().ToString('o')
    mode      = $mode
    summary   = [ordered]@{
        total   = $checks.Count
        pass    = $passCount
        warn    = $warnCount
        fail    = $failCount
        unknown = $unknownCount
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
