<#
.SYNOPSIS
    Emits a redacted avd-security-outputs/v1 manifest from deployment outputs.
#>
[CmdletBinding()]
param(
    [ValidateSet('lab', 'enterprise')]
    [string]$CostProfile = 'lab',

    [ValidateSet('commercial', 'usgov')]
    [string]$CloudProfile = 'commercial',

    [ValidateSet('Free', 'Standard')]
    [string]$DefenderTier = 'Free',

    [ValidateSet('Audit', 'Deny')]
    [string]$PolicyEffect = 'Audit',

    [bool]$SentinelEnabled = $false,

    [string[]]$PolicyAssignmentIds = @(),

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Extract only the assignment short names and strip any accidental GUIDs.
$guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
$assignmentNames = @(
    foreach ($id in $PolicyAssignmentIds) {
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $leaf = ($id -split '/')[-1]
            $leaf -replace $guidPattern, '<redacted-guid>'
        }
    }
)

$manifest = [ordered]@{
    schema                = 'avd-security-outputs/v1'
    generatedAt           = (Get-Date).ToUniversalTime().ToString('o')
    costProfile           = $CostProfile
    cloudProfile          = $CloudProfile
    defenderTier          = $DefenderTier
    policyEffect          = $PolicyEffect
    sentinelEnabled       = $SentinelEnabled
    policyAssignmentNames = $assignmentNames
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding utf8NoBOM
}

return $manifest
