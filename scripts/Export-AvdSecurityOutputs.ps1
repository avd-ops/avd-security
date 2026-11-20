#Requires -Version 7.0
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

    [ValidatePattern('^[a-z0-9-]{3,16}$')]
    [string]$NamePrefix = 'avd-sec',

    [bool]$DefenderPlansDeployed = $false,

    [ValidateSet('Unchanged', 'Free', 'Standard')]
    [string]$DefenderTier = 'Unchanged',

    [ValidateSet('Audit', 'Deny')]
    [string]$PolicyEffect = 'Audit',

    [object]$SentinelEnabled = $false,

    [string[]]$PolicyAssignmentIds = @(),

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Parse SentinelEnabled strictly so string "false" from az deployment outputs never coerces to $true.
$sentinelBool = switch ($SentinelEnabled) {
    { $_ -is [bool] } { $_; break }
    'true'            { $true; break }
    'false'           { $false; break }
    default           { throw "SentinelEnabled must be a boolean or 'true'/'false', got: '$SentinelEnabled'" }
}

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
    defenderPlansDeployed = $DefenderPlansDeployed
    defenderTier          = $DefenderTier
    policyEffect          = $PolicyEffect
    sentinelEnabled       = $sentinelBool
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
