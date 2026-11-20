#Requires -Version 7.0
<#
.SYNOPSIS
    Resets AVD-relevant Microsoft Defender for Cloud plans back to Free.
.DESCRIPTION
    Teardown helper to stop per-hour/per-transaction Defender charges after an
    enterprise lab run. Requires Az.Security or az CLI and honors -WhatIf.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$plans = @('VirtualMachines', 'KeyVaults', 'StorageAccounts')
foreach ($plan in $plans) {
    if ($PSCmdlet.ShouldProcess("subscription/<redacted>/pricings/$plan", 'Set pricingTier to Free')) {
        az security pricing create --subscription $SubscriptionId --name $plan --tier Free | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to reset Defender plan '$plan' to Free."
        }
    }
}
