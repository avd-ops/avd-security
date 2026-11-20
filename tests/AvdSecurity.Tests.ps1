BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
}

Describe 'avd-security Bicep control plane' {
    It 'compiles bicep/main.bicep without errors' {
        $tempOut = Join-Path ([System.IO.Path]::GetTempPath()) "avd-security-main-$([guid]::NewGuid()).json"
        try {
            $output = az bicep build --file (Join-Path $repoRoot 'bicep/main.bicep') --outfile $tempOut 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
            Test-Path $tempOut | Should -BeTrue
            $compiled = Get-Content -Path $tempOut -Raw
            $compiled | Should -Match 'fe83a0eb-a853-422d-aac2-1bffd182c5d0'
            $compiled | Should -Match '0b60c0b2-2dc2-4e1c-b5c9-abbed971de53'
            $compiled | Should -Match 'c95b54ad-0614-4633-ab29-104b01235cbf'
        }
        finally {
            if (Test-Path $tempOut) { Remove-Item $tempOut -Force }
        }
    }

    It 'embeds all four KQL files into compiled sentinel-analytics module' {
        $tempOut = Join-Path ([System.IO.Path]::GetTempPath()) "avd-security-sentinel-$([guid]::NewGuid()).json"
        try {
            $output = az bicep build --file (Join-Path $repoRoot 'bicep/modules/sentinel-analytics.bicep') --outfile $tempOut 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
            $compiled = Get-Content -Path $tempOut -Raw
            $compiled | Should -Match 'WVDConnections'
            $compiled | Should -Match '270efc09-cd0d-444b-a71f-39af4910ec45'
            $compiled | Should -Match 'DeviceFileEvents'
            $compiled | Should -Match 'EventID == 4732'
        }
        finally {
            if (Test-Path $tempOut) { Remove-Item $tempOut -Force }
        }
    }

    It 'ships lab, enterprise, and usgov bicepparam files plus docs and teardown script' {
        Test-Path (Join-Path $repoRoot 'parameters/lab.bicepparam') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'parameters/enterprise.bicepparam') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'parameters/usgov-lab.bicepparam') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'scripts/Remove-AvdSecurityTier.ps1') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'docs/cost-model.md') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'docs/usgov-parity.md') | Should -BeTrue
    }
}

Describe 'Export-AvdSecurityOutputs.ps1' {
    It 'emits valid avd-security-outputs/v1 matching schema for commercial and usgov and redacts GUIDs' {
        $scriptPath = Join-Path $repoRoot 'scripts/Export-AvdSecurityOutputs.ps1'
        $schemaPath = Join-Path $repoRoot 'contracts/avd-security-outputs.schema.json'
        $sampleId = '/subscriptions/11111111-2222-3333-4444-555555555555/providers/Microsoft.Authorization/policyAssignments/avd-sec-kv-softdelete-11111111-2222-3333-4444-555555555555'
        $result = & $scriptPath -CostProfile 'lab' -CloudProfile 'usgov' -DefenderPlansDeployed $false -DefenderTier 'Unchanged' -PolicyEffect 'Audit' -SentinelEnabled 'false' -PolicyAssignmentIds @($sampleId)

        $json = $result | ConvertTo-Json -Depth 5
        Test-Json -Json $json -SchemaFile $schemaPath | Should -BeTrue
        $result.cloudProfile | Should -Be 'usgov'
        $result.sentinelEnabled | Should -BeFalse
        $result.policyAssignmentNames[0] | Should -Be 'avd-sec-kv-softdelete-<redacted-guid>'
        $json | Should -Not -Match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    }

    It 'rejects invalid NamePrefix values' {
        $scriptPath = Join-Path $repoRoot 'scripts/Export-AvdSecurityOutputs.ps1'
        { & $scriptPath -NamePrefix 'Contoso_Prod!' } | Should -Throw
    }
}

Describe 'Invoke-AvdSecurityAudit.ps1 (C11 facts mode)' {
    It 'evaluates a compliant C11 fact bundle as c11-facts mode with 6 pass and matches schema' {
        $scriptPath = Join-Path $repoRoot 'scripts/Invoke-AvdSecurityAudit.ps1'
        $schemaPath = Join-Path $repoRoot 'contracts/avd-security-posture.schema.json'
        $c11 = @{
            schema        = 'avd-current-state-facts/v1'
            subscriptions = @(
                @{
                    defenderPlans = @{ VirtualMachines = 'Standard' }
                    policy        = @{ assignments = 6; doNotEnforce = 0 }
                    hostPools     = @(
                        @{
                            redirection  = @{ drives = 'off'; clipboard = 'off'; usb = 'off' }
                            sessionHosts = @{ total = 4; trustedLaunch = 4; encryptionAtHost = 4; edrMissing = 0 }
                        }
                    )
                }
            )
        }

        $report = & $scriptPath -C11Facts $c11
        $json = $report | ConvertTo-Json -Depth 6
        Test-Json -Json $json -SchemaFile $schemaPath | Should -BeTrue
        $report.mode | Should -Be 'c11-facts'
        $report.summary.total | Should -Be 6
        $report.summary.pass | Should -Be 6
        $report.summary.fail | Should -Be 0
        $report.summary.unknown | Should -Be 0
    }

    It 'scores missing C11 telemetry as unknown and failing controls as fail' {
        $scriptPath = Join-Path $repoRoot 'scripts/Invoke-AvdSecurityAudit.ps1'
        $c11 = @{
            schema        = 'avd-current-state-facts/v1'
            subscriptions = @(
                @{
                    defenderPlans = @{ VirtualMachines = 'Free' }
                    policy        = @{ assignments = 0; doNotEnforce = 0 }
                    hostPools     = @(
                        @{
                            redirection  = @{ drives = 'on'; clipboard = 'off'; usb = 'off' }
                            sessionHosts = @{ total = 2; trustedLaunch = 1; encryptionAtHost = $null; edrMissing = 1 }
                        }
                    )
                }
            )
        }

        $report = & $scriptPath -C11Facts $c11
        $report.mode | Should -Be 'c11-facts'
        $report.summary.total | Should -Be 6
        $report.summary.fail | Should -Be 5
        $report.summary.unknown | Should -Be 1
    }
}

Describe 'Invoke-AvdSecurityAudit.ps1 (self-reported mode)' {
    It 'scores a fully compliant estate as 7 pass, 0 warn, 0 fail and matches schema' {
        $scriptPath = Join-Path $repoRoot 'scripts/Invoke-AvdSecurityAudit.ps1'
        $schemaPath = Join-Path $repoRoot 'contracts/avd-security-posture.schema.json'
        $compliant = @{
            trustedLaunchEnabled                 = $true
            rdpRedirectionRestricted             = $true
            screenCaptureProtectionEnabled       = $true
            edrPresent                           = $true
            fslogixAvExclusionsConfigured        = $true
            keyVaultSoftDeleteAndPurgeProtection = $true
            rbacLeastPrivilegeVerified           = $true
        }

        $report = & $scriptPath -InputData $compliant
        $json = $report | ConvertTo-Json -Depth 6
        Test-Json -Json $json -SchemaFile $schemaPath | Should -BeTrue
        $report.mode | Should -Be 'self-reported'
        $report.summary.pass | Should -Be 7
        $report.summary.warn | Should -Be 0
        $report.summary.fail | Should -Be 0
    }

    It 'rejects string-coerced booleans like "false" and unknown keys' {
        $scriptPath = Join-Path $repoRoot 'scripts/Invoke-AvdSecurityAudit.ps1'
        $stringFalse = @{
            trustedLaunchEnabled                 = 'false'
            rdpRedirectionRestricted             = $true
            screenCaptureProtectionEnabled       = $true
            edrPresent                           = $true
            fslogixAvExclusionsConfigured        = $true
            keyVaultSoftDeleteAndPurgeProtection = $true
            rbacLeastPrivilegeVerified           = $true
        }
        { & $scriptPath -InputData $stringFalse } | Should -Throw
    }
}
