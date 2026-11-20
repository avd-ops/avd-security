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
        }
        finally {
            if (Test-Path $tempOut) { Remove-Item $tempOut -Force }
        }
    }

    It 'embeds exact KQL files into compiled sentinel-analytics module' {
        $tempOut = Join-Path ([System.IO.Path]::GetTempPath()) "avd-security-sentinel-$([guid]::NewGuid()).json"
        try {
            $output = az bicep build --file (Join-Path $repoRoot 'bicep/modules/sentinel-analytics.bicep') --outfile $tempOut 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
            $compiled = Get-Content -Path $tempOut -Raw
            $stormKql = Get-Content -Path (Join-Path $repoRoot 'sentinel/rules/avd-connection-storm.kql') -Raw
            $bruteKql = Get-Content -Path (Join-Path $repoRoot 'sentinel/rules/avd-bruteforce-signin.kql') -Raw
            $compiled | Should -Match 'WVDConnections'
            $compiled | Should -Match '270efc09-cd0d-444b-a71f-39af4910ec45'
            $stormKql.Trim() | Should -Not -BeNullOrEmpty
            $bruteKql.Trim() | Should -Not -BeNullOrEmpty
        }
        finally {
            if (Test-Path $tempOut) { Remove-Item $tempOut -Force }
        }
    }

    It 'ships lab and enterprise bicepparam files and Remove-AvdSecurityTier.ps1' {
        Test-Path (Join-Path $repoRoot 'parameters/lab.bicepparam') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'parameters/enterprise.bicepparam') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'scripts/Remove-AvdSecurityTier.ps1') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'docs/cost-model.md') | Should -BeTrue
    }
}

Describe 'Export-AvdSecurityOutputs.ps1' {
    It 'emits valid avd-security-outputs/v1 matching schema and redacts GUIDs' {
        $scriptPath = Join-Path $repoRoot 'scripts/Export-AvdSecurityOutputs.ps1'
        $schemaPath = Join-Path $repoRoot 'contracts/avd-security-outputs.schema.json'
        $sampleId = '/subscriptions/11111111-2222-3333-4444-555555555555/providers/Microsoft.Authorization/policyAssignments/avd-sec-kv-softdelete-11111111-2222-3333-4444-555555555555'
        $result = & $scriptPath -CostProfile 'lab' -CloudProfile 'commercial' -DefenderPlansDeployed $false -DefenderTier 'Unchanged' -PolicyEffect 'Audit' -SentinelEnabled 'false' -PolicyAssignmentIds @($sampleId)

        $json = $result | ConvertTo-Json -Depth 5
        Test-Json -Json $json -SchemaFile $schemaPath | Should -BeTrue
        $result.sentinelEnabled | Should -BeFalse
        $result.policyAssignmentNames[0] | Should -Be 'avd-sec-kv-softdelete-<redacted-guid>'
        $json | Should -Not -Match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    }

    It 'rejects invalid NamePrefix values' {
        $scriptPath = Join-Path $repoRoot 'scripts/Export-AvdSecurityOutputs.ps1'
        { & $scriptPath -NamePrefix 'Contoso_Prod!' } | Should -Throw
    }
}

Describe 'Invoke-AvdSecurityAudit.ps1' {
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

        $unknownKey = @{
            trustedLaunch                        = $true
            rdpRedirectionRestricted             = $true
            screenCaptureProtectionEnabled       = $true
            edrPresent                           = $true
            fslogixAvExclusionsConfigured        = $true
            keyVaultSoftDeleteAndPurgeProtection = $true
            rbacLeastPrivilegeVerified           = $true
        }
        { & $scriptPath -InputData $unknownKey } | Should -Throw
    }

    It 'flags missing controls with fail/warn counts and remediation hints' {
        $scriptPath = Join-Path $repoRoot 'scripts/Invoke-AvdSecurityAudit.ps1'
        $nonCompliant = @{
            trustedLaunchEnabled                 = $false
            rdpRedirectionRestricted             = $false
            screenCaptureProtectionEnabled       = $false
            edrPresent                           = $false
            fslogixAvExclusionsConfigured        = $false
            keyVaultSoftDeleteAndPurgeProtection = $false
            rbacLeastPrivilegeVerified           = $false
        }

        $report = & $scriptPath -InputData $nonCompliant
        $report.summary.total | Should -Be 7
        $report.summary.pass | Should -Be 0
        $report.summary.warn | Should -Be 2
        $report.summary.fail | Should -Be 5
        ($report.checks | Where-Object { $_.status -ne 'pass' } | ForEach-Object { $_.remediationHint }).Count | Should -Be 7
    }
}
