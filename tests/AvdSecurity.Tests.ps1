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

    It 'ships lab and enterprise bicepparam files and KQL rules' {
        Test-Path (Join-Path $repoRoot 'parameters/lab.bicepparam') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'parameters/enterprise.bicepparam') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'sentinel/rules/avd-redirection-anomaly.kql') | Should -BeTrue
        Test-Path (Join-Path $repoRoot 'sentinel/rules/avd-bruteforce-signin.kql') | Should -BeTrue
    }
}

Describe 'Export-AvdSecurityOutputs.ps1' {
    It 'emits avd-security-outputs/v1 and redacts GUIDs in policy assignment IDs' {
        $scriptPath = Join-Path $repoRoot 'scripts/Export-AvdSecurityOutputs.ps1'
        $sampleId = '/subscriptions/11111111-2222-3333-4444-555555555555/providers/Microsoft.Authorization/policyAssignments/avd-sec-kv-softdelete-11111111-2222-3333-4444-555555555555'
        $result = & $scriptPath -CostProfile 'lab' -CloudProfile 'commercial' -DefenderTier 'Free' -PolicyEffect 'Audit' -SentinelEnabled $false -PolicyAssignmentIds @($sampleId)

        $result.schema | Should -Be 'avd-security-outputs/v1'
        $result.costProfile | Should -Be 'lab'
        $result.defenderTier | Should -Be 'Free'
        $result.policyAssignmentNames[0] | Should -Be 'avd-sec-kv-softdelete-<redacted-guid>'
    }
}

Describe 'Invoke-AvdSecurityAudit.ps1' {
    It 'scores a fully compliant estate as 7 pass, 0 warn, 0 fail' {
        $scriptPath = Join-Path $repoRoot 'scripts/Invoke-AvdSecurityAudit.ps1'
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
        $report.schema | Should -Be 'avd-security-posture/v1'
        $report.summary.total | Should -Be 7
        $report.summary.pass | Should -Be 7
        $report.summary.warn | Should -Be 0
        $report.summary.fail | Should -Be 0
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
