# PSScriptAnalyzer settings for avd-security (PowerShell 7+ across Windows, macOS, and Linux).
@{
  Severity     = @('Error', 'Warning', 'ParseError')
  ExcludeRules = @(
    'PSAvoidUsingWriteHost'
  )
  Rules        = @{
    PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('7.0') }
    PSUseCompatibleCommands = @{
      Enable         = $true
      TargetProfiles = @(
        'ubuntu_x64_18.04_7.0.0_x64_3.1.2_core'
        'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
      )
      IgnoreCommands = @('az', 'Test-Json')
    }
  }
}
