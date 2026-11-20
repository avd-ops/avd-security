# avd-security

Part of [avd-ops](https://avd-ops.dev/), the open toolkit for Azure Virtual Desktop.

AVD security control plane (Defender for Cloud, Microsoft Sentinel KQL detections, Azure Policy baselines) and schema-validated posture scoring (`avd-security`).

> [!WARNING]
> **Community research project. Use at your own risk. No warranty.**
>
> - This is my own personal project, built on my own time **for research and learning**. It is **not affiliated with, endorsed by or supported by my employer**, Liquidware, ServiceNow or Microsoft, and it does not represent their views, products or guidance.
> - Test it first in a dedicated lab subscription and tenant before using it in production; you are responsible for reviewing the code and validating it for your environment.
> - It is provided **"as is", without warranty of any kind**, under the [MIT License](LICENSE). You use it at your own risk.
> - **Contributions and forks are welcome and encouraged.** See [Contributing](#contributing).

## How it connects

| Direction | Repo | Relationship |
|---|---|---|
| Front door | [avd-ops](https://github.com/avd-ops/avd-ops#readme) | Overview and [security review map](https://avd-ops.dev/security.html) |
| Standards | [avd-assess](https://github.com/avd-ops/avd-assess#readme) | Supplies `ref:*` security claims and `asm-*` check IDs |
| Inventory | [avd-current-state](https://github.com/avd-ops/avd-current-state#readme) | Collects live estate facts (C11) that feed posture scoring |

## What it does

1. **Security Control Plane (`bicep/`, `sentinel/`):**
   - **Defender for Cloud (`bicep/modules/defender-plans.bicep`):** In `lab` (`Auto`), leaves existing subscription Defender plans untouched so it never downgrades paid protection or incurs spend. In `enterprise`, configures `Standard` (`VirtualMachines` P1, `KeyVaults`, `StorageAccounts` V2 with `OnUploadMalwareScanning` and `SensitiveDataDiscovery` disabled by default). See [docs/cost-model.md](docs/cost-model.md).
   - **Azure Policy (`bicep/modules/policy-assignments.bicep`):** Assigns 3 built-in policies (Key Vault soft-delete, Storage HTTPS secure transfer, NIC no public IP) with `Audit` in `lab` and `Deny` in `enterprise` (supports `policyNotScopes`).
   - **Microsoft Sentinel (`bicep/modules/sentinel-analytics.bicep`):** Opt-in (`enableSentinel = false` by default) KQL rules loaded directly from `sentinel/rules/` (`avd-connection-storm.kql` and `avd-bruteforce-signin.kql`) targeting an existing Sentinel-onboarded Log Analytics workspace.
   - Currently targets `commercial` cloud (`usgov` policy parity is pending C19 verification).
2. **Self-Reported Posture Scoring (`scripts/Invoke-AvdSecurityAudit.ps1`, PowerShell 7+):**
   - Validates caller-supplied evidence (`-InputData` or `-FixturePath`) against [avd-security-input.schema.json](contracts/avd-security-input.schema.json) (strict booleans, no string coercion, no unknown keys) and emits `avd-security-posture/v1` (`mode: "self-reported"`) mapped to verified `avd-assess` claims and `asm-*` check IDs.
3. **Redacted Outputs & Cleanup (`scripts/`):**
   - [Export-AvdSecurityOutputs.ps1](scripts/Export-AvdSecurityOutputs.ps1) emits `avd-security-outputs/v1` with GUIDs redacted.
   - [Remove-AvdSecurityTier.ps1](scripts/Remove-AvdSecurityTier.ps1) resets Defender plans back to `Free` (supports `-WhatIf`).

## Quickstart

Requires PowerShell 7+ (`pwsh`) and Bicep CLI.

```powershell
# Validate Bicep templates
az bicep build --file bicep/main.bicep

# Run offline Pester verification suite
Invoke-Pester -Path tests/AvdSecurity.Tests.ps1 -Output Detailed
```

## Docs

- Agent instructions & guardrails: [AGENTS.md](AGENTS.md)
- Cost model & teardown: [docs/cost-model.md](docs/cost-model.md)
- Contracts: [avd-security-outputs.schema.json](contracts/avd-security-outputs.schema.json), [avd-security-posture.schema.json](contracts/avd-security-posture.schema.json), [avd-security-input.schema.json](contracts/avd-security-input.schema.json)

## Contributing

Fork it, open an issue or a pull request. Follow the family guardrails in [AGENTS.md](AGENTS.md): no tenant IDs, secrets, domains or customer names, and propose changes via pull request only. Contributions are accepted under the [MIT License](LICENSE).

## License and disclaimer

[MIT](LICENSE). Community research project, provided as is, use at your own risk, not affiliated with the author's employer, Liquidware, ServiceNow or Microsoft.
