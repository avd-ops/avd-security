# avd-security

Part of [avd-ops](https://avd-ops.dev/), the open toolkit for Azure Virtual Desktop.

AVD security control plane, posture verification, and threat detection (`avd-security`), spanning `control`, `assess`, and `operate` ([avd-ops decision 0028](https://avd-ops.dev/docs/decisions/0028-add-avd-security.html)).

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
| Front door | [avd-ops](https://github.com/avd-ops/avd-ops#readme) | Overview, [security review map](https://avd-ops.dev/security.html), and platform decisions |
| Orchestrator | [avd-landing-zone](https://github.com/avd-ops/avd-landing-zone#readme) | Invokes `avd-security` Bicep baselines alongside workload deployments |
| Standards | [avd-assess](https://github.com/avd-ops/avd-assess#readme) | Supplies security claims (`C20`, `methods/security.md`) verified by `Invoke-AvdSecurityAudit.ps1` |
| Inventory | [avd-current-state](https://github.com/avd-ops/avd-current-state#readme) | Consumes `security-outputs.json` (`avd-security-outputs/v1`) and `security-posture.json` |
| Remediation | [avd-remediate](https://github.com/avd-ops/avd-remediate#readme) | Consumes failed posture findings for human-approved remediation |

## What it does

1. **Security Control Plane (`bicep/`, `sentinel/`):**
   - Configures Microsoft Defender for Cloud plans (`VirtualMachines`, `KeyVaults`, `StorageAccounts`) with cost-aware `lab` (`Free`) and `enterprise` (`Standard`) profiles.
   - Assigns Azure Policy security baselines tailored to AVD (Key Vault soft-delete, Storage HTTPS/TLS 1.2, and public IP restrictions on NICs) using `Audit` in `lab` and `Deny` in `enterprise`.
   - Deploys optional Microsoft Sentinel scheduled KQL analytics rules (`sentinel/rules/`) for AVD redirection anomalies and brute-force sign-in patterns when a Log Analytics workspace is provided.
   - Supports `commercial` and `usgov` cloud profiles.
2. **Continuous Posture Verification (`scripts/Invoke-AvdSecurityAudit.ps1`):**
   - Evaluates session-host hardening (Trusted Launch/vTPM, RDP redirection restrictions, Screen Capture Protection, Watermarking, Credential Guard, Defender EDR, FSLogix AV exclusions) and control-plane hygiene (Key Vault soft-delete/purge protection, RBAC least-privilege) against `avd-assess` claims.
   - Supports `-InputObject` / `-FixturePath` for offline CI verification as well as live estate inputs.
3. **Redacted Contracts (`contracts/`):**
   - Emits `security-outputs.json` (`avd-security-outputs/v1`) via `scripts/Export-AvdSecurityOutputs.ps1` and `security-posture.json` (`avd-security-posture/v1`) via `scripts/Invoke-AvdSecurityAudit.ps1`, redacting subscription and tenant GUIDs before writing.

## Quickstart

```powershell
# Validate Bicep templates
az bicep build --file bicep/main.bicep

# Run offline Pester verification suite
Invoke-Pester -Path tests/AvdSecurity.Tests.ps1 -Output Detailed
```

## Docs

- Agent instructions & guardrails: [AGENTS.md](AGENTS.md)
- Contracts: [contracts/avd-security-outputs.schema.json](contracts/avd-security-outputs.schema.json), [contracts/avd-security-posture.schema.json](contracts/avd-security-posture.schema.json)

## Contributing

Fork it, open an issue or a pull request. Follow the family guardrails in [AGENTS.md](AGENTS.md): no tenant IDs, secrets, domains or customer names, and propose changes via pull request only. Contributions are accepted under the [MIT License](LICENSE).

## License and disclaimer

[MIT](LICENSE). Community research project, provided as is, use at your own risk, not affiliated with the author's employer, Liquidware, ServiceNow or Microsoft.
