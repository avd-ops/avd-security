# Cost Model (`avd-security`)

`avd-security` follows the family **no-spend-without-approval** and **never-leave-the-meter-running** guardrails:

| Component | `lab` (`Auto`) | `enterprise` |
|---|---|---|
| Defender for Cloud (`VirtualMachines`) | **Not written** (leaves existing subscription tier unchanged; never downgrades) | `Standard` (`subPlan: P1`, per-VM/hour) |
| Defender for Cloud (`KeyVaults`) | **Not written** | `Standard` (per-transaction) |
| Defender for Cloud (`StorageAccounts`) | **Not written** | `Standard` (`DefenderForStorageV2`, `OnUploadMalwareScanning: False`, `SensitiveDataDiscovery: False` by default) |
| Azure Policy assignments (3 built-ins) | `Audit` (\$0) | `Deny` (\$0) |
| Microsoft Sentinel analytics rules | Disabled (`enableSentinel: false`) | Opt-in (`enableSentinel: false` by default; requires an existing Sentinel-onboarded workspace) |

## Cost Controls

- `defenderTierOverride = 'Standard'` is ignored when `costProfile = 'lab'` (`deployDefenderPlans` remains `false`).
- `OnUploadMalwareScanning` on Storage is off by default (`enableStorageMalwareScanning = false`) to avoid per-GB scan charges.
- Use [Remove-AvdSecurityTier.ps1](../scripts/Remove-AvdSecurityTier.ps1) (supports `-WhatIf`) to reset Defender plans back to `Free` after an enterprise lab test.
