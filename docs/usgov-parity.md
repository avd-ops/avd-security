# Azure US Government (`usgov`) Parity

`avd-security` supports `cloudProfile: 'commercial' | 'usgov'` aligned with `avd-assess` C19 (`cloud-environments.json`):

| Setting | `commercial` | `usgov` |
|---|---|---|
| `azCloudName` | `AzureCloud` | `AzureUSGovernment` |
| `logAnalyticsWorkspaceSuffix` | `opinsights.azure.com` | `opinsights.azure.us` |
| Built-in Azure Policy GUIDs (`tenantResourceId`) | Same global built-in GUIDs | Same global built-in GUIDs |
| Defender for Cloud plans (`VirtualMachines`, `KeyVaults`, `StorageAccounts`) | Supported | Supported |
| Sentinel scheduled KQL rules (`Microsoft.SecurityInsights/alertRules`) | Opt-in (`enableSentinel`) | Opt-in (`enableSentinel`) |

Use [parameters/usgov-lab.bicepparam](../parameters/usgov-lab.bicepparam) for `usgov` lab deployments (leaves existing Defender plans untouched and assigns Policy in `Audit` mode).
