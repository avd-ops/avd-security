# Upstream Sources of Truth and Roadmap

`avd-security` does not invent security standards or threat models from scratch. Normative claims live in [avd-assess](https://github.com/avd-ops/avd-assess#readme) (`references/`), and subject-matter experts are tracked and scored in [avd-second-brain](https://github.com/avd-ops/avd-second-brain/blob/main/docs/knowledge/experts.md). This page maps which upstream sources drive `avd-security` and what is next on the roadmap.

## 1. Normative Standards (the "what")

| Source | Scope in `avd-security` | Where pinned |
|---|---|---|
| **Microsoft Cloud Security Benchmark (MCSB) — AVD Baseline** | Control-plane and workload baseline (`DP-*`, `IM-*`, `LT-*`, `NS-*`, `PA-*`) | `avd-assess` (`ref:mcsb-avd-baseline`) |
| **Microsoft Learn AVD Security & Zero Trust Guides** | Trusted Launch, RDP redirection restrictions, Screen Capture Protection, EDR, FSLogix AV exclusions | `avd-assess` (`ref:avd-security-guide`, `ref:screen-capture-protection`, `ref:zero-trust-avd`) |
| **CIS Microsoft Azure Compute Services & CIS Windows 11/Server Benchmarks** | Subscription compute guardrails and L1/L2 session-host golden-image hardening parity | Target parity for Policy & audit checks |
| **Microsoft Windows Security Baselines & DISA STIGs** | Multi-session OS hardening and future `usgov` / GCC High compliance parity | Target parity for `usgov` (`C19`) |

## 2. Upstream Detection & Policy Repos (the "how" in code)

| Repo | License | Role |
|---|---|---|
| [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) | MIT | Upstream KQL analytics, hunting queries, and workbooks for `SigninLogs`, `WVDConnections`, and `DeviceEvents` / `DeviceFileEvents` |
| [Azure/PSRule.Rules.Azure](https://github.com/Azure/PSRule.Rules.Azure) | MIT | Static Bicep/ARM security rules (`avd-assess` `ref:psrule-azure`) |
| [Azure/FederalAVD](https://github.com/Azure/FederalAVD) | MIT | Commercial and Azure US Government AVD reference patterns |
| Azure Policy built-in definitions | Microsoft | Tenant-level built-in Policy GUIDs (`tenantResourceId`) |

## 3. EUC Security Threat Model & Practitioners

- **Patrick Coble (`@VDIHacker` / VDISEC):** Primary EUC-security reference for the VDI-specific threat model — challenging "secure out of the box" assumptions, multi-session host breakout and redirection abuse, CIS compliance verification on AVD/Windows 365, and quantifying the EDR/security-agent performance tax on session-host density.
- **AVD architecture & automation practitioners:** **Sander Rozemuller**, **Marcel Meurer**, **Freek Berson**, **Travis Roberts**, and **Dean Cefola** — tracked and scored in [avd-second-brain `experts.md`](https://github.com/avd-ops/avd-second-brain/blob/main/docs/knowledge/experts.md).

## 4. What Is Next (Roadmap)

1. **Live C11 fact consumption:** Replace `self-reported` boolean inputs in [Invoke-AvdSecurityAudit.ps1](../scripts/Invoke-AvdSecurityAudit.ps1) with direct consumption of [avd-current-state](https://github.com/avd-ops/avd-current-state#readme) `C11` fact bundles, and pin `avd-security-outputs/v1` + `avd-security-posture/v1` in `avd-assess`.
2. **Expanded Azure Policy pack (`resourceSelectors`):** Add Storage minimum TLS 1.2, Key Vault purge protection, Trusted Launch / vTPM, and disk encryption built-ins scoped via `resourceSelectors` so `Deny` targets AVD resources without blocking unrelated workloads in shared subscriptions.
3. **Host-telemetry Sentinel KQL rules:** Add `DeviceEvents` / `DeviceFileEvents` detections for `\\tsclient\` redirection file-copy abuse, AppLocker/WDAC blocks, and unexpected local administrator group changes (complementing `WVDConnections` storm and `SigninLogs` brute-force/spray rules).
4. **`usgov` Policy parity (`C19`):** Verify every built-in Policy definition GUID and Defender plan in Azure Government against `avd-assess` `cloud-environments.json` before re-enabling `usgov` in [main.bicep](../bicep/main.bicep).
