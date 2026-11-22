# Lessons Learned (`avd-security`)

1. **Never downgrade Defender in `lab`:** A `lab` (`Auto`) profile must not write `Microsoft.Security/pricings` `Free` over an existing subscription (which silently downgrades paid protection). When `Standard` is enabled in `enterprise`, explicitly pin `subPlan: 'P1'` for `VirtualMachines` and disable `OnUploadMalwareScanning` / `SensitiveDataDiscovery` on `StorageAccounts` by default.
2. **Never coerce posture evidence with `[bool]`:** In PowerShell, `[bool]"false"` evaluates to `$true`. Validate self-reported inputs against [avd-security-input.schema.json](../contracts/avd-security-input.schema.json) (`Test-Json`) and enforce `-is [bool]`, or consume `avd-current-state` `C11` facts directly (`mode: "c11-facts"`).
3. **Verify built-in Azure Policy definitions against a live subscription (`b20261122-1839`):**
   - `404c3081-a854-4457-ae30-26a93ef943f9` (*Secure transfer to storage accounts*) returned `PolicyDefinitionNotFound`; Storage minimum TLS 1.2 (`fe83a0eb-a853-422d-aac2-1bffd182c5d0`) remains active.
   - `83a86a26-fd1f-447c-b59d-e51f44264114` (*Network interfaces should not have public IPs*) is parameterless (`UndefinedPolicyParameter` when passing `effect`), so pass `parameters: {}` and use `enforcementMode: 'DoNotEnforce'` in `Audit`/`lab` mode.
4. **Sandbox queue `record` parity:** Non-`avd-landing-zone` sandbox items must set `"record": "none"` (enforced by `New-AvdSandboxBatch.ps1` and warned on by `avd-sandbox/queue/build_queue.py`).
