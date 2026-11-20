# Instructions for AI agents

Read this file first, then [CLAUDE.md](CLAUDE.md). Follow the avd-ops family rules at <https://github.com/avd-ops/avd-ops/blob/main/AGENTS.md>.

- **No spend without the owner's exact go.**
- **Never leave the meter running.** Defender for Cloud Standard plans and Sentinel ingestion bill continuously; `lab` profile defaults to `Free` Defender tiers, `Audit` policy effect, and Sentinel rules disabled.
- **Never delete the last copy** of data without a checked copy elsewhere or `-DiscardLastCopy`.
- **No secrets, IDs or names.** Use `contoso.com`, `<tenant-id>`, `10.x`. Never commit real subscription IDs, workspace IDs, or tenant IDs.
- **Pull requests only; the owner merges.** Work on a branch and open a PR; never push directly to `main` after initial bootstrap.
- **Stay in your lane.** `avd-security` owns cross-cutting AVD security controls (Defender for Cloud, Sentinel AVD detections, Azure Policy security baselines) and read-only posture verification under [avd-ops decision 0028](https://avd-ops.dev/docs/decisions/0028-add-avd-security.html). Keep Entra ID in `avd-entra`, Intune profiles in `avd-intune`, hub networking in `avd-networking`, workload resources in `avd-azure`, and destructive remediation in `avd-remediate`.
- **Personal project, not for production, as is, not affiliated with the author's employer, Liquidware, ServiceNow or Microsoft.**
- **American English** in docs, output and comments.
