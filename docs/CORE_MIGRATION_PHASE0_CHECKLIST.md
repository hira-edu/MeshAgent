# Core Migration Phase 0 – Stabilization Checklist

**Purpose:** lock down sensitive provisioning data, capture a reproducible baseline build, and record where evidence is stored before the deeper migration work begins. All checklist items tie back to the Phase 0 bullets in `CORE_MIGRATION_MASTER_PLAN.md` and `branding_build_overhaul.md`.

- **Branch:** `feature/core-migration`
- **Maintainer:** Codex automation thread
- **Last updated:** 2025-10-24

## Control Checklist

| Item | Command / Evidence | Status | Artifact / Log Location | Notes |
| --- | --- | --- | --- | --- |
| Quarantine live provisioning data | `.gitignore` entries for `branding_config.local.json`, `WinDiagnosticHost.msh`, `meshcore/generated/` | ? Complete | n/a | Verified against `.gitignore` (2025-10-24) and staged deletions of generated headers. |
| Branch + CI sanity build | `msbuild MeshAgent-2022.sln /m /p:Configuration=StealthLab /p:Platform=x64 /p:DeviceGroup=default` | ?? In progress | Logs to `out/baseline/<date>/msbuild-StealthLab.log` | Branch exists; CI wiring + artifact upload still pending. |
| Baseline regression run | `pwsh ./test.ps1 -Configuration StealthLab -ReportPath verification/baseline` | ? Pending | `out/baseline/<date>/verification/` | Blocked until CI job above has stable binaries. |
| Packaging snapshot | `pwsh ./build_complete.ps1 -Configuration StealthLab -ArchiveTag baseline` | ? Pending | `dist/baseline/<date>/` | Runs only after regression evidence captured; zip + manifest stored alongside verification logs. |
| Evidence retention | `Compress-Archive out/baseline/<date> dist/baseline/<date>` | ?? Defined | `artifacts/stabilization/<date>/baseline-evidence.zip` | Keep at least two historical baselines for diffing Phase 4 packaging outputs. |

## Artifact & Log Storage

- **Live workspace:** `out/baseline/<YYYYMMDD>/` for builds + regression logs, `dist/baseline/<YYYYMMDD>/` for packaged outputs.
- **Long-term retention:** zip the two folders above into `artifacts/stabilization/<YYYYMMDD>/baseline-evidence.zip`.
- **Access control:** `artifacts/` stays out of git; upload bundles to the internal share (MeshCentral ops drop location) after each refresh.
- **Rotation:** keep the latest two baselines on disk; archive older ones to cold storage.

## Procedure References

1. **Sanity build**
   ```powershell
   msbuild MeshAgent-2022.sln `
       /m `
       /p:Configuration=StealthLab `
       /p:Platform=x64 `
       /p:DeviceGroup=default `
       /fileLoggerParameters:LogFile=out/baseline/$(Get-Date -Format yyyyMMdd)/msbuild-StealthLab.log
   ```
   - Ensure `meshcore/generated/meshagent_branding.h` does **not** exist before the build to prove we are sourcing config through the controlled embedding routine.

2. **Regression sweep**
   ```powershell
   pwsh ./test.ps1 `
       -Configuration StealthLab `
       -ReportPath out/baseline/$(Get-Date -Format yyyyMMdd)/verification `
       -StrictBranding
   ```
   - Upload `verify-report.json` + `verify-log.txt` into the same baseline folder; manifests become the comparison point for later phases.

3. **Packaging snapshot**
   ```powershell
   pwsh ./build_complete.ps1 `
       -Configuration StealthLab `
       -ArchiveTag baseline `
       -OutputRoot dist/baseline/$(Get-Date -Format yyyyMMdd)
   ```
   - Copy the SHA256 manifest + signer audit into the artifacts zip so we can prove parity when multi-group packaging lands (Phase 4).

## Outstanding Gaps

- CI definition (GitHub Actions + self-hosted runner) still needs to point to `feature/core-migration` and publish the baseline logs to blob storage.
- Regression + packaging steps depend on the sanitized build; both should remain blocked until the CI job is producing artifacts reliably.
- Need automation to prune `artifacts/stabilization/*` when more than two baselines exist locally (script TBD).
