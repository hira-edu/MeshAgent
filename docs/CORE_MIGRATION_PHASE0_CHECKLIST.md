# Core Migration Phase 0 – Stabilization Checklist

**Purpose:** lock down sensitive provisioning data, capture a reproducible baseline build, and record where evidence is stored before the deeper migration work begins. All checklist items roll up to the Phase 0 bullets in `MeshAgent_Project_Plan.md` (with `CORE_MIGRATION_MASTER_PLAN.md` retained for historical context).

- **Branch:** `feature/core-migration`
- **Maintainer:** Codex automation thread
- **Last updated:** 2025-10-26

## Control Checklist

| Item | Command / Evidence | Status | Artifact / Log Location | Notes |
| --- | --- | --- | --- | --- |
| Quarantine live provisioning data | `.gitignore` entries for `branding_config.local.json`, `WinDiagnosticHost.msh`, `meshcore/generated/` | ✅ Complete | n/a | Verified against `.gitignore` (2025-10-24) and staged deletions of generated headers. |
| Branch + CI sanity build | `msbuild MeshAgent-2022.sln /m /p:Configuration=StealthLab /p:Platform=x64 /p:DeviceGroup=default` | ✅ Complete | `out/baseline/20251025/msbuild-StealthLab.log` + GitHub artifact `baseline-out` | `.github/workflows/core-migration-baseline.yml` now runs on every `feature/core-migration` push. |
| Baseline regression run | `pwsh ./test.ps1 -Configuration StealthLab -ReportPath verification/baseline` | ✅ Complete | `out/baseline/20251025/verification/` + workflow artifact `baseline-out/verification` | Local run (2025-10-25) matches the CI layout; warnings captured in `verify-log.txt`. |
| Packaging snapshot | `pwsh ./build_complete.ps1 -Configuration StealthLab -ArchiveTag baseline` | ✅ Complete | `dist/baseline/20251025/` + `dist/baseline/20251025.zip` + CI artifact `baseline-dist` | Packaging executed locally (StrictBranding) and mirrored by the CI job (`core-migration-baseline.yml`). |
| Evidence retention | `Compress-Archive out/baseline/<date> dist/baseline/<date>` | ✅ Complete | `artifacts/stabilization/20251025/baseline-evidence.zip` + CI artifact `baseline-evidence/baseline-ci-<run>.zip` | Local zip uploaded to the MeshCentral share; CI produces an identical bundle per run for auditing. |

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

- Need automation to prune `artifacts/stabilization/*` and the GitHub `baseline-*` artifacts when more than two baselines exist locally (script + retention policy TBD).
- Mirror the CI-generated `baseline-*` bundles into the MeshCentral ops share automatically so release managers do not have to download from GitHub manually.

