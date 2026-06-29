# MeshAgent Svchost Fix Verification – Test Evidence

## Environment
- Host shell: non-elevated PowerShell via Codex CLI (`BuiltIn\Administrators` present as *deny only*)
- Privilege strategy: individual commands elevated with `Start-Process … -Verb RunAs`
- Repo base commit: `dbd6bf6d3819b3300c9f35f42a782d5bb75ec250` (`master`)
- Toolchain: Visual Studio 2022 Community (MSVC 14.44.35207), `msbuild` CLI

## Build Results
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m`
  - Status: **success**
  - Artifact: `meshservice\x64\StealthLab_DLL\MeshService-2022.dll`
  - Export verification: `dumpbin /exports` shows single export `Stealth_SvchostServiceMain`
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64 /m`
  - Status: **success** (warnings limited to bundled duktape `sprintf`/`sscanf`)
  - Artifact: `meshservice\x64\StealthLab\MeshService-2022.exe`

## Installation / Update Evidence

| Scenario | Evidence | Notes |
| --- | --- | --- |
| Manual install (PowerShell helper) | `docs/testing/evidence/deploy_install.log` | Creates `C:\\ProgramData\\DiagnosticHost`, copies DLL, registers service & firewall, disables PS logging |
| DLL unload / reload | `svchost_modules.txt`, `svchost_modules_after_start.txt` | Confirms DLL present while service running, absent after stop, restored after restart |
| Locked-file swap | Manual `Copy-Item` during service stop (hash preserved via `Get-FileHash`) | Demonstrates safe DLL rotation |
| Cleanup | `cleanup_uninstall.log` + post-checks (`Get-Service`, `Test-Path`, `Get-NetFirewallRule`) | Service, directory, firewall rules removed |
| Reinstall loop | `deploy_reinstall.log`, `svchost_modules_reinstall.txt` | Validates reinstall after cleanup |
| SCM creation | `sc_create.log` | Direct `sc.exe create` run to confirm syntax/permissions |

## Tooling Updates
- `deploy_stealth_agent.ps1`
  - Adds SCM creation (`sc.exe create .`) for svchost mode, sets `ServiceDllUnloadOnStop`
  - Clears existing `Windows Diagnostic Host Service - Inbound/Outbound` rules before re-adding
  - New optional `-LogPath` parameter starts a transcript for evidence capture
  - Relies on `sc.exe` defaults for the service account and start mode to avoid headless creation errors; registry writes enforce shared (`0x20`) type and auto-start (`0x2`) post-create
  - Marks install assets with hidden/system attributes and replaces existing payloads safely before copy
- `stealth_antidetect.c`
  - `Stealth_CreateInstallationDirectory()` now falls back to plain `CreateDirectoryW` when the security descriptor creation fails, preventing fatal errors during C++ registration
- `cleanup_old_agents.ps1`
  - Removes diagnostic host firewall rules in addition to legacy `WebRTC Traffic` entries
- Evidence directory (`docs/testing/evidence/`) captures all elevated command transcripts listed above

## Current Gaps / Follow-Up
1. **PowerShell deploy transcript** - ✅ Completed 2025-10-23 via elevated helper; see `docs/testing/evidence/deploy_run.log` for the full transcript.
2. **Native C++ registration** – direct executable registration has been retired; registration must be exercised through the `MeshLifecycleHostW` lifecycle host with elevated end-to-end evidence.
3. **Automated update workflow** – No scripted validation yet of manifest rotation / staged swap tooling; manual safe-swap evidence exists but automated test pending.

## Evidence Inventory
- `docs/testing/evidence/deploy_install.log`
- `docs/testing/evidence/deploy_reinstall.log`
- `docs/testing/evidence/deploy_run.log`
- `docs/testing/evidence/cleanup_uninstall.log`
- `docs/testing/evidence/sc_create.log`
- `docs/testing/evidence/svchost_modules.txt`
- `docs/testing/evidence/svchost_modules_after_start.txt`
- `docs/testing/evidence/svchost_modules_reinstall.txt`

## Artifacts
- `docs/testing/artifacts/svchost-deploy-20251023.zip` – generated bundle (ignored by Git); attach the file as a GitHub release asset for downstream auditors.

