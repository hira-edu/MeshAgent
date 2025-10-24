# MeshAgent Release Checklist

Quick reference for preparing and publishing a branded MeshAgent build.

## Pre-Build
- ✅ Ensure `branding_config.json` is up to date (Mesh ID, Server ID, service names, version strings).
- ✅ Update signer allow-list if new certificates are in use (`tools/SignerAllowlist.ps1`).
- ✅ Verify PowerShell 5.1+ and Visual Studio 2022 toolchain are installed on the build host.

## Build & Verification
- ▶️ Run `.\build.ps1 -StealthLab` (or desired configuration). Review console output for warnings.
- ▶️ Execute `pwsh .\test.ps1 -ReportPath .\dist\verify-report.json`; confirm 0 failures and capture warnings.
- 📄 Check `dist\<bundle>\verification\verify-log.txt` and `verify-report.json` for records.
- 🔐 (Signed builds) Validate certificates with `tools\SignerAllowlist.ps1` or `osslsigncode verify`.

## Packaging
- 📦 Generate the package with `.\build_complete.ps1` (or `.\tools\prepare_meshcentral_agent.ps1` when targeting MeshCentral).
- 🧾 Inspect `dist\<bundle>\<bundle>.sha256` and `<bundle>-manifest.json` for digest/signature metadata.
- 🛠️ Archive bundle logs (`verification\`, digests, manifest) alongside release notes.

## Deployment Prep
- 🔁 Use `tools\health_check.ps1` against a staging node to capture baseline service health.
- ♻️ If replacing agents in-place, uninstall gracefully with `tools\uninstall.ps1 -ArchivePath <path>` before redeploying.
- 🔄 For rollback planning, stash a known-good package and test `tools\rollback_update.ps1 -SourcePath <zip>`.

## MeshCentral Upload
- 📤 Copy `diagsvc.dll` to `meshcentral-data/agents-custom/meshagent_win32_x64.exe` (and companion EXEs to `meshcentral-data/agents/`).
- 🔁 Restart MeshCentral (`systemctl restart meshcentral`) and verify the download link serves the new build.
- 🧪 Download the agent from the portal, install, and confirm check-in + service metadata on a test endpoint.

## Post-Deployment
- 📋 File the verification artifacts (digest, verify logs, health check report) with the release ticket.
- 🛰️ Monitor the MeshCentral device list for anomalies during the rollout window.
