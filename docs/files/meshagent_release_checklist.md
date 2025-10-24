# MeshAgent Release Checklist

Quick reference for preparing and publishing a branded MeshAgent build.

## Pre-Build
- ✅ Confirm `branding_config.json` is current (Mesh ID, Server ID, service/display names, version strings).
- ✅ Run `pwsh .\tools\validate_branding_config.ps1` to catch schema issues before the build.
- ✅ Update signer allow-lists if new certificates will be used (`tools/SignerAllowlist.ps1`).
- ✅ Ensure PowerShell 5.1+ and the Visual Studio 2022 C++ toolchain are installed on the build host.

## Build & Verification
- ?? (Optional) Produce Release artefacts for the comprehensive suite:
  ```powershell
  $msbuild = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
  & $msbuild MeshAgent-2022.sln /p:Configuration=Release /p:Platform=x64 /m /nologo
  & $msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=Release /p:Platform=Win32 /m /nologo
  pwsh .\test_comprehensive.ps1
  ```
  ```powershell
  .\build_complete.ps1 -RunHealthCheck -HealthCheckArgs @{ InstallPath = 'C:\\ProgramData\\DiagnosticHost' }
  ```
  If you omit `InstallPath`, expect the probe to finish with one warning and one failure for the missing installed binary.
- ✅ Review `dist\<bundle>\verification\verify-log.txt`, `verify-report.json`, and (if produced) `health_report.json`.
- ✅ (Signed builds) Validate certificates with `tools\SignerAllowlist.ps1` or `osslsigncode verify`.

## Packaging
- ? Collect the artefacts from `dist\MeshAgent_Stealth_<timestamp>\` (diagsvc.dll, MeshService executables, verification folder, digests, manifest, README).
- ? Run `pwsh .\tools\create_release_package.ps1` (use `-IncludePdb:$false` when you do not need symbols).
- ? Archive `verification\`, digests, manifest, health report, and `out\deliverables\MeshAgent-YYYY-MM-DD\` (hashes, metadata, ZIP) with the release notes.

## Deployment Prep
- ✅ Use `tools\health_check.ps1` against a staging node to capture baseline service health after installation.
- ✅ If replacing agents in-place, uninstall gracefully with `tools\uninstall.ps1 -ArchivePath <path>` before redeploying.
- ✅ Stage a rollback package and test `tools\rollback_update.ps1 -SourcePath <zip>`.

## MeshCentral Upload
- ✅ Copy `diagsvc.dll` to `meshcentral-data/agents-custom/meshagent_win32_x64.exe` (and companion executables to `meshcentral-data/agents/`).
- ✅ Restart MeshCentral (`systemctl restart meshcentral`) and verify the download link serves the new build.
- ✅ Download the agent from the portal, install it on a test endpoint, and confirm check-in + service metadata.

## Post-Deployment
- ✅ File the verification artefacts (digest, verify logs, health check report) with the release ticket.
- ✅ Monitor the MeshCentral device list and telemetry for anomalies during the rollout window.
