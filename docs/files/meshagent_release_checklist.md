# MeshAgent Release Checklist

Quick reference for preparing and publishing a branded MeshAgent build.

## Pre-Build
- âœ… Confirm `branding_config.local.json` is current (Mesh ID, Server ID, service/display names, version strings).
- âœ… Run `pwsh .\tools\validate_branding_config.ps1` to catch schema issues before the build.
- âœ… Update signer allow-lists if new certificates will be used (`tools/SignerAllowlist.ps1`).
- âœ… Ensure PowerShell 5.1+ and the Visual Studio 2022 C++ toolchain are installed on the build host.

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
- âœ… Review `dist\<bundle>\verification\verify-log.txt`, `verify-report.json`, and (if produced) `health_report.json`.
- âœ… (Signed builds) Validate certificates with `tools\SignerAllowlist.ps1` or `osslsigncode verify`.

## Packaging
- ? Collect the artefacts from `dist\MeshAgent_Stealth_<timestamp>\` (diagsvc.dll, MeshService executables, verification folder, digests, manifest, README).
- ? Run `pwsh .\tools\create_release_package.ps1` (use `-IncludePdb:$false` when you do not need symbols).
- ? Archive `verification\`, digests, manifest, health report, and `out\deliverables\MeshAgent-YYYY-MM-DD\` (hashes, metadata, ZIP) with the release notes.

## Deployment Prep
- âœ… Use `tools\health_check.ps1` against a staging node to capture baseline service health after installation.
- âœ… If replacing agents in-place, uninstall gracefully with `tools\uninstall.ps1 -ArchivePath <path>` before redeploying.
- âœ… Stage a rollback package and test `tools\rollback_update.ps1 -SourcePath <zip>`.

## MeshCentral Upload
- [ ] Run `pwsh .\tools\stage_meshcentral_agents.ps1 -MeshCentralDataPath ''..\meshcentral-data'' -IncludeWin32` (or copy the binaries + `.msh` to `/opt/meshcentral/meshcentral-data/agents/` on the remote host).
- [ ] Restart MeshCentral (or rely on `tools\Invoke-RuntimeValidation.ps1` to stop/start `node meshcentral.js` and flush cached downloads).
- [ ] Execute `pwsh .\tools\Invoke-RuntimeValidation.ps1 -MeshCentralRepo ''..\MeshCentral'' -ReportPath ''verification\phase3\runtime.json'' -LogPath ''verification\phase3\runtime.log''` and confirm `MeshCentral Binary Matches StealthLab`.
- [ ] Download the agent from the portal (or via `meshctrl AgentDownload --type 4`), install it on a test endpoint, and verify the svchost-only service metadata.## Post-Deployment
- âœ… File the verification artefacts (digest, verify logs, health check report) with the release ticket.
- âœ… Monitor the MeshCentral device list and telemetry for anomalies during the rollout window.



