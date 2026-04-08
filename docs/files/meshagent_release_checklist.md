# MeshAgent Release Checklist

Quick reference for preparing and publishing a branded MeshAgent build.

## Pre-Build
- [ ] Confirm `branding_config.local.json` is current (Mesh ID, Server ID, service/display names, version strings).
- [ ] Run `python .\tools\generate_branding_assets.py --repo-root . --config .\branding_config.local.json` to validate the branding config and refresh generated assets.
- [ ] Update signer allow-lists if new certificates will be used (`tools\SignerAllowlist.ps1`).
- [ ] Ensure Visual Studio 2022 with the C++ toolchain, Windows SDK, and Python 3 are installed on the build host.

## Build & Verification
- [ ] Build the StealthLab outputs with `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`.
- [ ] Run `pwsh .\test.ps1 -ReportPath .\dist\verify-report.json`.
- [ ] Optional comprehensive Release regression:
  ```powershell
  $msbuild = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
  & $msbuild MeshAgent-2022.sln /p:Configuration=Release /p:Platform=x64 /m /nologo
  & $msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=Release /p:Platform=Win32 /m /nologo
  pwsh .\test_comprehensive.ps1
  ```
- [ ] Optional post-install health probe:
  ```powershell
  pwsh .\tools\health_check.ps1 -ServiceName WinDiagnosticHost -ReportPath .\dist\post-deploy-health.json
  ```
- [ ] Review `verify-log.txt`, `verify-report.json`, and any `health_report.json` output captured for the release.
- [ ] Signed builds: validate certificates with `tools\SignerAllowlist.ps1` or `osslsigncode verify`.

## Packaging
- [ ] Stage `MeshService64.exe`, `MeshService.exe`, `diagsvc.dll`, and `WinDiagnosticHost.msh` into a timestamped bundle under `dist\`.
- [ ] Generate `checksums.txt` from the staged files and archive the verification output beside the bundle.
- [ ] Archive the bundle, verification output, checksums, and any delivery metadata with the release notes.

## Deployment Prep
- [ ] Use `tools\health_check.ps1` against a staging node to capture baseline service health after installation.
- [ ] If replacing agents in-place, uninstall gracefully with `tools\uninstall.ps1 -ArchivePath <path>` before redeploying.
- [ ] Stage a rollback package and test `tools\rollback_update.ps1 -SourcePath <zip>`.

## MeshCentral Upload
- [ ] Copy `MeshService64.exe`, `MeshService.exe`, and `WinDiagnosticHost.msh` into `..\meshcentral-data\agents\` or `/opt/meshcentral/meshcentral-data/agents/` on the remote host.
- [ ] If you are serving pre-signed binaries, mirror the executables into `..\meshcentral-data\signedagents\`.
- [ ] Restart MeshCentral, or rely on `tools\Invoke-RuntimeValidation.ps1` to stop/start `node meshcentral.js` and flush cached downloads.
- [ ] Execute `pwsh .\tools\Invoke-RuntimeValidation.ps1 -MeshCentralRepo '..\MeshCentral' -ReportPath 'verification\phase3\runtime.json' -LogPath 'verification\phase3\runtime.log'` and confirm `MeshCentral Binary Matches StealthLab`.
- [ ] Download the agent from the portal (or via `meshctrl AgentDownload --type 4`), install it on a test endpoint, and verify the svchost-only service metadata.

## Post-Deployment
- [ ] File the verification artefacts (digest, verify logs, health check report) with the release ticket.
- [ ] Monitor the MeshCentral device list and telemetry for anomalies during the rollout window.
