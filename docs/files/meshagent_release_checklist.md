# MeshAgent Release Checklist

Quick reference for preparing and publishing a branded MeshAgent build.

## Pre-Build
- [ ] Confirm `branding_config.local.json` is current (Mesh ID, Server ID, service/display names, version strings).
- [ ] Run `python .\tools\generate_branding_assets.py --repo-root . --config .\branding_config.local.json` to validate the branding config and refresh generated assets.
- [ ] Update signer allow-lists if new certificates will be used (`tools\SignerAllowlist.ps1`).
- [ ] Ensure Visual Studio 2022 with the C++ toolchain, Windows SDK, and Python 3 are installed on the build host.

## Build & Verification
- [ ] Build the StealthLab outputs with `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`.
- [ ] Run targeted Node contracts for touched surfaces, for example `node test/kvm_audit_findings_contract.js`.
- [ ] Run any release-specific native validation from the built `MeshService-2022.exe`; do not use PowerShell build wrappers.
- [ ] Review verification logs and any health report output captured for the release.
- [ ] Signed builds: validate certificates with `tools\SignerAllowlist.ps1` or `osslsigncode verify`.

## Packaging
- [ ] Stage `MeshService64.exe`, `MeshService.exe`, `diagsvc.dll`, and `WinDiagnosticHost.msh` into a timestamped bundle under `dist\`.
- [ ] Generate `checksums.txt` from the staged files and archive the verification output beside the bundle.
- [ ] Archive the bundle, verification output, checksums, and any delivery metadata with the release notes.

## Deployment Prep
- [ ] Capture baseline service health after installation with native service and agent validation commands.
- [ ] If replacing agents in-place, use the native lifecycle engine to quiesce/update/restart while preserving `.msh` and `.conf`.
- [ ] Stage a rollback package and validate rollback through the native lifecycle path.

## MeshCentral Upload
- [ ] Copy `MeshService64.exe`, `MeshService.exe`, and `WinDiagnosticHost.msh` into `..\meshcentral-data\agents\` or `/opt/meshcentral/meshcentral-data/agents/` on the remote host.
- [ ] If you are serving pre-signed binaries, mirror the executables into `..\meshcentral-data\signedagents\`.
- [ ] Restart MeshCentral or use the server's native service manager to flush cached downloads.
- [ ] Confirm the served MeshCentral binary hash matches the local StealthLab build hash.
- [ ] Download the agent from the portal (or via `meshctrl AgentDownload --type 4`), install it on a test endpoint, and verify the svchost-only service metadata.

## Post-Deployment
- [ ] File the verification artefacts (digest, verify logs, health check report) with the release ticket.
- [ ] Monitor the MeshCentral device list and telemetry for anomalies during the rollout window.
