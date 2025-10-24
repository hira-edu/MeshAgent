# MeshAgent Branding & Build Overhaul

## Objectives
- Eliminate stale branding and provisioning data across all build outputs.
- Automate packaging so release artifacts always reflect the latest signed binaries.
- Bundle cleanup/update tooling to standardize endpoint rollouts.
- Establish cross-platform build parity (Visual Studio & MinGW) with branding validation.

## Pain Points (as of 2025-10-23)
- Branding header regenerates separately from MSBuild, so DLL/EXE packaging can ship outdated service IDs or names.
- `.msh` provisioning lacks the custom `meshServiceName`, leaving services registered as `Mesh Agent`.
- `dist/` ZIPs persist between runs without freshness checks, encouraging accidental re-use.
- Cleanup/update scripts live outside the delivered bundle, so endpoint hygiene varies.
- MinGW build path does not embed provisioning data or validate resources, breaking Linux-hosted auto-update flows.
- Regression tooling (`test.ps1`) does not compare branding_config against actual binaries, reducing confidence.

## Workstreams & TODOs

### 1. Provisioning & Branding Hardening
- [x] Extend `tools/embed_provisioning*.ps1` to emit `meshServiceName`, `displayName`, and cleanup/install script hints in both header and `.msh`.
- [x] Update `branding_config.schema` and add pre-build validation so new fields are enforced.
- [x] Ensure header write timestamp precedes any MSBuild invocation; fail if generated header is older than outputs.
- [x] Surface warnings when branding config fields differ from compiled resource metadata.

### 2. Build & Packaging Automation
- [x] Modify `build.ps1`, `build_complete.ps1`, and `build_single_installer.ps1` to auto-run embedding when inputs change and to abort on stale branding.
- [x] Purge or version `dist/` outputs before packaging to avoid carrying forward obsolete binaries.
- [x] Add inclusion of `tools/cleanup_old_agents.ps1` and a signed "force update" helper to packaged ZIPs with README guidance.
- [x] Wire checksum generation + signing verification directly into the packaging step (bundle digest + signer audit now emitted to `dist/`).

### 3. Verification & Regression Suite
- [x] Enhance `test.ps1` (or create `tools/verify_branded_build.ps1`) to validate service name, display name, Mesh ID, Server ID, version info, and signer thumbprints against `branding_config.json`. *(version info/signature checks pending)*
- [x] Add binary string/UTF-16 scans ensuring new hashes and service names exist in DLL/EXE artifacts.
- [x] Capture verification logs/checksums alongside release ZIPs for audit trail (`verification/verify-log.txt` + `verify-report.json` now bundled and hashed).
- [x] Integrate regression script into build pipeline documentation / CI hook.

### 4. Cross-Platform Build Parity
- [x] Update `build-windows-mingw.sh` to call an embedding routine (PowerShell Core or Python) prior to GCC.
- [x] Add post-build validation (e.g., `strings`, `osslsigncode` checks) to confirm ANSI/UTF-16 resources in MinGW outputs.
- [x] Document MinGW prerequisites and troubleshooting for MeshCentral server auto-update flows.

### 5. Documentation & Operator Guidance
- [x] Refresh `DEPLOYMENT_GUIDE.md` and `AGENTS.md` with the new pipeline, verification steps, and endpoint prep sequence.
- [x] Add a quick-reference checklist for uploading to MeshCentral and pushing self-update.
- [x] Capture MinGW/Linux build notes in a dedicated section or appendix.

## Detailed Implementation Notes (Open Items)

### 1. Provisioning & Branding Hardening
- Surface mismatch warnings by teaching `tools/validate_branding_config.ps1` (or a sibling helper) to inspect the freshly built binaries with `[System.Diagnostics.FileVersionInfo]::GetVersionInfo`. Compare `FileDescription`, `ProductName`, `CompanyName`, and service resource strings against the JSON payload already validated in-memory.
- Reuse `tools/ResourceProbe.ps1` to fish the UTF-16 service name/resource exports out of `MeshService64.exe` and `MeshServiceHost64.dll`. When the probe cannot find a string, emit `Write-Warning` instead of hard failing so build remains recoverable.
- Bubble the warning count up to `build_complete.ps1` via a lightweight JSON/CLIXML report (`out/build/branding_diff_report.json`). Packaging scripts can treat a non-zero warning count as a soft failure unless `-StrictBranding` is supplied.

### 2. Build & Packaging Automation
- Done: `build_complete.ps1` now walks the staged package, computes SHA256 digests for every file, and emits `<bundle>.sha256` plus `<bundle>-manifest.json` into both the package folder and `dist/`.
- Done: All packaged EXE/DLL binaries are checked against `tools/SignerAllowlist.ps1`; enforcement failures halt the build, while relaxed mode records warnings in the manifest and console output.
- Done: `tools/Build-Release.ps1` ingests the bundle audit artifacts, propagating digest metadata and signer status into `release-manifest.json` for downstream verification.

### 3. Verification & Regression Suite
- Done: `test.ps1` now accepts `-ReportPath` and writes `verification/verify-report.json` alongside a tee'd `verify-log.txt`, giving the packaging step structured + human-readable audit trails.
- Done: `build_complete.ps1` stages the `verification/` folder into each bundle, and the digest manifest from Workstream 2 covers these artifacts for downstream integrity checks.
- Done: `DEPLOYMENT_GUIDE.md` documents a GitHub Actions snippet so CI runs the regression suite and publishes verification artifacts automatically.

### 4. Cross-Platform Build Parity
- Done: `build-windows-mingw.sh` invokes the provisioning embed prior to GCC so MinGW builds stay in sync with MSBuild outputs.
- Done: Added `strings`/`osslsigncode` validation with log output (`build/mingw/build-mingw.log`) so MinGW builds flag missing Mesh/Server IDs.
- Done: MinGW prerequisites, package installs, and troubleshooting captured in the deployment guide's "MinGW Build Notes" appendix.

### 5. Documentation & Operator Guidance
- Done: `DEPLOYMENT_GUIDE.md` and `AGENTS.md` both reflect the new pipeline, regression artifacts, and operator helper scripts (`health_check`, `uninstall`, `rollback_update`).
- Done: Added `docs/files/meshagent_release_checklist.md` for release managers; the troubleshooting table now references rollback/uninstall helpers.
- Done: MinGW/Linux notes consolidated in documentation so Linux-hosted MeshCentral operators have parity guidance.

## Tracking & Status
- **Owner:** Codex automation effort (current session)
- **Last Updated:** 2025-10-24
- **Next Action:** Extend regression coverage to validate version metadata/signature fingerprints once code signing is available.

