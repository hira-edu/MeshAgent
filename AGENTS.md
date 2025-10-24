# Repository Guidelines

## Project Structure & Module Organization
- `meshcore/` hosts the cross-platform agent runtime; generated headers live in `meshcore/generated/`.
- `meshservice/` contains Windows service projects, with `MeshService-2022` carrying the svchost and standalone builds (`StealthLab`, `StealthLab_DLL`).
- `tools/` provides PowerShell helpers for provisioning, signing, cleanup, uninstall/rollback (``uninstall.ps1``, ``rollback_update.ps1``), and health verification (``health_check.ps1``); deployment automation lives in ``deploy_stealth_agent.ps1``.
- `docs/testing/` stores validation evidence, plans, and packaged artifacts (`docs/testing/artifacts/`).

## Build, Test, and Development Commands
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m` - build the svchost payload DLL.
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64 /m` - build the standalone executable.
- `pwsh .\deploy_stealth_agent.ps1 -Mode svchost -SourcePath .\meshservice\x64\StealthLab_DLL\MeshService-2022.dll -LogPath .\docs\testing\evidence\<name>.log` - deploy to a test host (requires elevation).
- `pwsh .\tools\cleanup_old_agents.ps1` - purge legacy installs and firewall rules prior to fresh validation.
- `pwsh .\tools\validate_branding_config.ps1` - schema/hex validation gate for branding updates.
- `pwsh .\test.ps1 -BinaryPath dist\MeshAgent_Stealth_YYYYMMDD_HHMMSS` - branding + regression suite for packaged artifacts.
- `pwsh .\tools\health_check.ps1 -ServiceName WinDiagnosticHost -ReportPath .\dist\post-deploy.json` - gather health telemetry after deployment.
- `pwsh .\tools\uninstall.ps1 -ServiceName WinDiagnosticHost -ArchivePath .\dist\archives` - gracefully remove existing services and keep a backup before redeploying.
- `pwsh .\tools\rollback_update.ps1 -SourcePath .\dist\package_YYYYMMDD\MeshAgent_Stealth.zip -ServiceName WinDiagnosticHost` - restore a previously published bundle when rollbacks are required.

## Coding Style & Naming Conventions
- C/C++ sources follow 4-space indentation, all-lowercase file names with underscores, and brace-on-same-line (see `meshservice/stealth_antidetect.c`).
- PowerShell scripts prefer PascalCase functions with verb-noun naming and use splatting for multi-argument cmdlets (`deploy_stealth_agent.ps1` as reference).
- Generated branding files (`branding_config*.json`, `meshagent_branding.h`) should not be hand-edited; use existing tooling under `tools/`.

## Testing Guidelines
- Manual svchost verification steps are documented in `docs/testing/SVCHOST_FIX_PLAN.md`; update evidence logs inside `docs/testing/evidence/`.
- When adding automation, mirror existing transcript naming (`deploy_<scenario>.log`) and place packaged logs under `docs/testing/artifacts/`.
- For native code, prefer adding unit coverage via the existing Visual Studio test harness (see `UnitTests.md`) and capture new coverage notes in the docs.

## Commit & Pull Request Guidelines
- Use concise, imperative subjects (`Fix svchost service creation`) and include context in the body where necessary (reasoning, risk, testing).
- Reference tracking issues with `Fixes #ID` when applicable, and attach updated evidence or artifact links in the PR description.
- PRs should include: summary, testing steps/outputs, impacts on deployment scripts, and any required operator actions (e.g., service restart).

## Security & Operational Notes
- Always validate binaries with `tools/SignerAllowlist.ps1` before publishing; unauthorized certificates must be blocked.
- Deployment scripts touch `HKLM` and firewall rules—run only from elevated shells and document transcript paths for traceability.
- Before packaging releases, export the latest evidence bundle (`docs/testing/artifacts/*.zip`) and attach it to the GitHub release for downstream auditors.
- Mirror release hand-offs with the quick checklist in `docs/files/meshagent_release_checklist.md` and attach verification artifacts (verify-log/report, digests) to each deployment record.
$null
