# 2026-05-10 Rundll32 SSOT Migration Plan

## Decision

Move retained Windows lifecycle and approved Windows runtime helper entrypoints to a single rundll32-hosted DLL contract, using the service DLL as the implementation authority.

This plan intentionally supersedes `docs/testing/20260510_SCOPED_WINDOWS_LIFECYCLE_HARDENING_PLAN.md`, which kept install, update, and uninstall on direct native EXE entrypoints and kept KVM as the only rundll32 surface.

The repo-wide source map for this migration is `docs/testing/20260510_RUNDLL32_REPO_SURFACE_MAP.md`. That map is the working inventory for lifecycle, update-from-server, KVM, session bridge, PowerShell, install, uninstall, deploy, build, and StealthLab surfaces. Changes in this plan must stay aligned with that map to avoid creating a second source of truth.

## Implementation Status - 2026-05-10

Status: implemented for Windows lifecycle/update/install/uninstall/validation routing, KVM entrypoint SSOT alignment, package provisioning authority, and removal of known Windows lifecycle/provisioning compatibility fallbacks.

Evidence:

- `docs/testing/evidence/advanced/20260510_160855_rundll32_lifecycle/summary.txt`
- `docs/testing/evidence/advanced/20260510_221100_meshcentral_hashfix3_rundll32_update/summary.txt`

Implemented changes:

- Added `meshservice/rundll32_contract.h` and `meshservice/rundll32_contract.c`.
- Exported `MeshLifecycleHostW` from `meshservice/MeshServiceHost.def` and `meshservice/MeshServiceHost_ARM64.def`.
- Routed native agent-core lifecycle/update callers through `MeshRundll32_LaunchLifecycleHostW`.
- Routed JS installer and interactive Windows install/uninstall through rundll32 manifest actions.
- Replaced Windows staged update payload suffix `.update.exe` with `.update.pkg`.
- Updated `deploy.py` update activation to write a lifecycle manifest and run `%SystemRoot%\System32\rundll32.exe <ServiceDll>,MeshLifecycleHostW <manifest>`.
- Kept `svchost.exe` as the steady-state installed service runtime. This is not a duplicate lifecycle path; it is the long-running service host. `rundll32.exe` is the transaction host for lifecycle/helper operations.
- Removed agent-core direct lifecycle command execution and left ServiceMain direct lifecycle switches only as hard-fail diagnostics returning unsupported operation.
- Centralized KVM bridge launcher/probe entrypoint spelling behind the rundll32 contract constants where policy and command construction consume it.
- Aligned the MeshCentral server-update hash model with upstream: the advertised/downloaded payload may include MeshCentral null-policy data, while the agent-side normalized hash strips both real MSH and null-policy trailers.
- Kept install/reinstall package identity strict: those flows require embedded MeshCentral provisioning from the real MSH GUID payload.
- Allowed binary-only MeshCentral update packages only when the installed `.conf` and `.msh` are present and valid, preserving the installed identity instead of accepting sibling sidecars or legacy fallback paths.
- Made the update DLL authority the MeshCentral-served EXE's embedded svchost DLL payload, not the temporary lifecycle host DLL.
- Normalized uninstall success to the authoritative final lifecycle discovery state so best-effort cleanup warnings do not return failure after the machine has converged to clean.

Verified gates:

- `msbuild meshservice/MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m` succeeded with 0 warnings and 0 errors.
- `msbuild meshservice/MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64 /m` succeeded with 0 warnings and 0 errors.
- `python -m py_compile deploy.py` passed.
- `python -m py_compile tools\generate_branding_assets.py deploy.py` passed.
- `node --check modules\agent-installer.js` and `node --check modules\interactive.js` passed.
- `tools\Invoke-RuntimeValidation.ps1` parsed successfully with `System.Management.Automation.PSParser`.
- Fresh `rundll32.exe <ServiceDll>,MeshLifecycleHostW <manifest>` package validation passed against the isolated MeshCentral-generated test package; evidence: `test\rundll32_validation_20260510_174326\evidence\validate_package_rundll32_startprocess.txt`.
- `link.exe /dump /exports meshservice\x64\StealthLab_DLL\MeshService-2022.dll` confirmed `MeshLifecycleHostW`, `KvmSessionBridgeW`, and `Stealth_SvchostServiceMain`.
- Repo audit has no `.update.exe` hits outside docs.
- Repo audit has no `process.execPath` direct full-lifecycle spawn hits.
- Direct lifecycle switch strings remain only in `ServiceMain.c` hard-fail rejection checks.
- `tools/generate_branding_assets.py` generates branding headers only; it no longer writes static `.msh` manifests or scans repo-root `.msh` files.
- Windows lifecycle package preflight reports only package executable and embedded MeshCentral provisioning payload authority. Sibling `.msh`, sibling `.conf`, sibling `.db`, and existing-install provisioning fallback fields were removed from the native API/JSON.
- Windows install/reinstall staging extracts provisioning only from the embedded MeshCentral package payload and fails closed when source package data is absent.
- Windows update staging accepts a binary-only MeshCentral-served package only after validating the already-installed provisioning files; it then retains those files through the transaction and still sources the service DLL from the update EXE payload.
- Windows uninstall returns success only after final discovery proves the clean state; a clean final state overrides resolved best-effort cleanup warnings, while real residue still fails.
- Hardcoded legacy cleanup for the old `DiagHostSvc` / `WinDiagnosticHost` service and task names was removed from the retained install/update/uninstall path.
- The svchost helper selector uses the configured branded helper path only; it no longer probes `MeshService64.exe`, `MeshService-2022.exe`, the current process image, or module path as a helper fallback.
- The native in-process PowerShell helper no longer falls back to `%TEMP%\PsRunspaceHelper.dll` or external `powershell.exe` execution.
- `tools/Invoke-RuntimeValidation.ps1` no longer runs `-fullinstall` / `-fulluninstall` checks and always asks the existing validation harness for svchost-only coverage.

Classified residuals:

- Existing PowerShell/cmd references in runtime modules are not lifecycle executors after this change. They remain separate feature surfaces such as file search, identifiers, UI toast/systray, terminal, task scheduling, diagnostics, or blocklists, except that the native external PowerShell fallback in `stealth_pshost.cpp` was removed.
- Remote deploy still uses `cmd /Q /D /C` to create/read remote files through MeshCentral runcommand, but lifecycle execution is the rundll32 manifest host.
- Live install/update/uninstall was not executed from this workstation because those actions mutate local service state.
- Follow-up isolated live testing did execute local install, server-triggered update, update validation, and stability checks against a dummy MeshCentral server under `test\rundll32_manual_20260510_175630`; this did not touch the live MeshCentral deployment.

The target state is stricter:

- One Windows implementation authority for install, update, repair, reinstall, uninstall, validation, and status.
- One rundll32 contract table for every retained DLL-hosted operation.
- No standalone Windows agent runtime path.
- No direct PowerShell, JavaScript service-manager, `.update.exe`, self-exe, helper-monitor, or arbitrary user-session process path for lifecycle.
- No compatibility aliases that silently execute legacy lifecycle logic.
- No fallback from rundll32 failure to the old EXE lifecycle path.

## Baseline Conflict Inventory

This inventory records the baseline drift found before the 2026-05-10 migration pass. It is kept for traceability; resolved items are reflected in the implementation status above and in the current source tree.

- `20260331_REALIGNMENT_SSOT.md` requires one native lifecycle engine but says PowerShell-invoked flows may call native entrypoints.
- `20260510_SCOPED_WINDOWS_LIFECYCLE_HARDENING_PLAN.md` explicitly says not to migrate lifecycle paths to rundll32.
- `ServiceMain.c` still accepts `-fullinstall`, `-fullupdate`, `-fulluninstall`, validation commands, and GUI cleanup launch commands as EXE command-line surfaces.
- `modules/agent-installer.js` uses `process.execPath` to run `-fullinstall`, `-fullupdate`, and `-fulluninstall`.
- `microstack/ILibProcessPipe.c` allows `--slave` and `-b64exec` internal helper re-entry in addition to the KVM rundll32 bridge.
- Several Windows modules still start `powershell.exe` directly for terminal, task scheduler, identifiers, process manager, toaster, systray, file search, and dispatcher behavior.
- `stealth_pshost.cpp` has an explicit external `powershell.exe` fallback.
- The regression matrix still contains at least one KVM row that mentions self-exe fallback if rundll32 consistently fails.

These are planning blockers for the requested no-drift end state. They must be resolved before code is declared aligned.

## Code-Backed Source Map

This plan is based on the current source tree, not only on prior SSOT language.

| Area | Current code anchor | Observed drift risk |
|---|---|---|
| JavaScript lifecycle wrapper | `modules/agent-installer.js:210`, `modules/agent-installer.js:938`, `modules/agent-installer.js:986`, `modules/agent-installer.js:997`, `modules/agent-installer.js:1093` | Windows install/update/uninstall still launch direct EXE lifecycle switches through `process.execPath` instead of a rundll32 lifecycle export. |
| Legacy updater body | `modules/agent-installer.js:1109`, `modules/agent-installer.js:1156`, `modules/agent-installer.js:1188`, `modules/agent-installer.js:1361` | `.update.exe`, recursive `sys_update`, and copy/re-exec logic still exist and must be deleted or unreachable for Windows. |
| Native EXE lifecycle switches | `meshservice/ServiceMain.c:8494`, `meshservice/ServiceMain.c:8518`, `meshservice/ServiceMain.c:8627`, `meshservice/ServiceMain.c:9284`, `meshservice/ServiceMain.c:9784` | Direct `-fullinstall`, `-fullupdate`, `-fulluninstall`, help text, and GUI cleanup command construction remain as EXE entrypoints. |
| KVM rundll32 proof path | `meshcore/KVM/Windows/kvm.c:1005`, `meshcore/KVM/Windows/kvm.c:3222`, `meshcore/KVM/Windows/kvm.c:3368` | KVM already has the rundll32 pattern to reuse, but the local resolver and argument assembly should move behind shared contract helpers. |
| KVM direct slave block | `meshservice/ServiceMain.c:8533`, `meshservice/ServiceMain.c:9079`, `meshservice/ServiceMain.c:9087` | Direct `-kvm0` / `-kvm1` is blocked unless hosted by rundll32; this is the model lifecycle should match. |
| Process spawn policy | `microstack/ILibProcessPipe.c:101`, `microstack/ILibProcessPipe.c:203`, `microstack/ILibProcessPipe.c:211`, `microstack/ILibProcessPipe.c:219`, `microstack/ILibProcessPipe.c:220`, `microstack/ILibProcessPipe.c:449` | Policy still has local string checks and helper re-entry exceptions (`--slave`, `-b64exec`, `STEALTH_ALLOW_DESKTOP_BRIDGE`) outside one contract table. |
| Direct PowerShell runtime helpers | `modules/file-search.js:66`, `modules/identifiers.js:437`, `modules/process-manager.js:303`, `modules/task-scheduler.js:114`, `modules/toaster.js:106`, `modules/win-dispatcher.js:247`, `modules/win-systray.js:129`, `meshservice/stealth_pshost.cpp:89`, `meshservice/stealth_pshost.cpp:151` | PowerShell launch points remain in runtime modules and the native external fallback path. |

These anchors should be refreshed when implementation starts. If a line moves, the file/function mapping remains authoritative.

## Target SSOT Shape

### Process model

Windows has only these shipped process authorities:

| Surface | Host | Scope |
|---|---|---|
| Service runtime | `svchost.exe` loading installed service DLL | Long-running agent service, networking, policy, lifecycle orchestration state |
| Lifecycle transaction host | `rundll32.exe <staged-or-installed-service-dll>,MeshLifecycleHostW <manifest>` | Install, update, repair, reinstall, uninstall, validation, status |
| Remote desktop bridge | `rundll32.exe <installed-service-dll>,KvmSessionBridgeW <pipes>` | KVM capture and input only |
| Optional console bridge | `rundll32.exe <installed-service-dll>,MeshConsoleBridgeW <pipe>` | Only if terminal support is retained; no lifecycle behavior |

Anything not in this table is rejected on Windows.

### DLL contract table

Create a single compile-time contract table in new files:

- `meshservice/rundll32_contract.h`
- `meshservice/rundll32_contract.c`

The table defines:

- export name
- operation kind
- whether Session 1 is allowed
- whether SYSTEM token redirection is allowed
- whether a named pipe is required
- whether a manifest file is required
- expected desktop, if any
- event log category
- validation gate name

Every launcher and every policy check uses this table. No component hard-codes independent allowlists for `KvmSessionBridgeW`, lifecycle, PowerShell, terminal, or helper behavior.

### No-drift enforcement

The no-drift guarantee comes from code structure plus gates, not from documentation alone.

Required enforcement controls:

- All approved rundll32 exports are declared once in `rundll32_contract.c`; local string checks for export names are deleted.
- All Windows lifecycle callers must link or import one launcher helper, not build command lines directly.
- All policy decisions must include a contract table lookup and write a structured audit record.
- Any command-line switch retained only for negative compatibility must return a hard unsupported-operation error before loading lifecycle code.
- CI or release validation must run the negative `rg` audits in this document and fail on unclassified hits.
- Regression evidence must include the command line, resolved rundll32 path, DLL path, export name, manifest hash, operation, correlation ID, process ID, exit code, and policy decision.
- The TODO matrix cannot mark a migration row `DONE` unless its evidence includes both positive rundll32 execution and negative legacy-path rejection.

### Lifecycle authority

The lifecycle engine remains the sequence already defined by the 20260331 SSOT:

1. `DiscoverCurrentState`
2. `BuildTransitionPlan`
3. `StageArtifacts`
4. `QuiesceRuntime`
5. `ApplyServiceAndSystemState`
6. `StartOrRemove`
7. `ValidatePostState`
8. `CommitOrRollback`
9. `EmitStructuredEvidence`

The implementation moves behind `MeshLifecycleHostW`. EXE switches, JavaScript wrappers, GUI paths, and PowerShell operator wrappers are only launch clients for this DLL host or are removed.

### Lifecycle manifest

Do not pass full lifecycle state through a long rundll32 command line.

Use a controlled lifecycle manifest file with one action and package/DLL inputs.
Provisioning comes from the MeshCentral-embedded package payload only:

```ini
[Lifecycle]
Action=install|update|repair|reinstall|uninstall|validate-install|validate-update|validate-uninstall|validate-package
SourceExe=C:\absolute\path\meshagent64.exe
SourceDll=C:\absolute\path\MeshService-2022.dll
DisplayName=optional runtime display name
Description=optional runtime description
RequireConfig=1
```

The rundll32 command line passes only:

```text
rundll32.exe "<dll>",MeshLifecycleHostW "<manifest-path>"
```

The host validates:

- manifest path is absolute and under an approved staging or install root
- manifest schema is exact
- operation is in the contract table
- all paths canonicalize under allowed roots
- expected hashes match before mutation
- service name and branding match `Stealth_GetInstallPaths`
- caller context is allowed for the operation

No missing manifest field is guessed from legacy defaults.

## Implementation Phases

### Phase 0 - SSOT and matrix rewrite

Update these documents in one change:

- `20260331_REALIGNMENT_SSOT.md`
- `20260331_REALIGNMENT_GUARDRAILS.md`
- `20260331_REALIGNMENT_RETAINED_SURFACES.md`
- `20260331_REALIGNMENT_REGRESSION_MATRIX.md`
- `20260331_REALIGNMENT_TODO_MATRIX.md`
- `20260510_SCOPED_WINDOWS_LIFECYCLE_HARDENING_PLAN.md`

Required documentation changes:

- Replace "PowerShell-invoked native entrypoint" language with "PowerShell may only launch the rundll32 lifecycle host with a manifest."
- Replace "KVM only rundll32 surface" with the contract table above.
- Remove any claim that lifecycle must stay on EXE entrypoints.
- Remove regression wording that allows self-exe fallback after rundll32 failure.
- Add TODO rows for lifecycle export, wrapper migration, legacy deletion, and evidence refresh.

### Phase 1 - Build the rundll32 contract layer

Add the shared contract and launcher helpers:

- canonical `%SystemRoot%\System32\rundll32.exe` resolver
- installed service DLL resolver
- staged transaction DLL resolver
- export contract lookup
- manifest path canonicalization
- event log audit emitter
- correlation ID generator
- pipe name generator for long-running bridges
- common cleanup helpers for process, token, environment, pipe, and manifest handles

Rules:

- Use `GetSystemDirectoryW` or equivalent System32 resolution, not caller-supplied paths.
- Use `GetFullPathNameW`, `PathCchCanonicalizeEx`, or local equivalent normalization before policy decisions.
- Use `CommandLineToArgvW` against `GetCommandLineW`; do not trust rundll32 `lpszCmdLine` alone.
- Fail closed on parse ambiguity.
- Emit structured error codes.

### Phase 2 - Add `MeshLifecycleHostW`

Implement:

```c
void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow);
```

The export lives beside `KvmSessionBridgeW` in the service DLL and is exported through `MeshServiceHost.def`.

Host behavior:

- initialize branding and logging once
- parse manifest path
- validate manifest and hashes
- call the single lifecycle engine
- emit structured evidence
- return a deterministic process exit code through explicit `ExitProcess`

Update `stealth_installer.c` so the lifecycle runner is not static-only private code. It should expose one internal C API used by the rundll32 host:

```c
BOOL StealthLifecycle_RunFromManifest(const StealthLifecycleManifest* manifest, StealthLifecycleResult* result);
```

Do not duplicate install/update/uninstall logic in the export.

### Phase 3 - Migrate install, update, uninstall clients

Replace current Windows lifecycle clients:

- `modules/agent-installer.js`
- GUI lifecycle paths in `ServiceMain.c`
- silent install wrapper
- CLI install/update/uninstall handling
- server-triggered self-update activation
- PowerShell operator wrapper, if retained

New behavior:

- write a manifest to the controlled staging root
- launch `rundll32.exe <transaction-dll>,MeshLifecycleHostW <manifest>`
- wait for exit
- read structured result or evidence
- return the rundll32 host exit code

Important update rule:

- Update must use a staged transaction DLL, not the installed DLL that may need replacement.
- The service must quiesce before the staged rundll32 host replaces the installed DLL.
- The host owns service stop, file replacement, svchost registration, service start, post-state validation, rollback, and evidence.

### Phase 4 - Remove legacy lifecycle code paths

Delete or hard-fail these Windows paths:

- `-install`
- `-uninstall`
- direct `-fullinstall`
- direct `-fullupdate`
- direct `-fupdate`
- direct `-fulluninstall`
- `.update.exe` copy and re-exec
- Windows `sys_update` legacy loop
- JavaScript service-manager install/uninstall behavior for Windows
- standalone service registration
- direct cleanup launcher EXE re-entry
- any direct lifecycle path through `process.execPath`

The EXE may keep only:

- help text that points to the supported rundll32 lifecycle host
- negative tests proving blocked legacy switches
- non-Windows behavior where applicable

No alias may silently call the old code.

### Phase 5 - Migrate or remove PowerShell and other helper surfaces

Classify every Windows direct child-process helper into one of three outcomes:

| Current surface | Target |
|---|---|
| lifecycle PowerShell wrapper | manifest-only launcher for `MeshLifecycleHostW`, or delete |
| `stealth_pshost.cpp` | delete external `powershell.exe` fallback; retain only if converted to an explicit DLL-hosted command with no fallback |
| terminal PowerShell | move to `MeshConsoleBridgeW` or remove Windows PowerShell terminal support |
| terminal cmd | move to `MeshConsoleBridgeW` or remove Windows terminal support |
| toaster/systray notification | replace with native Win32 APIs or a dedicated DLL-hosted notification command |
| task scheduler | replace PowerShell module usage with COM Task Scheduler API |
| identifiers/process manager/file search | replace PowerShell with native API/WMI/COM in-process code or fail closed |
| `--slave` and `-b64exec` user-session helper re-entry | replace with explicit contract-table exports or remove |

No retained helper can call `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, or caller-supplied executables directly unless that command is represented in the contract table and validated by a feature-specific gate.

### Phase 6 - Consolidate spawn policy

Replace scattered launch allowlists with one policy check:

```c
BOOL MeshRundll32Contract_IsAllowedLaunch(
    const MeshRundll32LaunchRequest* request,
    MeshRundll32PolicyDecision* decision);
```

Update:

- `microstack/ILibProcessPipe.c`
- `meshservice/stealth_watchdog.c`
- `meshservice/stealth_integration.c`
- KVM restart code
- any remaining helper monitor code

Policy rules:

- lifecycle runs in Session 0 only
- KVM bridge is the only Session 1 capture/input bridge
- console bridge is optional and separately gated
- arbitrary process launch is denied
- missing rundll32, missing DLL, missing export, failed manifest validation, or failed pipe authentication is terminal failure, not fallback

### Phase 7 - Delete duplicate and drift-prone code

After all callers use the contract table, delete duplicate local logic:

- duplicate rundll32 path resolvers in KVM and `ServiceMain.c`
- duplicate KVM entrypoint string checks
- duplicate PowerShell path resolution for runtime helpers
- JS-side lifecycle parameter filtering that exists only to sanitize old EXE switches
- old help text that advertises direct lifecycle switches
- old svchost helper executable probing that can launch stale EXEs; this was removed in the 2026-05-10 continuation pass

Leave only shared helpers and feature-specific thin adapters.

### Phase 8 - Validation and evidence

Add or update regression rows:

- `rundll32 lifecycle clean install`
- `rundll32 lifecycle clean update`
- `rundll32 lifecycle clean uninstall`
- `rundll32 lifecycle repair/reinstall`
- `rundll32 lifecycle GUI path`
- `rundll32 lifecycle silent path`
- `rundll32 lifecycle PowerShell wrapper`
- `legacy lifecycle switches blocked`
- `no process.execPath lifecycle launch`
- `no powershell.exe direct runtime launch`
- `no self-exe KVM fallback`
- `single contract table policy audit`
- `staged update DLL replacement safety`

Every row writes evidence under:

```text
docs/testing/evidence/advanced/<timestamp>_rundll32_ssot_<area>/summary.txt
```

Required build gate after every code change:

```text
msbuild meshservice/MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m
```

Required negative audit commands:

```text
rg -n "process\.execPath.*-full|\.update\.exe|sys_update|powershell\.exe|KvmSessionBridgeW|--slave|-b64exec|CreateProcess" modules meshservice meshcore microstack
rg -n "fallback|legacy|backward|compatibility" modules meshservice meshcore microstack docs/testing
```

Any remaining hit must be either deleted or tied to a named retained contract row.

## Coding Standards

- Every Windows API call checks return values.
- Every handle, token, environment block, COM object, registry key, heap allocation, and local memory allocation has one cleanup owner.
- Use `StringCch*`, `PathCch*`, bounded buffers, or existing project-safe helpers.
- Use exact operation enums, not stringly typed branching in multiple files.
- Use structured result objects and stable exit codes.
- Use least-privilege token rights.
- Use `CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW` where process creation is required.
- Use service-owned Event Log audit for every rundll32 launch, policy deny, lifecycle mutation, rollback, and validation failure.
- Treat command parsing, manifest parsing, and path canonicalization failures as security-relevant denies.
- Do not add `#pragma warning(disable)` to silence migration warnings.

## Exit Criteria

The migration is done only when:

- all Windows install/update/uninstall callers use `MeshLifecycleHostW`
- no Windows lifecycle path calls `process.execPath` directly
- no Windows lifecycle path uses JavaScript service-manager install/update/uninstall logic
- no Windows update path uses `.update.exe`
- no retained Windows runtime helper directly launches PowerShell or arbitrary child processes outside the rundll32 contract table
- KVM still uses `KvmSessionBridgeW` and has no self-exe fallback
- all direct legacy switches fail closed with explicit unsupported-operation output
- SSOT, TODO, ledger, regression matrix, deployment docs, and evidence paths agree
- full required regression rows pass with evidence
