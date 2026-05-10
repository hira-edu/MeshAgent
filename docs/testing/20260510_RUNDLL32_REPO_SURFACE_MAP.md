# Rundll32 SSOT Repo Surface Map

Date: 2026-05-10

Implementation note: the original anchors below document the baseline inventory that
was used to perform the migration. The implemented code state and verification
evidence are recorded in:

- `docs/testing/20260510_RUNDLL32_SSOT_MIGRATION_PLAN.md`
- `docs/testing/evidence/advanced/20260510_160855_rundll32_lifecycle/summary.txt`

As of the implementation pass, Windows install/update/uninstall/validation and
deploy update activation route through `MeshLifecycleHostW` manifests. `svchost`
remains the steady-state service runtime, not a duplicate lifecycle transaction
path.

This document maps the current Windows lifecycle, bridge, session, KVM, PowerShell,
update, install, uninstall, server-update, agent-core, and StealthLab surfaces that
must be realigned behind the rundll32 SSOT contract described in:

- `docs/testing/20260510_RUNDLL32_SSOT_MIGRATION_PLAN.md`
- `docs/testing/20260331_REALIGNMENT_SSOT.md`
- `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md`

This is a code-backed map. Every item below is anchored to a current source file or
build/deploy artifact so implementation work can remove drift without relying on a
parallel interpretation of the system.

## Target SSOT Contract

The desired Windows model is a single authoritative rundll32-hosted DLL path for
approved lifecycle and helper entrypoints.

| Surface | Target owner | Target entrypoint | State transport |
| --- | --- | --- | --- |
| Install | Service DLL | `MeshLifecycleHostW` | signed/validated manifest path |
| Update | Service DLL | `MeshLifecycleHostW` | signed/validated manifest path |
| Server-triggered update | Service DLL | `MeshLifecycleHostW` | staged update manifest path |
| Repair/reinstall | Service DLL | `MeshLifecycleHostW` | signed/validated manifest path |
| Uninstall | Service DLL | `MeshLifecycleHostW` | signed/validated manifest path |
| Validation/status | Service DLL | `MeshLifecycleHostW` | signed/validated manifest path |
| KVM session bridge | Service DLL | `KvmSessionBridgeW` | named pipe token set |
| Optional terminal bridge | Service DLL | explicit console bridge export | named pipe token set |

The contract must be declared once, preferably in a new native contract module such
as `meshservice/rundll32_contract.h` and `meshservice/rundll32_contract.c`.
JavaScript, agent-core, deploy, tests, and native service code should consume the
same contract data or generated artifacts. No component should locally spell a
different executable, export name, command shape, or fallback sequence.

## End-to-End Flow Map

### 1. Lifecycle Install, Update, Uninstall

Current flow:

1. User, service, deploy, or server command selects lifecycle action.
2. JavaScript and agent-core code launch the current EXE with direct switches.
3. `meshservice/ServiceMain.c` parses direct EXE switches and forwards to native
   lifecycle functions.
4. `meshservice/stealth_installer.c` executes service registration, file staging,
   install, update, uninstall, validation, and legacy cleanup.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `modules/agent-installer.js:210` | `runWindowsNativeLifecycle()` launches `process.execPath` with `-fullinstall`, `-fullupdate`, `-fulluninstall`. | Migrate to manifest plus rundll32 `MeshLifecycleHostW`; delete direct EXE lifecycle path. |
| `modules/agent-installer.js:938` | `fullUninstall()` calls native direct `-fulluninstall`. | Replace with rundll32 lifecycle manifest. |
| `modules/agent-installer.js:986` | `fullInstall()` calls native direct `-fullinstall`. | Replace with rundll32 lifecycle manifest. |
| `modules/agent-installer.js:997` | `fullInstallEx()` calls native direct `-fullinstall`. | Replace with rundll32 lifecycle manifest. |
| `modules/agent-installer.js:1093` | `windowsNativeUpdate()` calls native direct `-fullupdate`. | Replace with rundll32 lifecycle manifest. |
| `modules/agent-installer.js:1109` | `sys_update()` enters legacy Windows updater path. | Delete legacy path or make it a thin rundll32 manifest submitter. |
| `modules/agent-installer.js:1156` | `.update.exe` staging path. | Replace with staged DLL plus manifest model. |
| `modules/agent-installer.js:1188` | update polling/retry loop. | Move retry policy to lifecycle host or one SSOT launcher policy. |
| `modules/agent-installer.js:1361` | old `_execve()` update reentry remains below an earlier return. | Delete unreachable legacy updater body. |
| `meshcore/agentcore.c:2124` | `MeshAgent_RunNativeStealthFullUpdate()`. | Replace direct EXE invocation with rundll32 lifecycle launcher. |
| `meshcore/agentcore.c:2155` | Builds `-fullupdate --update-source=... --update-dll=...`. | Move args into manifest; command line carries manifest path only. |
| `meshcore/agentcore.c:2159` | `CreateProcessW(sourceExe, updateArgs, ...)`. | Replace with SSOT rundll32 launcher helper. |
| `meshcore/agentcore.c:2210` | Native regression path launches child lifecycle commands. | Convert tests to rundll32 lifecycle manifest. |
| `meshcore/agentcore.c:2226` | Child `-fullinstall` direct EXE path. | Delete direct EXE lifecycle. |
| `meshcore/agentcore.c:2424` | Builds update args. | Manifest-only transport. |
| `meshcore/agentcore.c:2443` | Direct `-validate-update`. | Move to `MeshLifecycleHostW` validation action. |
| `meshcore/agentcore.c:2526` | Child `-fulluninstall`. | Replace with lifecycle manifest. |
| `meshcore/agentcore.c:7648` | Direct lifecycle CLI parsing. | Reject these switches or keep only as hard-fail migration diagnostics. |
| `meshcore/agentcore.c:7731` | `-fullinstall` action. | Delete or hard-fail. |
| `meshcore/agentcore.c:7740` | `-fulluninstall` action. | Delete or hard-fail. |
| `meshcore/agentcore.c:7745` | `-fullupdate` and `-fupdate`. | Delete or hard-fail. |
| `meshcore/agentcore.c:7761` | `-validate-update`. | Delete or hard-fail. |
| `meshcore/agentcore.c:8001` | Native full update call. | Replace with rundll32 launcher. |
| `meshservice/ServiceMain.c:8494` | Windows main argument normalization. | Remove lifecycle direct-switch allowlist. |
| `meshservice/ServiceMain.c:8518` | Managed direct lifecycle switches. | Replace with rundll32-only acceptance. |
| `meshservice/ServiceMain.c:8627` | Arg shuffle for direct lifecycle. | Delete when `MeshLifecycleHostW` owns lifecycle. |
| `meshservice/ServiceMain.c:9284` | Help advertises direct lifecycle switches. | Update help to no longer publish legacy lifecycle paths. |
| `meshservice/ServiceMain.c:9784` | GUI builds `-fullinstall --cleanup-launcher`. | Replace GUI submit with manifest plus rundll32 lifecycle. |
| `meshservice/ServiceMain.c:9793` | GUI builds `-fulluninstall --cleanup-launcher`. | Replace GUI submit with manifest plus rundll32 lifecycle. |
| `meshservice/stealth_installer.c:4550` | `Stealth_BuildTransitionPlan()`. | Retain as lifecycle engine behind `MeshLifecycleHostW`. |
| `meshservice/stealth_installer.c:4603` | `Stealth_DiscoverCurrentState()`. | Retain as lifecycle engine behind `MeshLifecycleHostW`. |
| `meshservice/stealth_installer.c:4869` | `Stealth_RunLifecycleOperation()`. | Make this the native engine called by `MeshLifecycleHostW`. |
| `meshservice/stealth_installer.c:4926` | install wrapper. | Retain only as internal call. |
| `meshservice/stealth_installer.c:4931` | uninstall wrapper. | Retain only as internal call. |
| `meshservice/stealth_installer.c:4936` | update wrapper. | Retain only as internal call. |

Target flow:

1. Caller writes a validated lifecycle manifest.
2. Caller invokes the single launcher helper.
3. Launcher resolves `%SystemRoot%\System32\rundll32.exe` and the approved service
   DLL path from SSOT.
4. Launcher invokes `rundll32.exe <ServiceDll>,MeshLifecycleHostW <manifest>`.
5. `MeshLifecycleHostW` parses and validates the manifest, then calls
   `Stealth_RunLifecycleOperation()`.

### 2. Server Update And Update-From-Server

Current flow:

1. Server-side deployment tooling stages agent payloads and updates hashes.
2. Mesh server sends `updateAgents`.
3. Agent receives the update command and stages `.update.exe`.
4. Agent re-enters direct EXE `-fullupdate`.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `deploy.py:1215` | Sends `updateAgents`. | Retain server command, change client activation contract. |
| `deploy.py:1398` | Remote staged command runs `"{update_path}" -fullinstall`. | Replace with rundll32 lifecycle activation or deployment manifest. |
| `deploy.py:2289` | `--native-activate` help references native `-fullupdate`. | Update to rundll32 lifecycle wording. |
| `tools/meshcentral_update_agents.js:84` | Sends `updateAgents`. | Retain command; evidence must show client uses rundll32 path. |
| `meshcore/agentcore.c:5339` | `MeshServer_selfupdate_continue()`. | Replace direct EXE update continuation with rundll32 lifecycle. |
| `meshcore/agentcore.c:5386` | `.update.exe` path generation. | Replace with staged DLL/manifest naming. |
| `meshcore/agentcore.c:5396` | Comment promises convergence through same lifecycle. | Update after real convergence exists. |
| `meshcore/agentcore.c:5407` | Builds `-fullupdate --update-source=...`. | Manifest-only state. |
| `meshcore/agentcore.c:5410` | `CreateProcessW()` direct EXE update. | Use SSOT rundll32 launcher. |
| `meshcore/agentcore.c:6088` | `MeshCommand_AgentUpdate`. | Keep command surface, change execution path. |
| `meshcore/agentcore.c:6104` | `.update.exe` update file path. | Replace with staged DLL/manifest. |
| `meshcore/agentcore.c:6190` | `MeshCommand_AgentUpdateBlock`. | Keep command surface, change staging/execution path. |
| `meshcore/agentcore.c:6197` | `.update.exe` block path. | Replace with staged DLL/manifest. |

Target flow:

1. Server update command remains protocol-compatible at the server boundary.
2. Client stages the approved service DLL payload and lifecycle manifest.
3. Client calls SSOT rundll32 launcher only.
4. Direct `.update.exe` creation, copy, and execution paths are removed.

### 3. KVM Rundll32 Session Bridge

Current flow:

1. KVM selects a target session.
2. KVM creates named pipe pairs.
3. KVM launches `rundll32.exe <ServiceDll>,KvmSessionBridgeW <pipe tokens>`.
4. The bridge connects pipes and runs KVM session code.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `meshcore/KVM/Windows/kvm.c:3207` | relay restart entry. | Retain. Refactor launcher to consume shared rundll32 contract. |
| `meshcore/KVM/Windows/kvm.c:3222` | bridge token setup. | Retain named-pipe model; use generated contract names. |
| `meshcore/KVM/Windows/kvm.c:3284` | bridge enabled checks. | Retain policy, remove drift with SSOT launcher. |
| `meshcore/KVM/Windows/kvm.c:3359` | builds `"<dll>,KvmSessionBridgeW"` command. | Replace literal export string with SSOT contract constant. |
| `meshcore/KVM/Windows/kvm.c:3368` | logs bridge spawn command. | Keep evidence, redact/normalize as needed. |
| `meshcore/KVM/Windows/kvm.c:3382` | `ILibProcessPipe_Manager_SpawnProcessEx4()` launch. | Retain only through approved launcher/policy. |
| `meshservice/ServiceMain.c:427` | local rundll32 resolver. | Move resolver to shared rundll32 launcher. |
| `meshservice/ServiceMain.c:455` | probe command uses `KvmSessionBridgeW`. | Use SSOT constant. |
| `meshservice/ServiceMain.c:461` | probe `CreateProcessW()`. | Use shared launcher helper. |
| `meshservice/ServiceMain.c:9079` | direct KVM slave block. | Delete direct slave path once bridge is authoritative. |
| `meshservice/ServiceMain.c:9087` | direct KVM slave execution. | Delete or hard-fail legacy direct slave path. |
| `meshservice/stealth_svchost.c:453` | exported `KvmSessionBridgeW`. | Retain, align with contract table. |
| `meshservice/stealth_svchost.c:503` | bridge launch context and pipe mode. | Remove legacy single-pipe/stdio fallback if no fallback policy applies. |
| `meshservice/stealth_svchost.c:506` | `useLegacySinglePipeBridge`. | Delete unless explicitly retained in SSOT, current request says no. |
| `meshservice/stealth_svchost.c:514` | stdio bridge mode. | Delete unless explicitly retained in SSOT, current request says no. |
| `meshservice/stealth_watchdog.c:2215` | approves only rundll32 KVM bridge command. | Retain and consume SSOT contract instead of local strings. |
| `microstack/ILibProcessPipe.c:203` | approved desktop bridge check. | Retain policy but consume SSOT contract. |
| `microstack/ILibProcessPipe.c:205` | requires `KvmSessionBridgeW`. | Replace local string with generated contract constant. |
| `microstack/ILibProcessPipe.c:456` | allows approved KVM bridge. | Retain. |

Target flow:

1. KVM remains the proof pattern for rundll32 bridging.
2. Export name, DLL path, rundll32 path, named-pipe token grammar, and policy
   checks are sourced from one contract module.
3. Direct KVM slave, stdio bridge, legacy single-pipe bridge, and local fallback
   strings are removed or hard-failed.

### 4. Session, Helper, And Bridge Policy

Current flow:

1. `ILibProcessPipe` and helper monitor code gate user-session process creation.
2. Some internal helper paths are still approved by local command string checks.
3. JavaScript modules can schedule or launch helper commands using direct EXE,
   `-b64exec`, command hosts, or PowerShell.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `microstack/ILibProcessPipe.h:36` | spawn type enum includes user/session modes. | Retain only with centralized policy. |
| `microstack/ILibProcessPipe.c:211` | internal helper approval helper. | Remove local special cases or register them in SSOT contract. |
| `microstack/ILibProcessPipe.c:219` | allows `--slave`. | Delete direct helper allowance or make it hard-fail. |
| `microstack/ILibProcessPipe.c:220` | allows `-b64exec`. | Replace with approved bridge export or remove feature. |
| `microstack/ILibProcessPipe.c:449` | `STEALTH_ALLOW_DESKTOP_BRIDGE` env override. | Delete runtime override if no fallback policy applies. |
| `meshservice/stealth_watchdog.c:1717` | helper monitor requires approved desktop bridge. | Retain but load SSOT command shape. |
| `meshservice/stealth_watchdog.c:2243` | session spawn allowed policy. | Retain as enforcement point. |
| `meshservice/stealth_watchdog.c:2357` | `CreateProcessAsUserW()`. | Retain only behind approved bridge contract. |
| `meshservice/stealth_integration.c:313` | rejects outside rundll32 bridge under strict policy. | Retain and bind to SSOT. |
| `modules/child-container.js:153` | scheduled task launches `process.execPath -b64exec`. | Replace with contract bridge or remove. |
| `modules/child-container.js:184` | command host fallback. | Remove fallback. |
| `modules/child-container.js:223` | direct `process.execPath` execution. | Replace with SSOT launcher or remove. |
| `modules/win-dispatcher.js:220` | scheduled task uses `process.execPath -b64exec`. | Replace with contract bridge or remove. |
| `modules/win-deskutils.js:82` | user-session `-b64exec`. | Replace with contract bridge or remove. |

Target flow:

1. All allowed cross-session helpers are explicit rundll32 exports or service IPC.
2. Approval checks consume one contract table.
3. Direct `--slave`, `-b64exec`, environment override, command host fallback, and
   ad hoc helper allowances are removed unless the SSOT explicitly defines a
   replacement export.

### 5. PowerShell, Cmd, Schtasks, And Arbitrary Process Launch

Current flow:

Several Windows modules use PowerShell, cmd, schtasks, or external shell hosts for
runtime discovery, UI, scheduling, and helper actions. Some native code also
contains cmd and PowerShell helpers.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `modules/win-system-paths.js:32` | canonical command host resolver. | Retain only if command host remains explicitly allowed. |
| `modules/win-system-paths.js:39` | canonical PowerShell resolver. | Remove if PowerShell runtime path is eliminated. |
| `modules/file-search.js:66` | PowerShell path. | Replace with native API or service RPC. |
| `modules/identifiers.js:437` | PowerShell path. | Replace with native API or service RPC. |
| `modules/identifiers.js:493` | `cmd.exe /c manage-bde`. | Replace with native API or approved lifecycle/bridge action. |
| `modules/process-manager.js:303` | PowerShell path. | Replace with native API or service RPC. |
| `modules/task-scheduler.js:32` | `schtasks` command usage. | Replace with Task Scheduler COM/native code or contract-hosted action. |
| `modules/task-scheduler.js:100` | cmd host path. | Remove command host dependency. |
| `modules/task-scheduler.js:114` | PowerShell path. | Replace with native API or service RPC. |
| `modules/toaster.js:106` | PowerShell path. | Replace with native toast API path or remove feature. |
| `modules/win-dispatcher.js:247` | PowerShell host. | Replace with native API or contract bridge. |
| `modules/win-systray.js:129` | PowerShell path. | Replace with native tray/notification code or remove. |
| `modules/win-terminal.js:50` | `cmd.exe` terminal path. | Decide whether terminal remains; if yes, use explicit console bridge export. |
| `modules/win-terminal.js:51` | `powershell.exe` terminal path. | Remove PowerShell default or make terminal feature explicit and isolated. |
| `modules/win-terminal.js:69` | `CreateProcessA`. | Retain only for explicit terminal feature if approved. |
| `modules/win-virtual-terminal.js:24` | `cmd.exe` virtual terminal path. | Decide whether terminal remains; if yes, explicit console bridge export. |
| `modules/win-virtual-terminal.js:25` | `powershell.exe` virtual terminal path. | Remove PowerShell default or isolate explicit terminal feature. |
| `modules/win-virtual-terminal.js:57` | pseudoconsole `CreateProcessW`. | Retain only for explicit terminal feature if approved. |
| `modules/win-userconsent.js:246` | `%windir%\system32\cmd.exe /C START`. | Replace with ShellExecute/native UI path or remove. |
| `meshservice/stealth_cmd.c:66` | hidden `cmd.exe /c`. | Remove or replace with native implementation. |
| `meshservice/stealth_cmd.c:75` | `CreateProcessA()` hidden cmd. | Remove or move behind explicit approved action. |
| `meshservice/stealth_pshost.cpp:89` | external hidden PowerShell fallback. | Delete fallback. |
| `meshservice/stealth_pshost.cpp:151` | PowerShell external fallback invocation. | Delete fallback. |
| `meshservice/stealth.h:391` | hidden cmd declaration. | Remove if native implementation replaces it. |
| `meshservice/stealth.h:396` | PowerShell via WMI declaration. | Remove or restrict to explicit SSOT-approved action. |

Target flow:

1. Runtime PowerShell is not a lifecycle or helper dependency.
2. Command shell use is removed from install, update, uninstall, KVM, session
   bridge, and service helper paths.
3. Any retained terminal feature is isolated behind an explicit terminal bridge
   export and cannot be used as a lifecycle fallback.

### 6. StealthLab DLL, Build, Export, And Payload Surfaces

Current flow:

1. `StealthLab_DLL` builds the service DLL and payload resources.
2. KVM bridge export exists in the DLL export file.
3. Lifecycle host export does not yet exist.
4. Deployment and validation scripts still reference direct EXE lifecycle paths.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `meshservice/MeshServiceHost.def` | exports `Stealth_SvchostServiceMain` and `KvmSessionBridgeW`. | Add `MeshLifecycleHostW`; keep export table as SSOT output or checked artifact. |
| `meshservice/MeshServiceHost_ARM64.def` | exports only `Stealth_SvchostServiceMain`. | Add ARM64 parity for approved exports. |
| `meshservice/MeshService-2022.vcxproj:60` | `StealthLab_DLL` configuration. | Add contract source files to this configuration. |
| `meshservice/MeshService-2022.vcxproj:883` | module definition file usage. | Ensure def exports match contract. |
| `meshservice/MeshService-2022.vcxproj:1170` | `svchost_payload.c` build item. | Keep payload update aligned with DLL entrypoints. |
| `MeshAgent.Build.proj:14` | `StealthLab_DLL` built before EXE. | Retain; lifecycle host depends on DLL first. |
| `meshservice/MeshAgent.MSBuild.targets:22` | DLL dependency target. | Retain; add contract validation target if practical. |
| `meshservice/MeshAgent.MSBuild.targets:30` | refreshes svchost payload using Python. | Retain. |
| `tools/refresh_svchost_payload.py:53` | missing DLL error. | Retain and include lifecycle export validation if practical. |
| `meshservice/refresh_svchost_payload.cmd:21` | PowerShell build helper. | Remove or replace with direct Python/MSBuild command if no PowerShell build wrappers allowed. |
| `docs/DEPLOYMENT.md:173` | build rules. | Update deployment docs to rundll32 lifecycle. |
| `tools/Invoke-RuntimeValidation.ps1:530` | validation runs `-fullinstall`. | Replace with rundll32 lifecycle validation or remove PowerShell test driver. |
| `tools/Invoke-RuntimeValidation.ps1:550` | validation runs `-fulluninstall`. | Replace with rundll32 lifecycle validation or remove PowerShell test driver. |

Target flow:

1. `StealthLab_DLL` exports all approved rundll32 entrypoints.
2. Build validates export presence and contract table consistency.
3. Payload refresh and deployment docs no longer instruct direct EXE lifecycle.
4. Validation invokes the same SSOT launcher used by production code.

### 7. Agent Core, Recovery, And UMH-Adjacent Paths

Current flow:

Agent core owns server update, native regression, cleanup scheduling, and some
Windows process launch code. Recovery and service-manager code contain direct
`process.execPath` service paths.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `meshcore/agentcore.c:453` | command host cleanup scheduler. | Replace with native cleanup or lifecycle-host cleanup action. |
| `meshcore/agentcore.c:1959` | Windows process launch. | Audit and route through SSOT launcher if lifecycle/helper related. |
| `meshcore/agentcore.c:8575` | `.update.exe` cleanup path. | Replace with manifest/staged DLL cleanup. |
| `modules/service-manager.js:1294` | Windows `_execve(process.execPath, ...)`. | Replace or remove direct EXE reentry. |
| `modules/service-manager.js:1736` | Windows `_execve(process.execPath, ...)`. | Replace or remove direct EXE reentry. |
| `modules/service-manager.js:2039` | Windows `_execve(process.execPath, ...)`. | Replace or remove direct EXE reentry. |
| `modules/service-manager.js:2269` | Windows service install. | Reconcile with native lifecycle host or delete duplicate lifecycle implementation. |
| `modules/service-manager.js:2343` | default service path is `process.execPath`. | Replace service path ownership with native lifecycle host. |
| `modules/service-manager.js:2453` | unload script generation. | Delete if it duplicates lifecycle cleanup. |
| `modules/service-manager.js:2535` | `daemonEx` script generation. | Delete if it duplicates lifecycle startup. |
| `modules/service-manager.js:2683` | restart loop uses `process.execPath`. | Replace with service control/native lifecycle. |
| `modules/service-manager.js:3024` | uninstall path. | Reconcile with native lifecycle host. |
| `modules/service-manager.js:3482` | runs `process.execPath`. | Replace or remove. |
| `modules/interactive.js:197` | interactive direct EXE lifecycle/help. | Update or delete direct lifecycle commands. |
| `modules/interactive.js:293` | spawns direct lifecycle command. | Replace with rundll32 lifecycle or remove UI command. |

Target flow:

1. Agent core may request lifecycle work but cannot define its own lifecycle
   command shape.
2. JavaScript service-manager paths are not a second Windows lifecycle engine.
3. Recovery/cleanup actions are represented as lifecycle manifest actions or
   service-owned native operations.

### 8. Test, Regression, And Evidence Surfaces

Current flow:

Regression tests and validation scripts contain direct lifecycle and some
PowerShell helper use. Existing KVM rundll32 evidence exists, but lifecycle
rundll32 evidence does not.

Current anchors:

| File | Current surface | Required disposition |
| --- | --- | --- |
| `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md` | TODO-007 and TODO-012 define bridge/lifecycle convergence. | Update acceptance criteria to lifecycle rundll32 evidence once implemented. |
| `docs/testing/20260331_REALIGNMENT_SSOT.md` | SSOT policy baseline. | Add this map and lifecycle contract as authoritative references. |
| `test/kvm_initial_frame_runtime.js:71` | test PowerShell helper. | Replace with native test helper or document test-only exception if allowed. |
| `test/kvm_initial_frame_runtime.js:110` | test PowerShell helper. | Replace with native test helper or document test-only exception if allowed. |
| `test/kvm_system_picture_runtime.js:239` | test PowerShell helper. | Replace with native test helper or document test-only exception if allowed. |

Required evidence after implementation:

- Positive install through `rundll32.exe <ServiceDll>,MeshLifecycleHostW <manifest>`.
- Positive update through the same lifecycle host.
- Positive server-triggered update through the same lifecycle host.
- Positive uninstall through the same lifecycle host.
- Positive KVM session bridge through `KvmSessionBridgeW`.
- Negative direct EXE lifecycle switch rejection.
- Negative `.update.exe` execution path audit.
- Negative PowerShell/cmd fallback audit for lifecycle/helper code.
- Negative duplicate export/string drift audit.

## Removal And Migration Matrix

| Category | Keep | Migrate | Delete or hard-fail |
| --- | --- | --- | --- |
| Native lifecycle engine | `Stealth_RunLifecycleOperation()` and supporting state/plan functions. | All callers to `MeshLifecycleHostW`. | Direct `-fullinstall`, `-fullupdate`, `-fulluninstall`, `-validate-update` execution. |
| Server update protocol | `updateAgents` server command. | Client activation to rundll32 lifecycle manifest. | `.update.exe` staging/execution. |
| KVM bridge | `KvmSessionBridgeW`, named pipes, session token handling. | Export names and launch commands to contract constants. | Direct KVM slave, stdio bridge, legacy single-pipe bridge. |
| Helper/session policy | `ILibProcessPipe` and helper monitor as enforcement points. | Approval checks to contract table. | `--slave`, `-b64exec`, env override, command host fallback. |
| PowerShell/cmd runtime | Explicit terminal feature only if approved. | Native APIs or explicit bridge exports. | Lifecycle/helper PowerShell and cmd fallback paths. |
| JavaScript lifecycle | Thin manifest creator only. | `agent-installer`, `interactive`, and `service-manager` to SSOT launcher. | Duplicate Windows install/update/uninstall engines. |
| Build/deploy/docs | `StealthLab_DLL`, Python payload refresh. | Export validation, docs, deploy activation. | PowerShell build wrappers and direct EXE docs. |

## No-Drift Enforcement

The implementation is not complete until these audits pass or have documented,
intentional, non-runtime exceptions:

```powershell
rg -n --glob '!*.md' --glob '!docs/testing/evidence/**' "-fullinstall|-fullupdate|-fulluninstall|-validate-update|-fupdate" .
rg -n --glob '!*.md' --glob '!docs/testing/evidence/**' "\.update\.exe" .
rg -n --glob '!*.md' --glob '!docs/testing/evidence/**' "powershell(\.exe)?|pwsh(\.exe)?" .
rg -n --glob '!*.md' --glob '!docs/testing/evidence/**' "cmd\.exe|cmd /c|%COMSPEC%|ComSpec" .
rg -n --glob '!*.md' --glob '!docs/testing/evidence/**' "KvmSessionBridgeW|MeshLifecycleHostW" .
rg -n --glob '!*.md' --glob '!docs/testing/evidence/**' "process\.execPath" modules meshcore meshservice
```

Expected end state:

- Only SSOT contract files, generated checked artifacts, tests, and docs contain
  approved export names.
- No production lifecycle caller contains direct EXE lifecycle switches.
- No production lifecycle/update path contains `.update.exe`.
- No production lifecycle/helper path contains PowerShell or cmd fallback code.
- Any remaining `process.execPath` use is non-Windows or explicitly unrelated to
  lifecycle, helper, bridge, update, install, uninstall, KVM, session, or service
  management.

## Implementation Order

1. Add the native rundll32 contract module and export declarations.
2. Implement `MeshLifecycleHostW` as a manifest-only lifecycle host.
3. Move `Stealth_RunLifecycleOperation()` behind the lifecycle host.
4. Add one shared launcher helper for native code and one generated JS contract
   view for JavaScript.
5. Migrate `agentcore` server update and native regression paths.
6. Migrate `agent-installer`, `interactive`, and `service-manager` lifecycle
   callers.
7. Align KVM bridge strings and policy checks with the contract table.
8. Remove direct KVM slave, stdio bridge, and legacy single-pipe bridge paths.
9. Replace or delete PowerShell, cmd, schtasks, and `-b64exec` runtime paths.
10. Update build/export validation, deploy docs, and runtime validation.
11. Run positive and negative evidence collection.
12. Update the TODO matrix only after evidence exists.

## Open Decisions Before Code Removal

These decisions should be made in the migration branch before deleting code:

| Decision | Options | Default for this plan |
| --- | --- | --- |
| Terminal feature | Keep behind explicit console bridge export, or remove Windows terminal feature. | Remove PowerShell default; keep only if a bridge export is approved. |
| Test PowerShell use | Allow test-only PowerShell, or replace all tests. | Replace, because the request asks for no PowerShell paths. |
| Legacy KVM bridge modes | Keep stdio/single-pipe for diagnostics, or delete. | Delete/hard-fail, because the request asks for no fallbacks. |
| Direct lifecycle switches | Keep compatibility shim, or hard-fail. | Hard-fail with a clear audit log. |
| `.update.exe` artifact | Keep staged EXE compatibility, or replace entirely. | Replace entirely with staged DLL/manifest. |
