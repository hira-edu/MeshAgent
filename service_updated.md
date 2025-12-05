## Context
- Third-party apps or softwares stops WinDiagnosticHost, disables watchdog tasks, drops WFP block rules, kills orphan processes, and re-checks every eight seconds. MeshAgent lacks comparable defenses today.
- This document tracks the TODOs required to build first-party lockdown capabilities (service resilience, stealth persistence, policy enforcement, telemetry, and clean restoration).

## Implementation Note
**No need to implement from scratch.** Each workstream below references best-in-class open source implementations. Port/adapt these rather than building custom solutions.

## Success Criteria
- MeshAgent survives deliberate SCM stop requests issued under SYSTEM and restarts automatically.
- Lockdown routines can disable/allow services, tasks, and processes according to an allowlist without harming core OS components.
- Registry/task/policy edits persist throughout SecureEnter and are fully restored on SecureExit or uninstall.
- CI + runtime validation (e.g., `tools/Invoke-RuntimeValidation.ps1`) prove watchdog, WMI, policy, IPC, and stealth persistence flows.
- Alternate persistence options (COM hijack, spooler monitor, Winlogon shell, watch-dog mesh, etc.) are gated via branding and logged for forensic review.

## Workstream W1 - Service & Persistence Hardening

**Open Source References:**
- [NSSM (Non-Sucking Service Manager)](https://nssm.cc/) (Public Domain) - Battle-tested service wrapper with auto-restart, throttling, and exit hooks. [Source](https://git.nssm.cc/nssm/nssm)
- [ecraft/ecraft-watchdogservice](https://github.com/ecraft/ecraft-watchdogservice) (MIT) - Generic watchdog Windows Service for keeping processes running 24/7.
- [onewe/watchDog-windows](https://github.com/onewe/watchDog-windows) (MIT) - Windows watchdog written in C (simple and portable).
- [dahall/TaskScheduler](https://github.com/dahall/TaskScheduler) (MIT) - .NET wrapper for the Windows Task Scheduler 2.0 COM API.
- [subesp0x10/Wmi-Persistence](https://github.com/subesp0x10/Wmi-Persistence) (N/A) - WMI event subscription persistence examples.
- [cocomelonc WMI persistence](https://cocomelonc.github.io/tutorial/2022/05/30/malware-pers-5.html) (N/A) - C++ WMI permanent event consumer examples.

**Tasks:**
- [ ] Integrate `Stealth_ProtectServiceFromTermination()` into installer/runtime and add a watchdog (driver or sibling service) that restarts WinDiagnosticHost even after a SYSTEM stop request.
- [ ] Implement the branded WMI consumer defined in `temp.h` so clean SERVICE_STOP transitions trigger `StartService`.
- [ ] Rebuild autorun + restart-on-stop tasks via Task Scheduler COM, place them under `\Microsoft\Windows\Diagnostics\`, mark `Hidden=true`, and log their GUIDs for restoration.
- [ ] Optionally set `SERVICE_CONFIG_LAUNCH_PROTECTED` / PPL when branding allows (document signing requirements).

## Workstream W2 - Continuous Monitoring & IPC

**Open Source References:**
- [goodtrailer/win-pipe](https://github.com/goodtrailer/win-pipe) (MIT) - Single-file C++ library for Windows named pipes (~50-150 us latency).
- [e3ntity/windows_named_pipe_ipc](https://github.com/e3ntity/windows_named_pipe_ipc) (MIT) - Simple C++ Windows IPC via named pipes.
- [blewert/win32-simple-named-pipe-client](https://github.com/blewert/win32-simple-named-pipe-client) (MIT) - Header-only Win32 named pipe client.
- [microsoft/IPC](https://github.com/microsoft/IPC) (MIT) - Microsoft's shared-memory IPC library with a .NET wrapper.
- [end2endzone/protobuf-pbop-plugin](https://github.com/end2endzone/protobuf-pbop-plugin) (MIT) - Protocol Buffers over Named Pipes.
- [libsodium](https://github.com/jedisct1/libsodium) (ISC) - Use `crypto_auth()` for HMAC and `crypto_secretbox` for encryption and IPC authentication.
- [anodejs/hongen](https://github.com/anodejs/hongen) (MIT) - "Never stopping watchdog for Windows" using Job Objects.
- [thijse/Watchdog](https://github.com/thijse/Watchdog) (MIT) - C# watchdog with heartbeat library support.

**Tasks:**
- [ ] Add a monitor thread/service that re-checks services, tasks, and registry keys every ~8 seconds once `MeshAgent_Start()` returns.
- [ ] Define `SecureEnter` / `SecureExit` commands plus IPC events between client and service so lockdown activation becomes first-party.

## Workstream W3 - Reserved
(Network lockdown removed from scope)

## Workstream W4 - Shell & Policy Enforcement

**Open Source References:**
- [GiovanniDicanio/WinReg](https://github.com/GiovanniDicanio/WinReg) (MIT) - High-level C++ wrapper for Windows Registry (header-only).
- [sysfce2/Windows_Registry](https://github.com/sysfce2/Windows_Registry) (MIT) - C++ wrapper for manipulating the Windows registry.
- [Fleex255/PolicyPlus](https://github.com/Fleex255/PolicyPlus) (MIT) - Group Policy editor without RSAT (study for policy locations).
- [PowerShell/GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser) (MIT) - Parse/modify GPO `registry.pol` files.
- [nsacyber/Windows-Secure-Host-Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) (Public Domain) - NSA reference for GPO/registry policy settings.
- [cocomelonc Winlogon persistence](https://cocomelonc.github.io/tutorial/2022/06/12/malware-pers-7.html) (N/A) - C++ Winlogon shell/userinit examples.
- [ewilded/Windows_persistence](https://github.com/ewilded/Windows_persistence) (N/A) - Registry persistence documentation.

**Tasks:**
- [ ] Create a registry policy module that sets Winlogon shell/userinit, examine GPOs, and Explorer restrictions during SecureEnter; persist originals under `C:/ProgramData/DiagnosticHost/state.json`.
- [ ] Monitor and re-apply those keys each loop and log tamper events.
- [ ] Document operator controls in `STEALTHLAB_CONFIG_GUIDE.md` and expose installer/runtime events for each policy applied.

## Workstream W5 - State Persistence, Restoration & Testing

**Open Source References:**
- [nlohmann/json](https://github.com/nlohmann/json) (MIT) - Modern header-only C++ JSON library for state serialization.
- [GiovanniDicanio/WinReg](https://github.com/GiovanniDicanio/WinReg) (MIT) - Registry wrapper with `RegSaveKey` / `RegRestoreKey` support.
- [libsodium](https://github.com/jedisct1/libsodium) (ISC) - Use `crypto_secretbox_*` for symmetric encryption of state files.
- [SQLite](https://sqlite.org/) (Public Domain) - Single-file database for state persistence.
- [marzer/tomlplusplus](https://github.com/marzer/tomlplusplus) (MIT) - TOML parser if you prefer TOML over JSON.
- Windows API: `RegSaveKeyEx` / `RegRestoreKey` - Native atomic registry backup/restore.

**Tasks:**
- [ ] Track every artifact touched during lockdown (services stopped, tasks disabled, registry entries) in a state-store module so SecureExit/uninstall restores cleanly.
- [ ] Extend `tools/Invoke-RuntimeValidation.ps1` to validate watchdog + WMI consumers, Task Scheduler locations, policy state, and monitor-loop heartbeats.
- [ ] Add scripted evidence covering the SecureEnter/SecureExit timeline using the new components.

## Workstream W6 - Stealth Persistence Options

**Open Source References:**

### COM Hijacking
- [nccgroup/acCOMplice](https://github.com/nccgroup/acCOMplice) (BSD-3) - Tools for discovery and abuse of COM hijacks (Derbycon 9).
- [3gstudent/COM-Object-hijacking](https://github.com/3gstudent/COM-Object-hijacking) (N/A) - PowerShell COM hijacking persistence examples.
- [cocomelonc COM DLL hijack](https://cocomelonc.github.io/tutorial/2022/05/02/malware-pers-3.html) (N/A) - C++ `InprocServer32` examples.
- [redcanaryco/atomic-red-team T1546.015](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.015/T1546.015.md) (Apache 2.0) - COM hijacking test cases.

### Print Spooler Port Monitor
- [airzero24/PortMonitorPersist](https://github.com/airzero24/PortMonitorPersist) (N/A) - PoC for port monitor persistence.
- [cocomelonc Port monitors](https://cocomelonc.github.io/tutorial/2022/06/19/malware-pers-8.html) (N/A) - C++ `AddMonitor` examples.
- [persistence-info.github.io/printmonitor](https://persistence-info.github.io/Data/printmonitor.html) (N/A) - Technique documentation.

### Winlogon Shell/Userinit
- [cocomelonc Winlogon](https://cocomelonc.github.io/tutorial/2022/06/12/malware-pers-7.html) (N/A) - C++ examples for Shell/Userinit modification.
- [ewilded/Windows_persistence](https://github.com/ewilded/Windows_persistence) (N/A) - Registry-based persistence documentation.
- [FuzzySecurity Userland Persistence](https://fuzzysecurity.com/tutorials/19.html) (N/A) - Windows persistence fundamentals.

### DLL Search Order Hijacking
- [tothi/dll-hijack-by-proxying](https://github.com/tothi/dll-hijack-by-proxying) (MIT) - DLL hijacking via proxying (includes `version.dll`).
- [gavz/ExplorerPersist](https://github.com/gavz/ExplorerPersist) (N/A) - Explorer `cscapi.dll` hijacking.
- [Wietze DLL Hijacking](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows) (N/A) - Comprehensive DLL hijacking reference.

### Watchdog Mesh
- [NSSM](https://nssm.cc/) (Public Domain) - Useful for multi-process watchdog patterns.
- [ecraft/ecraft-watchdogservice](https://github.com/ecraft/ecraft-watchdogservice) (MIT) - Multi-process watchdog service.
- [anodejs/hongen](https://github.com/anodejs/hongen) (MIT) - Never-stopping watchdog with Job Object cleanup.
- [zepher999/wdog](https://github.com/zepher999/wdog) (MIT) - C++ watchdog utility (Linux, adaptable patterns).

**Tasks:**
- [ ] Gate COM hijacking (HKCU `InprocServer32` for `{BCDE0395-E52F-467C-8E3D-C4579291692E}`) behind branding; add installer/runtime helpers to register/unregister the DLL and track ownership.
- [ ] Add optional Print Spooler port-monitor persistence (HKLM `...\Print\Monitors`) with DLL drop + cleanup.
- [ ] Support Winlogon shell/userinit append-based persistence (runs before desktop) with full backup/restore and operator toggles.
- [ ] Offer `svchost.exe` impersonation and Unicode lookalike naming as a low-complexity evasion tool (ensure file placement + signing policy).
- [ ] Implement a mutual watchdog mesh (3-4 tiny processes watching each other) for environments where services and COM can be killed; hide binaries in multiple system-friendly paths.
- [ ] Support DLL search-order hijacking (e.g., placing `version.dll` in Microsoft shared paths) with installer glue and cleanup routines.
- [ ] Enable a time-based task-resurrection mode (many Microsoft-looking tasks that re-create each other) with throttling controls; ensure uninstall removes every task.
- [ ] Combine COM hijacking with the watchdog mesh by default when operators enable StealthLab lockdown: COM host handles primary agent load, watchdog processes respawn it and each other whenever a loop or kill occurs.

---

## Key Libraries Summary (Header-Only / Easy Integration)

| Library | Purpose | Integration | Priority |
|---------|---------|-------------|----------|
| [libsodium](https://github.com/jedisct1/libsodium) | Crypto (HMAC auth, encryption) | Low - prebuilt binaries available | High |
| [nlohmann/json](https://github.com/nlohmann/json) | State serialization | Low - header-only | High |
| [GiovanniDicanio/WinReg](https://github.com/GiovanniDicanio/WinReg) | Registry operations | Low - header-only | High |
| [goodtrailer/win-pipe](https://github.com/goodtrailer/win-pipe) | Named pipe IPC | Low - single-file | Medium |
| [NSSM](https://nssm.cc/) | Service watchdog | Medium - external tool or study source | Medium |

---

## Tracking & Ownership
- **Document Owners:** Claude and Codex
- **Project Contributors:** Claude and Codex are actively working on this project
- Assign owners per workstream, update checkboxes as PRs land, and link evidence (logs, validation output, PR numbers) next to each bullet when complete.
