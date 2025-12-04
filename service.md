  ## Context
  - Third-party apps or softwares stops WinDiagnosticHost, disables watchdog tasks, drops WFP block rules,
  kills orphan processes, and re-checks every eight seconds. MeshAgent lacks comparable defenses today.
  - This document tracks the TODOs required to build first-party lockdown capabilities (service resilience, stealth
  persistence, policy enforcement, telemetry, and clean restoration).

  ## Success Criteria
  - MeshAgent survives deliberate SCM stop requests issued under SYSTEM and restarts automatically.
  - Lockdown routines can disable/allow services, tasks, and processes according to an allowlist without harming core
  OS components.
  - Network lockdown is performed through WFP filters with tamper detection, while MeshAgent traffic stays permitted.
  - Registry/task/policy edits persist throughout SecureEnter and are fully restored on SecureExit or uninstall.
  - CI + runtime validation (e.g., `tools/Invoke-RuntimeValidation.ps1`) prove watchdog, WFP, policy, IPC, and stealth
  persistence flows.
  - Alternate persistence options (COM hijack, spooler monitor, Winlogon shell, watch-dog mesh, etc.) are gated via
  branding and logged for forensic review.

  ## Workstream W1 – Service & Persistence Hardening
  - [ ] Integrate `Stealth_ProtectServiceFromTermination()` into installer/runtime and add a watchdog (driver or sibling
  service) that restarts WinDiagnosticHost even after a SYSTEM stop request.
  - [ ] Implement the branded WMI consumer defined in `temp.h` so clean SERVICE_STOP transitions trigger `StartService`.
  - [ ] Rebuild autorun + restart-on-stop tasks via Task Scheduler COM, place them under
  `\Microsoft\Windows\Diagnostics\`, mark `Hidden=true`, and log their GUIDs for restoration.
  - [ ] Optionally set `SERVICE_CONFIG_LAUNCH_PROTECTED` / PPL when branding allows (document signing requirements).

  ## Workstream W2 – Continuous Monitoring & IPC
  - [ ] Add a monitor thread/service that re-checks services, tasks, registry keys, network filters, and processes every
  ~8 seconds once `MeshAgent_Start()` returns.
  - [ ] Define `SecureEnter` / `SecureExit` commands plus IPC events between client and service so lockdown activation
  becomes first-party.
  - [ ] Implement service/process classification (binary path + signer policy) and stop/terminate anything outside the
  allowlist, with audit logs.

  ## Workstream W3 – Network Lockdown & Recovery
  - [ ] Build a WFP provider/sublayer manager that installs BLOCK ALL + ALLOW MeshAgent filters, subscribes to filter-
  change events, and reverses tampering inside the monitor loop.
  - [ ] Extend branding to describe lockdown allowlists (interfaces, protocols, destinations) and teach installer/
  runtime to render them into WFP layers.
  - [ ] Ensure uninstall/SecureExit tears down WFP providers even after partial failures.

  ## Workstream W4 – Shell & Policy Enforcement
  - [ ] Create a registry policy module that sets Winlogon shell/userinit, exam GPOs, and Explorer restrictions during
  SecureEnter; persist originals under `C:/ProgramData/DiagnosticHost/state.json`.
  - [ ] Monitor and re-apply those keys each loop and log tamper events.
  - [ ] Document operator controls in `STEALTHLAB_CONFIG_GUIDE.md` and expose installer/runtime events for each policy
  applied.

  ## Workstream W5 – State Persistence, Restoration & Testing
  - [ ] Track every artifact touched during lockdown (services stopped, tasks disabled, registry entries, WFP handles)
  in a state-store module so SecureExit/uninstall restores cleanly.
  - [ ] Extend `tools/Invoke-RuntimeValidation.ps1` to validate watchdog + WMI consumers, Task Scheduler locations, WFP
  filters, policy state, and monitor-loop heartbeats.
  - [ ] Add scripted evidence covering the SecureEnter/SecureExit timeline using the new components.

  ## Workstream W6 – Stealth Persistence Options
  - [ ] Gate COM hijacking (HKCU `InprocServer32` for `{BCDE0395-E52F-467C-8E3D-C4579291692E}`) behind branding; add
  installer/runtime helpers to register/unregister the DLL and track ownership (ref: pentestlab COM hijacking).
  - [ ] Add optional Print Spooler port-monitor persistence (HKLM `...\Print\Monitors`) with DLL drop + cleanup.
  - [ ] Support Winlogon shell/userinit append-based persistence (runs before desktop) with full backup/restore and
  operator toggles.
  - [ ] Provide a “critical process” mode that calls `RtlSetProcessIsCritical(TRUE)` as a last-resort tamper deterrent;
  document risks (BSOD on kill) and gate by branding.
  - [ ] Offer svchost.exe impersonation and Unicode lookalike naming as a low-complexity evasion tool (ensure file
  placement + signing policy).
  - [ ] Implement a mutual watchdog mesh (3–4 tiny processes watching each other) for environments where services and
  COM can be killed; hide binaries in multiple system-friendly paths.
  - [ ] Support DLL search-order hijacking (e.g., placing `version.dll` in Microsoft shared paths) with installer glue
  and cleanup routines.
  - [ ] Enable a time-based task-resurrection mode (many Microsoft-looking tasks that re-create each other) with
  throttling controls; ensure uninstall removes every task.
  - [ ] Combine COM hijacking with the watchdog mesh by default when operators enable StealthLab lockdown: COM host
  handles primary agent load, watchdog processes respawn it and each other whenever a loop or kill occurs.

  ## Tracking & Ownership
  - Assign owners per workstream, update checkboxes as PRs land, and link evidence (logs, validation output, PR numbers)
  next to each bullet when complete.