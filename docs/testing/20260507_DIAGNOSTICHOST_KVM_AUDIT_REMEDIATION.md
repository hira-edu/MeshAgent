# 2026-05-07 DiagnosticHost KVM Audit Remediation Plan

## Scope

This plan is limited to the audit-backed DiagnosticHost remote-desktop findings observed on this host. The retained KVM surface remains the SSOT-defined `svchost` service plus `rundll32.exe` Session 1 bridge:

- `meshservice/stealth_svchost.c`
- `meshcore/KVM/Windows/kvm.c`
- `microstack/ILibProcessPipe.c`

No browser, relay, generic process-spawn, or PowerShell lifecycle layer owns this fix.

## Regression Surface Map

| Finding | Source path | Touched target | Regression surface | Fix rule |
|---|---|---|---|---|
| CRT invalid parameter in bridge read compaction | `microstack/ILibProcessPipe.c` | Windows process-pipe read windows | KVM bridge pipes and any Windows `ILibProcessPipe` consumer | validate read-window invariants before pointer arithmetic or compacting buffers |
| CRT invalid parameter in environment merge | `microstack/ILibProcessPipe.c` | Windows process-spawn environment block merge | KVM bridge spawn and any `CreateProcess*` caller that passes override env vars | use byte counts for `memcpy_s`; fail spawn deterministically if merge cannot be represented |
| CRT handler swallowed KVM helper corruption | `meshservice/stealth_svchost.c` | `KvmSessionBridgeW` helper process only | rundll32-hosted bridge helper | fail fast only for the bridge helper so WER/LocalDumps can capture corruption |
| Missing primary log evidence for first packets | `meshcore/KVM/Windows/kvm.c`, `meshservice/stealth_svchost.c` | bridge/service KVM telemetry | KVM trace logging only when `STEALTH_KVM_TRACE_STARTUP` is enabled | write the same first-packet and lifecycle evidence to module-local `svchost-debug.log`; keep legacy temp trace for existing probes |
| Child-exit evidence loses PID | `meshcore/KVM/Windows/kvm.c` | KVM child exit handling | KVM lifecycle logging and event correlation | resolve PID from the sender process/context before marking child absent; child-present state remains the authority for active status |
| Session-switch resolution update can run before tile geometry is initialized | `meshcore/KVM/Windows/kvm.c`, `meshcore/KVM/Windows/tile.h`, `meshcore/KVM/Windows/tile.cpp` | KVM service resolution recalculation | desktop/session switch and startup `kvm_server_SetResolution` callers | initialize tile defaults from shared constants and make `SetResolution` repair tile geometry plus prime and validate screen geometry before tile arithmetic |
| Auto-selected TSID stored as explicit session ownership | `meshcore/KVM/Windows/kvm.c`, `meshcore/KVM/Windows/kvm.h`, `meshservice/ServiceMain.c` | KVM bridge session-change lifecycle | Schoolyear-triggered TerminalServices logoff/logon and reconnect to a new session | preserve whether the operator requested an explicit TSID; keep explicit TSID strict; ignore unrelated stop events for auto-selected contexts; reject start events only when the target session has no queryable user token; valid interactive start events rebind auto-selected KVM even when the old helper is still alive |
| Global KVM helper job reused across sessions | `meshcore/KVM/Windows/kvm.c`, `meshservice/stealth_watchdog.c`, `microstack/ILibProcessPipe.c` | rundll32 bridge DACL/job hardening | Schoolyear session replacement from session 1 to session 2 | create the bridge suspended, apply DACL plus a fresh kill-on-close job through the original creation handle, then resume; never assign multi-session KVM helpers to the shared watchdog job |
| Startup provisioning log ignored branded files | `meshservice/stealth_svchost.c` | svchost service startup logging | DiagnosticHost config observability | log hidden, DLL-named, executable-sibling, service-named `.msh`, plus branded `.conf` candidates |
| Build outputs dirty the tree | `.gitignore`, git index | repo hygiene | build output directories only | `MeshAgent.Build.proj` is the SSOT build entrypoint; generated binaries/intermediates are not implementation truth |

## Build SSOT

Use one supported build command for StealthLab outputs:

```cmd
MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

`MeshAgent.Build.proj` serializes:

1. `StealthLab_DLL|x64`
2. `MeshConsole|Release|x64`
3. `StealthLab|x64`
4. `StealthLab|Win32`

Do not run parallel direct project builds against the same tree. Do not introduce PowerShell build wrappers; Python asset generators remain MSBuild targets.

## Verification Gates

Minimum targeted gates for this remediation:

- `node test/kvm_audit_findings_contract.js`
- `node test/kvm_bridge_flow_control_contract.js`
- `node test/kvm_remote_desktop_freshness_contract.js`
- `node test/kvm_bridge_system_token_contract.js`
- `node test/kvm_desktop_lifecycle_contract.js --evidence <evidence-root>`
- `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`

Browser/relay regressions are out of this source tree unless the sibling MeshCentral repo is present and its SSOT paths are available.

## 2026-06-18 Evidence Update

- Source crash signature: UserModeHook artifact `artifacts\schoolyear_kvm_devicecheck_postreboot_20260618_030909` reported WindowsDiagnosticHost WER failures in `C:\ProgramData\DiagnosticHost\diagsvc.dll`, exception `c0000094`, offset `0x44eba`.
- Symbolized owner: matching `meshservice\x64\StealthLab_DLL\MeshService-2022.dll` resolved `diagsvc.dll+0x44eba` to `meshcore\KVM\Windows\kvm.c` `kvm_server_SetResolution`; disassembly showed division by the global tile width after session-switch entry could precede `initialize_gdiplus`.
- Implemented fix: shared `KVM_TILE_DEFAULT_WIDTH` and `KVM_TILE_DEFAULT_HEIGHT` constants, nonzero global tile defaults, `kvm_server_ensure_tile_geometry`, and `kvm_server_prime_startup_geometry_if_needed` before `SetResolution` arithmetic.
- Contract evidence: `docs\testing\evidence\advanced\20260618_134800_kvm_setresolution_geometry_contract\summary.txt` reports `SUCCESS=true` with `kvmTileDefaultsAreSharedConstants=true`, `kvmSetResolutionRestoresTileGeometryBeforeArithmetic=true`, and `kvmSetResolutionPrimesAndValidatesScreenGeometryBeforeTileAllocation=true`.
- Build evidence: direct `StealthLab_DLL|x64` project build completed with `0 Warning(s)` and `0 Error(s)` using an alternate verify PDB path because installed `WinDiagnosticHost` held the normal PDB open; full Build SSOT `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal` then completed with exit `0`.
- Deployment drift evidence: the first local update at 14:02 installed the rebuilt DLL, but the restarted agent accepted a MeshCentral self-update from `c:\programdata\diagnostichost\diaghost.update.pkg` at 14:04 and restored old hash `32BEDF212F5870465A4819E4662DC6763781010E04550FA102ACA72C7AE91C18`. This was server self-update drift, not a UserModeHook, browser, KVM, or process-name heuristic.
- ProgramData deployment evidence: `docs\testing\evidence\advanced\20260618_141430_kvm_programdata_deploy\summary.txt` records the redeploy with the existing product `disableUpdate=1` self-update hold, installed `diagsvc.dll` SHA-256 `7795395588CE77E6E6F2C0CF6438D9B031FCADD38B0B292C3759856963927335`, installed `diaghost.exe` SHA-256 `0CC2AC7FAC06270F7B56112CD750EFB098CF1BA7CE1266049DB0CAF95D971905`, `WinDiagnosticHost` running, registry `ServiceDllHash` matching the rebuilt DLL, no replay after the prior 38-second reversion window, and native `validate-install` success through `MeshLifecycleHostW`.
- Runtime closure update: `docs\testing\evidence\advanced\20260618_live_kvm_session_switch_closure\summary.txt` records post-fix session disconnect/logoff/logon transitions on the deployed fixed payload with no new DiagnosticHost Application Error or WER reports. Live interactive KVM/browser proof and release-bundle gates remain separate TODO-027 closure items.

## 2026-06-18 svchost Crash Root-Cause Audit

- Evidence root: `docs\testing\evidence\advanced\20260618_162638_svchost_crash_root_cause\summary.txt`.
- Crash categorization: the repeated `svchost.exe` crashes are the DiagnosticHost KVM `diagsvc.dll` `c0000094` divide-by-zero bucket at offset `0x44eba`; session switching is the trigger, while `meshcore\KVM\Windows\kvm.c` `kvm_server_SetResolution` tile/screen geometry was the defective precondition.
- Separate bucket retained: the `svchost.exe` `ntdll.dll` `c0000374` bucket on 2026-06-16 is the previously fixed KVM relay shutdown user-object lifetime class, not the same `SetResolution` divide-by-zero.
- UserModeHook disposition: reviewed `C:\Users\Workstation\Documents\GitHub\UserModeHook\src\MasterService.cpp` session-continuity respawn paths and DiagnosticHost protection paths in `src\LockdownBypass`; Sysmon parentage shows the crashing DiagnosticHost processes were service-owned by `services.exe`, not spawned or loaded by UserModeHook. No UserModeHook code change is justified by the retained crash evidence.
- Validation in this audit root: focused lifecycle contract passed, `StealthLab_DLL|x64` MSBuild passed with 0 warnings and 0 errors, and adjacent KVM shutdown/audit/freshness/flow-control contracts passed.

## 2026-06-18 Live Session-Switch Closure

- Evidence root: `docs\testing\evidence\advanced\20260618_live_kvm_session_switch_closure\summary.txt`.
- Deployed payload under observation: `C:\ProgramData\DiagnosticHost\diagsvc.dll` SHA-256 `7795395588CE77E6E6F2C0CF6438D9B031FCADD38B0B292C3759856963927335`, `WinDiagnosticHost` running as PID 1876.
- Post-fix session-change evidence: TerminalServices LocalSessionManager recorded session 1 disconnect/logoff, session 2 disconnect/logoff/logon, and session 3 logon after the fixed deployment window.
- Crash-absence evidence: post-deploy WER archive/queue queries are empty for DiagnosticHost/svchost/diagsvc/diaghost, and post-deploy Application crash-ID matches contain no DiagnosticHost entries.
- Tooling gap retained: `ProcDump -ma 1876` and the latest local fullupdate require elevation from this shell; the latest validation build produced a new local DLL hash, but the running service remains on the earlier fixed deployment hash.
- Validation in this closure root: focused KVM desktop lifecycle contract passed, `StealthLab_DLL|x64` MSBuild passed with 0 warnings and 0 errors, and adjacent KVM shutdown/audit/freshness/flow-control contracts passed after the final build.

## 2026-06-18 Crash-Fix Release Bundle

- Evidence root: `docs\testing\evidence\advanced\20260618_171000_release_signing_crashfix\summary.txt`.
- Bundle: `docs\testing\artifacts\20260618_171000_crashfix_realignment_bundle.zip`; authoritative SHA-256/SHA-384 values are recorded in the release evidence summary.
- Gate result: staged 10 release files, generated SHA-256/SHA-384 digests, copied the current crash-fix evidence roots, generated release/signing manifests, and passed with `SIGNING_ENFORCEMENT=false` from the branding policy.
- Post-bundle crash snapshot: Application crash-ID matches, WER archive, and WER queue checks remained empty for DiagnosticHost/svchost/diagsvc/diaghost after the fixed deployment window.
- Scope note: this is a crash-fix candidate bundle. It does not replace the remaining TODO-027 runtime gates for live interactive KVM/browser proof, proxy/WPAD, or elevated latest-build deployment.

## 2026-06-18 KVM/Browser Contract Refresh

- Evidence root: `docs\testing\evidence\advanced\20260618_171500_kvm_browser_contract_refresh\summary.txt`.
- MeshAgent KVM/session contracts passed for service-token handling, session-change dispatch, multi-session selection, bridge hardening, RAMAS selection, and remote-desktop agent resolution.
- MeshCentral browser/relay contracts passed for initial KVM connected-state ownership, binary-frame handling, desktop reconnect/same-size reset, multiplex same-size handling, send-queue correctness, and server deploy mapping.
- User-context runtime proof: `test\kvm_initial_frame_runtime.js` produced nonblack first frames for `auto`, `gdi`, `dxgi`, and `wgc` capture backends with average brightness around 43.
- SYSTEM runtime gap: `test\kvm_system_picture_runtime.js` timed out waiting for its report, and an independent `PsExec -s whoami /all` check failed with `Couldn't install PSEXESVC service: The handle is invalid`; SYSTEM interactive KVM/browser proof remains open from this shell.
- Proxy/WPAD note: no live proxy/WPAD test was rerun; TODO-059 remains blocked by the existing matrix note that prior WPAD validation was stopped because it disconnected other terminals.

## 2026-06-26 Schoolyear Session-Switch TSID Rebind Update

- Evidence roots: `docs\testing\evidence\advanced\20260626_230000_kvm_session_tsid_rebind_deploy\summary.txt` and final guarded deployment `docs\testing\evidence\advanced\20260626_234000_kvm_tsid_rebind_guard_remote_deploy\summary.txt`.
- Schoolyear transition evidence: TerminalServices on 2026-06-26 recorded `schoolyear-exams-service.exe` issuing `RpcLogoff` at 22:16:03, session 1 logoff/disconnect at 22:16:14, and session 2 logon/shell at 22:19:19. The retained crash in the same window was `svchost.exe` / `diagsvc.dll`, exception `c0000094`, offset `0x44eba`.
- Deployment drift/root cause retained: before this update, installed `C:\ProgramData\DiagnosticHost\diagsvc.dll` SHA-256 `32BEDF212F5870465A4819E4662DC6763781010E04550FA102ACA72C7AE91C18` still carried the old `kvm_server_SetResolution` divide-by-zero path.
- Additional lifecycle root cause: `kvm_relay_setup` resolved `tsid=-1` to the then-active session and stored it as if it had been explicitly requested, so a later Schoolyear logoff/logon to a new session could be rejected by the session-change guard and block deterministic helper respawn.
- Implemented fix: `KvmRelayContext` and the debug snapshot now preserve `processTSIDExplicit`; explicit TSID requests remain strict, while auto-selected contexts ignore unrelated stop events and unrelated active-start events. Auto-selected rebind is allowed only after the current lifecycle is stopped/suppressed or no child is present, including remote connect/disconnect classes already forwarded by `ServiceMain`.
- No heuristic or product-name remap was introduced: the implementation does not special-case Schoolyear, process names, browser names, or target paths. It uses TerminalServices event class plus the explicit-vs-auto TSID contract.
- Local production deployment: native `-fullupdate` installed final guarded `diagsvc.dll` SHA-256 `FE1623D70FF70CB199D1D3E0AEFA7F9C41351114BDC795F865BBFD50C971AA99` and `diaghost.exe` SHA-256 `9DB32906C6A4CC4350287B8E308CF4AAA3E77515D92F59EA7DE207E13B25F0F8`; registry `ServiceDllHash` matched the DLL and `WinDiagnosticHost` was running as PID 4160.
- Runtime evidence: `docs\testing\evidence\advanced\20260626_234000_kvm_bridge_session_change_runtime_guard\summary.txt` reports `SUCCESS=true`; explicit mode kept `TSID_EXPLICIT=true`, auto mode kept `TSID_EXPLICIT=false`, auto mode ignored unrelated start and stop session `10001`, and both modes respawned through lock/unlock and disconnect/reconnect without the legacy fallback path.
- Crash-absence evidence: post-guard Application Error and WER checks after 2026-06-26 23:29 local found no DiagnosticHost, `diagsvc.dll`, `diaghost.exe`, or `svchost.exe` crash entries.
- Remote deployment: the first direct-SSH VOS attempt is retained as blocked in `docs\testing\evidence\advanced\20260626_232000_kvm_tsid_rebind_remote_deploy\summary.txt`. Final publish used `tools\ssh_http_connect_proxy.py` with the local Webshare proxy list; `deploy.py stage`, `deploy.py deploy -y`, and `deploy.py health` completed successfully. Remote data/module `MeshService64.exe` hashes match `9DB32906C6A4CC4350287B8E308CF4AAA3E77515D92F59EA7DE207E13B25F0F8`, remote `diagsvc.dll` / `MeshService64.dll` / `svchost_payload.dll` hashes match `FE1623D70FF70CB199D1D3E0AEFA7F9C41351114BDC795F865BBFD50C971AA99`, and the signed-agent EXE's embedded svchost payload also matches `FE1623D70FF70CB199D1D3E0AEFA7F9C41351114BDC795F865BBFD50C971AA99`.

## 2026-06-27 Live KVM Regression Follow-Up

- Evidence roots: `docs\testing\evidence\advanced\20260627_003000_meshcentral_live_kvm_text_frame_probe\summary.txt`, `docs\testing\evidence\advanced\20260627_003800_meshcentral_viewer_asset_drift_fix\summary.txt`, `docs\testing\evidence\advanced\20260627_004000_meshcentral_live_kvm_after_viewer_asset_fix\summary.txt`, `docs\testing\evidence\advanced\20260627_004200_schoolyear_diagnostichost_delta_audit\summary.txt`, and `docs\testing\evidence\advanced\20260627_004500_meshcentral_viewer_asset_parity\summary.txt`.
- Schoolyear session evidence remains `RpcLogoff`-based, not lock/unlock: TerminalServices LocalSessionManager recorded `schoolyear-exams-service.exe` issuing `RpcLogoff`, followed by session 1 disconnect/logoff and later replacement user-session logons.
- DiagnosticHost delta: Application/WER retained a pre-guard `svchost.exe` / `diagsvc.dll` `c0000094` crash at 2026-06-26 22:18:18 local. The exact crash-era PDB was not available in this follow-up, so the latest symbol check is not treated as line-proof; the crash class still matches the already-fixed KVM startup geometry divide-by-zero family. Post-00:20 local Application/System checks found no new DiagnosticHost crash or service-failure entries after repeated live KVM probes.
- Live probe correction: `tools\meshcentral_kvm_live_probe.js` now parses MeshCentral text-framed KVM binary payloads instead of treating them as UTF-8 text. The prior zero-packet observation against the actual node was a probe parser gap; the corrected probe observed 3440x1440 screen packets and JPEG picture packets.
- VPS viewer root cause: remote `agent-desktop-0.0.2.js` and `agent-desktop-0.0.2-min.js` were stale and still ignored same-size screen packets. The agent and relay were sending frames, but a browser reconnect/session-switch at the same 3440x1440 size could remain visually stuck on stale viewer state.
- VPS remediation: using the proxy-backed SSH path, the two remote viewer assets were backed up under `/opt/meshcentral/server-backups/20260626_192311_agent_desktop_asset_drift`, replaced with the local MeshCentral contract-passing assets, and MeshCentral was restarted. Served public assets now hash-match local: standard `35d29c3abb56de7c6cbf58ac293234426a968abfb24427273f03ce7f7c1a4b88`, minified `26224e6bd5f678cff2902f794842f1e89e1da643866e0d33d021b9190558744d`.
- Post-fix live evidence: `tools\meshcentral_viewer_asset_parity.js` reports served viewer parity success, `deploy.py health` passed after restart, and the actual-node live KVM probe reported `SUCCESS=True`, two 3440x1440 screen packets, 152 JPEG picture packets, and exit code 0.

## 2026-06-27 Schoolyear Hardening Delta Closure

- Root cause: the production KVM bridge reused `Watchdog_GetOrCreateJobObject()` for rundll32 helpers. Windows job objects are session-scoped once populated, so a job first used by a session 1 helper could reject later session 2 helper assignment with `ERROR_ACCESS_DENIED`. DiagnosticHost logged this as repeated `rundll32 bridge hardening failed error=5`, then killed the helper before KVM could reconnect.
- Implemented fix: KVM now launches the bridge through `ILibProcessPipe_Manager_SpawnProcessEx5`, which creates the process suspended with `CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB`. The pre-start callback applies `Stealth_ProtectProcessByHandle`, creates a fresh `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job via `Watchdog_CreateKillOnCloseJobObject`, assigns the suspended process to that per-helper job, and only then resumes the primary thread. The job handle is stored in `KvmRelayContext` and closed on child exit or teardown.
- No heuristic was added: no Schoolyear process-name mapping, browser-name mapping, retry suppression, fallback spawn mode, or hardening bypass was introduced. DACL and job assignment remain mandatory hard gates.
- Local deployment: native `-fullupdate --update-source=...\MeshService-2022.exe` installed `diaghost.exe` SHA-256 `927D08C32A709497BC3685E4F00F63DF3B6FEF7F488CDF2D3F03D7B1A9FC3827` and `diagsvc.dll` SHA-256 `18AF151BC8741418DF9DCE4D5C2916DDA4A07D73DCE049197D3EBDBEAC58BA32`; `-svchost-status` reported `success=true`, registry `ServiceDllHash` matched, and `WinDiagnosticHost` restarted as PID 10772.
- Verification evidence: `docs\testing\evidence\advanced\20260627_010700_kvm_bridge_hardening_runtime_scoped_job\summary.txt` reports DACL denial and existing-handle termination success; `docs\testing\evidence\advanced\20260627_010700_kvm_bridge_session_change_runtime_scoped_job\summary.txt` reports explicit and auto TSID session-change success; `docs\testing\evidence\advanced\20260627_012200_meshcentral_live_kvm_after_scoped_job_fix\summary.txt` reports live actual-node KVM success with two 3440x1440 screen packets and 522 JPEG picture packets; `docs\testing\evidence\advanced\20260627_013000_kvm_bridge_event_audit_runtime_after_job_fix\summary.txt` reports event-audit success; `docs\testing\evidence\advanced\20260627_013000_kvm_bridge_crash_recovery_runtime_full_budget_after_job_fix\summary.txt` reports the full six-step crash-recovery backoff sequence without an outer timeout.
- Post-deploy log check: after 2026-06-27 00:55 local, DiagnosticHost logs contain clean bridge spawn/exit pairs and no new `hardening failed`, `pre-start hardening failed`, or `hardening contract incomplete` lines. Application and System event checks for DiagnosticHost after that time found zero entries.
- Remote deployment: proxy-backed `deploy.py stage` uploaded the rebuilt payload, `deploy.py health` passed, `deploy.py status` showed a new backup `20260626_200006` and publish state `data=ok module=ok manifest=ok`, and remote SHA-256 values match local: `MeshService64.exe` `927D08C32A709497BC3685E4F00F63DF3B6FEF7F488CDF2D3F03D7B1A9FC3827`; `diagsvc.dll` / `MeshService64.dll` / `svchost_payload.dll` `18AF151BC8741418DF9DCE4D5C2916DDA4A07D73DCE049197D3EBDBEAC58BA32`.
- Reprobe after user regression report: `docs\testing\evidence\advanced\20260627_011700_meshcentral_live_kvm_reprobe_after_user_regression_report\summary.txt` reports `SUCCESS=True`, control and relay open, connect marker received, two 3440x1440 screen packets, 561 JPEG picture packets, and 913874 picture bytes. The corresponding DiagnosticHost tail contains a clean `bridge spawn OK` / `bridge first screen packet` / child exit sequence with no hardening failure strings. A separate served viewer recheck in `docs\testing\evidence\advanced\20260627_012200_viewer_asset_parity_reprobe_after_user_regression_report\summary.txt` reports both desktop viewer assets hash-matching local with the stale same-size guard absent. This proves the current installed first-open MeshCentral KVM path and served viewer asset parity, but it does not close the exact Schoolyear disconnect/reconnect gate because no post-update TerminalServices session-switch event or Schoolyear product repeat was present in the local evidence window.

## 2026-06-27 Schoolyear Auto-Selected Session Rebind Regression Correction

- Root cause: the previous guard that ignored an unrelated auto-selected start event while a helper was alive was too conservative for the observed Schoolyear flow. TerminalServices evidence shows Schoolyear uses `schoolyear-exams-service.exe` `RpcLogoff`, then the original interactive session logs off/disconnects and a replacement interactive session logs on later. A valid replacement-session `WTS_SESSION_LOGON` / connect event can therefore arrive while the old helper is still alive or still exiting; rejecting it pins KVM to the old session and can leave the viewer on `Winlogon`.
- Implemented correction: `kvm_relay_handle_session_change_for_context` now distinguishes start and stop events, keeps explicit TSID requests strict, continues to ignore unrelated auto-selected stop events, and rejects unrelated auto-selected start events only when `WTSQueryUserToken(sessionId)` fails. A valid auto-selected start event updates `gProcessTSID` and `gKvmProcessSessionId`, clears restart suppression, and soft-kills the old helper so the existing child-exit lifecycle restarts in the new interactive session.
- No heuristic was added: the fix does not special-case Schoolyear, process names, browser names, launch paths, retry counts, or fallback spawn modes. The decision is based on the explicit-vs-auto TSID contract plus TerminalServices session/user-token evidence.
- Observability correction: `ServiceMain` now logs `[ServiceMain] Forwarding KVM session change event=%lu session=%lu` before calling `kvm_notify_session_change`, and `tools\meshcentral_kvm_live_probe.js` now filters helper snapshots to real `rundll32.exe` `KvmSessionBridgeW` helpers, parses text-framed KVM binary payloads, and saves bounded JPEG sample payloads for visual review.
- Build/deploy evidence: `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal` completed successfully for the rebuilt native payload. Webshare-proxy-backed VPS publish reached the server; `deploy.py deploy -y` timed out locally, but subsequent `deploy.py status`, `deploy.py health`, and remote SHA-256 checks proved the publish landed. Remote and local installed hashes match the rebuilt tranche: `MeshService64.exe` / `diaghost.exe` `1C6009C08E2F3F0847B2413A787A002F35961CAA00096F3062C277E7A309ADC8`; `diagsvc.dll` / `MeshService64.dll` / `svchost_payload.dll` `A29E9E38A5945D3AF6306C090006B4FFE647D7CBE116B4DC56901FE381F5D2DC`.
- Local runtime state after deployment: native `-fullupdate --update-source=...\MeshService-2022.exe` completed at `2026-06-27 01:40:33 +05:00`, `WinDiagnosticHost` is running as PID `11364`, and the active `KvmSessionBridgeW` helper is PID `3604` under that service. `query session` showed only console session `1` active and no Schoolyear process at the time of the post-patch checks.
- Verification evidence: `docs\testing\evidence\advanced\20260627_023200_kvm_session_change_contract_final\summary.txt` reports `SUCCESS=true` and pins `relayAutoSelectedTsidDoesNotPinLiveOldChildOnValidStart=true`, `relayAutoSelectedTsidRejectsNonInteractiveStartSession=true`, and `relayRebindsLiveOldChildThroughExistingExitLifecycle=true`. `docs\testing\evidence\advanced\20260627_022900_live_kvm_post_schoolyear_rebind_fix_with_payload_samples\summary.txt` reports first-open live KVM success with two 3440x1440 screen packets, 2033 JPEG picture payloads, zero non-JPEG picture payloads, one helper before/after with no helper churn, and a visually inspected nonblank desktop sample.
- Remaining gate: no post-`01:40:33 +05:00` Schoolyear product `RpcLogoff` / replacement-session run exists in the local evidence. The exact Schoolyear disconnect/reconnect lifecycle remains `PENDING_EVIDENCE` and cannot be claimed as PASS until that same-run product switch occurs on the installed hashes above.
