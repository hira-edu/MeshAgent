# 2026-04-09 KVM Restoration SSOT

## Purpose

This document is the single source of truth for the current remote desktop restoration effort. The goal is to restore stable MeshCentral/MeshAgent KVM behavior by reducing the implementation back toward upstream ownership boundaries and retaining only the deltas that are strictly required for this product.

## Problem Statement

Observed field behavior:

- browser UI can show remote desktop as connected while the session is not actually producing usable screen data
- reconnects can succeed, black-screen, or stall on setup depending on prior session state
- mouse and keyboard can stop working after a reconnect or after a delayed helper restart
- restarting MeshCentral, restarting the agent service, or repeatedly reloading RecoveryCore can temporarily clear the bad state

This is a lifecycle ownership problem, not a simple viewer rendering bug. The stack currently has too many independent recovery paths.

## Authoritative Baseline

Upstream authority:

- MeshCentral desktop tunnel ownership stays in the standard `mesh.getRemoteDesktopStream(tsid)` path in `MeshCentral/agents/meshcore.js`.
- MeshCentral browser and relay layers should remain as close to upstream as possible unless a retained product requirement proves a delta is required.
- MeshAgent KVM session ownership should stay in the native KVM bridge/session path, with one authoritative owner for spawn, readiness, disconnect, and restart.

Required retained product deltas:

- `LEDGER-007`: explicit `localhost` relay contract
- `LEDGER-008`: Session 1 `rundll32` bridge hosted from the `StealthLab_DLL` payload
- `LEDGER-014`: DXGI/WGC capture with fallback
- `LEDGER-015`: SYSTEM-context input path, including secure desktop support

Everything else must justify itself against those retained requirements.

## Mandatory Retained KVM Path

The retained KVM path for this product is:

1. MeshCentral requests desktop through the standard tunnel path.
2. MeshAgent service owns KVM session lifecycle.
3. MeshAgent spawns `rundll32.exe <MeshService-2022.dll>,KvmSessionBridgeW ...` in the target interactive session.
4. Service and helper communicate over the named-pipe KVM bridge.
5. Helper captures screen and injects input from the interactive session while the service remains the authoritative owner.

Files that are mandatory for this retained path:

- `meshcore/KVM/Windows/kvm.c`
- `meshcore/KVM/Windows/kvm.h`
- `meshservice/stealth_svchost.c`
- `microstack/ILibProcessPipe.c`

## Current Drift To Collapse

The following areas are currently treated as suspect drift until proven necessary:

- `meshcore/agentcore.c` logical-session freshness, watchdog, resync, and cached-stream recovery added on top of the native bridge lifecycle
- `MeshCentral/public/scripts/agent-redir-ws-0.1.1.js` browser connected-state deviations from upstream
- `MeshCentral/public/scripts/agent-desktop-0.0.2.js` reconnect/reset behavior added to compensate for stale sessions
- `MeshCentral/meshdesktopmultiplex.js` relay-side reconnect and queue-healing changes

These layers may contain useful observations, but they are not the first owner of the bug. The first owner is the native bridge/session contract.

Current MeshCentral-side audit split:

- `meshdesktopmultiplex.js` queue-send fixes (`sendQueue.length`, setting `sending=true` before `ws.send`) are concrete relay correctness bugs and should be evaluated as retained fixes even though they are not upstream.
- `meshdesktopmultiplex.js` same-size screen reanchor logic, `agent-desktop-0.0.2.js` stream/session reset logic, and `agent-redir-ws-0.1.1.js` delayed KVM connected-state promotion are reconnect/UI behavior patches. These may still be useful, but they must be justified by trace-backed requirements instead of assumed as root-cause fixes.

## Confirmed Failure Model

The failure was a chain of local drifts inside the retained svchost+rundll32 bridge contract, not one browser-side bug.

Confirmed root-cause chain on `2026-04-09`:

1. Bridge startup timeout drift:
   - the parent pipe-connect window had been reduced below the child bridge wait window
   - delayed helper attach could be torn down as a false startup failure before the child reached pipe connect
2. Bridge launch-policy drift:
   - fresh retained-bridge setup in `meshcore/KVM/Windows/kvm.c` was forced away from the winning `WINLOGON` path and back onto `USER`
   - repeated bridge restarts also stopped retaining the winning `WINLOGON` launch type
   - startup trace proved `USER` first-attempt launches repeatedly stalled or failed before pipe attach, while `WINLOGON` launches connected immediately and carried screen/input continuity
3. Bridge pipe resume recursion/state corruption:
   - bridge output handling resumed overlapped reads recursively from the read callback path
   - `ILibProcessPipe` also resumed overlapped reads from non-owner threads during pause/resume churn
   - under live churn this corrupted the read state and crashed in `memmove_s`
4. Cleanup/exit lifetime race:
   - `kvm_cleanup()` soft-killed a live child and then immediately destroyed the same `KvmRelayContext`
   - the later child-exit callback then re-entered destruction on the freed context

These drifts explain the field symptoms:

- connect/setup stalls with no usable desktop even though the wider tunnel stays alive
- intermittent success only after retries, service restarts, or server restarts
- reconnect instability after lock/unlock or disconnect/reconnect because each fresh bridge cycle re-entered the wrong launch order
- black screen or dead input after churn because bridge state was being corrupted or destroyed underneath the active session

MeshCentral viewer/relay deltas were secondary. The first owner of the failure was the native bridge/session contract.

## Restoration Strategy

### Rule 1: One owner

The native KVM bridge owns:

- helper spawn
- pipe connect readiness
- first-packet readiness
- restart on helper exit
- teardown on disconnect/session change

`agentcore.c`, relay, and browser layers must not invent independent readiness or restart semantics unless they are explicitly required and regression-backed.

### Rule 2: Restore before optimizing

If a local optimization changes timing, recovery ordering, or fallback behavior, it must be removed unless a reproduced bug proves it is necessary. The 1000 ms bridge wait reduction is the first example.

### Rule 3: Trace before patching

Every retained change must be backed by targeted trace data that identifies:

- spawn attempt id
- session id
- spawn type
- bridge input/output pipe creation time
- child connect elapsed time for each pipe
- transport attach time
- first output packet time
- first screen packet time
- first input packet after connect
- disconnect reason
- child exit reason

The DiagnosticHost build must emit this evidence to the module-local `svchost-debug.log` resolved from the loaded `StealthLab_DLL` path. Legacy temporary trace files may remain for standalone probes, but they are not the authoritative evidence lane.

## Work Program

### TODO-080

Create this SSOT, enumerate mandatory versus suspect deltas, and lock the restoration scope.

### TODO-081

Restore the native bridge startup contract:

- align parent and child connect windows
- add authoritative startup timing trace
- add a deterministic delayed-connect test that proves the contract

### TODO-082

Remove or gate non-essential `agentcore.c` KVM recovery ownership so restart/readiness live in the bridge path again.

Status on 2026-04-09:

- complete in `meshcore/agentcore.c`
- the non-upstream watchdog/resync/recovery owner layer has been removed
- cached stream reuse is back to upstream-style passive reuse
- first-connect setup is back to direct `kvm_relay_setup(...)`
- evidence: `docs/testing/evidence/advanced/20260409_210400_agentcore_upstream_restore/summary.txt`

### TODO-083

Realign MeshCentral browser and relay behavior toward upstream and retain only requirement-backed deltas for the service-hosted bridge.

Status on 2026-04-09:

- audited against local `origin/master` in the MeshCentral repo
- retained as requirement-backed:
  - relay send queue correctness fix in `meshdesktopmultiplex.js`
  - KVM connected-state promotion only after first screen packet
  - same-size screen reset propagation and stale-state clearing for reconnect continuity
- evidence: `docs/testing/evidence/advanced/20260409_210700_meshcentral_delta_audit/summary.txt`

### TODO-084

Run deep churn/edge-case validation and archive traces for:

- fresh connect
- disconnect/reconnect
- reconnect after idle delay
- browser reload during active session
- agent service restart
- slow helper startup
- monitor/layout change at same resolution
- lock/unlock
- secure desktop/UAC transition
- input after reconnect
- helper crash during active session

Status on 2026-04-09:

- complete
- authoritative edge-matrix summary: `docs/testing/evidence/advanced/20260409_215500_kvm_edge_matrix/summary.txt`
- scenario map:
  - fresh connect and slow helper start: `connect_delay/summary.txt`
  - first-frame and picture flow after attach: `initial_frame/summary.txt`, `system_picture/summary.txt`
  - reconnect, lock/unlock, and reconnect churn: `session_change/summary.txt`
  - browser reconnect/state reset and same-size continuity: `desktop_reconnect_runtime/summary.txt`, `desktop_same_size_contract/summary.txt`, `multiplex_same_size_contract/summary.txt`
  - initial connected-state ownership and relay queue correctness: `initial_kvm_sync_contract/summary.txt`, `send_queue_contract/summary.txt`
  - post-restart KVM recovery: `service_restart/post_restart_system_picture/summary.txt`
  - secure desktop/UAC transition: `secure_desktop/summary.txt`
  - helper crash recovery: `crash_recovery/summary.txt`
  - input path and post-reconnect input-state reset: `elevated_input/summary.txt`, `block_input/summary.txt`, `desktop_reconnect_runtime/summary.txt`
  - upstream ownership regression guard: `remote_desktop_freshness_contract/summary.txt`
  - additional churn coverage: `multi_session/runtime-summary.txt`

## Exit Criteria

The KVM restoration work is only complete when:

- the native bridge is the authoritative lifecycle owner again
- upstream behavior is restored wherever no retained product requirement justifies drift
- reconnect and idle-delay sessions no longer require service/server restarts
- screen and input both recover cleanly after reconnect and session changes
- the TODO matrix rows `TODO-080` through `TODO-084` are evidenced and closed

Status on 2026-04-09:

- `TODO-080` through `TODO-084` are now evidenced and closed
- broader release completion still depends on the program-level rows outside this SSOT, especially `TODO-027` and `TODO-029`
