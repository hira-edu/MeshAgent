# 2026-03-31 Realignment Retained Surfaces

This document satisfies `TODO-004` through `TODO-007`.

It fixes the retained Windows lifecycle surface, the minimum UMH surface, the `localhost` relay contract, and the remote-desktop-only Session 1 bridge policy on the clean `realignment-origin-main` branch.

## TODO-004: Minimal Retained Windows Lifecycle Surface

### Authoritative lifecycle owner

The authoritative Windows lifecycle engine is the native installer/update/uninstall implementation in `meshservice/stealth_installer.c`.

The retained lifecycle mutation surface is:

- `Stealth_GetInstallPaths()`
- `Stealth_PerformCompleteInstallation()`
- `Stealth_PerformUpdate()`
- `Stealth_PerformCompleteUninstallation()`
- `Stealth_RunInstallValidation()`
- `Stealth_RunUpdateValidation()`
- `Stealth_RunUninstallValidation()`
- `Stealth_RegisterSvchostService()` / `Stealth_UnregisterSvchostService()` only as low-level helpers owned by the lifecycle engine

### Retained public native entrypoints

Windows operator-facing lifecycle entrypoints must converge onto these native wrappers in `meshcore/agentcore.c`:

- `MeshAgent_RunNativeStealthFullInstall()`
- `MeshAgent_RunNativeStealthFullUpdate()`
- `MeshAgent_RunNativeStealthFullUninstall()`
- validation dispatch through `-validate-install`, `-validate-update`, and `-validate-uninstall`
- diagnostics through `-svchost-status`

These wrappers are retained because they already route Windows svchost builds onto native install/update/uninstall code instead of the legacy JavaScript installer path.

### Wrapper-only surfaces

The following remain allowed only as thin wrappers with no independent lifecycle mutations:

- `meshservice/ServiceMain.c` argument normalization and GUI button launch code
- PowerShell or CLI entry that shells into the same native commands
- `modules/agent-installer.js` on Windows only as a wrapper/error surface; it must not own Windows lifecycle state changes

### Explicit lifecycle reductions

The following are retained only as internal helpers or are slated for removal from operator-facing flows:

- `-svchost-register` and `-svchost-unregister` remain low-level service registration helpers, not alternative install/update flows
- legacy `-install` / `-uninstall` stay blocked on Windows svchost builds
- direct lifecycle mutation in `ServiceMain.c` outside the native installer surface is not accepted as authoritative behavior
- JavaScript `fullInstall` / `fullUninstall` logic is non-authoritative on Windows svchost builds

### Decision

The accepted lifecycle surface is:

1. `agentcore.c` parses operator intent and calls one native lifecycle wrapper.
2. `stealth_installer.c` performs all Windows lifecycle state mutations.
3. validation commands prove the resulting state.
4. no other Windows entrypoint is allowed to own independent install/update/uninstall behavior.

## TODO-005: Minimal Retained UMH Surface

### Authoritative UMH lifecycle surface

The retained UMH companion is:

- binary name: `MasterService.exe`
- service name: `AdvancedHookService`
- control pipe: `\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-control`

The retained native contract is no longer a bundled-agent UMH lifecycle in `meshcore/agentcore.c`.

The accepted contract is:

- MeshAgent native install/update/uninstall manage only agent package artifacts.
- `MasterService.exe` is published separately for operator download.
- UMH lifecycle authority is `umhctl install --url ...`, `umhctl uninstall`, and the control-pipe/operator contract.
- Agent validation may report UMH state, but it does not stage or own an external UMH installation.

### Retained operator surface

The retained operator surface is the UMH command contract explicitly named by the regression matrix and archived harnesses:

- lifecycle: `install`, `uninstall`, `verify`, `status --service`, `status`
- pipe-backed informational ops: `listProcesses`, `getFlowContract`, `getCapabilities`, `getPolicy`, `getConfig`, `uiSnapshot`
- mutation ops: `inject`, `injectAll`, `telemetry`, `repair`, `setFlags`, `disable`, `disableAll`, `setPolicy`, `setConfig`
- target-scoped ops: `profileProcess`, `getInjectionState`, `registerProtectedPid`, `unregisterProtectedPid`, `injectTargetSet`, `clearTargetScope`
- bypass ops: `lockdownBypass`, `examsoftBypass`, `ipcBypass`

The authoritative harness sources are:

- `test_umhctl_e2e.js`
- `test/run_umh_type4_matrix.js`

### RecoveryCore reduction

`modules/RecoveryCore.js` is retained only for:

- UMH command construction
- UMH command dispatch
- UMH result rendering
- the supported operator paths that map to the retained command list above

The following are explicitly not part of the retained UMH surface:

- unrelated raw terminal/console expansion
- unrelated runtime shell features
- broad RecoveryCore drift that is not tied to UMH service lifecycle, control-pipe validation, or the supported operator contract

### Decision

The accepted UMH surface is:

1. `MasterService.exe` plus `AdvancedHookService`, managed separately from the agent package lifecycle.
2. one control pipe contract.
3. the exact operator command families named above.
4. no unrelated RecoveryCore console/runtime expansion.

## TODO-006: Retained `localhost` Relay Connectivity Contract

### Upstream identity source of truth

The upstream server identity remains provisioned by staged configuration:

- `MeshServer`
- `ServerID`
- `MeshID`
- TLS identity checks in `ValidateMeshServer()`

These staged values remain the only authoritative upstream identity and trust inputs.

### Retained contract

The retained production connection contract is:

1. agent connects to a loopback relay endpoint on `localhost` / `127.0.0.1`
2. the relay forwards to the staged upstream server endpoint
3. the upstream identity remains bound to staged `MeshServer`, `ServerID`, SNI/Host header, and certificate validation material
4. the relay may not silently retarget or replace the upstream trust contract

### Minimum retained control-channel surface

Only the following control-channel responsibilities are retained:

- load staged endpoint/trust material from the datastore
- open the WebSocket transport needed for the agent control channel
- preserve upstream identity validation
- record connectivity diagnostics needed by the regression matrix

### Networking drift explicitly rejected up front

The following current networking behaviors are not part of the retained minimum contract and are default revert candidates unless later TODOs reintroduce them explicitly:

- branded endpoint fallback lists in `g_meshNetworkProfile`
- endpoint rotation through `brandedFallbackIndex`
- the hard-coded swarm migration rewrite
- multicast discovery behavior driven by `MeshServer=local`
- incidental direct-to-upstream proxy/autoproxy permutations embedded in `agentcore.c`
- ad hoc DNS cache mutation as a primary connectivity feature

If DNS, proxy, TLS-inspection, or firewall hardening is needed, it must re-enter through the explicit `LEDGER-017` work items, not by preserving broad control-channel drift.

### Decision

The accepted networking baseline is:

- one explicit `agent -> localhost relay -> configured upstream endpoint` transport path
- upstream identity still anchored to staged provisioning and trust material
- unrelated networking drift rejected unless later TODOs and regression gates require it

## TODO-007: Remote-desktop-only Session 1 Bridge Policy

### Default policy

Windows remains strict service-only by default.

User-session process spawning is denied unless it is the approved remote-desktop bridge.

The current policy chokepoints are:

- `ILibProcessPipe_IsSessionSpawnAllowed()` in `microstack/ILibProcessPipe.c`
- `Helper_IsSessionSpawnAllowed()` in `meshservice/stealth_watchdog.c`

### Only approved Session 1 exception

The only approved Session 1 exception is the remote desktop/KVM bridge.

Current call sites proving the scope are:

- `kvm_relay_setup()` / `kvm_relay_restart()` in `meshcore/KVM/Windows/kvm.c`
- KVM entrypoints in `meshcore/agentcore.c` that call the relay setup/restart path

The retained target design is the documented rundll32 bridge:

- `rundll32.exe <dll>,KvmSessionBridgeW <pipe>`
- SYSTEM-integrity token redirected to the target session
- desktop selection limited to `winsta0\\default` or `Winsta0\\Winlogon`
- named-pipe IPC between service and helper
- capture/input only

### Explicitly blocked user-session dispatches

The following remain disallowed from generic Session 1 dispatch:

- PowerShell execution
- remote terminal spawning
- file-operation helpers
- arbitrary process launch
- generic helper-monitor respawn behavior unrelated to KVM readiness

### Standalone/runtime blocking

Standalone remains blocked on Windows svchost builds:

- legacy `-install` / `-uninstall` remain denied
- the shipped Windows service build remains svchost-only
- only managed service entrypoints, validation commands, and the remote-desktop helper path stay allowed

### Current-vs-target bridge decision

The retained implementation no longer allows direct helper execution as the agent executable with `-kvm0` / `-kvm1`.

That old self-spawn path is rejected outside the internal `rundll32`-hosted bridge.

The retained policy is:

- preserve only the KVM/session bridge exception
- migrate the implementation to the rundll32 DLL host
- remove generic session-spawn drift
- reject direct `agent.exe -kvm0/-kvm1` invocation so Session 1 bridge execution remains rundll32-only

## Accepted Surface Summary

- `TODO-004`: native lifecycle authority is `stealth_installer.c`, wrapped by the native Windows entrypoints in `agentcore.c`
- `TODO-005`: UMH authority is `MasterService.exe` + `AdvancedHookService` + the control-pipe/operator contract named above, not bundled agent sidecars
- `TODO-006`: networking authority is the staged upstream identity plus a required `localhost` relay hop, with unrelated networking drift rejected
- `TODO-007`: Session 1 spawning is denied by default; only the remote-desktop bridge remains approved, and the target host is rundll32
