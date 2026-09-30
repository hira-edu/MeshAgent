# MeshAgent Architecture

## Scope

This document describes the repository as it exists now: the upstream
cross-platform MeshAgent runtime plus this fork's Windows service packaging,
runtime validation, deployment tooling, and UserModeHook integration.

## Runtime layers

| Layer | Main paths | Responsibility |
|---|---|---|
| Native foundation | `microstack/` | Single-threaded chain/event loop, sockets, HTTP/WebSocket, TLS helpers, process pipes, crypto, and local data store |
| Embedded runtime | `microscript/` | Duktape engine and Node-like native bindings exposed to agent cores |
| Agent core | `meshcore/` | MeshCentral control channel, server authentication, agent identity, update protocol, and platform-specific KVM |
| JavaScript modules | `modules/` | Runtime modules used by the normal core, recovery core, installers, terminal, networking, and UMH operator commands |
| Hosts | `meshconsole/`, `meshservice/` | Console process and Windows service/DLL hosts for the same agent runtime |

The core execution flow is:

```text
MeshCentral control channel
        |
        v
meshcore/agentcore.c
        |
        +--> Microstack networking and event loop
        |
        +--> Duktape runtime --> modules/*.js / server-supplied core
        |
        +--> platform KVM, terminal, file, update, and service operations
```

The agent authenticates its control channel before accepting management
traffic. Server-delivered JavaScript runs inside the embedded runtime and calls
the native bindings supplied by Microstack/Microscript. Remote desktop,
terminal, and file sessions use separate relay channels authorized through the
control channel.

## Windows packaging

`meshservice/MeshService-2022.vcxproj` provides the fork's Windows packaging:

- `MeshServiceBundle|x64` builds the service-hosted DLL used by approved helper and
  lifecycle entry points.
- `MeshServiceRuntime|x64` builds the 64-bit service executable and embeds the prepared
  service payload.
- `MeshServiceRuntime|Win32` builds the 32-bit service executable.
- `meshconsole/MeshConsole-2022.vcxproj` builds the x64 console host.

`MeshAgent.Build.proj` is the package build orchestrator. It intentionally
serializes DLL generation, console build, x64 executable build, and Win32
executable build so the embedded payload cannot be stale.

Branding and provisioning inputs are transformed into generated headers and
resources during MSBuild. Generated files and linked binaries are not source of
truth; see [Configuration](CONFIGURATION.md).

## Windows service and helper boundary

The Windows service owns installation, update, uninstall, service recovery,
and approved user-session helper lifecycle. User-session desktop work is
launched through bounded `rundll32.exe <dll>,<export>` contracts. The service
creates the IPC endpoints, selects the target session, starts the approved
host, monitors it, and cleans up on shutdown.

The installed Windows service runs only as the system `rundll32.exe` loading
the service DLL's `MeshServiceHostW` export. This callback enters the Windows
service-control dispatcher and reports an own-process service. Lifecycle and
user-session helpers use their separate approved exports in the same DLL.
There is no `svchost` registration or standalone EXE service entry point.

Project code names this boundary `RuntimeHost`: shared contracts live in
`meshservice/runtime_host_contract.c` and `.h`, with `MeshRuntimeHost_*`
functions and `MESH_RUNTIME_HOST_*` constants. The Windows executable retains
its system filename, `rundll32.exe`.

The `MeshServiceRuntime` EXE is the delivery package and bootstrapper. Its
configured installed path remains the identity/provisioning base and update
package reference; it does not run the background agent. Installed DLL readers
validate the SCM `ImagePath` command, system host, and primary export. The old
`ServiceDll`, `ServiceMain`, and unload-on-stop registry values are removed by
successful migration; they are not fallback launch configuration.

The design rules for this boundary are:

- validate the DLL path, export, pipe names, arguments, target session, and
  token before launch;
- restrict IPC and process access to the required principals;
- fail closed when validation or session selection fails;
- keep operator-visible logs for lifecycle and policy decisions;
- release tokens, process/thread handles, pipes, desktops, and job objects on
  every exit path.

Agent-owned Windows commands and user-session commands have distinct token
contracts. The native console bridge requires exactly one validated
`token=privileged-agent` or `token=session-user` mode, and requires a session
ID only for the latter. Agent-owned command and UMH lifecycle hosts obtain an explicit
primary token, accept SYSTEM or an administrator token only at high-or-greater
integrity, and verify the child token after creation. A split-token
administrator still using its limited token, a standard user, or any other
medium token is rejected with `ERROR_ELEVATION_REQUIRED` instead of silently
launching without the required elevated token. User-session commands
obtain their token from `WTSQueryUserToken`, remain bound to the requested
session, and never fall back to the bridge or SYSTEM token. This separation
applies to every Run Commands payload; it is not application- or
UMH-profile-specific.

The exact native implementation is spread across `meshservice/`,
`microstack/ILibProcessPipe.c`, and `meshcore/KVM/Windows/`. Contract and
runtime coverage lives in `test/`.

### KVM session bridge

Each remote desktop session owns one relay context in
`meshcore/KVM/Windows/kvm.c`, keyed by the caller's `reserved` pointer. The
relay lock serializes every entry point. Session-change notifications from the
service control thread never take it: they signal registered contexts under a
short signal lock (which context destruction also takes) and queue the rest of
the handling to the chain thread. Session state is
mirrored into globals only while a context is activated; activation nests, so
a stream callback that re-enters `kvm_pause()` or `kvm_cleanup()` keeps the
outer frame's state. A call that names an unregistered session is dropped; it
never falls back to another session's context.

The helper is `rundll32.exe <bundle dll>,KvmSessionBridgeW`, connected over two
directional named pipes. It is launched into the relay's target session: on
the Winlogon desktop when that is the console session, and as a
session-specific launch otherwise (for example an RDP session). The pipes admit only SYSTEM and the service account,
reject remote clients, and accept a client only if it is the process the
service spawned. A helper that fails before
attaching is terminated and its process object freed. Relay writes to the helper
are bounded; a timed-out, broken, or badly framed helper is replaced
through the exit/restart path. While no helper is attached, only replayable
control packets (refresh, display, compression, frame-rate, input-lock) are
queued, up to a fixed limit; mouse and keyboard input is dropped rather than
replayed later.

A workstation lock leaves the helper running: it follows the input desktop
onto the Winlogon lock screen, so the viewer keeps seeing the session, and it
exits cleanly to be relaunched there if an in-place switch fails. Console or
remote disconnect and logoff stop the helper and suppress restarts until the
session connects or logs on again; the viewer stays attached meanwhile. Only a
viewer disconnect (relay shutdown) ends the viewer's stream.

While a viewer is attached the relay never gives up on its helper: there is no
restart limit, every helper exit is followed by a relaunch, and every failed
launch (including the first one in `kvm_relay_setup`, which keeps the context)
schedules another attempt. Restarts share one per-context timer that keeps the
earliest deadline: exponential backoff (2 s doubling, capped at 60 s), a
refresh-probe watchdog, and session-start token retries. A helper exit counts
as a failed start when the relay did not request it and it was non-zero or came
within twice the connect timeout of attaching (a helper that never attached
has no uptime), so a helper that exits right after its first frame cannot
relaunch in a tight loop. Backoff resets once a helper has run for twice the
connect timeout. Input never bypasses a pending backoff.
The refresh probe is not timed while the viewer is paused for backpressure,
since a paused helper stops sending pictures. Inside the helper, the control
pipe is read with a blocking overlapped read, any shutdown also releases the
capture loop's startup resume wait, and refusals and transport errors exit
with their own code instead of 0, so the relay logs the reason and backs off.

## Configuration and identity

The build uses one branding JSON document and one provisioning manifest:

```text
branding_config.local.json (preferred, ignored)
            or
branding_config.json (repository fallback)
            |
            v
tools/generate_branding_assets.py and MSBuild targets
            |
            v
generated headers/resources consumed by meshservice and meshcore
```

`WinDiagnosticHost.msh` is the preferred provisioning manifest when present;
otherwise the build looks for `MeshAgent.msh`. The deployment package must keep
the executable, service DLL, embedded payload, and `.msh` identity aligned.

## Deployment boundary

`deploy.py` stages the local package, verifies payload parity, creates a remote
backup, publishes MeshCentral agent files, regenerates hashes, restarts the
server when approved, and runs post-publish checks. The authoritative paths and
rollback commands are in [Deployment](DEPLOYMENT.md).

MeshAgent also owns the agent-side `umhctl` contract. Native UserModeHook
behavior belongs to the `UserModeHook` repository, and browser UI behavior
belongs to the `MeshCentral` repository. The ownership and synchronization
rules are in [UMH sister-repository SSOT](UMH_CONTROL_SISTER_REPO_SSOT.md).

## Verification model

Validation is layered:

1. source contracts check specific invariants without installing the agent;
2. native/runtime probes exercise built binaries and session behavior;
3. the grouped elevated harness covers package preflight and local
   install/update/uninstall;
4. release gates verify expected files, signing state, digests, and bundle
   contents;
5. deployment health checks compare published bytes and service state.

Generated reports belong under ignored `artifacts/validation/` paths. Reusable
fixtures belong with their tests; dated runtime evidence is not tracked.
