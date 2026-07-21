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

- `StealthLab_DLL|x64` builds the service-hosted DLL used by approved helper and
  lifecycle entry points.
- `StealthLab|x64` builds the 64-bit service executable and embeds the prepared
  service payload.
- `StealthLab|Win32` builds the 32-bit service executable.
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

The design rules for this boundary are:

- validate the DLL path, export, pipe names, arguments, target session, and
  token before launch;
- restrict IPC and process access to the required principals;
- fail closed when validation or session selection fails;
- keep operator-visible logs for lifecycle and policy decisions;
- release tokens, process/thread handles, pipes, desktops, and job objects on
  every exit path.

The exact native implementation is spread across `meshservice/`,
`microstack/ILibProcessPipe.c`, and `meshcore/KVM/Windows/`. Contract and
runtime coverage lives in `test/`.

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

Generated reports belong under ignored `artifacts/` paths. The tracked
`verification/` files are small fixtures or examples consumed by validation,
not a chronological project record.
