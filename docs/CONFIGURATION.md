# Configuration

## Sources of truth

MeshAgent's Windows package build consumes two independent inputs:

1. a branding JSON document for product identity, paths, signing policy,
   supported runtime options, persistence/recovery policy, and explicit
   hardcoded-lab network metadata;
2. a MeshCentral provisioning manifest (`.msh`) for server and mesh identity.

Local credentials and environment-specific identities must stay in ignored
files.

Branding is required for the RuntimeHost service and lifecycle hosts: the
installer uses the product identity and paths, and `deploy.py` derives the
default installed service-DLL and lifecycle-state paths from the active
branding configuration when it performs remote native update activation.

## Branding selection

`MeshAgent.Build.proj` and the project targets use this precedence:

1. the explicit MSBuild property `MeshAgentBrandingConfig`;
2. `branding_config.local.json` when it exists;
3. the checked-in `branding_config.json` fallback.

Start a local configuration with:

```powershell
Copy-Item .\branding_config.template.json .\branding_config.local.json
```

Replace every `REPLACE_WITH_*` placeholder before building. Do not commit the
local file, certificate paths, private keys, passwords, or production tokens.

The schema is `schema/meshagent.schema.json`. Major sections are:

| Section | Purpose |
|---|---|
| `branding` | Company/product names, service identity, install/log paths, and version resources |
| `network` | Lab-build network metadata; production connection authority remains the `.msh`/datastore |
| `artifacts` | Database, log, and configuration filenames |
| `runtime` | RuntimeHost feature toggles (bundle extract, file/registry management, inventory, logging) |
| `persistence` | Run key, autorun task, service recovery task and monitor, watchdog, and SCM recovery policy |
| `telemetry` | Local telemetry/retention and process-visibility settings |
| `security` | Certificate validation, signing enforcement, and signer allow-list |
| `provisioning` | Mesh name/type, mesh ID, server ID, URL, and install flags |
| `advanced` | Logging, keepalive, idle timeout, compression, and local power-action policy |

Only enable administrative behavior that is approved for the target
environment. Configuration cannot override consent, audit, or fail-closed
requirements.

## Persistence and service recovery

The `persistence` block drives the independent survival mechanisms that the
service deployment layer reconciles. Each sub-block is applied and then verified
by `ServiceDeploy_ReconcileServiceRecovery`; a verification failure fails the
operation closed. The schema rejects unknown properties for each block.

| Block | Purpose |
|---|---|
| `runKey` | `HKLM\...\CurrentVersion\Run` entry that starts the service; created then verified by exact value |
| `scheduledTask` | Autorun Task Scheduler task (`enabled`, `taskName`, `trigger`, `hidden`) |
| `serviceRecoveryTask` | Task Scheduler task that restarts the service on a stopped-state event |
| `serviceRecoveryMonitor` | WMI permanent event subscription that observes stopped-state transitions |
| `watchdog` | In-service health watchdog (`enabled`, `intervalSeconds`, `restartOnCrash`, `restartDelay`) |
| `serviceRecovery` | Windows SCM recovery actions on crash (`resetPeriod`, `restartDelay`, `actions`) |

### `serviceRecoveryTask`

```json
"serviceRecoveryTask": {
  "enabled": true,
  "taskName": "Mesh Agent Service Recovery"
}
```

| Field | Type | Meaning |
|---|---|---|
| `enabled` | boolean (required) | When true, deployment creates and verifies the recovery task; when false, an existing task is removed |
| `taskName` | string, min length 1 (required) | Display hint for the task name under the Task Scheduler folder |

The task is created through Task Scheduler COM with `TASK_CREATE_OR_UPDATE`,
a `TASK_TRIGGER_EVENT` bound to the service stop event XPath, and a
`TASK_ACTION_EXEC` action that runs `sc.exe start "<service>"`. It lives under
the intentional `\Microsoft\Windows\Diagnostics` folder. Creation is idempotent
and is re-verified with `FaultRecovery_ServiceRecoveryTaskMatches` after the
write.

### `serviceRecoveryMonitor`

```json
"serviceRecoveryMonitor": {
  "enabled": true,
  "namespace": "root/subscription"
}
```

| Field | Type | Meaning |
|---|---|---|
| `enabled` | boolean (required) | When true, deployment creates and verifies the WMI monitor; when false, an existing monitor is removed |
| `namespace` | string, min length 1 (required) | WMI namespace for the subscription; only `root\subscription` is accepted |

The monitor is a standard WMI permanent event subscription: an `__EventFilter`
whose query matches a `Win32_Service` instance modification to the `Stopped`
state where `PreviousInstance.State<>'Stopped'`, a `CommandLineEventConsumer`
that runs `sc.exe start "<service>"`, and a `__FilterToConsumerBinding` that
joins them. The filter, consumer, and binding are all created with
`WBEM_FLAG_CREATE_OR_UPDATE`, and rollback removes the binding before its
filter and consumer endpoints.

Both the task and the monitor are disabled in the generic (non-RuntimeHost)
build and enabled by `meshcore/config/persistence_config.h` only when the
RuntimeHost feature set is compiled in. `tools/generate_branding_assets.py`
emits the matching `#define MESH_AGENT_SERVICE_RECOVERY_TASK_ENABLED` and
`#define MESH_AGENT_SERVICE_RECOVERY_MONITOR_ENABLED` controls from the branding
JSON.

## Provisioning manifest selection

The package orchestrator uses this precedence:

1. the explicit MSBuild property `MeshAgentProvisioningManifest`;
2. `WinDiagnosticHost.msh` when present;
3. `MeshAgent.msh` as the generic fallback.

The executable, sidecar `.msh`, database identity, service DLL, and embedded
DLL payload must belong to the same build/package set. Deployment validation
rejects mismatched package identities.

For `MeshServiceRuntime` service EXEs, both direct project builds and the package
orchestrator copy the selected manifest to `$(TargetDir)$(TargetName).msh`.
A missing manifest fails the build before compilation. Every successful build
refreshes the sidecar, including when the selected manifest is older than an
existing sidecar. This prevents a previous deployment's endpoint from surviving
a rebuild. The shared manifest and branding URL must describe the intended
deployment; matching local files alone does not prove server admission.

## Windows installer elevation

Both `MeshServiceRuntime` service EXEs embed
`requestedExecutionLevel=requireAdministrator` with `uiAccess=false`.
Installation needs administrative service-manager and installation-directory
access. Already-elevated callers retain their existing privileges. This is the
standard Windows manifest boundary. Check the manifest in the actual downloaded
EXE when diagnosing an access-denied report.

## Windows inventory and session boundaries

Process lists, process details, service lists, and account SID resolution use
Win32 APIs in the agent. They do not launch a shell or require an inventory
helper. Protected processes may omit optional owner information. Enumeration
closes snapshot, process, token, SCM, and registry handles on failure as well as
success, and consumes all service enumeration pages. Service detail requests
close their service and SCM handles before returning a reply.

Interactive terminals and run commands use `MeshConsoleBridgeW`. The bridge
must send its ready marker before input is flushed; a startup failure closes the
tunnel with an error. `win-virtual-terminal` remains a compatibility alias.
Clipboard dispatch reuses the console bridge in the interactive user's session
with `token=session-user`, running Windows PowerShell clipboard commands. It
does not start a ScriptContainer, create another callback export, or fall back
to the service identity. Clipboard operations have a 30-second bound and a
1 MiB text input limit. An elevated administrator alone cannot call
`WTSQueryUserToken`; the service performs the session transition.

Desktop capture, consent, and service lifecycle callbacks retain their required
process/session boundaries. Legacy update and uninstall callbacks remain needed
for endpoints installed with older bindings until those bindings are migrated.

MeshCentral core overrides carry the source module's UTC modification date into
`addModule`. Undated overrides cannot replace dated embedded modules. Deployment
selects one source for each module name: minified files when core minification is
enabled, plain files otherwise, with fallback when only one variant exists.
This avoids duplicate registration when both files are present. Deployment
generates the patched core loader from the target server's installed package and
publishes inventory/clipboard modules into both normal and minified module
directories under the data and package roots. The tracked transformation preserves
the server's package version; staging binds its original digest and publication
rejects a loader that changed afterward. Local npm copies are not release sources.
Refresh the target's default core
after publication; a server loader change requires a server restart.

## Windows lifecycle manifest encoding and errors

Every lifecycle INI writer uses UTF-16LE with a BOM. `WritePrivateProfileStringW`
otherwise creates an ANSI file, even though its arguments are wide strings.
The native writer initializes the BOM before writing fields. The JavaScript
installer (including its embedded copy), deployment helper, and test harnesses
use the same encoding. Existing ASCII manifests remain readable.

The lifecycle launch path preserves API failures before logging and cleanup.
A completed child that fails returns `FALSE` with its actual status in
`exitCodeOut`, so the caller reports an install failure with the child status
instead of an unrelated last-error value from cleanup. Genuine
launch/write/wait failures retain their Windows error code.

## Native update transport

Native command 13 verifies `GenerateSHA384FileHash`: Windows EXEs normalize PE
checksum/signature fields and appended provisioning; ZIP files use their full
byte hash. Raw native transfers must end with MeshCentral's `agentExeInfo.hash`,
and compressed transfers with `zhash`. `fileHash` is the complete HTTP download
hash used by the JavaScript HTTP updater and cannot substitute for the native
EXE hash.

Capability `0x100` retains its existing compression meaning. Native streaming
ZIP updates additionally require `0x200`, advertised by the corrected decoder.
Older agents receive raw native updates so they can install that decoder. Hash
verification remains mandatory for both formats.

The Windows self-update activation is asynchronous: `MeshServer_selfupdate_continue`
stages the package, records its activation target hash, and calls
`MeshServer_StartUpdateActivation`, which launches the update-only compatibility
lifecycle host and registers the process with the agent chain. This host also
provides uninstall and interrupted-update recovery for older callback-based
service bindings; normal service startup uses the scoped service group. The activation result is
observed in `MeshServer_UpdateActivation_Sink`; on failure the staged payload is
dropped and the failure is reported through `MeshServer_FailUpdateActivation`
(fail-closed). Builds without the RuntimeHost feature set refuse the update and
delete the staged payload rather than falling back to a legacy command shell.

## Generated outputs

The build invokes `tools/generate_branding_assets.py` and related MSBuild
targets to produce generated headers/resources. Common generated outputs
include:

- `meshcore/generated/meshagent_branding.h`
- `meshcore/generated/network_profile.h`
- service version/resource inputs
- `meshservice/embedded/service_bundle.dll`

Network values in the branding header are guarded by
`MESH_PROVISIONING_HARDCODED`, which is not defined by the production project
configurations. Do not treat either generated file as a production connection
authority or edit it as a substitute for the `.msh` manifest.

To validate and regenerate the branding header explicitly:

```powershell
python .\tools\generate_branding_assets.py --repo-root . --config .\branding_config.local.json
```

Then run the normal MSBuild command so every consumer is refreshed in the
correct order.

## Network and proxy policy

Production reads `MeshServer` from the provisioning `.msh` into the datastore,
parses one configured URL, performs one OS resolution, and issues one request.
Keep a single URL in the deployment manifests unless a separately validated
contract requires otherwise. The branding JSON must mirror that URL for build
and package validation, but its fallback/SNI/Host fields are not an alternate
production route.

If a proxy is required, provide an explicit MeshCentral `WebProxy` value.
Ambient proxy discovery is not used by the active agent path; do not rely on
WPAD, per-user browser settings, or heuristic proxy fallback. Stock reconnect
handling remains part of MeshAgent and is not an endpoint-selection fallback.

## Connection failure diagnostics

On Windows, the core, native service host, lifecycle installer, runtime policy,
monitor, and KVM helpers all write to one log: the branding `logPath` directory
plus `artifacts.logFileName` (normally `logs/diagnostics.log`). No separate debug,
installer, TEMP, or `.bak` log is created. `require('MeshAgent').logPath` exposes
the absolute path, and `util-agentlog` reads it by default. Records use UTF-8,
local timestamps with milliseconds, PID, TID, and component labels. An existing
UTF-16 installer log at that path is converted in place. Concurrent processes
serialize writes with a file lock; at 2 MiB the newest approximately 1 MiB of
complete lines is retained in the same file. Existing historical logs are not
silently deleted. Uninstall still removes the installed log and stops file
logging before directory removal; uninstall validation does not recreate it.
Explicit regression reports and optional crash dumps are validation artifacts,
not additional runtime logs. Non-Windows critical logging remains unchanged.

The agent always writes control-channel failures.
`[CONTROLCHANNEL_FAILURE]` records the failed stage, connection/authentication
state, HTTP status, WebSocket close code, socket/TLS error codes, heartbeat/data
ages, uptime, and PID. `[TRANSPORT_FAILURE]` preserves the first native socket or
TLS failure before cleanup; `[AUTH_FAILURE]` identifies rejected authentication.
These records do not require `controlChannelDebug`, `logUpdate`, or
`SERVICE_CONTROLCHANNEL_TRACE` and do not log packet bodies, credentials, or keys.

Ordinary traffic, successful connects, transient would-block/interrupted I/O,
explicit script disconnects, and chain shutdown do not produce failure records.
A peer EOF is recorded only when it terminates the persistent control channel;
it proves the peer closed the stream, not why. A WebSocket close code describes
the peer's protocol response, not the cause inside a relay or server.
Close code `0` means no close frame was received, `1005` means an empty close
frame, and `-1` means a malformed one-byte close payload. Correlate
the unified agent log with server/relay logs to investigate an offline endpoint.
`[START_FAILURE]` identifies failures reached during service startup;
`[UNEXPECTED_EXIT]` records core return without a stop request. Accepted SCM stops
and OS shutdowns have distinct lifecycle markers. The unhandled-exception filter
records `[AGENT_CRASH]` with exception code, module and offset, and access-violation
operation/target when available, without suppressing Windows crash handling.
A versioned registry `TelemetrySession` under the service's `Parameters` key
records startup/running/stop/exit state. On restart, `[PREVIOUS_SESSION]`
distinguishes a recorded crash from an unclean exit with unknown cause; it never
claims to identify an external terminating program. Failure to persist telemetry
is itself logged. These observations are best effort, not full OS crash telemetry.
KVM launch/protocol/unexpected-helper-exit failures are logged by the privileged
parent. Capture failures from a restricted session helper are forwarded through
its existing pipe when it cannot write the protected log. In-process helper
crash metadata still requires write access and a functioning exception handler.
Missing error records do not rule out forced termination or
Windows heap-corruption fail-fast, which may bypass in-process handlers; those
require the endpoint's Windows Application/SCM events and a crash dump.
Failure to load the executable/DLL before agent code runs also needs SCM/OS
evidence, or the installer's logged service-start error.

## Windows Files actions

The MeshCentral Files tunnel sends literal paths to `MeshAgent.fileAction` for
Open, Run, Run privileged, and Delete. These actions execute native Win32 code;
they do not build PowerShell commands, use scheduled tasks, or start an agent
helper. Open resolves the signed-in user's file association, and folders open
in Windows Explorer. Run launches one selected `.exe` as the interactive user;
Run privileged uses the agent's existing privileged identity. An absent user or
insufficient privilege produces an error without switching identities.

The agent checks Files access for deletion and also requires Remote Commands
permission for Open and execution. Recursive deletion treats junctions and
symbolic links as leaves and rejects drive/share roots. Outcomes include Win32
errors, process IDs, or deletion counts and are returned to the Files tunnel.
The native agent and all server core variants must be updated together; older
agents receive no command-shell fallback.

## Deployment environment

`.env.template` is operator documentation and is separate from production
provisioning. Its endpoint value is not consumed by the current build or deploy
path. Copy it to an ignored `.env` only when a local wrapper explicitly consumes
it, and keep secrets out of shell history and source control.
