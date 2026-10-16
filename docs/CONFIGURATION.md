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
by `ServiceDeploy_ReconcileServiceRecovery`. A verification failure fails the
install, repair, or update operation. A committed package cannot roll back, so
its service keeps running and its transaction journal is still resolved. The
schema rejects unknown properties for each block.

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
Clipboard dispatch uses the native `MeshClipboardBridgeW` callback and Win32
Unicode clipboard APIs. A broker selects the explicit WTS session-user token,
verifies the suspended child before resuming it, and keeps that helper in a job
that terminates it when the broker exits. A private, local-only pipe restricts
access to SYSTEM and that user and verifies the child PID. Each request verifies
the original logon AuthenticationId, so session ID reuse cannot retain an old
user helper. Clipboard text never
appears in command arguments or helper logs. A write owns the clipboard through
a message-only window that exists only for that write, so an idle helper holds no
window that broadcasts or other clipboard users can wait on. Reads accept
over-allocated clipboard blocks and stop scanning at the 1 MiB limit.

Each agent module keeps at most four session helpers. Requests are serialized,
concurrent adjacent reads share a request, and each session queue holds at most
16 waiting operations, with at most 64 callers sharing a pending read. Text is
limited to 1 MiB of UTF-8; embedded NULs are rejected. A new helper's first
request times out after 30 seconds because it includes the helper start; later
requests time out after 15 seconds. Idle helpers close after 60 seconds, the
helper's own idle bound is 120 seconds, and failed launches wait 30 seconds before
retrying. Timeout and idle cleanup tolerate Duktape's `clearTimeout`, which throws
for a timer that already fired. Replacement also waits for the previous helper
to exit; a denied or delayed kill cannot create overlapping brokers. The parent
uses overlapped writes, retains I/O storage through cancellation completion, and
drains queued input before graceful EOF. Each child's queued stdin is bounded at
64 MiB; a write beyond that closes the child's stdin rather than growing agent
memory or dropping bytes from the stream. A write whose completion wait fails is
cancelled and released once Windows confirms it; otherwise its storage stays
allocated. With no active session, dispatch fails closed.
Reads and writes return
promises; callers must handle rejection and acknowledge writes after completion.
In the MeshCentral message handler, write replies carry `success` and are sent
after completion. Read failures and non-text results send no reply, because
viewers copy `getclip` data without checking for failure. Empty text reaches the
clipboard dialog (tag 1) but not clipboard pulls or auto-sync (tags 2 and 3), so
non-text remote content never clears the operator's clipboard. The console
handler reports read and write failures as text. The agent's embedded clipboard
module must match `modules/clipboard.js`; the callback must be present in the
installed DLL and the server must publish the updated clipboard module and core
together. An ordinary elevated administrator cannot call `WTSQueryUserToken`;
the service performs that session transition.

Desktop capture, consent, and service lifecycle callbacks retain their required
process/session boundaries. Legacy update and uninstall callbacks remain needed
for endpoints installed with older bindings until those bindings are migrated.

MeshCentral core overrides carry the source module's UTC modification date into
`addModule`. Undated overrides cannot replace dated embedded modules, and an
override dated later than the embedded copy replaces it on agents. After changing
a module, re-embed it with `python3 tools/embed_modules.py <name>...`, which
compresses `modules/<name>.js` into `microscript/ILibDuktape_Polyfills.c` with the
current UTC time and keeps the single-line or chunked form MSVC accepts. Deployment
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

## Windows desktop audio

The `desktop-audio` module streams the endpoint's speaker output (WASAPI
loopback, never the microphone) for one Windows session through the native
`MeshAudioBridgeW` callback. It launches
`rundll32.exe "<ServiceDll>",MeshAudioBridgeW tsid=<session>` with the same
system `rundll32.exe` path and installed service-DLL resolution as clipboard
dispatch; the broker starts the capture child in that session.

`supported()` is true only for a Windows service agent whose installed service
DLL is the module loaded in the agent process and exports `MeshAudioBridgeW`.
Console agents report no support, as does an installed DLL that is not yet
running (an update pending restart).

Set the agent datastore key `desktopAudio` to `0` (for example with the agent
console command `dbset desktopAudio 0`) to disable audio on that device. Any
other value, or no key, leaves it enabled. If the shared datastore cannot be
read, audio is treated as disabled. While disabled, `disabled()` is true and
every `open()` ends with status `unavailable`; a running helper is not stopped
by changing the key.

`open(tsid)` takes a session ID from 1 to 0xFFFFFFFE, or `null` for the active
console session that the desktop shows without one, and returns a stream that
emits `status`, `packet` and `close`. Events start after `open()` returns. Each
stream gets at most one `started` status, then exactly one terminal status
(`stopped`, `unavailable` or `error`, with `code` and `reason` when known) and
`close`; `close()` ends the stream with `stopped`, and no event follows it.
All streams for a session share one helper, which ends with the last stream.
A stream that joins a running helper receives `started` and the current
configuration packet first. The module keeps at most four helpers; a failed
helper blocks new streams for that session for 30 seconds, and a stopped helper
blocks them until its process exits, so brokers never overlap. A helper that
sends no configuration within 30 seconds, or no packet for 10 seconds after
starting, is closed as an error.

The helper's stdout is split into packets with a 16-byte header (version 1,
type, flags, sequence, timestamp, payload length of at most 4,096 bytes).
Configuration packets must announce Opus at 48 kHz, stereo, 20 ms frames with
the discontinuity flag and come first; silence packets are empty, audio packets
are not, and status payloads hold a code and at most 256 bytes of UTF-8. Any
other frame stops the helper and ends every stream with `error`. A helper status
packet ends the helper: code 0 is `stopped`; `ERROR_NOT_FOUND`, `E_NOTFOUND`,
`AUDCLNT_E_DEVICE_INVALIDATED` and `AUDCLNT_E_SERVICE_NOT_RUNNING` are
`unavailable`; other codes are `error`. An unexpected exit or broken pipe is
`error`. Packets are forwarded unchanged to every stream as they arrive. The
module retains only the trailing partial frame and the current configuration
packet; it never queues, stores or logs audio. Flow control belongs to the
consumer, which drops packets it cannot send.

The agent's embedded copy (Windows builds) must match
`modules/desktop-audio.js`. The MeshCentral core copies in
`agents/modules_meshcore/desktop-audio.js` and
`agents/modules_meshcore_min/desktop-audio.js` and `desktop-audio.min.js` are
identical to it, and the installed DLL must export `MeshAudioBridgeW`.

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
hash used by the JavaScript HTTP updater. For compatibility with older RAM
senders, the Windows receiver also accepts an exact whole-file SHA-384 after
the normalized hash reader validates the input. New native senders continue
using the normalized EXE hash; malformed images and mismatched digests fail.

Capability `0x100` retains its existing compression meaning. Native streaming
ZIP updates additionally require `0x200`, advertised by the corrected decoder.
Eligible agents without that decoder receive raw native updates. Hash
verification remains mandatory for both formats.

Capability `0x400` is advertised by Windows service agents that apply native
packages through the lifecycle host. MeshCentral pushes a native package to a
Windows service agent only when it advertises `0x400` or `0x200` (every agent
with the corrected decoder already has the lifecycle host). A historical agent
without either bit would hand the package to its own updater, which overwrites
the service EXE with a binary that is not an SCM host, so it is left on its
current version instead.

A Windows service agent defers a server-pushed update while Windows is shutting
down (`SM_SHUTTINGDOWN`) or a Windows Installer transaction holds
`Global\_MSIExecute`. Setting `updateMinUptimeSeconds` (default 0, off) also
defers it until the system has been up that many seconds. The agent checks at
hash negotiation and again before the lifecycle handoff. At negotiation a
deferral answers an all-zero hash, as a blocked transfer does, so no transfer
starts and the server runs its normal core check; the reason is only logged
locally. Before the handoff a deferral drops the staged package and reports
`agentupdatefailed`, so the server restores the core, and the reason is also sent
as a device event (`Agent update deferred: <reason>`). The server negotiates only
on connect or on an operator request, so the agent rechecks every 300 seconds and
reconnects the control channel once, when the deferral clears. With automatic
agent updates disabled on the server, an operator update request that arrives
during a deferral is dropped and must be repeated.

Each lifecycle handoff is counted before it starts, per package hash, in the
datastore key `UpdateRetryState` (`1 <attempts> <unix time> <SHA-384 hex>`), so a
host that dies mid-update has used its attempt. A different package starts again
at one; the record is deleted once the running binary's hash equals it. Automatic
retries of the same package wait 1, 2, 4, 8 and 16 hours, then 24 hours each,
with no attempt limit. While the package waits, a server that sent
`agentupdatefailurecapability` receives
`{"action":"agentupdatefailure","hash":"<hex>"}` before the hash reply and skips
it; an operator's explicit update request still proceeds and is counted. A server
without that capability receives an all-zero hash until the retry is due. When
the wait ends the agent reconnects once so the server offers the package again.
`forceUpdate` and `fakeUpdate` skip the wait but not the readiness checks. Delete
`UpdateRetryState` to reset the count. On connect the agent deletes hold keys
written by earlier builds (`UpdateActivationTargetHash`,
`UpdateActivationFailureHash`, `UpdateActivationFailureCompressed`,
`UpdateForceAttempt`, `forceUpdateHold`, `forceUpdatePending`); none of them is
read.

The lifecycle host checks `SM_SHUTTINGDOWN` before it stops the incumbent service
and again immediately before the commit. During shutdown it aborts and restores
the original installation from the PREPARED or BACKED_UP checkpoint instead of
replacing binaries. `SM_SHUTTINGDOWN` describes the caller's session; whether it
is set for these session 0 processes during a system shutdown still needs
validation on a Windows host.

The Windows self-update activation is asynchronous: `MeshServer_selfupdate_continue`
stages and hashes the package, and calls
`MeshServer_StartUpdateActivation`, which launches the update-only compatibility
lifecycle host and registers the process with the agent chain. This host also
provides uninstall and interrupted-update recovery for older callback-based
service bindings; normal service startup uses the scoped service group. The activation result is
observed in `MeshServer_UpdateActivation_Sink`; on failure the staged payload is
dropped and the failure is reported through `MeshServer_FailUpdateActivation`
(fail-closed). Builds without the RuntimeHost feature set advertise updates as
disabled (an all-zero agent hash), so servers never start a transfer they cannot
apply.

While `forceUpdate` or `fakeUpdate` is set, the agent reports a hash that no
binary has on every connection, so the server sends its package each time.
Clear the key after the update.

An activation timeout does not prove the lifecycle process exited. The agent
keeps that process handle and the staged package, and refuses another transfer
until it observes the process exit. It stays available while the lifecycle host
works. Native block writes acknowledge only complete writes and successful
flush/close; a partial write aborts the transfer instead of appending a retry.

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

## Windows KVM startup input

The MeshCentral KVM viewer starts without synthesizing keyboard or mouse input.
Screen-size updates release only keys recorded as pressed by that viewer before
resetting its stream state; they do not send a blanket modifier-key reset.
This behavior is implemented in the standard and minified
`agent-desktop-0.0.2` viewer assets in the MeshCentral repository and requires
those assets to be published and the viewer page reloaded. The regression probe
is `node test/meshcentral_desktop_startup_input_runtime.js --browsers`; it checks
both assets in Chromium, Firefox, and WebKit without connecting to an endpoint.

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
TLS failure before cleanup, with the bytes sent on that connection
(`totalBytesSent`, including the TLS handshake) for comparison with the bytes
the server received. `[TRANSPORT_ZERO_SEND]` records a `send()` that accepted
0 bytes of TLS ciphertext; the data stays queued, and the record is written at
counts 1, 2, 4, 8, ... per connection. `[AUTH_FAILURE]` identifies rejected authentication.
These records do not require `controlChannelDebug`, `logUpdate`, or
`SERVICE_CONTROLCHANNEL_TRACE` and do not log packet bodies, credentials, or keys.

Each server-authenticated session writes one always-on
`[CONTROLCHANNEL_CONNECTED] descriptor= idleTimeoutSeconds= previousRetryMs= pid=`
record, so the log shows recovery after a failure. `previousRetryMs` is the
reconnect backoff value in effect before authentication resets it to `0`; small
values (500-3000) mean an immediate or first-step reconnect, larger values mean
earlier attempts failed.

Control-channel keepalive: after `controlChannelIdleTimeout` seconds (default
120, minimum 30) with no socket activity in either direction, the agent sends a
WebSocket ping. A pong is due within 15 seconds; a missed pong is re-probed up to
3 times (received data resets the count) before `reason=pong_timeout`.

| `[CONTROLCHANNEL_FAILURE]` field | Meaning |
|---|---|
| `uptimeMs` | System uptime (Windows `GetTickCount64`, Linux `CLOCK_MONOTONIC`, macOS time since boot), not process uptime. |
| `pingAgeMs` | Age of the outstanding keepalive ping; `-1` means no ping was outstanding (cleared at connect and on each pong), not that none was ever sent. |
| `pongProbes` | Re-pings sent after missed pongs for the current ping (0-3). |
| `lastDataAgeMs` | Time since the last received data frame, pong, or connect; sends do not update it. |
| `httpStatus` | `-1` means no HTTP response header was available (socket teardown, connect timeout, DNS failure), not an HTTP error. |
| `interrupt` | WebClient interrupt code; `5` is `WEBCLIENT_DESTROYED` (connection object torn down). |

Ordinary traffic, transient would-block/interrupted I/O, explicit script
disconnects, and chain shutdown do not produce failure records; a successful
connect produces only the `[CONTROLCHANNEL_CONNECTED]` record.
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
