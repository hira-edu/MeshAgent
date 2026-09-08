# Deployment — Single Source of Truth

> Authoritative reference for deploying MeshAgent binaries AND MeshCentral server code to the production server.

Related operational SSOT:

- `docs/REPO_SYNC_AND_DEPLOYMENT_PLAN.md` for cross-repo keep-set, sync hygiene, branch policy, and combined release order across `MeshAgent`, `MeshCentral`, and `UserModeHook`.
- `docs/UMH_CONTROL_SISTER_REPO_SSOT.md` for the agent-side `umhctl` contract and sister-repo update rules.
- `docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md` for the current MeshAgent-side UMH deployment assumptions and recorded cross-repo drift.

Migration note (2026-04-19):
- operator-designated replacement VPS IP is `74.208.52.191`
- direct SSH to `74.208.52.191:22` timed out from the workstation during this update, so any infrastructure facts not explicitly re-captured below remain the last verified pre-migration values
- update the local `meshcentral` SSH alias or override `MESHCENTRAL_SERVER`/`MESHCENTRAL_SSH_HOST` before using `deploy.py` without explicit host overrides

## September 8 desktop release — published

The authorized release is active on VPS `74.208.52.191`. Publication finished
at 13:15:47.888853 UTC on the VPS clock. MeshCentral is active/running as
PID 95340 with `NRestarts=0`. This publication added one coordinated service
stop/start after the four earlier server-fix restarts. The installed server
remains MeshCentral 1.2.5 with the validated relay delta; its complete older
local npm checkout was not used as a production replacement.

The explicit release contains 21 target files and two regenerated
`hashagents.json` manifests. Data and module source EXEs match the frozen build;
MeshCentral's derived signed copies pass signature, executable-section and
embedded-DLL parity checks. Both runtime architecture downloads and the public
HTTPS x64 download contain the exact released DLL. The public and loopback x64
downloads match byte for byte. The native `getSHA384FileHash` result agrees with
the server's source-agent hash for both architectures and for Umair's installed
x64 EXE, including the runtime random-policy footer normalization.

Supplemental read-only checks at 13:40:38–13:41:51 UTC (Windows clock) fetched
group-specific downloads for both architectures in Umair's group and the
existing published group. All four returned HTTP 200 with the expected group
and server identity, `wss://high.support:443/agent.ashx`, no NodeID or update hold,
an exact canonical EXE prefix and a valid big-endian policy-length/GUID trailer.
Independent data-only extraction from both EXEs in all three publish roots,
including the derived signed copies, found the exact DLL in RCDATA type 10,
resource 101. These results are in ignored `group-download-audit/` JSON reports.
The PE32 wrapper embeds an x64 (`0x8664`) service DLL; Win32 wrapper/console
coverage does not establish native 32-bit Windows service support. No binary,
configuration or service change was made for these supplemental checks.

| Published artifact | SHA-256 |
| --- | --- |
| x64 source `MeshService64.exe` / Umair `diaghost.exe` | `204b22948b311e80a5fc4484b586af7df27b8bf3ba617b7cd08f7bc887b8f347` |
| Win32 source `MeshService.exe` | `e03f7f873ff1572558884a1ba52f9a19bc430291484962ab4ca719b28fc448e1` |
| DLL payload and all published DLL aliases | `caa63f1fdebf189da901540388efd3da00d5ad10b16d6dfa19268a1f05b17f80` |
| live `meshdesktopmultiplex.js` | `66baaf88c5b75c344fc3c8eaf36bb6bd9ac8c82063627b4a5c91613d1b28b395` |

The frozen native package uses deployed base
`0fb268971e670b09a89f977f727336a91328f0ea` plus the verified desktop/worker fixes
and stack-allocation alignment correction described below. Its embedded commit
metadata still names that base; file hashes identify this release. The native
fixes were pushed in MeshAgent `53e62729`; the server fixes and merged history
were pushed in MeshCentral `7949ce3cc`, both to `origin/main`.

Preflight found the old VPS sidecars pointed at the unfinished
`agents.high.support` migration while the live domain certificate source and
validated agent still used `high.support`. The three release sidecars now use
`wss://high.support:443/agent.ashx`; every other original sidecar byte, including
each existing VPS enrollment identity, was preserved. No canary update hold is
distributed. The July endpoint/certificate migration below remains historical
and unexecuted by this release. The existing TLS/certificate admission,
keepalive, proxy, core and public UI configuration remains in effect.

Exact rollback copies and original ownership/modes for all 23 targets are in
`/opt/meshcentral/backups/desktop-release-20260908_131537/activation.json` and
its numbered sibling files. The record also identifies targets originally
absent. Deployment used guarded replacements while MeshCentral was stopped,
with automatic exact-file rollback on transaction failure. A later rollback
must restore that recorded set, regenerate/restore its matching manifests and
restart MeshCentral; older server-fix backups below cover only their stated
module changes. Release staging is
`/opt/meshcentral/staging/desktop-release-20260908-1320/`.

After publication and the native hash check, Umair's temporary hold was removed
through the existing native lifecycle. The transaction began at 13:20:40.786 UTC
(Windows clock), passed in 3.144 seconds and started service PID 33152.
Read-only datastore inspection found neither `disableUpdate` nor the earlier
script-namespace key; the authenticated console returned
`require('MeshAgent').updatesEnabled=true`. Both original config files were
restored byte for byte (SHA-256
`af967b82ddf24601f248ec504a24751a7af0823c0598043ab795dceb3940b43e`).
The release `validate-update` check passed with every emitted health check true.
At 13:27:27 UTC (Windows clock), PID 33152 still ran the same EXE/DLL with zero
SCM failure events since its 13:20:43 start. Post-release browser checks showed
fresh images in two viewers, a successful secondary reconnect and an
uninterrupted primary observed through 3 minutes 31 seconds. Input stayed off.
Both viewers were deliberately disconnected and all three release diagnostic
tabs were closed; no debugger remained attached. This is a separate release
smoke check in addition to the earlier 15-minute sustained trace.
Umair remains the only endpoint selected for interactive diagnostic validation;
published packages are now available through normal server distribution.

Both repositories now retain only local `main` and owned `origin/main` branches.
MeshCentral's fully merged `agent/umh-vps-deployment-20260805` branch was deleted
locally and from the owned origin; pre-publication bundles preserve the branch
history. Third-party upstream repositories were not changed. The pre-existing
unrelated `public/scripts/custom.js` edit remains local and was not published.

Release evidence is under MeshAgent's ignored
`artifacts/validation/desktop-stall-20260908/`: `vps-release-result.json`,
`vps-release-download-validation.json`, `vps-release-native-hashes.json`,
`umair-update-hold-release-result.json` and
`umair-release-final-validation-result.json`. The sustained investigation
evidence below predates publication and remains valid for the identical native
payload and relay code.

## 2026-07-26 Single-Endpoint Agent Regression Repair

- The first captured Files failure was an outbound TCP connection to the Cloudflare-backed `high.support:443` path that remained in `SYN-SENT`; no TLS, HTTP, WebSocket, or relay-pairing code ran on that attempt.
- The regression boundary is the ignored provisioning state changing `MeshServer` from the prior direct agent origin to `high.support:443`; Git cannot identify an author or commit for ignored `.msh` files. The active candidate route was compared with refreshed upstream refs (`MeshAgent` `ebff7fb7`, `MeshCentral` `9c872e94`): one configured URL, one URL-derived Host/SNI, one OS address selection, and one request. This is a statement about the inspected route, not a claim that either fork is byte-for-byte upstream.
- The deploy candidate uses exactly `wss://agents.high.support:443/agent.ashx` in the shared, x64, and Win32 `.msh` authorities. Branding metadata has zero fallback endpoints and no explicit Host or SNI override, so both values derive from that URL.
- No address race, raw-IP fallback, proxy discovery, retry layer, delay, certificate bypass, or hash allowlist is part of this repair. No connection or timing code changed during this debugging run.
- One older fork difference remains visible: the failed control-channel request watchdog is 60 seconds, versus 20 seconds in refreshed upstream. It can prolong recovery after a blackholed SYN, but it neither selected the failing route nor runs during normal socket/WebSocket closure, so changing it is outside this evidence-backed regression fix. Source audit found no close-path sleep or timer; the public clean WebSocket close had a reproducible 229 ms median (one network round trip). A real authenticated relay open/close remains a pre-publication gate.
- Standard-port TLS validation plus 20 immediate sequential WebSocket upgrades and peer-confirmed clean closes passed with normal hostname validation. This proves TLS, HTTP `101`, and WebSocket closure only. Full agent command-1 authentication is intentionally blocked from live rollout until MeshCentral's existing default/domain certificate-hash contract admits the `agents.high.support` certificate.
- Status: locally built and contract-tested; not deployed. Replacing the live certificate, package, Caddy configuration, or restarting either service still requires explicit operator approval immediately before the action.
- Do not use the generic `deploy.py stage`/`deploy` path for this repair while unrelated public/core artifacts are present: it stages every available agent, public-download, and MeshCentral core artifact. Live publication must use an explicit allow-list containing only the rebuilt MeshService binaries/DLL payloads and the three matching `.msh` entries; exclude `MasterService.exe`, MeshCentral core/UI files, and Caddy configuration.

### Certificate-Hash Migration Gate

MeshCentral accepts an agent edge certificate when its full/key hash matches
either the configured domain certificate or the default server certificate.
Use that existing four-slot check for a state-based migration; do not disable or
extend it.

1. Phase 1 keeps `domains[""].certurl=https://high.support/` for existing agents.
   Back up the default certificate files, replace only
   `webserver-cert-public.crt` and `webserver-cert-private.key` with the matching
   Caddy `agents.high.support` certificate/key pair from
   `/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/agents.high.support/`,
   preserve `meshcentral:meshcentral` ownership and
   `0644`/`0600` modes, then restart MeshCentral once. This produces the proven
   overlap: old `high.support` agents match the domain slot and new
   `agents.high.support` agents match the default slot.
2. Validate real command-1 authentication for both cohorts, then publish the
   single-endpoint package. Advance based on observed connected-agent inventory;
   do not add a sleep, retry race, or arbitrary migration window.
3. After no deployed agent remains on `high.support`, set only
   `domains[""].certurl=https://agents.high.support/` and restart MeshCentral a
   second time. This final state follows normal proxy-certificate refresh and no
   longer depends on the copied default-certificate snapshot.

Two restarts are required because both certificate inputs are loaded into
process state. Combining the phases would remove compatibility for the old
cohort before it migrates. On phase-1 failure, restore the backed-up default
pair and restart. On phase-2 failure, restore only the old `certurl` and restart,
which restores the phase-1 overlap. HTTP `101` alone is not a release gate;
verify agent authentication and a real relay open/close cycle.

## Desktop multiplexer repair boundary

Pre-publication validation, September 8 at 12:49:50 UTC (Windows clock): the server relay
corrections below and Umair's native canary are active and validated. Umair is
the only endpoint selected for this native deployment. `WinDiagnosticHost`
remained Running as PID 13936, started at 12:29:58 UTC, with no subsequent
service-failure events. Its installed binary SHA-256 values are:

- `diaghost.exe`: `204b22948b311e80a5fc4484b586af7df27b8bf3ba617b7cd08f7bc887b8f347`
- `diagsvc.dll`: `caa63f1fdebf189da901540388efd3da00d5ad10b16d6dfa19268a1f05b17f80`

The sustained checkpoint records 939.053 seconds of uninterrupted primary
traffic, 40,156,441 bytes delivered and 15 matched heartbeat rounds on both
the viewer and agent transports. The primary ultimately ran 956.998 seconds
and received 41,033,471 bytes before its deliberate UI disconnect. Five
secondary reconnects received fresh desktop images while the primary remained
connected. A subsequent fresh viewer pair each received over 4 MB and completed
a heartbeat round. There
was no native fatal capture or stream gap; the collector reported zero kernel
packet drops. Native `validate-update` passed. The debugger, process monitor,
relay collector and two diagnostic tabs were closed. An unrelated viewer was
preserved, so the fresh pair does not prove complete shared-capture teardown.
This is bounded live validation, not an attribution of every historical freeze.

The initial canary required a temporary native update hold because the server
then published the older package. Its first successful activation at
12:18:57 UTC was replaced through normal automatic update. The held binary-only
transaction began at 12:29:26 UTC and passed in 33.038 seconds. Native `.msh`
import set the previously absent bare `disableUpdate=1` key, and the native
`updatesEnabled` getter returned false during sustained validation.

Console `dbset` had written the ineffective script key `0/disableUpdate`; that
key was removed. Restoring config that simply omits a setting does not delete
its persisted native value. After the correct package was published, restoration
used the original config plus a temporary empty `disableUpdate=` line for native
startup to delete the bare key, verified key absence and `updatesEnabled=true`,
then restored both exact original config files. This restoration is complete,
as recorded in the published-release section above. Original config backups are
in `native-canary-config-before-hold`; original and server-restored binary
rollback sets remain separate under the ignored evidence root.

Relay timestamps use the VPS clock; activation, process and SCM timestamps use
Windows. A read-only comparison at 12:45 UTC bounded the VPS clock 14.143–17.341
seconds ahead of Windows. Use same-source durations for the trace; reported
cross-host timestamps below are not synchronized causal-delay measurements.

The desktop multiplexer must reevaluate agent read backpressure when a viewer
joins or leaves. If every viewer is overloaded, the agent socket pauses; a
healthy viewer must release that pause unless a recording write is pending.
Removing the only healthy viewer must restore backpressure. In particular,
joining during startup or a screen reset cannot depend on the new viewer first
entering and leaving image overflow: the image cache can contain only the screen
size packet at that point.

Agent disconnection must close a snapshot of the viewer array. Each viewer's
close method synchronously removes it from the original array; iterating that
mutating array skips viewers and leaves them connected to a disposed image
cache. The existing close, permission and audit paths remain in use.

The relay caller must honor `addPeer()` rejecting a duplicate agent. Closing
that rejected relay prevents an unregistered socket and its timers from
remaining attached to the shared session; existing members remain connected.

The September 8 inspection found the live server module differs from the local
MeshCentral source, including older refresh and image-cache handling. Publish
only an explicitly reviewed delta against the current live module, with a
pre-publication SHA-256 check and an exact rollback copy. Do not replace the
whole live module with the local checkout. The initial server-only repair did
not publish native binaries; the later authorized combined release is recorded
above. Following operator authorization, the flow-control delta
was activated on September 8 at 08:35:27 UTC. A subsequent live two-viewer check
exposed the disconnect defect, which also reproduced against the original
source. The viewer snapshot fix was activated at 08:50:13 UTC. Relay tracing
then confirmed that rejected duplicate agent sockets remained open. The final
delta, including explicit rejection cleanup, was activated at 09:10:12 UTC.
The two-line input queue correction was activated at 11:12:59 UTC after
reproducing both the missing in-flight flag and the incorrect queue-length
comparison. Four MeshCentral restarts occurred during this investigation.
The active module SHA-256 is
`66baaf88c5b75c344fc3c8eaf36bb6bd9ac8c82063627b4a5c91613d1b28b395`.
The previous three-fix module is preserved in
`/opt/meshcentral/backups/desktop-flow-20260908_111259`.
Input writes now allow one outstanding send, queue subsequent commands in
order, and pause viewers when that queue exceeds ten entries. All nine
behavioral cases and the real-socket test passed against the active module as
the service user with the server's actual nested `ws` dependency.
The exact previous module and activation metadata are preserved in
`/opt/meshcentral/backups/desktop-flow-20260908_083527`. To roll back this change,
restore that directory's `meshdesktopmultiplex.js` to the live module path with
the recorded original owner and mode (`root:root 0644`), then restart MeshCentral.
The intermediate flow-control-only version is separately preserved in
`/opt/meshcentral/backups/desktop-flow-20260908_085013`.
The intermediate flow-control and viewer-snapshot version is preserved in
`/opt/meshcentral/backups/desktop-flow-20260908_091012`.
The candidate remains in `/opt/meshcentral/staging/desktop-stall-20260908/`.
Service startup, authenticated admin reload, agent reconnection, and the
loopback regression using the live server's nested `ws` dependency passed.
Rohit was offline during diagnosis, so its historical freeze cannot be
attributed conclusively. The operator selected Umair alone for live validation;
Rohit's availability is not a deployment or completion prerequisite.

The later Umair run retained the original agent tunnel through a third viewer's
join/leave and two controlled secondary reconnects. Passive relay metadata
showed over 30 MB of continuing traffic and six successful 60-second ping/pong
exchanges; browser checks exceeded seven minutes. Earlier three-to-four-minute
closures, including one on the final module, did not occur during that trace,
but the later session also closed after 480 seconds once the short trace ended.
An extended trace then captured the native service fatal exit at 09:57:03 UTC,
followed by the agent-side TCP close at 09:57:55 and closure of both viewers.
More than 96 MB and repeated successful heartbeats preceded this failure.
That pre-canary run failed; the final held-canary result is recorded above.
Keepalive, cookie and proxy configuration were not changed.

Subsequent Windows SCM event 7031 records and the service-owned `diaghost.log`
identify six native agent fatal exits during these checks. Duktape reports
`uncaught: 'invalid base value'` through
`ILibDuktape_ScriptContainer_Engine_fatal` (`exit(254)`), followed by the existing
10-second service recovery. The invalid access required a stack/reproduction
before a crash fix or rollout.
A standard elevated debugger inventory succeeded. The first request to attach
a fatal-exit breakpoint was canceled at Windows elevation. The elevated
continuation on September 8 at 10:45 UTC successfully attached to the running
`WinDiagnosticHost` service and armed the fatal-handler breakpoint with matching
private symbols. At 10:55:46 UTC the breakpoint captured the fatal caller and a
minidump, then detached. The stack runs from
`NonIsolatedWorker_ProcessAsSlave` through `Process_UncaughtExceptionEx` and
`EventEmitter_GetEmitter` to `duk_has_prop`. The minimal worker heap had been
published before its INIT command returned through the parent's event loop.
An early script error therefore reached error reporting before the `process`
object existed. A local runtime reproduction produces the same fatal message
and exit 254; execution after `ready` reports the original error normally.

The local startup fix queues INIT before publishing the worker and retains
commands arriving before publication in FIFO order. Permissions are assigned
before thread creation; their values and enforcement are unchanged. Exit and
send use the same startup queue, and commands after heap destruction are
discarded through the existing nonce/lifetime checks. The nine-case startup
runtime test covers early/immediate execution, syntax errors, ordered messages,
early exit, post-exit calls and denied modules. The original binary passes only
the `ready` control; all nine pass with the fixed console and full-package
console. No fatal-error suppression or retry was added.
The DLL and full x64/Win32 package builds passed. The packaged console also
passed 61 capture connections, and the packaged DLL passed the first-frame
test and embedded-payload parity check. These fixes are included in the
validated Umair canary recorded above.

The live agent reports commit `0fb268971e670b09a89f977f727336a91328f0ea`,
compiled July 26. Its installed executable embeds
`wss://high.support:443/agent.ashx`, whereas the current checkout's build profile
uses a different endpoint. The September 8 native canary is therefore built
from that deployed commit with the two fixes above and the already-committed
`ILibParsers.h` stack-allocation alignment correction. The latter is required
by a separate reproduced HTTP request stack overwrite: the old allocator
reserved unaligned storage while `ILibMemory_Init` writes the rounded size.
The debugger reports `_RTC_AllocaFailure` from
`ILibDuktape_HttpStream_http_ConvertOptionToSend`; the existing eight-path HTTP
alignment test fails before the header correction and passes afterward.
This does not attribute every previously malformed live packet to that defect.

The exact canary passes all nine worker startup cases, eight HTTP request
lengths, 61 capture connections, DLL first-frame capture and embedded DLL
parity. Its DLL and full x64/Win32 builds pass. Stage only its paired binaries
for the existing binary-only update transaction, which validates and retains
installed provisioning and NodeID. Do not use the broad publisher or the
current-checkout package for this canary. The initial elevation request was
canceled at 11:43:14 UTC. Following renewed operator authorization, the
elevated task completed read-only package preflight at 12:00:12 UTC, with
service PID 33116 unchanged. That older package was superseded by the additional
proven lifecycle corrections below. Only the revised immutable package was
used for the final activation and sustained validation recorded above.

Additional worker lifecycle testing reproduced a second native crash in the
original binary: an exit listener released its last container reference and
native event dispatch subsequently read the freed master buffer. The debugger
captured command 128 in `NonIsolatedWorker_ProcessAsMaster` and `duk_pop` using
the freed-memory value `feeefeeefeeefeee`. Dispatch now holds a stack reference
to the container until all native accesses finish, using a saved context for
the final pop. Immediate and ready/error/data callback release checks pass.

With the crash isolated, 45 worker lifecycles exposed three leaked Windows
handles per worker: the caller's worker-thread handle, the chain's separately
opened thread handle and its watchdog event. The owning finalizer and chain
cleanup now release them. Cleanup joins the watchdog before freeing the chain
it reads. API failures remain explicit. Handle counts at 5/25/45 completed
workers changed from 202/262/322 to 187/187/187; all 45 threads finish normally.
The revised canary adds `ILibParsers.c` as its fourth native-file delta from the
deployed revision. DLL/full-package builds, nine startup cases, 13 additional
startup/concurrency cases, lifecycle cleanup, HTTP alignment, 61 capture
connections, DLL first-frame capture and embedded-payload parity pass on x64.
The startup, concurrency and lifecycle cases also pass on Win32, with handle
counts 205/205/205 after warmup. The current-checkout build mirror separately
passes its DLL/full builds, startup/lifecycle, HTTP and capture checks; it is
not the deployment candidate because its unrelated module/endpoint changes
are outside this repair.
These runtime findings are independently proved defects; they do not establish
that every historical Rohit freeze had the same cause. Native activation was
owned by the coordinated elevated task, which verified the frozen
`native-canary-lifecycle-package` handoff (EXE SHA-256 prefix `204b2294`, DLL
prefix `caa63f1f`). It performed elevated preflight, the Umair update, local
debugger and sustained two-viewer validation. The source task retained
source/tests/docs ownership and verified the final evidence before recording
the current state above. The source and package stayed frozen during this run.

The isolated console capture path exposed a separate, reproduced deadlock:
the capture thread waited for output while holding the tile-state lock, while
the chain thread handling a new pipe's refresh waited for that lock. The chain
could therefore never run the output completion that resumes capture.
`kvm.c` now waits for transport output before acquiring the tile lock and ends
the current scan when output pauses. Unsent tiles are reconsidered on the next
frame under the existing tile-state lock and generation checks. Refresh,
resolution changes and transport backpressure retain their existing contracts.
This native change is included in the validated Umair canary. Its console
reproduction does not establish the cause of the separate Duktape fatal exit.
Use `test/kvm_capture_reconnect_runtime.js` against both the original and rebuilt
console binaries on an authorized interactive desktop before publishing it.

The same inspection confirmed nightly archives were failing while traversing
`/opt/meshcentral/backups/meshagent-only-20260722_203928-d6ccd3ab`. That directory
now remains owned by root, with group `meshcentral` and mode `0750` instead of
`root:root 0700`; its descendants were already readable. Archiving the affected
tree as the service user succeeded. This validates the permission repair, not
completion of a scheduled full backup. Preserve service-account read/traverse
access on deployment snapshots included in automatic backups; do not make them
world-readable. To undo this permission change, restore this directory alone
to `root:root 0700`.

## Server Infrastructure

| Property | Value |
|---|---|
| **Host** | `74.208.52.191` (`srv1057130`, verified by the 2026-07-26 SSH capture) |
| **DNS** | `high.support` / `agents.high.support` / `relay.high.support` |
| **OS** | Ubuntu 24.04, Linux 6.8.0-106-generic x86_64 |
| **SSH User** | `root` |
| **SSH Key** | `~/.ssh/id_ed25519` (comment: `meshagent-deploy@workstation`) |
| **Service** | `systemctl {start|stop|restart|status} meshcentral` |
| **Node** | `/usr/bin/node` |
| **MeshCentral Base** | `/opt/meshcentral` |
| **MongoDB** | `mongodb://127.0.0.1:27017/meshcentral` |

## Remote Directory Layout

```
/opt/meshcentral/
├── meshcentral-data/
│   ├── config.json                          # MeshCentral server config
│   └── signedagents/                        # Agent binaries served to endpoints
│       ├── MeshService.exe                  # x86 32-bit agent
│       ├── MeshService64.exe                # x86 64-bit agent  ← PRIMARY DEPLOY TARGET
│       ├── MeshServiceARM64.exe             # ARM64 agent
│       ├── MeshCmd.exe / MeshCmd64.exe      # Command-line tools
│       └── hashagents.json                  # Signed-agent metadata (auto-generated)
├── node_modules/meshcentral/agents/         # Module-level agent copies
│   ├── MeshService64.exe                    # ← Authoritative source build for MeshCentral startup
│   ├── hashagents.js                        # Architecture ID mapping source
│   ├── hashagents.json                      # Authoritative runtime manifest read by MeshCentral
│   └── ...                                  # Other tools (Router, Commander, etc.)
├── staging/                                 # Pre-deploy staging area (created by deploy.py)
└── backups/                                 # Timestamped backup snapshots
    └── YYYYMMDD_HHMMSS/
        ├── signedagents/
        └── agents/
```

## Local Build Artifacts

| Artifact | Local Path (relative to repo root) | Renamed To (on server) |
|---|---|---|
| Standalone EXE x64 | `meshservice/x64/StealthLab/MeshService-2022.exe` | **`MeshService64.exe`** |
| Standalone EXE x86 | `meshservice/StealthLab/MeshService-2022.exe` | `MeshService.exe` |
| Svchost DLL publish sidecar | `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` | `MeshService64.dll` |
| Runtime svchost DLL | `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` | `diagsvc.dll` |
| Embedded Payload | `meshservice/embedded/svchost_payload.dll` | `svchost_payload.dll` |
| Agent policy x64 | `meshservice/x64/StealthLab/MeshService-2022.msh` | `MeshService64.msh` |
| Agent policy x86 | `meshservice/StealthLab/MeshService-2022.msh` | `MeshService.msh` |
| Shared provisioning policy | `WinDiagnosticHost.msh` | `WinDiagnosticHost.msh` |
| UMH public payload | `../UserModeHook/build/bin/Release/MasterService.exe` | `MasterService.exe` |

**Important:** The Visual Studio build output is named `MeshService-2022.exe`. During staging/deploy it is **renamed** to `MeshService64.exe` to match the filename MeshCentral expects when serving agents to endpoints.

## hashagents.json

After deploying new binaries, `hashagents.json` must be regenerated from the actual published bytes. MeshCentral reads `node_modules/meshcentral/agents/hashagents.json` at startup, then resolves runtime binaries in this order: `meshcentral-data/agents/` first, `meshcentral-data/signedagents/` second, and `node_modules/meshcentral/agents/` last. The signed-agent manifest is maintained for observability and post-restart verification, but the module-side manifest is the authoritative startup input. Each entry contains:

```json
{
  "4": {
    "filename": "MeshService64.exe",
    "hash": "<SHA384 of the binary>",
    "size": 7720960,
    "mtime": "2026-03-02T17:56:54Z"
  }
}
```

| Field | Description |
|---|---|
| **Key** (`"4"`) | MeshCentral agent architecture ID (`4` = Windows Service x64) |
| `filename` | Must match the renamed binary on disk (`MeshService64.exe`) |
| `hash` | SHA-384 hash of the binary — MeshCentral uses this to detect changes and serve updates |
| `size` | File size in bytes |
| `mtime` | ISO 8601 UTC timestamp of when the binary was last modified |

**Regeneration:** `deploy.py deploy` does not execute `node hashagents.js`. That file is only the filename-to-architecture mapping source. The deploy tool parses it locally and regenerates `hashagents.json` remotely with Python so the manifest is built from the real on-disk binaries in each target directory.

**Architecture IDs relevant to this project:**

| ID | Agent |
|---|---|
| `3` | `MeshService.exe` (Windows Service x86 32-bit) |
| `4` | `MeshService64.exe` (Windows Service x86 64-bit) — **primary deploy target** |
| `5` | `meshagent_x86` (Linux x86 32-bit) |
| `6` | `meshagent_x86-64` (Linux x86 64-bit) |

## Access Methods

### 1. deploy.py (Automated — Primary)

The deployment tool at repo root (`deploy.py`) handles the full lifecycle via SSH key auth.

```bash
python deploy.py status          # Server health, agents, backups
python deploy.py stage           # Upload artifacts to /opt/meshcentral/staging/
python deploy.py deploy          # Backup → deploy → rehash → restart
python deploy.py deploy -y       # Same, skip confirmation
python deploy.py rollback        # Restore from backup
python deploy.py rollback -i 0   # Restore specific backup index
python deploy.py config          # View config.json
python deploy.py config edit     # Download, edit locally, upload, restart
python deploy.py logs 100        # Tail last N lines of service logs
python deploy.py health          # Full health check (ports, service, DB)
python deploy.py ssh "command"   # Run arbitrary remote command
```

**Deploy pipeline steps (what `deploy` does):**
1. Verifies the full local package set is present before staging
2. Creates timestamped backups of the current `meshcentral-data/agents`, `meshcentral-data/signedagents`, and `node_modules/meshcentral/agents` payloads
3. Copies the staged package set → `/opt/meshcentral/meshcentral-data/agents/`
4. Mirrors the staged package set → `/opt/meshcentral/meshcentral-data/signedagents/`
5. Mirrors the staged package set → `/opt/meshcentral/node_modules/meshcentral/agents/`
6. Copies `MasterService.exe` → `/opt/meshcentral/meshcentral-files/domain/user-hsadmin/Public/` (for `umhctl install --url ...` download only)
7. Regenerates `hashagents.json` for the module and signed publish directories from the actual remote files
8. Restarts `meshcentral` systemd service
9. Re-runs post-restart publish verification so `meshcentral-data/agents/` and `node_modules/meshcentral/agents/` still match the local build while `signedagents/` remains self-consistent if MeshCentral repacks/signs the EXEs
10. Writes a local release manifest with repo SHAs and artifact hashes under `artifacts/deployment/`
11. Cleans staging area

### 2. Direct SSH (Ad-Hoc)

```bash
ssh -i ~/.ssh/id_ed25519 root@74.208.52.191
```

Passwordless key auth is configured. No password needed.

### 3. WinSCP (GUI — Ad-Hoc)

- Installed at: `C:\Users\Public\Desktop\WinSCP.lnk`
- Use for manual file browsing, quick edits, and drag-drop uploads
- Connect with: Host `74.208.52.191`, User `root`, Key file `C:\Users\Workstation\.ssh\id_ed25519`

### 4. SCP (Single-File Transfer)

```bash
# Upload
scp -i ~/.ssh/id_ed25519 localfile.exe root@74.208.52.191:/opt/meshcentral/staging/

# Download
scp -i ~/.ssh/id_ed25519 root@74.208.52.191:/opt/meshcentral/meshcentral-data/config.json ./config.json
```

## Deployment Workflow

### Standard Deploy (Build → Stage → Deploy)

```
1. Build with `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`
2. python deploy.py stage      → uploads to server staging/
3. python deploy.py deploy     → backup, copy, rehash, restart
4. python deploy.py health     → verify service, ports, no errors
```

Build contract:
- `MeshAgent.Build.proj` is the supported entrypoint because it serializes `StealthLab_DLL|x64` before `StealthLab|x64` and `StealthLab|Win32`.
- Direct `StealthLab|x64` project builds now force the `StealthLab_DLL|x64` prerequisite before the EXE build refreshes `meshservice/embedded/svchost_payload.dll`.
- Do not run separate x64 DLL and x64 EXE project builds in parallel against the same tree; use `MeshAgent.Build.proj` for full package output.
- Do not add or use PowerShell build wrappers. Build orchestration lives in MSBuild; Python generators are invoked only through MSBuild targets or explicit pre-build validation.
- Generated Visual Studio output directories (`meshservice/x64`, `meshservice/Win32`, `meshservice/MeshService-2022/x64`, root `x64`, and embedded svchost payload outputs) are excluded from implementation truth and should not be committed.

Publish contract for MeshAgent packages:
- `deploy.py stage` must prove the full package set is present before upload: `MeshService64.exe`, `MeshService.exe`, `MeshService64.dll`, `svchost_payload.dll`, `diagsvc.dll`, `MeshService64.msh`, `MeshService.msh`, and `WinDiagnosticHost.msh`.
- `deploy.py stage` must prove local payload parity before upload: the repo `MeshService64.dll`, `meshservice/embedded/svchost_payload.dll`, and the embedded svchost RCDATA payload inside `MeshService64.exe` must all hash-identically.
- After `deploy.py deploy`, verify the embedded svchost payload inside the remote `meshcentral-data/agents/MeshService64.exe`, `node_modules/meshcentral/agents/MeshService64.exe`, and `meshcentral-data/signedagents/MeshService64.exe`.
- A `signedagents` EXE may have a different raw file size or digest than the local EXE because MeshCentral repacks it, but its embedded svchost payload must still match the repo DLL exactly.
- When validating live package identity, distinguish the generic agent URL from a real group download. `https://high.support/meshagents?id=4` is the generic Windows x64 service package and will not prove group-specific identity. Use the portal-generated Office download link or `https://high.support/meshagents?id=4&meshid=<group-meshid>` when checking `-name`, embedded `.msh` identity, or install behavior for a specific group.
- Package-driven Windows updates adopt the staged package provisioning identity (`MeshID`, `ServerID`, `MeshServer`) while preserving the installed `NodeID`; packages that would replace or delete an installed `NodeID` are rejected before commit. Binary-only updates continue to retain the installed provisioning identity.
- Windows update activation has one native authority. MeshCentral JavaScript does not replace Windows binaries; the control channel verifies and stages the package in `agentcore`, while the compatibility `agent-installer.js` update API delegates through `MeshAgent.activateNativeUpdate()` into the shared native activation layer. Native callers converge on `MeshRundll32_LaunchLifecycleHostW`, then `MeshLifecycleHostW`, `Stealth_RunLifecycleOperation`, and the sole update transaction executor `Stealth_ApplyUpdateFlow`. Platform and ingress branches are adapters, not alternate Windows commit implementations.
- Remote update activation in `deploy.py` derives the default Windows install root, installed `ServiceDll`, and `state\rundll32-lifecycle` directory from the active branding configuration instead of a hard-coded product path. For the current DiagnosticHost build, `branding_config.local.json` resolves those paths to `C:\ProgramData\DiagnosticHost`, `C:\ProgramData\DiagnosticHost\diagsvc.dll`, and `C:\ProgramData\DiagnosticHost\state\rundll32-lifecycle`; `MESHCENTRAL_INSTALL_ROOT`, `MESHCENTRAL_LIFECYCLE_DLL`, and `MESHCENTRAL_LIFECYCLE_STATE_DIR` remain explicit operator overrides.
- `deploy.py` also publishes the retained MeshCentral KVM/browser support files (`meshdesktopmultiplex.js`, `agent-redir-ws-0.1.1*.js`, and `agent-desktop-0.0.2*.js`) to the module/web public roots so served viewer behavior cannot drift from the local contract fixtures.

### Emergency Rollback

```
1. python deploy.py rollback   → lists backups, select one, restore, restart
2. python deploy.py health     → verify recovery
```

### Config Change

```
1. python deploy.py config edit   → downloads, opens in editor, validates JSON, uploads
   (OR use WinSCP to browse and edit config.json directly)
2. Service restarts automatically if you confirm
```

---

## Part 1b: MasterService (UserModeHook) Deployment

MasterService.exe is published for UMH operator workflows, but it is not part of the MeshAgent package shape and it is not staged beside MeshAgent binaries for install/update/uninstall.

Operator-surface authority note:

- this section documents the MeshAgent-side `umhctl` operator layer
- it does not claim that the native `UserModeHook` CLI exposes identical text commands
- `docs/UMH_CONTROL_SISTER_REPO_SSOT.md` is authoritative for the split between the MeshAgent operator layer, MeshCentral UI emitters, and the native `UserModeHook` surface
- the current operator-layer default header version in this repo is `2026-03-05`, which now matches the current `UserModeHook` hard-fail version recorded in `docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md`

### How It Works

1. `deploy.py stage` uploads `MasterService.exe` (from `../UserModeHook/build/bin/Release/`) to the server staging area
2. `deploy.py deploy` publishes it to the public userfiles directory
3. Agents download it on-demand via `umhctl install --url ...`
4. Native MeshAgent `-fullinstall`, `-fullupdate`, `-fulluninstall`, GUI install/update, and server auto-update do not stage or manage `MasterService.exe`
5. Native MeshAgent provisioning stays dynamic: identity and endpoint values come from the downloaded package's sibling `.msh`, embedded `.msh`, or valid staged config, not from hardcoded mesh/group values
6. Native lifecycle waits for SCM service-name release before reinstalling; `ERROR_SERVICE_MARKED_FOR_DELETE` is treated as a transient busy state, not a successful uninstall
7. Native `start` and `restart` service-control commands recover the managed service back to `AUTO_START` before retrying if the start type was found disabled unexpectedly

### Agent Console Commands (`umhctl`)

The MeshAgent shared operator module `modules/umhctl.js` is consumed by `modules/RecoveryCore.js` and mirrored into the MeshCentral-served default, minified-default, agent-recovery, tiny, and live-override core paths. The retained `umhctl` command surface for managing MasterService is:

| Command | Description |
|---|---|
| `umhctl install` | Downloads `MasterService.exe` from server and installs service |
| `umhctl install --url <url>` | Downloads from a custom URL instead of server |
| `umhctl uninstall` | Stops and uninstalls `AdvancedHookService` |
| `umhctl status` | Sends `{"op":"status"}` to UMH control pipe |
| `umhctl status --service` | Runs `MasterService.exe --status --output json` through the approved `rundll32.exe <ServiceDll>,MeshUmhHostW <manifest>` contract |
| `umhctl listProcesses` | Sends `{"op":"listProcesses"}` to control pipe |
| `umhctl getFlowContract` / `getCapabilities` | Sends control-contract and capability queries to the control pipe |
| `umhctl getPolicy` / `getConfig` | Sends read-only policy/config queries to the control pipe |
| `umhctl uiSnapshot [--pid <pid>]` | Aggregates the retained read-only UMH snapshot sections |
| `umhctl profileProcess --pid <pid>` | Sends `{"op":"profileProcess"}` to the control pipe |
| `umhctl methodPolicy [--pid <pid>]` | Sends `{"op":"methodPolicy"}` to the control pipe |
| `umhctl safetyState` | Sends `{"op":"safetyState"}` to the control pipe |
| `umhctl hookProfile --target <tag> [--exe <path>]` | Sends `{"op":"hookProfile"}` to the control pipe |
| `umhctl securityBoundary [--pid <pid>] [--target <tag>]` | Sends `{"op":"securityBoundary"}` to the control pipe |
| `umhctl inject --pid <pid> [--method <m>] [--technique <t>]` | Sends inject request to control pipe |
| `umhctl injectAll` | Sends `{"op":"injectAll"}` to control pipe |
| `umhctl telemetry` | Sends `{"op":"telemetry"}` to control pipe |
| `umhctl repair` | Sends `{"op":"repair"}` to control pipe |
| `umhctl injectTargetSet --pids <csv> [--run-id <id>] [--target-tag <tag>] [--method-key <key>]` | Sets the active target scope in the control pipe |
| `umhctl clearTargetScope` | Clears the active target scope |
| `umhctl setPolicy` / `setConfig` | Sends the retained write-policy/config operations to the control pipe |
| `umhctl --json "<json>"` | Sends raw JSON request directly to control pipe |
| `umhctl help` | Lists commands and runtime paths |

Retired operator commands `hookControl`, `lockdownBypass`, `examsoftBypass`, and
`ipcBypass` are not canonicalized or dispatched. Console and raw-JSON requests for
them fail closed as unsupported. Input and WDA neutralization for the applicable
targets is automatic at HookDLL install time.

**Download URL**: `https://agents.high.support/userfiles/hsadmin/MasterService.exe?download=1`. MeshCentral's UMH install buttons use this explicit Caddy-backed origin because the rolled-back embedded agent TLS client cannot complete the Cloudflare-backed `high.support` handshake. The server `Public/` storage remains exposed without the `Public` path segment.

**Binary location**: Determined by the UMH installer/operator flow. It is not a MeshAgent package sidecar and must not be appended next to the downloaded agent binary.

**Control pipe**: `\\.\pipe\{95c1a2e0-f84e-4c8a-9c32}-control`

Current `uiSnapshot` semantics:

- without `--pid`, it requests `status`, `flow_contract`, `capabilities`, `processes`, `policy`, `config`, and `safety_state`
- with `--pid <pid>`, it additionally requests `process_profile`, `method_policy`, and `security_boundary`
- `partial=true` means one or more section requests failed
- the current expected live partial on a healthy canary is missing `C:\ProgramData\UserModeHook\config.json`, which makes native `getConfig` return `config not found`

Runtime compatibility notes for the shared operator module:

- guard timer handles that do not implement `.unref()`
- attach child-process completion defensively when only one of `exit` or `close` is supported
- do not prepend the executable basename to `execFile` argv arrays

Current live publication reference (2026-08-05):

- published payload path: `/opt/meshcentral/meshcentral-files/domain/user-hsadmin/Public/MasterService.exe`
- published payload URL: `https://agents.high.support/userfiles/hsadmin/MasterService.exe?download=1`
- published payload size: `16986624`
- published payload SHA256: `347f3c5ec7478fbb9e765d70b39ba4130a018662b2be633fe424af9440d14fc1`
- published payload SHA384 / install pin: `827b9d4e9bb254a2bdb4e9c423a3ae97e319f119941f4c2bd792719ac7bcf178e6932b452aa23d02e7164908f60e1b54`
- all four live `umhctl.js` copies: SHA256 `64cd8c4c660fd14f4b9a64a9b20345e84488762b152f3943491664ed94a5448f`
- live `recoverycore.js`: SHA256 `4013fa7f958632df0462f2fbbd8cef6cb35663e7b2f3334a43017be7a4a75843`
- live UI override path: `/opt/meshcentral/meshcentral-web/public/scripts/custom.js`
- live MeshCentral publication currently exposes `umhctl` across the default, minified default, recovery, diagnostic, tiny, and `meshcentral-data` default core paths
- see `docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md` and the UserModeHook sister ledger for the current live hashes

### MeshCentral UI Buttons

The `custom.js` script (deployed to MeshCentral) adds preset buttons to the Run Commands dialog:

- **UMH Install** — sends `umhctl install` as agent console command (type 4)
- **UMH Status** — sends `umhctl status`
- **UMH Uninstall** — sends `umhctl uninstall`
- **UMH Help** — sends `umhctl help`

The curated live UI subset also exposes retained query/mutation buttons for:

- `listProcesses`
- `getFlowContract`
- `getCapabilities`
- `safetyState`
- `profileProcess`
- `methodPolicy`
- `securityBoundary`
- `inject`
- `injectAll`
- `clearTargetScope`

These replace the previous 62+ PowerShell download-and-run buttons with simple agent console commands.

### Deploy Workflow

```
1. Build MasterService in VS (from UserModeHook repo)
2. python deploy.py stage           → uploads MasterService.exe and MeshAgent artifacts to staging
3. python deploy.py deploy          → deploys MeshAgent to agent publish dirs and MasterService.exe to userfiles/
4. realign/update the local `MeshCentral` live mirror before changing any UMH UI surface
5. record the same change in the MeshCentral and UserModeHook sister ledgers
6. test the deployed path from the agent console with `umhctl install`
```

---

## Part 2: MeshCentral Server Code Deployment

### Overview

MeshCentral v1.1.56 is installed via npm at `/opt/meshcentral/node_modules/meshcentral/`.
The local `MeshCentral` repo is treated as a mirror of the live VPS module tree plus selected live overrides, not as an authoritative source checkout with guaranteed local-only deployment tooling.

### MeshCentral Local Repo

The MeshCentral repo at `C:\Users\Workstation\Documents\GitHub\MeshCentral` is now a live mirror workspace for the deployed VPS state. See:

- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_SISTER_REPO_SSOT.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_DEPLOYMENT_LEDGER.md`

### Tracked File Mapping

| Local Path (in MeshCentral repo) | Remote Path on Server |
|---|---|
| `public/scripts/custom.js` | `/opt/meshcentral/meshcentral-web/public/scripts/custom.js` |
| `public/scripts/agent-redir-ws-0.1.1.js` | `/opt/meshcentral/meshcentral-web/public/scripts/agent-redir-ws-0.1.1.js` |
| `public/scripts/agent-redir-ws-0.1.1-min.js` | `/opt/meshcentral/meshcentral-web/public/scripts/agent-redir-ws-0.1.1-min.js` |
| `public/scripts/agent-desktop-0.0.2.js` | `/opt/meshcentral/meshcentral-web/public/scripts/agent-desktop-0.0.2.js` |
| `public/scripts/agent-desktop-0.0.2-min.js` | `/opt/meshcentral/meshcentral-web/public/scripts/agent-desktop-0.0.2-min.js` |
| `views/default3.handlebars` | `/opt/meshcentral/node_modules/meshcentral/views/default3.handlebars` |
| `views/agentinvite.handlebars` | `/opt/meshcentral/node_modules/meshcentral/views/agentinvite.handlebars` |
| `meshdevicefile.js` | `/opt/meshcentral/node_modules/meshcentral/meshdevicefile.js` |
| `meshagent.js` | `/opt/meshcentral/node_modules/meshcentral/meshagent.js` |
| `meshdesktopmultiplex.js` | `/opt/meshcentral/node_modules/meshcentral/meshdesktopmultiplex.js` |
| `meshcentral-data/config.json` | `/opt/meshcentral/meshcentral-data/config.json` |

To track a new file: add an entry to `FILE_MAP` in `deploy-server.py`, then `deploy-server.py pull`.

### deploy-server.py Commands

Run from `C:\Users\Workstation\Documents\GitHub\MeshCentral`:

```bash
python deploy-server.py status               # Server version, service, tracked files
python deploy-server.py pull                  # Pull all tracked files from server to local
python deploy-server.py diff                  # Compare local vs server (hash + unified diff)
python deploy-server.py push                  # Push all changed files (backup + restart)
python deploy-server.py push --file <key>     # Push specific file only
python deploy-server.py push --dry-run        # Preview what would be pushed
python deploy-server.py update                # npm update meshcentral (backup + reapply customizations)
python deploy-server.py rollback              # Restore from server-backups/
python deploy-server.py config                # View config.json
python deploy-server.py config edit           # Edit config locally then push
python deploy-server.py logs 100              # Tail service journal
python deploy-server.py health                # Full health check
python deploy-server.py ssh "command"         # Run arbitrary remote command
python deploy-server.py vscode                # Open VS Code Remote-SSH to /opt/meshcentral
```

### Server Code Workflows

**Edit a view or module:**
```
1. python deploy-server.py pull           # Get latest from server
2. Edit files in meshcentral-server/      # Make changes locally (or in VS Code)
3. python deploy-server.py diff           # Review changes
4. python deploy-server.py push           # Backup, push, restart
5. python deploy-server.py health         # Verify
```

**npm update MeshCentral:**
```
1. python deploy-server.py update         # Backs up, stops, npm update, reapplies customizations, starts
2. python deploy-server.py health         # Verify
3. python deploy-server.py pull           # Pull any new stock files you may want to track
```

**Edit directly on server via VS Code:**
```
1. python deploy-server.py vscode         # Opens VS Code Remote-SSH to /opt/meshcentral
2. Edit files directly on server
3. Restart: ssh meshcentral "systemctl restart meshcentral"
4. python deploy-server.py pull           # Sync changes back to local working copy
```

### Server Backups (Code)

- Stored at `/opt/meshcentral/server-backups/YYYYMMDD_HHMMSS/`
- Created automatically before every `push` and `update`
- npm update backups prefixed with `npm-update-`
- Config edits create timestamped `.bak` files alongside `config.json`

### VS Code Remote-SSH

- Extension installed: `ms-vscode-remote.remote-ssh`
- SSH config alias `meshcentral` in `~/.ssh/config`
- Launch: `python deploy-server.py vscode` or `code --remote ssh-remote+meshcentral /opt/meshcentral`
- Edit server files directly with full IntelliSense, terminal, and git

### GitHub CLI

| Location | Account | Status |
|---|---|---|
| **Local (Windows)** | `hira-edu` | Authenticated via `gh auth login --web` |
| **Server (Linux)** | `hira-edu` | Authenticated, git credential helper configured |

Git protocol: HTTPS on both. Credential helper: `gh auth git-credential`.

## Key Server Configuration Notes

Verified from the sanitized 2026-07-26 live capture:

| Setting | Value | Purpose |
|---|---|---|
| `settings.cert` | `high.support` | Current domain-certificate identity for already deployed agents |
| `domains[""].certurl` | `https://high.support/` | Current domain certificate-hash source during migration |
| `ignoreAgentHashCheck` | `false` | Preserve fail-closed agent certificate authentication |
| `tlsOffload` | `127.0.0.1,::1` | Accept TLS only from the local edge proxy |
| `port` | `4430` | Internal loopback MeshCentral listener |
| `aliasPort` | `443` | Public standard-port alias |
| `agentPortTls` | `false` | Caddy terminates public TLS |

The live Caddy instance still exposes legacy `4445`/`4446` listeners for already deployed packages. They are migration compatibility state, not candidate provisioning endpoints. The deploy candidate has one standard-port endpoint only; retire the legacy listeners only after observed agent migration is complete.

## Backup and Recovery

- Backups are stored at `/opt/meshcentral/backups/YYYYMMDD_HHMMSS/`
- Each backup contains copies from both `signedagents/` and `agents/`
- Automatic backups created before every deploy
- Server-side auto-backup of full MeshCentral data runs every 24h to `/var/meshcentral-backups/` (14-day retention)

## Health Check Targets

During the overlap migration, the `health` command validates:
- `meshcentral` systemd service is `active`
- the internal `4430`, public `443`, and compatibility `4445`/`4446` listeners are present
- Node process is running
- MongoDB is reachable
- Disk usage is healthy
- No recent error-level journal entries

The compatibility-listener checks remain required until observed inventory proves the old cohort has migrated. Listener health alone does not prove agent authentication. Before publication, a candidate must also complete the MeshCentral agent certificate-hash handshake and a real relay open/close cycle.

## Security Notes

- SSH key (`id_ed25519`) has no passphrase — protect the workstation
- Do not duplicate SSH, TURN, database, signing, or certificate private-key credentials in this repository
- `dbEncryptKey` and `dbRecordsEncryptKey` are configured in config.json
- The direct `agents.high.support` edge presents a publicly trusted certificate; MeshCentral agent hash admission is a separate check and must remain enabled
- TURN credentials remain server-side configuration and must be treated as secrets
