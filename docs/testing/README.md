# Testing

This repository validates MeshAgent in layers, from source-only static checks up
to full install/update/uninstall exercises on an approved Windows host. Run the
smallest relevant layer for a change, then widen to broader regression when the
risk warrants it.

## Coordinated release automation

Run `python -m unittest discover -s test -p 'ci_release*_test.py' -v` for isolated
promotion/rollback fault tests, input validation, stale sibling-commit rejection,
and real disposable Git synchronization tests. The tests do not call Docker,
systemd, SSH, or production endpoints. Linux is needed to exercise real POSIX
permissions and directory fsync; Windows fixtures stub only POSIX-only APIs.

Validate hook/coordinated-release.yml and the public repository dispatch workflows with
`actionlint`. The release workflow also aggregates the Windows matrix and runs
both release bundle gates, including the configured branding signing policy,
before building its container. Its image smoke gate
boots and restarts the exact published digest using disposable configuration,
an isolated local listener, and a read-only image filesystem. This integration
gate requires Docker and does not use the production database or certificates.
Production promotion additionally verifies the selected image is running and
the configured public HTTPS `health.ashx` response is exactly `ok`.

## Test layers

### Static Node contracts

Source-only checks that read the tracked C, JavaScript, Python, JSON, and header
surfaces and assert invariants without building. They generally follow
`test/*_contract.js` and run with `node test/<name>_contract.js`. They are the
fastest gate and do not require built binaries.

`node test/meshcentral_core_module_parity_contract.js` requires every sibling
MeshCentral `agents/modules_meshcore*` copy with an agent counterpart to match
`modules/` exactly. The server's undated copies replace modules that an agent
build does not embed or embeds undated. Clipboard is the listed exception: its
server copy must not use `MeshClipboardBridgeW`, which those builds lack.

### Runtime probes

Behavioral probes that require built files and exercise the agent at runtime.
They generally follow `test/*_runtime.js` and must be run after a build so the
binaries they load are present.

`python3 test/network_policy_branding_native.py` runs the production firewall
label migration and WFP identity checks with in-memory COM/WFP stores and
sanitizers. It checks unrelated duplicate labels, rename/enumeration failures,
idempotent migration, all four WFP filter names, app-ID checks, long service
names, foreign-only uninstall labels, unreadable rules, case-insensitive WFP
labels, and mixed ownership: owned rules sharing a foreign label are moved to a
unique label before removal, and a failed move or removal restores the label.
With MinGW it also compiles these helpers against Windows headers.
`wfp_failure_telemetry_native.py` verifies that every failed replacement stage
retains the previous WFP policy, that uninstall still removes it, and that a
failed label rename still runs the firewall check and repair.
`runtime_host_installed_runtime_paths_runtime.js` also executes all three sibling
MeshCentral parser variants and requires source parity with the embedded module.
`runtime_host_service_host_native.py`, `service_binding_transaction_native.py`,
and `service_transaction_journal_native.py` cover branded group derivation,
legacy membership cleanup, stop-only admission of historical scoped groups,
rollback and checkpoint compatibility without changing installed services.

`test/native_terminal_lifecycle_native.py` compiles the production terminal
dispatcher with injected lifecycle failures and verifies quiet output through
real CRT and Windows handles. `test/native_terminal_uninstall_native.py`
exercises locked retirement, hard-link identity, filesystem residue, service
group residue, and deletion-scheduling faults using temporary files. Both
require Windows headers and `clang` (or `CC`); neither changes Windows services
or registers reboot deletions.

`test/windows_certificate_identity_native.py` executes the production certificate
loader against real signed X509 and PKCS12 fixtures, covering renamed subjects,
older databases, missing private keys, and corrupt or mismatched identities.
`test/windows_certificate_store_native.py` exercises read-only lookup and TLS
renewal against a real disposable CNG key in the current user's certificate
store, including legacy CAPI exchange and signature keys. It verifies exported
private keys, unique temporary containers, allocation cleanup, and export
failures. It uses unique fixture container names and removes its certificates and
keys afterward. These probes require Windows, Clang, and the bundled OpenSSL
library; they do not modify the installed agent's identity.

`test/windows_certificate_startup_native.py` injects load and generation
failures into the production startup block and verifies failure exit codes and
explicit identity reset. `test/windows_lifecycle_identity_native.py` checks
datastores that store their private identity as PKCS12 without a separate
NodeID record. `test/native_service_name_binding_native.py` and
`test/historical_service_discovery_native.py` cover renamed SCM keys,
standalone `-run` bindings, historical callback DLLs, quoted and unquoted
paths, and rejected loader or argument impersonation.

`test/service_legacy_host_native.py` exercises copied-host command parsing and
real embedded/catalog trust, including tampered images, wrong Windows binaries
and junction traversal. `test/service_legacy_process_native.py` fault-injects
read-only process admission: shared PIDs, wrong images, process exit, state races,
query failures and handle cleanup. Neither probe changes installed services.

`test/service_transaction_state_dacl_native.py` checks current and historical
state ACL admission using real Windows security descriptors, including trusted
ownership, exact grants, inheritance and access failures.

`test/service_recovery_state_native.py` uses real temporary files to cover
historical filenames and recovery keys, suspension progress and retry, ambiguous
files, BOM encodings, conflicting aliases, truncated names and read errors.
`test/meshcentral_legacy_bootstrap_runtime.js`
uses mocked transport/native APIs to check staging, identity, hash and ACL
refusals and bounded, correlated process launch; it does not exercise an endpoint.

`test/historical_install_paths_native.py` uses temporary files and a built
DLL/EXE pair to verify incumbent selection, ambiguous identities, resource
matching, deletion faults, retained identity proof, and bounded cleanup. It
injects SCM and datastore observations and does not modify services.
It also covers identical backup copies, multiple optional companion EXEs, and
same-directory migration retirement using journaled ownership paths.
These filesystem probes require an x64 C compiler on Windows.

`test/service_update_recovery_native.py` fault-injects update and crash
recovery orchestration, including database migration at the original path,
the NodeID gate for existing databases, and recovery that records no update
hold. `test/service_update_recovery_policy_native.py` checks bounded delegated
recovery and restart retries, failure reporting, and transaction-directory
trust checks without changing real services or permissions.
`test/service_transaction_journal_native.py` checks that a checkpoint
without incumbent paths keeps the version 1 layout. The binding, transaction
journal, transaction recovery, and update recovery native probes also run on
macOS with Clang and sanitizers.
`test/service_stop_native.py` runs the production service-stop loop against a
deterministic SCM and clock. It covers pending states, deadlines and tick
wraparound, stop retries, status-query faults, process-ownership checks and
termination faults without touching any real service. It runs on macOS with
Clang and sanitizers, and when MinGW is installed it also compiles the loop
against the real Windows status structures.
`test/service_startup_control_native.py` extracts the production startup-control
transition and races it against accepted stop requests. It verifies that an
early stop remains latched and cannot be overwritten by `SERVICE_RUNNING`.

`python3 test/native_runtime_controller_native.py` compiles the relay request
parser (UUID and operation mapping) under ASan/UBSan. Its source contract checks
that the MeshAgent binding launches controllers directly inside a kill-on-close
job object, fails closed on a startup install error or missing job, reports a
crashed controller distinctly, never installs or hashes images while handling a
request, and contains no controller pipe, supervisor, policy, or target state.
`python3 test/runtime_component_packaging_contract.py` checks PE/catalog
validation and architecture-specific controller-executable staging.

`test/service_deployment_copy_native.py` injects copy, flush, attribute, and
rename failures into production replacement code and checks that live files
survive. It also covers DLL-only provisioning and dotted parent directories.
`test/datastore_readonly_native.py` reads real NG and legacy datastore fixtures
and verifies that discovery never alters their bytes or creates missing files.
`test/datastore_persistence_native.py` covers flush failures, read-only and
cache-only rejection, and failed plain/compressed record deletion. These probes
use Clang with ASan/UBSan; the datastore probes run on POSIX hosts and the
read-only probe needs OpenSSL (`OPENSSL_ROOT` can select its installation).

`node test/installer_compatibility_runtime.js` and
`node test/update_packaging_runtime.js` exercise installer compatibility and
update packaging using injected platform observations and temporary packaging
files. They do not change live services.

`test/historical_migration_runtime.js` performs destructive endpoint migration
on an elevated, explicitly approved disposable Windows host. Supply
`--approved-host`, `--fixture-repo <separate-built-historical-checkout>`, and
`--evidence <ignored-output-directory>`; `--grouped` also runs the full local
lifecycle regression. The fixture must have a different service key and
installation directory. The runner checks raw update, NodeID preservation,
native validation, quiet output, and uninstall, then reinstalls a saved copy
of the published baseline. Identity deletion requires the operator's approval;
Windows elevation is still required.

Windows inventory and bridge checks that do not install an agent:

```powershell
node test/windows_inventory_runtime.js
node test/meshcentral_inventory_runtime.js
node test/windows_terminal_failure_runtime.js
node test/windows_clipboard_bridge_runtime.js
node test/meshcentral_clipboard_runtime.js
python3 test/windows_clipboard_native.py
python3 test/windows_clipboard_agent_runtime.py --agent /absolute/path/to/built/meshagent
python test/meshcentral_module_versions_runtime.py
python test/process_pipe_lifetime_runtime.py
python test/process_pipe_write_runtime.py
python test/chain_write_runtime.py
python test/chain_wait_dispatch_runtime.py
python3 test/embed_modules_runtime.py
python3 test/deploy_macos_profile_runtime.py --agent ./meshagent_osx-arm-64
python test/process_pipe_windows_runtime.py
```

The inventory test covers both pointer widths, denied process access, WCHAR
bounds, process details, token and registry key cleanup, and SCM pagination.
The MeshCentral inventory test executes the normal and minified core handlers
to check valid replies, access errors, service-detail cleanup, and service-detail
fallthrough. The terminal test
checks failures before listeners attach and before the ready handshake. The
clipboard dispatch fixture covers helper reuse, adjacent read coalescing, ordered
writes, Unicode and empty values, queue/session limits, failed-start backoff,
malformed replies, stderr errors, throwing consumers, denied/delayed termination
and timeout cleanup, first-request and steady-state timeouts, and idle
retirement. Its injected `clearTimeout` throws for fired timers, as Duktape's
does. It also fails when the clipboard module embedded in
`microscript/ILibDuktape_Polyfills.c` differs from `modules/clipboard.js`. It
injects child processes and timers and runs on any Node host without accessing a
clipboard. The MeshCentral fixture executes both core variants' message and console
clipboard cases, including synchronous and asynchronous failures, silent read
failures, empty and non-text reads for each viewer tag, and completion
acknowledgements. The
native Python probe executes the production Win32 clipboard ownership/cleanup
logic, write-only message-window lifetime, over-allocated reads, helper launch
validation and logon identity changes with injected API failures under ASan/UBSan.
When MinGW is available it also cross-compiles the complete native bridge against
Windows headers with warnings treated as errors. The built-agent probe runs the
production module with injected Windows dependencies and real Duktape promises,
buffers and timers (delays scaled down); it verifies independent read subscribers,
UTF-8 surrogate pairs, empty writes, rejection containment, timeout and idle
cleanup on fired timers and consumer exception isolation on any platform. The core generation test
verifies explicit module versions,
one registration per module across minification modes and file ordering, and
source preservation. The pipe test exercises extracted production state machines
with sanitizers; it also sets the Windows sanitizer runtime search path.
The write probes cover partial completions, delayed cancellation, off-thread and
reentrant close, reentrant writes, EOF ordering, invalid byte counts, event
and allocation exhaustion, process detachment before deferred free, and the generic chain writer's state ownership.
`test/kvm_bridge_wait_handle_contract.js` also requires `waitExit()` to compact
its wait list, because the chain stops at the first NULL and stdin has no write
event before its first write, and requires process-pipe registrations to pass
static metadata instead of the allocating `ILibChain_AddWaitHandle` macro.
The write probes also cover the 64 MiB stdin queue bound and its accounting, and
writes whose completion wait failed: they are retired after a confirmed
cancellation and otherwise stay pinned. The chain writer probe checks that a
reissued partial file write continues at the right file offset and that callers
get their base offset back. `test/chain_wait_dispatch_runtime.py` runs the
production TIMEOUT/INVALID_HANDLE dispatch under ASan, including handlers that
remove their own registration, which previously freed a node the chain then
removed again. The Windows pipe
probe compiles the production transport against real handles and starts only
its own disposable reader children. On Windows it runs 30 drain, cancellation
and child-crash rounds; on other hosts it cross-compiles and explicitly skips
execution. The portable write probe also cross-compiles the full process-pipe
translation unit when MinGW is available. Neither replaces a service-DLL build
or the installed-service integration gate.
After building, `node test/windows_inventory_runtime.js --native` additionally
queries real Windows processes and services three times, checks handle counts,
and verifies ISO module version replacement in Duktape. Its query-only console
does not start a desktop notification message pump.
`node test/meshcentral_inventory_runtime.js --native` makes 20 read-only service
detail requests through the core handler and checks that handle counts stay stable.
`node test/windows_terminal_failure_runtime.js --native` exercises actual Duktape
Duplex/pipe cleanup for invalid service paths and rejected launches.

The elevated terminal smoke probes are `meshconsole_bridge_exec_smoke.js`,
`meshconsole_bridge_terminal_smoke.js`, and `win_terminal_wrapper_exec_smoke.js`.
After a Windows package build, validate clipboard reads, empty/Unicode writes,
repeated KVM polling, user-session changes, helper idle retirement and agent
termination cleanup through the installed service on an authorized test endpoint.
Include blocked stdin writes, simultaneous timeout/helper exit, denied kill,
logoff/relogin with session reuse and forced broker termination.
These portable fixtures do not prove a live WTS session transition, pipe ACL,
job teardown or remote desktop integration. The installed DLL, server clipboard
module and both core variants must be updated together. An ordinary elevated
administrator is expected to fail closed at `WTSQueryUserToken` with error 1314;
the cross-session integration check must run through the service identity.

`node test/desktop_audio_bridge_contract.js` is the source-only gate for the
native desktop-audio loopback helper (`MeshAudioBridgeW`). It asserts the helper
is registered on the same runtime-host surface as the clipboard bridge (export
declaration, `meshservice/audio_bridge.h` include, both architecture `.def`
files, and the entry-name constants), that `microstack/ILibProcessPipe.c` defines
and consults `ILibProcessPipe_IsApprovedAudioBridgeLaunchA` for only the
agent-reachable `local`/`tsid=` launch forms, that the packet framing constants
and the CONFIG payload match the shared audio spec, that the capture path is
WASAPI shared-mode loopback with libopus and an `IMMNotificationClient`
default-device re-init, that the broker/user split carries a kill-on-close job
object, and that the helper never writes audio to disk or logs it. It also guards
that `meshcore/KVM/**`, `meshcore/agentcore.c`, `meshcore/meshdefines.h` and
`meshservice/ServiceMain.c` remain free of audio-helper edits. The new export is
also covered by `service_host_exports_contract.js` and
`runtime_host_all_helpers_migration_contract.js`. After a Windows package build,
`node test/desktop_audio_bridge_runtime.js <ServiceDll> <evidence-dir>` launches
the built DLL in `local` mode on an authorized interactive desktop, parses the
stdout packet stream, and validates the CONFIG handshake, header invariants,
AUDIO/SILENCE cadence and a clean shutdown on stdin EOF; captured audio is parsed
for structure only and discarded. It skips cleanly on non-Windows hosts.

The agent-side `desktop-audio` module is covered by
`node test/desktop_audio_module_contract.js`, a source-only contract that checks
the module launches `MeshAudioBridgeW tsid=<sessionId>` through the system
rundll32, parses and validates the framed packet stream, refcounts one helper per
tsid, enforces the global helper cap and the failed-start backoff, and stays fail
closed on malformed frames; and by `node test/desktop_audio_module_runtime.js`,
which runs the module under a Node `vm` with injected child processes, pipes and
timers to exercise packet delivery, status and close events, backpressure drops
and helper teardown on any platform without launching a Windows process.

`python test/connection_failure_telemetry_native.py` runs the production receive
and diagnostic functions against disposable Windows loopback TCP sockets. It
checks reset-versus-EOF classification, quiet successful/would-block reads,
intentional shutdown suppression, first-error retention through cleanup, and
connection reuse guards. TLS diagnostic snapshots are injected; this probe does
not exercise a live TLS handshake or relay. It requires Clang and Windows SDK
headers and does not start or modify an installed service.

`python3 test/asyncsocket_tls_error_queue_native.py` runs the production TLS
receive and queued-write functions with real OpenSSL memory-BIO peers and local
socket pairs. It checks that a fatal alert on another connection cannot turn
healthy reads, partial handshakes, or queued writes into fatal errors, including
an error left by a buffer-reallocation callback between reads. Corrupt
records and real peer alerts must still disconnect with their own diagnostics;
clean TLS shutdown remains a quiet EOF. The probe uses ASan/UBSan and the bundled
OpenSSL libraries on macOS and Windows x64 (using loopback TCP instead of Unix
socket pairs). It also checks the TLS version and decoded failure reason in the
production diagnostics. Other POSIX hosts can specify `--openssl-include`
and `--openssl-lib-dir`. Evidence goes under `artifacts/validation/`.

`python test/asyncsocket_tls_send_native.py` exercises the production TLS send
and PostSelect write paths with real TLS 1.2/1.3 memory peers on Windows x64.
Injected socket acceptance covers short writes, zero-byte writes, would-block,
buffer exhaustion, interrupted calls, and fatal resets. Multi-buffer sends and
immediate caller-buffer reuse must deliver every plaintext byte in order with
correct ciphertext accounting. The probe uses Clang ASan/UBSan and the bundled
OpenSSL libraries; it does not run an installed agent or use a remote endpoint.

`python test/wfp_failure_telemetry_native.py` injects WFP failures at each
transaction stage and clobbers last-error during cleanup and logging. It checks
original status retention, stage/filter identification, and transaction cleanup.
It also exercises production firewall reconciliation with healthy rules,
ordinary-rule drift, and invalid WFP rules that cannot be removed. Valid WFP
rules must survive reuse without hiding unrelated repair failures. A second
fixture runs the production removal paths against a reference-counting WFP model
to check that legacy `svchost.exe` filters are deleted and that an unknown
filter still aborts the transaction. The probe does not change firewall rules. It uses Clang ASan/UBSan on Windows or POSIX;
when MinGW is available on POSIX it also compiles against Windows headers.

`python3 test/native_update_state_runtime.py` compiles production update
functions with process, datastore, and file-I/O mocks. It checks durable force
consumption, interrupted consumption, late activation completion, transfer
ownership, and partial-write/flush/close failures. It requires Clang and runs
with ASan/UBSan on POSIX; it never launches an updater or modifies a service.

`python3 test/update_readiness_backoff_native.py` compiles the production
Windows update readiness and retry-backoff functions against mutex, clock,
datastore, timer and control-channel fakes. It covers each deferral reason, the
per-package attempt record and its wait, malformed records, forced updates, the
failed-package status for capable and older servers, and the single intentional
reconnect after a deferral or wait clears. It requires Clang and runs
with ASan/UBSan on POSIX.

`python3 test/native_update_hash_portable.py` compiles the production Windows
normalized-hash reader against OpenSSL. Its disposable fixtures cover raw
files, signed PE32/PE32+ images, appended provisioning, malformed offsets,
header lengths, and normalized versus historical whole-file transfer hashes.
It requires Clang and OpenSSL development headers/libraries
(Homebrew OpenSSL 3 is detected on Apple Silicon) and uses ASan/UBSan.

### Grouped regression

`test/run_grouped_regression.js` performs a local install/update/uninstall cycle
and requires an elevated, approved Windows test host. Do not run it on a host
that is not approved for destructive service lifecycle operations.
Use the same wrapper for both native architectures; the ARM64 run must execute
on an approved native ARM64 Windows host:

```powershell
.\tools\Invoke-RuntimeValidation.ps1 -Architecture x64
.\tools\Invoke-RuntimeValidation.ps1 -Architecture ARM64
```

The wrapper checks the matching MeshCentral server payload
(`MeshService64.exe` or `MeshServiceARM64.exe`) before it starts the grouped
lifecycle suite. It also fails before any lifecycle mutation unless the native
Windows host architecture matches the selected package. `test.ps1
-RuntimeArchitecture ARM64 -RuntimeValidation` is the equivalent lower-level
selector when inputs are supplied directly and applies the same host check.
By default, `test.ps1` inspects only the selected architecture. Use `-FullRelease`
to require all three Windows executables. Authenticated server downloads request
agent type 4 for x64 and 43 for ARM64.

Build the matching `MeshConsole-2022.vcxproj` `Release` configuration before
grouped regression. The suite validates the EXE, DLL, and console PE machines
before changing services, then passes those binaries to its HTTP, bridge, KVM,
and embedding probes. Direct callers can override the console with
`--source-console <path>`.

When runtime validation is enabled in hook's `coordinated-release.yml`, the workflow runs
the same gate as separate x64 and ARM64 jobs; the ARM64 leg uses the native
`windows-11-arm` runner rather than treating cross-compilation as runtime proof.
CI builds the matching console, installs the .NET 10 GUI harness SDK, and checks
out the exact MeshCentral and runtime commits frozen by the release coordinator
beside MeshAgent. Runtime validation requires the
deployment input secrets described in `docs/DEPLOYMENT.md`, a control URL, and
a mesh ID; missing prerequisites fail the job.
Fresh installation after uninstall generates a new endpoint identity. A backup
of the `.db` alone cannot restore an identity backed by a Windows CNG key;
identity-preserving recovery also requires the corresponding certificate and
private key. Use a disposable endpoint for this regression.
Its native CLI phase invokes the actual `-install`, `-update --quiet`, and
`-uninstall -silent` EXE commands, checks output suppression and NodeID
preservation, and validates the resulting service through lifecycle callbacks.
It also checks installed-image and hard-link update refusals, raw binary
updates, the EXE's `-fullupdate` ingress, and installed-image uninstall with
retirement of the running executable.
An install command failure fails the phase even if the old service is healthy.

### UMH Playwright

`test/run_umh_playwright.js` covers the desktop and mobile UMH fixtures.

### Viewer pointer input

These checks read the sibling `../MeshCentral` checkout and its installed
`node_modules/meshcentral`.

- `test/meshcentral_desktop_pointer_baseline_runtime.js` runs the fork's
  `agent-desktop-0.0.2.js` and `-min.js` in a Node VM. It drives desktop mouse
  input, plus the touch and trackpad handlers sliced from the pinned upstream
  `default3` and `default-mobile` views, with a fake DOM and clock. It compares
  every mouse packet with the recorded traces, including known defects that must
  not change by accident.
- `test/meshcentral_trackpad_default3_coupling_contract.js` and
  `test/meshcentral_trackpad_default_mobile_coupling_contract.js` pin the view
  globals, element ids, canvas markups, lifecycle hooks and detection markers the
  trackpad adapters depend on.
- `test/meshcentral_viewer_min_build_contract.js` requires the served
  `agent-desktop-0.0.2-min.js` to equal the output of
  `../MeshCentral/scripts/build-viewer-min.js`.
- `test/meshcentral_trackpad_engine_runtime.js` drives the DOM-free trackpad
  gesture engine (`public/scripts/agent-desktop-trackpad-0.0.1.js`) with a fake
  clock. It has one table test per gesture and disambiguation rule, timing and
  slop edges, finger-count transitions, malformed touch lists, unusable geometry,
  re-entrant callbacks, and cancellation in every state. Its randomized run
  (100,000 sequences by default; `--runs` changes it) requires every press to be
  released, one button to change at a time, integer on-screen coordinates, and
  nothing to happen after a reset.
- `test/meshcentral_desktop_remote_pointer_runtime.js` checks the viewer's
  remote-pixel pointer API (`SendRemotePointer`, `SendRemoteWheel`,
  `ReleaseAllPointerButtons`, `GetRemoteGeometry`) packet by packet on both
  assets, and drives it from the trackpad engine end to end.
- `test/meshcentral_trackpad_adapter_runtime.js` runs the trackpad controller and
  both view adapters in Chromium (real multi-touch through CDP) and WebKit.
  The fixtures use each pinned view's exact canvas markup and its own touch,
  mouse and trackpad code, with the real `agent-desktop` module recording
  packets. The test checks that:
  - with the flag off, or trackpad mode off, handler calls and packets are
    identical to a page without the controller;
  - with trackpad mode on, no page handler or compatibility click runs;
  - enabling sends one move to the visible centre;
  - the overlay tracks the remote pointer;
  - turning trackpad off, Input off, or hiding the page mid-drag releases the
    button;
  - a replaced canvas is still owned;
  - native-zoom pinch and follow-scrolling work;
  - a rotated view moves along the remote axes;
  - an Intel AMT desktop (no remote-pixel API) stays with the page;
  - a dialog, a rights change or a disconnect that arrives without a click
    releases a held button within the watchdog period;
  - blur, touchcancel, a new SCREEN or the connection going down mid-drag
    releases;
  - enabling before the first frame sends the remote centre;
  - turning trackpad on stops the page's edge-scroll interval;
  - a WebRTC module switch releases on the old module;
  - a pinch keeps its landing point on a scrolled page;
  - uninstall removes every listener it added.
- `test/meshcentral_trackpad_loader_runtime.js` runs the trackpad loader block of
  `custom.js` on the fixture pages, served from a routed origin, in Chromium and
  WebKit. It checks that:
  - with the flag off nothing is loaded or registered;
  - `?trackpadengine=on|off|default` sets the per-browser flag for each page kind;
  - the engine, controller and adapter load in order and install;
  - a module created later reports its state: a real disconnect deactivates and
    hides the overlay; a WebRTC soft desktop coming up mid-drag releases on the
    old module and places the pointer once it knows its screen; another desktop
    module's state changes do not reach the controller;
  - the guest share page, which has no trackpad mode, loads nothing;
  - a failed script load leaves trackpad mode to the page and stops observing
    new modules.
- `test/meshcentral_multiplex_button_release_runtime.js` drives the real desktop
  multiplexer. It checks that a departing viewer's held buttons are released at
  its last position, unless another viewer holds them, and that view-only,
  double-click and wheel packets are not counted as presses. It also checks that
  the release still reaches a busy agent before it is closed, and that nothing
  is sent to an agent that is going away.
- `test/meshcentral_trackpad_licence_contract.js` keeps the Apache Guacamole and
  Chromium attribution in the engine header and in `THIRD_PARTY_NOTICES.txt`.

The baseline and both contracts are pinned to one MeshCentral version and fail
when another version is installed. To upgrade:
1. Review the upstream view changes.
2. Rerun the baseline with `--print`.
3. Update its traces and the pinned version.
4. Adjust the contracts.

`test/meshcentral_viewer_touch_harness_runtime.js` checks the browser event
ordering the adapters rely on:
- in Chromium with CDP multi-touch;
- in WebKit with dispatched touch-typed events (desktop WebKit has no `Touch`
  constructor), which cover DOM dispatch order but not WebKit's tap-to-mouse
  conversion.

It uses the Playwright version pinned in `test/package.json`. Set it up with
`npm ci --prefix test`, then `npx --prefix test playwright install chromium webkit`.

### Release gates

`test/release_signing_bundle_gate.js` and `test/release_bundle_gate.js` are the
release gates. They check the signed bundle and the release bundle, including the
presence of the required documentation under `docs/` (`docs/README.md`,
`docs/CONFIGURATION.md`, `docs/DEPLOYMENT.md`, and `docs/testing/README.md`).
Both read built service binaries under `meshservice/x64/` and
`meshservice/ARM64/`, verify their PE machine types, and require both native
service DLLs, so build first; the signing gate also reads
`branding_config.local.json` and stages the Win32 runtime executable. Release packages contain provisioning manifests and binaries;
endpoint identity databases are excluded.

## Builds before binary-reading tests

Runtime probes and any contract that reads built binaries need a current build
first. In particular, `test/service_bundle_embedding_contract.js` reads the
built x64 and ARM64 service binaries and verifies that each embeds its matching
native service DLL, so build the package before running it; otherwise it has
nothing valid to read. Automation migrating from the original evidence fields can invoke the
same neutral entry point with `--legacy-evidence-schema`; this emits the exact
three-field compatibility schema while retaining the neutral script and evidence
filenames.

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

## Native Windows Files validation

After building, run `node test/file_execution_actions_contract.js`,
`python test/native_file_actions_runtime.py`, and
`python test/native_file_actions_binding_runtime.py`. The native probes use
isolated files, a harmless executable, and temporary per-user file associations.
They cover token selection, real launches, Unicode paths, recursive deletion,
locked files, root rejection, and junction target preservation. The binding
probe changes only disposable executable copies to an `asInvoker` manifest to
exercise the console-user branch; production manifests stay unchanged.

`npx playwright test test/playwright/native_files_actions.spec.js --config
playwright.config.js` validates Files button requests and result/error display.

## Generated reports

`node test/meshcentral_historical_certificate_runtime.js` executes the tracked
server authentication request and signature verifier with real RSA signatures.
It checks current and explicitly pinned historical web certificates, rejection
of unknown/malformed/zero pins and invalid proofs, domain isolation, and replay
guards. `meshcentral_certificate_admission_runtime.js` verifies a live signed
server proof without enrolling a device or sending remote commands.

`python test/unified_failure_telemetry_native.py --cc <clang-path>` validates
the production Windows log writer with concurrent disposable processes,
in-place retention, UTF-16 conversion, write/lock failure, error preservation,
bounded helper packets, and no post-uninstall directory recreation. It uses a private HKCU key to
exercise clean exit, failed startup, injected exception/heap-status records,
and an externally terminated probe child. Exception metadata is injected;
this is not a real heap-corruption or Windows Error Reporting integration test.
It does not install, stop, or alter the real endpoint service. Reports go to
`artifacts/validation/unified-failure-telemetry/` by default.

Store generated validation reports outside tracked documentation, normally under
`artifacts/validation/`. Do not check in dated planning files, status ledgers, or
runtime evidence.

## macOS lifecycle and remote desktop checks

Mac lifecycle and session probes:

```sh
node test/macos_install_runtime.js
python3 test/macos_install_agent_runtime.py --agent /absolute/path/to/built/meshagent
node test/macos_sessions_runtime.js
python3 test/macos_sessions_agent_runtime.py --agent /absolute/path/to/built/meshagent
node test/macos_kvm_relay_contract.js
python3 test/macos_kvm_io_native.py
python3 test/macos_kvm_protocol_native.py
python3 test/macos_kvm_mainloop_native.py
python3 test/macos_kvm_session_native.py --agent /absolute/path/to/built/meshagent
python3 test/macos_kvm_provision_native.py --agent /absolute/path/to/built/meshagent
node test/macos_kvm_setup_runtime.js
python3 test/macos_vnc_relay_native.py
python3 test/macos_helper_framing_runtime.py --agent /absolute/path/to/built/meshagent
node test/macos_message_helper_runtime.js
python3 test/macos_message_helper_agent_runtime.py --agent /absolute/path/to/built/meshagent
python3 test/js_timer_retention_runtime.py --agent /absolute/path/to/built/meshagent
python3 test/posix_fs_modes_agent_runtime.py --agent /absolute/path/to/built/meshagent
```

Installation probes redirect `/Library` writes into temporary directories and
verify publication order, handled-failure cleanup, private file modes and retained
provisioning. The Node fixture also runs the uninstall flow to check that a
reinstall keeps the Screen Sharing relay credential and a completed uninstall
removes it. The fixture injects launchctl state; these tests do not prove a
live root install/uninstall or reboot. Session probes cover console selection,
account lookup failures, literal arguments, signed legacy IDs and Unicode home
paths; the built-agent probe performs read-only queries against the host.
The relay contract is a source guard: no native capture, input or privacy
permission API remains, one root helper is spawned without a session hop, the
helper checks the credential and port owner before authenticating, the relay
connects to loopback only, and installation creates no KVM LaunchAgent.
The KVM I/O probe runs the production input loop and writer with fault-injected
I/O under ASan/UBSan, including packet splits, interrupted calls and short writes.
The protocol probe drives the helper-pipe output handler the way the process pipe
does, across every split and with invalid frames. The main-loop probe runs the
production session loop against a scripted relay and checks that the resolution
precedes tiles, nothing is sent before the first frame, missing first frames
produce a visible timeout, delayed first frames still work, refresh resends every
tile, pause holds an update, resize reallocates, and relay, viewer and pipe
failures end the session with the right message. These probes do not capture a
screen or inject desktop input.
The VNC relay probe compiles the Screen Sharing relay client under ASan/UBSan
and drives it against a scripted loopback RFB server: 3.8 and Apple 3.889
handshakes, None and VNC authentication, Raw/CopyRect/DesktopSize updates,
fail-closed handling of unnegotiated encodings, out-of-bounds rectangles,
disconnects and stalls, and the key/pointer wire format. It does not contact the
real Screen Sharing service.

The session native probe exercises console selection with injected CoreFoundation
preference calls: missing/false/invalid values are set to a system-wide boolean,
an existing true value needs no write, and load, save or readback failures prevent
authentication. It does not change real Screen Sharing preferences. Its session
fixture verifies selection runs after credential and listener checks and before
the RFB handshake. A live regression check must start from an unlocked Mac and
confirm the viewer shows the same current desktop; when the physical console is
locked, the viewer should show that console's lock screen.

First-start setup probes run the production orchestration with injected UI and
private pipes and exercise native provisioning under ASan/UBSan with real
temporary files. They cover saved-credential reuse, boot before login, cancel,
invalid input, verified authentication before saving, exclusive root-only mode
0600 storage, unsafe incumbents, symlinks, failed-write cleanup and password
buffer cleanup. They do not show a real password dialog or contact Screen Sharing.
A live setup check should show one masked macOS dialog on first root-agent start,
save only an accepted password, and show no dialog after reconnect or restart.

The session native probe reads the relay credential from real temporary files,
with fstat reporting the current user as root, and covers content, length, modes,
hard links, symlinks, FIFOs and the parent directory. It checks port ownership
against injected process tables and against real libproc data for a temporary
listener owned by the current user. It also covers failure reasons in check order,
key, Unicode, mouse and control dispatch to the relay, the readiness check
(including authentication without an image and connection failure), the
root helper's launch arguments, and exit cleanup. With `--agent` it runs the
built `-kvm0` and `-kvmcheck` without root, which must report the root
requirement, and the legacy `-kvm1` switch, which must exit cleanly. It does not prove a live Screen Sharing session.
Validate that on a Mac set up as described in the deployment guide: run
`sudo <installed executable> -kvmcheck`, then a remote desktop session. Helper framing tests compare Node and native
wire bytes and exercise a real temporary Unix socket without starting GUI helpers.

The message-helper Node test runs the production parent/client code with real
private sockets and injected launchd/command execution. It covers authentication,
one reused helper per desktop user, serialized requests, shared concurrent
clipboard reads, idle removal, the retry delay after a failed start, removal of
helpers left by an earlier agent, cancellation, dialog outcomes, UTF-8 data and
file removal when unloading fails. The built-agent helper probe registers a
disposable Aqua LaunchAgent using the same binary, sends two unsupported requests
through one helper, and verifies launch, authentication, error delivery and
removal without accessing the clipboard or showing UI. Run it as the foreground
user, without sudo. `--child-logs` enables temporary startup diagnostics. It does
not prove root-to-user delivery or live UI behavior.

The timer probe runs the built agent on a script that drops the objects returned
by `setTimeout` in immediates, promise handlers, timers and top-level code, and
checks that every timeout fires, that a cleared one does not, and that intervals
behave as before.

The filesystem probe creates only temporary files, starts its child with umask
zero and checks initial modes, exclusive collisions, symlinks and invalid modes.

## macOS native update validation

Run these probes on a macOS development host:

```sh
python3 test/macos_certificate_identity_native.py
python3 test/posix_update_extraction_native.py
python3 test/macos_update_transaction_native.py
python3 test/macos_update_handoff_native.py
python3 test/macos_identity_startup_runtime.py --agent /absolute/path/to/built/meshagent
python3 test/compressed_update_runtime.py --console /absolute/path/to/built/meshagent --evidence artifacts/validation/macos-compressed-update
```

The certificate probe uses real OpenSSL PKCS12 identities. The transaction probe
injects file-operation failures and process crashes at persistent boundaries,
checking rollback, commit cleanup, lock contention and unrelated-file retention.
The hand-off probe executes the production orchestration against temporary
executables to check PID and argument preservation and failed-exec recovery.
The startup probe runs the built agent with damaged temporary identity records,
then verifies trial rollback and datastore lock release. These tests do not
install a system service or establish a server connection; service installation,
server-driven transfer/authentication, and live desktop/session features require
separate integration validation.
