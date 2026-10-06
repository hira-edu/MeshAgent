# Testing

This repository validates MeshAgent in layers, from source-only static checks up
to full install/update/uninstall exercises on an approved Windows host. Run the
smallest relevant layer for a change, then widen to broader regression when the
risk warrants it.

## Test layers

### Static Node contracts

Source-only checks that read the tracked C, JavaScript, Python, JSON, and header
surfaces and assert invariants without building. They generally follow
`test/*_contract.js` and run with `node test/<name>_contract.js`. They are the
fastest gate and do not require built binaries.

### Runtime probes

Behavioral probes that require built files and exercise the agent at runtime.
They generally follow `test/*_runtime.js` and must be run after a build so the
binaries they load are present.

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
hold. `test/service_transaction_journal_native.py` checks that a checkpoint
without incumbent paths keeps the version 1 layout. The binding, transaction
journal, transaction recovery, and update recovery native probes also run on
macOS with Clang and sanitizers.

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
python test/meshcentral_module_versions_runtime.py
python test/process_pipe_lifetime_runtime.py
```

The inventory test covers both pointer widths, denied process access, WCHAR
bounds, process details, token and registry key cleanup, and SCM pagination.
The MeshCentral inventory test executes the normal and minified core handlers
to check valid replies, access errors, service-detail cleanup, and service-detail
fallthrough. The terminal test
checks failures before listeners attach and before the ready handshake. The
clipboard test covers Unicode, empty values, command-safe writes, errors, and
timeout cleanup. The core generation test verifies explicit module versions,
one registration per module across minification modes and file ordering, and
source preservation. The pipe test exercises extracted production state machines
with sanitizers; it also sets the Windows sanitizer runtime search path.
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
The clipboard test's `--live-read --session <id>` mode reads without changing the
clipboard and prints only success and length. Run that mode under the service
identity: an ordinary elevated administrator is expected to fail closed at the
session-token boundary with error 1314.

`python test/connection_failure_telemetry_native.py` runs the production receive
and diagnostic functions against disposable Windows loopback TCP sockets. It
checks reset-versus-EOF classification, quiet successful/would-block reads,
intentional shutdown suppression, first-error retention through cleanup, and
connection reuse guards. TLS diagnostic snapshots are injected; this probe does
not exercise a live TLS handshake or relay. It requires Clang and Windows SDK
headers and does not start or modify an installed service.

`python3 test/native_update_state_runtime.py` compiles production update
functions with process, datastore, and file-I/O mocks. It checks durable force
consumption, interrupted consumption, late activation completion, transfer
ownership, and partial-write/flush/close failures. It requires Clang and runs
with ASan/UBSan on POSIX; it never launches an updater or modifies a service.

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

### Release gates

`test/release_signing_bundle_gate.js` and `test/release_bundle_gate.js` are the
release gates. They check the signed bundle and the release bundle, including the
presence of the required documentation under `docs/` (`docs/README.md`,
`docs/CONFIGURATION.md`, `docs/DEPLOYMENT.md`, and `docs/testing/README.md`).
Both read built service binaries under `meshservice/x64/`, so build first; the
signing gate also reads `branding_config.local.json` and stages the Win32
runtime executable. Release packages contain provisioning manifests and binaries;
endpoint identity databases are excluded.

## Builds before binary-reading tests

Runtime probes and any contract that reads built binaries need a current build
first. In particular, `test/service_bundle_embedded_payload_contract.js` reads
the built service binaries and their embedded payload, so build the package (or
at least the service-DLL gate) before running it; otherwise it has nothing valid
to read.

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

## macOS permission checks

Mac lifecycle and session probes:

```sh
node test/macos_install_runtime.js
python3 test/macos_install_agent_runtime.py --agent /absolute/path/to/built/meshagent
node test/macos_sessions_runtime.js
python3 test/macos_sessions_agent_runtime.py --agent /absolute/path/to/built/meshagent
python3 test/macos_kvm_io_native.py
python3 test/macos_kvm_session_native.py
python3 test/macos_helper_framing_runtime.py --agent /absolute/path/to/built/meshagent
node test/macos_message_helper_runtime.js
python3 test/macos_message_helper_agent_runtime.py --agent /absolute/path/to/built/meshagent
python3 test/posix_fs_modes_agent_runtime.py --agent /absolute/path/to/built/meshagent
python3 test/macos_hid_reports_native.py
```

Installation probes redirect `/Library` writes into temporary directories and
verify publication order, handled-failure cleanup, private file modes and retained
provisioning. The Node fixture injects launchctl state; these tests do not prove a
live root install/uninstall or reboot. Session probes cover console selection,
account lookup failures, literal arguments, signed legacy IDs and Unicode home
paths; the built-agent probe performs read-only queries against the host.
The KVM I/O probe runs the production input loop and writer with fault-injected
I/O under ASan/UBSan, including packet splits, interrupted calls and short writes.
It does not capture a screen or inject desktop input.

The session native probe checks production launch arguments, ordered credential
changes, console-switch rejection, failure cleanup and desktop-stream termination.
It injects the privileged credential operations and separately runs the real
initializer as the current user. Helper framing tests compare Node and native
wire bytes and exercise a real temporary Unix socket without starting GUI helpers.

The message-helper Node test runs the production parent/client code with real
private sockets and injected launchd/command execution. It covers authentication,
dialog outcomes, UTF-8 data, setup failures, expired timers and cleanup. The
built-agent helper probe registers a disposable Aqua LaunchAgent using the same
binary and sends an unsupported request; this verifies launch, authentication,
error delivery and removal without accessing the clipboard or showing UI.
Run it as the foreground user, without sudo. `--child-logs` enables temporary
startup diagnostics. It does not prove root-to-user delivery or live UI behavior.

The filesystem probe creates only temporary files, starts its child with umask
zero and checks initial modes, exclusive collisions, symlinks and invalid modes.
The HID report probe compiles production report encoding under ASan/UBSan with a
fake delivery sink. It covers keypad mapping, six-key rollover, modifiers,
coordinate bounds, failed reports and held-button preservation during double
clicks. It never creates a virtual device or injects desktop input.

`test/macos_kvm_launcher_runtime.py --agent /absolute/path/to/built/meshagent`
uses disposable launchd jobs to check the context transition. An unprivileged
background job may be denied entry to the GUI audit session; the test reports
that condition as skipped (exit 77), not a passing privileged transition. On an
authorized root test host, run it with `--uid <active-desktop-uid>` to verify a
system-job-to-Aqua transition. The probe verifies that `launchctl asuser` retains
the launcher's credentials, so the helper's separate credential checks remain
necessary. It removes only its unique fixture jobs and never invokes KVM.

`python3 test/macos_kvm_permissions_native.py` compiles production permission
queries and input dispatch with injected authorization results under ASan/UBSan.
It checks denied, granted, and revoked input, legacy OS fallback, and desktop
status packets without accessing the screen or injecting input. It also guards
against restoring startup permission requests and protected-file probes. A real
macOS permission grant/revocation and remote desktop smoke test is still needed
to validate OS integration; the injected test does not establish TCC approval.

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
