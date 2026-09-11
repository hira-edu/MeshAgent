# Testing

The `test/` directory contains current executable checks. Tests are grouped by
what they require, not by a historical work item.

## Static contracts

Most `*_contract.js` scripts inspect source or exercise isolated JavaScript and
can run with Node.js from the repository root. Useful baseline checks include:

```powershell
node .\test\deploy_publish_paths_contract.js
node .\test\health_check_branding_contract.js
node .\test\drift_reduction_contract.js
node .\test\kvm_bridge_pipe_contract.js
node .\test\update_quiesce_contract.js
node .\test\provisioning-ssot-check.js `
  --evidence .\artifacts\validation\provisioning `
  --branding-json .\branding_config.local.json `
  --meshcentral-msh .\WinDiagnosticHost.msh
```

Choose contracts for the files changed; do not claim the whole suite passed
when only a subset was run.

Provisioning has executable regressions that do not contact the VPS:

```powershell
node .\test\meshagent_provisioning_copy_runtime.js
node .\test\provisioning_ssot_validation_runtime.js
```

The first runs isolated MSBuild fixtures for x64/Win32 manifest selection,
replacement of stale sidecars, and missing-input failure before building.
The second checks valid embedded policies and rejection of missing files or
unextractable policies. Both accept an evidence directory as the first argument.
For the separate read-only live certificate gate, use
`meshcentral_certificate_admission_runtime.js` as documented in
[Deployment](../DEPLOYMENT.md#agent-certificate-admission-and-local-packages).
That gate verifies server authentication without registering a device; it does
not prove complete agent enrollment, core initialization, or relay operation.

Desktop multiplexing has executable regressions in addition to source checks:

```powershell
node .\test\meshcentral_multiplex_flow_control_runtime.js
node .\test\meshcentral_multiplex_socket_runtime.js
node .\test\meshcentral_desktop_reconnect_runtime.js
```

The first two accept an optional multiplexer source path. The flow-control
test also verifies that queued input sends pause viewers and drain once in
order. The socket test also
accepts a package path for resolving the server's `ws` dependency. They run
without a production session: the flow-control test controls send completions,
and the socket test uses a loopback listener. Coverage includes the empty image
cache after a screen reset, an existing picture cache, slow-viewer reconnects,
removal of the fastest viewer, pending recording writes, duplicate membership
changes, agent disconnection with multiple viewers and synchronous close
callbacks, closure of rejected duplicate agent sockets, and rejection of invalid
relay cookies. The socket adapter accepts
both `ws` 7 and 8 message signatures. On the VPS, use
`/opt/meshcentral/node_modules/express-ws/package.json` as its dependency path
to exercise the actual HTTP server's nested `ws` version. Use the original
deployed source as the failing control when local and live versions differ.

## Native and runtime probes

`*_runtime.js`, runtime PowerShell probes, and bridge smoke tests require the
matching built executable/DLL. Session, service, secure-desktop, input, and
install/update/uninstall tests may require an elevated Windows shell and an
interactive test session.

Run them only on an approved test endpoint. Many accept:

```text
--evidence <directory>
```

Use an ignored path such as `artifacts/validation/<run>/<test>`.

`kvm_capture_reconnect_runtime.js` exercises native capture with one persistent
loopback viewer and repeated clean/abrupt secondary disconnects. It requires
Windows, the sibling MeshCentral `ws` dependency, and an accessible interactive
test desktop. It sends compression and capture-resume commands only, discards
image data, and never connects to the production server. A 25-second watchdog
terminates only the test process it created. It fails on missing pictures,
stalled native timers, native errors, or an unsuccessful exit. A UAC/secure
desktop can deny capture and must not be counted as a passing image test.

```powershell
node .\test\kvm_capture_reconnect_runtime.js `
  .\meshconsole\Release\MeshConsole64.exe `
  .\artifacts\validation\capture-reconnect
```

Run the original binary as a failing control and a rebuilt binary for the
fix. The test does not validate the out-of-process service bridge or identify
unrelated service fatal exits.

`scriptcontainer_startup_runtime.js` runs disposable native console processes
without remote connections or service changes. It tests commands submitted
before `ready`, immediately after creation, and after exit; ordered messages;
script/syntax error delivery; startup exit; and worker permission enforcement.
The deliberately occupied parent event loop exposes initialization ordering.
Its watchdog terminates only its own test child. Keep the returned native
timer handles reachable in fixtures: unreferenced timers can be finalized.

```powershell
node .\test\scriptcontainer_startup_runtime.js `
  .\meshconsole\Release\MeshConsole64.exe `
  .\artifacts\validation\scriptcontainer-startup
```

Run against the original and rebuilt binaries. This local test does not replace
sustained validation of a deployed service with multiple desktop viewers.

`scriptcontainer_lifecycle_runtime.js` additionally drops the last reference
immediately and inside ready/error/data callbacks, then runs 45 worker
create/exit/collection cycles in one owned process. It requires exactly one
ready and exit per cycle and compares Windows handle/thread counts after
warmup. The baseline crashes when an exit listener releases the parent; with
that lifetime defect isolated, it leaks three handles per worker. The test
rejects this cumulative leak while allowing small runtime count variation.

```powershell
node .\test\scriptcontainer_lifecycle_runtime.js `
  .\meshconsole\Release\MeshConsole64.exe `
  .\artifacts\validation\scriptcontainer-lifecycle
```

## Grouped regression

`test/run_grouped_regression.js` combines package preflight, embedded-runtime
self-tests, MeshCentral contract checks, native lifecycle, and the GUI harness.
It installs, updates, and uninstalls the local test service, so elevation and an
approved disposable/canary endpoint are required.

```powershell
node .\test\run_grouped_regression.js `
  --source-exe .\meshservice\x64\StealthLab\MeshService-2022.exe `
  --source-dll .\meshservice\x64\StealthLab_DLL\MeshService-2022.dll `
  --evidence .\artifacts\validation\grouped
```

## UMH operator UI

The operator fixtures and desktop/mobile Playwright specs live under
`test/playwright/`. Run the repository wrapper:

```powershell
node .\test\run_umh_playwright.js
```

The contract shared by the fixtures, raw console, and recovery core is
[UMH Operator Panel SSOT](UMH_OPERATOR_PANEL_SSOT.md).

## Release checks

- `test/release_signing_bundle_gate.js` stages the release set and reports PE
  signing state and digests.
- `test/release_bundle_gate.js` verifies the expected package, current release
  documents, signing state, checksums, and archive generation.
- [Release checklist](../files/meshagent_release_checklist.md) covers the
  operator steps around those gates.

Release output belongs under ignored `artifacts/` or `dist/` paths.

## Detailed references

- [Self-update harness](SelfUpdate.md)
- [Embedded JavaScript unit-test harness](UnitTests.md)
- [Advanced Windows debug toolchain](ADVANCED_DEBUG_TOOLCHAIN.md)

## Artifact policy

Do not commit per-run logs, ETL/PML traces, dumps, screenshots, generated JSON,
or release archives. Keep them with the associated build or release ticket and
record only stable procedures and contracts in `docs/`.
