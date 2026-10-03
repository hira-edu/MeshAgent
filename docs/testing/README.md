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

Windows inventory and bridge checks that do not install an agent:

```powershell
node test/windows_inventory_runtime.js
node test/windows_terminal_failure_runtime.js
node test/windows_clipboard_bridge_runtime.js
python test/meshcentral_module_versions_runtime.py
python test/process_pipe_lifetime_runtime.py
```

The inventory test covers both pointer widths, denied process access, WCHAR
bounds, process details, token cleanup, and SCM pagination. The terminal test
checks failures before listeners attach and before the ready handshake. The
clipboard test covers Unicode, empty values, command-safe writes, errors, and
timeout cleanup. The core generation test verifies explicit module versions and
source preservation. The pipe test exercises extracted production state machines
with sanitizers; it also sets the Windows sanitizer runtime search path.
After building, `node test/windows_inventory_runtime.js --native` additionally
queries real Windows processes and services three times, checks handle counts,
and verifies ISO module version replacement in Duktape. Its query-only console
does not start a desktop notification message pump.

The elevated terminal smoke probes are `meshconsole_bridge_exec_smoke.js`,
`meshconsole_bridge_terminal_smoke.js`, and `win_terminal_wrapper_exec_smoke.js`.
The clipboard test's `--live-read --session <id>` mode reads without changing the
clipboard and prints only success and length. Run that mode under the service
identity: an ordinary elevated administrator is expected to fail closed at the
session-token boundary with error 1314.

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

Store generated validation reports outside tracked documentation, normally under
`artifacts/validation/`. Do not check in dated planning files, status ledgers, or
runtime evidence.
