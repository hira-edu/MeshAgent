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

### Grouped regression

`test/run_grouped_regression.js` performs a local install/update/uninstall cycle
and requires an elevated, approved Windows test host. Do not run it on a host
that is not approved for destructive service lifecycle operations.

### UMH Playwright

`test/run_umh_playwright.js` covers the desktop and mobile UMH fixtures.

### Release gates

`test/release_signing_bundle_gate.js` and `test/release_bundle_gate.js` are the
release gates. They check the signed bundle and the release bundle, including the
presence of the required documentation under `docs/` (`docs/README.md`,
`docs/CONFIGURATION.md`, `docs/DEPLOYMENT.md`, and `docs/testing/README.md`).
Both read built service binaries under `meshservice/x64/`, so build first; the
signing gate also reads `branding_config.local.json` and stages the Win32
runtime executable and the x64 agent database.

## Builds before binary-reading tests

Runtime probes and any contract that reads built binaries need a current build
first. In particular, `test/service_bundle_embedded_payload_contract.js` reads
the built service binaries and their embedded payload, so build the package (or
at least the service-DLL gate) before running it; otherwise it has nothing valid
to read.

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

## Generated reports

Store generated validation reports outside tracked documentation, normally under
`artifacts/validation/`. Do not check in dated planning files, status ledgers, or
runtime evidence.
