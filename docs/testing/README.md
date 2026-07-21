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
