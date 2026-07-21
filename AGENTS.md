# MeshAgent Repository Guidance

## Purpose

MeshAgent is an authorized fork of the MeshCentral agent used on endpoints the
operator owns or is permitted to administer. Changes should improve
reliability, auditability, maintainability, and visible remote-support
behavior.

`AGENTS.override.md` contains the highest-priority repository-specific safety
and execution rules.

## Source map

- `meshcore/`: control channel, identity, update, and KVM platform code
- `microstack/`: native event loop, networking, process, crypto, and storage
- `microscript/`: Duktape runtime and bindings
- `modules/`: agent-side JavaScript modules
- `meshservice/`: Windows service executable, DLL, installer, and lifecycle
- `meshconsole/`: console executable
- `test/`: contracts, runtime probes, grouped regression, and UI tests
- `tools/`: build generators, signing, deployment support, and health checks
- `docs/`: current architecture, deployment, testing, and cross-repo contracts

Generated output under `artifacts/`, `build/`, `dist/`, `out/`, `x64/`, and
`Win32/` is not source of truth.

## Engineering workflow

1. Read the source and the current documentation for the requested surface.
2. Keep changes bounded to the user request and its direct validation.
3. Preserve failure handling, cleanup, logging, and fail-closed behavior.
4. Build after native code, project, resource, or generated-header changes.
5. Run the smallest relevant contract tests, then broader regression when risk
   warrants it.
6. Store generated reports outside tracked documentation, normally under
   `artifacts/validation/`.

## Build

Complete Windows package:

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

Minimum service-DLL gate:

```powershell
msbuild .\meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m
```

Use `branding_config.local.json` for local identities and secrets. Never commit
that file or generated credentials.

## Validation

- Static Node contracts generally follow `test/*_contract.js`.
- Runtime probes generally follow `test/*_runtime.js` and require built files.
- `test/run_grouped_regression.js` performs local install/update/uninstall and
  requires an elevated, approved Windows test host.
- `test/run_umh_playwright.js` covers the desktop/mobile UMH fixtures.
- Release gates are `test/release_signing_bundle_gate.js` and
  `test/release_bundle_gate.js`.

## Current documentation authorities

| Subject | Document |
|---|---|
| Documentation index | `docs/README.md` |
| Repository architecture | `docs/Architecture.md` |
| Configuration | `docs/CONFIGURATION.md` |
| Deployment, backups, rollback | `docs/DEPLOYMENT.md` |
| Testing | `docs/testing/README.md` |
| UMH cross-repo ownership | `docs/UMH_CONTROL_SISTER_REPO_SSOT.md` |
| UMH live assumptions | `docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md` |

Do not add dated planning files, status ledgers, completed-work summaries, or
checked-in runtime evidence. Track proposed work outside the repository and
keep documentation focused on current behavior.
