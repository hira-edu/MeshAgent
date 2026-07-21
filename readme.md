# MeshAgent

This repository is an authorized MeshCentral agent fork based on
[Ylianst/MeshAgent](https://github.com/Ylianst/MeshAgent). It retains the
cross-platform native agent and embedded JavaScript runtime while adding the
Windows packaging, service lifecycle, remote-support validation, branding, and
deployment integration used by this fork.

The repository is source-first. Generated binaries, local branding, runtime
logs, traces, and release bundles are intentionally ignored.

## Repository at a glance

| Path | Responsibility |
|---|---|
| `meshcore/` | Agent control channel, identity, update logic, and platform KVM code |
| `microstack/` | Event loop, networking, cryptography, process pipes, and data store |
| `microscript/` | Duktape runtime and native JavaScript bindings |
| `modules/` | JavaScript modules loaded by the agent and recovery core |
| `meshservice/` | Windows service executable, service-hosted DLL, installer, and lifecycle code |
| `meshconsole/` | Console-hosted agent executable |
| `meshreset/` | Windows reset utility |
| `test/` | Static contracts, native/runtime probes, grouped regression, and UI tests |
| `tools/` | Branding, signing, health, publication, tunnel, and validation helpers |
| `docs/` | Current architecture, configuration, deployment, testing, and cross-repo contracts |
| `schema/` | JSON schema for branding configuration |
| `verification/` | Small machine-readable validation fixtures retained with the source |
| `openssl/`, `lib-jpeg-turbo/`, `webrtc/` | Bundled third-party build inputs |

See [Repository layout](docs/Files.md) and
[Architecture](docs/Architecture.md) for the detailed map.

## Windows build

Prerequisites:

- Visual Studio 2022 with the Desktop development with C++ workload
- a compatible Windows SDK
- Python 3 available as `python`
- MSBuild available on `PATH` (a Developer PowerShell is the simplest option)

Create `branding_config.local.json` from
`branding_config.template.json`, replace every placeholder, and keep the local
file uncommitted. The build falls back to `branding_config.json` when the local
override is absent.

Build the complete Windows package in dependency order:

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

The orchestrator builds the x64 service DLL first, then MeshConsole, the x64
service executable, and the Win32 service executable. Primary outputs are:

| Artifact | Output |
|---|---|
| x64 service DLL | `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` |
| x64 service executable | `meshservice/x64/StealthLab/MeshService-2022.exe` |
| Win32 service executable | `meshservice/StealthLab/MeshService-2022.exe` |
| x64 console | `meshconsole/Release/MeshConsole64.exe` |

For a DLL-only validation build:

```powershell
msbuild .\meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m
```

Configuration precedence and generated files are documented in
[Configuration](docs/CONFIGURATION.md).

## Validation

Most source contracts run directly with Node.js:

```powershell
node .\test\deploy_publish_paths_contract.js
node .\test\health_check_branding_contract.js
node .\test\drift_reduction_contract.js
node .\test\provisioning-ssot-check.js `
  --evidence .\artifacts\validation\provisioning `
  --branding-json .\branding_config.local.json `
  --meshcentral-msh .\WinDiagnosticHost.msh
```

Native runtime tests require built artifacts; lifecycle tests also require an
elevated Windows shell. The grouped harness is intentionally disruptive to a
local test installation and must only be run on an approved test endpoint:

```powershell
node .\test\run_grouped_regression.js --evidence .\artifacts\validation\grouped
```

See [Testing](docs/testing/README.md) for test categories, prerequisites, and
artifact handling.

## Deployment and sister repositories

- [Deployment SSOT](docs/DEPLOYMENT.md) is the authoritative build-to-server,
  backup, rollback, and health-check runbook.
- [UMH sister-repository contract](docs/UMH_CONTROL_SISTER_REPO_SSOT.md) defines
  ownership across MeshAgent, MeshCentral, and UserModeHook.
- [UMH deployment ledger](docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md) records the
  live cross-repository deployment assumptions that must remain synchronized.

Staging and read-only health checks are safe preparation steps. Replacing live
agent payloads, restarting services, or rolling out to endpoints requires
explicit operator approval.

## CI

The active Windows artifact workflow is
`.github/workflows/build-release.yml`; CodeQL is defined in
`.github/workflows/codeql-analysis.yml`. See
[GitHub Actions](GITHUB_ACTIONS_STEALTHLAB.md) for triggers and artifact names.

## Documentation policy

The `docs/` tree contains current operating references only. Work queues,
dated project plans, migration narratives, and generated debug evidence do not
belong in source control. Use issues or the project tracker for future work and
ignored `artifacts/` paths for per-run output.

## Upstream and licensing

Upstream changes are available through the `upstream` Git remote. Source files
retain their original license notices; the core MeshAgent sources are licensed
under Apache License 2.0, with bundled dependencies carrying their own terms.
