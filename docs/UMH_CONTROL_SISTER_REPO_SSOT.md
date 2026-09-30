# MeshAgent UMH Control Sister-Repo SSOT

## Purpose

This repo owns the endpoint-side UMH operator contract. It does not own the native `UserModeHook` CLI text surface, and it does not own the MeshCentral browser UI.

The authoritative agent-side UMH contract currently lives in:

- `modules/umhctl.js`
- `modules/RecoveryCore.js`
- `test/lib/recoverycore_vm.js`
- `test/lib/umh_operator_contract.js`
- `test_umhctl_e2e.js`
- `meshcore/config/umh_defines.h`
- `meshservice/runtime_host_contract.c` / `MeshUmhHostW`

## Sister Repos

| Repo | Role |
|---|---|
| `UserModeHook` | Native service, control pipe, CLI, and native docs |
| `MeshCentral` | Web UI that emits `umhctl` commands and server publication |
| `MeshAgent` | Endpoint operator contract, flow-header defaults, and companion-service deployment |

Authoritative sister contracts are `UserModeHook/docs/ssot/UmhControlSisterRepoContract.md`
and `MeshCentral/docs/UMH_CONTROL_SISTER_REPO_SSOT.md`. Resolve these paths from
the configured sibling checkouts rather than a particular workstation.

## What This Repo Owns

This repo owns:

- the `umhctl` console/operator contract exposed by the agent runtime
- request building for control-pipe JSON ops
- default flow-header contract values
- pipe/service identifier constants shared with the agent-side UMH lifecycle
- runtime compatibility handling for timer, process-completion, and exec-file invocation behavior

This repo does not own:

- the native `UmhCli.exe` command names in `UserModeHook`
- the MeshCentral browser UI button labels or layout

## Current Retained Operator Contract

The retained agent-side operator layer models:

- `status`
- `listProcesses`
- `getFlowContract`
- `getCapabilities`
- `getPolicy`
- `getConfig`
- `uiSnapshot`
- `profileProcess`
- `methodPolicy`
- `safetyState`
- `hookProfile`
- `securityBoundary`
- `inject`
- `injectTargetSet`
- `injectAll`
- `telemetry`
- `repair`
- `setPolicy`
- `setConfig`
- `clearTargetScope`

`hookControl` and the legacy secondary control operations are retired. They are
absent from the control-op map, help, desktop/mobile operator fixtures, and
MeshCentral UI. Console and raw-JSON attempts fail closed as unsupported.
The HookDLL applies its configured input and Window Display Affinity changes
automatically only to applicable authorized test targets; there is no operator
toggle.

## Shared Identity and Flow Contract

`meshcore/config/umh_defines.h` defines the native identifiers mirrored by the
shared JavaScript modules:

- executable: `MasterService.exe`
- service: `AdvancedHookService`
- control pipe: `\\.\pipe\{95c1a2e0-f84e-4c8a-9c32}-control`

The default flow contract is:

- protocol: `umh-control`
- `x-umh-contract-version=2026-03-05`
- `x-umh-flow-profile=report-driven-lab-v1`

The version is a protocol identifier, not a deployment date. Flow-scoped
requests also carry `x-umh-run-id`, `x-umh-client`, `x-umh-target-tag`, and
`x-umh-method-key`; preserve explicit operator overrides. See the
[operator panel contract](testing/UMH_OPERATOR_PANEL_SSOT.md#flow-headers)
for UI and console parity requirements.

## `uiSnapshot` Aggregate Contract

Without `--pid`, `umhctl uiSnapshot` requests:

- `status`
- `flow_contract`
- `capabilities`
- `processes`
- `policy`
- `config`
- `safety_state`

With `--pid <pid>`, it additionally requests:

- `process_profile`
- `method_policy`
- `security_boundary`

`partial=true` means one or more section requests failed. It does not mean the entire snapshot failed.

The native `getConfig` operation reads the UserModeHook configuration at
`C:\ProgramData\UserModeHook\config.json`. If it returns `config not found`,
the `config` section makes the aggregate partial. Inspect the per-section
errors to distinguish missing configuration from failures in other requests.

## Runtime Compatibility Notes

The current shared implementation also carries mandatory runtime-compatibility guards:

- timer handles may exist without Node's `unref()` method, so `umhctl` must guard `unref` calls
- child-process completion must tolerate runtimes that only support one of `exit` or `close`
- Windows UMH service commands must not spawn `MasterService.exe` directly from the agent; they must run through `rundll32.exe <ServiceDll>,MeshUmhHostW <manifest>`
- The UMH host and agent-owned Run Commands host must resolve and validate an
  explicit SYSTEM/high-integrity primary token before launch, then verify the
  created child's integrity and session. They must not rely on inheritance from
  an assumed-elevated bridge process.
- The console bridge contract requires exactly one explicit mode:
  `token=privileged-agent` without `tsid`, or `token=session-user` with an exact
  `tsid`. Missing, duplicate, or contradictory mode/session arguments are
  rejected by both the process policy and native parser.
- A split-token administrator still using its limited token, a standard user,
  or any other medium-integrity caller must fail with an explicit elevation
  error. The bridge must not activate `TokenLinkedToken`, continue without the
  required elevated token, or continue as if installation succeeded.
- User-session Run Commands use the WTS session-user token and must never fall
  back to a bridge/SYSTEM token. Token ownership is generic across all
  payloads, including MasterService, Inject32, and RServ audio; it is not an
  application-specific rule.
- non-Windows/direct `execFile` argument vectors must not prepend the executable basename

These are contract-level runtime requirements, not optional workarounds.

## Publication Contract

Behavioral changes originate in `modules/umhctl.js` and its matching recovery-core
implementation, then must be mirrored into the MeshCentral core/module copies
before publication. Keep default, minified, recovery, diagnostic, tiny, and
configured data-override cores aligned with the operator surface.

`deploy.py` supplies the publish mappings. Its UMH candidate is
`../UserModeHook/build/bin/Release/MasterService.exe`; any companion publication
tool must select the same reviewed candidate. Set `MESHCENTRAL_USERFILES_USER`
to publish it under the configured MeshCentral user's public files directory.
The UI source `../MeshCentral/public/scripts/custom.js` is published to both
configured module-public and web-public targets.

The agent resolves its download URL from `UMH_MASTERSERVICE_URL`, or from its
server URL plus `UMH_MASTERSERVICE_PATH` or `UMH_USERFILES_USER`. The userfiles
form is `/userfiles/<owner>/MasterService.exe?download=1`. Configure an HTTPS
endpoint compatible with the deployed agent's TLS client, retain certificate
verification, and verify the published payload against the selected package's
digest. Server addresses, release hashes, and canary observations belong in
per-run evidence rather than this contract.

See [Deployment](DEPLOYMENT.md) for staging, publication, verification, and
rollback, and [Testing](testing/README.md) for the validation workflow.

## Required Sync Rules

If this repo changes any of the following:

- control op map
- required PID rules
- state-changing op map
- flow-scoped op map
- action canonicalization
- default flow contract
- control pipe name
- service name or UMH binary name
- runtime compatibility behavior for timers, child-process completion, or exec-file invocation
- the `MeshUmhHostW` RuntimeHost contract used by Windows UMH lifecycle commands

then coordinate the matching changes in:

1. `UserModeHook` native code and current contract docs
2. `MeshCentral` UI, published modules, and current contract docs
3. this document and the operator panel contract

The implementations and current contracts must agree before rollout.
