# MeshAgent UMH Control Sister-Repo SSOT

Last Updated: 2026-08-05
Owner: Codex + User
Status: Active sister-repo SSOT for the agent-side `umhctl` operator contract

## Purpose

This repo owns the endpoint-side UMH operator contract. It does not own the native `UserModeHook` CLI text surface, and it does not own the MeshCentral browser UI.

The authoritative agent-side UMH contract currently lives in:

- `modules/umhctl.js`
- `modules/RecoveryCore.js`
- `test/lib/recoverycore_vm.js`
- `test/lib/umh_operator_contract.js`
- `test_umhctl_e2e.js`
- `meshcore/config/umh_defines.h`

## Sister Repos

| Repo | Local Path | Role |
|---|---|---|
| `UserModeHook` | `C:\Users\Workstation\Documents\GitHub\UserModeHook` | native service, native control pipe, native CLI, native docs |
| `MeshCentral` | `C:\Users\Workstation\Documents\GitHub\MeshCentral` | web UI that emits `umhctl` commands and live VPS publication workspace |
| `MeshAgent` | `C:\Users\Workstation\Documents\GitHub\MeshAgent` | endpoint-side operator contract, flow-header defaults, companion-service deployment rules |

Authoritative sister docs:

- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlSisterRepoContract.md`
- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlDeploymentLedger.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_SISTER_REPO_SSOT.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_DEPLOYMENT_LEDGER.md`

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

`hookControl`, `lockdownBypass`, `examsoftBypass`, and `ipcBypass` are retired.
They are absent from the control-op map, help, desktop/mobile operator fixtures, and
MeshCentral UI. Console and raw-JSON attempts fail closed as unsupported. LockDown,
ETS, and PSI input/WDA neutralization is automatic at HookDLL install time and has no
operator toggle.

The current agent-side default flow contract is:

- `x-umh-contract-version=2026-03-05`
- `x-umh-flow-profile=report-driven-lockdown-v1`

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

Current expected live partial on a healthy canary:

- native `getConfig` reads `C:\ProgramData\UserModeHook\config.json`
- if that file is absent, `UserModeHook` returns `config not found`
- that missing-file condition is currently the expected reason `uiSnapshot` remains `partial=true`

## Runtime Compatibility Notes

The current shared implementation also carries mandatory runtime-compatibility guards:

- timer handles may exist without Node's `unref()` method, so `umhctl` must guard `unref` calls
- child-process completion must tolerate runtimes that only support one of `exit` or `close`
- Windows UMH service commands must not spawn `MasterService.exe` directly from the agent; they must run through `rundll32.exe <ServiceDll>,MeshUmhHostW <manifest>`
- non-Windows/direct `execFile` argument vectors must not prepend the executable basename

These are contract-level runtime requirements, not optional workarounds.

## Current Live Publication State

As of 2026-04-14:

- MeshCentral's live publication exposes `umhctl` across the default core, minified default core, recovery core, diagnostic core, tiny core, and the `meshcentral-data` default override
- live requested node `Sal` was offline during validation
- representative live validation used `DESKTOP-TONBSMQ` on core lineage `Apr 9 2026, 3220172809`

## Current Agent-Compatible Live Publication

- active MeshCentral VPS IP: `74.208.52.191`
- compatible rolled-back embedded client lineage: `0fb268971e670b09a89f977f727336a91328f0ea`
- current MeshAgent source baseline: `1f21cd62ac8699f3e35e2d11c6ef73098faeebf9` plus the coordinated local retired-op removal
- live `MasterService.exe` size: `16986624`
- live `MasterService.exe` SHA384 / install pin: `827b9d4e9bb254a2bdb4e9c423a3ae97e319f119941f4c2bd792719ac7bcf178e6932b452aa23d02e7164908f60e1b54`
- live `MasterService.exe` SHA256: `347f3c5ec7478fbb9e765d70b39ba4130a018662b2be633fe424af9440d14fc1`
- all four live `umhctl.js` copies: SHA256 `64cd8c4c660fd14f4b9a64a9b20345e84488762b152f3943491664ed94a5448f`
- live `recoverycore.js`: SHA256 `4013fa7f958632df0462f2fbbd8cef6cb35663e7b2f3334a43017be7a4a75843`
- compatible HTTPS publication URL: `https://agents.high.support/userfiles/hsadmin/MasterService.exe?download=1`
- the direct endpoint is required because the rolled-back embedded client fails the Cloudflare-backed `high.support` TLS handshake but succeeds with certificate validation against the existing Caddy-backed `agents.high.support` endpoint

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
- the `MeshUmhHostW` rundll32 host contract used by Windows UMH lifecycle commands

then the same change tranche must also update:

1. `UserModeHook` native code and docs
2. `MeshCentral` UI/ledger docs
3. this repo's sister ledger docs

No MeshAgent UMH contract change is complete until those sister docs agree.
