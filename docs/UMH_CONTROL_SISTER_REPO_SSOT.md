# MeshAgent UMH Control Sister-Repo SSOT

Last Updated: 2026-04-19
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
- `lockdownBypass`
- `examsoftBypass`
- `ipcBypass`

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

## 2026-07-26 Rolled-Back Agent-Compatible Live Publication

- active MeshCentral VPS IP: `74.208.52.191`
- rolled-back MeshAgent commit: `0fb268971e670b09a89f977f727336a91328f0ea`
- live `MasterService.exe` size: `17078784`
- live `MasterService.exe` SHA384 / install pin: `86f0b4828b36ac88351ceb687fc61b8b6d608aa3d6d1406b79061518ba07b27af99c3334c30d9b00464c5a61c6277903`
- live `MasterService.exe` SHA256: `e7784af6e6849ec11c8bf1ae5555a31d6adaa3f2da610b3635429c5bd8893bbd`
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
