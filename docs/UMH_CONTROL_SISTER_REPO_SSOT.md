# MeshAgent UMH Control Sister-Repo SSOT

Last Updated: 2026-04-14
Owner: Codex + User
Status: Active sister-repo SSOT for the agent-side `umhctl` operator contract

## Purpose

This repo owns the endpoint-side UMH operator contract, not the native `UserModeHook` CLI text surface.

The authoritative agent-side UMH contract currently lives in:

- `modules/RecoveryCore.js`
- `test/lib/umh_operator_contract.js`
- `test_umhctl_e2e.js`
- `meshcore/config/umh_defines.h`

## Sister Repos

| Repo | Local Path | Role |
|---|---|---|
| `UserModeHook` | `C:\Users\Workstation\Documents\GitHub\UserModeHook` | native service, native control pipe, native CLI, native docs |
| `MeshCentral` | `C:\Users\Workstation\Documents\GitHub\MeshCentral` | web UI that emits `umhctl` commands and live VPS mirror workspace |
| `MeshAgent` | `C:\Users\Workstation\Documents\GitHub\MeshAgent` | endpoint-side operator contract, flow-header defaults, companion-service deployment rules |

Authoritative sister docs:

- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlSisterRepoContract.md`
- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlDeploymentLedger.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_SISTER_REPO_SSOT.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_DEPLOYMENT_LEDGER.md`

## What This Repo Actually Owns

This repo owns:

- the `umhctl` console/operator contract exposed by the agent runtime
- request building for control-pipe JSON ops
- default flow-header contract values
- pipe/service identifier constants shared with the agent-side UMH lifecycle

This repo does not own:

- the native `UmhCli.exe` command names in `UserModeHook`
- the MeshCentral browser UI text/buttons

## Current Contract Split

The retained `MeshAgent` operator layer now models:

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
- `injectAll`
- `clearTargetScope`
- `lockdownBypass`
- `examsoftBypass`
- `ipcBypass`

Those names are the agent-side operator contract. They are not proof that the native `UserModeHook` CLI still exposes identical text commands.

The current agent-side default flow contract is:

- `x-umh-contract-version=2026-03-05`
- `x-umh-flow-profile=report-driven-lockdown-v1`

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

then the same change tranche must also update:

1. `UserModeHook` native code and docs
2. `MeshCentral` UI/ledger docs
3. this repo's sister ledger docs

## Current Blocker

After the 2026-04-14 control-surface alignment:

- the retained operator surface in source matches the `UserModeHook` report-driven hard-fail contract
- the default agent-side header version now matches `2026-03-05`
- `MeshCentral/custom.js` must be republished before the live UI can claim the same curated subset

Implication:

- source-level sister-repo contract drift is closed, but live UI deployment still needs publication/verification

## Immediate Rule

Before changing or extending this repo's `umhctl` contract:

1. update this repo's contract/tests
2. update `UserModeHook` SSOT/ledger docs
3. update `MeshCentral` SSOT/ledger docs
4. verify the deployed MeshCentral/agent path still exposes the same operator layer
