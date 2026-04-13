# MeshAgent UMH Control Deployment Ledger

Last Updated: 2026-04-14
Owner: Codex + User
Status: Active ledger for MeshAgent-side UMH operator deployment assumptions

## Scope

This ledger records the MeshAgent-side assumptions that must remain aligned with `UserModeHook` and `MeshCentral`.

## Current Agent-Side Authority

| Surface | File |
|---|---|
| control pipe and service identity constants | `meshcore/config/umh_defines.h` |
| runtime/operator implementation | `modules/RecoveryCore.js` |
| contract test library | `test/lib/umh_operator_contract.js` |
| parity and behavior tests | `test_umhctl_e2e.js` |
| deployment narrative | `docs/DEPLOYMENT.md` |

## Current Shared Identity

Current constants used by the agent-side UMH layer:

- executable name: `MasterService.exe`
- service name: `AdvancedHookService`
- control pipe: `\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-control`

## Current Default Flow Contract

Current agent-side default flow contract:

- protocol: `umh-control`
- contract version: `2026-03-05`
- flow profile: `report-driven-lockdown-v1`
- required headers:
  - `x-umh-contract-version`
  - `x-umh-flow-profile`
  - `x-umh-run-id`
  - `x-umh-client`
  - `x-umh-target-tag`
  - `x-umh-method-key`

Current alignment:

- `UserModeHook` currently hard-fails on `x-umh-contract-version=2026-03-05`
- `MeshAgent` now defaults to `x-umh-contract-version=2026-03-05`

## Deployment Path Assumptions

This repo currently assumes:

- `MasterService.exe` is published to `/opt/meshcentral/meshcentral-files/domain/user-hsadmin/Public/MasterService.exe`
- operator installs can derive a public userfiles URL without the `Public` path segment

## Recorded Cross-Repo Drift

### Native CLI drift

`UserModeHook` native CLI text commands have moved away from the older operator-layer names. The native surface now uses names such as:

- `processes`
- `inject-all`
- `capabilities`
- `lockdown`
- `examsoft`
- `ipc-bypass`

### MeshCentral UI drift

The aligned source `MeshCentral/public/scripts/custom.js` now emits the curated retained operator subset such as:

- `listProcesses`
- `getFlowContract`
- `getCapabilities`
- `safetyState`
- `profileProcess`
- `methodPolicy`
- `securityBoundary`
- `injectAll`
- `clearTargetScope`
- `lockdownBypass`
- `examsoftBypass`
- `ipcBypass`

### Live deployment blocker

After syncing the local `MeshCentral` repo to the live VPS, the mirrored module-side MeshCentral files do not show a matching visible `umhctl` bridge in the module tree itself. That means the deployed operator path must be revalidated before any repo treats the current UI as contract-safe.

### Retired ops removed from the operator contract

The agent-side contract no longer exposes retired control ops that now hard-fail or are explicitly retired in `UserModeHook`:

- `getInjectionState`
- `setFlags`
- `disable`
- `disableAll`
- `registerProtectedPid`
- `unregisterProtectedPid`

## Required Cross-Repo Rule

No change to the MeshAgent-side UMH contract is complete until the same tranche updates:

- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlSisterRepoContract.md`
- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlDeploymentLedger.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_SISTER_REPO_SSOT.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_DEPLOYMENT_LEDGER.md`

## Current Action Rule

Treat `modules/RecoveryCore.js` and `test/lib/umh_operator_contract.js` as the MeshAgent operator-layer truth, but do not assume that truth is already wired cleanly through the current live MeshCentral deployment without explicit validation or that its header version already matches `UserModeHook`.
