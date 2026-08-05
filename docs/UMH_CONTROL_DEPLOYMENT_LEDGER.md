# MeshAgent UMH Control Deployment Ledger

Last Updated: 2026-08-05
Owner: Codex + User
Status: Active ledger for MeshAgent-side UMH operator deployment assumptions and live validation conditions

## 2026-08-05 Retired-Op Closure And Post-WDA-Fix Publication

- `hookControl` was removed from both shared modules, the operator contract fixture, help, and desktop/mobile layouts. Console and raw-JSON attempts now fail closed as unsupported; no retired bypass operation is published.
- Focused install-path, module-parity, operator E2E, desktop/mobile matrix, rundll32 helper migration, and Playwright checks passed before publication.
- Live `MasterService.exe`: size `16986624`, SHA256 `347f3c5ec7478fbb9e765d70b39ba4130a018662b2be633fe424af9440d14fc1`, SHA384/pin `827b9d4e9bb254a2bdb4e9c423a3ae97e319f119941f4c2bd792719ac7bcf178e6932b452aa23d02e7164908f60e1b54`.
- Live control files: all four `umhctl.js` copies SHA256 `64cd8c4c660fd14f4b9a64a9b20345e84488762b152f3943491664ed94a5448f`; `recoverycore.js` SHA256 `4013fa7f958632df0462f2fbbd8cef6cb35663e7b2f3334a43017be7a4a75843`.
- Public re-fetch and both UserModeHook VPS guards passed. This is deployment/control-surface evidence only; endpoint reinstall and browser runtime evidence remain pending.

## 2026-07-26 Rolled-Back Agent TLS Download Compatibility

- MeshAgent remains at the rolled-back commit `0fb268971e670b09a89f977f727336a91328f0ea`; no native source or binary was changed or rebuilt for this repair.
- The rolled-back embedded HTTP client failed before HTTP with `TLS Handshake Error` through the Cloudflare-backed `https://high.support/userfiles/...` route, while the same `rejectUnauthorized=1` path downloaded the complete unchanged payload through `https://agents.high.support/userfiles/...`.
- The control download returned `17078784` bytes and SHA384 `86f0b4828b36ac88351ceb687fc61b8b6d608aa3d6d1406b79061518ba07b27af99c3334c30d9b00464c5a61c6277903`, matching the VPS and installed local `MasterService.exe`.
- MeshCentral now emits the proven direct endpoint and matching pin. This is an exact endpoint contract correction, not a retry, fallback, TLS bypass, or heuristic.

## 2026-07-01 Live UMH Publication / MasterService Republish

- operator-designated replacement MeshCentral VPS IP: `74.208.52.191`
- current local `MasterService.exe` publish candidate: `C:\Users\Workstation\Documents\GitHub\UserModeHook\build\bin\Release\MasterService.exe`
- current local candidate size: `19848192`
- current local candidate SHA384: `1985cdfa65cbdb6f46f138a01ad79e4008930da01a4998ed29a438e6f431b171e1957499af4a36474bfe7a46896c585a`
- current local candidate SHA256: `75a7fc3581318f8bc5cb1969f440b2abbda7c70cb9646d404616b32f05671e8a`
- deployment status: SSH and HTTPS publication are reachable on July 1, 2026
- consequence: `deploy.py` and the dedicated UMH publish script must both publish from the same `build\bin\Release` candidate

## Scope

This ledger records the MeshAgent-side assumptions that must remain aligned with `UserModeHook` and `MeshCentral`.

## Current Agent-Side Authority

| Surface | File |
|---|---|
| control pipe and service identity constants | `meshcore/config/umh_defines.h` |
| shared operator implementation | `modules/umhctl.js` |
| recovery-core console host | `modules/RecoveryCore.js` |
| Windows UMH process host | `meshservice/rundll32_contract.c` / `MeshUmhHostW` |
| VM harness for shared module loading | `test/lib/recoverycore_vm.js` |
| contract test library | `test/lib/umh_operator_contract.js` |
| parity and behavior tests | `test_umhctl_e2e.js` |
| deployment narrative | `docs/DEPLOYMENT.md` |

## Current Shared Identity

Current constants used by the agent-side UMH layer:

- executable name: `MasterService.exe`
- service name: `AdvancedHookService`
- control pipe: `\\.\pipe\{95c1a2e0-f84e-4c8a-9c32}-control`

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

## `uiSnapshot` Contract and Config Dependency

Without `--pid`, `uiSnapshot` requests:

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

`partial=true` means one or more section requests failed.

Current expected live partial on a healthy canary:

- `UserModeHook getConfig` reads `C:\ProgramData\UserModeHook\config.json`
- if that file is absent, `getConfig` returns `config not found`
- that missing-file condition is currently the expected reason `uiSnapshot` remains `partial=true`

## Deployment Path Assumptions

This repo currently assumes:

- `MasterService.exe` is published to `/opt/meshcentral/meshcentral-files/domain/user-hsadmin/Public/MasterService.exe`
- operator installs derive the public URL `https://agents.high.support/userfiles/hsadmin/MasterService.exe?download=1`
- the live UI override is `/opt/meshcentral/meshcentral-web/public/scripts/custom.js`

## Current Live Publication Conditions

Current live MeshCentral publication relevant to the MeshAgent operator layer:

- `/opt/meshcentral/meshcentral-data/meshcore.js` -> `30e9a91b9985f1004bfe4861c6db6ecddbf198a999a72c075793ef3d66754a4f`
- `/opt/meshcentral/node_modules/meshcentral/agents/meshcore.js` -> `97394dd5e24afc39cec91710f4612584ee3f3b76aa6de138f13fc6412b15d194`
- `/opt/meshcentral/node_modules/meshcentral/agents/meshcore.min.js` -> `518145e9fbcdfb5c7d8eb756c3ab3ccb94956de645ff9132907c9cfdc115c9a3`
- `/opt/meshcentral/node_modules/meshcentral/agents/recoverycore.js` -> `4013fa7f958632df0462f2fbbd8cef6cb35663e7b2f3334a43017be7a4a75843`
- `/opt/meshcentral/node_modules/meshcentral/agents/meshcore_diagnostic.js` -> `87c55517a3b50966508d9be03135633d67c40be708b6f9114ceebc764bde3845`
- `/opt/meshcentral/node_modules/meshcentral/agents/tinycore.js` -> `396e05d2c3559c0740ded904b96da32f6af36f3f80925316fcf3819dd67c674b`
- all four live publication copies of `umhctl.js` currently hash to `64cd8c4c660fd14f4b9a64a9b20345e84488762b152f3943491664ed94a5448f`
- the live published `MasterService.exe` currently hashes to SHA384 `827b9d4e9bb254a2bdb4e9c423a3ae97e319f119941f4c2bd792719ac7bcf178e6932b452aa23d02e7164908f60e1b54` and SHA256 `347f3c5ec7478fbb9e765d70b39ba4130a018662b2be633fe424af9440d14fc1`

Publication note:

- the MeshCentral-served `umhctl.js` publication copies are the live deployment reference
- behavioral changes still originate in `MeshAgent/modules/umhctl.js`, then must be mirrored into MeshCentral before rollout claims are valid

## Current Live Validation State

Current recorded live validation:

- requested node `Sal` was offline during the 2026-04-14 validation tranche
- representative live canary was `DESKTOP-TONBSMQ`
- `umhctl install --url ...` succeeded on the canary
- `umhctl methodPolicy` succeeded with `meta.headers_required=false`
- `umhctl safetyState` succeeded with `meta.headers_required=false`
- `umhctl uiSnapshot` remained `partial=true` only because `config` was missing on the canary

## Runtime Compatibility Closures in This Tranche

Closed compatibility requirements in the shared operator layer:

- guarded timer-handle `unref()` calls
- defensive `exit`/`close` child-process completion subscription
- corrected `execFile` argv construction so lifecycle commands pass only the intended flags

These are mandatory compatibility fixes, not optional fallbacks.

## Required Cross-Repo Rule

No change to the MeshAgent-side UMH contract is complete until the same tranche updates:

- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlSisterRepoContract.md`
- `C:\Users\Workstation\Documents\GitHub\UserModeHook\docs\ssot\UmhControlDeploymentLedger.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_SISTER_REPO_SSOT.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_DEPLOYMENT_LEDGER.md`
