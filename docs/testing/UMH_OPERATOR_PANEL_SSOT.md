# UMH Operator Panel SSOT

## Scope

This document is the retained source of truth for the MeshCentral-facing UMH operator surface that must stay aligned with:

- the raw MeshAgent console path in `umhctl`
- the `modules/RecoveryCore.js` request builder and result renderer
- the desktop and mobile operator fixtures and Playwright coverage

It exists to close the contract gap called out by `TODO-018` and to give `TODO-024` one machine-checkable surface definition.

## Invariants

1. Desktop and mobile operator pages may differ in layout only. They may not change UMH request semantics.
2. Every retained operator action maps to exactly one canonical `umhctl` command family.
3. Pipe-backed actions use the same canonical JSON request body whether they were built by desktop UI, mobile UI, console flags, or `umhctl --json`.
4. State-changing operations inherit the active flow contract and session-scoped headers from the raw console path.
5. Result rendering stays grouped into three retained modes only:
   - lifecycle text output
   - control-pipe JSON output
   - `uiSnapshot` JSON output
6. Protected-screen mutations may not dispatch until pre-protection capture evidence has been written locally.

## Retained Command Families

### Lifecycle

- `install`
- `uninstall`
- `status --service`
- `verify`

### Query

- `status`
- `listProcesses`
- `getFlowContract`
- `getCapabilities`
- `getPolicy`
- `getConfig`
- `uiSnapshot`
- `getInjectionState`
- `profileProcess`

### Mutation

- `inject`
- `injectTargetSet`
- `injectAll`
- `telemetry`
- `repair`
- `setFlags`
- `disable`
- `disableAll`
- `setPolicy`
- `setConfig`
- `clearTargetScope`

### Target Registration

- `registerProtectedPid`
- `unregisterProtectedPid`

### Bypass

- `ipcBypass`
- `lockdownBypass`
- `examsoftBypass`

## Raw Console And UI Parity Rules

### Canonical op names

The canonical pipe-backed op names are the values emitted by `umhctlCanonicalControlOp()` in `modules/RecoveryCore.js`. UI surfaces may display friendly labels, but dispatch must use the canonical names.

### Canonical actions

The only retained action maps are:

- `ipcBypass`: `list-targets`, `status`, `disable`, `enable`
- `lockdownBypass`: `status`, `apply`, `apply-harness`, `revert`, `revert-harness`
- `examsoftBypass`: `status`, `secure-enter`, `secure-exit`

If the user does not choose an action for one of these command families, the canonical default is `status`.

### Flow headers

The retained default flow contract is:

- protocol: `umh-control`
- contract version: `2026-03-07`
- flow profile: `report-driven-lockdown-v1`
- required headers:
  - `x-umh-contract-version`
  - `x-umh-flow-profile`
  - `x-umh-run-id`
  - `x-umh-client`
  - `x-umh-target-tag`
  - `x-umh-method-key`

Desktop and mobile panels must preserve the same request-header semantics as the raw console path:

1. state-changing requests fetch or reuse the flow contract before dispatch
2. `injectTargetSet` establishes scope for the session
3. `injectAll` and `clearTargetScope` reuse the same scoped headers
4. explicit header overrides from the operator are allowed and must survive unchanged

## Protected-Screen Sequencing

The retained protected-screen mutation set is:

- `lockdownBypass --action apply`
- `lockdownBypass --action apply-harness`
- `examsoftBypass --action secure-enter`

For these actions only, the retained operator path must execute this order:

1. resolve canonical headers and target identity
2. run the native pre-protection capture probe
3. persist the capture artifact and a JSON manifest locally
4. emit the capture paths back to the operator console
5. only then dispatch the state-changing UMH request

If the native capture probe fails, the operator path must emit an explicit failure and the protection mutation may not be dispatched.

## Result Rendering Contract

### Lifecycle text output

The UI may label these differently, but the data source stays the raw text emitted by the retained `umhctl` lifecycle helpers:

- `install`
- `uninstall`
- `status --service`
- `verify`

### Control-pipe JSON output

The following command families render the returned control payload as formatted JSON:

- `status`
- `listProcesses`
- `getFlowContract`
- `getCapabilities`
- `getPolicy`
- `getConfig`
- `getInjectionState`
- `profileProcess`
- all mutation operations
- all bypass operations

### `uiSnapshot`

`uiSnapshot` renders one JSON snapshot object with retained sections:

- `status`
- `flow_contract`
- `capabilities`
- `processes`
- `policy`
- `config`
- `injection_state` when `pid` is present
- `process_profile` when `pid` is present

## Surface Grouping

Desktop and mobile surfaces must expose the same operation set with the same input schema. The retained group order is:

1. lifecycle
2. query
3. mutation
4. target registration
5. bypass

The retained fixtures and tests for this contract are:

- `test_umhctl_e2e.js`
- `test/run_umh_type4_matrix.js`
- `test/playwright/umh_operator_desktop.spec.js`
- `test/playwright/umh_operator_mobile.spec.js`
