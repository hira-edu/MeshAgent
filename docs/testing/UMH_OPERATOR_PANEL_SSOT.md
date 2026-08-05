# UMH Operator Panel SSOT

## Scope

This document is the retained source of truth for the MeshCentral-facing UMH operator surface that must stay aligned with:

- the raw MeshAgent console path in `umhctl`
- the `modules/RecoveryCore.js` request builder and result renderer
- the desktop and mobile operator fixtures and Playwright coverage

It provides one machine-checkable surface definition for the raw console,
recovery core, and desktop/mobile operator fixtures.

## Invariants

1. Desktop and mobile operator pages may differ in layout only. They may not change UMH request semantics.
2. Every retained operator action maps to exactly one canonical `umhctl` command family.
3. Pipe-backed actions use the same canonical JSON request body whether they were built by desktop UI, mobile UI, console flags, or `umhctl --json`.
4. State-changing operations inherit the active flow contract and session-scoped headers from the raw console path.
5. Result rendering stays grouped into three retained modes only:
   - lifecycle text output
   - control-pipe JSON output
   - `uiSnapshot` JSON output
6. Retired operator controls must fail closed before a request is dispatched.

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
- `profileProcess`
- `methodPolicy`
- `safetyState`
- `hookProfile`
- `securityBoundary`

### Mutation

- `inject`
- `injectTargetSet`
- `injectAll`
- `telemetry`
- `repair`
- `setPolicy`
- `setConfig`
- `clearTargetScope`

## Raw Console And UI Parity Rules

### Canonical op names

The canonical pipe-backed op names are the values emitted by `umhctlCanonicalControlOp()` in `modules/RecoveryCore.js`. UI surfaces may display friendly labels, but dispatch must use the canonical names.

### Canonical actions

No retained command family has a secondary action map. `hookControl`,
`ipcBypass`, `lockdownBypass`, and `examsoftBypass` are retired and must be
rejected as unsupported before dispatch.

### Flow headers

The retained default flow contract is:

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

Desktop and mobile panels must preserve the same request-header semantics as the raw console path:

1. state-changing requests fetch or reuse the flow contract before dispatch
2. `injectTargetSet` establishes scope for the session
3. `injectAll` and `clearTargetScope` reuse the same scoped headers
4. explicit header overrides from the operator are allowed and must survive unchanged

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
- `profileProcess`
- `methodPolicy`
- `safetyState`
- `hookProfile`
- `securityBoundary`
- all mutation operations

### `uiSnapshot`

`uiSnapshot` renders one JSON snapshot object with retained sections:

- `status`
- `flow_contract`
- `capabilities`
- `processes`
- `policy`
- `config`
- `safety_state`
- `process_profile`
- `method_policy`
- `security_boundary`

## Surface Grouping

Desktop and mobile surfaces must expose the same operation set with the same input schema. The retained group order is:

1. lifecycle
2. query
3. mutation

The retained fixtures and tests for this contract are:

- `test_umhctl_e2e.js`
- `test/run_umh_type4_matrix.js`
- `test/playwright/umh_operator_desktop.spec.js`
- `test/playwright/umh_operator_mobile.spec.js`
