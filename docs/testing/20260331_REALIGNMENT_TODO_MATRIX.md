# 2026-03-31 Realignment TODO Matrix

## Status Key

- `OPEN`: not started
- `IN_PROGRESS`: active implementation or investigation
- `BLOCKED`: waiting on a prerequisite
- `DONE`: completed and evidenced
- `REJECTED`: intentionally removed from scope with a ledger reason

## Work Rules

- Every TODO must map to at least one ledger entry in `docs/testing/20260331_REALIGNMENT_LEDGER.md`.
- Every `DONE` item must name evidence under `docs/testing/evidence/advanced/`.
- No TODO may be closed by argument alone. Closure requires implementation plus evidence.
- No new PowerShell runtime logic or PowerShell regression automation may be introduced.

## Program TODOs

| Phase | Priority | Status | ID | Task | Ledger Ref | Depends On | Acceptance |
|---|---|---|---|---|---|---|---|
| P0 | P0 | OPEN | TODO-001 | Create `realignment-origin-main` from `origin/main`, preserve the current working branch/worktree as a source-only reference, and freeze archived drift refs as patch sources only | LEDGER-001, LEDGER-012 | none | new clean branch exists and no lifecycle implementation work continues on the preserved reference baseline |
| P0 | P0 | OPEN | TODO-002 | Produce the file-level keep/port/rewrite/revert inventory for all hotspot files | LEDGER-001 through LEDGER-012 | TODO-001 | no hotspot file remains unclassified |
| P0 | P1 | OPEN | TODO-003 | Separate generated artifacts, tracked binaries, and build outputs from implementation truth | LEDGER-010 | TODO-001 | build outputs are explicitly excluded from code-port decisions |
| P1 | P0 | OPEN | TODO-004 | Define the minimal retained Windows lifecycle surface and remove duplicated entrypoint logic | LEDGER-001 | TODO-002 | authoritative lifecycle surface is documented and accepted |
| P1 | P0 | OPEN | TODO-005 | Define the minimal retained UMH surface, including `MasterService.exe`, control pipe, and operator workflow | LEDGER-002, LEDGER-006 | TODO-002 | important UMH scope is fixed and unrelated drift is marked for removal |
| P1 | P1 | OPEN | TODO-006 | Define the required MeshAgent `localhost` relay connectivity contract, identify the minimum retained transport surface, and document all unrelated networking reverts up front | LEDGER-007 | TODO-002 | no unresolved networking drift remains outside the explicit `localhost` relay contract |
| P1 | P1 | OPEN | TODO-007 | Define the remote-desktop-only Session 1 `rundll32` bridge, keep standalone blocked, and lock policy so generic PowerShell/arbitrary-process user-session spawning remains disallowed | LEDGER-008, LEDGER-009 | TODO-002 | default service-only policy is documented, remote desktop is the only approved Session 1 exception, and standalone remains blocked |
| P2 | P0 | OPEN | TODO-008 | Implement authoritative `DiscoverCurrentState` for files, services, registry, firewall, DACL, WMI, persistence, and UMH | LEDGER-001, LEDGER-002, LEDGER-004 | TODO-004 | lifecycle engine can classify clean, partial, broken, pending-update, and uninstall states deterministically |
| P2 | P0 | OPEN | TODO-009 | Implement single native transition planning for install, update, repair, reinstall, and uninstall | LEDGER-001 | TODO-008 | all Windows entrypoints route to one lifecycle planner |
| P2 | P0 | OPEN | TODO-010 | Implement bounded staging, quiesce, rollback, and post-state validation flow for agent payload updates | LEDGER-001, LEDGER-004 | TODO-009 | update path is deterministic, rollback-safe, and evidence-producing |
| P2 | P0 | OPEN | TODO-011 | Preserve NodeID and provisioning identity across update and reinstall, including backup and restore validation | LEDGER-004 | TODO-008 | update and reinstall preserve NodeID unless an explicit reset path is used |
| P2 | P0 | OPEN | TODO-012 | Make GUI, silent, CLI, and PowerShell-invoked install/update/uninstall call the same native lifecycle engine while preserving svchost-only service mode and blocking standalone runtime | LEDGER-001 | TODO-009 | entrypoint wrappers no longer contain independent lifecycle behavior and standalone stays blocked |
| P2 | P1 | OPEN | TODO-013 | Finalize uninstall negative validation for files, service registration, firewall rules, WMI, and UMH artifacts | LEDGER-001, LEDGER-002 | TODO-010 | uninstall proves absence, not just stop-state |
| P2 | P1 | OPEN | TODO-014 | Port the svchost self-update activation behavior into the new lifecycle engine cleanly | LEDGER-001 | TODO-010 | self-update triggers native full update flow without ad hoc divergence |
| P3 | P0 | OPEN | TODO-015 | Implement authoritative `MasterService.exe` source resolution, staging, install/update, and uninstall policy | LEDGER-002 | TODO-005, TODO-009 | companion lifecycle is deterministic across all operator paths |
| P3 | P0 | OPEN | TODO-016 | Implement control-pipe readiness verification and post-uninstall absence verification for UMH | LEDGER-002 | TODO-015 | install/update require pipe readiness, uninstall requires pipe absence |
| P3 | P1 | OPEN | TODO-017 | Reduce `RecoveryCore.js` to the important UMH/operator surfaces and remove unrelated expansion | LEDGER-006 | TODO-005 | retained RecoveryCore surface is minimal and requirement-backed |
| P3 | P1 | OPEN | TODO-018 | Reconcile MeshCentral UMH operator flows, raw console path, and Playwright surface contract | LEDGER-002, LEDGER-006 | TODO-015 | desktop and mobile operator paths are contract-defined and testable |
| P3 | P0 | OPEN | TODO-030 | Define and implement the protected-screen capture contract so end-to-end capture completes before screen protections or blackout state are applied | LEDGER-002, LEDGER-013 | TODO-015, TODO-018 | supported protected-screen flows record capture success before protection state mutation, or fail explicitly before protection state changes |
| P3 | P0 | OPEN | TODO-032 | Build the source-informed guardrail map from Microsoft service/session guidance and OWASP logging guidance, and keep SSOT, ledger, and regression coverage synchronized to it | LEDGER-014, LEDGER-015, LEDGER-018 | TODO-001, TODO-002 | clean branch plan documents encode the external guardrails and no implementation area is operating from undocumented assumptions |
| P3 | P0 | OPEN | TODO-033 | Define the svchost installation contract in detail: local trusted path only, quoted SCM path, `ServiceDll` validation, host-group assumptions, service account choice, recovery actions, and standalone-blocking invariants | LEDGER-001, LEDGER-016 | TODO-004, TODO-008 | install/update validation proves the exact intended svchost registration and standalone remains blocked |
| P3 | P0 | OPEN | TODO-034 | Define the privilege boundary and session-broker model so elevated service context is limited to lifecycle and trusted session brokerage, with no generic full-elevation mode or reusable elevated child context | LEDGER-014 | TODO-007, TODO-015 | privileged execution is explicit, minimal, audited, and not exposed as a general operator shell |
| P3 | P0 | OPEN | TODO-035 | Define the Session 1 bridge IPC contract using authenticated local IPC, explicit session targeting, correlation IDs, token-handle lifecycle rules, and a deny-by-default action allowlist | LEDGER-008, LEDGER-014 | TODO-007, TODO-016 | the remote-desktop bridge is narrowly scoped and cannot be repurposed into a generic launcher |
| P3 | P0 | OPEN | TODO-036 | Define the localhost relay hardening contract: loopback-only binding, ACL restrictions, upstream identity pinning, trust/hash preservation, retargeting denial, restart/update continuity, and failure evidence | LEDGER-007, LEDGER-018 | TODO-006, TODO-011 | relay behavior is deterministic, auditable, and cannot silently change the intended upstream endpoint |
| P3 | P0 | OPEN | TODO-037 | Refine the pre-protection capture contract to distinguish supported application-managed protections from OS security boundaries, and require explicit failure evidence instead of any bypass attempt when Windows blocks capture or input | LEDGER-013, LEDGER-017 | TODO-030, TODO-018 | capture sequencing remains supported where allowed, and protected desktop/content/input boundaries fail explicitly with evidence |
| P3 | P0 | OPEN | TODO-038 | Define the audit/evidence schema for lifecycle, relay, session brokerage, privilege use, and protection-boundary failures, including separate security and operational logs plus correlation IDs | LEDGER-015, LEDGER-018 | TODO-022, TODO-023, TODO-032 | every security-relevant decision is reconstructible from authoritative logs and evidence artifacts |
| P3 | P1 | OPEN | TODO-039 | Harden install/update package trust and local staging rules: signer validation, local-only service paths, quoted path verification, ACL verification, fail-secure denied-access handling, and secret-free installer logging | LEDGER-005, LEDGER-016 | TODO-019, TODO-022, TODO-032 | package preflight and post-state validation reject unsafe staging and produce deterministic evidence |
| P3 | P1 | OPEN | TODO-040 | Define session-switch ownership rules for the remote-desktop bridge, including `WM_WTSSESSION_CHANGE`/session-notification handling, reattach behavior, teardown, and no-handle-inheritance assumptions across sessions | LEDGER-008, LEDGER-014 | TODO-035 | bridge lifecycle follows session changes deterministically and remote/local desktop transitions do not strand privileged state |
| P4 | P0 | OPEN | TODO-019 | Harden package preflight for `.msh`, `.conf`, optional `.db`, `MasterService.exe`, and staged launcher sidecars | LEDGER-004, LEDGER-005 | TODO-012, TODO-015 | invalid packages fail early, valid packages do not fail on irrelevant sidecar absence |
| P4 | P1 | OPEN | TODO-020 | Close partial-state edge cases: stale service registration, locked payloads, missing sidecars, and interrupted updates | LEDGER-001, LEDGER-002, LEDGER-004 | TODO-010, TODO-015 | lifecycle engine handles partial state deterministically |
| P4 | P1 | OPEN | TODO-021 | Remove or revert non-essential core-agent drift from control-channel, proxy, KVM, and helper-monitor paths while preserving only the explicit `localhost` relay contract, the remote-desktop-only Session 1 bridge, and other required proofs | LEDGER-007, LEDGER-008, LEDGER-009 | TODO-006, TODO-007 | implementation branch retains only the justified `localhost` relay transport, the remote-desktop-only Session 1 bridge, and other requirement-backed deltas |
| P5 | P0 | OPEN | TODO-022 | Finalize native validation outputs for install, update, uninstall, svchost status, and package validation | LEDGER-001, LEDGER-002, LEDGER-005 | TODO-013, TODO-019 | validation commands are authoritative release gates |
| P5 | P0 | OPEN | TODO-023 | Build the full regression harness set: native CLI, JS, GUI, package preflight, and grouped evidence output | LEDGER-005, LEDGER-011 | TODO-022 | every required gate has runnable tooling and summary artifacts |
| P5 | P0 | OPEN | TODO-024 | Implement Playwright coverage for MeshCentral UMH operator desktop and mobile flows | LEDGER-002, LEDGER-006 | TODO-018 | Playwright artifacts exist and validate command construction, dispatch, and result rendering |
| P5 | P0 | OPEN | TODO-031 | Add timestamped native, harness, and operator-path evidence that proves capture completes before screen protections are applied in supported protected-screen flows, and add explicit failure-path evidence when Windows security boundaries deny capture or input | LEDGER-005, LEDGER-013, LEDGER-017 | TODO-023, TODO-024, TODO-030, TODO-037 | regression rows for pre-protection capture pass with capture artifacts and ordered protection-state evidence, while blocked security-boundary cases fail explicitly with evidence |
| P5 | P1 | OPEN | TODO-025 | Implement stress and churn validation for restart, update loops, rollback, and service continuity | LEDGER-001, LEDGER-002, LEDGER-008 | TODO-023 | stress profile passes with bounded retries and complete evidence |
| P5 | P1 | OPEN | TODO-026 | Resolve the historical grouped-run artifact gap so mixed grouped scenarios always write `summary.txt` or an explicit fatal artifact | LEDGER-011 | TODO-023 | grouped harnesses are artifact-complete under all expected outcomes |
| P6 | P0 | OPEN | TODO-027 | Run the full regression matrix and archive evidence in the new 20260331 program namespace | LEDGER-001 through LEDGER-011 | TODO-022 through TODO-026 | every release-blocking row in the regression matrix is green |
| P6 | P0 | OPEN | TODO-028 | Run remote deployment validation with retained `deploy.py` stage, deploy, health, and rollback flows | LEDGER-003 | TODO-027 | deployment path remains functional and evidenced |
| P6 | P1 | OPEN | TODO-029 | Run signature, digest, release checklist, and evidence-bundle export gates | LEDGER-003, LEDGER-010 | TODO-027 | release bundle is auditable and deployment-ready |

## Completion Rule

The program may only be declared complete when:

- all P0 items are `DONE`
- no release-blocking regression row remains unexecuted
- no `DEFAULT REVERT` or `EXCLUDE` ledger item remains unresolved in the implementation branch
- the final evidence set proves install, update, uninstall, the required `localhost` relay connectivity contract, svchost-only standalone blocking, the bounded privilege/session-broker model, UMH lifecycle, protected-screen pre-protection capture ordering, explicit protected-boundary failures without bypass, remote desktop continuity, and deployment health
