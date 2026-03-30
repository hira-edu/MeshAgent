# 2026-03-31 Agent Runtime Realignment SSOT

## Authority

This document is the authoritative implementation-direction SSOT for the MeshAgent realignment program starting on 2026-03-31.

It supersedes the following documents where they conflict on forward implementation direction:

- `docs/testing/20260324_AUDIT_SSOT.md`
- `docs/testing/20260324_TODO_MATRIX.md`
- `docs/testing/20260324_BUG_LEDGER.md`
- `docs/testing/20260324_REGRESSION_MATRIX.md`

Historical evidence and historical findings in the superseded documents remain reference material. They do not define the new implementation baseline.

The following documents remain authoritative in their own domains:

- `docs/DEPLOYMENT.md`
- `docs/testing/ADVANCED_DEBUG_TOOLCHAIN.md`

## Objective

Deliver a production-grade MeshAgent service package with the following properties:

- install, update, reinstall, repair, and uninstall are deterministic, idempotent, and fully validated
- svchost service mode is the only supported runtime mode for the shipped Windows agent
- operator-facing GUI, silent mode, CLI mode, and PowerShell-invoked entry all execute the same native lifecycle engine
- `MasterService.exe` and the important UMH control surfaces remain supported, staged, validated, updated, and removed in lockstep with the agent
- MeshAgent production connectivity is relayed through `localhost` to the configured server endpoint, with the relay preserving the intended upstream identity and trust material
- protected-screen target flows preserve an explicit end-to-end capture path that completes before screen protections or blackout behavior are applied
- non-essential branch drift is not carried forward into the implementation baseline
- `deploy.py` remains the retained and supported remote agent deployment tool

## Program Outcome

The target end state is not "make the current drifted branch green."

The target end state is:

1. a clean implementation branch rooted from `origin/main`, with the current working branch/worktree preserved as a reference-only patch source
2. a reviewed keep/port/rewrite/revert ledger for every relevant delta from the drifted branch and dirty worktree
3. a single authoritative lifecycle engine for agent and UMH companion management
4. a complete regression and evidence system that proves the retained behavior, edge cases, and deployment path

## Baseline Strategy

### Clean implementation baseline

- Code baseline: `origin/main`
- Current known baseline tip at planning time: `47ec66a850c29a88cc67c3f09b0171d59d0f3bd4`
- Planned implementation branch: `realignment-origin-main`
- The current working branch/worktree is preserved as a reference-only patch source; new implementation work lands on the clean branch created from `origin/main`

### Patch-source candidates

The following sources may contain changes worth selectively porting:

- `origin/archive/20260331-touch-gesture-e2e-agent` (`0f46af83ded71c5eb7e057e05f51c11009a41780`)
- `origin/archive/20260331-touch-gesture-e2e` (`bf5f684a7f057148b384081ca103f2d0b37d28ac`)
- `origin/archive/20260331-main-preclean` (`863b8774eca1ca2bd675027423dff3eaea4fb2ff`)
- current uncommitted edits in:
  - `meshcore/agentcore.c`
  - `meshservice/ServiceMain.c`
  - `meshservice/stealth_installer.c`
  - `microstack/ILibProcessPipe.c`
  - related supporting files

### Prohibited baseline shortcut

The implementation program may not accept the current preserved branch/worktree or any archived drift ref as the new baseline by default.

Each retained behavior must be justified by:

- an explicit product requirement
- a bug with current evidence
- an acceptance gate in the regression matrix
- a ledger entry that names the source commit or source file

## Immutable Product Requirements

- Service mode only on Windows.
- svchost-hosted runtime only for the shipped Windows service.
- No standalone agent execution in the shipped svchost build.
- Silent and GUI install/update/uninstall must converge onto the same native lifecycle implementation.
- PowerShell-invoked operator entry remains supported, but PowerShell may only invoke native entrypoints. It may not implement runtime or lifecycle logic.
- Provisioning `.msh` and `.conf` staging must preserve intended `MeshServer`, `ServerID`, and required hash material.
- MeshAgent production connectivity must use the supported `localhost` relay path to reach the configured server endpoint; the relay may not change the intended upstream server identity or trust contract.
- Install/update must preserve identity unless an explicit migration/reset operation is requested and logged.
- Registry, firewall, DACL, WMI, service recovery, and persistence artifacts must be correct after install and update, and absent after uninstall.
- Remote desktop availability and restart/update continuity remain required release gates.
- UMH integration remains in scope and must stay first-class.
- Where screen protections are part of the supported target flow, capture must occur before those protections are applied, or the flow must fail explicitly before protection state is mutated.
- `deploy.py` remains in scope and will be kept.

## Retain, Reduce, Remove Policy

| Area | Policy | Direction |
|---|---|---|
| Native svchost installer/update/uninstall | RETAIN AND REWRITE TO SINGLE ENGINE | keep proven behavior, remove duplicated lifecycle paths |
| Native validation commands (`-validate-*`, `-svchost-status`) | RETAIN AND EXPAND | validation becomes a release gate, not a best-effort diagnostic |
| UMH native lifecycle (`MasterService.exe`, service, pipe probes) | RETAIN | companion lifecycle is mandatory and tied to agent lifecycle |
| UMH operator console/UI flows | RETAIN AFTER CONTRACT REVIEW | keep the important operator path, remove unrelated expansion |
| Pre-protection capture sequencing | RETAIN AND REWRITE | keep the requirement to capture before screen protections apply, but re-implement it as a minimal explicit contract with evidence |
| Provisioning staging (`.msh`, `.conf`, sidecars) | RETAIN | single source of truth, deterministic staging, parity validation |
| NodeID / identity preservation logic | RETAIN | must survive update/reinstall unless explicitly reset |
| svchost installation and service-only enforcement | RETAIN AND REWRITE | selectively port the required svchost install/update/uninstall behavior onto the clean baseline while keeping standalone execution blocked |
| `deploy.py` remote deployment workflow | RETAIN AND HARDEN | remains authoritative deployment tool for agent binaries |
| `RecoveryCore.js` expansion unrelated to UMH | REDUCE | keep only what is necessary for UMH/operator requirements |
| Localhost relay connectivity contract and minimum required control-channel path | RETAIN AND REWRITE | keep the required `localhost` relay transport to the real server endpoint, but remove unrelated networking drift and undocumented proxy behavior |
| Remote-desktop Session 1 desktop bridge | RETAIN AND REWRITE | keep only the explicit `rundll32`-based Session 1 bridge required for remote desktop/KVM readiness; revert generic desktop-spawn rewrites |
| Helper-monitor / user-session spawning infrastructure | DEFAULT DISABLED | no persistent cross-session spawning unless explicitly required and validated |
| Generated binaries, `.tlog`, `.iobj`, `.ipdb`, embedded payload artifacts | EXCLUDE AS SOURCE | build outputs are not implementation truth |

## Required Architectural Shape

### Single lifecycle engine

The Windows lifecycle implementation must converge into one native orchestration model:

1. `DiscoverCurrentState`
2. `BuildTransitionPlan`
3. `StageArtifacts`
4. `QuiesceRuntime`
5. `ApplyServiceAndSystemState`
6. `StartOrRemove`
7. `ValidatePostState`
8. `CommitOrRollback`
9. `EmitStructuredEvidence`

There may be multiple entrypoints, but there may not be multiple independent implementations of install/update/uninstall semantics.

### Managed companion model

UMH is not an afterthought. It must be represented in the lifecycle engine as a managed companion component with the same operation phases:

- discover
- stage
- install or update
- verify running state
- verify control pipe readiness
- uninstall and verify absence

### Pre-protection capture contract

Supported protected-screen flows must obey an explicit sequencing contract:

1. resolve the target and capture scope
2. prove capture readiness
3. perform the required end-to-end capture
4. persist capture evidence with timestamps and target identity
5. only then apply screen protections, blackout behavior, or equivalent target-hardening actions

There may not be a silent race where protection state is applied first and capture success is inferred later.

### Explicit transport boundaries

- MeshAgent production connectivity must follow the path `agent -> localhost relay -> configured server endpoint`.
- The configured upstream server endpoint, `ServerID`, and trust/hash material still come from staged provisioning and remain the source of truth for the connection contract.
- The `localhost` relay is part of the supported production transport path, not a test-only or helper-only exception.
- The relay may not silently retarget traffic to an unintended upstream endpoint, bypass provisioning identity, or weaken the expected trust validation semantics.
- Any user-session transition must be feature-scoped, explicit, logged, and justified by a release gate.

### Remote-desktop Session 1 boundary

- If a user-session bridge is required for remote desktop readiness, it must be an explicit service-owned `rundll32` Session 1 bridge.
- That Session 1 bridge is only for remote desktop/KVM readiness and related capture/control requirements that are explicitly gated.
- PowerShell, terminal, file operations, update/install logic, helper monitors, and arbitrary child-process launch may not use the Session 1 `rundll32` path.
- Standalone agent execution remains blocked; the desktop bridge does not create a second standalone runtime mode.

## Engineering Guardrails

### Code quality

- No workarounds, temporary fixes, compatibility shims, or silent fallbacks.
- No "best effort" success reporting for required artifacts.
- No alternate code path may be added unless it is a documented fallback with deterministic logging and validation.
- Every rollback path must be bounded, explicit, and validated.
- Every file, registry, firewall, and service mutation must have a corresponding state validation check.

### Change-control

- No direct implementation on top of the drifted branch.
- No blind cherry-pick of broad commits.
- No port of a hunk without a ledger entry.
- No code merge without a matching regression-matrix row and an evidence destination.
- No release if the SSOT, TODO matrix, ledger, and regression matrix are not updated in the same change series as the code.

### Runtime policy

- Default policy is strict service-only behavior.
- Desktop bridge behavior, if kept, must be minimized and explicit.
- Any helper monitor or user-session spawn path must be disabled unless the feature-specific gate requires it.
- Any new flag or environment variable that alters lifecycle or transport behavior must be added to this SSOT before it is accepted.

### Packaging

- Package preflight must reject incomplete packages before mutating system state.
- `.db` sidecar absence may not break supported operator packages unless the package genuinely requires a pre-seeded identity.
- `MasterService.exe` source resolution must be deterministic and validated.
- Sidecar rules must be identical across CLI, silent, GUI, staged-launch, and self-update activation paths.

## Program Phases

| Phase | Name | Objective | Exit Gate |
|---|---|---|---|
| P0 | Baseline Freeze | establish clean branch, preserve source snapshots, forbid direct work on drift baseline | implementation branch from `origin/main` exists and patch-source inventory is frozen |
| P1 | Ledger Triage | classify every relevant drift as keep, selective port, rewrite, revert, or exclude | no unknown drift remains in core agent or UMH files |
| P2 | Lifecycle Consolidation | implement single native lifecycle engine for install/update/uninstall/repair | one authoritative lifecycle path is used by all Windows entrypoints |
| P3 | UMH Consolidation | integrate `MasterService.exe` lifecycle into the same engine | agent and UMH pass shared lifecycle gates |
| P4 | Edge-Case Hardening | close packaging, identity, service-state, and partial-state edge cases | all planned edge cases have deterministic behavior and tests |
| P5 | Validation And Harness | finalize CLI, JS, GUI, Playwright, and stress harnesses | regression matrix is fully runnable and evidence-complete |
| P6 | Release Qualification | run full local and live deployment gates, package evidence, and sign off | full matrix passes and deployment health is green |

## Phase Detail

### P0 Baseline Freeze

Mandatory work:

- create a new implementation branch from `origin/main`
- preserve the current working branch/worktree as a reference-only patch source
- capture the exact source commits and dirty files that may be mined for retained logic
- freeze the broad drift branch as a reference, not a delivery target
- confirm that generated build outputs are excluded from source-of-truth reasoning

P0 exit gate:

- source inventory complete
- no implementation commits yet beyond documentation and inventory

### P1 Ledger Triage

Mandatory work:

- build a file-by-file and subsystem-by-subsystem keep/revert ledger
- isolate the minimum required UMH deltas
- isolate the minimum required svchost lifecycle deltas
- explicitly classify the following hotspots:
  - `meshcore/agentcore.c`
  - `meshservice/ServiceMain.c`
  - `meshservice/stealth_installer.c`
  - `modules/RecoveryCore.js`
  - `microstack/ILibProcessPipe.c`
  - `meshcore/KVM/Windows/*`
  - `meshservice/stealth_watchdog.c`

P1 exit gate:

- no hotspot remains unclassified
- no "keep for now" ambiguity remains in core lifecycle or networking paths

### P2 Lifecycle Consolidation

Mandatory work:

- implement authoritative state discovery for installed, partial, broken, pending-update, and companion-service states
- unify GUI, CLI, silent, and PowerShell-invoked flows onto the same engine
- remove duplicate lifecycle branches where possible
- make update activation use native lifecycle orchestration, not ad hoc replacement logic
- ensure uninstall is a first-class inverse transition with negative validation

P2 exit gate:

- install, update, repair, reinstall, and uninstall share one lifecycle engine
- lifecycle engine emits structured validation output and deterministic logs

### P3 UMH Consolidation

Mandatory work:

- formalize `MasterService.exe` source resolution and staging rules
- keep `AdvancedHookService` install/update/uninstall bound to the agent lifecycle
- verify control pipe readiness after install and update
- verify service absence and pipe absence after uninstall
- keep important MeshCentral UMH operator workflows, but strip unrelated drift
- formalize the capture-before-protection contract for supported protected-screen workflows, including explicit failure behavior when pre-protection capture cannot complete

P3 exit gate:

- UMH lifecycle is deterministic and fully validated
- operator path is tied to a documented contract and test coverage
- protected-screen workflows cannot apply protections before capture success or explicit capture failure is recorded

### P4 Edge-Case Hardening

Mandatory work:

- partial-state repair installs
- update over locked or stale payloads
- update over missing or mismatched sidecars
- NodeID preservation across update and reinstall
- service start-type recovery and rollback safety
- path handling with spaces, parentheses, staging roots, and install-root scenarios
- stale service registration and stale firewall/DACL cleanup

P4 exit gate:

- every listed edge case has deterministic behavior, logging, and a regression row

### P5 Validation And Harness

Mandatory work:

- native CLI regression coverage
- JS harness coverage
- GUI regression harness coverage with dialog capture
- Playwright operator coverage for UMH desktop and mobile surfaces
- explicit capture-before-protection timing coverage with timestamped artifacts and failure-path evidence
- stress harness for repeated install/update/uninstall/restart loops
- evidence schema and summary-file contract enforcement

P5 exit gate:

- every required gate in the regression matrix has runnable tooling and an evidence target

### P6 Release Qualification

Mandatory work:

- run full local regression matrix
- run required major-bug profile for remote desktop continuity
- run required live deployment and rollback health checks
- validate signatures, digests, and packaged evidence bundle
- update release checklist and deployment record

P6 exit gate:

- zero open P0 or P1 items
- zero release-blocking ledger items
- full evidence bundle attached under `docs/testing/evidence/advanced/`

## Acceptance Gates

The program is incomplete until all of the following are true:

1. `-fullinstall`, `-fullupdate`, and `-fulluninstall` return success and pass validation.
2. Silent, GUI, CLI, and PowerShell-invoked operator flows all converge to the same lifecycle engine.
3. svchost-only runtime is enforced and validated.
4. NodeID is preserved across update and reinstall unless explicitly reset.
5. `.msh` and `.conf` staging fidelity is preserved.
6. MeshAgent connectivity proves the required `localhost` relay hop while preserving the intended upstream server identity and persistence across restart and update.
7. Registry, firewall, DACL, WMI, service recovery, and persistence checks pass.
8. `AdvancedHookService` lifecycle and control-pipe readiness pass after install and update.
9. `AdvancedHookService` is absent after uninstall.
10. MeshCentral operator UMH path passes console and Playwright coverage.
11. Supported protected-screen flows prove end-to-end capture before screen protections are applied, or fail explicitly before protection state changes.
12. Remote desktop readiness and restart/update continuity pass the major-bug profile, with any Session 1 `rundll32` bridge limited to that feature scope.
13. No unauthorized user-session process spawn path is introduced or retained silently, including PowerShell or arbitrary-process Session 1 dispatch.
14. Standalone agent execution remains blocked in the shipped service build.
15. `deploy.py` stage, deploy, health, and rollback workflows remain functional.
16. Full evidence is written under `docs/testing/`.

## Evidence And Documentation Rules

- Every code change must reference a TODO ID and a ledger ID.
- Every completed TODO must point to at least one evidence artifact.
- Every retained drift hunk must point to the source commit or source file that justified the port.
- Every rejected drift area must be documented in the ledger with a reason.
- Summary files under `docs/testing/evidence/advanced/<timestamp>_<name>/summary.txt` are mandatory for every grouped run.

## Explicit Non-Goals

The following are not acceptable as "scope convenience" changes:

- broadening core agent networking behavior without a reproduced bug
- broadening KVM or session-spawn behavior without a reproduced bug
- turning the Session 1 `rundll32` bridge into a generic launcher for PowerShell, terminal, file operations, or arbitrary processes
- inventing undocumented localhost transport behavior that bypasses the required relay contract or changes the intended upstream endpoint
- preserving broad `RecoveryCore.js` expansion just because it already exists
- turning deployment tooling into runtime logic
- allowing build outputs or tracked binaries to become implementation truth

## Document Set For This Program

The authoritative companion documents are:

- `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md`
- `docs/testing/20260331_REALIGNMENT_LEDGER.md`
- `docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md`

These documents must stay synchronized.
