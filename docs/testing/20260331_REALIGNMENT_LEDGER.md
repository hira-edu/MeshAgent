# 2026-03-31 Realignment Ledger

## Status Key

- `KEEP`: preserve as-is conceptually, though implementation may still be cleaned up
- `SELECTIVE_PORT`: port only reviewed, requirement-backed hunks
- `REWRITE`: preserve the requirement, but re-implement on the clean baseline
- `DEFAULT_REVERT`: remove unless a reproduced bug or gate proves the change is needed
- `EXCLUDE`: do not treat as implementation source
- `REFERENCE_ONLY`: keep as historical context only

## Ledger

| ID | Status | Area | Current Source Candidates | Policy | Why | Closure Gate |
|---|---|---|---|---|---|---|
| LEDGER-001 | REWRITE | Native Windows lifecycle engine | `meshservice/stealth_installer.c`, `meshservice/ServiceMain.c`, `meshcore/agentcore.c`, plus current worktree edits | preserve the product requirement but rebuild around one authoritative lifecycle engine on top of `origin/main` | install/update/uninstall behavior is in scope, but current logic is spread across broad drift and duplicate entry paths | clean implementation branch has one lifecycle engine and full regression passes |
| LEDGER-002 | SELECTIVE_PORT | UMH companion lifecycle and operator path | `modules/RecoveryCore.js`, `meshcore/agentcore.c`, `meshservice/stealth_installer.c`, `modules/service-manager.js`, `test_umhctl_e2e.js`, `test/run_umh_type4_matrix.js` | keep `MasterService.exe` lifecycle, control-pipe validation, and important operator surfaces; port only the requirement-backed subset | UMH is explicitly required, but the current branch also expanded non-essential console/runtime surfaces | retained UMH surface is documented, minimal, and fully validated |
| LEDGER-003 | KEEP | Remote deployment tooling | `deploy.py`, `tools/http_connect_tunnel.py`, related deployment docs | retain `deploy.py` as the authoritative remote agent deployment tool and harden it only where needed | user explicitly wants to keep deployment tooling and it is operationally important | `deploy.py` stage/deploy/health/rollback pass and remain documented |
| LEDGER-004 | SELECTIVE_PORT | Provisioning, package staging, NodeID preservation | `meshservice/stealth_installer.c`, `meshcore/agentcore.c`, `meshservice/ServiceMain.c` | keep provisioning parity, sidecar staging, package preflight, and identity preservation logic that is explicitly tied to release gates | these behaviors are core requirements and some current fixes appear valuable, but they must be re-landed on a clean baseline | `.msh`/`.conf` parity, NodeID preservation, and package validation all pass |
| LEDGER-005 | SELECTIVE_PORT | GUI/package preflight and harness hardening | `meshservice/ServiceMain.c`, `test/gui_button_race_harness/Program.cs`, package validation paths | keep valid package-preflight and dialog-capture work, but only in the minimal form required to guarantee operator outcomes | operator-facing robustness is required, but must not drag unrelated runtime drift into core agent logic | GUI/package validation rows in the regression matrix pass with complete artifacts |
| LEDGER-006 | SELECTIVE_PORT | `RecoveryCore.js` and MeshCentral UMH operator surfacing | `modules/RecoveryCore.js` and linked operator/test paths | retain only UMH and required operator/control-pipe functionality; remove unrelated expansion, redundant console behavior, and broad drift | current file changed heavily and is a high-risk drift accumulator | retained console/operator contract is documented and Playwright-tested |
| LEDGER-007 | REWRITE | Core agent localhost-relay connectivity contract and related control-channel surface | `meshcore/agentcore.c`, related networking hunks | preserve only the explicit `agent -> localhost relay -> configured server endpoint` requirement and re-implement the minimum transport surface on the clean baseline; revert unrelated networking drift | user clarified that MeshAgent connectivity must be relayed through `localhost`, but broad proxy/control-channel drift is still not justified as-is | clean implementation branch contains only the required relay transport and explicit validation of upstream identity/trust |
| LEDGER-008 | REWRITE | Remote-desktop Session 1 bridge, KVM readiness path, and minimal desktop-spawn surface | `meshcore/KVM/Windows/*`, `microstack/ILibProcessPipe.c`, related service/session-spawn changes | preserve only the explicit `rundll32`-based Session 1 bridge required for remote desktop/KVM readiness and re-implement it minimally on the clean baseline; revert generic desktop-spawn drift | remote desktop continuity is required, but branch-wide KVM/session-spawn rewrites are too broad and must be reduced to a narrow feature-scoped bridge | only the remote-desktop-required Session 1 bridge remains and major-bug profile passes |
| LEDGER-009 | DEFAULT_REVERT | Helper-monitor and broad user-session spawn infrastructure | `meshservice/stealth_watchdog.c`, `microstack/ILibProcessPipe.c`, policy env handling | keep default strict service-only policy; do not preserve persistent helper spawning unless explicitly required | broad session-spawn infrastructure is high-risk drift and must not silently survive | any retained user-session spawn path is explicit, minimal, logged, and validated |
| LEDGER-010 | EXCLUDE | Generated binaries and build artifacts | tracked `.dll`, `.iobj`, `.ipdb`, `.tlog`, embedded payload outputs | never use tracked build outputs as implementation truth or patch source | industrial process requires source-based reasoning and reproducible builds | no implementation decision cites build artifacts as source truth |
| LEDGER-011 | REFERENCE_ONLY | Historical audit docs and evidence sets | `20260324_*` docs, older plan docs, historical evidence | retain as historical context only | they remain useful, but they do not define the new implementation baseline | new program docs fully replace them for forward direction |
| LEDGER-012 | SELECTIVE_PORT | Current dirty worktree changes | current modified files in the working tree | no blind merge; port only individually reviewed hunks that match program requirements | current worktree contains both promising fixes and unmanaged drift | every retained hunk is traced to a TODO, a gate, and a source rationale |
| LEDGER-013 | REWRITE | Protected-screen capture sequencing | UMH operator paths, capture/injection orchestration, and supporting native timing/state code | keep the product requirement to capture before screen protections apply, but re-implement it as a minimal explicit sequencing contract | this is an end-to-end requirement, but the current broad drift does not justify carrying forward unmanaged timing and operator complexity wholesale | protected-screen flows prove ordered capture-before-protection behavior in the regression matrix |

## Immediate Interpretation

- `LEDGER-001`, `LEDGER-002`, `LEDGER-003`, `LEDGER-004`, and `LEDGER-005` are the required retained value.
- `LEDGER-006` is in-scope but must be reduced.
- `LEDGER-007`, `LEDGER-008`, and `LEDGER-009` are the primary networking/session drift control points; `LEDGER-007` preserves only the explicit `localhost` relay requirement and `LEDGER-008` preserves only the remote-desktop-only Session 1 bridge.
- `LEDGER-010` and `LEDGER-011` define what may not become implementation truth.
- `LEDGER-012` blocks unmanaged carry-forward from the current dirty worktree.
- `LEDGER-013` makes capture-before-protection sequencing an explicit requirement instead of an implied side effect.

## Review Rule

No code port is accepted until the port note records:

- the ledger ID
- the source commit or source file
- the target requirement
- the matching regression-matrix gate
