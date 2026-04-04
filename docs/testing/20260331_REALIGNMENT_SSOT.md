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
- `MasterService.exe` and the important UMH control surfaces remain supported, but the UMH binary lifecycle is operator-managed through `umhctl` and not bundled into native agent install/update/uninstall
- MeshAgent production connectivity is relayed through `localhost` to the configured server endpoint, with the relay preserving the intended upstream identity and trust material
- protected-screen target flows preserve an explicit end-to-end capture path that completes before screen protections or blackout behavior are applied
- non-essential branch drift is not carried forward into the implementation baseline
- `deploy.py` remains the retained and supported remote agent deployment tool

## Program Outcome

The target end state is not "make the current drifted branch green."

The target end state is:

1. a clean implementation branch rooted from `origin/main`, with the current working branch/worktree preserved as a reference-only patch source
2. a reviewed keep/port/rewrite/revert ledger for every relevant delta from the drifted branch and dirty worktree
3. a single authoritative lifecycle engine for the Windows agent, plus a separate authoritative UMH operator lifecycle through `umhctl`
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
- Screen capture must remain functional across DWM-composited desktops and secure desktops (UAC/lock screen), using the best available backend (DXGI > WGC > GDI) with automatic fallback. DXGI and WGC respect `SetWindowDisplayAffinity` by design; only IDD (Indirect Display Driver) captures display-affinity-protected content.
- Input injection must deliver keystrokes and mouse events to any window in the user session, including elevated windows, by maintaining SYSTEM integrity level (IL=0x4000) through the Session 0 to Session 1 helper bridge. The real obstacle is Session 0 isolation, not UIPI.
- Tamper detection must correctly classify PPL-protected processes and not raise false alarms for OS-protected system components.

## Retain, Reduce, Remove Policy

| Area | Policy | Direction |
|---|---|---|
| Native svchost installer/update/uninstall | RETAIN AND REWRITE TO SINGLE ENGINE | keep proven behavior, remove duplicated lifecycle paths |
| Native validation commands (`-validate-*`, `-svchost-status`) | RETAIN AND EXPAND | validation becomes a release gate, not a best-effort diagnostic |
| UMH operator lifecycle (`MasterService.exe`, service, pipe probes) | RETAIN AND SEPARATE | UMH remains supported through `umhctl` and control-pipe flows, but it is not part of the native agent package lifecycle |
| UMH operator console/UI flows | RETAIN AFTER CONTRACT REVIEW | keep the important operator path, remove unrelated expansion |
| Pre-protection capture sequencing | RETAIN AND REWRITE | keep the requirement to capture before screen protections apply, but re-implement it as a minimal explicit contract with evidence |
| Provisioning staging (`.msh`, `.conf`, sidecars) | RETAIN | single source of truth, deterministic staging, parity validation |
| NodeID / identity preservation logic | RETAIN | must survive update/reinstall unless explicitly reset |
| svchost installation and service-only enforcement | RETAIN AND REWRITE | selectively port the required svchost install/update/uninstall behavior onto the clean baseline while keeping standalone execution blocked |
| `deploy.py` remote deployment workflow | RETAIN AND HARDEN | remains authoritative deployment tool for agent binaries |
| `RecoveryCore.js` expansion unrelated to UMH | REDUCE | keep only what is necessary for UMH/operator requirements |
| Localhost relay connectivity contract and minimum required control-channel path | RETAIN AND REWRITE | keep the required `localhost` relay transport to the real server endpoint, but remove unrelated networking drift and undocumented proxy behavior |
| Remote-desktop Session 1 `rundll32` bridge | REWRITE | replace current self-exe spawning (`agent->exePath` + `-kvm0`/`-kvm1`) with `rundll32.exe` loading the KVM payload DLL (`MeshService-2022.dll`) in user sessions via `CreateProcessAsUser`; consolidate dual token strategies; apply DACL protection and job-object lifetime management to the spawned process |
| Helper-monitor / user-session spawning infrastructure | DEFAULT DISABLED | no persistent cross-session spawning unless explicitly required and validated |
| Generated binaries, `.tlog`, `.iobj`, `.ipdb`, embedded payload artifacts | EXCLUDE AS SOURCE | build outputs are not implementation truth |
| KVM screen capture backend (GDI) | RETAIN AND EXTEND | add DXGI Desktop Duplication and WGC backends; GDI remains as fallback for pre-Win8 and degraded paths |
| KVM secure-desktop capture | RETAIN AND HARDEN | explicit Winlogon desktop targeting from service context; close the UAC/lock-screen capture gap |
| KVM input injection (`SendInput`) | RETAIN AND HARDEN | verify UIPI integrity chain; add BlockInput override; secure-desktop input path |
| Tamper detection and process monitoring | RETAIN AND EXTEND | add PPL awareness to prevent false tamper alarms on protected processes |
| GPU-accelerated encoding (zero-copy) | NEW (PROVEN PATTERN) | Sunshine-style zero-copy pipeline: shared texture handle + keyed mutex + NVENC; replaces CPU-bound JPEG tiles |
| Indirect Display Driver (IDD) | NEW (PRODUCTION-VIABLE) | UMDF virtual monitor captures below display-affinity enforcement; attestation signing sufficient for Win10/11 client; Citrix shipped in production 2024 |
| Credential Provider integration | NEW (RESEARCH) | authentication-event visibility via sanctioned OS integration point; multiOTP reference; post-release evaluation |
| Service ACL hardening | RETAIN AND HARDEN | deny `WRITE_DAC` to non-SYSTEM; Velociraptor's known LPE proves this matters |
| Firewall rule auto-remediation | NEW | Huntress/Datto pattern: detect and roll back firewall rules blocking agent; defends against common attack vector |

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

### Separate UMH operator model

UMH is not an afterthought, but it is also not part of the agent package shape.

The accepted model is:

- MeshAgent native lifecycle manages only the agent executable, svchost DLL, `.msh`, `.conf`, `.db`, identity, and Windows service/runtime artifacts.
- UMH is published separately for operator download and is installed or removed through `umhctl`.
- Agent lifecycle validation may report UMH state diagnostically, but it may not fail install/update/uninstall solely because an external UMH service exists outside the agent install root.

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

- The Session 1 bridge must use `rundll32.exe` as the host process, loading the agent's KVM payload DLL (built as `StealthLab_DLL` -> `MeshService-2022.dll`) via `rundll32.exe <path>\MeshService-2022.dll,KvmEntryPoint`. Direct self-exe KVM invocation (`agent->exePath` with `-kvm0`/`-kvm1` flags) is outside the retained contract and must be rejected outside the internal `rundll32`-hosted bridge.
- **Why rundll32**: Microsoft-signed trusted binary, already allowlisted by AppLocker/SRP/WDAC, avoids AV/EDR flagging of custom executables in user sessions, leverages the existing DLL build target (`StealthLab_DLL`).
- Two token acquisition strategies exist and must be consolidated into the rundll32 bridge:
  - **ILibProcessPipe** (current upstream): duplicates the service's own SYSTEM token, sets `TokenSessionId` to the target session. Child runs as SYSTEM in the user session. More powerful for capture/input (bypasses UIPI entirely).
  - **stealth_watchdog** (current helper monitor): uses `WTSQueryUserToken` to get the user's token, then `DuplicateTokenEx` with minimum required access rights. Child runs as the user. More secure but may hit UIPI if user is non-elevated.
  - **Recommended for rundll32 bridge**: SYSTEM token approach (Approach B) for KVM/capture/input, since the helper needs SYSTEM IL to inject input into elevated windows and capture the secure desktop.
- The RAMAS (Resilient Adaptive Multi-Attempt Spawn) cascade must be adapted for rundll32: `SPECIFIED_USER` -> `WINLOGON` -> `USER` -> `WINLOGON` fallback with token strategy selection per attempt.
- Desktop targeting: `Winsta0\Winlogon` for secure desktop (WINLOGON spawn type), `winsta0\default` for normal desktop.
- `CreateProcessAsUser` call: `rundll32.exe` as the application, DLL path + entry point as command line, `CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW`, proper `CreateEnvironmentBlock` for user profile.
- Process DACL protection (`Stealth_ProtectProcessByHandle`) must be applied to the spawned rundll32 process immediately after creation to prevent user/lockdown-software termination.
- Job object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) must be assigned so the rundll32 helper is automatically killed when the service stops.
- Named pipe IPC between service (Session 0) and rundll32 helper (Session 1) for KVM data, using the existing pipe infrastructure with `PIPE_TYPE_MESSAGE` framing.
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
- Sidecar rules must be identical across CLI, silent, GUI, staged-launch, and self-update activation paths.

## Program Phases

| Phase | Name | Objective | Exit Gate |
|---|---|---|---|
| P0 | Baseline Freeze | establish clean branch, preserve source snapshots, forbid direct work on drift baseline | implementation branch from `origin/main` exists and patch-source inventory is frozen |
| P1 | Ledger Triage | classify every relevant drift as keep, selective port, rewrite, revert, or exclude | no unknown drift remains in core agent or UMH files |
| P2 | Lifecycle Consolidation | implement single native lifecycle engine for install/update/uninstall/repair | one authoritative lifecycle path is used by all Windows entrypoints |
| P3 | UMH Consolidation | keep the supported UMH control/operator path while removing bundled-agent lifecycle coupling | agent lifecycle stays package-pure and UMH remains operable through `umhctl` |
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

- formalize that `MasterService.exe` is downloaded separately through `umhctl install --url ...`
- keep `AdvancedHookService` install/update/uninstall outside the native agent lifecycle
- verify UMH operator control-pipe behavior independently from agent package install/update/uninstall
- ensure native agent lifecycle ignores external UMH installations except for optional diagnostics and cleanup of legacy stray files under the agent install root
- keep important MeshCentral UMH operator workflows, but strip unrelated drift
- formalize the capture-before-protection contract for supported protected-screen workflows, including explicit failure behavior when pre-protection capture cannot complete

P3 exit gate:

- UMH operator lifecycle is deterministic and fully validated without being bundled into the agent package
- operator path is tied to a documented contract and test coverage
- protected-screen workflows cannot apply protections before capture success or explicit capture failure is recorded

### P4 Edge-Case Hardening

Mandatory work:

- partial-state repair installs
- update over locked or stale payloads
- update over missing or mismatched sidecars
- SCM delete-pending service release before reinstall or validation success
- NodeID preservation across update and reinstall
- service start-type recovery and rollback safety
- native `start`/`restart` control commands must recover managed auto-start drift before retrying service start
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
17. DXGI capture backend produces a valid frame on a DWM-composited desktop capturing DX/GL surfaces and overlays that GDI misses, with GDI fallback engaging cleanly when duplication is unavailable. Note: DXGI respects `SetWindowDisplayAffinity` by design; only IDD captures display-affinity-protected content.
18. Input injection delivers keystrokes to an elevated window from the SYSTEM-IL KVM helper in the user session, and `SendInput` succeeds from the same thread while `BlockInput(TRUE)` is active.
19. Secure-desktop capture produces a frame during an active UAC prompt via explicit `OpenDesktop("Winlogon")` targeting from SYSTEM context.
20. PPL process status is reported in diagnostic output without triggering false tamper alarms.

## Evidence And Documentation Rules

- Every code change must reference a TODO ID and a ledger ID.
- Every completed TODO must point to at least one evidence artifact.
- Every retained drift hunk must point to the source commit or source file that justified the port.
- Every rejected drift area must be documented in the ledger with a reason.
- Summary files under `docs/testing/evidence/advanced/<timestamp>_<name>/summary.txt` are mandatory for every grouped run.

## Screen Protection, Input Blocking, and Elevated-Control Research

The companion roadmap document `docs/testing/20260331_SCREEN_INPUT_ELEVATED_CONTROL_ROADMAP.md` defines the full research and implementation plan for three interconnected capability domains:

### Screen-protection bypass

The current GDI `BitBlt` capture path (`meshcore/KVM/Windows/tile.cpp`) misses DWM-composited content, hardware cursors, and DX/OpenGL surfaces. Applications using `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` produce black frames in ALL userland capture APIs (GDI, DXGI, WGC). The roadmap adds:

- **DXGI Desktop Duplication** (Tier 1) -- captures the DWM-composited frame at GPU level, including DX/GL surfaces and overlays that GDI misses. **Does NOT bypass display affinity** -- this is a common misconception; the DWM enforces affinity at the compositor level. Best-in-class reference: Sunshine (zero-copy GPU texture pipeline with shared handles + `IDXGIKeyedMutex`). Use `DuplicateOutput1` (not `DuplicateOutput`) for HDR format negotiation. Must handle `ACCESS_LOST` with progressive backoff and rotation on portrait displays.
- **Windows.Graphics.Capture** (Tier 1) -- fallback for cross-GPU/hybrid laptop scenarios where DXGI reports `DXGI_ERROR_UNSUPPORTED`. **Cannot capture secure desktop** (UAC/lock screen). Not a primary capture path.
- **Secure desktop capture** (Tier 1) -- explicit `OpenDesktop("Winlogon")` targeting from SYSTEM service context. The ONLY reliable path for UAC prompt and lock screen capture. WGC cannot do this. Listen for `EVENT_SYSTEM_DESKTOPSWITCH` to detect transitions.
- **GPU-accelerated encoding** (Tier 2) -- Sunshine-style zero-copy pipeline: DXGI texture stays on GPU, shared texture handle + `IDXGIKeyedMutex` synchronization, NVENC/AMF/QSV encode directly from GPU texture bypassing FFmpeg. Critical for 60fps+ with minimal CPU.
- **Indirect Display Driver** (Tier 2, production-viable) -- UMDF virtual monitor that receives all composited frames from the DWM below the windowing layer. **The ONLY capture path that bypasses `SetWindowDisplayAffinity`**. Citrix shipped IDD as default capture in CVAD 2212 (2024). Requires attestation signing (NOT WHQL) for Win10/11 client deployment -- significantly lower bar than originally assessed.

### Input-blocking bypass

**Corrected understanding**: The real obstacle for service-level input injection is **Session 0 isolation**, NOT UIPI. UIPI only blocks lower-integrity to higher-integrity; SYSTEM (IL=0x4000) is the highest level and can `SendInput` to any window. Services run in Session 0 which has no interactive desktop -- the solution is spawning a SYSTEM-IL helper in the user's session via `CreateProcessAsUser`. MeshAgent already implements this pattern correctly. The roadmap adds:

- **Session 0 bridge verification** (Tier 1) -- audit that the existing helper bridge (`stealth_watchdog.c` with `WTSQueryUserToken` + `CreateProcessAsUser`) retains SYSTEM integrity through the token chain. Verify `SendInput` reaches elevated windows. This is the universal pattern used by UltraVNC, TightVNC, and every production VNC/RMM tool.
- **BlockInput semantics verification** (Tier 1) -- document the correct `BlockInput` behavior: the calling thread is exempt from its own block (can still `SendInput`); RDP input is not blocked; SYSTEM `BlockInput(FALSE)` overrides application-level blocks. MeshAgent already implements `BlockInput(1)` / `BlockInput(0)` in `kvm.c`.
- **UI Automation framework** (Tier 2) -- structured interaction via `IUIAutomation` for button/control interaction. Does NOT bypass UIPI for raw input -- UIAutomation providers run in the target process via cross-process COM, sidestepping UIPI for control patterns but not for `SendInput`.
- **Virtual HID miniport** (Tier 3, deprioritized) -- no mainstream RMM or VNC tool uses virtual HID for input. The helper-process + `SendInput` pattern is proven and sufficient. Virtual HID exists for game anti-cheat evasion, not RMM.

### Elevated-control posture

The current elevated-control implementation (`stealth_lockdown.c`, `stealth_watchdog.c`, `stealth_persistence.c`) is the most comprehensive in any open-source RMM. Research confirmed that no commercial RMM vendor (ConnectWise, Datto, NinjaOne, Huntress) uses kernel-level self-protection -- all rely on userland mechanisms. The roadmap adds:

- **PPL awareness** (Tier 1) -- detect Protected Process Light status via `NtQueryInformationProcess(ProcessProtectionInformation)` to prevent false tamper alarms. All stable userland PPL bypasses are patched (PPLdump July 2022, PPLFault Feb 2024). Detection-only scope is correct.
- **Early-boot service readiness** (Tier 2) -- capture Winlogon desktop immediately on boot for pre-login support.
- **Credential Provider integration** (Tier 2) -- sanctioned OS integration point for authentication events and remote-unlock. Best reference: multiOTP Credential Provider (production-grade V2, Win7-Win11/Server 2025).
- **Kernel callback protection** (Tier 3, deprioritized) -- `ObRegisterCallbacks` is defeated by BYOVD attacks. No commercial RMM uses it. EDRs use it only in combination with ELAM/PPL, which is restricted to Microsoft antimalware partners. ELAM is not available to RMM tools.
- **Recommended investment instead**: service ACL hardening (Velociraptor has a known LPE via `WRITE_DAC`), firewall rule auto-remediation (Huntress/Datto pattern), atomic upgrade process (defend against BYOI attacks).

### Integration with program phases

| Roadmap Item | Realignment Phase | Ledger Ref | Viability |
|---|---|---|---|
| DXGI Desktop Duplication backend | P3 (alongside KVM rewrite) | LEDGER-014 | Production-proven (Sunshine, OBS, RustDesk) |
| Secure desktop capture hardening | P3 (enhance existing) | LEDGER-014 | Production-proven (UltraVNC, TightVNC) |
| Session 0 bridge verification | P3 (audit existing) | LEDGER-015 | Already implemented; needs verification |
| BlockInput semantics verification | P3 (audit existing) | LEDGER-015 | Already implemented; needs documentation |
| Early-boot service | P3 (service config) | LEDGER-016 | Standard service config |
| WGC capture backend | P4 (cross-GPU fallback) | LEDGER-014 | Production-proven (OBS auto-selection) |
| PPL detection | P4 (diagnostic) | LEDGER-016 | Straightforward API |
| GPU-accelerated encoding | P4-P5 (zero-copy pipeline) | LEDGER-014 | Production-proven (Sunshine gold standard) |
| IDD virtual display | P5 (attestation signing) | LEDGER-014 | **Production-viable** (Citrix shipped 2024) |
| Credential Provider | P5+ (post-release) | LEDGER-016 | Production-viable (multiOTP reference) |
| UI Automation path | P5 (optional structured interaction) | LEDGER-015 | Niche value; not an input bypass |
| Virtual HID | **Deprioritized** | LEDGER-015 | Not needed for RMM; no production use |
| Kernel callbacks | **Deprioritized** | LEDGER-016 | Defeated by BYOVD without ELAM/PPL |

### Open-source best-of-breed references (verified)

| Domain | Top Project | Key Technique | Why Best | License |
|---|---|---|---|---|
| Screen capture | **Sunshine** (LizardByte) | Zero-copy DXGI + shared texture handle + `IDXGIKeyedMutex` + NVENC bypass of FFmpeg | Only project with true GPU-resident capture-to-encode pipeline | GPL-3.0 |
| Screen capture | **OBS Studio** | Smart DXGI/WGC auto-selection + progressive retry + SDR/HDR tone-mapping | Best fallback logic and error recovery; battle-tested | GPL-2.0 |
| Input injection | **MeshAgent** (this project) | Session 0 bridge + cascading token candidates + SendInput + touch + BlockInput + SAS | Already implements the universal VNC/RMM pattern correctly | Apache-2.0 |
| Input injection | **UltraVNC** | WTSQueryUserToken + ImpersonateLoggedOnUser + Winlogon desktop thread | Mature Ctrl+Alt+Del handling; clean token impersonation | GPL-2.0 |
| Elevated control | **MeshAgent** (this project) | 12-feature lockdown + multi-persistence + watchdog mesh + tamper detection | Most comprehensive open-source RMM self-protection | Apache-2.0 |
| Credential provider | **multiOTP** | V2 provider, Win7-Win11/Server 2025, RDP + push token | Best open-source reference for agent credential integration | LGPL-3.0 |
| IDD capture | **Citrix CVAD** | IDD as default HDX capture (2024) | Production-proven at scale; attestation-signed UMDF | Proprietary |

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

- `docs/testing/20260331_SCREEN_INPUT_ELEVATED_CONTROL_ROADMAP.md`

These documents must stay synchronized.
