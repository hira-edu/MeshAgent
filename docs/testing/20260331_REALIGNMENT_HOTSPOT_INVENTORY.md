# 2026-03-31 Realignment Hotspot Inventory

This inventory satisfies `TODO-002` and `TODO-003`.

Scope:

- union diff of `origin/main` against `origin/archive/20260331-main-preclean`
- union diff of `origin/main` against `origin/archive/20260331-touch-gesture-e2e`
- union diff of `origin/main` against `origin/archive/20260331-touch-gesture-e2e-agent`

Source-ref shorthand used below:

- `MP` = `origin/archive/20260331-main-preclean`
- `TG` = `origin/archive/20260331-touch-gesture-e2e`
- `TGA` = `origin/archive/20260331-touch-gesture-e2e-agent`

Classification rule:

- `KEEP`: retain as authoritative on the clean branch
- `SELECTIVE_PORT`: port only requirement-backed hunks
- `REWRITE`: preserve the requirement but re-implement on top of `origin/main`
- `DEFAULT_REVERT`: drop unless a gate later proves the change is required
- `EXCLUDE`: generated artifact or tracked output; never use as patch source
- `REFERENCE_ONLY`: historical/planning context only

## Core Lifecycle, KVM, Networking, and State Files

| File | Source refs | Classification | Ledger | Disposition |
|---|---|---|---|---|
| `meshcore/agentcore.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-001`, `LEDGER-004`, `LEDGER-007` | Rebuild lifecycle, identity, and localhost-relay logic on the clean baseline; port only requirement-backed hunks. |
| `meshcore/KVM/Windows/input.c` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-015` | Retain SYSTEM-IL input, secure-desktop, and `BlockInput` validation work only. |
| `meshcore/KVM/Windows/kvm.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-008`, `LEDGER-014`, `LEDGER-015` | Rebuild desktop targeting, helper/session orchestration, and secure-desktop readiness on the clean branch. |
| `meshcore/KVM/Windows/tile.cpp` | `TG`, `TGA` | `REWRITE` | `LEDGER-014` | Rebuild capture stack as `DXGI -> WGC -> GDI`; do not port GDI-era drift wholesale. |
| `meshservice/ServiceMain.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-001`, `LEDGER-005` | Collapse duplicate entrypoint logic into one lifecycle engine; keep wrapper-only behavior. |
| `meshservice/stealth_cmd.c` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-005`, `LEDGER-016` | Keep authoritative validation/status CLI surfaces only. |
| `meshservice/stealth_firewall.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-017` | Re-implement WFP hard-permit and firewall remediation cleanly; do not trust drifted binary outputs. |
| `meshservice/stealth_installer.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-001`, `LEDGER-004` | Rebuild install/update/uninstall orchestration; selectively port provisioning and package-preflight fixes. |
| `meshservice/stealth_monitor.c` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-016`, `LEDGER-017` | Keep PPL diagnostics and watchdog remediation paths required by the regression matrix. |
| `meshservice/stealth_monitor.h` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-016`, `LEDGER-017` | Port only declarations required by retained monitor/remediation work. |
| `meshservice/stealth_reflective.c` | `TG`, `TGA` | `DEFAULT_REVERT` | `LEDGER-009` | Reflective DLL injection is outside the retained lifecycle, KVM, and deployment requirements. |
| `meshservice/stealth_registry.c` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-004`, `LEDGER-016`, `LEDGER-017` | Keep required registry state, policy, and NRPT support only. |
| `meshservice/stealth_registry.h` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-004`, `LEDGER-016`, `LEDGER-017` | Port only declarations needed by retained registry/state work. |
| `meshservice/stealth_resilience.cpp` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-002` | Retain WMI/task persistence primitives required by install/update/uninstall validation. |
| `meshservice/stealth_resilience.h` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-002` | Port only declarations needed by retained persistence primitives. |
| `meshservice/stealth_state.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-001`, `LEDGER-002`, `LEDGER-004` | Rebuild authoritative state discovery for clean/partial/broken/update/uninstall states. |
| `meshservice/stealth_svchost.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-001`, `LEDGER-008`, `LEDGER-014` | Rebuild svchost-only entry, exported session bridge, and capture/input glue on the clean branch. |
| `meshservice/stealth_watchdog.c` | `TG`, `TGA` | `REWRITE` | `LEDGER-008`, `LEDGER-009`, `LEDGER-017` | Rebuild rundll32/session-management behavior and revert generic user-session spawn drift. |
| `meshservice/stealth.h` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-002`, `LEDGER-017` | Port only shared declarations required by retained modules. |
| `meshservice/svchost_payload.c` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-010` | Keep minimal source-backed payload embedding flow; generated payload binaries remain excluded. |
| `microstack/ILibProcessPipe.c` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-008`, `LEDGER-009` | Keep only remote-desktop-only session bridge primitives; revert generic session-spawn expansion. |
| `modules/RecoveryCore.js` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-002`, `LEDGER-006`, `LEDGER-013` | Retain UMH control-pipe and protected-screen operator surfaces only. |

## Supporting Install, Deployment, Test, and Process Files

| File | Source refs | Classification | Ledger | Disposition |
|---|---|---|---|---|
| `.gitignore` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-010` | Port only ignore rules that keep evidence/artifacts out of implementation-truth decisions. |
| `AGENTS.md` | `TG`, `TGA` | `KEEP` | process control | Keep the repo execution instructions on the clean branch. |
| `deploy.py` | `MP`, `TGA` | `KEEP` | `LEDGER-003` | Authoritative remote deployment tool; retain and harden only where required by gates. |
| `docs/DEPLOYMENT.md` | `MP`, `TGA` | `KEEP` | `LEDGER-003` | Keep deployment documentation aligned to retained `deploy.py` flow. |
| `modules/agent-installer.js` | `MP`, `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-005` | Keep native-entrypoint enforcement and path-handling fixes only. |
| `modules/agent-selftest.js` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-005` | Keep harness behavior required by release-gate validation. |
| `modules/service-manager.js` | `MP`, `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-002`, `LEDGER-005` | Keep service lifecycle and path-handling fixes tied to operator outcomes. |
| `modules/update-helper.js` | `MP`, `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-001`, `LEDGER-004`, `LEDGER-005` | Keep update/package-preflight helpers tied to retained lifecycle gates. |
| `modules/win-authenticode-opus.js` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-003`, `LEDGER-005` | Keep only signing and digest support needed by release qualification. |
| `test_umhctl_e2e.js` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-002`, `LEDGER-006` | Retain the UMH control-path validation harness. |
| `test/run_umh_type4_matrix.js` | `TG`, `TGA` | `SELECTIVE_PORT` | `LEDGER-002`, `LEDGER-006` | Retain the UMH operation/profile matrix harness. |
| `tools/http_connect_tunnel.py` | `MP`, `TGA` | `KEEP` | `LEDGER-003` | Keep as retained deployment support tooling. |
| `tools/meshcentral_update_agents.js` | `MP`, `TGA` | `DEFAULT_REVERT` | `LEDGER-003` | Not part of the retained deployment gate; drop unless a release gate later proves dependency. |

## Reference-only Docs

| File | Source refs | Classification | Ledger | Disposition |
|---|---|---|---|---|
| `docs/REPO_SYNC_AND_DEPLOYMENT_PLAN.md` | `TG`, `TGA` | `REFERENCE_ONLY` | `LEDGER-011` | Historical planning context only; not authoritative for implementation. |
| `docs/UMH_OPERATOR_PANEL_SSOT.md` | `TG`, `TGA` | `REFERENCE_ONLY` | `LEDGER-011` | Historical/operator design reference only; TODO-018 must define the retained contract explicitly. |

## Generated Artifacts and Tracked Build Outputs

These paths are explicitly excluded from code-port decisions. They may be rebuilt for validation, but they are never accepted as implementation truth or patch sources.

| File | Source refs | Classification | Ledger | Disposition |
|---|---|---|---|---|
| `meshservice/embedded/svchost_payload.dll` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Generated payload binary; source-backed rebuild only. |
| `meshservice/MeshService-2022/x64/StealthLab_DLL/MeshService-2022.tlog/CL.command.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Compiler tracking log; never use as patch source. |
| `meshservice/MeshService-2022/x64/StealthLab_DLL/MeshService-2022.tlog/CL.read.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Compiler tracking log; never use as patch source. |
| `meshservice/MeshService-2022/x64/StealthLab_DLL/MeshService-2022.tlog/CL.write.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Compiler tracking log; never use as patch source. |
| `meshservice/MeshService-2022/x64/StealthLab_DLL/MeshService-2022.tlog/link.read.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Link tracking log; never use as patch source. |
| `meshservice/MeshService-2022/x64/StealthLab_DLL/MeshService-2022.tlog/rc.read.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Resource compiler tracking log; never use as patch source. |
| `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Built DLL output; source-backed rebuild only. |
| `meshservice/x64/StealthLab_DLL/MeshService-2022.exp` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Linker export artifact; source-backed rebuild only. |
| `meshservice/x64/StealthLab_DLL/MeshService-2022.lib` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Import library artifact; source-backed rebuild only. |
| `meshservice/x64/StealthLab/MeshService-2022.iobj` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Incremental link artifact; never use as patch source. |
| `meshservice/x64/StealthLab/MeshService-2022.ipdb` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Incremental PDB artifact; never use as patch source. |
| `meshservice/x64/StealthLab/MeshService-2022.tlog/CL.command.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Compiler tracking log; never use as patch source. |
| `meshservice/x64/StealthLab/MeshService-2022.tlog/CL.read.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Compiler tracking log; never use as patch source. |
| `meshservice/x64/StealthLab/MeshService-2022.tlog/CL.write.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Compiler tracking log; never use as patch source. |
| `meshservice/x64/StealthLab/MeshService-2022.tlog/link.command.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Link tracking log; never use as patch source. |
| `meshservice/x64/StealthLab/MeshService-2022.tlog/link.read.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Link tracking log; never use as patch source. |
| `meshservice/x64/StealthLab/MeshService-2022.tlog/rc.read.1.tlog` | `TG`, `TGA` | `EXCLUDE` | `LEDGER-010` | Resource compiler tracking log; never use as patch source. |

## Outcome

- Every divergent hotspot and support file from the archived patch sources is classified once.
- All tracked binaries, `.tlog` files, and other build outputs are explicitly marked `EXCLUDE`.
- The clean branch may now port only from the files marked `KEEP`, `SELECTIVE_PORT`, or `REWRITE`, and only against the matching ledger/todo gates.
