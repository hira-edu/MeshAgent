# 2026-03-31 Realignment Regression Matrix

## Coverage Legend

- `REQUIRED`: must run before release
- `MAJORBUG_ONLY`: run when the major-bug profile is required by the gate
- `LIVE_DEPLOY`: must run for deployment qualification
- `ON_CHANGE`: required whenever the named area changes

## Matrix

| Area | Required Gate | Profile | Tooling | Evidence Target | Release Blocker |
|---|---|---|---|---|---|
| Clean install | `-fullinstall` returns `0` on a clean machine and `-validate-install` passes | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_clean_install/` | yes |
| Silent install | silent/non-interactive install uses the same native path and yields the same system state as interactive install | REQUIRED | native CLI plus validation | `docs/testing/evidence/advanced/<ts>_silent_install/` | yes |
| PowerShell-invoked native install | PowerShell entry invokes the native installer path only and completes successfully | REQUIRED | operator invocation plus validation | `docs/testing/evidence/advanced/<ts>_powershell_native_install/` | yes |
| Repair install | install over partial or broken state converges to a healthy installed state | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_repair_install/` | yes |
| Clean update | `-fullupdate` returns `0`, preserves NodeID, and `-validate-update` passes | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_clean_update/` | yes |
| Update over identical version | update on an already-current install is idempotent and healthy | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_idempotent_update/` | yes |
| Update over partial state | update succeeds from stale service registration, stale files, or partial sidecars | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_partial_state_update/` | yes |
| Self-update activation | live self-update path triggers native update flow and converges cleanly | ON_CHANGE | self-update harness plus validation | `docs/testing/evidence/advanced/<ts>_selfupdate_activation/` | yes |
| Clean uninstall | `-fulluninstall` returns `0` and `-validate-uninstall` passes | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_clean_uninstall/` | yes |
| Reinstall loop | install -> validate -> uninstall -> validate -> reinstall -> validate -> update -> validate | REQUIRED | native CLI or JS harness | `docs/testing/evidence/advanced/<ts>_reinstall_loop/` | yes |
| `-svchost-status` | service image path, group, `ServiceDll`, hash, unload-on-stop, and running state are all correct | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_svchost_status/` | yes |
| Service-only enforcement | standalone execution is blocked and only managed/helper entrypoints remain allowed | REQUIRED | native CLI plus negative tests | `docs/testing/evidence/advanced/<ts>_service_only_policy/` | yes |
| Registry state | service keys, parameters, persistence, and policy keys are correct after install/update and absent after uninstall | REQUIRED | validation command | `docs/testing/evidence/advanced/<ts>_registry_validation/` | yes |
| Firewall state | required firewall rules converge after install/update and are absent after uninstall | REQUIRED | validation command | `docs/testing/evidence/advanced/<ts>_firewall_validation/` | yes |
| DACL state | service and file DACLs are correct after install/update | REQUIRED | validation command | `docs/testing/evidence/advanced/<ts>_dacl_validation/` | yes |
| WMI/task persistence | WMI and scheduled-task persistence match policy after install/update and are absent after uninstall | REQUIRED | validation command plus native inspection | `docs/testing/evidence/advanced/<ts>_persistence_validation/` | yes |
| Provisioning parity | staged `.msh` and `.conf` preserve intended endpoint, `ServerID`, and required hash material | REQUIRED | provisioning check plus validation | `docs/testing/evidence/advanced/<ts>_provisioning_parity/` | yes |
| Package preflight | invalid packages fail before system mutation; valid packages succeed regardless of non-required sidecar absence | REQUIRED | package validation plus GUI/CLI runs | `docs/testing/evidence/advanced/<ts>_package_preflight/` | yes |
| Path handling | repo paths, staged paths, paths with spaces, and paths with parentheses all behave correctly | REQUIRED | GUI and CLI harnesses | `docs/testing/evidence/advanced/<ts>_path_handling/` | yes |
| Identity preservation | NodeID and identity artifacts remain stable across update and reinstall | REQUIRED | native CLI plus datastore check | `docs/testing/evidence/advanced/<ts>_identity_preservation/` | yes |
| Restart continuity | service restart exits `0`, returns `RUNNING`, and keeps required readiness | REQUIRED | native CLI | `docs/testing/evidence/advanced/<ts>_restart_continuity/` | yes |
| Reboot continuity | install survives reboot with service running, connectivity intact, and svchost validation healthy | REQUIRED | native CLI plus reboot harness | `docs/testing/evidence/advanced/<ts>_reboot_continuity/` | yes |
| Agent connectivity | service connects through the required `localhost` relay to the configured staged server endpoint and remains connected across restart and update | REQUIRED | native regression plus log/evidence capture | `docs/testing/evidence/advanced/<ts>_connectivity/` | yes |
| Localhost relay integrity | `localhost` relay evidence proves the local hop, the intended upstream endpoint identity, and the preserved trust/hash contract without silent retargeting | REQUIRED | native probe plus connectivity evidence capture | `docs/testing/evidence/advanced/<ts>_localhost_relay_integrity/` | yes |
| Unauthorized session spawn absence | no silent or policy-violating user-session spawn occurs during normal install/update/uninstall/runtime flows | REQUIRED | policy audit plus event/log capture | `docs/testing/evidence/advanced/<ts>_session_spawn_audit/` | yes |
| Remote-desktop Session 1 bridge policy | any Session 1 `rundll32` bridge is exercised only for remote desktop/KVM readiness; PowerShell, terminal, file operations, and arbitrary processes remain blocked from generic Session 1 dispatch | REQUIRED | native policy probe plus major-bug evidence capture | `docs/testing/evidence/advanced/<ts>_session1_bridge_policy/` | yes |
| Remote desktop continuity | remote desktop remains available through restart and update and major-bug self-test passes | MAJORBUG_ONLY | native CLI `--majorBug=1` profile | `docs/testing/evidence/advanced/<ts>_remote_desktop_majorbug/` | yes |
| Terminal/file surfaces | terminal and file operations work when investigating a major bug or regression in those areas | MAJORBUG_ONLY | targeted self-test/harness | `docs/testing/evidence/advanced/<ts>_terminal_file_majorbug/` | conditional |
| UMH install lifecycle | `AdvancedHookService` installs, starts, and reports healthy service state | REQUIRED | native CLI plus service probe | `docs/testing/evidence/advanced/<ts>_umh_install/` | yes |
| UMH update lifecycle | UMH stays healthy across agent update and remains on the expected binary path | REQUIRED | native CLI plus service probe | `docs/testing/evidence/advanced/<ts>_umh_update/` | yes |
| UMH uninstall lifecycle | `AdvancedHookService` and managed binary are absent after uninstall | REQUIRED | native CLI plus absence checks | `docs/testing/evidence/advanced/<ts>_umh_uninstall/` | yes |
| UMH control pipe | pipe connects and `status` succeeds after install/update; pipe is absent after uninstall | REQUIRED | native probe or console probe | `docs/testing/evidence/advanced/<ts>_umh_pipe/` | yes |
| UMH operation matrix | `listProcesses`, `status`, `inject`, `injectAll`, `telemetry`, `repair`, `setFlags`, `disable`, `disableAll`, `getPolicy`, `setPolicy`, `getConfig`, `setConfig`, `lockdownBypass`, and `examsoftBypass` all complete through the supported path | REQUIRED | UMH matrix harness | `docs/testing/evidence/advanced/<ts>_umh_operation_matrix/` | yes |
| UMH injection-profile matrix | all 20 supported injection-profile values are explicitly requested, honored, and evidenced | REQUIRED | UMH matrix harness | `docs/testing/evidence/advanced/<ts>_umh_profile_matrix/` | yes |
| Protected-screen pre-protection capture | supported protected-screen flows produce the required capture artifact before screen protections or blackout behavior are applied, or fail explicitly before protection state changes | REQUIRED | native probe plus UMH/operator harness | `docs/testing/evidence/advanced/<ts>_pre_protection_capture/` | yes |
| UMH operator desktop UI | MeshCentral desktop device page builds and dispatches UMH commands correctly | REQUIRED | Playwright | `docs/testing/evidence/advanced/<ts>_playwright_umh_desktop/` | yes |
| UMH operator mobile UI | MeshCentral mobile device page preserves the same UMH command semantics | REQUIRED | Playwright | `docs/testing/evidence/advanced/<ts>_playwright_umh_mobile/` | yes |
| GUI install/update/uninstall | GUI operator flows succeed across installed/not-installed/update/uninstall states | REQUIRED | GUI harness | `docs/testing/evidence/advanced/<ts>_gui_lifecycle/` | yes |
| GUI dialog capture | unexpected modal dialogs are captured and fail the scenario | REQUIRED | GUI harness | `docs/testing/evidence/advanced/<ts>_gui_dialog_capture/` | yes |
| Grouped-run artifact integrity | grouped harness runs always emit `summary.txt` or an explicit fatal artifact | REQUIRED | GUI and grouped harnesses | `docs/testing/evidence/advanced/<ts>_grouped_artifact_integrity/` | yes |
| Stress churn | repeated install/update/uninstall/restart loops do not leak state or strand services | REQUIRED | stress harness | `docs/testing/evidence/advanced/<ts>_stress_churn/` | yes |
| Rollback safety | failed update/install rollback leaves a healthy prior state or explicit fatal failure with evidence | REQUIRED | fault-injection harness | `docs/testing/evidence/advanced/<ts>_rollback_safety/` | yes |
| Deployment stage/deploy/health | retained `deploy.py` workflow still stages, deploys, and verifies agent binaries remotely | LIVE_DEPLOY | `deploy.py` | `docs/testing/evidence/advanced/<ts>_deploy_py_health/` | yes |
| Deployment rollback | retained `deploy.py rollback` restores the prior remote payload set cleanly | LIVE_DEPLOY | `deploy.py` | `docs/testing/evidence/advanced/<ts>_deploy_py_rollback/` | yes |
| Signer allowlist and digest gates | binaries are signed appropriately and hashes are captured for release | REQUIRED | signer validation plus digest export | `docs/testing/evidence/advanced/<ts>_release_signing/` | yes |
| Evidence-bundle export | final evidence archive is produced and ready for deployment/release records | REQUIRED | packaging step | `docs/testing/artifacts/<ts>_realignment_bundle.zip` | yes |

## Execution Rules

- `REQUIRED` rows must all pass before release.
- `MAJORBUG_ONLY` rows are still release blockers where the standing requirement names the major-bug profile.
- `LIVE_DEPLOY` rows are mandatory before declaring deployment qualification complete.
- Every matrix row must have a reproducible command line or harness invocation recorded in the evidence folder.
