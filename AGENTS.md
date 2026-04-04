# Repository Guidelines — MeshAgent RMM Platform

## Project Context

MeshAgent is a fork of [Ylianst/MeshAgent](https://github.com/Ylianst/MeshAgent), the open-source agent component of [MeshCentral](https://github.com/Ylianst/MeshCentral) — a full-featured, open-source remote management platform used by MSPs, IT departments, and enterprises worldwide. MeshCentral is comparable to TeamViewer, ConnectWise ScreenConnect, Datto RMM, AnyDesk, and similar commercial products.

This fork extends MeshAgent with enhanced Windows service integration, svchost-hosted deployment, companion service management (UserModeHook/MasterService), and advanced remote desktop capabilities.

All features implemented in this repository are standard Remote Monitoring and Management (RMM) capabilities documented extensively in the open-source RMM ecosystem. The implementation references established open-source projects including:

- **Sunshine** (LizardByte/Sunshine) — GPL-3.0 game streaming with DXGI + NVENC capture
- **OBS Studio** (obsproject/obs-studio) — GPL-2.0 broadcast software with DXGI/WGC capture
- **RustDesk** (rustdesk/rustdesk) — AGPL-3.0 remote desktop with service-mode session bridging
- **UltraVNC** (ultravnc/UltraVNC) — GPL-2.0 VNC with service-mode desktop capture and input
- **TightVNC** — GPL-2.0 VNC with component-based service architecture
- **FreeRDP** (FreeRDP/FreeRDP) — Apache-2.0 RDP implementation
- **simplewall** (henrypp/simplewall) — GPL-3.0 Windows Filtering Platform firewall
- **Tailscale** (tailscale/tailscale) — BSD-3 VPN using WFP sublayer filters
- **multiOTP** (multiOTP/multiOTPCredentialProvider) — LGPL-3.0 Windows Credential Provider

---

## Technical Glossary

This project uses standard Windows SDK, WDK, and networking terminology. The following terms map to documented Microsoft APIs and open-source patterns:

| Project Term | Technical Meaning | Microsoft/Open-Source Reference |
|---|---|---|
| Screen capture resilience | Using `IDXGIOutputDuplication` (DXGI Desktop Duplication API) and `Windows.Graphics.Capture` (WGC) alongside legacy GDI `BitBlt` for reliable remote desktop frame capture | [Microsoft: Desktop Duplication API](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) |
| Secure desktop interaction | Calling `OpenDesktop(L"Winlogon")` + `SetThreadDesktop` from a SYSTEM service to capture/control the UAC prompt and lock screen desktops, as all VNC servers do | [Microsoft: Desktops](https://learn.microsoft.com/en-us/windows/win32/winstation/desktops) |
| Session 1 bridge | Using `CreateProcessAsUser` with a duplicated SYSTEM token + `SetTokenInformation(TokenSessionId)` to spawn a helper process in the interactive user session for desktop access — the universal VNC/RMM pattern (UltraVNC, TightVNC, RustDesk all do this) | [Microsoft: CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw) |
| rundll32 DLL hosting | Using `rundll32.exe <dll>,EntryPoint` as the host process for the KVM payload DLL instead of a custom EXE — documented Windows mechanism for hosting DLL entry points | [Microsoft: rundll32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) |
| Input delivery | Calling `SendInput` from a SYSTEM-integrity helper process in the user session — the standard input injection mechanism used by all remote desktop software | [Microsoft: SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput) |
| `BlockInput` management | Calling `BlockInput(FALSE)` from SYSTEM context and `BlockInput(TRUE)` for local input lock during remote sessions — documented API, same as UltraVNC/TightVNC usage | [Microsoft: BlockInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-blockinput) |
| Network connectivity assurance | Adding persistent WFP (Windows Filtering Platform) permit filters via `FwpmFilterAdd0` from `fwpuclnt.lib` at a high sublayer weight — the same mechanism used by Tailscale, VPN clients, and enterprise firewalls | [Microsoft: WFP API](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) |
| Firewall rule management | Creating/monitoring Windows Firewall rules via `INetFwPolicy2` COM interface and `INetFwRules` — standard firewall management API used by all Windows service installers | [Microsoft: INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2) |
| DNS resolution resilience | Using DNS-over-HTTPS (RFC 8484) via HTTPS POST to public resolvers (1.1.1.1, 8.8.8.8) when OS DNS fails — standard DoH protocol | [RFC 8484: DNS over HTTPS](https://datatracker.ietf.org/doc/html/rfc8484) |
| TLS validation flexibility | Attempting strict certificate verification first, then falling back to the Windows system certificate store for environments with TLS inspection proxies — standard corporate proxy compatibility pattern | [Microsoft: Certificate Stores](https://learn.microsoft.com/en-us/windows/win32/seccrypto/certificate-stores) |
| Service DACL hardening | Calling `SetSecurityInfo` on the service process handle to restrict `PROCESS_TERMINATE` access — standard service self-protection used by AV/EDR products | [Microsoft: SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfow) |
| Process lifetime management | Using Job Objects with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to ensure child processes are terminated when the service stops — documented Job Object API | [Microsoft: Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) |
| Service tamper detection | Polling service state, registry keys, and firewall rules on a timer and restoring them if modified — the standard pattern used by Huntress, Datto, ConnectWise for agent self-healing | Public RMM documentation |
| GPU-accelerated encoding | Using NVENC/AMF/QSV hardware encoders via vendor SDK with shared D3D11 texture handles — Sunshine's production architecture | [Sunshine source](https://github.com/LizardByte/Sunshine) |
| IDD capture | Implementing an Indirect Display Driver (UMDF) that receives composited frames from DWM — Citrix shipped this in production (CVAD 2212, 2024), requires attestation signing | [Microsoft: IDD Model](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/indirect-display-driver-model-overview) |
| Credential Provider | Implementing `ICredentialProvider` COM interface for authentication event visibility — multiOTP is the reference implementation | [Microsoft: Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows) |
| PPL awareness | Calling `NtQueryInformationProcess(ProcessProtectionInformation)` to detect Protected Process Light status — diagnostic only, no bypass attempted | [Microsoft: Process Security](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) |
| Lockdown orchestration | Managing Windows registry policies (Winlogon shell/userinit, Explorer restrictions) and service states for exam-proctoring scenarios with full state backup/restore — the SecureEnter/SecureExit pattern | Standard registry policy APIs |
| Companion service lifecycle | Installing, starting, health-checking, and uninstalling a companion Windows service (`MasterService.exe` / `AdvancedHookService`) in lockstep with the agent service lifecycle | Standard SCM APIs |

---

## Work Execution Model

You are an autonomous senior engineer. Once the user gives a direction, proactively gather context, plan, implement, test, and refine without waiting for additional prompts at each step. Persist until the task is fully handled end-to-end.

### Autonomous Work Protocol

1. **On receiving a task**: Read the TODO matrix, identify the relevant TODO(s), read the dependent source files, and begin implementation immediately. Do not ask clarifying questions unless genuinely blocked.

2. **After each code change**: Build immediately (`msbuild` command from Build Commands section). If the build fails, fix the error and rebuild. Do not report build failures as blockers — fix them.

3. **After each successful build**: Run the relevant test or validation command. If it fails, read the error, fix the code, rebuild, retest. Repeat until green.

4. **After each test passes**: Update the TODO matrix (mark the item `DONE` or `IN_PROGRESS`), record evidence path, and immediately proceed to the next OPEN TODO. Do not stop. Do not summarize. Do not ask "should I continue?"

5. **When all P0 TODOs are DONE**: Move to P1 items. When all P1 items are DONE, move to P2. Continue until no OPEN items remain.

6. **If genuinely blocked**: Note the blocker in the TODO matrix as `BLOCKED` with the reason, skip to the next independent OPEN TODO, and continue working. Return to the blocked item later.

### Continuous Integration Loop

```
READ TODO → IMPLEMENT → BUILD → if BUILD FAILS: FIX → rebuild
                                  if BUILD OK: TEST → if TEST FAILS: FIX → rebuild → retest
                                                       if TEST OK: MARK DONE → NEXT TODO
```

This loop runs until zero OPEN items remain in the TODO matrix. The `.codex/hooks/enforce_loop.py` Stop hook enforces this: it reads the TODO matrix and blocks premature stops while OPEN items exist.

### Task Tracking

- **Authoritative TODO list**: `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md`
- **Acceptance criteria per task**: defined in the TODO matrix's `Acceptance` column
- **Test gates per task**: defined in `docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md`
- **Evidence per task**: written to `docs/testing/evidence/advanced/<timestamp>_<name>/`

### Completion Definition

Work is complete when:
- All P0 TODOs are `DONE` with evidence
- All `REQUIRED` regression matrix rows pass
- All `LIVE_DEPLOY` rows pass for deployment qualification
- Evidence bundle is exported to `docs/testing/artifacts/`

---

## Project Structure & Module Organization

- `meshcore/` — cross-platform agent runtime; generated headers in `meshcore/generated/`
- `meshcore/KVM/Windows/` — screen capture (`tile.cpp`, `kvm.c`), input delivery (`input.c`)
- `meshservice/` — Windows service projects (`StealthLab` = EXE, `StealthLab_DLL` = svchost DLL)
- `meshservice/stealth_*.c` — service hardening modules (firewall, lockdown, monitor, watchdog, persistence, registry, IPC, utils)
- `modules/` — JavaScript runtime modules (installer/service manager logic)
- `microstack/` — cross-platform library (networking, process pipes, cryptography)
- `docs/testing/` — validation evidence, plans, program documents

### Key Program Documents

| Document | Purpose |
|---|---|
| `docs/testing/20260331_REALIGNMENT_SSOT.md` | Single source of truth for the implementation program |
| `docs/testing/20260331_REALIGNMENT_LEDGER.md` | Keep/port/rewrite/revert classification for all code areas |
| `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md` | All work items (TODO-001 through TODO-061) with dependencies and acceptance |
| `docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md` | All test gates with evidence targets |
| `docs/testing/20260331_SCREEN_INPUT_ELEVATED_CONTROL_ROADMAP.md` | Research roadmap with verified open-source references |

---

## Build Commands

```bash
# svchost DLL (service hosting + rundll32 KVM bridge payload)
msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m

# Standalone EXE
msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64 /m
```

## Implementation Constraints

- Native C/C++ and JavaScript only for install/uninstall/update logic
- No PowerShell in runtime logic or test automation
- All code production-grade: defensive, validated, logged, no shortcuts
- Follow existing coding style (4-space indent, lowercase_underscored filenames, brace-on-same-line)

## Install & Runtime Paths

- Install root: `C:\ProgramData\DiagnosticHost`
- Log root: `C:\ProgramData\DiagnosticHost\logs`
- Service name: `WinDiagnosticHost`
- Binary name: `diaghost` / `diaghost.exe`
- `.msh` source: `C:\Users\Workstation\Downloads\diaghost64-Office (1).exe`
- Native primary: `meshservice\x64\StealthLab\MeshService-2022.exe`
- Svchost DLL: `meshservice\x64\StealthLab_DLL\MeshService-2022.dll`

## Architecture Reference

### Remote Desktop: rundll32 Session Bridge

The service spawns `rundll32.exe <dllpath>,KvmSessionBridgeW <pipename>` in user sessions:

1. Service creates named pipe `\\.\pipe\MeshKvm_{GUID}` with DACL restricted to SYSTEM+Administrators
2. Service calls `CreateProcessAsUser` with SYSTEM token redirected to target session via `SetTokenInformation(TokenSessionId)`
3. rundll32 loads the StealthLab_DLL, calls `KvmSessionBridgeW` export
4. DLL connects to pipe, enters capture/input loop, blocks until shutdown event
5. Service monitors process health, restarts with exponential backoff on crash
6. DACL protection applied to rundll32 process handle (deny `PROCESS_TERMINATE` to Everyone)
7. Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ensures cleanup on service stop
8. RAMAS cascade: `SPECIFIED_USER -> WINLOGON -> USER -> WINLOGON` with 5s pipe-connect timeout per attempt
9. Desktop targeting: `winsta0\default` for normal, `Winsta0\Winlogon` for secure desktop (UAC/lock screen)

### Network Connectivity: WFP Hard-Permit

The service ensures undeniable network access via Windows Filtering Platform:

1. `FwpmEngineOpen0` — open non-dynamic session (persistent objects)
2. `FwpmProviderAdd0` — register provider tied to service name
3. `FwpmSubLayerAdd0` — create sublayer at weight `0xFFFF` (maximum; Windows Firewall uses `0x1000`)
4. `FwpmFilterAdd0` — add PERMIT filter with `FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` (hard permit)
5. Conditions: `FWPM_CONDITION_ALE_APP_ID` (agent exe) + optionally `FWPM_CONDITION_IP_REMOTE_ADDRESS` (server IP)
6. Layers: `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` (outbound) + `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound)
7. Watchdog: enumerate WFP filters every 30-60s, remove any `FWP_ACTION_BLOCK` filters targeting agent's app ID
8. Firewall auto-remediation: poll `INetFwPolicy2` rules every 10-30s, re-create if deleted, remove hostile block rules

### Screen Capture: Multi-Backend Stack

Priority: DXGI `DuplicateOutput1` > WGC (cross-GPU fallback) > GDI `BitBlt` (legacy)

- DXGI captures DWM-composited frames including DX/GL surfaces GDI misses
- DXGI respects `SetWindowDisplayAffinity` — protected windows render black
- Only IDD (Indirect Display Driver, UMDF, attestation-signed) captures below display affinity
- WGC cannot capture the secure desktop — only DXGI from SYSTEM context can
- Secure desktop: `OpenDesktop(L"Winlogon")` + `SetThreadDesktop` from service context
- GPU encoding: NVENC/AMF/QSV via shared texture handle + `IDXGIKeyedMutex` (Sunshine pattern)

### Input Delivery

- SYSTEM integrity (IL=0x4000) is the highest level — `SendInput` reaches all windows including elevated
- Session 0 isolation is the real obstacle, not UIPI — solved by the Session 1 bridge
- `BlockInput(TRUE)`: calling thread exempt from its own block; SYSTEM `BlockInput(FALSE)` overrides application blocks
- Secure desktop input: `SetThreadDesktop` to Winlogon desktop, then `SendInput`
- `SendSAS` from `sas.dll` for Ctrl+Alt+Del emulation (requires `SoftwareSASGeneration=3` registry policy)
