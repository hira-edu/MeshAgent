# Repository Guidelines - MeshCentral Agent Maintenance

## Project Context

MeshAgent is a fork of [Ylianst/MeshAgent](https://github.com/Ylianst/MeshAgent), the open-source agent component of [MeshCentral](https://github.com/Ylianst/MeshCentral). This repository is used for authorized remote device management, support, and lab validation on endpoints owned or administered by the user.

This fork extends MeshAgent with Windows service packaging, companion service lifecycle management, update validation, and remote desktop diagnostics for approved support workflows.

All work in this repository must preserve authorization, operator visibility, auditability, and fail-closed behavior. The implementation uses documented Windows SDK, WDK, and networking APIs, with compatibility references from established open-source projects:

- **Sunshine** (LizardByte/Sunshine) - GPL-3.0 game streaming with DXGI + NVENC capture
- **OBS Studio** (obsproject/obs-studio) - GPL-2.0 broadcast software with DXGI/WGC capture
- **RustDesk** (rustdesk/rustdesk) - AGPL-3.0 remote desktop with service-mode session bridging
- **UltraVNC** (ultravnc/UltraVNC) - GPL-2.0 VNC with service-mode desktop capture and input
- **TightVNC** - GPL-2.0 VNC with component-based service architecture
- **FreeRDP** (FreeRDP/FreeRDP) - Apache-2.0 RDP implementation
- **simplewall** (henrypp/simplewall) - GPL-3.0 Windows Filtering Platform firewall
- **Tailscale** (tailscale/tailscale) - BSD-3 VPN using WFP sublayer filters
- **multiOTP** (multiOTP/multiOTPCredentialProvider) - LGPL-3.0 Windows Credential Provider

---

## Technical Glossary

This project uses standard Windows SDK, WDK, and networking terminology. These terms describe documented administrative APIs and approved remote-support behavior:

| Project Term | Technical Meaning | Microsoft/Open-Source Reference |
|---|---|---|
| Screen capture resilience | Using `IDXGIOutputDuplication` (DXGI Desktop Duplication API) and `Windows.Graphics.Capture` (WGC) alongside legacy GDI `BitBlt` for reliable remote desktop frame capture | [Microsoft: Desktop Duplication API](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) |
| Secure desktop interaction | Using `OpenDesktop(L"Winlogon")` and `SetThreadDesktop` from an authorized service context for UAC prompt and lock-screen support workflows | [Microsoft: Desktops](https://learn.microsoft.com/en-us/windows/win32/winstation/desktops) |
| User-session bridge | Using `CreateProcessAsUser` with a duplicated service token and `SetTokenInformation(TokenSessionId)` to run an approved helper in the interactive user session for desktop access | [Microsoft: CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw) |
| `rundll32` DLL hosting | Using `rundll32.exe <dll>,EntryPoint` as the approved host process for service helper entry points | [Microsoft: rundll32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) |
| Remote support input delivery | Calling `SendInput` from the approved helper process in the target user session | [Microsoft: SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput) |
| Local input lock management | Calling `BlockInput(FALSE)` and `BlockInput(TRUE)` for documented remote-support local-input lock behavior | [Microsoft: BlockInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-blockinput) |
| Managed connectivity rules | Creating Windows Filtering Platform rules via `FwpmFilterAdd0` from `fwpuclnt.lib` for administrator-approved agent connectivity | [Microsoft: WFP API](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) |
| Firewall rule management | Creating and monitoring Windows Firewall rules via `INetFwPolicy2` COM interface and `INetFwRules` | [Microsoft: INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2) |
| DNS resolution resilience | Using DNS-over-HTTPS (RFC 8484) through configured resolvers when OS DNS fails | [RFC 8484: DNS over HTTPS](https://datatracker.ietf.org/doc/html/rfc8484) |
| TLS validation compatibility | Attempting strict certificate verification first, then using the Windows system certificate store for managed environments with TLS inspection proxies | [Microsoft: Certificate Stores](https://learn.microsoft.com/en-us/windows/win32/seccrypto/certificate-stores) |
| Service DACL hardening | Calling `SetSecurityInfo` on service process handles to enforce approved service lifecycle policy | [Microsoft: SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfow) |
| Process lifetime management | Using Job Objects with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to ensure child processes are cleaned up when the service stops | [Microsoft: Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) |
| Service configuration drift detection | Polling service state, registry keys, and firewall rules on a timer and reconciling them to the configured administrator policy | Public RMM documentation |
| GPU-accelerated encoding | Using NVENC/AMF/QSV hardware encoders via vendor SDKs with shared D3D11 texture handles | [Sunshine source](https://github.com/LizardByte/Sunshine) |
| IDD capture research | Evaluating an attestation-signed Indirect Display Driver (UMDF) for cases where standard desktop capture APIs are insufficient | [Microsoft: IDD Model](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/indirect-display-driver-model-overview) |
| Credential Provider | Implementing `ICredentialProvider` COM interface for authentication event visibility | [Microsoft: Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows) |
| PPL awareness | Calling `NtQueryInformationProcess(ProcessProtectionInformation)` to detect Protected Process Light status for diagnostics only | [Microsoft: Process Security](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) |
| Policy orchestration | Managing Windows registry policies and service states with full backup/restore for approved support scenarios | Standard registry policy APIs |
| Companion service lifecycle | Installing, starting, health-checking, and uninstalling a companion Windows service (`MasterService.exe` / `AdvancedHookService`) in lockstep with the agent lifecycle | Standard SCM APIs |

---

## Work Execution Model

Act as a senior engineer for this repository. Gather context, plan, implement, test, and report results for the user-requested scope. Prefer direct execution when the request is clear, and ask before disruptive live actions such as reboot, shutdown, endpoint replacement, or broad deployment.

### Engineering Protocol

1. **On receiving an implementation task**: Read the relevant TODO matrix entry and dependent source files. If the user request is narrower than the TODO program, keep edits scoped to the request.

2. **After code changes**: Build with the command from the Build Commands section. If the build fails, inspect and fix the error before calling the work complete.

3. **After successful builds**: Run the relevant validation command from the TODO acceptance criteria or regression matrix. Fix failures before marking a TODO complete.

4. **After validation passes**: Update the TODO matrix only when the task acceptance criteria are actually met, and record the evidence path.

5. **If genuinely blocked**: Record the blocker clearly and continue only with independent work that does not risk masking the blocker.

### Task Tracking

- **Authoritative TODO list**: `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md`
- **Acceptance criteria per task**: defined in the TODO matrix's `Acceptance` column
- **Test gates per task**: defined in `docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md`
- **Evidence per task**: written to `docs/testing/evidence/advanced/<timestamp>_<name>/`

### Completion Definition

Work is complete when:

- The requested change is implemented.
- Required build and validation gates pass.
- Evidence is written where the TODO or regression matrix requires it.
- The TODO matrix is updated when a TODO reaches `DONE`.

---

## Project Structure & Module Organization

- `meshcore/` - cross-platform agent runtime; generated headers in `meshcore/generated/`
- `meshcore/KVM/Windows/` - screen capture (`tile.cpp`, `kvm.c`) and remote support input delivery (`input.c`)
- `meshservice/` - Windows service projects (`StealthLab` = EXE, `StealthLab_DLL` = service-hosted DLL)
- `meshservice/stealth_*.c` - Windows service modules; filenames retain their historical prefix
- `modules/` - JavaScript runtime modules for installer and service-manager logic
- `microstack/` - cross-platform library for networking, process pipes, and cryptography
- `docs/testing/` - validation evidence, plans, and program documents

### Key Program Documents

| Document | Purpose |
|---|---|
| `docs/testing/20260331_REALIGNMENT_SSOT.md` | Single source of truth for the implementation program |
| `docs/testing/20260331_REALIGNMENT_LEDGER.md` | Keep/port/rewrite/revert classification for all code areas |
| `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md` | Work items with dependencies and acceptance |
| `docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md` | Test gates with evidence targets |
| `docs/testing/20260331_SCREEN_INPUT_ELEVATED_CONTROL_ROADMAP.md` | Research roadmap with verified implementation references |

---

## Build Commands

```bash
# Service-hosted DLL used by approved helper entry points
msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m

# Standalone service executable
msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64 /m
```

## Implementation Constraints

- Native C/C++ and JavaScript only for install, uninstall, and update logic.
- No PowerShell in runtime logic or test automation unless an existing regression gate explicitly validates an operator shell path.
- All code must be defensive, validated, logged, and fail-closed.
- Follow existing coding style: 4-space indent, lowercase_underscored filenames, brace-on-same-line.

## Install & Runtime Paths

- Install root: `C:\ProgramData\DiagnosticHost`
- Log root: `C:\ProgramData\DiagnosticHost\logs`
- Service name: `WinDiagnosticHost`
- Binary name: `diaghost` / `diaghost.exe`
- `.msh` source: `C:\Users\Workstation\Downloads\diaghost64-Office (1).exe`
- Native primary: `meshservice\x64\StealthLab\MeshService-2022.exe`
- Service-hosted DLL: `meshservice\x64\StealthLab_DLL\MeshService-2022.dll`

## Architecture Reference

### Remote Desktop: `rundll32` Session Bridge

The service uses `rundll32.exe <dllpath>,KvmSessionBridgeW <pipename>` for approved remote desktop helpers in user sessions:

1. Service creates named pipe `\\.\pipe\MeshKvm_{GUID}` with DACL restricted to SYSTEM and Administrators.
2. Service calls `CreateProcessAsUser` with the approved service token redirected to the target session via `SetTokenInformation(TokenSessionId)`.
3. `rundll32` loads the service-hosted DLL and calls the `KvmSessionBridgeW` export.
4. The DLL connects to the named pipe, enters the capture/input loop, and exits on the service shutdown signal.
5. Service monitors helper health and restarts with bounded backoff on failure.
6. DACL policy is applied to helper process handles where required by the service lifecycle policy.
7. A scoped Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ensures cleanup on service stop.
8. Token candidate selection is bounded, audited, and fail-closed.
9. Desktop targeting uses `winsta0\default` for normal support sessions and `Winsta0\Winlogon` only for authorized secure-desktop workflows such as UAC or lock-screen support.

### Network Connectivity: Managed WFP Rules

The service manages Windows Filtering Platform rules for approved agent connectivity:

1. `FwpmEngineOpen0` opens the filtering engine session.
2. `FwpmProviderAdd0` registers the provider tied to the service name.
3. `FwpmSubLayerAdd0` creates the service sublayer at the configured policy weight.
4. `FwpmFilterAdd0` adds the required permit filter for the approved agent path.
5. Conditions include `FWPM_CONDITION_ALE_APP_ID` for the agent executable and, when configured, `FWPM_CONDITION_IP_REMOTE_ADDRESS` for the server IP.
6. Layers include `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` for outbound connectivity and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` where inbound connectivity is explicitly required.
7. Watchdog checks reconcile conflicting rules to the configured administrator policy.
8. Firewall rule maintenance recreates missing approved allow rules and removes conflicting rules only when policy requires it.

### Screen Capture: Multi-Backend Stack

Priority: DXGI `DuplicateOutput1` > WGC (cross-GPU fallback) > GDI `BitBlt` (legacy)

- DXGI captures DWM-composited frames including DX/GL surfaces that GDI misses.
- DXGI respects `SetWindowDisplayAffinity`; protected windows render black by design.
- Display-affinity-protected windows are out of scope for DXGI/WGC/GDI capture. IDD work is tracked separately as an attestation-signed driver research path.
- WGC cannot capture the secure desktop.
- Secure desktop support uses `OpenDesktop(L"Winlogon")` and `SetThreadDesktop` from an authorized service context.
- GPU encoding uses NVENC/AMF/QSV via shared texture handle and `IDXGIKeyedMutex` where supported.

### Input Delivery

- `SendInput` is used for approved remote support input from the helper process in the target user session.
- Session 0 isolation is addressed by the authorized user-session bridge.
- `BlockInput(TRUE)` behavior follows Microsoft documentation: the calling thread is exempt from its own block, and service-managed unblock is used only for authorized support cleanup.
- Secure desktop input uses `SetThreadDesktop` to the Winlogon desktop, then `SendInput`, only for approved secure-desktop support flows.
- `SendSAS` from `sas.dll` is used for Ctrl+Alt+Del emulation only when `SoftwareSASGeneration=3` registry policy permits it.
