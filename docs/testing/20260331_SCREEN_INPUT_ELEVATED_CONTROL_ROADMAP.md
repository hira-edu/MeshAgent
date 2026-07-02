# 2026-03-31 Screen Capture, Input Delivery, and Privileged Service Behavior Research Roadmap

## Authority

This document extends the `20260331_REALIGNMENT_SSOT.md` program. It defines the research and implementation roadmap for improving screen capture resilience, input delivery reliability, and privileged service posture across owned and authorized target environments.

All work items here must follow the same change-control rules as the parent SSOT: ledger entry, TODO tracing, regression-matrix gate, and evidence.

All claims in this document have been verified against open-source implementations, official Microsoft documentation, and security research published through early 2026. Where common assumptions were found to be incorrect, corrections are noted explicitly.

## Scope

Three interconnected capability domains:

1. **Screen capture compatibility** -- ensuring reliable capture for authorized support workflows while respecting Windows security boundaries and explicitly failing when protected content cannot be captured.
2. **Input delivery reliability** -- ensuring approved keyboard, mouse, and touch delivery when Session 0 isolation, secure desktop boundaries, or application-level input filters affect standard `SendInput` behavior.
3. **Privileged service behavior** -- maintaining auditable, fail-closed service control across session boundaries, privilege tiers, and reboot cycles.

## Critical Corrections to Common Assumptions

The following misconceptions were identified during research and are corrected throughout this document:

| Myth | Reality | Source |
|---|---|---|
| "DXGI captures `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` windows" | **FALSE.** DXGI Desktop Duplication respects display affinity. Protected windows render as black. The DWM enforces affinity at the compositor level before the duplicated frame is produced. | Microsoft DXGI documentation; tested behavior in OBS/Sunshine |
| "SYSTEM processes can't use `SendInput` due to UIPI" | **FALSE.** UIPI only blocks lower-integrity to higher-integrity. SYSTEM (IL=0x4000) is the highest level. The real obstacle is **Session 0 isolation** -- services run in Session 0 which has no interactive desktop. | Microsoft Integrity Mechanism Design |
| "`BlockInput` blocks all input including injected input" | **FALSE.** The thread that called `BlockInput(TRUE)` can still call `SendInput` from the same thread. Only other threads and physical input are blocked. RDP input is also not blocked. | Microsoft `BlockInput` documentation |
| "You need a virtual HID driver for UIPI limits" | **FALSE for RMM.** No mainstream RMM or VNC tool uses virtual HID. The standard support pattern is: service spawns helper in user session via `CreateProcessAsUser`, helper runs as SYSTEM IL in that session, plain `SendInput` works. | UltraVNC, TightVNC, MeshAgent source analysis |
| "IDD requires WHQL certification" | **FALSE for Win10/11 client.** Attestation signing (not WHQL) is sufficient for desktop deployment. Citrix shipped IDD as default capture in CVAD 2212 (production, 2024). WHQL is only required for Windows Server. | Microsoft driver signing policy; Citrix blog |
| "Kernel ObRegisterCallbacks provides strong process protection" | **Partially true but defeated by BYOVD.** BYOVD (Bring Your Own Vulnerable Driver) attacks can unregister kernel callbacks. No commercial RMM vendor uses kernel callbacks for self-protection. EDRs use them only in combination with ELAM/PPL. | EDRSandblast; Microsoft security research 2024-25 |
| "ELAM can be used by RMM tools for PPL protection" | **FALSE.** ELAM requires a special Microsoft partnership program certificate with EKU OID `1.3.6.1.4.1.311.61.4.1`, available only to qualifying antimalware vendors. | Microsoft ELAM documentation |
| "All userland PPL access techniques work on current Windows" | **FALSE.** PPLdump patched July 2022, PPLFault patched February 2024, GodFault patched same date. Only BYOVDLL (August 2024, itm4n) partially works and is being mitigated. | Elastic Security Labs; itm4n blog |
| "`DwmGetDxSharedSurface` works reliably on modern Windows" | **UNRELIABLE.** Microsoft documentation says "only valid for Windows 7." The API exists on Win10/11 but is undocumented and could break with any update. | Microsoft undocumented API reference |
| "WGC can capture the secure desktop (UAC/lock screen)" | **FALSE.** Only DXGI Desktop Duplication from SYSTEM context can capture the Winlogon desktop. WGC cannot. | Sunshine issue #3487; OBS testing |

## Current State (Baseline Audit)

### Screen Capture

| Technique | File | Status | Limitation |
|---|---|---|---|
| GDI `BitBlt` + GDI+ JPEG tile encoding | `meshcore/KVM/Windows/tile.cpp` | Implemented | Misses DWM-composited overlays, hardware cursors, DX/OpenGL surfaces; no GPU acceleration; CPU-bound at ~15-20fps |
| `OpenInputDesktop` + `SetThreadDesktop` | `meshcore/KVM/Windows/kvm.c` | Implemented | Handles desktop switching for lock screen and screensaver; does not explicitly target `Winlogon` by name |
| SAS (`SendSAS` from `sas.dll`) | `meshcore/KVM/Windows/kvm.c` | Implemented | Unlocks via Ctrl+Alt+Del emulation; requires `SoftwareSASGeneration=3` registry policy |
| Multi-monitor enumeration | `meshcore/KVM/Windows/kvm.c` | Implemented | `EnumDisplayMonitors` based; no virtual-desktop awareness; no cross-GPU support |

### Input Delivery

| Technique | File | Status | Limitation |
|---|---|---|---|
| `SendInput` (mouse + keyboard + touch) | `meshcore/KVM/Windows/input.c` | Implemented | Works from SYSTEM IL; the real obstacle is ensuring the helper runs in the correct session and on the correct desktop |
| Unicode key delivery (`KEYEVENTF_UNICODE`) | `meshcore/KVM/Windows/input.c` | Implemented | Works for most apps; some fullscreen/game apps ignore synthetic input |
| Multi-touch (16 points, `InjectTouchInput`) | `meshcore/KVM/Windows/input.c` | Implemented | Requires touch injection capability registration |
| `BlockInput` management | `meshcore/KVM/Windows/kvm.c` | Implemented | Already calls `BlockInput(1)` and `BlockInput(0)` around sessions; same-thread `SendInput` works while block is active |
| `SetForegroundWindow` focus steal | `meshcore/KVM/Windows/input.c` | Implemented | Modern Windows restricts foreground stealing; `AttachThreadInput` workaround in place |

### Privileged Service Behavior

| Technique | File | Status | Limitation |
|---|---|---|---|
| Service-to-user session bridge (`WTSQueryUserToken` + `CreateProcessAsUser`) | `meshservice/stealth_watchdog.c` | Implemented | Bridges Session 0 to Session 1+; cascading token candidates (USER -> WINLOGON); `SE_TCB_NAME` privilege |
| SecureEnter/SecureExit lockdown orchestration | `meshservice/stealth_lockdown.c` | Implemented | 12 lockdown features with state backup/restore |
| Watchdog mesh (mutual heartbeat + respawn) | `meshservice/stealth_watchdog.c` | Implemented | Shared memory heartbeat; auto-restart on termination; configurable backoff |
| Service recovery policy (Task Scheduler, WMI, COM, DLL, port monitor checks) | `meshservice/stealth_persistence.c` | Implemented | Multiple policy-controlled recovery checks |
| Configuration drift detection + reconcile | `meshservice/stealth_monitor.c` | Implemented | 8-second polling cycle; reconciles services, registry, tasks |
| Registry policy enforcement | `meshservice/stealth_registry.c` | Implemented | GPO-level policy read/write; Winlogon shell/userinit override |

## Research Roadmap

### Tier 1 -- Near-Term (Known Windows APIs, Verified Open-Source Precedent)

#### T1-SCREEN-001: DXGI Desktop Duplication API

**What**: Replace or supplement GDI `BitBlt` capture with `IDXGIOutputDuplication` (Win8+). Captures the final DWM-composited desktop frame as a GPU texture, including DX/OpenGL surfaces, hardware cursors (with metadata), and DWM overlays that GDI misses.

**Critical clarification**: DXGI Desktop Duplication does **not** capture windows protected with `SetWindowDisplayAffinity`. Windows protected with `WDA_EXCLUDEFROMCAPTURE` or `WDA_MONITOR` render as black in the duplicated frame. This is by design -- the DWM enforces display affinity at the compositor level. However, DXGI still provides major advantages over GDI: it captures DX/GL surfaces, hardware-accelerated cursors, and DWM-composited overlays that GDI completely misses.

**Open-source reference (verified)**:
- **Sunshine** (`src/platform/windows/display_vram.cpp`, `display_ram.cpp`) -- **Gold standard.** Zero-copy GPU texture pipeline: `duplication_t::next_frame()` acquires desktop texture, shared texture handle + `IDXGIKeyedMutex` synchronizes with encoder device, NVENC encodes directly from GPU texture. Supports HDR via `DuplicateOutput1` with `DXGI_FORMAT_R10G10B10A2_UINT` and `DXGI_FORMAT_R16G16B16A16_FLOAT`.
- **OBS Studio** (`plugins/win-capture/duplicator-monitor-capture.c`) -- Production-grade. Uses `gs_duplicator_t` abstraction. Auto-selects DXGI vs WGC: defaults to DXGI, falls back to WGC on cross-GPU (monitor index -1) or battery+multi-adapter. 3-second retry on `ACCESS_LOST`. Handles SDR/HDR tone-mapping.
- **RustDesk** (`libs/scrap/src/dxgi/`) -- Functional but **reads back to CPU memory** (no zero-copy). Historically had DXGI memory leaks causing GDI fallback. Performance limited to ~37fps with software codecs.

**Verified implementation requirements**:
1. Use `IDXGIOutput5::DuplicateOutput1` (not `DuplicateOutput`) on Win10+ for HDR format negotiation and avoiding unnecessary BGRA conversion
2. `AcquireNextFrame` accumulates updates -- release current frame immediately before acquiring next to minimize gap
3. Process MOVE rects first, then DIRTY rects (never interleave)
4. One worker thread per monitor (Microsoft's official pattern) with event-based error signaling
5. `DXGI_ERROR_ACCESS_LOST` is common (mode change, desktop switch, TDR, portrait mode on Win11, Hyper-V VMs) -- must release all resources and re-create duplication. Use progressive backoff (Microsoft's `DYNAMIC_WAIT` pattern)
6. Hard limit: max 4 concurrent duplication sessions system-wide (`DXGI_ERROR_NOT_CURRENTLY_AVAILABLE`)
7. D3D12 cannot use Desktop Duplication at all -- D3D11on12 always returns `ACCESS_LOST`
8. Rotated displays return surface in un-rotated orientation with rotated content -- you must handle rotation yourself
9. Hybrid GPU laptops: cannot duplicate against discrete GPU; must force to integrated (`DXGI_ERROR_UNSUPPORTED`). This is where WGC fallback is needed.
10. **Cursor handling**: check `PointerPosition.Visible` in `DXGI_OUTDUPL_FRAME_INFO`; if visible, draw cursor yourself via cached `GetFramePointerShape` data

**Fallback chain**: DXGI `DuplicateOutput1` -> DXGI `DuplicateOutput` (pre-Win10) -> GDI `BitBlt` (pre-Win8, RDP, headless)

**Integration point**: `meshcore/KVM/Windows/tile.cpp` -- add DXGI backend alongside existing GDI path, selected at runtime.

#### T1-SCREEN-002: Windows.Graphics.Capture API (WGC)

**What**: Modern Win10 1903+ capture API. Handles DWM composition, multi-monitor, per-window capture, and cross-GPU scenarios.

**Critical clarification**: WGC **cannot capture the secure desktop** (UAC prompts, lock screen). Only DXGI from SYSTEM context can do that. WGC also respects `SetWindowDisplayAffinity`. WGC is not a way around either limitation -- it is a fallback for scenarios where DXGI is unavailable (cross-GPU, hybrid laptop).

**Open-source reference (verified)**:
- **Sunshine** (`display_wgc_vram_t` class) -- WGC is NOT the default; must be manually forced by user. Used primarily for HDR streaming when DXGI HDR support is insufficient.
- **OBS Studio** -- WGC selected automatically only for cross-GPU or battery+multi-adapter; DXGI is always preferred.
- **RustDesk** (`libs/scrap/src/wgc/`) -- WinRT `GraphicsCaptureSession` with `Direct3D11CaptureFramePool`.

**Verified comparison with DXGI**:

| Feature | DXGI Desktop Duplication | WGC |
|---|---|---|
| Minimum OS | Windows 8 | Windows 10 1803 |
| Cross-GPU | NO | YES |
| Per-window capture | NO (full monitor only) | YES |
| Dirty regions | YES (move + dirty rects) | NO |
| Secure desktop (UAC) | YES (with SYSTEM) | **NO** |
| Yellow border | None | Required Win10; optional Win11 |
| Concurrent limit | Max 4 apps | No known limit |
| HDR | Via `DuplicateOutput1` | Supported |

**When to use**: WGC is a fallback path for cross-GPU laptops and per-window scenarios, not the primary capture backend. DXGI is preferred for full-desktop RMM capture.

**Integration point**: Second capture backend; activated when DXGI reports `DXGI_ERROR_UNSUPPORTED` on hybrid GPU or when per-window capture is needed.

#### T1-SCREEN-003: Secure Desktop Capture via Explicit Winlogon Desktop Targeting

**What**: When the active desktop is `Winlogon` (UAC prompt, lock screen, Ctrl+Alt+Del), explicitly open that desktop by name from SYSTEM context for both capture and input delivery. This is the only reliable capture path for secure desktop -- WGC cannot do this.

**Open-source reference (verified)**:
- **UltraVNC** (`winvnc/` service mode) -- service obtains `winlogon.exe` token via `WTSQueryUserToken` (Vista+) or by duplicating the `winlogon.exe` process token as fallback. Uses `ImpersonateLoggedOnUser()` for desktop access.
- **TightVNC** (`tvnserver/` service mode) -- redesigned component architecture separating service code from user interface; delegates desktop switching to user-session processes.
- **MeshAgent** (`kvm.c`) -- already calls `OpenInputDesktop()` + `SetThreadDesktop()`, but does not explicitly target `Winlogon` by name and may miss the transition window.

**Verified implementation requirements**:
1. The `Winlogon` desktop's DACL allows access only to LocalSystem
2. A service-level (SYSTEM) thread can call `OpenDesktop(L"Winlogon", 0, FALSE, GENERIC_ALL)` to open the secure desktop
3. After `SetThreadDesktop`, both DXGI capture and `SendInput` work on the secure desktop
4. Listen for `EVENT_SYSTEM_DESKTOPSWITCH` to detect desktop transitions promptly
5. For Ctrl+Alt+Del triggering, `SendSAS()` from `sas.dll` requires the `SoftwareSASGeneration=3` registry policy and caller must be a service or have `uiAccess="true"` in manifest

**Integration point**: `meshcore/KVM/Windows/kvm.c` -- enhance desktop-switching logic to explicitly target Winlogon desktop by name.

#### T1-INPUT-001: Session 0 Isolation Bridge Verification

**What**: The real obstacle for service-level input delivery is NOT UIPI -- it is Session 0 isolation. The service must spawn a helper process in the user's interactive session. MeshAgent already implements this pattern (`stealth_watchdog.c` with `ILibProcessPipe_SpawnTypes_SPECIFIED_USER` / `ILibProcessPipe_SpawnTypes_WINLOGON`). This item verifies the integrity chain end-to-end.

**Corrected understanding**: UIPI only blocks lower-to-higher integrity. SYSTEM (IL=0x4000) is the highest integrity level. A SYSTEM-integrity process in the user's session can `SendInput` to ANY window regardless of the target's integrity level. The real problems are:
1. The service runs in Session 0 (no interactive desktop) -- must bridge to Session 1+
2. The KVM helper must be attached to the correct desktop (`OpenInputDesktop` + `SetThreadDesktop`)
3. The helper token must retain SYSTEM integrity (verify after `CreateProcessAsUser` with duplicated winlogon token)

**Open-source precedent**: This is the standard pattern used by UltraVNC, TightVNC, MeshAgent, and every other VNC/RMM tool. No production tool uses kernel-level input delivery.

**Verification steps**:
1. Confirm KVM helper token integrity level is SYSTEM after session bridge
2. Confirm `SendInput` reaches elevated (`Run as Administrator`) windows
3. Confirm desktop switching works when active desktop changes (Default <-> Winlogon)
4. Confirm `BlockInput` behavior: same-thread `SendInput` works while `BlockInput(TRUE)` is active; the blocking thread itself is exempt

**Integration point**: `meshcore/KVM/Windows/input.c` and `meshservice/stealth_watchdog.c` -- audit and document the existing bridge.

#### T1-INPUT-002: `BlockInput` Semantics and Management

**What**: Verify and document the correct `BlockInput` behavior for lockdown scenarios.

**Corrected understanding** (from Microsoft documentation):
- `BlockInput(TRUE)` blocks physical hardware input only
- The **calling thread** can still call `SendInput` -- only other threads are blocked
- The block auto-releases if: the blocking thread exits, user presses Ctrl+Alt+Del, or system invokes Hard System Error modal
- RDP input follows a separate path through the terminal services subsystem and is NOT blocked by `BlockInput`

**MeshAgent already implements this**: `kvm.c` calls `BlockInput(1)` to block local input during remote sessions and `BlockInput(0)` to unblock. The KVM input delivery path calls `SendInput` from the same process context.

**Verification steps**:
1. Confirm `SendInput` works from the KVM helper thread while `BlockInput(TRUE)` is active from the same process
2. Confirm that application-level `BlockInput(TRUE)` from a separate process is reconciled correctly during an approved support session
3. Document the cleanup precedence: service-managed `BlockInput(FALSE)` > application `BlockInput(TRUE)`

**Integration point**: Already functional in `meshcore/KVM/Windows/kvm.c`; needs verification and documentation.

#### T1-ELEVATED-001: Protected Process Light (PPL) Awareness

**What**: Detect PPL-protected processes and correctly classify them in drift detection to prevent false alarms.

**Verified status of PPL access techniques (as of early 2026)**:
- **PPLdump** (itm4n): Patched since Windows 10 21H2, July 2022. NTDLL now prevents PPLs from loading Known DLLs.
- **PPLFault** (Gabriel Landau/Elastic): Patched February 13, 2024. Windows Insider build 25941 added `MiValidateSectionCreate` checks.
- **GodFault**: Same underlying vulnerability as PPLFault; patched same date.
- **BYOVDLL** ("Ghost in the PPL", itm4n, August 2024): Newest technique; exploits loading a vulnerable DLL into a PPL. Microsoft actively mitigating.

**Correct scope**: This is **detection-only**. All stable userland PPL access techniques are patched on current Windows. The agent should:
1. Call `NtQueryInformationProcess(ProcessProtectionInformation)` to detect PPL level
2. Classify PPL processes as "protected by OS" in `stealth_monitor.c`
3. Skip interaction attempts with PPL processes
4. Report PPL status in diagnostic output (`-svchost-status`)
5. Not raise drift alarms when `OpenProcess` fails on PPL-protected processes

**Integration point**: `meshservice/stealth_monitor.c`.

### Tier 2 -- Medium-Term (Advanced Patterns, Verified Viable)

#### T2-SCREEN-001: GPU-Accelerated Encoding (NVENC / AMF / QSV) via Zero-Copy Pipeline

**What**: Replace GDI+ JPEG software encoding with GPU hardware encoders. The gold standard is Sunshine's zero-copy pipeline.

**Verified architecture (Sunshine, best-in-class)**:
1. DXGI `duplication_t::next_frame()` acquires desktop as `ID3D11Texture2D` on GPU
2. Shared texture handle created (`HANDLE encoder_texture_handle`)
3. Encoder device opens handle via `device1->OpenSharedResource1()`
4. `IDXGIKeyedMutex` synchronizes access between capture and encoder D3D devices
5. **NVENC path** (`d3d_nvenc_encode_device_t`): feeds texture directly to NVENC via `nvenc->encode_frame()` without FFmpeg's avcodec layer
6. Color conversion shaders run on GPU (perceptual quantizer transforms for P010/Y410 HDR)
7. Supports selective reference frame invalidation (avoids full IDR frames)
8. When encoder supports `PARALLEL_ENCODING`, capture and encoding run on separate threads concurrently

**RustDesk comparison**: Does NOT have zero-copy. Reads DXGI frames back to CPU memory, limiting performance to ~37fps with software codecs. Acknowledged needing hardware-accelerated encoding.

**Implementation shape**:
1. Probe GPU encoder at KVM session start: NVENC (CUDA/D3D11), AMF (D3D11), QSV (D3D11/MFT)
2. If GPU encoder available + DXGI capture active: zero-copy path (shared texture handle + keyed mutex)
3. Output H.264/HEVC NAL units; negotiate codec with viewer
4. Fallback: DXGI + CPU readback + JPEG tiles (current quality)
5. Fallback: GDI + JPEG tiles (pre-Win8)

**Integration point**: New encoding backend alongside JPEG tile path in `meshcore/KVM/Windows/tile.cpp`.

#### T2-SCREEN-002: Virtual Desktop Awareness

**What**: Windows 10+ virtual desktops. DXGI Desktop Duplication captures the DWM-composited desktop which includes all virtual desktops' visible content on the active display, so this is primarily a metadata/awareness feature.

**Implementation shape**:
1. `IVirtualDesktopManager::IsWindowOnCurrentVirtualDesktop` to check window visibility
2. COM activation of `VirtualDesktopManager` class
3. Report active virtual desktop state in KVM metadata
4. Low priority -- DXGI captures the composited output regardless of virtual desktop

**Complexity**: Low. **Value**: Low. **Recommended Phase**: P4.

#### T2-INPUT-001: UI Automation Framework for Structured Interaction

**What**: `IUIAutomation` provides programmatic access to UI elements via cross-process COM.

**Corrected understanding**: UI Automation does NOT remove UIPI limits for raw input delivery. What it does:
- UIAutomation providers run in the target process's context via COM cross-process calls
- For control patterns (`IUIAutomationInvokePattern::Invoke`), the action is executed inside the target process through the provider model
- For raw keyboard/mouse simulation, UIAutomation still uses `SendInput` under the hood, subject to the same rules
- Value for RMM: structured control interaction (clicking buttons, setting text fields) without pixel coordinate guessing

**Open-source reference**: FlaUI (.NET), pywinauto (Python).

**Integration point**: Optional structured-interaction path via KVM command channel. Not a replacement for `SendInput`.

#### T2-ELEVATED-001: Early-Boot Service Start for Pre-Login Capture

**What**: Ensure the agent service starts early enough to capture the login screen.

**Implementation**: `SERVICE_AUTO_START` with dependency on `Tcpip` + `Dhcp`. On service start, immediately call `SetThreadDesktop(OpenDesktop("Winlogon"))` for pre-login capture. Already partially implemented.

**Complexity**: Low. **Recommended Phase**: P3.

#### T2-ELEVATED-002: Credential Provider Integration

**What**: Implement a V2 Windows Credential Provider for authentication-event visibility and optional remote-unlock.

**Open-source reference (verified, best-of-breed)**:
- **multiOTP Credential Provider** (multiOTP/multiOTPCredentialProvider) -- **Best reference.** Production-grade V2 provider supporting Win7 through Win11/Server 2025. RDP support, push token support, actively maintained through 2026.
- **Lithnet Windows Credential Provider** (`lithnet/windows-credential-provider`) -- .NET wrapper, lower barrier to entry.
- **Microsoft V2 samples** (`Windows-classic-samples/Samples/CredentialProvider/cpp/`) -- Clean C++ COM implementation.

**Verified gotchas**:
1. Credential providers run in the Winlogon process on the secure desktop -- crashes can make the machine unbootable
2. `CredPackAuthenticationBuffer()` does NOT work for `CPUS_UNLOCK_WORKSTATION` scenarios; must use `KerbInteractiveUnlockLogonInit` instead
3. `UpdateRemoteCredential` callback handles RDP credential pass-through; can be adapted for agent-initiated unlock

**Implementation shape (minimal version)**:
1. Implement `ICredentialProvider` + `ICredentialProviderCredential` (V2)
2. Register via registry; communicate with agent service via named pipe
3. Report authentication events (tile selection, auth attempt, success/failure)
4. Optionally: remote-unlock tile with delegated credentials

**Complexity**: Medium-High for minimal version. **Value**: High for pre-login support. **Recommended Phase**: P5+.

### Tier 3 -- Research / Verified Viability Assessment

#### T3-SCREEN-001: Indirect Display Driver (IDD) Evaluation

**What**: A UMDF (User-Mode Driver Framework) Indirect Display Driver creates a virtual monitor that receives composited frames from the DWM. This changes the capture model and requires explicit policy review, attestation signing, and owned-device authorization before use.

**VIABILITY UPGRADE: This is production-viable.** Citrix shipped IDD as the default HDX capture method in CVAD 2212 (2024). It is NOT "research only."

**Corrected signing requirements**:
- IDD is a **UMDF user-mode driver**, NOT a kernel driver
- **Attestation signing** (not WHQL) is sufficient for Windows 10/11 client deployment
- Attestation signing requires: EV code signing certificate ($200-500/year) + Microsoft Partner Center account
- Attestation signing does NOT work on Windows Server (WHQL required there)
- Attestation-signed drivers cannot be distributed via Windows Update (must be installed by your own installer)

**Open-source reference**:
- Microsoft `Windows-driver-samples/video/IndirectDisplay/` -- official IDD sample
- `peacepenguin/Virtual-Display-Driver` -- community IDD implementation
- `ge9/IddSampleDriver` -- minimal IDD reference
- Citrix IDD architecture documentation

**Policy boundary**: DXGI, WGC, and GDI all respect display affinity. Any IDD work must remain limited to approved support and compatibility scenarios and must not be used to capture protected, DRM, or otherwise unauthorized content.

**Revised assessment**: Complexity: **High** (down from Very High). Viability: **Production-feasible** (up from Research only). Recommended Phase: **P5 with attestation signing pipeline**.

#### T3-SCREEN-002: DWM Shared Surface Capture via Undocumented APIs

**What**: `DwmGetDxSharedSurface` (user32.dll) and `DwmDxGetWindowSharedSurface` (dwmapi.dll) extract per-window DWM shared surfaces.

**VIABILITY DOWNGRADE: Not recommended.**
- Microsoft documentation explicitly states `DwmGetDxSharedSurface` is "only valid for Windows 7" and is not supported as a stable cross-version interface
- It does exist on Win10/11 but is undocumented and could break with any update
- The DWMCapture OBS plugin (`notr1ch/DWMCapture`) uses it but is experimental
- IDD (T3-SCREEN-001) is a far more reliable path for the same goal

**Revised assessment**: Complexity: Medium. Viability: **Not recommended for production**. Value: **Low** (down from Medium). Recommended: **Deprioritize in favor of IDD**.

#### T3-INPUT-001: Virtual HID Miniport Assessment

**What**: A virtual HID miniport driver delivers input at the hardware abstraction level.

**VIABILITY ASSESSMENT: Not needed for RMM.**

Verified findings:
- **No mainstream RMM or VNC tool uses virtual HID for remote support input delivery.** All use the helper-process-in-user-session + plain `SendInput` pattern.
- Virtual HID drivers are commonly discussed for game input-filter circumvention, which is outside this project's scope.
- ViGEm is for virtual gamepad emulation, not keyboard/mouse delivery.
- The only relevant distinction is that virtual HID events lack the `LLMHF_INJECTED` flag; this is not needed for RMM.
- Requires EV-signed kernel driver (Windows 10+) for production, adding significant complexity for zero practical benefit.

**Revised assessment**: Value: **Low for RMM** (down from Very High). Recommended: **Deprioritize.** The helper process + `SendInput` pattern is sufficient and proven.

#### T3-ELEVATED-001: Kernel Callback Registration (ObRegisterCallbacks)

**What**: Register kernel-level object-access callbacks to protect agent processes from termination.

**VIABILITY DOWNGRADE: Low practical value for RMM.**

Verified findings:
- **No commercial RMM vendor uses kernel callbacks for self-protection.** ConnectWise, Datto, NinjaOne, and Huntress all use userland mechanisms (service ACLs, watchdog processes, firewall auto-remediation).
- EDR vendors (CrowdStrike, SentinelOne, Microsoft Defender) use ObRegisterCallbacks but ONLY in combination with ELAM/PPL, which gives their processes kernel-enforced protection. Without ELAM/PPL backing, ObRegisterCallbacks can be defeated by BYOVD attacks.
- ELAM is not available to RMM tools (requires Microsoft antimalware partnership).
- The real 2024-2025 RMM threat landscape is: credential compromise (36% of IR cases), BYOVD (defeats all userland AND kernel protections), and BYOI (abusing the agent's own installer). Kernel callbacks address none of these.
- The existing `stealth_monitor.c` polling + auto-restore pattern is actually solid defense against most real-world attacks. The 8-second polling cycle is reasonable.

**What's actually worth investing in instead**:
1. Service ACL hardening (deny `WRITE_DAC` to non-SYSTEM -- Velociraptor got this wrong, has a known LPE via `BUILTIN\Users` `WRITE_DAC` on install dir)
2. Firewall rule auto-remediation (Huntress/Datto pattern)
3. Atomic/resilient upgrade process (defend against BYOI)
4. Mutual TLS with pinned certificates
5. Server-side anomaly detection

**Revised assessment**: Value: **Low** (down from High). Recommended: **Deprioritize in favor of userland hardening.** Kernel callbacks without ELAM/PPL provide a false sense of security.

## Open-Source Implementation Quality Ranking (Verified)

### Screen Capture

| Rank | Project | Language | Key Strength | Verified Detail | License |
|---|---|---|---|---|---|
| 1 | **Sunshine** (LizardByte) | C++ | Zero-copy DXGI+NVENC, HDR, shared texture handles + keyed mutex | Only project with true GPU-resident capture-to-encode pipeline; uses direct NVENC path | GPL-3.0 |
| 2 | **OBS Studio** | C | Production-grade multi-source, smart DXGI/WGC selection, SDR/HDR tone-mapping | Best fallback logic; 3-second progressive retry; battle-tested error recovery | GPL-2.0 |
| 3 | **RustDesk** | Rust | DXGI+WGC dual backend, cross-platform | **No zero-copy** -- reads back to CPU memory; ~37fps limit with software codecs; had DXGI memory leaks | AGPL-3.0 |
| 4 | **UltraVNC** | C++ | Mature service-mode Winlogon desktop capture | Token impersonation pattern for secure desktop; legacy mirror driver support | GPL-2.0 |
| 5 | **TightVNC** | C++ | Clean component-based service architecture | Redesigned in 2.0; good reference for service/helper separation | GPL-2.0 |

### Input Delivery

| Rank | Project | Language | Key Strength | Verified Detail | License |
|---|---|---|---|---|---|
| 1 | **MeshAgent** (this project) | C | Full helper-process bridge + SendInput + touch + BlockInput + SAS | Already implements the universal pattern correctly; cascading token candidates | Apache-2.0 |
| 2 | **UltraVNC** | C++ | WTSQueryUserToken + ImpersonateLoggedOnUser + desktop switching | Mature service-mode input delivery with Ctrl+Alt+Del via Winlogon desktop thread | GPL-2.0 |
| 3 | **TightVNC** | C++ | Component-based service/helper separation | Clean architecture for delegation | GPL-2.0 |
| 4 | **FreeRDP** | C | Comprehensive RDP input channel | Fundamentally different architecture (RDP session host, not VNC helper input); not directly comparable | Apache-2.0 |

Note: **ViGEm removed from ranking** -- it is a virtual gamepad driver for gaming, not used by any RMM tool for keyboard/mouse delivery.

### Service Reliability And Drift Detection

| Rank | Project | Language | Key Strength | Verified Detail | License |
|---|---|---|---|---|---|
| 1 | **MeshAgent** (this project) | C | Service recovery, watchdog mesh, policy orchestration, drift detection | Broad open-source implementation; 12 policy features | Apache-2.0 |
| 2 | **UltraVNC** | C++ | Service-mode elevation, secure desktop bridging | Solid but limited to VNC-specific concerns | GPL-2.0 |
| 3 | **osquery** | C++ | System state detection and monitoring | Strong query/detection but no active protection | Apache-2.0/GPL-2.0 |
| 4 | **Velociraptor** | Go | Forensic-grade VQL query engine | **Known LPE vulnerability**: `BUILTIN\Users` gets `WRITE_DAC` on install dir. No watchdog or service recovery policy. | AGPL-3.0 |

Note: **Velociraptor downranked** from #3 due to verified privilege escalation vulnerability (Synacktiv advisory).

## Implementation Priority Matrix (Revised with Research Findings)

| ID | Tier | Domain | Complexity | Value | Viability | Recommended Phase |
|---|---|---|---|---|---|---|
| T1-SCREEN-001 | T1 | DXGI Desktop Duplication | Medium | **Very High** | Production-proven | P3 |
| T1-SCREEN-003 | T1 | Secure Desktop Capture | Low | **Very High** | Production-proven | P3 |
| T1-INPUT-001 | T1 | Session Bridge Verification | Low | High | Already implemented; needs audit | P3 |
| T1-INPUT-002 | T1 | BlockInput Verification | Low | Medium | Already implemented | P3 |
| T1-ELEVATED-001 | T1 | PPL Awareness | Low | Medium | Straightforward API | P4 |
| T1-SCREEN-002 | T1 | WGC API | Medium | Medium | Fallback for cross-GPU only | P4 |
| T2-SCREEN-001 | T2 | GPU Encoding (zero-copy) | High | **Very High** | Sunshine proves it; major UX impact | P4-P5 |
| T2-ELEVATED-001 | T2 | Early-Boot Service | Low | Medium | Standard service config | P3 |
| T2-ELEVATED-002 | T2 | Credential Provider | Medium-High | High | multiOTP reference; production-viable | P5+ |
| T2-SCREEN-002 | T2 | Virtual Desktop Awareness | Low | Low | Metadata only | P4 |
| T2-INPUT-001 | T2 | UI Automation | Medium | Low | Not a raw-input replacement; niche use | P5 (optional) |
| T3-SCREEN-001 | T3 | IDD Virtual Display | **High** (revised down) | **Very High** | **Production-viable** (Citrix shipped it) | P5 |
| T3-SCREEN-002 | T3 | DWM Shared Surface | Medium | **Low** (revised down) | **Not recommended** | Deprioritized |
| T3-INPUT-001 | T3 | Virtual HID Driver | Very High | **Low** (revised down) | **Not needed for RMM** | Deprioritized |
| T3-ELEVATED-001 | T3 | Kernel Callbacks | Very High | **Low** (revised down) | **Defeated by BYOVD** without ELAM | Deprioritized |

## Real-World Threat Model for RMM Agent Protection

Based on verified security research (Microsoft, Elastic, Arctic Wolf, ReliaQuest, 2024-2025):

### Attack Categories by Frequency

1. **Credential compromise / RMM abuse of trust** (most common): Attackers install legitimate RMM agents (AnyDesk, ScreenConnect, Atera) as persistence. 51+ RMM solutions identified as attack vectors; 32 observed in a single quarter. 59.4% of ransomware cases began with external remote access.
2. **BYOVD** (most effective against protected agents): Attackers load a legitimately signed but vulnerable kernel driver to kill security/RMM processes from kernel mode. This can defeat many userland and kernel protections including ObRegisterCallbacks.
3. **BYOI** (Bring Your Own Installer): Interrupt the agent's own upgrade mid-process to leave it in a non-running state.
4. **Zero-day exploit of RMM platform**: CVE-2025-11492/CVE-2025-11493 (ConnectWise Automate AiTM RCE), SimpleHelp vulnerabilities (CISA advisory), BeyondTrust Remote Support zero-days.

### What the Best Commercial RMMs Actually Do (2025)

Based on public documentation from ConnectWise, Datto, NinjaOne, and Huntress:

| Defense | Who Does It | Our Status |
|---|---|---|
| Service ACL hardening (deny stop/delete to non-SYSTEM) | All | Partial (verify) |
| Anti-uninstall requiring server-side authorization | All | Not implemented |
| Firewall rule monitoring + auto-remediation | Datto, Huntress | Not implemented |
| Binary integrity verification on startup | All | Partial |
| Mutual TLS with pinned certificates | Most | Partial |
| Atomic/resilient upgrade (defend against BYOI) | Most | In scope (lifecycle engine) |
| **Kernel driver self-protection (ObRegisterCallbacks)** | **None** | N/A -- correctly deprioritized |

### Recommended Investment Priority (Defense)

1. Atomic upgrade process with rollback (lifecycle engine -- already in SSOT scope)
2. Service ACL hardening (verify `WRITE_DAC` denied to non-SYSTEM)
3. Firewall rule auto-remediation (detect and roll back rules blocking agent)
4. Server-side anomaly detection for agent behavior
5. Binary integrity verification on startup and update

## Integration With Realignment Program

This roadmap feeds into the realignment program as follows:

- **LEDGER-008** (Session 1 bridge) -- T1-SCREEN-003, T1-INPUT-001 refine the existing bridge for secure desktop
- **LEDGER-013** (Pre-protection capture) -- T1-SCREEN-001 provides DXGI capture; T3-SCREEN-001 (IDD) is tracked only as a signed-driver evaluation that requires separate policy approval
- New ledger entries (LEDGER-014, LEDGER-015, LEDGER-016) cover net-new capability

### New Ledger Entries

- **LEDGER-014**: DXGI/WGC/IDD capture backend -- add hardware-composited capture alongside existing GDI path; IDD remains a separately approved signed-driver evaluation
- **LEDGER-015**: Input delivery verification -- audit existing Session 0 bridge and BlockInput management; verify SYSTEM IL is retained through helper chain
- **LEDGER-016**: Privileged service posture -- PPL awareness, early-boot readiness, credential provider research, service ACL hardening

### New TODO Entries

- **TODO-032**: Implement DXGI Desktop Duplication capture backend with `DuplicateOutput1`, progressive backoff, rotation handling, and GDI fallback
- **TODO-033**: Implement WGC capture backend for cross-GPU fallback on Win10 1903+
- **TODO-034**: Harden secure-desktop capture with explicit `OpenDesktop("Winlogon")` targeting and `EVENT_SYSTEM_DESKTOPSWITCH` listening
- **TODO-035**: Audit and verify Session 0 bridge: confirm SYSTEM IL retention through helper chain, confirm `SendInput` reaches elevated windows
- **TODO-036**: Verify `BlockInput` semantics: same-thread exemption and service-managed cleanup of application blocks
- **TODO-037**: Add PPL detection via `NtQueryInformationProcess(ProcessProtectionInformation)` to diagnostics and drift detection
- **TODO-038**: GPU-accelerated encoding spike: implement Sunshine-style zero-copy pipeline (shared texture handle + keyed mutex + NVENC)
- **TODO-039**: Evaluate IDD virtual display driver with attestation signing under the approved-driver policy

### New Regression Matrix Rows

- DXGI capture: frame captured on DWM-composited desktop with DX overlay content visible (GDI would miss this)
- DXGI fallback: GDI engages cleanly on pre-Win8, RDP, or when DXGI reports `DXGI_ERROR_UNSUPPORTED`
- Secure desktop capture: frame captured during active UAC prompt via explicit Winlogon desktop targeting from SYSTEM context
- Input on elevated window: keystroke delivered to an elevated `cmd.exe` from SYSTEM-IL KVM helper in user session
- BlockInput cleanup: `SendInput` succeeds from same thread while `BlockInput(TRUE)` active; service-managed `BlockInput(FALSE)` restores input state for approved sessions
- PPL diagnostic accuracy: PPL processes reported in diagnostics without false drift alarms
- Display-affinity handling: DXGI/WGC/GDI render `WDA_EXCLUDEFROMCAPTURE` windows as black; any IDD evaluation requires separate approved-driver policy

### Corrected Regression Matrix Rows (from prior version)

**REMOVED**: "DXGI capture produces a valid frame including a `WDA_EXCLUDEFROMCAPTURE` window" -- this is FALSE. DXGI respects display affinity. The DXGI regression test should verify DX overlay capture (content GDI misses), not protected-content capture.

## Sources

### Microsoft Documentation
- [Desktop Duplication API](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api)
- [IDXGIOutput5::DuplicateOutput1](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_5/nf-dxgi1_5-idxgioutput5-duplicateoutput1)
- [SetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity)
- [BlockInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-blockinput)
- [SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)
- [Windows Integrity Mechanism Design](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10))
- [Session 0 Isolation](https://techcommunity.microsoft.com/blog/askperf/application-compatibility---session-0-isolation/ba-p/372361)
- [SendSAS](https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas)
- [IDD Model Overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/indirect-display-driver-model-overview)
- [Attestation Sign Windows Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation)
- [ELAM Driver Submission](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-submission)
- [Protecting Anti-Malware Services (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [V2 Credential Provider Sample](https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/credential-provider/)
- [DXGI Desktop Duplication Sample](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/DXGIDesktopDuplication/cpp/DesktopDuplication.cpp)

### Open-Source Projects (Analyzed)
- [Sunshine/LizardByte](https://github.com/LizardByte/Sunshine) -- display_vram.cpp, display_ram.cpp, duplication_t class
- [OBS Studio](https://github.com/obsproject/obs-studio) -- duplicator-monitor-capture.c, WGC integration
- [RustDesk](https://github.com/rustdesk/rustdesk) -- libs/scrap (DXGI, WGC), libs/hwcodec
- [UltraVNC](https://github.com/ultravnc/UltraVNC) -- vncservice.cpp, service-mode injection
- [multiOTP Credential Provider](https://github.com/multiOTP/multiOTPCredentialProvider)
- [ViGEm](https://docs.nefarius.at/projects/ViGEm/) -- gamepad emulation (NOT applicable to RMM input)
- [IbInputSimulator](https://github.com/Chaoses-Ib/IbInputSimulator) -- multi-backend, game-focused
- [Rhydon1337/windows-kernel-process-protector](https://github.com/Rhydon1337/windows-kernel-process-protector)
- [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast)
- [Virtual Display Driver](https://github.com/peacepenguin/Virtual-Display-Driver)

### Security Research
- [Elastic: Inside Microsoft's Plan to Kill PPLFault](https://www.elastic.co/security-labs/inside-microsofts-plan-to-kill-pplfault) (Feb 2024)
- [itm4n: Ghost in the PPL Part 1 - BYOVDLL](https://itm4n.github.io/ghost-in-the-ppl-part-1/) (Aug 2024)
- [Microsoft: Keys to the Kingdom - RMM Exploits 2024-25](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/keys-to-the-kingdom-rmm-exploits-enabling-human-operated-intrusions-in-2024%E2%80%9325/4410903)
- [Synacktiv: Velociraptor LPE](https://www.synacktiv.com/en/advisories/local-privilege-escalation-in-windows-velociraptor-service)
- [Citrix: Introducing Citrix IDD](https://www.citrix.com/blogs/2024/06/10/introducing-citrix-idd-enhancing-your-hdx-experience/) (2024)
- [Google Project Zero: Bypassing Administrator Protection via UIAccess](https://projectzero.google/2026/02/windows-administrator-protection.html) (Feb 2026)

## Document Set

This roadmap is a companion to:

- `docs/testing/20260331_REALIGNMENT_SSOT.md`
- `docs/testing/20260331_REALIGNMENT_LEDGER.md`
- `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md`
- `docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md`

All four documents are updated in the same change series as this roadmap.
