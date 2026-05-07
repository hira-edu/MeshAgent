# 2026-05-07 DiagnosticHost KVM Audit Remediation Plan

## Scope

This plan is limited to the audit-backed DiagnosticHost remote-desktop findings observed on this host. The retained KVM surface remains the SSOT-defined `svchost` service plus `rundll32.exe` Session 1 bridge:

- `meshservice/stealth_svchost.c`
- `meshcore/KVM/Windows/kvm.c`
- `microstack/ILibProcessPipe.c`

No browser, relay, generic process-spawn, or PowerShell lifecycle layer owns this fix.

## Regression Surface Map

| Finding | Source path | Touched target | Regression surface | Fix rule |
|---|---|---|---|---|
| CRT invalid parameter in bridge read compaction | `microstack/ILibProcessPipe.c` | Windows process-pipe read windows | KVM bridge pipes and any Windows `ILibProcessPipe` consumer | validate read-window invariants before pointer arithmetic or compacting buffers |
| CRT invalid parameter in environment merge | `microstack/ILibProcessPipe.c` | Windows process-spawn environment block merge | KVM bridge spawn and any `CreateProcess*` caller that passes override env vars | use byte counts for `memcpy_s`; fail spawn deterministically if merge cannot be represented |
| CRT handler swallowed KVM helper corruption | `meshservice/stealth_svchost.c` | `KvmSessionBridgeW` helper process only | rundll32-hosted bridge helper | fail fast only for the bridge helper so WER/LocalDumps can capture corruption |
| Missing primary log evidence for first packets | `meshcore/KVM/Windows/kvm.c`, `meshservice/stealth_svchost.c` | bridge/service KVM telemetry | KVM trace logging only when `STEALTH_KVM_TRACE_STARTUP` is enabled | write the same first-packet and lifecycle evidence to module-local `svchost-debug.log`; keep legacy temp trace for existing probes |
| Child-exit evidence loses PID | `meshcore/KVM/Windows/kvm.c` | KVM child exit handling | KVM lifecycle logging and event correlation | resolve PID from the sender process/context before marking child absent; child-present state remains the authority for active status |
| Startup provisioning log ignored branded files | `meshservice/stealth_svchost.c` | svchost service startup logging | DiagnosticHost config observability | log hidden, DLL-named, executable-sibling, service-named `.msh`, plus branded `.conf` candidates |
| Build outputs dirty the tree | `.gitignore`, git index | repo hygiene | build output directories only | `MeshAgent.Build.proj` is the SSOT build entrypoint; generated binaries/intermediates are not implementation truth |

## Build SSOT

Use one supported build command for StealthLab outputs:

```cmd
MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

`MeshAgent.Build.proj` serializes:

1. `StealthLab_DLL|x64`
2. `MeshConsole|Release|x64`
3. `StealthLab|x64`
4. `StealthLab|Win32`

Do not run parallel direct project builds against the same tree. Do not introduce PowerShell build wrappers; Python asset generators remain MSBuild targets.

## Verification Gates

Minimum targeted gates for this remediation:

- `node test/kvm_audit_findings_contract.js`
- `node test/kvm_bridge_flow_control_contract.js`
- `node test/kvm_remote_desktop_freshness_contract.js`
- `node test/kvm_bridge_system_token_contract.js`
- `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`

Browser/relay regressions are out of this source tree unless the sibling MeshCentral repo is present and its SSOT paths are available.
