# Scoped Windows Lifecycle Hardening Plan

Date: 2026-05-10

## Superseded

This plan is superseded by `docs/testing/20260510_RUNDLL32_SSOT_MIGRATION_PLAN.md` for the requested rundll32-only SSOT migration direction.

Keep this file only as historical context for the earlier scoped hardening decision.

## Decision

Keep the current working native service binary lifecycle path for Windows install, uninstall, and update. Do not migrate all lifecycle paths to rundll32.

The only authorized rundll32 launch surface remains the KVM session bridge export. Using rundll32 as a generic launcher for install, uninstall, update, PowerShell, terminal, file operations, or arbitrary helpers would add another process-lifecycle surface without fixing the current update-loop failure mode.

## SSOT Targets

- KVM desktop bridge: `rundll32.exe <service-dll>,KvmSessionBridgeW` only.
- Windows install: native service lifecycle entrypoint.
- Windows uninstall: native service lifecycle entrypoint.
- Windows update: native service lifecycle entrypoint using `-fullupdate`.
- Windows terminal command shell: `%SystemRoot%\System32\cmd.exe`.
- Windows terminal PowerShell: `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`.
- Windows official path resolution SSOT: `modules/win-system-paths.js`.

## Removed Legacy Behavior

- Windows server-triggered update must not enter the legacy JavaScript `service-manager` retry loop.
- Windows console self-update must not copy `.update.exe` over the live binary or re-exec from a console fallback.
- Windows updater-version probing must not spawn `.update.exe`.
- PowerShell must not be resolved from `SysWow64`, diagnostic helper paths, install directories, current directories, or caller-supplied custom host paths.
- Command shell and PowerShell terminal requests are canonicalized to the official System32 executable paths.

## Implementation Plan

1. Keep KVM rundll32 hardening as-is and do not expand the approved rundll32 command set.
2. Route `modules/agent-installer.js` Windows update exports to one native `-fullupdate` lifecycle call.
3. Block Windows console self-update through the JavaScript helper.
4. Leave non-Windows update behavior on the existing updater path.
5. Resolve Windows terminal, pseudo-console, toaster, systray, file search, dispatcher, identifiers, process manager, and task scheduler PowerShell/SCHTASKS launches through `modules/win-system-paths.js`.
6. Call `LockWorkStation` through `User32.dll` directly; do not use `cmd.exe` or rundll32 for desktop lock.
7. Treat missing `%SystemRoot%` or missing official PowerShell as a fail-closed configuration error.

## Validation Gates

- Server-triggered Windows update invokes native `-fullupdate` once and does not schedule a recurring JavaScript update interval.
- No Windows terminal or pseudo-console PowerShell launch uses `SysWow64`, diagnostic host, install directory, current directory, or caller-supplied custom path.
- No Windows toast, tray, file-search, or dispatcher PowerShell launch bypasses `modules/win-system-paths.js`.
- No Windows identifiers, process-manager, or task-scheduler PowerShell/SCHTASKS launch bypasses `modules/win-system-paths.js`.
- Desktop lock uses `User32.dll!LockWorkStation` directly and does not shell through rundll32.
- Console self-update on Windows returns a hard failure that points callers back to the native service lifecycle.
- KVM remains the only rundll32-approved desktop/session bridge path.
- Build gate: `msbuild meshservice/MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m`.
