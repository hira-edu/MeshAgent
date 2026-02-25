# Advanced Debug Toolchain (Current)

## Scope
This document is the authoritative baseline for deep debugging, regression, and stress testing of MeshAgent install/update/uninstall and svchost service behavior.

## Required Toolchain
- `WinDbgX` debugger: `C:\Users\Workstation\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe`
- `Procmon` (Sysinternals): `C:\Users\Workstation\AppData\Local\Microsoft\WinGet\Links\Procmon.exe`
- `procdump` (Sysinternals): `C:\Users\Workstation\AppData\Local\Microsoft\WinGet\Links\procdump.exe`
- `WPR` (ETW recorder): `C:\Windows\System32\wpr.exe`
- `WPA` (ETW analyzer): `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpa.exe`
- `xperf` (ETW CLI): `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe`
- `pktmon` (packet monitor): `C:\Windows\System32\PktMon.exe`
- `netsh trace` (network/system trace): `C:\Windows\System32\netsh.exe`

## Install Or Refresh
Run these before major debugging and regression cycles:

```powershell
winget install --id Microsoft.Sysinternals.Suite -e --accept-package-agreements --accept-source-agreements
winget install --id Microsoft.WinDbg -e --accept-package-agreements --accept-source-agreements
winget upgrade --id Microsoft.Sysinternals.Suite -e --accept-package-agreements --accept-source-agreements
winget upgrade --id Microsoft.WinDbg -e --accept-package-agreements --accept-source-agreements
```

## High-Level Debug Workflows
1. Install/update/uninstall ETW + file/registry deep trace.
2. Service crash/hang capture with full dumps.
3. Network/TLS persistence capture during reconnect and post-update.
4. Native full regression + harness regression + stress loops.

## Workflow A: Deep Install/Update/Uninstall Trace
Capture ETW and ProcMon while running native flows:

```powershell
wpr.exe -start GeneralProfile -filemode
Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile "C:\Users\Workstation\Documents\GitHub\MeshAgent\docs\testing\evidence\advanced\procmon_install.pml"
"C:\Users\Workstation\Documents\GitHub\MeshAgent\meshservice\x64\StealthLab\MeshService-2022.exe" -fullinstall
Procmon.exe /Terminate
wpr.exe -stop "C:\Users\Workstation\Documents\GitHub\MeshAgent\docs\testing\evidence\advanced\install.etl"
```

Repeat for `-fullupdate` and `-fulluninstall`.

## Workflow B: Crash/Hang Dump Capture
Use full dumps for service host and agent process:

```powershell
procdump.exe -accepteula -ma -e -w svchost.exe "C:\Users\Workstation\Documents\GitHub\MeshAgent\docs\testing\evidence\advanced\dumps"
procdump.exe -accepteula -ma -h -w MeshService-2022.exe "C:\Users\Workstation\Documents\GitHub\MeshAgent\docs\testing\evidence\advanced\dumps"
```

Use `WinDbgX` for dump triage and call stack analysis.

## Workflow C: Network Persistence Trace
Capture network path during service restart and update reconnect:

```powershell
pktmon start --etw -p 0
netsh trace start capture=yes report=no persistent=no tracefile="C:\Users\Workstation\Documents\GitHub\MeshAgent\docs\testing\evidence\advanced\network.etl"
"C:\Users\Workstation\Documents\GitHub\MeshAgent\meshservice\x64\StealthLab\MeshService-2022.exe" -fullupdate
netsh trace stop
pktmon stop
```

## Workflow D: Native Regression + Harness + Stress
Run native full regression, then update stress harness:

```powershell
"C:\Users\Workstation\Documents\GitHub\MeshAgent\meshservice\x64\StealthLab\MeshService-2022.exe" -fullregression
"C:\Users\Workstation\Documents\GitHub\MeshAgent\meshservice\x64\StealthLab\MeshService-2022.exe" "C:\Users\Workstation\Documents\GitHub\MeshAgent\test\update-test.js" --CycleCount=20
```

For remote desktop/terminal/file transfer major-regression investigations, include:

```powershell
"C:\Users\Workstation\Documents\GitHub\MeshAgent\meshservice\x64\StealthLab\MeshService-2022.exe" --selfTest=1 --serviceName="WinDiagnosticHost" --majorBug=1
```

## Required Evidence Layout
Store each run in:
- `docs/testing/evidence/advanced/<YYYYMMDD_HHMMSS>/`

Minimum artifacts per run:
- `commands.txt`
- `install.etl`, `update.etl`, `uninstall.etl` where applicable
- `procmon_install.pml`, `procmon_update.pml`, `procmon_uninstall.pml`
- `network.etl`, `pktmon.etl` where applicable
- `dumps\*.dmp`
- validation outputs and JSON summaries

## Notes
- Runtime install/uninstall/update logic remains native C/C++ and JS only.
- Do not add PowerShell scripts for runtime/regression logic.
- Historical documents in `docs/testing/` may be stale; use this file as the current source of truth for advanced debugging workflow.
