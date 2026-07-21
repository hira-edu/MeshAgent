# Advanced Debug Toolchain

## Scope

This is the current procedure for deep Windows diagnostics of MeshAgent
install, update, uninstall, service-host, process, and network failures.
Capture only on systems the operator owns or is authorized to diagnose.

## Tools

- WinDbg or WinDbgX for dump analysis
- Sysinternals ProcDump and Process Monitor
- Windows Performance Recorder/Analyzer (`wpr.exe`, WPA)
- `pktmon.exe` and `netsh trace` for network capture
- the repository's native validation and Node contract scripts

Resolve installed locations with `Get-Command` rather than hard-coding a
workstation-specific path. WinDbg and Sysinternals tools can be installed with
`winget` when permitted by local policy.

## Per-run directory

Keep large or sensitive output out of source control:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Join-Path (Resolve-Path .) "artifacts\debug\$stamp"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
```

Record the exact commands, source commit, binary hashes, elevation state, and
test host in that directory. Review traces for credentials, tokens, endpoint
identifiers, and user data before sharing them.

## Install, update, and uninstall trace

```powershell
$agent = Resolve-Path '.\meshservice\x64\StealthLab\MeshService-2022.exe'
wpr.exe -start GeneralProfile -filemode
Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile (Join-Path $runDir 'lifecycle.pml')
& $agent -fullinstall
Procmon.exe /Terminate
wpr.exe -stop (Join-Path $runDir 'lifecycle.etl')
```

Repeat with the exact update or uninstall operation being diagnosed. Always
run the corresponding validation command after the operation and preserve both
stdout and stderr.

## Crash and hang capture

Use a dedicated dump directory:

```powershell
$dumpDir = Join-Path $runDir 'dumps'
New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
procdump.exe -accepteula -ma -e -w svchost.exe $dumpDir
procdump.exe -accepteula -ma -h -w MeshService-2022.exe $dumpDir
```

Scope an `svchost.exe` capture to the affected service/PID as soon as the PID
is known; a global host capture can collect unrelated system data.

## Network capture

```powershell
$networkTrace = Join-Path $runDir 'network.etl'
pktmon start --etw -p 0
netsh trace start capture=yes report=no persistent=no tracefile="$networkTrace"
# Reproduce the connection or update failure here.
netsh trace stop
pktmon stop
```

Stop capture promptly after reproduction and treat the output as sensitive.

## Regression after diagnosis

Start with the smallest contract for the corrected surface. For a full local
Windows lifecycle regression on an approved elevated test host:

```powershell
node .\test\run_grouped_regression.js --evidence (Join-Path $runDir 'grouped')
```

The minimum useful diagnostic bundle contains:

- `commands.txt` or an equivalent command transcript;
- source commit and hashes of every tested binary;
- the focused trace/dump files;
- validation stdout/stderr and JSON reports;
- a short root-cause summary that distinguishes observation from inference.

Do not check this bundle into `docs/`; attach it to the authorized incident or
release record.
