# MeshAgent Svchost Integration Audit & Debug Script

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ("{0}" -f $Title) -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param(
        [string]$Prefix,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    Write-Host ("  [{0}] {1}" -f $Prefix, $Message) -ForegroundColor $Color
}

function Read-MshFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return @{} }
    $result = @{}

    foreach ($line in (Get-Content -Path $Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed.StartsWith("#")) { continue }

        $parts = $trimmed.Split("=", 2)
        if ($parts.Count -eq 2) {
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            if ($key) { $result[$key] = $value }
        }
    }

    return $result
}

$scriptRoot = Split-Path -Parent $PSCommandPath
if (-not $scriptRoot) { $scriptRoot = (Get-Location).ProviderPath }

$repoRoot   = $scriptRoot
$serviceName = "WinDiagnosticHost"
$installRoot = Join-Path $env:SystemRoot "System32\DiagnosticHost"
$installedDllPath = Join-Path $installRoot "diagsvc.dll"
$sourceDllPath = Join-Path $repoRoot "meshservice\x64\StealthLab_DLL\MeshService-2022.dll"
$configPath = Join-Path $repoRoot "WinDiagnosticHost.msh"

Write-Section "MeshAgent Svchost Integration Audit"

Write-Host "Repository : $repoRoot" -ForegroundColor Gray
Write-Host "Service    : $serviceName" -ForegroundColor Gray
Write-Host "InstallDir : $installRoot" -ForegroundColor Gray
Write-Host ""

# 1. Source files
Write-Section "[1] Validating build artifacts"

if (Test-Path $sourceDllPath) {
    $dllInfo = Get-Item $sourceDllPath
    Write-Status "OK" ("Source DLL present: {0}" -f $sourceDllPath) ([ConsoleColor]::Green)
    Write-Status "--" ("Size     : {0} bytes" -f $dllInfo.Length)
    Write-Status "--" ("Modified : {0:u}" -f $dllInfo.LastWriteTimeUtc)
} else {
    Write-Status "ERR" ("Source DLL missing: {0}" -f $sourceDllPath) ([ConsoleColor]::Red)
    Write-Status "HINT" "Run .\build_complete.ps1 to build StealthLab DLL" ([ConsoleColor]::Yellow)
}

$mshData = Read-MshFile -Path $configPath
if ($mshData.Count -gt 0) {
    Write-Status "OK" ("Provisioning file present: {0}" -f $configPath) ([ConsoleColor]::Green)
    foreach ($key in @("MeshName","MeshServer","MeshID","ServerID","MeshType","InstallFlags","AutoRegister")) {
        if ($mshData.ContainsKey($key)) {
            Write-Status "--" ("{0} = {1}" -f $key, $mshData[$key])
        }
    }
} else {
    Write-Status "WARN" ("Provisioning file not found or empty: {0}" -f $configPath) ([ConsoleColor]::Yellow)
}

# 2. Service installation
Write-Section "[2] Inspecting service registration"

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    $statusColor = if ($service.Status -eq 'Running') { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
    Write-Status "OK" ("Service installed. Status: {0}" -f $service.Status) $statusColor
    Write-Status "--" ("StartType : {0}" -f $service.StartType)
} else {
    Write-Status "ERR" "Service is not installed" ([ConsoleColor]::Red)
}

# 3. Registry configuration
Write-Section "[3] Checking registry configuration"

$regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
if (Test-Path $regBase) {
    Write-Status "OK" ("Service key present: {0}" -f $regBase) ([ConsoleColor]::Green)
    $imagePath = (Get-ItemProperty -Path $regBase -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    if ($imagePath) {
        Write-Status "--" ("ImagePath: {0}" -f $imagePath)
    }
    $startType = (Get-ItemProperty -Path $regBase -Name Start -ErrorAction SilentlyContinue).Start
    if ($startType) {
        Write-Status "--" ("Start    : {0} (2=Auto,3=Manual,4=Disabled)" -f $startType)
    }

    $paramsKey = Join-Path $regBase "Parameters"
    if (Test-Path $paramsKey) {
        Write-Status "OK" "Parameters key present" ([ConsoleColor]::Green)
        $svcDll = (Get-ItemProperty -Path $paramsKey -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
        if ($svcDll) { Write-Status "--" ("ServiceDll : {0}" -f $svcDll) }
        $svcMain = (Get-ItemProperty -Path $paramsKey -Name ServiceMain -ErrorAction SilentlyContinue).ServiceMain
        if ($svcMain) {
            if ($svcMain -ne "Stealth_SvchostServiceMain") {
                Write-Status "WARN" ("ServiceMain unexpected value: {0}" -f $svcMain) ([ConsoleColor]::Yellow)
            } else {
                Write-Status "--" ("ServiceMain : {0}" -f $svcMain)
            }
        } else {
            Write-Status "WARN" "ServiceMain value missing" ([ConsoleColor]::Yellow)
        }
    } else {
        Write-Status "ERR" "Parameters subkey missing" ([ConsoleColor]::Red)
    }
} else {
    Write-Status "ERR" ("Registry key missing: {0}" -f $regBase) ([ConsoleColor]::Red)
}

# 4. DLL installation
Write-Section "[4] Checking installed DLL"

if (Test-Path $installRoot) {
    Write-Status "OK" ("Install directory present: {0}" -f $installRoot) ([ConsoleColor]::Green)
} else {
    Write-Status "ERR" ("Install directory missing: {0}" -f $installRoot) ([ConsoleColor]::Red)
}

if (Test-Path $installedDllPath) {
    $installedInfo = Get-Item $installedDllPath
    Write-Status "OK" ("Installed DLL present: {0}" -f $installedDllPath) ([ConsoleColor]::Green)
    Write-Status "--" ("Size     : {0} bytes" -f $installedInfo.Length)
    Write-Status "--" ("Modified : {0:u}" -f $installedInfo.LastWriteTimeUtc)

    if (Test-Path $sourceDllPath) {
        $sourceInfo = Get-Item $sourceDllPath
        if ($sourceInfo.Length -eq $installedInfo.Length) {
            Write-Status "OK" "Installed DLL size matches source" ([ConsoleColor]::Green)
        } else {
            Write-Status "WARN" ("DLL size mismatch. Source={0} Installed={1}" -f $sourceInfo.Length, $installedInfo.Length) ([ConsoleColor]::Yellow)
        }
    }
} else {
    Write-Status "ERR" ("Installed DLL missing: {0}" -f $installedDllPath) ([ConsoleColor]::Red)
}

# 5. Svchost registration
Write-Section "[5] Validating svchost registration"

$svchostKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
$netsvcs = (Get-ItemProperty -Path $svchostKey -Name "netsvcs" -ErrorAction SilentlyContinue).netsvcs
if ($netsvcs) {
    if ($netsvcs -contains $serviceName) {
        Write-Status "OK" ("Service listed in netsvcs group ({0})" -f $serviceName) ([ConsoleColor]::Green)
    } else {
        Write-Status "ERR" "Service not present in netsvcs group" ([ConsoleColor]::Red)
        Write-Status "HINT" "Re-run installation or update netsvcs multi-string manually" ([ConsoleColor]::Yellow)
    }
} else {
    Write-Status "WARN" "Unable to read netsvcs group" ([ConsoleColor]::Yellow)
}

# 6. Process status
Write-Section "[6] Inspecting running process"

$serviceProcess = $null
if ($service) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.ProcessId) {
        $serviceProcess = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
        if ($serviceProcess) {
            Write-Status "OK" ("Service running under PID {0}" -f $serviceProcess.Id) ([ConsoleColor]::Green)
            Write-Status "--" ("Process : {0}" -f $serviceProcess.Name)
            Write-Status "--" ("Memory  : {0:N2} MB" -f ($serviceProcess.WorkingSet64 / 1MB))
            if ($serviceProcess.Name -ieq "svchost") {
                Write-Status "OK" "Service hosted by svchost.exe" ([ConsoleColor]::Green)
            } else {
                Write-Status "WARN" ("Unexpected host process: {0}" -f $serviceProcess.Name) ([ConsoleColor]::Yellow)
            }

            try {
                $moduleMatch = $serviceProcess.Modules | Where-Object { $_.FileName -like "*diagsvc.dll" }
                if ($moduleMatch) {
                    Write-Status "OK" "DLL loaded in process" ([ConsoleColor]::Green)
                } else {
                    Write-Status "WARN" "DLL not present in module list" ([ConsoleColor]::Yellow)
                }
            } catch {
                Write-Status "WARN" "Unable to enumerate process modules (administrator privileges required)" ([ConsoleColor]::Yellow)
            }
        }
    }
}

if (-not $serviceProcess) {
    Write-Status "WARN" "Service is not running; start service to inspect runtime state" ([ConsoleColor]::Yellow)
}

# 7. Network connections
Write-Section "[7] Network activity snapshot"

if ($serviceProcess) {
    try {
        $connections = Get-NetTCPConnection -OwningProcess $serviceProcess.Id -ErrorAction SilentlyContinue
        if ($connections) {
            Write-Status "OK" ("Active TCP connections: {0}" -f $connections.Count) ([ConsoleColor]::Green)
            $connections | Select-Object -First 5 | ForEach-Object {
                Write-Status "--" ("{0}:{1} -> {2}:{3} [{4}]" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.State)
            }
        } else {
            Write-Status "INFO" "No active TCP connections detected" ([ConsoleColor]::Gray)
        }
    } catch {
        Write-Status "WARN" "Failed to query TCP connections (requires Windows 8+ and admin privileges)" ([ConsoleColor]::Yellow)
    }
} else {
    Write-Status "INFO" "Skipping network check because service is not running" ([ConsoleColor]::Gray)
}

# 8. Event log snapshot
Write-Section "[8] Recent service-related events"

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName  = 'System'
        ID       = 7034,7035,7036,7040,7045
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$serviceName*" } | Select-Object -First 5

    if ($events) {
        foreach ($event in $events) {
            Write-Status "LOG" ("[{0}] {1}: {2}" -f $event.TimeCreated, $event.LevelDisplayName, ($event.Message.Split("`n")[0]))
        }
    } else {
        Write-Status "INFO" "No matching service events found in the last 24 hours" ([ConsoleColor]::Gray)
    }
} catch {
    Write-Status "WARN" "Unable to query event logs" ([ConsoleColor]::Yellow)
}

# Summary
$issues = @()

if (-not $service) { $issues += "Service not installed" }
if ($service -and $service.Status -ne 'Running') { $issues += "Service is not running" }
if (-not (Test-Path $installedDllPath)) { $issues += "Installed DLL missing" }
if ($serviceProcess -and $serviceProcess.Name -ne "svchost") { $issues += "Service host is not svchost.exe" }
if ($netsvcs -and -not ($netsvcs -contains $serviceName)) { $issues += "Service missing from netsvcs group" }

Write-Section "Summary"

if ($issues.Count -eq 0) {
    Write-Status "OK" "All checks passed" ([ConsoleColor]::Green)
} else {
    Write-Status "ISSUE" ("Detected {0} problem(s)" -f $issues.Count) ([ConsoleColor]::Red)
    foreach ($item in $issues) {
        Write-Status "--" $item ([ConsoleColor]::Red)
    }
}

Write-Section "Next Steps and Useful Commands"

Write-Host "Start service     : Start-Service -Name $serviceName" -ForegroundColor Gray
Write-Host "Stop service      : Stop-Service -Name $serviceName" -ForegroundColor Gray
Write-Host "Restart service   : Restart-Service -Name $serviceName" -ForegroundColor Gray
Write-Host "Service status    : Get-Service -Name $serviceName | Format-List *" -ForegroundColor Gray
Write-Host "Process modules   : `"Get-Process -Name svchost -IncludeUserName | ? { `$_.Id -eq PID } | Select-Object -ExpandProperty Modules`"" -ForegroundColor Gray
Write-Host "Reinstall svchost : .\install_svchost_now.ps1 (run as Administrator)" -ForegroundColor Gray
Write-Host ""
