#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$ServiceName = 'AcmeTelemetryCore',
  [string]$DisplayName = 'Acme Telemetry Core Service',
  [string]$CompanyName = 'Acme Corp',
  [string]$InstallPath = 'C:\\ProgramData\\Acme\\TelemetryCore',
  [switch]$UninstallFirst
)

$ErrorActionPreference = 'Stop'

Write-Host "ServiceName = $ServiceName" -ForegroundColor Cyan
Write-Host "InstallPath = $InstallPath" -ForegroundColor Cyan

function Invoke-Agent {
  param([string[]]$Args)
  $exe = Get-ChildItem -Filter 'MeshService64.exe','MeshService.exe' -Path (Get-Location) | Select-Object -First 1
  if (-not $exe) { throw 'MeshService64.exe or MeshService.exe not found in current directory' }
  & $exe.FullName @Args
}

if ($UninstallFirst) {
  Write-Host "[uninstall] $ServiceName" -ForegroundColor Yellow
  try { Invoke-Agent -Args @('-fulluninstall', "--meshServiceName=$ServiceName") } catch { Write-Host "(ignore) $_" -ForegroundColor DarkGray }
  Start-Sleep -Seconds 2
}

Write-Host "[install] $ServiceName" -ForegroundColor Green
Invoke-Agent -Args @(
  '-fullinstall',
  "--installPath=$InstallPath",
  "--meshServiceName=$ServiceName",
  "--displayName=$DisplayName",
  "--companyName=$CompanyName",
  '--copy-msh=1'
)

Write-Host "[done]" -ForegroundColor Green

