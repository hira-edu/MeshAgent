#Requires -Version 5.1
<#
.SYNOPSIS
  Cleans previous MeshAgent installations from a Windows endpoint: services, binaries, logs, and related entries.

.DESCRIPTION
  - Stops and deletes specified services (or auto-detects common MeshAgent services)
  - Kills running MeshService/meshagent processes
  - Removes install folders, .msh configs, logs, and .proxy files
  - Removes Uninstall entries and Firewall rules created by the agent
  - Optionally removes additional known install paths

.PARAMETER ServiceNames
  One or more service names to remove (e.g., 'AcmeTelemetryCore','Mesh Agent'). If omitted, the script attempts discovery.

.PARAMETER InstallPaths
  One or more install paths to purge (e.g., 'C:\\ProgramData\\Acme\\TelemetryCore'). If omitted, the script uses known defaults.

.PARAMETER Aggressive
  Also search and remove common MeshAgent default directories if present.

.PARAMETER WhatIf
  Simulate actions without changing the system.

.EXAMPLE
  .\\cleanup_old_agents.ps1 -ServiceNames 'AcmeTelemetryCore' -InstallPaths 'C:\\ProgramData\\Acme\\TelemetryCore' -Aggressive -Verbose -WhatIf

.EXAMPLE
  .\\cleanup_old_agents.ps1 -Aggressive

.NOTES
  Run as Administrator. Designed to be conservative by default; use -Aggressive to sweep common defaults.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [string[]]$ServiceNames,
  [string[]]$InstallPaths,
  [switch]$Aggressive
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) { throw 'Please run this script in an elevated PowerShell (Run as Administrator).' }

Write-Verbose 'Discovering candidate services and paths...'

# Known default paths and names
$knownServiceNames = @(
  'Mesh Agent',
  'meshagent',
  'AcmeTelemetryCore'
)

$defaultPaths = @(
  'C:\\Program Files\\Mesh Agent',
  'C:\\Program Files (x86)\\Mesh Agent',
  'C:\\ProgramData\\Mesh Agent',
  'C:\\ProgramData\\Mesh',
  'C:\\ProgramData\\Acme\\TelemetryCore'
)

if ($InstallPaths) { $defaultPaths = $defaultPaths + $InstallPaths }

if (-not $ServiceNames -or $ServiceNames.Count -eq 0) {
  # Try to auto-detect: services with mesh-like names or image paths
  $svc = Get-CimInstance Win32_Service | Where-Object {
    $_.Name -in $knownServiceNames -or
    $_.DisplayName -match '(?i)mesh|telemetrycore' -or
    $_.PathName -match '(?i)mesh(service|agent).*\\(exe|proxy)'
  }
  $ServiceNames = ($svc | Select-Object -ExpandProperty Name -Unique)
}

Write-Host "[info] Target services: $($ServiceNames -join ', ' )" -ForegroundColor Cyan

# 1) Stop processes first
$procNames = @('MeshService64','MeshService','meshagent')
foreach ($p in $procNames) {
  $procs = Get-Process -Name $p -ErrorAction SilentlyContinue
  foreach ($pr in $procs) {
    if ($PSCmdlet.ShouldProcess("Process:$($pr.Id)", 'Stop-Process')) {
      try { Stop-Process -Id $pr.Id -Force -ErrorAction Stop; Write-Host "[kill] $p pid=$($pr.Id)" -ForegroundColor Yellow } catch { Write-Verbose $_ }
    }
  }
}

# 2) Stop & delete services
foreach ($name in ($ServiceNames | Sort-Object -Unique)) {
  if (-not $name) { continue }
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($null -ne $svc) {
    if ($svc.Status -ne 'Stopped') {
      if ($PSCmdlet.ShouldProcess("Service:$name", 'Stop-Service')) {
        try { Stop-Service -Name $name -Force -ErrorAction Stop; Write-Host "[stop] $name" -ForegroundColor Yellow } catch { Write-Verbose $_ }
      }
    }
    if ($PSCmdlet.ShouldProcess("Service:$name", 'sc.exe delete')) {
      & sc.exe delete "$name" | Out-Null
      Write-Host "[delete] service $name" -ForegroundColor Yellow
    }
  }

  # Remove Uninstall entries (both views)
  $uninstKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$name",
    "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$name"
  )
  foreach ($k in $uninstKeys) {
    if (Test-Path $k) {
      if ($PSCmdlet.ShouldProcess($k, 'Remove-Item')) {
        try { Remove-Item -Path $k -Recurse -Force -ErrorAction Stop; Write-Host "[reg] removed $k" -ForegroundColor Yellow } catch { Write-Verbose $_ }
      }
    }
  }

  # Remove firewall rule commonly created by agent
  try {
    $ruleName = "$name WebRTC Traffic"
    $rules = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    foreach ($r in $rules) {
      if ($PSCmdlet.ShouldProcess($ruleName, 'Remove-NetFirewallRule')) {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        Write-Host "[fw] removed rule '$ruleName'" -ForegroundColor Yellow
      }
    }
  } catch { Write-Verbose $_ }
}

# 3) Remove install folders and residual files
$paths = @()
$paths += $defaultPaths
if ($Aggressive) {
  # Add extra common temp/extraction locations
  $paths += @(
    "$env:TEMP\\meshagent-new",
    "$env:TEMP\\MeshAgent*",
    "$env:ProgramData\\Intel\\Mesh*"
  )
}

$paths = $paths | Sort-Object -Unique | Where-Object { $_ -and (Test-Path $_) }

foreach ($d in $paths) {
  if ($PSCmdlet.ShouldProcess($d, 'Remove-Item -Recurse -Force')) {
    try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction Stop; Write-Host "[rm] $d" -ForegroundColor Yellow } catch { Write-Verbose $_ }
  }
}

# 4) Remove stray files in ProgramData if known
$candidateFiles = @(
  'C:\\ProgramData\\*.msh',
  'C:\\ProgramData\\*\\meshagent.msh',
  'C:\\ProgramData\\*\\*mesh*.log',
  'C:\\ProgramData\\*\\*mesh*.proxy'
)
foreach ($pattern in $candidateFiles) {
  Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
    if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove-Item')) {
      try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop; Write-Host "[rm] file $($_.FullName)" -ForegroundColor Yellow } catch { Write-Verbose $_ }
    }
  }
}

Write-Host "[done] Cleanup completed." -ForegroundColor Green

