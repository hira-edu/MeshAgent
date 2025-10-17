param(
    [string]$Platform = "x64",
    [string]$Configuration = "Release",
    [switch]$IncludeDLL = $true,
    [switch]$IncludeConsole = $true,
    [switch]$IncludeConfig = $true
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$outRoot = Join-Path $root "dist"
if (!(Test-Path $outRoot)) { New-Item -ItemType Directory -Path $outRoot | Out-Null }

# Branding for folder name
$brandingPath = Join-Path $root "meshcore/generated/meshagent_branding.h"
$brand = "MeshAgent"
if (Test-Path $brandingPath) {
    $b = Get-Content -Raw $brandingPath
    if ($b -match 'define\s+MESH_AGENT_SERVICE_FILE\s+TEXT\("([^)]+)"\)') { $brand = $Matches[1] }
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$bundleName = "{0}_{1}_{2}" -f $brand,$Platform,$Configuration
$bundleDir = Join-Path $outRoot $bundleName
if (Test-Path $bundleDir) { Remove-Item -Recurse -Force $bundleDir }
New-Item -ItemType Directory -Path $bundleDir | Out-Null

# Copy EXE
$exePath = Join-Path $root "$Configuration/MeshService64.exe"
Copy-Item -LiteralPath $exePath -Destination (Join-Path $bundleDir "MeshService64.exe")

if ($IncludeDLL) {
    $dllPath = Join-Path $root "Release_DLL/MeshServiceHost64.dll"
    if (Test-Path $dllPath) {
        Copy-Item -LiteralPath $dllPath -Destination (Join-Path $bundleDir "MeshServiceHost64.dll")
    }
}

if ($IncludeConsole) {
    $consolePath = Join-Path $root "$Configuration/MeshConsole64.exe"
    if (Test-Path $consolePath) {
        Copy-Item -LiteralPath $consolePath -Destination (Join-Path $bundleDir "MeshConsole64.exe")
    }
}

if ($IncludeConfig) {
    $cfg = Join-Path $root "branding_config.template.json"
    if (Test-Path $cfg) {
        Copy-Item -LiteralPath $cfg -Destination (Join-Path $bundleDir "branding_config.template.json")
    }
}

# Drop a quick README with usage
$readme = @"
MeshAgent Release Bundle
Service: $brand

EXE install (standard service):
  MeshService64.exe -install
  MeshService64.exe -start

Svchost-hosted registration (DLL):
  MeshService64.exe -svchost-register "`$PWD\MeshServiceHost64.dll"
  MeshService64.exe -svchost-status   (exit code bitmask)
  MeshService64.exe -svchost-unregister

Exit mask for -svchost-status:
  1 = missing service registry key
  2 = not in svchost 'netsvcs'
  4 = service not installed in SCM
  8 = SCM access unavailable
"@
Set-Content -Path (Join-Path $bundleDir "README.txt") -Value $readme -Encoding UTF8

# Helper scripts
$installSvchost = @"
param([string]$Dll = "MeshServiceHost64.dll")
$exe = Join-Path $PSScriptRoot "MeshService64.exe"
& $exe -svchost-register (Resolve-Path (Join-Path $PSScriptRoot $Dll))
exit $LASTEXITCODE
"@
Set-Content -Path (Join-Path $bundleDir "Install-Svchost.ps1") -Value $installSvchost -Encoding UTF8

$uninstallSvchost = @"
$exe = Join-Path $PSScriptRoot "MeshService64.exe"
& $exe -svchost-unregister
exit $LASTEXITCODE
"@
Set-Content -Path (Join-Path $bundleDir "Uninstall-Svchost.ps1") -Value $uninstallSvchost -Encoding UTF8

$statusScript = @"
$exe = Join-Path $PSScriptRoot "MeshService64.exe"
& $exe -svchost-status
exit $LASTEXITCODE
"@
Set-Content -Path (Join-Path $bundleDir "Status.ps1") -Value $statusScript -Encoding UTF8

$installStandard = @"
$exe = Join-Path $PSScriptRoot "MeshService64.exe"
& $exe -install
& $exe -start
"@
Set-Content -Path (Join-Path $bundleDir "Install-Standard.ps1") -Value $installStandard -Encoding UTF8

# Build manifest (JSON) for server-side ingestion
function Get-FileMeta($path) {
    $full = Resolve-Path $path
    $fi = Get-Item $full
    $sha = [System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash([System.IO.File]::OpenRead($full))).Replace('-','').ToLowerInvariant()
    return [ordered]@{
        name = $fi.Name
        path = $fi.Name
        size = [int64]$fi.Length
        sha256 = $sha
    }
}

$serviceDisplay = $null
if ($b -match 'define\s+MESH_AGENT_SERVICE_NAME\s+TEXT\("([^)]+)"\)') { $serviceDisplay = $Matches[1] }

$binList = @()
$binList += Get-FileMeta (Join-Path $bundleDir 'MeshService64.exe')
if ($IncludeDLL -and (Test-Path (Join-Path $bundleDir 'MeshServiceHost64.dll'))) { $binList += Get-FileMeta (Join-Path $bundleDir 'MeshServiceHost64.dll') }
if ($IncludeConsole -and (Test-Path (Join-Path $bundleDir 'MeshConsole64.exe'))) { $binList += Get-FileMeta (Join-Path $bundleDir 'MeshConsole64.exe') }

$manifest = [ordered]@{
  name = $brand
  platform = "windows-x64"
  timestamp = $stamp
  configuration = $Configuration
  bundle = $bundleName
  service = [ordered]@{
    serviceFile = $brand
    displayName = $serviceDisplay
    description = $serviceDisplay
    objectName = "LocalSystem"
  }
  binaries = $binList
  install = [ordered]@{
    standard = @(
      "MeshService64.exe -install",
      "MeshService64.exe -start"
    )
    svchost = @(
      "MeshService64.exe -svchost-register `"MeshServiceHost64.dll`"",
      "MeshService64.exe -svchost-status",
      "MeshService64.exe -svchost-unregister"
    )
  }
  statusExitMask = [ordered]@{
    missingServiceKey = 1
    notInNetsvcs = 2
    notInScm = 4
    scmAccessUnavailable = 8
  }
  notes = @(
    "Svchost-hosted DLL target enabled; exports Stealth_SvchostServiceMain",
    "Service status (-svchost-status) now returns exit code bitmask",
    "DEF names aligned to remove LNK4070; PDB warnings suppressed"
  )
}

$manifestPath = Join-Path $bundleDir 'release-manifest.json'
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

# Create zip
$zipPath = Join-Path $outRoot ("{0}.zip" -f $bundleName)
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($bundleDir, $zipPath)

Write-Host "Created bundle:" -ForegroundColor Green
Write-Host "  $bundleDir" -ForegroundColor Green
Write-Host "  $zipPath" -ForegroundColor Green
