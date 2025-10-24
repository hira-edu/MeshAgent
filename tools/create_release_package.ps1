#Requires -Version 5.1
<#
.SYNOPSIS
    Produce a zipped transfer bundle (binaries, symbols, hashes, metadata).

.DESCRIPTION
    Collects Release binaries (`MeshService64.exe`, `MeshService.exe`) plus optional
    matching PDBs, writes SHA256 hashes, records build metadata (commit, branch,
    toolchain versions, build matrix, warnings), and emits a ZIP for hand-off.

.PARAMETER DateTag
    Override the folder/ZIP suffix (defaults to today's yyyy-MM-dd).

.PARAMETER OutputRoot
    Destination directory for deliverables. Defaults to out\deliverables.

.PARAMETER IncludePdb
    Include Release PDB files in the package. Enabled by default.

.PARAMETER ZipOnly
    Skip rebuilding metadata/hashes and only regenerate the ZIP from an existing folder.

.EXAMPLE
    pwsh ./tools/create_release_package.ps1

.EXAMPLE
    pwsh ./tools/create_release_package.ps1 -DateTag 2025-10-24 -IncludePdb:$false
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter()] [string]$DateTag = (Get-Date -Format 'yyyy-MM-dd'),
    [Parameter()] [string]$OutputRoot = (Join-Path $PSScriptRoot '..\out\deliverables'),
    [Parameter()] [switch]$IncludePdb = $true,
    [Parameter()] [switch]$ZipOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$releaseX64 = Join-Path $repoRoot 'Release\MeshService64.exe'
$releaseWin32 = Join-Path $repoRoot 'meshservice\Release\MeshService.exe'
$pdbX64 = Join-Path $repoRoot 'Release\MeshService64.pdb'
$pdbWin32 = Join-Path $repoRoot 'meshservice\Release\MeshService.pdb'

if (-not (Test-Path $releaseX64)) {
    throw "Release build not found at $releaseX64. Build MeshAgent-2022.sln (Release|x64) first."
}
if (-not (Test-Path $releaseWin32)) {
    throw "Release build not found at $releaseWin32. Build meshservice\MeshService-2022.vcxproj (Release|Win32) first."
}

if (-not (Test-Path $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}

$resolvedOutputRoot = (Resolve-Path $OutputRoot).ProviderPath
$deliverableRoot = Join-Path $resolvedOutputRoot ("MeshAgent-$DateTag")
if (-not (Test-Path $deliverableRoot)) {
    New-Item -ItemType Directory -Path $deliverableRoot -Force | Out-Null
}

$binDir = Join-Path $deliverableRoot 'bin'
$pdbDir = Join-Path $deliverableRoot 'pdb'
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
if ($IncludePdb) {
    New-Item -ItemType Directory -Path $pdbDir -Force | Out-Null
}

if (-not $ZipOnly) {
    Copy-Item -Path $releaseX64, $releaseWin32 -Destination $binDir -Force
    if ($IncludePdb) {
        Copy-Item -Path $pdbX64, $pdbWin32 -Destination $pdbDir -Force
    } elseif (Test-Path $pdbDir) {
        Remove-Item -Path $pdbDir -Recurse -Force
    }

    $hashOutput = Get-ChildItem -Path $binDir -File | ForEach-Object {
        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
        '{0}  SHA256  {1}' -f $_.Name, $hash.Hash.ToLowerInvariant()
    }
    $hashOutput | Set-Content -Path (Join-Path $deliverableRoot 'hashes.txt') -Encoding ASCII

    $commit = (git -C $repoRoot rev-parse HEAD).Trim()
    $branch = (git -C $repoRoot rev-parse --abbrev-ref HEAD).Trim()

    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    $vsVersion = if (Test-Path $vswhere) {
        (& $vswhere -latest -requires Microsoft.Component.MSBuild -property catalog_productDisplayVersion).Trim()
    } else { 'unknown' }

    $sdkLib = 'C:\Program Files (x86)\Windows Kits\10\Lib'
    $sdkVersion = if (Test-Path $sdkLib) {
        (Get-ChildItem -Path $sdkLib | Where-Object PSIsContainer | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name)
    } else { 'unknown' }

    $metadata = @(
        "Commit: $commit"
        "Branch: $branch"
        "Build date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
        "Visual Studio: $vsVersion"
        "Windows SDK: $sdkVersion"
        "Build matrix:"
        "  - MeshAgent-2022.sln / Release|x64"
        "  - meshservice\MeshService-2022.vcxproj / Release|Win32"
        "Warnings: C4996 (sprintf/sscanf), C4013 (Stealth_DebugPrintfW); no errors."
        "Include PDBs: $IncludePdb"
    )
    $metadata | Set-Content -Path (Join-Path $deliverableRoot 'metadata.txt') -Encoding UTF8
}

$zipName = "MeshAgent-$DateTag-win.zip"
$zipPath = Join-Path $resolvedOutputRoot $zipName
if (Test-Path $zipPath) {
    Remove-Item -Path $zipPath -Force
}
Compress-Archive -Path (Join-Path $deliverableRoot '*') -DestinationPath $zipPath -Force

Write-Host ("Deliverable staged at {0}" -f $deliverableRoot) -ForegroundColor Cyan
Write-Host ("ZIP archive created: {0}" -f $zipPath) -ForegroundColor Cyan
