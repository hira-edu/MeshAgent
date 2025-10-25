#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a MeshCentral-friendly agent payload (meshcentral-data/agents) from a built package.

.DESCRIPTION
    Copies the branded MeshAgent binaries (MeshService*.exe, diagsvc.dll, WinDiagnosticHost.msh) out of a
    `dist/<label>/` folder and stages them into a MeshCentral hand-off directory. Optionally syncs the files
    directly into a sibling MeshCentral repository so the server can re-sign them automatically.

.PARAMETER PackageDir
    Path to the MeshAgent dist folder that contains MeshService*.exe, diagsvc.dll, WinDiagnosticHost.msh.

.PARAMETER OutputRoot
    Directory where the hand-off payload should be staged (a meshcentral-data/agents tree is created beneath it).
    Use this when preparing artefacts for CI or for manual transfer to a remote MeshCentral host.

.PARAMETER MeshCentralRepo
    Optional path to the local MeshCentral repository (the fork that lives at Documents/GitHub/MeshCentral).
    When specified, the script copies the payload directly into `<repo>/meshcentral-data/agents`.

.PARAMETER Force
    Overwrite existing files in the destination payload folder.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDir,

    [Parameter()]
    [string]$OutputRoot,

    [Parameter()]
    [string]$MeshCentralRepo,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ExistingPath {
    param([string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    return $resolved.ProviderPath
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

$packageDir = Resolve-ExistingPath $PackageDir

$payloadRoot = $null
$destinationDesc = $null
if ($MeshCentralRepo) {
    $repoRoot = Resolve-ExistingPath $MeshCentralRepo
    $payloadRoot = Join-Path $repoRoot 'meshcentral-data\agents'
    $destinationDesc = "MeshCentral repo ($payloadRoot)"
} elseif ($OutputRoot) {
    $outputPath = Resolve-ExistingPath $OutputRoot
    $payloadRoot = Join-Path $outputPath 'meshcentral-data\agents'
    $destinationDesc = "handoff folder ($payloadRoot)"
} else {
    throw "You must provide either -OutputRoot or -MeshCentralRepo."
}

Ensure-Directory $payloadRoot

$assetMap = @(
    @{ Name = 'MeshService64.exe'; Mandatory = $true },
    @{ Name = 'MeshService.exe'; Mandatory = $false },
    @{ Name = 'MeshServiceARM64.exe'; Mandatory = $false },
    @{ Name = 'diagsvc.dll'; Mandatory = $true },
    @{ Name = 'WinDiagnosticHost.msh'; Mandatory = $true }
)

$copied = New-Object System.Collections.Generic.List[object]
foreach ($asset in $assetMap) {
    $source = Join-Path $packageDir $asset.Name
    if (-not (Test-Path -LiteralPath $source)) {
        if ($asset.Mandatory) {
            throw "Mandatory asset '$($asset.Name)' not found in package '$packageDir'."
        }
        continue
    }

    $destination = Join-Path $payloadRoot $asset.Name
    if ($PSCmdlet.ShouldProcess($destinationDesc, "Copy $($asset.Name)")) {
        Copy-Item -LiteralPath $source -Destination $destination -Force:$Force
        $copied.Add([pscustomobject]@{
                file      = $asset.Name
                source    = $source
                target    = $destination
                timestamp = (Get-Date).ToUniversalTime().ToString('o')
            }) | Out-Null
    }
}

$payloadManifest = @{
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    packageDir   = $packageDir
    destination  = $payloadRoot
    assets       = $copied
}
$manifestPath = Join-Path (Split-Path $payloadRoot -Parent) 'meshcentral-payload.json'
$payloadManifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host "[OK] MeshCentral payload staged at $payloadRoot" -ForegroundColor Green
Write-Host "     Manifest: $manifestPath"
