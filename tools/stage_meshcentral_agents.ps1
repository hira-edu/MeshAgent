[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$MeshCentralDataPath = "..\meshcentral-data",
    [switch]$SkipBuild,
    [switch]$IncludeWin32
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot

function Resolve-PathRelative {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

$meshDataPath = Resolve-PathRelative -Path $MeshCentralDataPath
if (-not (Test-Path -LiteralPath $meshDataPath)) {
    throw "MeshCentral data directory not found at '$meshDataPath'."
}

$agentsDir = Join-Path $meshDataPath "agents"
if (-not (Test-Path -LiteralPath $agentsDir)) {
    throw "MeshCentral agents directory not found at '$agentsDir'."
}
$signedAgentsDir = Join-Path $meshDataPath "signedagents"

if (-not $SkipBuild) {
    Write-Host "[1/4] Ensuring StealthLab build is current..." -ForegroundColor Cyan
    & (Join-Path $repoRoot "build.ps1") -StealthLab -SkipTests
    if ($LASTEXITCODE -ne 0) {
        throw "build.ps1 exited with code $LASTEXITCODE"
    }
} else {
    Write-Host "[1/4] Skipping build per parameter." -ForegroundColor Yellow
}

$exeX64 = Join-Path $repoRoot "meshservice\x64\StealthLab\MeshService-2022.exe"
$exeWin32 = Join-Path $repoRoot "meshservice\StealthLab\MeshService-2022.exe"
$mshPath = Join-Path $repoRoot "WinDiagnosticHost.msh"

foreach ($path in @($exeX64, $mshPath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required artifact missing: $path"
    }
}

if ($IncludeWin32 -and -not (Test-Path -LiteralPath $exeWin32)) {
    throw "IncludeWin32 specified, but Win32 StealthLab executable not found at $exeWin32"
}

Write-Host "[2/4] Preparing artifacts for staging..." -ForegroundColor Cyan

$artifacts = @(
    @{ Source = $exeX64; Destination = "MeshService64.exe"; Description = "StealthLab x64 service" },
    @{ Source = $mshPath; Destination = "MeshService-2022.msh"; Description = "Provisioning (.msh)" }
)

if ($IncludeWin32) {
    $artifacts += @{ Source = $exeWin32; Destination = "MeshService.exe"; Description = "StealthLab Win32 service" }
}

function Get-HashMaybe {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }
    return $null
}

$summary = @()

Write-Host "[3/4] Copying artifacts into $agentsDir" -ForegroundColor Cyan
foreach ($artifact in $artifacts) {
    $destination = Join-Path $agentsDir $artifact.Destination
    $sourceHash = (Get-FileHash -LiteralPath $artifact.Source -Algorithm SHA256).Hash
    $existingHash = Get-HashMaybe -Path $destination

    if ($existingHash -eq $sourceHash) {
        Write-Host ("  - {0} already up-to-date (SHA256 {1})" -f $artifact.Destination, $sourceHash.Substring(0, 12)) -ForegroundColor DarkGray
        $summary += [PSCustomObject]@{
            Name = $artifact.Destination
            Status = "Unchanged"
            Hash = $sourceHash
        }
        continue
    }

    if ($PSCmdlet.ShouldProcess($destination, "Copy $($artifact.Source)")) {
        Copy-Item -LiteralPath $artifact.Source -Destination $destination -Force
        Write-Host ("  - Updated {0} (SHA256 {1})" -f $artifact.Destination, $sourceHash.Substring(0, 12)) -ForegroundColor Green
        $summary += [PSCustomObject]@{
            Name = $artifact.Destination
            Status = "Updated"
            Hash = $sourceHash
        }
    }
}

Write-Host "[4/4] Staging complete." -ForegroundColor Green
$summary | Format-Table Name, Status, Hash | Out-String | Write-Host

if (Test-Path -LiteralPath $signedAgentsDir) {
    Write-Host ""
    Write-Host ("[INFO] Mirroring signed artefacts into {0}" -f $signedAgentsDir) -ForegroundColor Cyan
    foreach ($artifact in $artifacts | Where-Object { $_.Destination -like '*.exe' }) {
        $destination = Join-Path $signedAgentsDir $artifact.Destination
        if ($PSCmdlet.ShouldProcess($destination, "Sync signed agent")) {
            Copy-Item -LiteralPath $artifact.Source -Destination $destination -Force
        }
    }
}

Write-Host ""
Write-Host "Reminder: restart MeshCentral (or wait for auto reload) so downloads pick up the new binaries." -ForegroundColor Yellow
