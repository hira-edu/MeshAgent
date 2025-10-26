#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Administrator-only wrapper around build_all.ps1 with additional validation.

.DESCRIPTION
    Delegates build and packaging to build_all.ps1, then runs regression tests and
    branding drift analysis against the generated artefacts. Produces a concise
    summary highlighting package location, archive path, hashes, and warnings.

.PARAMETER Configuration
    MeshAgent configuration to build/package. Default: StealthLab.

.PARAMETER Clean
    Forwarded to build_all.ps1 to prune previous dist artefacts before running.

.PARAMETER SkipBuild
    Skip invoking build.ps1 (build_all will package existing artefacts only).

.PARAMETER SkipArchive
    Skip creation of the ZIP archive; package directory remains.

.PARAMETER SkipTests
    Skip execution of test.ps1 regression suite against the packaged binaries.

.PARAMETER SkipSignatureValidation
    Pass-through to build_all.ps1 to disable Authenticode enforcement (not
    recommended for release builds).

.PARAMETER SkipSvchostValidation
    Pass-through to build_all.ps1 to skip embedded svchost payload validation.

.PARAMETER StrictBranding
    Treat branding drift warnings as fatal.

.PARAMETER RunHealthCheck
    Forwarded to build_all.ps1 to run tools\health_check.ps1 after packaging. Results land
    under verification\health_report.json for quick review.

.PARAMETER Retention
    Number of dist/ archives to retain when Clean is specified. Default: 3.

.PARAMETER OutputLabel
    Override the generated package folder name.

.PARAMETER AllowNonAdmin
    Permit execution without administrative privileges (intended for CI runners).

.PARAMETER SignerScript
    Optional helper invoked after branding drift analysis. Receives `-PackageDir` and `-Configuration`
    (plus any `SignerScriptArgument` values) so you can trigger signtool/authenticode hooks or sync artefacts
    into MeshCentral automatically.

.PARAMETER SignerScriptArgument
    Additional arguments forwarded to SignerScript (array preserves ordering).

.PARAMETER MeshCentralRepo
    Optional path to a local MeshCentral checkout. When supplied (and no custom SignerScript is given),
    build_complete.ps1 automatically runs tools\Invoke-MeshCentralSigner.ps1 to mirror the payload into
    `<repo>\meshcentral-data\agents`.

.PARAMETER SigningCommand
    External signing command (signtool/HSM wrapper/etc.) forwarded to Invoke-MeshCentralSigner.ps1 when
    MeshCentralRepo is specified without a custom SignerScript.

.PARAMETER SigningArgument
    Additional arguments forwarded to SigningCommand (preserves ordering).

.PARAMETER Quiet
    Suppress informational output (errors still surface).
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter()] [switch]$Clean,
    [Parameter()] [switch]$SkipBuild,
    [Parameter()] [switch]$SkipArchive,
    [Parameter()] [switch]$SkipTests,
    [Parameter()] [switch]$SkipSignatureValidation,
    [Parameter()] [switch]$SkipSvchostValidation,
    [Parameter()] [switch]$StrictBranding,
    [Parameter()] [switch]$RunHealthCheck,
    [Parameter()]
    [ValidateSet(
        'Release',
        'Release_NoOpenSSL',
        'Debug',
        'Debug_NoOpenSSL',
        'StealthLab',
        'StealthLab_DLL'
    )]
    [string]$Configuration = 'StealthLab',
    [Parameter()] [ValidateRange(0, 32)] [int]$Retention = 3,
    [Parameter()] [string]$OutputLabel,
    [Parameter()] [switch]$AllowNonAdmin,
    [Parameter()] [string]$SignerScript,
    [Parameter()] [string[]]$SignerScriptArgument,
    [Parameter()] [string]$MeshCentralRepo,
    [Parameter()] [string]$SigningCommand,
    [Parameter()] [string[]]$SigningArgument,
    [Parameter()] [switch]$Quiet,
    [Parameter()] [string]$SigningCertificatePath,
    [Parameter()] [SecureString]$SigningCertificatePassword,
    [Parameter()] [string]$SigningCertificateThumbprint,
    [Parameter()] [string]$SigningTimestampServer = 'http://timestamp.digicert.com',
    [Parameter()] [switch]$SkipSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:IsCIContext = [bool]$env:GITHUB_ACTIONS -or [bool]$env:CI
$script:NonAdminOverride = ($AllowNonAdmin -or $script:IsCIContext)
$script:IsQuiet = [bool]$Quiet
$script:RepoRoot = $PSScriptRoot
$script:DistRoot = Join-Path $script:RepoRoot 'dist'
$script:BuildAllScript = Join-Path $script:RepoRoot 'build_all.ps1'
$script:Timestamp = Get-Date
$script:GitCommit = $null
$script:PackageDir = $null
$script:ArchivePath = $null
$script:SignerScriptPath = $null
$script:SignerScriptArgs = @()
$script:SignerScriptSplat = @{}
$script:SignerScriptIsCustom = $false
$script:VerificationDir = $null
$script:BrandingWarnings = 0
$script:DllHash = $null
$script:PackageManifestPath = $null
$script:HealthReportPath = $null
$script:HealthSummary = $null
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:SigningMode = 'None'
$script:SigningCertificatePathResolved = $null
$script:SigningCertificatePasswordSecure = $null
$script:SigningCertificateThumbprintNormalized = $null
$script:SigningTimestampServer = $SigningTimestampServer
$script:AllowedThumbprints = @()

$brandingHelperScript = Join-Path $script:RepoRoot 'tools\BrandingConfig.ps1'
if (-not (Test-Path -LiteralPath $brandingHelperScript)) {
    throw "Branding helper missing at $brandingHelperScript"
}
. $brandingHelperScript
$brandingConfigInfo = Get-BrandingConfig -RepoRoot $script:RepoRoot -Quiet
$script:BrandingConfigPath = $brandingConfigInfo.Path
if (-not $script:IsQuiet) {
    Write-Host ("[INFO] Branding config : {0}" -f $script:BrandingConfigPath) -ForegroundColor Gray
}

function Write-Section {
    param([string]$Title)
    if (-not $script:IsQuiet) {
        Write-Host ""
        Write-Host ("==================================================") -ForegroundColor Cyan
        Write-Host ("{0}" -f $Title) -ForegroundColor Cyan
        Write-Host ("==================================================") -ForegroundColor Cyan
    }
}

function Write-Info { param([string]$Message) if (-not $script:IsQuiet) { Write-Host ("[INFO] {0}" -f $Message) -ForegroundColor Gray } }
function Write-Warn { param([string]$Message) if (-not $script:IsQuiet) { Write-Host ("[WARN] {0}" -f $Message) -ForegroundColor Yellow } }
function Write-Ok   { param([string]$Message) if (-not $script:IsQuiet) { Write-Host ("[ OK ] {0}" -f $Message) -ForegroundColor Green } }
function Write-Err  { param([string]$Message) Write-Host ("[ERR ] {0}" -f $Message) -ForegroundColor Red }

function Invoke-Step {
    param(
        [int]$Index,
        [int]$Total,
        [string]$Label,
        [scriptblock]$Action
    )

    if (-not $script:IsQuiet) {
        Write-Host ""
        Write-Host ("[{0}/{1}] {2}" -f $Index, $Total, $Label) -ForegroundColor Cyan
    }
    try {
        & $Action
        Write-Ok ("{0} complete" -f $Label)
    } catch {
        Write-Err ("{0} failed: {1}" -f $Label, $_.Exception.Message)
        throw
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-ExistingPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    return $resolved.ProviderPath
}

function Test-AdminContext {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Resolve-TestRunner {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwsh) { return $pwsh.Source }
    $ps = Get-Command powershell -ErrorAction SilentlyContinue
    if ($ps) { return $ps.Source }
    throw "Unable to locate pwsh or powershell executable."
}

if (-not (Test-AdminContext)) {
    if ($script:NonAdminOverride) {
        Write-Warn "Administrator privileges not detected; continuing due to CI/AllowNonAdmin override."
    } else {
        throw "Administrator privileges are required. Relaunch PowerShell elevated."
    }
}

if (-not (Test-Path -LiteralPath $script:BuildAllScript)) {
    throw "build_all.ps1 not found at $script:BuildAllScript"
}

Ensure-Directory -Path $script:DistRoot

if ($SignerScript) {
    try {
        $script:SignerScriptPath = Resolve-ExistingPath $SignerScript
    } catch {
        throw "Signer script not found at '$SignerScript'."
    }
    $script:SignerScriptIsCustom = $true
    if ($SignerScriptArgument) {
        $script:SignerScriptArgs += $SignerScriptArgument
    }
} elseif ($MeshCentralRepo -or $SigningCommand -or $SigningArgument) {
    $defaultSigner = Join-Path $script:RepoRoot 'tools\Invoke-MeshCentralSigner.ps1'
    if (-not (Test-Path -LiteralPath $defaultSigner)) {
        throw "Default signer script not found at '$defaultSigner'. Specify -SignerScript to override."
    }
    $script:SignerScriptPath = $defaultSigner
    if ($MeshCentralRepo) {
        $resolvedRepo = Resolve-ExistingPath $MeshCentralRepo
        $script:SignerScriptSplat['MeshCentralRepo'] = $resolvedRepo
    }
    if ($SigningCommand) {
        $script:SignerScriptSplat['SigningCommand'] = $SigningCommand
    }
    if ($SigningArgument) {
        $script:SignerScriptSplat['SigningArgument'] = $SigningArgument
    }
}

$signerAllowlistScript = Join-Path $script:RepoRoot 'tools\SignerAllowlist.ps1'
if ($SkipSigning) {
    Write-Info "Authenticode signing disabled via -SkipSigning."
} elseif ($SigningCertificatePath) {
    try {
        $script:SigningCertificatePathResolved = Resolve-ExistingPath $SigningCertificatePath
    } catch {
        throw "Signing certificate not found at '$SigningCertificatePath'."
    }
    if (-not $SigningCertificatePassword) {
        throw "-SigningCertificatePath requires -SigningCertificatePassword."
    }
    $script:SigningCertificatePasswordSecure = $SigningCertificatePassword
    $script:SigningMode = 'PFX'
} elseif ($SigningCertificateThumbprint) {
    $script:SigningCertificateThumbprintNormalized = $SigningCertificateThumbprint
    $script:SigningMode = 'Store'
}

if ($script:SigningMode -ne 'None') {
    if (-not (Test-Path -LiteralPath $signerAllowlistScript)) {
        throw "Signer allowlist helper missing at $signerAllowlistScript"
    }
    . $signerAllowlistScript
    $script:AllowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $script:RepoRoot

    if ($script:SigningMode -eq 'Store') {
        $script:SigningCertificateThumbprintNormalized = Normalize-Thumbprint -Thumbprint $script:SigningCertificateThumbprintNormalized
        if (-not $script:SigningCertificateThumbprintNormalized) {
            throw "Thumbprint '$SigningCertificateThumbprint' is not a valid SHA1 fingerprint."
        }
    }
}

$stamp = $script:Timestamp.ToString('yyyyMMdd_HHmmss')
$defaultPrefix = if ($Configuration -like 'StealthLab*') { 'MeshAgent_Stealth' } else { "MeshAgent_{0}" -f $Configuration }
$packageLabel = if ([string]::IsNullOrWhiteSpace($OutputLabel)) { "{0}_{1}" -f $defaultPrefix, $stamp } else { $OutputLabel }

$script:PackageDir = Join-Path $script:DistRoot $packageLabel
$script:ArchivePath = Join-Path $script:DistRoot ("{0}.zip" -f $packageLabel)
$script:VerificationDir = Join-Path $script:PackageDir 'verification'

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    try {
        $commit = & $gitCmd.Source -C $script:RepoRoot rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { $script:GitCommit = $commit.Trim() }
    } catch {
        Write-Warn ("Unable to resolve git commit: {0}" -f $_.Exception.Message)
    }
}

Write-Section "MeshAgent Complete Build Pipeline"
Write-Info ("Configuration : {0}" -f $Configuration)
Write-Info ("Package label : {0}" -f $packageLabel)
Write-Info ("Health check  : {0}" -f $(if ($RunHealthCheck) { 'enabled' } else { 'disabled' }))
if ($script:GitCommit) { Write-Info ("Git commit    : {0}" -f $script:GitCommit) }

$steps = New-Object System.Collections.Generic.List[pscustomobject]

$steps.Add([pscustomobject]@{
    Label  = 'Invoking build_all.ps1'
    Action = {
        $args = @{
            Configuration         = $Configuration
            OutputLabel           = $packageLabel
            Retention             = $Retention
        }
        if ($Clean)                 { $args['Clean'] = $true }
        if ($SkipBuild)             { $args['SkipBuild'] = $true }
        if ($SkipArchive)           { $args['SkipArchive'] = $true }
        if ($SkipSignatureValidation) { $args['SkipSignatureValidation'] = $true }
        if ($SkipSvchostValidation) { $args['SkipSvchostValidation'] = $true }
        if ($SkipTests)             { $args['SkipTests'] = $true }
        if ($RunHealthCheck)        { $args['RunHealthCheck'] = $true }
        if ($Quiet)                 { $args['Quiet'] = $true }
        if ($script:NonAdminOverride) { $args['AllowNonAdmin'] = $true }

        & $script:BuildAllScript @args
        if ($LASTEXITCODE -ne 0) {
            throw ("build_all.ps1 exited with code {0}" -f $LASTEXITCODE)
        }

        if (-not (Test-Path -LiteralPath $script:PackageDir)) {
            throw "Expected package directory not found at $script:PackageDir"
        }
        if (-not $SkipArchive -and -not (Test-Path -LiteralPath $script:ArchivePath)) {
            Write-Warn "Archive not found after build_all.ps1; continuing."
        }

        $checksums = Join-Path $script:PackageDir 'checksums.txt'
        if (Test-Path -LiteralPath $checksums) {
            $dllLine = Select-String -Path $checksums -Pattern 'diagsvc.dll'
            if ($dllLine) {
                $parts = $dllLine.ToString().Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
                if ($parts.Length -gt 0) { $script:DllHash = $parts[0] }
            }
        }

        $manifestCandidate = Join-Path $script:PackageDir 'manifest.json'
        if (Test-Path -LiteralPath $manifestCandidate) {
            $script:PackageManifestPath = $manifestCandidate
        }

        $healthCandidate = Join-Path $script:PackageDir 'verification\health_report.json'
        if (Test-Path -LiteralPath $healthCandidate) {
            $script:HealthReportPath = $healthCandidate
            try {
                $reportObject = Get-Content -Path $healthCandidate -Raw | ConvertFrom-Json -Depth 10
                if ($reportObject -and $reportObject.summary) {
                    $script:HealthSummary = $reportObject.summary
                }
            } catch {
                Write-Warn ("Unable to parse health report: {0}" -f $_.Exception.Message)
            }
        }
    }
})

if (-not $SkipTests) {
    $steps.Add([pscustomobject]@{
        Label  = 'Running regression tests'
        Action = {
            $testScript = Join-Path $script:RepoRoot 'test.ps1'
            if (-not (Test-Path -LiteralPath $testScript)) {
                Write-Warn "test.ps1 not found; skipping regression suite."
                return
            }

            Ensure-Directory -Path $script:VerificationDir
            $runner = Resolve-TestRunner
            $reportPath = Join-Path $script:VerificationDir 'verify-report.json'
            $logPath = Join-Path $script:VerificationDir 'verify-log.txt'

            $runnerArgs = @(
                '-NoLogo',
                '-NoProfile',
                '-ExecutionPolicy','Bypass',
                '-File', $testScript,
                '-BinaryPath', $script:PackageDir,
                '-ReportPath', $reportPath
            )

            & $runner @runnerArgs 2>&1 | Tee-Object -FilePath $logPath | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Regression tests failed. Consult verification\verify-log.txt for details."
            }
        }
    })
} else {
    Write-Warn "Regression tests skipped by request."
}

if ($script:SigningMode -ne 'None') {
    $steps.Add([pscustomobject]@{
        Label  = 'Authenticode signing'
        Action = {
            $targets = @(
                Join-Path $script:RepoRoot 'meshservice\x64\StealthLab\MeshService-2022.exe'
                Join-Path $script:RepoRoot 'meshservice\StealthLab\MeshService-2022.exe'
                Join-Path $script:RepoRoot 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll'
                Join-Path $script:PackageDir 'MeshService64.exe'
                Join-Path $script:PackageDir 'MeshService.exe'
                Join-Path $script:PackageDir 'diagsvc.dll'
            ) | Where-Object { Test-Path -LiteralPath $_ } | Sort-Object -Unique

            if ($targets.Count -eq 0) {
                Write-Warn "Signing requested but no target binaries were found."
                return
            }

            $signTool = (Get-Command 'signtool.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)?.Source
            if (-not $signTool) {
                $candidates = @(
                    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
                    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
                    "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
                )
                $signTool = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            }
            if (-not $signTool) {
                throw "signtool.exe not found. Install the Windows SDK or add signtool to PATH."
            }

            $certArgs = @()
            $thumbprintInUse = $null
            if ($script:SigningMode -eq 'PFX') {
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:SigningCertificatePasswordSecure)
                $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($script:SigningCertificatePathResolved, $plainPassword)
                    $thumbprintInUse = Normalize-Thumbprint -Thumbprint $cert.Thumbprint
                    Assert-MeshAgentThumbprintAllowed -Thumbprint $thumbprintInUse -AllowedThumbprints $script:AllowedThumbprints
                    $certArgs = @('/f', $script:SigningCertificatePathResolved, '/p', $plainPassword)
                } finally {
                    if ($bstr -ne [IntPtr]::Zero) {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    }
                }
            } elseif ($script:SigningMode -eq 'Store') {
                $thumbprintInUse = $script:SigningCertificateThumbprintNormalized
                Assert-MeshAgentThumbprintAllowed -Thumbprint $thumbprintInUse -AllowedThumbprints $script:AllowedThumbprints
                $certArgs = @('/sha1', $thumbprintInUse)
            }

            Write-Info ("Authenticode signer thumbprint: {0}" -f $thumbprintInUse)
            foreach ($target in $targets) {
                Write-Info ("Signing {0}" -f $target)
                $args = @('sign') + $certArgs + @('/fd','SHA256','/tr',$script:SigningTimestampServer,'/td','SHA256','/v',$target)
                & $signTool $args
                if ($LASTEXITCODE -ne 0) {
                    throw ("signtool failed for {0} (exit code {1})" -f $target, $LASTEXITCODE)
                }
                Assert-MeshAgentSignatureAllowed -Path $target -AllowedThumbprints $script:AllowedThumbprints -RequireSignature
            }
        }
    })
}

$steps.Add([pscustomobject]@{
    Label  = 'Branding drift analysis'
    Action = {
        $validateScript = Join-Path $script:RepoRoot 'tools\validate_branding_config.ps1'
        if (-not (Test-Path -LiteralPath $validateScript)) {
            Write-Warn "Branding validation script missing; skipping drift analysis."
            return
        }

        $candidates = @(
            Join-Path $script:PackageDir 'diagsvc.dll'
            Join-Path $script:PackageDir 'MeshService64.exe'
            Join-Path $script:PackageDir 'MeshService.exe'
        ) | Where-Object { Test-Path -LiteralPath $_ }

        if ($candidates.Count -eq 0) {
            Write-Warn "No packaged binaries available for branding drift analysis."
            return
        }

        Ensure-Directory -Path $script:VerificationDir
        $reportPath = Join-Path $script:VerificationDir 'branding_diff_report.json'

        & $validateScript `
            -ConfigPath $script:BrandingConfigPath `
            -SchemaPath (Join-Path $script:RepoRoot 'schema\meshagent.schema.json') `
            -BinaryPaths ([string]::Join(';', $candidates)) `
            -ReportPath $reportPath -Quiet

        if ($LASTEXITCODE -ne 0) {
            throw "Branding validation failed."
        }

        if (Test-Path -LiteralPath $reportPath) {
            try {
                $report = Get-Content -Path $reportPath -Raw | ConvertFrom-Json -Depth 6
                if ($report -and $report.warningCount) {
                    $script:BrandingWarnings = [int]$report.warningCount
                }
            } catch {
                Write-Warn ("Unable to parse branding diff report: {0}" -f $_.Exception.Message)
            }
        }

        if ($script:BrandingWarnings -gt 0) {
            Write-Warn ("Branding drift warnings detected: {0}" -f $script:BrandingWarnings)
            if ($StrictBranding) {
                throw ("Branding drift detected ({0} warning(s))." -f $script:BrandingWarnings)
            }
        } else {
            Write-Ok "Branding diff checks passed (no warnings)."
        }
    }
})

if ($script:SignerScriptPath) {
    $steps.Add([pscustomobject]@{
        Label  = 'Signer hook'
        Action = {
            if ($script:SignerScriptIsCustom) {
                $args = @(
                    '-PackageDir', $script:PackageDir,
                    '-Configuration', $Configuration
                )
                if ($script:SignerScriptArgs.Count -gt 0) {
                    $args += $script:SignerScriptArgs
                }

                Write-Info ("Signer script: {0} {1}" -f $script:SignerScriptPath, ($args -join ' '))
                & $script:SignerScriptPath @args
            } else {
                $invokeArgs = @{
                    PackageDir    = $script:PackageDir
                    Configuration = $Configuration
                }
                foreach ($entry in $script:SignerScriptSplat.GetEnumerator()) {
                    $invokeArgs[$entry.Key] = $entry.Value
                }
                $summary = ($invokeArgs.GetEnumerator() | ForEach-Object { "-$($_.Key)=$($_.Value)" }) -join ' '
                Write-Info ("Signer script: {0} {1}" -f $script:SignerScriptPath, $summary)
                & $script:SignerScriptPath @invokeArgs
            }
            if ($LASTEXITCODE -ne 0) {
                throw ("Signer script exited with code {0}" -f $LASTEXITCODE)
            }
        }
    })
}

if (-not $SkipArchive) {
    $steps.Add([pscustomobject]@{
        Label  = 'Archive verification'
        Action = {
            if (Test-Path -LiteralPath $script:ArchivePath) {
                $size = (Get-Item -LiteralPath $script:ArchivePath).Length
                Write-Info ("Archive size: {0:N2} MB" -f ($size / 1MB))
            } else {
                Write-Warn "Archive missing after build; ensure build_all.ps1 executed with packaging enabled."
            }
        }
    })
}

$stepIndex = 1
$totalSteps = $steps.Count
foreach ($step in $steps) {
    Invoke-Step -Index $stepIndex -Total $totalSteps -Label $step.Label -Action $step.Action
    $stepIndex++
}

Write-Section "Summary"
Write-Host ("Package directory : {0}" -f $script:PackageDir) -ForegroundColor Cyan
if (-not $SkipArchive) {
    Write-Host ("Archive          : {0}" -f $script:ArchivePath) -ForegroundColor Cyan
}
if ($script:VerificationDir) {
    Write-Host ("Verification dir : {0}" -f $script:VerificationDir) -ForegroundColor Cyan
}
if ($script:PackageManifestPath) {
    Write-Host ("Manifest        : {0}" -f $script:PackageManifestPath) -ForegroundColor Cyan
}
if ($script:HealthReportPath) {
    Write-Host ("Health report   : {0}" -f $script:HealthReportPath) -ForegroundColor Cyan
    if ($script:HealthSummary) {
        Write-Host ("  Summary       : Total={0}, Passed={1}, Warnings={2}, Failed={3}" -f $script:HealthSummary.total, $script:HealthSummary.passed, $script:HealthSummary.warnings, $script:HealthSummary.failed) -ForegroundColor Cyan
    }
} elseif ($RunHealthCheck) {
    Write-Warn "Health check was requested but no report was produced. Review build logs."
}
if ($script:DllHash) {
    Write-Host ("diagsvc.dll SHA256 : {0}" -f $script:DllHash) -ForegroundColor Gray
}
if ($script:BrandingWarnings -gt 0) {
    Write-Warn ("Branding warnings detected: {0}" -f $script:BrandingWarnings)
    if (-not $StrictBranding) {
        Write-Warn "Re-run with -StrictBranding to treat drift as an error."
    }
}

$script:Stopwatch.Stop()
Write-Section "Elapsed Time"
Write-Info ("Total duration : {0:N1}s" -f $script:Stopwatch.Elapsed.TotalSeconds)

Write-Section "Next steps"
Write-Info "1. Review package contents under dist\\"
Write-Info "2. Upload diagsvc.dll (rename to meshagent_win32_x64.exe) to MeshCentral agents-custom"
Write-Info "3. Redeploy MeshService executables if overriding defaults"
Write-Info "4. Archive manifest/checksums alongside release documentation"
if ($script:HealthReportPath) {
    Write-Info "5. Review verification\\health_report.json for environment health status"
}

