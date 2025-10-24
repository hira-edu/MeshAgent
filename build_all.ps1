#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end MeshAgent build and packaging pipeline.

.DESCRIPTION
    Orchestrates the recommended MeshAgent workflow: delegates compilation to
    build.ps1, validates outputs, and produces a timestamped distribution folder
    (with optional ZIP archive) containing svchost-enabled payloads and metadata.

.PARAMETER Configuration
    Build configuration to pass to build.ps1. Defaults to StealthLab.

.PARAMETER Clean
    Remove older package artefacts before building. Also allows build.ps1 to
    perform a full clean (SkipClean is only passed when Clean is not specified).

.PARAMETER SkipBuild
    Skip invoking build.ps1 and package the existing artefacts.

.PARAMETER SkipPackage
    Skip the packaging stage; useful for running only the build.

.PARAMETER SkipArchive
    Produce the package directory but skip creating the ZIP archive.

.PARAMETER SkipSignatureValidation
    Do not validate Authenticode signatures when staging binaries.

.PARAMETER SkipSvchostValidation
    Do not verify that staged binaries contain the SVCHOSTDLL resource.

.PARAMETER SkipTests
    Pass -SkipTests through to build.ps1.

.PARAMETER RunHealthCheck
    Execute tools\health_check.ps1 against the local environment after packaging. Results
    are captured under the package verification directory.

.PARAMETER Retention
    Number of package generations to retain when cleaning dist (default 3).

.PARAMETER OutputLabel
    Custom name for the output folder (defaults to MeshAgent_<config>_<timestamp>).

.PARAMETER Quiet
    Suppress informational output (errors still surface).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Release', 'Release_NoOpenSSL', 'Debug', 'Debug_NoOpenSSL', 'StealthLab', 'StealthLab_DLL')]
    [string]$Configuration = 'StealthLab',

    [Parameter()] [switch]$Clean,
    [Parameter()] [switch]$SkipBuild,
    [Parameter()] [switch]$SkipPackage,
    [Parameter()] [switch]$SkipArchive,
    [Parameter()] [switch]$SkipSignatureValidation,
    [Parameter()] [switch]$SkipSvchostValidation,
    [Parameter()] [switch]$SkipTests,
    [Parameter()] [switch]$RunHealthCheck,
    [Parameter()] [ValidateRange(0, 32)] [int]$Retention = 3,
    [Parameter()] [string]$OutputLabel,
    [Parameter()] [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:IsQuiet = [bool]$Quiet
$script:RepoRoot = $PSScriptRoot
$script:PackageDir = $null
$script:ArchivePath = $null
$script:DllHash = $null
$script:GitCommit = $null
$script:HasSvchostProbe = $false
$script:HealthReportPath = $null
$script:PackageManifestPath = $null

$brandingHelperScript = Join-Path $script:RepoRoot 'tools\BrandingConfig.ps1'
if (-not (Test-Path -LiteralPath $brandingHelperScript)) {
    throw "Branding helper missing at $brandingHelperScript"
}
. $brandingHelperScript
$brandingConfigInfo = Get-BrandingConfig -RepoRoot $script:RepoRoot -Quiet
$script:BrandingConfigPath = $brandingConfigInfo.Path
Write-Info ("Branding config : {0}" -f $script:BrandingConfigPath)
$script:BrandingServiceName = $null
$script:ResourceProbeScript = $null

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

function Invoke-BuildStep {
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
    }
    catch {
        Write-Err ("{0} failed: {1}" -f $Label, $_.Exception.Message)
        throw
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Normalize-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootResolved = (Resolve-Path -LiteralPath $Root).ProviderPath
    $pathResolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    return ($pathResolved.Substring($rootResolved.Length).TrimStart('\') -replace '\\', '/')
}

function Resolve-PowerShellHost {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwsh) { return $pwsh.Source }
    $ps = Get-Command powershell -ErrorAction SilentlyContinue
    if ($ps) { return $ps.Source }
    throw "Unable to locate PowerShell executable for health check invocation."
}

function Get-AgentOutputPath {
    param(
        [Parameter(Mandatory = $true)][string]$Configuration,
        [Parameter(Mandatory = $true)][ValidateSet('x64','Win32')][string]$Platform
    )

    $map = @{
        'Release'            = @{ 'x64' = 'meshservice\Release\MeshService64.exe';           'Win32' = 'meshservice\Release\MeshService.exe' }
        'Release_NoOpenSSL'  = @{ 'x64' = 'meshservice\Release_NoOpenSSL\MeshService64.exe'; 'Win32' = 'meshservice\Release_NoOpenSSL\MeshService.exe' }
        'Debug'              = @{ 'x64' = 'meshservice\Debug\MeshService64.exe';             'Win32' = 'meshservice\Debug\MeshService.exe' }
        'Debug_NoOpenSSL'    = @{ 'x64' = 'meshservice\Debug_NoOpenSSL\MeshService64.exe';   'Win32' = 'meshservice\Debug_NoOpenSSL\MeshService.exe' }
        'StealthLab'         = @{ 'x64' = 'meshservice\x64\StealthLab\MeshService-2022.exe'; 'Win32' = 'meshservice\StealthLab\MeshService-2022.exe' }
        'StealthLab_DLL'     = @{ 'x64' = 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll' }
    }

    if ($map.ContainsKey($Configuration) -and $map[$Configuration].ContainsKey($Platform)) {
        return Join-Path $script:RepoRoot $map[$Configuration][$Platform]
    }

    return $null
}

function Ensure-SvchostResource {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($SkipSvchostValidation) {
        return
    }

    $probe = Get-Command -Name Test-SvchostPayload -ErrorAction SilentlyContinue
    if (-not $probe -and $script:ResourceProbeScript -and (Test-Path -LiteralPath $script:ResourceProbeScript)) {
        . $script:ResourceProbeScript
        $probe = Get-Command -Name Test-SvchostPayload -ErrorAction SilentlyContinue
    }

    if (-not $probe) {
        $script:HasSvchostProbe = $false
        throw "SVCHOSTDLL validation unavailable; ResourceProbe helper failed to load."
    }

    $script:HasSvchostProbe = $true

    if (-not (Test-SvchostPayload -Path $Path)) {
        throw ("{0} is missing the SVCHOSTDLL embedded payload." -f $Description)
    }
}

function Ensure-Signature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($SkipSignatureValidation) {
        return [pscustomobject]@{
            Status     = 'skipped'
            Signed     = $false
            Subject    = $null
            Thumbprint = $null
        }
    }

    try {
        $signature = Get-AuthenticodeSignature -FilePath $Path
    } catch {
        Write-Warn ("Unable to inspect signature for {0}: {1}" -f $Description, $_.Exception.Message)
        return [pscustomobject]@{
            Status     = 'error'
            Signed     = $false
            Subject    = $null
            Thumbprint = $null
        }
    }

    switch ($signature.Status) {
        'Valid' {
            if ($signature.SignerCertificate) {
                Write-Info ("Signature observed for {0} ({1})" -f $Description, $signature.SignerCertificate.Subject)
            } else {
                Write-Info ("Signature observed for {0}" -f $Description)
            }
        }
        'NotSigned' {
            Write-Warn ("{0} is unsigned." -f $Description)
        }
        Default {
            Write-Warn ("Signature status for {0}: {1}" -f $Description, $signature.Status)
        }
    }

    $subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    $thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }

    return [pscustomobject]@{
        Status     = $signature.Status
        Signed     = ($signature.Status -eq 'Valid')
        Subject    = $subject
        Thumbprint = $thumbprint
    }
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$buildScript = Join-Path $script:RepoRoot 'build.ps1'
$script:ResourceProbeScript = Join-Path $script:RepoRoot 'tools\ResourceProbe.ps1'
$embedScript = Join-Path $script:RepoRoot 'tools\embed_provisioning_simple.ps1'
$distRoot = Join-Path $script:RepoRoot 'dist'

$timestamp = Get-Date
$stamp = $timestamp.ToString('yyyyMMdd_HHmmss')
$defaultPrefix = if ($Configuration -like 'StealthLab*') { 'MeshAgent_Stealth' } else { "MeshAgent_{0}" -f $Configuration }
$packageName = if ([string]::IsNullOrWhiteSpace($OutputLabel)) { "{0}_{1}" -f $defaultPrefix, $stamp } else { $OutputLabel }

$script:PackageDir = Join-Path $distRoot $packageName
$script:ArchivePath = Join-Path $distRoot ("{0}.zip" -f $packageName)

$steps = @()
$steps += @{ Label = 'Pre-flight checks'; Action = {
    Write-Section "MeshAgent End-to-End Build"
    Write-Info ("Repository root : {0}" -f $script:RepoRoot)
    Write-Info ("Output package  : {0}" -f $packageName)
    Write-Info ("Health check   : {0}" -f $(if ($RunHealthCheck) { 'enabled' } else { 'disabled' }))

    foreach ($path in @($buildScript, $script:ResourceProbeScript, $embedScript)) {
        if (-not (Test-Path $path)) {
            throw ("Required helper missing: {0}" -f $path)
        }
    }

    Ensure-Directory -Path $distRoot

    if (Test-Path -LiteralPath $script:ResourceProbeScript) {
        . $script:ResourceProbeScript
    }
    $script:HasSvchostProbe = [bool](Get-Command -Name Test-SvchostPayload -ErrorAction SilentlyContinue)

    if ($SkipSignatureValidation) {
        Write-Warn "Authenticode inspection disabled by request."
    } else {
        Write-Info "Authenticode signatures will be reported for awareness only (no enforcement)."
    }

    if (-not $SkipSvchostValidation) {
        if ($script:HasSvchostProbe) {
            Write-Info "SVCHOSTDLL resource validation enabled."
        } else {
            throw "ResourceProbe did not expose Test-SvchostPayload; cannot validate svchost payload."
        }
    } else {
        Write-Warn "SVCHOSTDLL validation disabled by request."
    }

    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if ($gitCmd) {
        try {
            $gitOut = & $gitCmd.Source -C $script:RepoRoot rev-parse HEAD 2>$null
            if ($LASTEXITCODE -eq 0) {
                $script:GitCommit = ($gitOut.Trim())
                Write-Info ("Git commit      : {0}" -f $script:GitCommit)
            } else {
                Write-Warn "Unable to resolve git commit (non-zero exit)."
            }
        } catch {
            Write-Warn ("Unable to resolve git commit: {0}" -f $_.Exception.Message)
        }
    } else {
        Write-Warn "git executable not found; manifest will omit commit metadata."
    }
}}

if ($Clean) {
    $steps += @{ Label = 'Pruning previous packages'; Action = {
        if (Test-Path $script:PackageDir) {
            Remove-Item -Path $script:PackageDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ((-not $SkipArchive) -and (Test-Path $script:ArchivePath)) {
            Remove-Item -Path $script:ArchivePath -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path $distRoot) {
            $dirs = Get-ChildItem -Path $distRoot -Directory -Filter 'MeshAgent_*' | Sort-Object CreationTime -Descending
            if ($dirs.Count -gt $Retention) {
                foreach ($dir in ($dirs | Select-Object -Skip $Retention)) {
                    Write-Info ("Removing old package directory: {0}" -f $dir.Name)
                    Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            $archives = Get-ChildItem -Path $distRoot -File -Filter 'MeshAgent_*.zip' | Sort-Object CreationTime -Descending
            if ($archives.Count -gt $Retention) {
                foreach ($zip in ($archives | Select-Object -Skip $Retention)) {
                    Write-Info ("Removing old archive: {0}" -f $zip.Name)
                    Remove-Item -Path $zip.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }}
}

if (-not $SkipBuild) {
    $steps += @{ Label = ("Building MeshAgent ({0})" -f $Configuration); Action = {
        if (-not (Test-Path $buildScript)) {
            throw "build.ps1 not found."
        }

        $buildParams = @{
            Configuration   = $Configuration
            BuildSvchostDll = $true
        }

        if (-not $Clean) { $buildParams['SkipClean'] = $true }
        if ($SkipTests) { $buildParams['SkipTests'] = $true }

        $paramSummary = ($buildParams.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join ', '
        Write-Info ("Invoking build.ps1 with parameters: {0}" -f $paramSummary)
        & $buildScript @buildParams
        if ($LASTEXITCODE -ne 0) {
            throw ("build.ps1 returned exit code {0}" -f $LASTEXITCODE)
        }
    }}
} else {
    Write-Warn "Skipping build stage; existing artefacts will be packaged."
}

if (-not $SkipPackage) {
    $steps += @{ Label = 'Packaging artefacts'; Action = {
        Ensure-Directory -Path $script:PackageDir

        $manifest = [ordered]@{
            version       = '1.1'
            createdUtc    = (Get-Date).ToUniversalTime().ToString('o')
            configuration = $Configuration
            commit        = $script:GitCommit
            branding      = $null
            healthReport  = $null
            files         = @()
        }
        $digestLines = New-Object System.Collections.Generic.List[string]
        $brandingObject = $null
        $brandingConfigPath = $script:BrandingConfigPath
        if (Test-Path -LiteralPath $brandingConfigPath) {
            try {
                $brandingObject = Get-Content -Path $brandingConfigPath -Raw | ConvertFrom-Json -Depth 10
                if ($brandingObject -and $brandingObject.branding) {
                    $manifest.branding = [ordered]@{
                        serviceName = $brandingObject.branding.serviceName
                        displayName = $brandingObject.branding.displayName
                        versionInfo = $brandingObject.branding.versionInfo
                    }
                    if ($brandingObject.branding.serviceName) {
                        $script:BrandingServiceName = $brandingObject.branding.serviceName
                    }
                }
            } catch {
                Write-Warn ("Unable to parse branding configuration at {0}: {1}" -f $brandingConfigPath, $_.Exception.Message)
            }
        }

        $artefacts = @()

        $dllPath = Get-AgentOutputPath -Configuration 'StealthLab_DLL' -Platform 'x64'
        if (-not $dllPath) {
            throw "Unable to resolve StealthLab_DLL output path."
        }
        $artefacts += @{
            Source = $dllPath
            Destination = 'diagsvc.dll'
            Required = $true
            Kind = 'dll'
            ValidateSvchost = $true
            Description = 'Stealth svchost payload DLL'
        }

        $exeX64 = Get-AgentOutputPath -Configuration $Configuration -Platform 'x64'
        if ($exeX64) {
            $artefacts += @{
                Source = $exeX64
                Destination = 'MeshService64.exe'
                Required = $Configuration -notmatch '_DLL$'
                Kind = 'exe'
                ValidateSvchost = ($Configuration -like 'StealthLab*')
                Description = 'MeshAgent service executable (x64)'
            }
        }

        $exeWin32 = Get-AgentOutputPath -Configuration $Configuration -Platform 'Win32'
        if ($exeWin32) {
            $artefacts += @{
                Source = $exeWin32
                Destination = 'MeshService.exe'
                Required = $false
                Kind = 'exe'
                ValidateSvchost = ($Configuration -like 'StealthLab*')
                Description = 'MeshAgent service executable (Win32)'
            }
        }

        $artefacts += @(
            @{ Source = Join-Path $script:RepoRoot 'WinDiagnosticHost.msh'; Destination = 'WinDiagnosticHost.msh'; Required = $true;  Kind = 'data';   ValidateSvchost = $false; Description = 'Provisioning payload (.msh)' },
            @{ Source = $script:BrandingConfigPath; Destination = 'branding_config.local.json'; Required = $false; Kind = 'data';   ValidateSvchost = $false; Description = 'Branding configuration used for build' },
            @{ Source = Join-Path $script:RepoRoot 'deploy_stealth_agent.ps1'; Destination = 'install.ps1'; Required = $false; Kind = 'script'; ValidateSvchost = $false; Description = 'Installer helper script' },
            @{ Source = Join-Path $script:RepoRoot 'audit_and_debug_svchost.ps1'; Destination = 'tools\audit_and_debug_svchost.ps1'; Required = $false; Kind = 'script'; ValidateSvchost = $false; Description = 'SVCHOST payload audit helper' },
            @{ Source = Join-Path $script:RepoRoot 'IMPLEMENTATION_SUMMARY.md'; Destination = 'docs\IMPLEMENTATION_SUMMARY.md'; Required = $false; Kind = 'doc'; ValidateSvchost = $false; Description = 'Implementation summary' },
            @{ Source = Join-Path $script:RepoRoot 'DEPLOYMENT_GUIDE.md'; Destination = 'docs\DEPLOYMENT_GUIDE.md'; Required = $false; Kind = 'doc'; ValidateSvchost = $false; Description = 'Deployment guidance' }
        )

        foreach ($item in $artefacts) {
            $source = $item.Source
            $destination = Join-Path $script:PackageDir $item.Destination

            if (-not (Test-Path $source)) {
                if ($item.Required) {
                    throw ("Required artefact missing: {0}" -f $source)
                }
                Write-Warn ("Optional artefact missing: {0}" -f $source)
                continue
            }

            $destParent = Split-Path $destination -Parent
            if ($destParent) {
                Ensure-Directory -Path $destParent
            }

            Copy-Item -Path $source -Destination $destination -Force

            $svchostValidated = $false
            if ($item.ValidateSvchost) {
                $svchostValidated = Ensure-SvchostResource -Path $destination -Description $item.Description
            }

            if ($item.Kind -in @('dll','exe')) {
                $signatureInfo = Ensure-Signature -Path $destination -Description $item.Description
            } else {
                $signatureInfo = [pscustomobject]@{
                    Status     = 'n/a'
                    Signed     = $false
                    Subject    = $null
                    Thumbprint = $null
                }
            }

            $hash = (Get-FileHash -Path $destination -Algorithm SHA256).Hash
            $relative = Normalize-RelativePath -Root $script:PackageDir -Path $destination
            $digestLines.Add(("{0} *{1}" -f $hash, $relative))

            $fileInfo = Get-Item $destination
            $manifest.files += [ordered]@{
                path = $relative
                size = $fileInfo.Length
                sha256 = $hash
                description = $item.Description
                kind = $item.Kind
                requiresSvchost = [bool]$item.ValidateSvchost
                svchostValidated = [bool]$svchostValidated
                signatureStatus = $signatureInfo.Status
                signed = [bool]$signatureInfo.Signed
                signerThumbprint = $signatureInfo.Thumbprint
                signerSubject = $signatureInfo.Subject
            }

            if ($item.Kind -eq 'dll' -and $item.Destination -eq 'diagsvc.dll') {
                $script:DllHash = $hash
            }
        }

        if (-not $manifest.files) {
            throw "No files staged; nothing to package."
        }

        $digestPath = Join-Path $script:PackageDir 'checksums.txt'
        $digestLines | Sort-Object | Out-File -FilePath $digestPath -Encoding ASCII

        $manifestPath = Join-Path $script:PackageDir 'manifest.json'
        $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding UTF8
        $script:PackageManifestPath = $manifestPath

        $readmeLines = @()
        $readmeLines += "MeshAgent End-to-End Package"
        $readmeLines += "================================"
        $readmeLines += ""
        $readmeLines += ("Build timestamp : {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
        $readmeLines += ("Configuration   : {0}" -f $Configuration)
        $readmeLines += ("Git commit      : {0}" -f ($script:GitCommit ?? 'n/a'))
        if ($script:DllHash) {
            $readmeLines += ("diagsvc.dll SHA256 : {0}" -f $script:DllHash)
        }
        $readmeLines += ""
        $readmeLines += "Included files"
        $readmeLines += "--------------"
        foreach ($file in $manifest.files) {
            $readmeLines += ("- {0}" -f $file.path)
        }
        $readmeLines += ""
        $readmeLines += "Deployment Notes"
        $readmeLines += "----------------"
        $readmeLines += "1. Upload diagsvc.dll to the MeshCentral agents-custom directory (rename to meshagent_win32_x64.exe)."
        $readmeLines += "2. Optionally replace MeshService64.exe/MeshService.exe under meshcentral-data\agents if overriding executables."
        $readmeLines += "3. Restart the MeshCentral service and download the agent to verify the deployment."
        $readmeLines += "4. Use tools\audit_and_debug_svchost.ps1 to validate svchost payloads on target hosts."

        $readmePath = Join-Path $script:PackageDir 'README.txt'
        $readmeLines | Out-File -FilePath $readmePath -Encoding ASCII

        Write-Info ("Package staged at {0}" -f $script:PackageDir)
    }}
}

if (-not $SkipPackage -and $RunHealthCheck) {
    $steps += @{ Label = 'Running health check'; Action = {
        $healthScript = Join-Path $script:RepoRoot 'tools\health_check.ps1'
        if (-not (Test-Path -LiteralPath $healthScript)) {
            Write-Warn "Health check script not found; skipping."
            return
        }

        try {
            $runner = Resolve-PowerShellHost
        } catch {
            Write-Warn $_.Exception.Message
            return
        }

        $verificationDir = Join-Path $script:PackageDir 'verification'
        Ensure-Directory -Path $verificationDir
        $reportPath = Join-Path $verificationDir 'health_report.json'
        $healthLogPath = Join-Path $verificationDir 'health_check.log'
        $script:HealthReportPath = $null

        $args = @(
            '-NoLogo',
            '-NoProfile',
            '-ExecutionPolicy','Bypass',
            '-File', $healthScript,
            '-ReportPath', $reportPath,
            '-Quiet'
        )
        if ($script:BrandingServiceName) {
            $args += @('-ServiceName', $script:BrandingServiceName)
        }

        & $runner @args 2>&1 | Tee-Object -FilePath $healthLogPath | Out-Null
        $exitCode = $LASTEXITCODE
        switch ($exitCode) {
            0 { Write-Ok "Health check completed successfully." }
            2 { Write-Warn "Health check completed with warnings. Review verification logs for details." }
            default {
                Write-Warn ("Health check reported issues (exit code {0}). Inspect verification logs." -f $exitCode)
            }
        }

        if (Test-Path -LiteralPath $reportPath) {
            $script:HealthReportPath = $reportPath
            $relativeReport = Normalize-RelativePath -Root $script:PackageDir -Path $reportPath
            $healthSummary = $null
            try {
                $reportObject = Get-Content -Path $reportPath -Raw | ConvertFrom-Json -Depth 10
                if ($reportObject -and $reportObject.summary) {
                    $healthSummary = $reportObject.summary
                    Write-Info ("Health summary : Total={0}, Passed={1}, Warnings={2}, Failed={3}" -f $healthSummary.total, $healthSummary.passed, $healthSummary.warnings, $healthSummary.failed)
                }
            } catch {
                Write-Warn ("Unable to parse health report: {0}" -f $_.Exception.Message)
            }

            $readmePath = Join-Path $script:PackageDir 'README.txt'
            if (Test-Path -LiteralPath $readmePath) {
                try {
                    $readmeRaw = Get-Content -Path $readmePath -Raw
                    if ($readmeRaw -notmatch 'health_report\.json') {
                        $healthNote = @(
                            '',
                            'Health Check',
                            '-------------',
                            'See verification\health_report.json for environment validation results.'
                        ) -join [Environment]::NewLine
                        Add-Content -Path $readmePath -Value $healthNote -Encoding ASCII
                    }
                } catch {
                    Write-Warn ("Unable to append health check note to README: {0}" -f $_.Exception.Message)
                }
            }

            if ($script:PackageManifestPath -and (Test-Path -LiteralPath $script:PackageManifestPath)) {
                try {
                    $manifestObject = Get-Content -Path $script:PackageManifestPath -Raw | ConvertFrom-Json -Depth 10
                    if ($manifestObject) {
                        $manifestObject.healthReport = [ordered]@{
                            path    = $relativeReport
                            exitCode = $exitCode
                            summary = $healthSummary
                        }
                        $manifestObject | ConvertTo-Json -Depth 10 | Set-Content -Path $script:PackageManifestPath -Encoding UTF8
                    }
                } catch {
                    Write-Warn ("Unable to annotate manifest with health report: {0}" -f $_.Exception.Message)
                }
            }
        }
    }}
}

if ((-not $SkipPackage) -and (-not $SkipArchive)) {
    $steps += @{ Label = 'Creating archive'; Action = {
        if (Test-Path $script:ArchivePath) {
            Remove-Item -Path $script:ArchivePath -Force -ErrorAction SilentlyContinue
        }
        Compress-Archive -Path (Join-Path $script:PackageDir '*') -DestinationPath $script:ArchivePath -Force
        Write-Info ("Archive created at {0}" -f $script:ArchivePath)
    }}
}

if (-not $SkipPackage) {
    Write-Section "Packaging Plan"
    Write-Info ("Package directory : {0}" -f $script:PackageDir)
    if (-not $SkipArchive) {
        Write-Info ("Archive path      : {0}" -f $script:ArchivePath)
    } else {
        Write-Info "Archive creation skipped."
    }
}

$stepIndex = 1
$totalSteps = $steps.Count
foreach ($step in $steps) {
    Invoke-BuildStep -Index $stepIndex -Total $totalSteps -Label $step.Label -Action $step.Action
    $stepIndex++
}

$stopwatch.Stop()

Write-Section "Build Summary"
Write-Info ("Elapsed time : {0:n1}s" -f $stopwatch.Elapsed.TotalSeconds)
Write-Info ("Configuration: {0}" -f $Configuration)
if ($script:GitCommit) {
    Write-Info ("Git commit   : {0}" -f $script:GitCommit)
}

if (-not $SkipPackage) {
    Write-Ok ("Package ready : {0}" -f $script:PackageDir)
    if (-not $SkipArchive) {
        Write-Ok ("Archive ready : {0}" -f $script:ArchivePath)
    }
    if ($script:PackageManifestPath) {
        Write-Info ("Manifest      : {0}" -f $script:PackageManifestPath)
    }
    if ($script:HealthReportPath) {
        Write-Info ("Health report : {0}" -f $script:HealthReportPath)
    } elseif ($RunHealthCheck) {
        Write-Warn "Health check was requested but no report was produced."
    }
    if ($script:DllHash) {
        Write-Info ("diagsvc.dll SHA256 : {0}" -f $script:DllHash)
    }
} else {
    Write-Warn "Packaging stage skipped; no artefacts generated."
}

exit 0

