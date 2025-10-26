#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    MeshAgent build orchestrator for Windows targets.

.DESCRIPTION
    Generates branding/provisioning artefacts, (optionally) produces network
    profiles, compiles the requested configuration/platforms via MSBuild, stages
    svchost payloads, and applies integrity validation with detailed reporting.

.PARAMETER Configuration
    MeshAgent configuration to build. Defaults to StealthLab.

.PARAMETER Platforms
    Platform selection: Both (default), x64, or Win32. DLL configurations force x64.

.PARAMETER SkipClean
    Skip removal of previous build artefacts.

.PARAMETER SkipTests
    Skip post-build validation (hashes & sanity checks still recorded).

.PARAMETER SkipBrandingValidation
    Do not run the branding schema validator before embedding provisioning data.

.PARAMETER SkipNetworkProfile
    Skip generation of the optional network profile header/json.

.PARAMETER SkipSignatureValidation
    Do not perform Authenticode validation on produced binaries.

.PARAMETER SkipSvchostValidation
    Skip svchost payload presence checks.

.PARAMETER BuildSvchostDll
    After the primary build completes, rebuild StealthLab_DLL and restage the payload (enabled by default).

.PARAMETER StealthLab
    Convenience switch that maps Release -> StealthLab and exports STEALTH_LAB=1 (profile enabled by default).

.PARAMETER Quiet
    Suppress informational output (errors still surface).

.PARAMETER SignStealth
    After a successful StealthLab build, Authenticode sign MeshService-2022.exe/dll using the provided certificate.

.PARAMETER StealthSignerPfx
    Path to a PFX that should be used when -SignStealth is specified.

.PARAMETER StealthSignerPassword
    SecureString password for the PFX when -StealthSignerPfx is used.

.PARAMETER StealthSignerThumbprint
    SHA1 thumbprint of a certificate in the CurrentUser\My store to use for signing.

.PARAMETER StealthSignerTimestampServer
    Timestamp server URL used when signing (default: http://timestamp.digicert.com).
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter()]
    [ValidateSet(
        'Release',
        'Release_NoOpenSSL',
        'Debug',
        'Debug_NoOpenSSL',
        'StealthLab',
        'StealthLab_DLL',
        'Release_DLL',
        'Debug_DLL'
    )]
    [string]$Configuration = 'StealthLab',

    [Parameter()]
    [ValidateSet('Both', 'x64', 'Win32')]
    [string]$Platforms = 'Both',

    [Parameter()] [switch]$SkipClean,
    [Parameter()] [switch]$SkipTests,
    [Parameter()] [switch]$SkipBrandingValidation,
    [Parameter()] [switch]$SkipNetworkProfile,
    [Parameter()] [switch]$SkipSignatureValidation,
    [Parameter()] [switch]$SkipSvchostValidation,
    [Parameter()] [switch]$BuildSvchostDll,
    [Parameter()] [switch]$StealthLab,
    [Parameter()] [switch]$Quiet,
    [Parameter()] [switch]$SignStealth,
    [Parameter()] [string]$StealthSignerPfx,
    [Parameter()] [SecureString]$StealthSignerPassword,
    [Parameter()] [string]$StealthSignerThumbprint,
    [Parameter()] [string]$StealthSignerTimestampServer = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function ConvertTo-PlainText {
    param([SecureString]$Secret)
    if ($null -eq $Secret) { return $null }
    return [System.Net.NetworkCredential]::new('', $Secret).Password
}

function Find-SignToolPath {
    $sdkBase = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Windows Kits\10\bin'
    $preferredVersions = @(
        '10.0.26100.0',
        '10.0.25398.0',
        '10.0.22621.0',
        '10.0.22000.0'
    )

    $candidates = @()
    foreach ($ver in $preferredVersions) {
        $candidate = Join-Path -Path $sdkBase -ChildPath (Join-Path -Path $ver -ChildPath 'x64\signtool.exe')
        $candidates += $candidate
    }
    $candidates += Join-Path -Path $sdkBase -ChildPath 'x64\signtool.exe'

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    if (Test-Path -LiteralPath $sdkBase) {
        $match = Get-ChildItem -Path $sdkBase -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object {
                $candidate = Join-Path -Path $_.FullName -ChildPath 'x64\signtool.exe'
                if (Test-Path -LiteralPath $candidate) { return $candidate }
            } |
            Where-Object { $_ } |
            Select-Object -First 1

        if ($match) { return $match }
    }

    return $null
}

function Invoke-StealthSigning {
    param(
        [string]$ConfigurationName,
        [string]$CertificatePath,
        [SecureString]$CertificatePassword,
        [string]$Thumbprint,
        [string]$TimestampServer,
        [string[]]$TargetPaths
    )

    $defaultTargets = @(
        (Join-Path -Path $script:RepoRoot -ChildPath 'meshservice\x64\StealthLab\MeshService-2022.exe')
        (Join-Path -Path $script:RepoRoot -ChildPath 'meshservice\StealthLab\MeshService-2022.exe')
    )
    if ($TargetPaths -and $TargetPaths.Count -gt 0)
    {
        $targets = $TargetPaths | ForEach-Object {
            if (Test-Path -LiteralPath $_) { (Resolve-Path -LiteralPath $_).ProviderPath }
        }
    }
    else
    {
        $targets = $defaultTargets | Where-Object { Test-Path -LiteralPath $_ }
    }

    $targets = @($targets | Where-Object { $_ } | ForEach-Object { (Resolve-Path -LiteralPath $_).ProviderPath })

    if ($targets.Count -eq 0)
    {
        Write-Warn "Stealth signing requested but no StealthLab artefacts were found."
        return
    }

    $signTool = Find-SignToolPath
    if (-not $signTool)
    {
        throw "signtool.exe not found. Install the Windows 10/11 SDK to enable Authenticode signing."
    }

    $signArgs = @()
    if ($CertificatePath)
    {
        $resolved = Resolve-Path -LiteralPath $CertificatePath -ErrorAction Stop
        $signArgs += '/f', $resolved.ProviderPath
        $passwordPlain = ConvertTo-PlainText $CertificatePassword
        if ($passwordPlain) { $signArgs += '/p', $passwordPlain }
    }
    elseif ($Thumbprint)
    {
        $normalized = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized))
        {
            throw "Stealth signer thumbprint is empty."
        }
        $signArgs += '/sha1', $normalized
    }
    else
    {
        throw "Provide either -StealthSignerPfx or -StealthSignerThumbprint when using -SignStealth."
    }

    $timestamp = if ([string]::IsNullOrWhiteSpace($TimestampServer)) { 'http://timestamp.digicert.com' } else { $TimestampServer }
    $signArgs += '/fd','SHA256','/tr',$timestamp,'/td','SHA256','/v'

    foreach ($target in $targets)
    {
        $resolvedTarget = (Resolve-Path -LiteralPath $target).ProviderPath
        Write-Info ("Signing {0}" -f $resolvedTarget)
        & $signTool sign @signArgs $resolvedTarget
        if ($LASTEXITCODE -ne 0)
        {
            throw ("signtool.exe exited with code {0} while signing {1}" -f $LASTEXITCODE, $resolvedTarget)
        }
        $signature = Get-AuthenticodeSignature -FilePath $resolvedTarget
        switch ($signature.Status)
        {
            'Valid' {
                Write-Ok ("{0} signed by {1}" -f (Split-Path $resolvedTarget -Leaf), $signature.SignerCertificate.Subject)
            }
            'UnknownError' {
                if ($signature.SignerCertificate)
                {
                    Write-Warn ("{0} signature present but Windows does not trust the issuer ({1})." -f (Split-Path $resolvedTarget -Leaf), $signature.SignerCertificate.Subject)
                }
                else
                {
                    throw ("Authenticode verification failed for {0} (status {1})." -f $resolvedTarget, $signature.Status)
                }
            }
            Default {
                throw ("Authenticode verification failed for {0} (status {1})." -f $resolvedTarget, $signature.Status)
            }
        }

        $signatureSummary = Ensure-Signature -Path $resolvedTarget -Description (Get-RelativeRepoPath -Path $resolvedTarget)
        foreach ($output in $script:BuildOutputs)
        {
            if ((Resolve-Path -LiteralPath $output.Path).ProviderPath -eq $resolvedTarget)
            {
                $output.SignatureInfo = $signatureSummary
            }
        }
    }

    $targetNames = ($targets | ForEach-Object { Split-Path $_ -Leaf })
    Write-Ok ("{0} signing complete: {1}" -f $ConfigurationName, ($targetNames -join ', '))
}

$script:IsQuiet = [bool]$Quiet
$script:RepoRoot = $PSScriptRoot
$script:ResolvedMSBuildPath = $null
$script:ResolvedPythonPath = $null
$script:Targets = @()
$script:BuildOutputs = New-Object System.Collections.Generic.List[pscustomobject]
$script:GitCommit = $null
$script:MSBuildVersion = $null
$script:PythonVersion = $null
$script:ManifestDirectory = Join-Path $script:RepoRoot 'out\build'
$script:ManifestTimestamp = Get-Date
$script:BrandingHeaderInfo = $null
$script:EmbeddedPayloadRestaged = $false
$script:EmbeddedPayloadHeaderInfo = $null
$script:Bin2hExecutable = $null
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:OriginalStealthLabValue = $env:STEALTH_LAB
$script:StealthLabExported = $false

$brandingHelperScript = Join-Path $script:RepoRoot 'tools\BrandingConfig.ps1'
if (-not (Test-Path -LiteralPath $brandingHelperScript)) {
    throw "Branding helper missing at $brandingHelperScript"
}
. $brandingHelperScript
$brandingConfigInfo = Get-BrandingConfig -RepoRoot $script:RepoRoot -Quiet
$script:BrandingConfigPath = $brandingConfigInfo.Path
Write-Info ("Branding config : {0}" -f $script:BrandingConfigPath)

if ($PSBoundParameters.ContainsKey('BuildSvchostDll')) {
    $BuildSvchostDll = [bool]$BuildSvchostDll
} else {
    $BuildSvchostDll = $true
}

if ($PSBoundParameters.ContainsKey('StealthLab') -and -not $StealthLab) {
    $StealthLab = $true
}

if ($SignStealth -and (-not $StealthSignerPfx) -and (-not $StealthSignerThumbprint)) {
    throw "-SignStealth requires either -StealthSignerPfx or -StealthSignerThumbprint."
}

if ($SignStealth -and ($Configuration -notlike 'StealthLab*')) {
    Write-Warn ("-SignStealth was supplied for configuration '{0}'. This flag is intended for StealthLab outputs." -f $Configuration)
}

function Invoke-Step {
    param(
        [int]$Index,
        [int]$Total,
        [string]$Label,
        [scriptblock]$Action,
        $Argument
    )

    if (-not $script:IsQuiet) {
        Write-Host ""
        Write-Host ("[{0}/{1}] {2}" -f $Index, $Total, $Label) -ForegroundColor Cyan
    }
    try {
        if ($PSBoundParameters.ContainsKey('Argument')) {
            & $Action $Argument
        } else {
            & $Action
        }
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

function Copy-ProvisioningManifest {
    param(
        [Parameter(Mandatory = $true)][string]$TargetBinary
    )

    if (-not (Test-Path -LiteralPath $TargetBinary)) { return }
    if (-not (Test-Path -LiteralPath $script:ProvisioningMsh)) { return }

    $targetItem = Get-Item -LiteralPath $TargetBinary -ErrorAction SilentlyContinue
    if (-not $targetItem) { return }
    if ($targetItem.Extension -ne '.exe') { return }

    $destination = [System.IO.Path]::ChangeExtension($targetItem.FullName, '.msh')
    try {
        Copy-Item -LiteralPath $script:ProvisioningMsh -Destination $destination -Force
        Write-Info ("Provisioning manifest copied to {0}" -f (Get-RelativeRepoPath -Path $destination))
    } catch {
        Write-Warn ("Unable to copy provisioning manifest to {0}: {1}" -f $destination, $_.Exception.Message)
    }
}


function Get-RelativeRepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetFullPath($script:RepoRoot)
        if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $full.Substring($root.Length).TrimStart('\','/')
        }
    } catch {
        return $Path
    }
    return $Path
}

function Get-Bin2hExecutable {
    if ($script:Bin2hExecutable) {
        return $script:Bin2hExecutable
    }

    $projectPath = Join-Path $script:RepoRoot 'tools\bin2h\bin2h.vcxproj'
    if (-not (Test-Path -LiteralPath $projectPath)) {
        throw "bin2h project missing at $projectPath"
    }

    $expectedExe = Join-Path $script:RepoRoot 'tools\bin2h\x64\Release\bin2h.exe'
    $needsBuild = $true
    if (Test-Path -LiteralPath $expectedExe) {
        try {
            $exeInfo = Get-Item -LiteralPath $expectedExe
            $sourceInfo = Get-Item -LiteralPath (Join-Path $script:RepoRoot 'tools\bin2h\bin2h.cpp')
            if ($exeInfo.LastWriteTimeUtc -ge $sourceInfo.LastWriteTimeUtc) {
                $needsBuild = $false
            }
        } catch {
            $needsBuild = $true
        }
    }

    if ($needsBuild) {
        $args = @(
            $projectPath,
            '/restore',
            '/m',
            '/nologo',
            '/verbosity:minimal',
            '/p:Configuration=Release',
            '/p:Platform=x64'
        )
        Invoke-ExternalCommand -FilePath $script:ResolvedMSBuildPath -Arguments $args -Description 'bin2h (Release|x64)' | Out-Null
    }

    if (-not (Test-Path -LiteralPath $expectedExe)) {
        throw "bin2h executable not found at $expectedExe"
    }

    $script:Bin2hExecutable = $expectedExe
    return $script:Bin2hExecutable
}

function Convert-SvchostPayloadToHeader {
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [switch]$Silent
    )

    if (-not (Test-Path -LiteralPath $InputPath)) {
        if (-not $Silent) {
            Write-Warn ("Svchost payload source missing at {0}" -f $InputPath)
        }
        return $false
    }

    try {
        $bin2hExe = Get-Bin2hExecutable
    } catch {
        if (-not $Silent) {
            Write-Warn ("Unable to prepare bin2h: {0}" -f $_.Exception.Message)
        }
        return $false
    }

    $generatedDir = Join-Path $script:RepoRoot 'meshcore\embedded\generated'
    Ensure-Directory -Path $generatedDir
    $outputHeader = Join-Path $generatedDir 'svchost_payload.h'
    $metadataPath = Join-Path $generatedDir 'svchost_payload.json'

    $needsGeneration = $true
    try {
        $inputInfo = Get-Item -LiteralPath $InputPath
        if (Test-Path -LiteralPath $outputHeader) {
            $headerInfo = Get-Item -LiteralPath $outputHeader
            if ($headerInfo.LastWriteTimeUtc -ge $inputInfo.LastWriteTimeUtc -and (Test-Path -LiteralPath $metadataPath)) {
                $needsGeneration = $false
            }
        }
    } catch {
        $needsGeneration = $true
    }

    if ($needsGeneration) {
        foreach ($existingPath in @($outputHeader, $metadataPath)) {
            if ([string]::IsNullOrWhiteSpace($existingPath)) { continue }
            if (-not (Test-Path -LiteralPath $existingPath)) { continue }
            try {
                $fileInfo = Get-Item -LiteralPath $existingPath -ErrorAction Stop
                if ($fileInfo.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                    $fileInfo.IsReadOnly = $false
                }
            } catch {
                if (-not $Silent) {
                    Write-Warn ("Unable to adjust attributes for {0}: {1}" -f $existingPath, $_.Exception.Message)
                }
            }
        }
    }

    if (-not $needsGeneration) {
        $metadataEntry = $null
        if (Test-Path -LiteralPath $metadataPath) {
            $metadataEntry = $metadataPath
        }
        $script:EmbeddedPayloadHeaderInfo = @{
            headerPath   = $outputHeader
            metadataPath = $metadataEntry
        }
        if (-not $Silent) {
            Write-Info ("Embedded payload header already current: {0}" -f (Get-RelativeRepoPath -Path $outputHeader))
        }
        return $true
    }

    $args = @(
        '--input', $InputPath,
        '--output', $outputHeader,
        '--symbol', 'g_SvchostPayload',
        '--metadata', $metadataPath
    )

    Invoke-ExternalCommand -FilePath $bin2hExe -Arguments $args -Description 'bin2h (svchost payload)' | Out-Null

    $metadataEntry = $null
    if (Test-Path -LiteralPath $metadataPath) {
        $metadataEntry = $metadataPath
    }

    $script:EmbeddedPayloadHeaderInfo = @{
        headerPath   = $outputHeader
        metadataPath = $metadataEntry
    }

    if (-not $Silent) {
        Write-Info ("Generated embedded payload header: {0}" -f (Get-RelativeRepoPath -Path $outputHeader))
    }
    return $true
}

function Escape-Argument {
    param([string]$Value)
    if ($Value -notmatch '[\s"`]') { return $Value }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-ExternalCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory = $script:RepoRoot,
        [string]$Description,
        [int]$Retries = 1,
        [int]$RetryDelaySeconds = 3
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Executable not found: $FilePath"
    }

    $attempt = 0
    $lastError = $null

    do {
        $attempt++
        $argumentString = if ($Arguments) { ($Arguments | ForEach-Object { Escape-Argument $_ }) -join ' ' } else { '' }
        if (-not $script:IsQuiet) {
            $desc = if ([string]::IsNullOrWhiteSpace($Description)) { Split-Path $FilePath -Leaf } else { $Description }
            $attemptLabel = if ($Retries -gt 1) { " (attempt $attempt/$Retries)" } else { "" }
            Write-Info ("{0}{3}: {1} {2}" -f $desc, $FilePath, $argumentString, $attemptLabel)
        }

        $process = $null
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $FilePath
            $psi.Arguments = $argumentString
            $psi.WorkingDirectory = $WorkingDirectory
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi

            $null = $process.Start()

            while (-not $process.HasExited) {
                $stdout = $process.StandardOutput.ReadLine()
                while ($stdout -ne $null) {
                    if (-not $script:IsQuiet) { Write-Host $stdout }
                    $stdout = $process.StandardOutput.ReadLine()
                }
                Start-Sleep -Milliseconds 50
            }

            while (-not $process.StandardOutput.EndOfStream) {
                $line = $process.StandardOutput.ReadLine()
                if (-not $script:IsQuiet) { Write-Host $line }
            }
            while (-not $process.StandardError.EndOfStream) {
                $errLine = $process.StandardError.ReadLine()
                if ($errLine) { Write-Err $errLine }
            }

            if ($process.ExitCode -ne 0) {
                throw ("Command '{0}' exited with code {1}" -f (Split-Path $FilePath -Leaf), $process.ExitCode)
            }

            return
        }
        catch {
            $lastError = $_
            if ($attempt -ge $Retries) {
                throw $lastError
            }

            $label = if ($null -ne $Description -and $Description -ne '') { $Description } else { Split-Path $FilePath -Leaf }
            Write-Warn ("{0} failed: {1}. Retrying in {2}s..." -f $label, $lastError.Exception.Message, $RetryDelaySeconds)
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        finally {
            if ($process) {
                $process.Dispose()
            }
        }
    } while ($attempt -lt $Retries)
}

function Resolve-MSBuildPath {
    $candidates = New-Object System.Collections.Generic.List[string]

    if ($env:MSBUILD_PATH) {
        $candidates.Add($env:MSBUILD_PATH)
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        try {
            $vsInstances = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null
            if ($vsInstances) {
                $vsInstances | ForEach-Object { if ($_ -and -not ($candidates -contains $_)) { $candidates.Add($_) } }
            }
        } catch {
            Write-Warn ("vswhere lookup failed: {0}" -f $_.Exception.Message)
        }
    }

    $defaultRoots = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    )
    foreach ($path in $defaultRoots) {
        if (-not ($candidates -contains $path)) {
            $candidates.Add($path)
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }

    throw "Unable to locate MSBuild. Install Visual Studio Build Tools or set MSBUILD_PATH."
}

function Resolve-PythonPath {
    if ($SkipNetworkProfile) { return $null }

    if ($env:PYTHON_PATH -and (Test-Path -LiteralPath $env:PYTHON_PATH)) {
        return (Resolve-Path -LiteralPath $env:PYTHON_PATH).ProviderPath
    }

    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd) {
        return $pythonCmd.Source
    }

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        return $pyLauncher.Source
    }

    Write-Warn "Python interpreter not found; network profile generation will be skipped."
    return $null
}

function Get-ConfigurationMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Configuration
    )

    $map = @{
        'Release' = @{
            platforms = @('x64','Win32')
            outputs   = @{ 'x64' = 'meshservice\Release\MeshService64.exe'; 'Win32' = 'meshservice\Release\MeshService.exe' }
            requiresSvchost = $false
        }
        'Release_NoOpenSSL' = @{
            platforms = @('x64','Win32')
            outputs   = @{ 'x64' = 'meshservice\Release_NoOpenSSL\MeshService64.exe'; 'Win32' = 'meshservice\Release_NoOpenSSL\MeshService.exe' }
            requiresSvchost = $false
        }
        'Debug' = @{
            platforms = @('x64','Win32')
            outputs   = @{ 'x64' = 'meshservice\Debug\MeshService64.exe'; 'Win32' = 'meshservice\Debug\MeshService.exe' }
            requiresSvchost = $false
        }
        'Debug_NoOpenSSL' = @{
            platforms = @('x64','Win32')
            outputs   = @{ 'x64' = 'meshservice\Debug_NoOpenSSL\MeshService64.exe'; 'Win32' = 'meshservice\Debug_NoOpenSSL\MeshService.exe' }
            requiresSvchost = $false
        }
        'StealthLab' = @{
            platforms = @('x64','Win32')
            outputs   = @{ 'x64' = 'meshservice\x64\StealthLab\MeshService-2022.exe'; 'Win32' = 'meshservice\StealthLab\MeshService-2022.exe' }
            requiresSvchost = $true
        }
        'StealthLab_DLL' = @{
            platforms = @('x64')
            outputs   = @{ 'x64' = 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll' }
            requiresSvchost = $true
        }
        'Release_DLL' = @{
            platforms = @('x64')
            outputs   = @{ 'x64' = 'meshservice\x64\Release_DLL\MeshService-2022.dll' }
            requiresSvchost = $false
        }
        'Debug_DLL' = @{
            platforms = @('x64')
            outputs   = @{ 'x64' = 'meshservice\x64\Debug_DLL\MeshService-2022.dll' }
            requiresSvchost = $false
        }
    }

    if (-not $map.ContainsKey($Configuration)) {
        throw "Unsupported configuration '$Configuration'."
    }

    return $map[$Configuration]
}

function Resolve-BuildTargets {
    param(
        [Parameter(Mandatory = $true)][string]$Configuration,
        [Parameter(Mandatory = $true)][string]$PlatformPreference
    )

    $meta = Get-ConfigurationMetadata -Configuration $Configuration
    $platforms = switch ($PlatformPreference) {
        'x64'   { @('x64') }
        'Win32' { @('Win32') }
        default { $meta.platforms }
    }

    $targets = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($platform in $platforms) {
        if (-not $meta.outputs.ContainsKey($platform)) {
            Write-Warn ("Configuration '{0}' does not produce a {1} artefact; skipping." -f $Configuration, $platform)
            continue
        }
        $relative = $meta.outputs[$platform]
        $absolute = Join-Path $script:RepoRoot $relative
        $targets.Add([pscustomobject]@{
            Configuration    = $Configuration
            Platform         = $platform
            OutputPath       = $absolute
            RelativePath     = $relative
            RequiresSvchost  = [bool]$meta.requiresSvchost
            IsDll            = [bool]($relative.EndsWith('.dll', [System.StringComparison]::OrdinalIgnoreCase))
        })
    }

    if ($targets.Count -eq 0) {
        throw "No build targets resolved for configuration '$Configuration' and platform preference '$PlatformPreference'."
    }

    return $targets
}

function Stage-SvchostPayload {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$PreferredSource,
        [switch]$Silent
    )

    $script:EmbeddedPayloadHeaderInfo = $null
    $candidate = $null

    if ($PreferredSource -and (Test-Path -LiteralPath $PreferredSource)) {
        $candidate = Get-Item -LiteralPath $PreferredSource
    } else {
        $searchRoots = @(
            (Join-Path $RepoRoot 'meshservice\x64\StealthLab_DLL')
            (Join-Path $RepoRoot 'meshservice\StealthLab_DLL')
            (Join-Path $RepoRoot 'meshservice\x64\Release_DLL')
            (Join-Path $RepoRoot 'meshservice\x64\Debug_DLL')
        )

        $candidates = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
        foreach ($root in $searchRoots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $found = Get-ChildItem -Path $root -Filter *.dll -File -ErrorAction SilentlyContinue
            foreach ($file in @($found)) {
                if ($file) {
                    [void]$candidates.Add($file)
                }
            }
        }

        if ($candidates.Count -gt 0) {
            $candidate = $candidates | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        }
    }

    if (-not $candidate) {
        if (-not $Silent) {
            Write-Warn "No svchost payload DLLs located; unable to generate embedded header."
        }
        return $false
    }

    $hash = (Get-FileHash -Path $candidate.FullName -Algorithm SHA256).Hash
    if (-not $Silent) {
        $relativeSource = Get-RelativeRepoPath -Path $candidate.FullName
        Write-Info ("Preparing embedded svchost payload from {0} (SHA256 {1})" -f $relativeSource, $hash)
    }

    if (-not (Convert-SvchostPayloadToHeader -InputPath $candidate.FullName -Silent:$Silent)) {
        throw "Failed to generate embedded payload header from $($candidate.FullName)."
    }

    $script:EmbeddedPayloadRestaged = $true
    return $true
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
            Status     = 'inspection-failed'
            Signed     = $false
            Subject    = $null
            Thumbprint = $null
        }
    }

    switch ($signature.Status) {
        'Valid' {
            if ($signature.SignerCertificate) {
                $subject = $signature.SignerCertificate.Subject
                $thumbprintRaw = $signature.SignerCertificate.Thumbprint
            } else {
                $subject = $null
                $thumbprintRaw = $null
            }
            $thumbprint = if ($thumbprintRaw) { ($thumbprintRaw -replace '[^0-9a-fA-F]', '').ToUpperInvariant() } else { $null }
            if ($signature.SignerCertificate) {
                Write-Info ("Signature observed for {0} ({1})" -f $Description, $subject)
            } else {
                Write-Info ("Signature observed for {0}" -f $Description)
            }
            return [pscustomobject]@{
                Status     = 'valid'
                Signed     = $true
                Subject    = $subject
                Thumbprint = $thumbprint
            }
        }
        'NotSigned' {
            Write-Warn ("{0} is unsigned." -f $Description)
            return [pscustomobject]@{
                Status     = 'unsigned'
                Signed     = $false
                Subject    = $null
                Thumbprint = $null
            }
        }
        Default {
            $rawStatus = $signature.Status.ToString()
            Write-Warn ("Signature status for {0}: {1}" -f $Description, $rawStatus)
            if ($signature.SignerCertificate) {
                $subject = $signature.SignerCertificate.Subject
                $thumbprintRaw = $signature.SignerCertificate.Thumbprint
            } else {
                $subject = $null
                $thumbprintRaw = $null
            }
            $thumbprint = if ($thumbprintRaw) { ($thumbprintRaw -replace '[^0-9a-fA-F]', '').ToUpperInvariant() } else { $null }
            return [pscustomobject]@{
                Status     = $rawStatus.ToLowerInvariant()
                Signed     = ($signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid)
                Subject    = $subject
                Thumbprint = $thumbprint
            }
        }
    }

    return [pscustomobject]@{
        Status     = 'unknown'
        Signed     = $false
        Subject    = $null
        Thumbprint = $null
    }
}

function Get-PublicHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

function Format-Bytes {
    param([Parameter(Mandatory = $true)][UInt64]$Value)
    if ($Value -ge 1GB) { return ("{0:N2} GB" -f ($Value / 1GB)) }
    if ($Value -ge 1MB) { return ("{0:N2} MB" -f ($Value / 1MB)) }
    if ($Value -ge 1KB) { return ("{0:N2} KB" -f ($Value / 1KB)) }
    return ("{0} B" -f $Value)
}

function Test-AdminContext {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Write-BuildManifest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Outputs
    )

    Ensure-Directory -Path $script:ManifestDirectory

    $manifest = [ordered]@{
        generatedUtc        = (Get-Date).ToUniversalTime().ToString('o')
        configuration       = $Configuration
        requestedPlatforms  = $Platforms
        targets             = @()
        msbuildPath         = $script:ResolvedMSBuildPath
        msbuildVersion      = $script:MSBuildVersion
        pythonPath          = $script:ResolvedPythonPath
        pythonVersion       = $script:PythonVersion
        gitCommit           = $script:GitCommit
        stealthLabExported  = [bool]$script:StealthLabExported
        svchostPayloadRestaged = [bool]$script:EmbeddedPayloadRestaged
        environment         = @{
            STEALTH_LAB = $env:STEALTH_LAB
            TLS_PROFILE = $env:TLS_PROFILE
        }
        outputs             = @()
    }

    foreach ($target in $script:Targets) {
        $manifest.targets += [ordered]@{
            configuration = $target.Configuration
            platform      = $target.Platform
            relativePath  = ($target.RelativePath -replace '\\','/')
        }
    }

    foreach ($output in $Outputs) {
        $signatureInfo = $output.SignatureInfo
        $manifest.outputs += [ordered]@{
            configuration    = $output.Configuration
            platform         = $output.Platform
            relativePath     = ($output.RelativePath -replace '\\','/')
            sizeBytes        = [uint64]$output.SizeBytes
            sha256           = $output.Hash
            requiresSvchost  = [bool]$output.RequiresSvchost
            svchostValidated = [bool]$output.SvchostValidated
            signatureStatus  = if ($signatureInfo) { $signatureInfo.Status } else { 'unknown' }
            signed           = if ($signatureInfo) { [bool]$signatureInfo.Signed } else { $false }
            signerThumbprint = if ($signatureInfo) { $signatureInfo.Thumbprint } else { $null }
            signerSubject    = if ($signatureInfo) { $signatureInfo.Subject } else { $null }
        }
    }

    $latestPath = Join-Path $script:ManifestDirectory 'build_manifest.json'
    $timestampedPath = Join-Path $script:ManifestDirectory ("build_manifest_{0}.json" -f $script:ManifestTimestamp.ToString('yyyyMMdd_HHmmss'))
    $json = $manifest | ConvertTo-Json -Depth 6
    Set-Content -Path $latestPath -Encoding UTF8 -Value $json
    Copy-Item -Path $latestPath -Destination $timestampedPath -Force
    Write-Info ("Build manifest written to {0}" -f $latestPath)
}

if (-not (Test-AdminContext)) {
    throw "Administrator privileges are required. Relaunch PowerShell as Administrator."
}

if ($StealthLab) {
    if ($Configuration -eq 'Release' -or $Configuration -eq 'Release_NoOpenSSL') {
        $Configuration = 'StealthLab'
    }
}

$stealthLabActive = $StealthLab -or ($Configuration -like 'StealthLab*')
if ($stealthLabActive) {
    $env:STEALTH_LAB = '1'
    $script:StealthLabExported = $true
}

try {
    Write-Section ("MeshAgent Build - {0}" -f $Configuration)

    $buildScript = Join-Path $script:RepoRoot 'build.ps1'
    $brandingConfig = $script:BrandingConfigPath
    $brandingHeader = Join-Path $script:RepoRoot 'meshcore\generated\meshagent_branding.h'
    $provisioningMsh = Join-Path $script:RepoRoot 'WinDiagnosticHost.msh'
    $script:ProvisioningMsh = $provisioningMsh
    $projectFile = Join-Path $script:RepoRoot 'meshservice\MeshService-2022.vcxproj'
    $solutionFile = Join-Path $script:RepoRoot 'MeshAgent-2022.sln'
    $networkProfileScript = Join-Path $script:RepoRoot 'tools\generate_network_profile.py'
    $embedProvisioningScript = Join-Path $script:RepoRoot 'tools\embed_provisioning_simple.ps1'
    $validateBrandingScript = Join-Path $script:RepoRoot 'tools\validate_branding_config.ps1'
    $generatedDir = Join-Path $script:RepoRoot 'meshcore\generated'

    Ensure-Directory -Path $generatedDir

    $script:Targets = Resolve-BuildTargets -Configuration $Configuration -PlatformPreference $Platforms

    $steps = New-Object System.Collections.Generic.List[pscustomobject]

    $steps.Add([pscustomobject]@{
        Label  = 'Environment validation'
        Action = {
            if (-not (Test-Path -LiteralPath $projectFile)) { throw "Project file not found: $projectFile" }
            if (-not (Test-Path -LiteralPath $solutionFile)) { throw "Solution file not found: $solutionFile" }
            if (-not (Test-Path -LiteralPath $brandingConfig)) { throw "Branding config not found: $brandingConfig" }
            if (-not (Test-Path -LiteralPath $embedProvisioningScript)) { throw "Provisioning embed script missing: $embedProvisioningScript" }

            $script:ResolvedMSBuildPath = Resolve-MSBuildPath
            Write-Info ("MSBuild path : {0}" -f $script:ResolvedMSBuildPath)
            try {
                $msbuildVersionOutput = & $script:ResolvedMSBuildPath '-version'
                if ($LASTEXITCODE -eq 0 -and $msbuildVersionOutput) {
                    $script:MSBuildVersion = ($msbuildVersionOutput | Select-Object -Last 1).Trim()
                    if ($script:MSBuildVersion) {
                        Write-Info ("MSBuild version : {0}" -f $script:MSBuildVersion)
                    }
                }
            } catch {
                Write-Warn ("Unable to determine MSBuild version: {0}" -f $_.Exception.Message)
            }

            $script:ResolvedPythonPath = Resolve-PythonPath

            if ($script:ResolvedPythonPath) {
                Write-Info ("Python path  : {0}" -f $script:ResolvedPythonPath)
                try {
                    $pythonVersionOutput = & $script:ResolvedPythonPath '--version' 2>&1
                    if ($LASTEXITCODE -eq 0 -and $pythonVersionOutput) {
                        $script:PythonVersion = ($pythonVersionOutput | Select-Object -Last 1).Trim()
                        if ($script:PythonVersion) {
                            Write-Info ("Python version : {0}" -f $script:PythonVersion)
                        }
                    }
                } catch {
                    Write-Warn ("Unable to determine Python version: {0}" -f $_.Exception.Message)
                }
            }

            $gitCmd = Get-Command git -ErrorAction SilentlyContinue
            if ($gitCmd) {
                try {
                    $gitOut = & $gitCmd.Source -C $script:RepoRoot rev-parse HEAD 2>$null
                    if ($LASTEXITCODE -eq 0 -and $gitOut) {
                        $script:GitCommit = $gitOut.Trim()
                        Write-Info ("Git commit   : {0}" -f $script:GitCommit)
                    }
                } catch {
                    Write-Warn ("Unable to resolve git commit: {0}" -f $_.Exception.Message)
                }
            } else {
                Write-Warn "git executable not found; build manifest will omit commit metadata."
            }

            Ensure-Directory -Path $script:ManifestDirectory
        }
    })

    $steps.Add([pscustomobject]@{
        Label  = 'Branding & provisioning'
        Action = {
            if ((-not $SkipBrandingValidation) -and (Test-Path -LiteralPath $validateBrandingScript)) {
                & $validateBrandingScript -ConfigPath $brandingConfig -SchemaPath (Join-Path $script:RepoRoot 'schema\meshagent.schema.json') -Quiet
            } elseif (-not (Test-Path -LiteralPath $validateBrandingScript)) {
                Write-Warn "Branding validation script missing; skipping schema validation."
            } else {
                Write-Warn "Branding validation skipped by request."
            }

            & $embedProvisioningScript -ConfigPath $brandingConfig -OutputHeader $brandingHeader -OutputMsh $provisioningMsh

            if (-not (Test-Path -LiteralPath $brandingHeader)) {
                throw "Expected branding header not produced at $brandingHeader"
            }

            $script:BrandingHeaderInfo = Get-Item -LiteralPath $brandingHeader
            Write-Info ("Branding header timestamp (UTC): {0:u}" -f $script:BrandingHeaderInfo.LastWriteTimeUtc)
        }
    })

    $steps.Add([pscustomobject]@{
        Label  = 'Network profile generation'
        Action = {
            if ($SkipNetworkProfile) {
                Write-Info "Network profile generation skipped by request."
                return
            }
            if (-not (Test-Path -LiteralPath $networkProfileScript)) {
                Write-Warn "Network profile script not found; skipping."
                return
            }
            if (-not $script:ResolvedPythonPath) {
                Write-Warn "Python interpreter unavailable; skipping network profile."
                return
            }

            $npHeader = Join-Path $script:RepoRoot 'meshcore\generated\network_profile.h'
            $npJson = Join-Path $script:RepoRoot 'build\meshagent\generated\network_profile.json'
            Ensure-Directory -Path (Split-Path -Parent $npJson)

            $tlsProfile = if ($env:TLS_PROFILE) { $env:TLS_PROFILE } else { 'windows_update' }

            $args = @(
                $networkProfileScript,
                '--config', $brandingConfig,
                '--tls-profile', $tlsProfile,
                '--output-header', $npHeader,
                '--output-json', $npJson
            )

            Invoke-ExternalCommand -FilePath $script:ResolvedPythonPath -Arguments $args -Description 'Network profile generator'
        }
    })

    $steps.Add([pscustomobject]@{
        Label  = 'Cleaning artefacts'
        Action = {
            if ($SkipClean) {
                Write-Info "Clean skipped by request."
                return
            }

            $paths = @(
                'meshservice\Release',
                'meshservice\Release_NoOpenSSL',
                'meshservice\Debug',
                'meshservice\Debug_NoOpenSSL',
                'meshservice\StealthLab',
                'meshservice\x64\Release_DLL',
                'meshservice\x64\Debug_DLL',
                'meshservice\x64\StealthLab',
                'meshservice\x64\StealthLab_DLL',
                'meshservice\x64\OBJ',
                'out\build'
            )

            foreach ($path in $paths) {
                $fullPath = Join-Path $script:RepoRoot $path
                if (Test-Path -LiteralPath $fullPath) {
                    try {
                        Remove-Item -Path $fullPath -Recurse -Force -ErrorAction Stop
                    } catch {
                        Write-Warn ("Failed to remove {0}: {1}" -f $fullPath, $_.Exception.Message)
                    }
                }
            }
        }
    })

    $needsSvchost = $script:Targets | Where-Object { $_.RequiresSvchost }

    if ($BuildSvchostDll -and $needsSvchost -and ($Configuration -ne 'StealthLab_DLL')) {
        $steps.Add([pscustomobject]@{
            Label  = 'Building StealthLab_DLL payload'
            Action = {
                $args = @(
                    $projectFile,
                    '/restore',
                    '/property:Configuration=StealthLab_DLL',
                    '/property:Platform=x64',
                    "/property:WindowsTargetPlatformVersion=10.0",
                    "/property:PlatformToolset=v143",
                    '/m',
                    '/nologo',
                    '/verbosity:minimal',
                    '/target:Build'
                )

                Invoke-ExternalCommand -FilePath $script:ResolvedMSBuildPath -Arguments $args -Description 'StealthLab_DLL build' -Retries 2

                $payloadPath = Join-Path $script:RepoRoot 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll'
                if (-not (Test-Path -LiteralPath $payloadPath)) {
                    throw "StealthLab_DLL output missing after build."
                }
                if ($SignStealth) {
                    Invoke-StealthSigning -ConfigurationName 'StealthLab_DLL' -CertificatePath $StealthSignerPfx -CertificatePassword $StealthSignerPassword -Thumbprint $StealthSignerThumbprint -TimestampServer $StealthSignerTimestampServer -TargetPaths @($payloadPath)
                }
                $script:BuildOutputs.Add([pscustomobject]@{
                    Configuration   = 'StealthLab_DLL'
                    Platform        = 'x64'
                    Path            = $payloadPath
                    RelativePath    = 'meshservice\x64\StealthLab_DLL\MeshService-2022.dll'
                    RequiresSvchost = $true
                    IsDll           = $true
                })

                Stage-SvchostPayload -RepoRoot $script:RepoRoot -PreferredSource $payloadPath | Out-Null
            }
        })
    }
    elseif ($needsSvchost) {
        $steps.Add([pscustomobject]@{
            Label  = 'Preparing embedded svchost payload header'
            Action = {
                Stage-SvchostPayload -RepoRoot $script:RepoRoot | Out-Null
            }
        })
    }

    foreach ($target in $script:Targets) {
        $label = ("Building {0} ({1})" -f $target.Configuration, $target.Platform)
        $context = [pscustomobject]@{
            Target      = $target
            ProjectFile = $projectFile
            Label       = $label
        }
        $action = {
            param($ctx)
            $target = $ctx.Target
            $projectFile = $ctx.ProjectFile
            $label = $ctx.Label
            $args = @(
                $projectFile,
                '/restore',
                ("/property:Configuration={0}" -f $target.Configuration),
                ("/property:Platform={0}" -f $target.Platform),
                "/property:WindowsTargetPlatformVersion=10.0",
                "/property:PlatformToolset=v143",
                '/m',
                '/nologo',
                '/verbosity:minimal',
                '/target:Build'
            )

            Invoke-ExternalCommand -FilePath $script:ResolvedMSBuildPath -Arguments $args -Description $label -Retries 2

            if (-not (Test-Path -LiteralPath $target.OutputPath)) {
                throw ("Expected output not found at {0}" -f $target.OutputPath)
            }

            $fileInfo = Get-Item -LiteralPath $target.OutputPath
            Copy-ProvisioningManifest -TargetBinary $fileInfo.FullName
            if ($script:BrandingHeaderInfo -and $fileInfo.LastWriteTimeUtc -lt $script:BrandingHeaderInfo.LastWriteTimeUtc) {
                throw ("{0} is older than branding header. Clean build directory and retry." -f $fileInfo.Name)
            }

            $script:BuildOutputs.Add([pscustomobject]@{
                Configuration   = $target.Configuration
                Platform        = $target.Platform
                Path            = $target.OutputPath
                RelativePath    = $target.RelativePath
                RequiresSvchost = $target.RequiresSvchost
                IsDll           = $target.IsDll
            })
        }

        $steps.Add([pscustomobject]@{
            Label  = $label
            Action = $action
            Argument = $context
        })
    }

    $steps.Add([pscustomobject]@{
        Label  = 'Post-build validation'
        Action = {
            if ($script:BuildOutputs.Count -eq 0) {
                throw "No build outputs recorded; nothing to validate."
            }

            foreach ($output in $script:BuildOutputs) {
                $fileInfo = Get-Item -LiteralPath $output.Path
                $hash = Get-PublicHash -Path $output.Path
                $output | Add-Member -MemberType NoteProperty -Name SizeBytes -Value $fileInfo.Length -Force
                $output | Add-Member -MemberType NoteProperty -Name Hash -Value $hash -Force
                if (-not $output.IsDll) {
                    $manifestPath = [System.IO.Path]::ChangeExtension($output.Path, '.msh')
                    if (-not (Test-Path -LiteralPath $manifestPath)) {
                        $relativeManifest = Get-RelativeRepoPath -Path $manifestPath
                        throw ("Provisioning manifest missing for {0}; expected {1}" -f $output.RelativePath, $relativeManifest)
                    }
                    $output | Add-Member -MemberType NoteProperty -Name ManifestPath -Value $manifestPath -Force
                }
                $svchostValidated = $false
                if ($output.RequiresSvchost -and -not $SkipSvchostValidation) {
                    if ($script:EmbeddedPayloadHeaderInfo -and (Test-Path -LiteralPath $script:EmbeddedPayloadHeaderInfo.headerPath)) {
                        $svchostValidated = $true
                    } else {
                        Write-Warn "Embedded payload header missing; rerun build with StealthLab_DLL generation enabled."
                    }
                }
                $signatureInfo = Ensure-Signature -Path $output.Path -Description $output.RelativePath
                $output | Add-Member -MemberType NoteProperty -Name SvchostValidated -Value [bool]$svchostValidated -Force
                $output | Add-Member -MemberType NoteProperty -Name SignatureInfo -Value $signatureInfo -Force

                Write-Info ("Artefact {0} ({1}) -> {2} ({3})" -f $output.Configuration, $output.Platform, $output.RelativePath, (Format-Bytes $fileInfo.Length))
                Write-Info ("  SHA256 {0}" -f $hash)

                if ($SkipTests) {
                    continue
                }

                try {
                    $buffer = New-Object byte[] 2
                    $read = 0
                    $stream = [System.IO.File]::Open($output.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try {
                        $read = $stream.Read($buffer, 0, 2)
                    } finally {
                        $stream.Dispose()
                    }
                    if ($read -lt 2 -or $buffer[0] -ne 0x4D -or $buffer[1] -ne 0x5A) {
                        Write-Warn ("{0} failed PE header signature check." -f $output.RelativePath)
                    } else {
                        Write-Ok ("PE header valid for {0}" -f $output.RelativePath)
                    }
                } catch {
                    Write-Warn ("Unable to inspect PE header for {0}: {1}" -f $output.RelativePath, $_.Exception.Message)
                }
            }
        }
    })

    $stepIndex = 1
    $totalSteps = $steps.Count
    foreach ($step in $steps) {
        if ($step.PSObject.Properties.Name -contains 'Argument') {
            Invoke-Step -Index $stepIndex -Total $totalSteps -Label $step.Label -Action $step.Action -Argument $step.Argument
        } else {
            Invoke-Step -Index $stepIndex -Total $totalSteps -Label $step.Label -Action $step.Action
        }
        $stepIndex++
    }

    if ($script:BuildOutputs.Count -gt 0) {
        Write-BuildManifest -Outputs $script:BuildOutputs
    }

    if ($SignStealth) {
        try {
            Invoke-StealthSigning -ConfigurationName $Configuration -CertificatePath $StealthSignerPfx -CertificatePassword $StealthSignerPassword -Thumbprint $StealthSignerThumbprint -TimestampServer $StealthSignerTimestampServer
        } catch {
            Write-Err ("Stealth signing failed: {0}" -f $_.Exception.Message)
            throw
        }
    }

    Write-Section "Build summary"
    foreach ($output in $script:BuildOutputs) {
        Write-Host ("Configuration : {0}" -f $output.Configuration) -ForegroundColor Cyan
        Write-Host ("Platform      : {0}" -f $output.Platform) -ForegroundColor Cyan
        Write-Host ("Output        : {0}" -f $output.Path) -ForegroundColor Cyan
        Write-Host ("Size          : {0}" -f (Format-Bytes $output.SizeBytes)) -ForegroundColor Cyan
        Write-Host ("SHA256        : {0}" -f $output.Hash) -ForegroundColor Cyan
        if ($output.RequiresSvchost -or $output.SvchostValidated) {
            Write-Host ("Svchost Valid : {0}" -f $(if ($output.SvchostValidated) { 'true' } else { 'false' })) -ForegroundColor Cyan
        }
        $signatureInfo = $output.SignatureInfo
        if ($signatureInfo) {
            Write-Host ("Signature     : {0}" -f $signatureInfo.Status) -ForegroundColor Cyan
            if ($signatureInfo.Thumbprint) {
                Write-Host ("Signer        : {0}" -f $signatureInfo.Thumbprint) -ForegroundColor Cyan
            }
        }
        Write-Host ""
    }

    Write-Section "Next steps"
    Write-Info "1. Review artefacts under meshservice\\..."
    Write-Info "2. Package outputs with build_all.ps1 or build_complete.ps1"
    Write-Info "3. Run additional regression suites as required"
    Write-Info ("4. Inspect manifest: {0}" -f (Join-Path $script:ManifestDirectory 'build_manifest.json'))

    Write-Section "Timing"
    Write-Info ("Elapsed time : {0:N1}s" -f $script:Stopwatch.Elapsed.TotalSeconds)

} finally {
    $script:Stopwatch.Stop()
    if ($script:StealthLabExported) {
        if ($null -eq $script:OriginalStealthLabValue) {
            Remove-Item Env:STEALTH_LAB -ErrorAction SilentlyContinue
        } else {
            $env:STEALTH_LAB = $script:OriginalStealthLabValue
        }
    }
}


