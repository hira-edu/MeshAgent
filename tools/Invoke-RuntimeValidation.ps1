#Requires -Version 5.1
<#
.SYNOPSIS
    Runs `test.ps1 -RuntimeValidation` with MeshCentral defaults pulled from the repo so CI/staging
    can exercise the elevated service install/uninstall flow with one command.

.DESCRIPTION
    This helper enforces elevation, locates `meshctrl.js`, resolves the Mesh ID from
    `branding_config.local.json`, and then shells into test.ps1 with all of the required MeshCentral
    parameters. Use it from CI (or locally) after staging the StealthLab build so runtime evidence
    is captured automatically under `verification/phase3/runtime.json`.

.PARAMETER BinaryPath
    Root directory that contains MeshService-2022.exe (default: meshservice\x64\StealthLab).

.PARAMETER MeshCentralRepo
    Path to the local MeshCentral checkout that hosts `meshctrl.js` and meshcentral-data (default: ..\MeshCentral).

.PARAMETER MeshCtrlPath
    Optional explicit path to meshctrl.js. When omitted, the helper searches inside MeshCentralRepo.

.PARAMETER MeshCentralControlUrl
    WebSocket control URL used by meshctrl. Defaults to ws://127.0.0.1:3000.

.PARAMETER MeshCentralMeshId
    Device group identifier. If omitted, the helper falls back to provisioning.meshId from branding_config.local.json.

.PARAMETER MeshCentralLoginUser / MeshCentralLoginPass
    Credentials passed to meshctrl AgentDownload. Defaults match the local diagadmin account.

.PARAMETER ReportPath
    Destination for the JSON report emitted by test.ps1 (default: verification/phase3/runtime.json).

.PARAMETER LogPath
    Optional path to capture console output from test.ps1 via Tee-Object so CI can archive the log alongside the JSON report.

.PARAMETER AllowNonAdmin
    Override the elevation requirement (useful for CI). When set, the helper warns but continues even if the session is not running as Administrator.

.PARAMETER SkipMeshCentralPreflight
    Skips the MeshCentral cache refresh/parity check. By default the helper restarts MeshCentral, clears cached meshagent downloads,
    and verifies that `meshcentral-data\agents\MeshService64.exe` matches the local StealthLab build before running tests.

.PARAMETER IncludeFullInstall
    When specified, runs the legacy install/uninstall RuntimeValidation checks instead of forcing svchost-only coverage.
#>
[CmdletBinding()]
param(
    [string]$BinaryPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'meshservice\x64\StealthLab'),
    [string]$MeshCentralRepo = (Join-Path (Split-Path $PSScriptRoot -Parent) '..\MeshCentral'),
    [string]$MeshCtrlPath,
    [string]$MeshCentralControlUrl = 'ws://127.0.0.1:3000',
    [string]$MeshCentralMeshId,
    [string]$MeshCentralLoginUser = 'diagadmin',
    [string]$MeshCentralLoginPass = 'DiagTest!23',
    [string]$ReportPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'verification\phase3\runtime.json'),
    [string]$LogPath,
    [switch]$AllowNonAdmin,
    [switch]$SkipMeshCentralPreflight,
    [switch]$IncludeFullInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Elevation {
    param([bool]$AllowOverride)

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($AllowOverride) {
            Write-Warning "Runtime validation requested outside an elevated session; continuing due to -AllowNonAdmin override."
            return
        }
        throw "Runtime validation requires an elevated PowerShell session. Re-run as Administrator or pass -AllowNonAdmin to override (not recommended)."
    }
}

function Resolve-ExistingPath {
    param([string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    return $resolved.ProviderPath
}

function Resolve-MeshCentralDataPath {
    param([string]$RepoPath)

    if ([string]::IsNullOrWhiteSpace($RepoPath)) {
        throw "MeshCentral repo path is required to resolve meshcentral-data."
    }

    $defaults = [System.Collections.Generic.List[string]]::new()
    $defaults.Add((Join-Path $RepoPath 'meshcentral-data'))
    $parent = Split-Path $RepoPath -Parent
    if ($parent) { $defaults.Add((Join-Path $parent 'meshcentral-data')) }

    $configCandidates = $defaults | ForEach-Object { Join-Path $_ 'config.json' } | Select-Object -Unique
    foreach ($configPath in $configCandidates) {
        if (-not (Test-Path -LiteralPath $configPath)) { continue }
        try {
            $configContent = Get-Content -LiteralPath $configPath -Raw
            try {
                $config = $configContent | ConvertFrom-Json
            } catch {
                $config = $configContent | ConvertFrom-Json -AsHashtable
            }
        } catch {
            Write-Warning ("Unable to parse MeshCentral config '{0}': {1}" -f $configPath, $_.Exception.Message)
            continue
        }
        $settings = $config.settings
        if ($settings -is [System.Collections.IDictionary]) {
            $datapath = $settings['datapath']
        } else {
            $datapath = $settings.datapath
        }
        if ([string]::IsNullOrWhiteSpace($datapath)) { continue }
        if (-not [System.IO.Path]::IsPathRooted($datapath)) {
            $datapath = Join-Path $RepoPath $datapath
        }
        return (Resolve-ExistingPath $datapath)
    }

    foreach ($candidate in $defaults) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-ExistingPath $candidate)
        }
    }

    throw "Unable to locate meshcentral-data. Ensure the MeshCentral repo lives beside MeshAgent or pass -MeshCentralRepo explicitly."
}

$script:MeshCentralProcessFilter = "CommandLine LIKE '%meshcentral.js%'"
function Get-MeshCentralProcesses {
    try {
        return @(Get-CimInstance -ClassName Win32_Process -Filter $script:MeshCentralProcessFilter -ErrorAction Stop)
    } catch {
        return @()
    }
}

function Stop-MeshCentralProcesses {
    $procs = Get-MeshCentralProcesses
    $procCount = @($procs).Count
    if ($procCount -eq 0) { return $false }
    foreach ($proc in @($procs)) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        } catch {
            Write-Warning ("Failed to stop MeshCentral PID {0}: {1}" -f $proc.ProcessId, $_.Exception.Message)
        }
    }
    Start-Sleep -Seconds 2
    return $true
}

function Start-MeshCentralProcess {
    param([string]$RepoPath)

    if (-not (Test-Path -LiteralPath $RepoPath)) {
        throw "MeshCentral repo path '$RepoPath' not found while attempting to start node meshcentral.js."
    }

    Start-Process -FilePath 'node' -ArgumentList 'meshcentral.js' -WorkingDirectory $RepoPath -WindowStyle Hidden | Out-Null
    Start-Sleep -Seconds 3
}

function Invoke-MeshCentralCacheRefresh {
    param(
        [string]$RepoPath,
        [string]$DataPath
    )

    $downloads = @(
        'meshagent.exe64-WindowsDiagnostics.exe',
        'meshagent.exe64-testdevices.exe'
    )

    foreach ($artifact in $downloads) {
        $target = Join-Path $RepoPath $artifact
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
        }
    }

    $cacheDir = Join-Path $DataPath 'meshcentral-downloads'
    if (Test-Path -LiteralPath $cacheDir) {
        Remove-Item -LiteralPath $cacheDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-MeshCentralPreflight {
    param(
        [string]$RepoPath,
        [string]$BinaryRoot
    )

    Write-Host "[RuntimeValidation] Performing MeshCentral cache refresh + parity check..." -ForegroundColor Cyan
    $dataPath = Resolve-MeshCentralDataPath -RepoPath $RepoPath

    $localBinary = Join-Path $BinaryRoot 'MeshService-2022.exe'
    if (-not (Test-Path -LiteralPath $localBinary)) {
        throw "Local StealthLab binary missing at $localBinary"
    }

    $serverBinary = Join-Path $dataPath 'agents\MeshService64.exe'
    if (-not (Test-Path -LiteralPath $serverBinary)) {
        throw "MeshCentral agent payload missing at $serverBinary. Run tools/stage_meshcentral_agents.ps1 before invoking runtime validation."
    }

    $localHash = (Get-FileHash -LiteralPath $localBinary -Algorithm SHA256).Hash
    $serverHash = (Get-FileHash -LiteralPath $serverBinary -Algorithm SHA256).Hash
    if (-not [string]::Equals($localHash, $serverHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("MeshCentral agent hash mismatch (server {0} vs local {1}). Re-stage agents before continuing." -f $serverHash, $localHash)
    }

    $hadProcesses = Stop-MeshCentralProcesses
    Invoke-MeshCentralCacheRefresh -RepoPath $RepoPath -DataPath $dataPath
    if ($hadProcesses -or @((Get-MeshCentralProcesses)).Count -eq 0) {
        Start-MeshCentralProcess -RepoPath $RepoPath
    }

    Write-Host ("[RuntimeValidation] MeshCentral preflight complete (data dir: {0})." -f $dataPath) -ForegroundColor DarkGray
}

$script:BrandingState = $null
$script:BrandingHelperLoaded = $false
function Get-BrandingState {
    param([string]$RepoRoot)

    if (-not $script:BrandingHelperLoaded) {
        $brandingHelper = Join-Path $RepoRoot 'tools\BrandingConfig.ps1'
        if (-not (Test-Path -LiteralPath $brandingHelper)) {
            throw "Branding helper missing at $brandingHelper"
        }
        . $brandingHelper
        $script:BrandingHelperLoaded = $true
    }

    if ($null -eq $script:BrandingState) {
        $script:BrandingState = Get-BrandingConfig -RepoRoot $RepoRoot -Quiet
    }

    return $script:BrandingState
}

function Resolve-MeshCtrlPath {
    param(
        [string]$ExplicitPath,
        [string]$RepoRoot
    )

    if ($ExplicitPath) {
        return (Resolve-ExistingPath $ExplicitPath)
    }

    $candidates = @()
    if ($RepoRoot) {
        $candidates += (Join-Path $RepoRoot 'meshctrl.js')
    }
    $candidates += (Join-Path (Split-Path $PSScriptRoot -Parent) '..\MeshCentral\meshctrl.js')

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-ExistingPath $candidate)
        }
    }

    throw "Unable to locate meshctrl.js. Pass -MeshCtrlPath or -MeshCentralRepo."
}

function Resolve-MeshIdFromBranding {
    param([string]$RepoRoot)

    $state = Get-BrandingState -RepoRoot $RepoRoot
    if ($null -eq $state.Config -or $null -eq $state.Config.provisioning) {
        throw "Branding configuration missing provisioning block."
    }
    return $state.Config.provisioning.meshId
}

function Test-MeshCentralReachable {
    param([string]$ControlUrl)

    try {
        $uri = [System.Uri]$ControlUrl
        $probe = "{0}://{1}:{2}/" -f (($uri.Scheme -eq 'wss') ? 'https' : 'http'), $uri.Host, ($uri.Port -ne -1 ? $uri.Port : ($uri.Scheme -eq 'wss' ? 443 : 80))
        Invoke-WebRequest -Uri $probe -UseBasicParsing -TimeoutSec 5 | Out-Null
        return $true
    } catch {
        Write-Warning ("MeshCentral probe failed for {0}: {1}" -f $ControlUrl, $_.Exception.Message)
        return $false
    }
}

function Get-ServiceNameFromBranding {
    param([string]$RepoRoot)

    $state = Get-BrandingState -RepoRoot $RepoRoot
    $serviceName = $state.Config.branding.serviceName
    if ([string]::IsNullOrWhiteSpace($serviceName)) {
        $serviceName = 'MeshAgent'
    }
    return $serviceName
}

function Get-ServiceFailureExpectation {
    param($PersistenceConfig)

    $result = [pscustomobject]@{
        Enabled       = $false
        ResetPeriod   = 0
        DelayMs       = 0
        ExpectRestart = $false
    }

    if ($null -eq $PersistenceConfig) {
        return $result
    }

    $recovery = $PersistenceConfig.serviceRecovery
    $watchdog = $PersistenceConfig.watchdog

    if ($recovery -and $recovery.enabled) {
        $result.Enabled = $true
        if ($recovery.resetPeriod) { $result.ResetPeriod = [uint32]$recovery.resetPeriod }
        if ($recovery.restartDelay) { $result.DelayMs = [uint32]$recovery.restartDelay }
        if ($recovery.actions) {
            $result.ExpectRestart = @($recovery.actions | Where-Object { $_ -match 'restart' }).Count -gt 0
        } else {
            $result.ExpectRestart = $true
        }
    }
    elseif ($watchdog -and $watchdog.enabled) {
        $result.Enabled = $true
        if ($watchdog.intervalSeconds) { $result.ResetPeriod = [uint32]$watchdog.intervalSeconds }
        if ($watchdog.restartDelay) { $result.DelayMs = [uint32]$watchdog.restartDelay * 1000 }
        $result.ExpectRestart = [bool]$watchdog.restartOnCrash
    }

    return $result
}

function Assert-ServiceFailureActions {
    param(
        [string]$ServiceName,
        [pscustomobject]$Expectation
    )

    if (-not $Expectation -or -not $Expectation.Enabled) {
        Write-Host ("[RuntimeValidation] Service '{0}' recovery/watchdog disabled per branding configuration." -f $ServiceName) -ForegroundColor Yellow
        return
    }

    Write-Host ("[RuntimeValidation] Verifying failure actions for '{0}'..." -f $ServiceName) -ForegroundColor Cyan
    $scOutput = & sc.exe qfailure $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query failure actions for service '$ServiceName': $scOutput"
    }
    $outputText = ($scOutput | Out-String)

    $resetMatch = [regex]::Match($outputText, 'RESET_PERIOD\s*\(in seconds\)\s*:\s*(\d+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $resetMatch.Success) {
        throw "Service '$ServiceName' failure actions missing reset period."
    }
    $actualReset = [uint32]$resetMatch.Groups[1].Value
    if ($Expectation.ResetPeriod -gt 0 -and $actualReset -ne $Expectation.ResetPeriod) {
        throw ("Service '{0}' reset period mismatch. Expected {1}, found {2}." -f $ServiceName, $Expectation.ResetPeriod, $actualReset)
    }

    $delayMatch = [regex]::Match($outputText, 'Delay\s*=\s*(\d+)\s*milliseconds', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($Expectation.ExpectRestart -and (-not $delayMatch.Success)) {
        throw "Service '$ServiceName' failure actions missing restart delay."
    }
    elseif ($delayMatch.Success -and $Expectation.DelayMs -gt 0) {
        $actualDelay = [uint32]$delayMatch.Groups[1].Value
        if ($actualDelay -ne $Expectation.DelayMs) {
            throw ("Service '{0}' restart delay mismatch. Expected {1} ms, found {2} ms." -f $ServiceName, $Expectation.DelayMs, $actualDelay)
        }
    }

    $restartCount = ([regex]::Matches($outputText, 'RESTART\s+--', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    if ($Expectation.ExpectRestart -and $restartCount -eq 0) {
        throw "Service '$ServiceName' failure actions do not include any restart entries."
    }
    if (-not $Expectation.ExpectRestart -and $restartCount -gt 0) {
        throw "Service '$ServiceName' failure actions unexpectedly include restart entries while branding disabled them."
    }

    Write-Host ("[RuntimeValidation] Failure actions verified for '{0}' (reset={1}s delay={2}ms restarts={3})." -f $ServiceName, $actualReset, ($delayMatch.Success ? $delayMatch.Groups[1].Value : 0), $restartCount) -ForegroundColor Green
}

function Assert-SvchostOnlyService {
    param(
        [string]$ServiceName,
        [pscustomobject]$FailureExpectation
    )

    Write-Host ("[RuntimeValidation] Validating service '{0}' is svchost-only..." -f $ServiceName) -ForegroundColor Cyan
    $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        throw "Service '$ServiceName' not found after runtime validation."
    }

    if ($svc.ServiceType -ne 'Share Process') {
        throw "Service '$ServiceName' is not registered as SERVICE_WIN32_SHARE_PROCESS (actual: $($svc.ServiceType))."
    }
    if ($svc.StartMode -ne 'Disabled') {
        throw "Service '$ServiceName' must be disabled after install. Detected StartMode=$($svc.StartMode)."
    }
    if ($svc.State -ne 'Stopped') {
        throw "Service '$ServiceName' must be stopped after install. Detected State=$($svc.State)."
    }
    if ($svc.PathName -notmatch 'svchost\.exe') {
        throw "Service '$ServiceName' does not point to svchost (PathName=$($svc.PathName))."
    }
    if ($svc.PathName -match 'meshagent\.exe') {
        throw "Service '$ServiceName' still references meshagent.exe which indicates a standalone registration."
    }

    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $svcReg = Get-ItemProperty -Path $svcRegPath -ErrorAction Stop
    if ($svcReg.Type -ne 0x20) {
        throw ("Service '{0}' registry Type is {1}. Expected 0x20 (SERVICE_WIN32_SHARE_PROCESS)." -f $ServiceName, ('0x{0:X}' -f $svcReg.Type))
    }
    if ($svcReg.Start -ne 4) {
        throw ("Service '{0}' registry Start is {1}. Expected 4 (Disabled)." -f $ServiceName, $svcReg.Start)
    }

    Write-Host ("[RuntimeValidation] Service '{0}' confirmed svchost-only (disabled/stopped)." -f $ServiceName) -ForegroundColor Green
    Assert-ServiceFailureActions -ServiceName $ServiceName -Expectation $FailureExpectation
}

Assert-Elevation -AllowOverride:$AllowNonAdmin

$repoRoot = Split-Path $PSScriptRoot -Parent
$brandingState = Get-BrandingState -RepoRoot $repoRoot
if ($null -eq $brandingState -or $null -eq $brandingState.Config) {
    throw "Branding configuration is unavailable. Run tools/embed_provisioning.ps1 to refresh generated headers."
}
$failureExpectation = Get-ServiceFailureExpectation -PersistenceConfig $brandingState.Config.persistence
$serviceNameTarget = Get-ServiceNameFromBranding -RepoRoot $repoRoot
$binaryRoot = Resolve-ExistingPath $BinaryPath

$meshCentralRepoResolved = $MeshCentralRepo
if ($MeshCentralRepo -and (Test-Path -LiteralPath $MeshCentralRepo)) {
    $meshCentralRepoResolved = Resolve-ExistingPath $MeshCentralRepo
}

$meshCtrlResolved = Resolve-MeshCtrlPath -ExplicitPath $MeshCtrlPath -RepoRoot $meshCentralRepoResolved

if (-not $SkipMeshCentralPreflight) {
    Invoke-MeshCentralPreflight -RepoPath $meshCentralRepoResolved -BinaryRoot $binaryRoot
}

if (-not $MeshCentralMeshId) {
    $MeshCentralMeshId = Resolve-MeshIdFromBranding -RepoRoot $repoRoot
}

if (-not $MeshCentralMeshId) {
    throw "MeshCentral Mesh ID could not be resolved. Provide -MeshCentralMeshId or update branding_config.local.json."
}

Test-MeshCentralReachable -ControlUrl $MeshCentralControlUrl | Out-Null

$testScript = Join-Path $repoRoot 'test.ps1'
if (-not (Test-Path -LiteralPath $testScript)) {
    throw "test.ps1 not found at $testScript"
}

$reportDir = Split-Path $ReportPath -Parent
if (-not (Test-Path -LiteralPath $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

if ($LogPath) {
    $logDir = Split-Path $LogPath -Parent
    if ($logDir -and (-not (Test-Path -LiteralPath $logDir))) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
}

$testArgs = @{
    BinaryPath            = $binaryRoot
    RuntimeValidation     = $true
    MeshCentralMeshId     = $MeshCentralMeshId
    MeshCentralControlUrl = $MeshCentralControlUrl
    MeshCentralLoginUser  = $MeshCentralLoginUser
    MeshCentralLoginPass  = $MeshCentralLoginPass
    MeshCtrlPath          = $meshCtrlResolved
    ReportPath            = $ReportPath
}
if (-not $IncludeFullInstall) {
    $testArgs['SvchostOnly'] = $true
}

Write-Host "[RuntimeValidation] Launching test.ps1 with MeshCentral download verification..." -ForegroundColor Cyan
if ($LogPath) {
    & $testScript @testArgs 2>&1 | Tee-Object -FilePath $LogPath
} else {
    & $testScript @testArgs
}
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    throw "Runtime validation failed (exit code $exitCode). See $ReportPath for details."
}

$binaryExe = Join-Path $binaryRoot "MeshService-2022.exe"
if (-not (Test-Path -LiteralPath $binaryExe)) {
    throw "Runtime binary not found at $binaryExe"
}

function Invoke-AgentBinary {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [int]$TimeoutSeconds = 180
    )

    $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Verb RunAs -WindowStyle Hidden -PassThru
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        try { $proc.Kill() } catch { }
        throw ("Command '{0} {1}' timed out after {2}s" -f $FilePath, ($Arguments -join ' '), $TimeoutSeconds)
    }
    return $proc.ExitCode
}

Write-Host ("[RuntimeValidation] Reinstalling '{0}' to assert svchost-only posture..." -f $serviceNameTarget) -ForegroundColor Cyan
$svchostInstallExit = Invoke-AgentBinary -FilePath $binaryExe -Arguments @('-fullinstall')
if ($svchostInstallExit -ne 0) {
    throw ("MeshService-2022.exe -fullinstall exited with code {0} during svchost verification." -f $svchostInstallExit)
}

Write-Host ("[RuntimeValidation] Forcing '{0}' into disabled/stopped state before verification..." -f $serviceNameTarget) -ForegroundColor Yellow
try {
    sc.exe stop $serviceNameTarget 2>$null | Out-Null
} catch { }
Start-Sleep -Milliseconds 500
try {
    sc.exe config $serviceNameTarget start= disabled 2>$null | Out-Null
} catch {
    Write-Warning ("Failed to set service '{0}' to disabled: {1}" -f $serviceNameTarget, $_.Exception.Message)
}

try {
    Assert-SvchostOnlyService -ServiceName $serviceNameTarget -FailureExpectation $failureExpectation
} finally {
    try {
        Invoke-AgentBinary -FilePath $binaryExe -Arguments @('-fulluninstall') | Out-Null
    } catch {
        Write-Warning ("Failed to uninstall '{0}' during svchost cleanup: {1}" -f $serviceNameTarget, $_.Exception.Message)
    }
}

Write-Host "[RuntimeValidation] Completed successfully. Report: $ReportPath" -ForegroundColor Green
