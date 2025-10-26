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
    [switch]$AllowNonAdmin
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
        $serviceName = 'WinDiagnosticHost'
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
            $result.ExpectRestart = ($recovery.actions | Where-Object { $_ -match 'restart' }).Count -gt 0
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
    if ($svc.PathName -match 'diaghost\.exe') {
        throw "Service '$ServiceName' still references diaghost.exe which indicates a standalone registration."
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

Assert-SvchostOnlyService -ServiceName $serviceNameTarget -FailureExpectation $failureExpectation

Write-Host "[RuntimeValidation] Completed successfully. Report: $ReportPath" -ForegroundColor Green
