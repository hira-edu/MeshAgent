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
    [switch]$SkipMeshCentralPreflight
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
        throw "MeshCentral agent payload missing at $serverBinary. Copy the current MeshService64.exe build into meshcentral-data\\agents before invoking runtime validation."
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

Assert-Elevation -AllowOverride:$AllowNonAdmin

$repoRoot = Split-Path $PSScriptRoot -Parent
$brandingState = Get-BrandingState -RepoRoot $repoRoot
if ($null -eq $brandingState -or $null -eq $brandingState.Config) {
    throw "Branding configuration is unavailable. Run MSBuild.exe .\\MeshAgent.Build.proj (or python .\\tools\\generate_branding_assets.py --repo-root . --config .\\branding_config.local.json) to refresh generated assets."
}
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
$testArgs['SvchostOnly'] = $true

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

Write-Host "[RuntimeValidation] Completed successfully. Report: $ReportPath" -ForegroundColor Green
