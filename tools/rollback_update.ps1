#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourcePath,

    [string]$ServiceName,
    [string]$InstallPath,
    [switch]$NoStart,
    [switch]$SkipBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-BrandingValue {
    param([string]$PropertyName)

    $configPath = Join-Path $PSScriptRoot "..\branding_config.json"
    if (-not (Test-Path $configPath)) { return $null }

    try {
        $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json -Depth 10
        switch ($PropertyName) {
            'serviceName' { return $config.branding.serviceName }
            default { return $null }
        }
    } catch {
        Write-Verbose ("Unable to parse branding_config.json: {0}" -f $_.Exception.Message)
        return $null
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Please run rollback_update.ps1 from an elevated PowerShell session (Run as administrator)."
}

if (-not (Test-Path $SourcePath)) {
    throw "SourcePath '$SourcePath' does not exist."
}

$stagingPath = $null
$cleanupStaging = $false
$sourceItem = Get-Item -LiteralPath $SourcePath

if ($sourceItem.PSIsContainer) {
    $stagingPath = $sourceItem.FullName
} else {
    if ($sourceItem.Extension -ne '.zip') {
        throw "SourcePath must be a directory or a .zip archive containing the previous build."
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stagingPath = Join-Path ([System.IO.Path]::GetTempPath()) ("meshagent-rollback-" + [System.IO.Path]::GetRandomFileName())
    Write-Verbose ("Extracting archive to staging folder {0}" -f $stagingPath)
    [System.IO.Compression.ZipFile]::ExtractToDirectory($sourceItem.FullName, $stagingPath)
    $cleanupStaging = $true
}

if (-not $ServiceName) {
    $ServiceName = Resolve-BrandingValue -PropertyName 'serviceName'
}
if (-not $ServiceName) {
    throw "ServiceName was not provided and could not be inferred from branding_config.json."
}

$serviceInstance = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if (-not $serviceInstance) {
    throw "Service '$ServiceName' was not found on this system."
}

if (-not $InstallPath) {
    if ($serviceInstance.PathName) {
        $exePath = $serviceInstance.PathName.Trim('"')
        if (Test-Path $exePath) {
            $InstallPath = Split-Path -Path $exePath -Parent
        }
    }
}
if (-not $InstallPath -or -not (Test-Path $InstallPath)) {
    throw "InstallPath could not be determined automatically. Please specify -InstallPath."
}

Write-Host "[info] Service name : $ServiceName" -ForegroundColor Cyan
Write-Host "[info] Install path : $InstallPath" -ForegroundColor Cyan
Write-Host "[info] Source path  : $stagingPath" -ForegroundColor Cyan

$primaryBinary = Get-ChildItem -Path $stagingPath -Filter 'MeshService64.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $primaryBinary) {
    Write-Warning "MeshService64.exe was not found in the source directory. Continuing, but ensure required binaries are present."
}

if ($serviceInstance.State -ne 'Stopped') {
    Write-Host "[stop] Stopping service..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess("Service:$ServiceName", "Stop-Service")) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $timeout = [TimeSpan]::FromSeconds(30)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed -lt $timeout) {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($null -eq $svc -or $svc.Status -eq 'Stopped') { break }
            Start-Sleep -Seconds 1
        }
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = "$InstallPath.current.$timestamp"

if (-not $SkipBackup) {
    Write-Host "[backup] Copying current installation to $backupPath" -ForegroundColor Gray
    if ($PSCmdlet.ShouldProcess($InstallPath, "Backup install")) {
        Copy-Item -LiteralPath $InstallPath -Destination $backupPath -Recurse -Force
    }
}

Write-Host "[clean] Removing current binaries..." -ForegroundColor Yellow
if ($PSCmdlet.ShouldProcess($InstallPath, "Remove old contents")) {
    Get-ChildItem -LiteralPath $InstallPath -Force | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Recurse -Force
    }
}

Write-Host "[restore] Copying files from source..." -ForegroundColor Green
if ($PSCmdlet.ShouldProcess($stagingPath, "Copy to install path")) {
    Get-ChildItem -Path $stagingPath -Force | ForEach-Object {
        $destination = Join-Path $InstallPath $_.Name
        if ($_.PSIsContainer) {
            Copy-Item -Path $_.FullName -Destination $destination -Recurse -Force
        }
        else {
            Copy-Item -Path $_.FullName -Destination $destination -Force
        }
    }
}

if (-not $NoStart) {
    Write-Host "[start] Starting service..." -ForegroundColor Green
    if ($PSCmdlet.ShouldProcess("Service:$ServiceName", "Start-Service")) {
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $svcState = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
        if ($svcState -ne 'Running') {
            Write-Warning "Service '$ServiceName' failed to start. Check logs and consider restoring from $backupPath."
        }
    }
}

Write-Host "[done] Rollback complete." -ForegroundColor Green
if (-not $SkipBackup) {
    Write-Host ("[note] Previous installation preserved at: {0}" -f $backupPath) -ForegroundColor Yellow
}

if ($cleanupStaging -and (Test-Path $stagingPath)) {
    Remove-Item -LiteralPath $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
}
