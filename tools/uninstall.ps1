#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ServiceName,
    [string]$InstallPath,
    [string]$ArchivePath,
    [switch]$PurgeData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-BrandingValue {
    param(
        [string]$PropertyName
    )

    $configPath = Join-Path $PSScriptRoot "..\branding_config.json"
    if (-not (Test-Path $configPath)) {
        return $null
    }

    try {
        $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json -Depth 10
        switch ($PropertyName) {
            'serviceName' { return $config.branding.serviceName }
            default { return $null }
        }
    } catch {
        Write-Verbose ("Unable to read branding_config.json: {0}" -f $_.Exception.Message)
        return $null
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Please re-run uninstall.ps1 from an elevated PowerShell session (Run as administrator)."
}

if (-not $ServiceName) {
    $ServiceName = Resolve-BrandingValue -PropertyName 'serviceName'
}
if (-not $ServiceName) {
    throw "ServiceName was not provided and could not be inferred from branding_config.json."
}

Write-Host "[info] Target service : $ServiceName" -ForegroundColor Cyan

$serviceInstance = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if (-not $serviceInstance) {
    Write-Warning "Service '$ServiceName' was not found. Continuing with best-effort cleanup."
}
else {
    if (-not $InstallPath) {
        if ($serviceInstance.PathName) {
            $path = $serviceInstance.PathName.Trim('"')
            if (Test-Path $path) {
                $InstallPath = Split-Path -Path $path -Parent
            }
        }
    }

    if ($serviceInstance.State -ne 'Stopped') {
        Write-Host "[stop] Stopping service..." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess("Service:$ServiceName", "Stop-Service")) {
            Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
            $timeout = [TimeSpan]::FromSeconds(30)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($sw.Elapsed -lt $timeout) {
                $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($null -eq $svc -or $svc.Status -eq 'Stopped') {
                    break
                }
                Start-Sleep -Seconds 1
            }
        }
    }

    Write-Host "[remove] Removing service registration..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess("Service:$ServiceName", "sc.exe delete")) {
        & sc.exe delete "$ServiceName" | Out-Null
    }
}

if (-not $InstallPath -and $serviceInstance -and $serviceInstance.PathName) {
    $binaryPath = $serviceInstance.PathName.Trim('"')
    if (Test-Path $binaryPath) {
        $InstallPath = Split-Path -Path $binaryPath -Parent
    }
}

if (-not $InstallPath) {
    Write-Verbose "InstallPath was not provided or discovered. Skipping directory cleanup."
}
elseif (-not (Test-Path $InstallPath)) {
    Write-Verbose ("Install path '{0}' does not exist. Nothing to clean." -f $InstallPath)
}
else {
    Write-Host "[info] Install path    : $InstallPath" -ForegroundColor Cyan
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    if ($ArchivePath) {
        $resolvedArchive = Resolve-Path -Path $ArchivePath -ErrorAction SilentlyContinue
        if (-not $resolvedArchive) {
            if ($PSCmdlet.ShouldProcess($ArchivePath, "Create archive directory")) {
                New-Item -ItemType Directory -Path $ArchivePath -Force | Out-Null
                $resolvedArchive = Resolve-Path -Path $ArchivePath
            }
        }

        if ($resolvedArchive) {
            $archiveFolder = Join-Path $resolvedArchive.Path ("{0}_{1}" -f (Split-Path $InstallPath -Leaf), $timestamp)
            Write-Host "[archive] Copying install directory to $archiveFolder" -ForegroundColor Gray
            if ($PSCmdlet.ShouldProcess($InstallPath, "Copy to archive")) {
                Copy-Item -LiteralPath $InstallPath -Destination $archiveFolder -Recurse -Force
            }
        }
    }

    if ($PurgeData) {
        Write-Host "[purge] Removing install directory..." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess($InstallPath, "Remove-Item -Recurse")) {
            Remove-Item -LiteralPath $InstallPath -Recurse -Force
        }
    }
    else {
        $quarantinePath = "{0}_removed_{1}" -f $InstallPath, $timestamp
        Write-Host "[rename] Moving install directory to $quarantinePath" -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess($InstallPath, "Rename-Item")) {
            Move-Item -LiteralPath $InstallPath -Destination $quarantinePath -Force
        }
    }
}

Write-Host "[done] Uninstall complete." -ForegroundColor Green

