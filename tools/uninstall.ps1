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
$repoRoot = Split-Path $PSScriptRoot -Parent
$brandingHelper = Join-Path $repoRoot "tools\BrandingConfig.ps1"
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper

if (-not $PSBoundParameters.ContainsKey('PurgeData')) {
    # Default to full removal unless explicitly overridden.
    $PurgeData = $true
}

function Test-IsAdministrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-BrandingValue {
    param(
        [string]$PropertyName
    )

    try {
        $config = (Get-BrandingConfig -RepoRoot $repoRoot -Quiet).Config
        switch ($PropertyName) {
            'serviceName' { return $config.branding.serviceName }
            default { return $null }
        }
    } catch {
        Write-Verbose ("Unable to load branding configuration: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Remove-RunKeyEntries {
    param([Parameter(Mandatory = $true)][string]$Name)

    $runPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($runPath in $runPaths) {
        try {
            if (Get-ItemProperty -Path $runPath -Name $Name -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $runPath -Name $Name -Force -ErrorAction SilentlyContinue
                Write-Host "[remove] Run key entry $runPath :: $Name" -ForegroundColor Yellow
            }
        } catch {
            Write-Verbose ("Failed removing run key {0}\\{1}: {2}" -f $runPath, $Name, $_.Exception.Message)
        }
    }
}

function Remove-ScheduledTaskIfExists {
    param([Parameter(Mandatory = $true)][string]$TaskName)

    $qualified = if ($TaskName.StartsWith("\")) { $TaskName } else { "\" + $TaskName }
    try {
        $null = schtasks.exe /Query /TN $qualified 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[remove] Scheduled task $qualified" -ForegroundColor Yellow
            schtasks.exe /Delete /TN $qualified /F | Out-Null
        }
    } catch {
        Write-Verbose ("Unable to delete scheduled task {0}: {1}" -f $qualified, $_.Exception.Message)
    }
}

function Remove-FirewallRules {
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $ruleNames = @(
        "Windows $ServiceName - Outbound",
        "Windows $ServiceName - Inbound"
    )

    foreach ($rule in $ruleNames) {
        try {
            netsh advfirewall firewall delete rule name="$rule" | Out-Null
        } catch {
            Write-Verbose ("Failed deleting firewall rule {0}: {1}" -f $rule, $_.Exception.Message)
        }
    }
}

function Remove-SvchostRegistration {
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $svchostKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
    try {
        $netsvcs = (Get-ItemProperty -LiteralPath $svchostKey -Name netsvcs -ErrorAction Stop).netsvcs
        if ($netsvcs) {
            $updated = $netsvcs | Where-Object { $_ -and $_.Trim() -and ($_ -ne $ServiceName) }
            if ($updated.Count -ne $netsvcs.Count) {
                Set-ItemProperty -LiteralPath $svchostKey -Name netsvcs -Value ([string[]]$updated) -ErrorAction Stop
                Write-Host "[remove] Svchost netsvcs registration cleaned" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Verbose ("Unable to prune svchost registration: {0}" -f $_.Exception.Message)
    }

    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (Test-Path -LiteralPath $svcRegPath) {
        try {
            Remove-Item -LiteralPath $svcRegPath -Recurse -Force -ErrorAction Stop
            Write-Host "[remove] Registry service key $svcRegPath" -ForegroundColor Yellow
        } catch {
            Write-Verbose ("Failed removing registry service key {0}: {1}" -f $svcRegPath, $_.Exception.Message)
        }
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Please re-run uninstall.ps1 from an elevated PowerShell session (Run as administrator)."
}

if (-not $ServiceName) {
    $ServiceName = Resolve-BrandingValue -PropertyName 'serviceName'
}
if (-not $ServiceName) {
    throw "ServiceName was not provided and could not be inferred from branding configuration."
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
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if (-not $programData) {
        $programData = Join-Path $env:SystemRoot 'ProgramData'
    }
    if ($programData) {
        $fallbackPath = Join-Path $programData 'DiagnosticHost'
        if (Test-Path $fallbackPath) {
            $InstallPath = $fallbackPath
        }
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

Remove-RunKeyEntries -Name $ServiceName
Remove-ScheduledTaskIfExists -TaskName "$ServiceName-Autorun"
Remove-ScheduledTaskIfExists -TaskName "$ServiceName-RestartOnStop"
Remove-FirewallRules -ServiceName $ServiceName
Remove-SvchostRegistration -ServiceName $ServiceName

Write-Host "[done] Uninstall complete." -ForegroundColor Green

