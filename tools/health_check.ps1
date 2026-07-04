#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ServiceName,
    [string]$InstallPath,
    [string]$ReportPath,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
$brandingHelper = Join-Path $repoRoot "tools\BrandingConfig.ps1"
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Name,
        [ValidateSet('Pass','Fail','Warning')]
        [string]$Status,
        [string]$Message
    )

    $results.Add([pscustomobject]@{
        Name = $Name
        Status = $Status
        Message = $Message
    })

    if ($Quiet) { return }

    switch ($Status) {
        'Pass'    { $label = '[PASS]';    $color = 'Green' }
        'Warning' { $label = '[WARN]';    $color = 'Yellow' }
        'Fail'    { $label = '[FAIL]';    $color = 'Red' }
    }
    Write-Host ("{0} {1} - {2}" -f $label, $Name, $Message) -ForegroundColor $color
}

function Resolve-Branding {
    try {
        $info = Get-BrandingConfig -RepoRoot $repoRoot -Quiet
        return $info.Config
    } catch {
        Add-Result -Name "Branding configuration" -Status "Warning" -Message ("Unable to load branding configuration: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Resolve-ServiceDllPath {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $parametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name\Parameters"
    try {
        $parameters = Get-ItemProperty -LiteralPath $parametersPath -Name ServiceDll -ErrorAction Stop
    } catch {
        return $null
    }
    if (-not $parameters.ServiceDll) { return $null }
    return [Environment]::ExpandEnvironmentVariables([string]$parameters.ServiceDll)
}

function Resolve-ServiceExecutablePath {
    param([string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $candidate = $PathName.Trim()
    if ($candidate.StartsWith('"')) {
        $endQuote = $candidate.IndexOf('"', 1)
        if ($endQuote -gt 1) {
            $candidate = $candidate.Substring(1, $endQuote - 1)
        }
    } else {
        $exeIndex = $candidate.ToLowerInvariant().IndexOf('.exe')
        if ($exeIndex -ge 0) {
            $candidate = $candidate.Substring(0, $exeIndex + 4)
        }
    }
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
        return $candidate
    }
    return $null
}

$branding = Resolve-Branding

if (-not $ServiceName -and $branding) {
    $ServiceName = $branding.branding.serviceName
}
if (-not $ServiceName) {
    Add-Result -Name "Service Discovery" -Status "Fail" -Message "ServiceName not provided and branding configuration missing 'branding.serviceName'."
}

$service = $null
if ($ServiceName) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $service) {
        Add-Result -Name "Service Presence" -Status "Fail" -Message ("Service '{0}' not found." -f $ServiceName)
    } else {
        Add-Result -Name "Service Presence" -Status "Pass" -Message ("Service '{0}' is registered." -f $ServiceName)
        if ($service.State -eq 'Running') {
            Add-Result -Name "Service Status" -Status "Pass" -Message ("Current state: {0}" -f $service.State)
        } else {
            Add-Result -Name "Service Status" -Status "Warning" -Message ("Service is {0}" -f $service.State)
        }
    }
}

if (-not $InstallPath -and $service) {
    $serviceDllPath = Resolve-ServiceDllPath -Name $ServiceName
    if ($serviceDllPath -and (Test-Path -LiteralPath $serviceDllPath)) {
        $InstallPath = Split-Path -Path $serviceDllPath -Parent
    } elseif ($service.PathName) {
        $binaryCandidate = Resolve-ServiceExecutablePath -PathName $service.PathName
        if ($binaryCandidate) {
            $InstallPath = Split-Path -Path $binaryCandidate -Parent
        }
    }
}

if (-not $InstallPath) {
    Add-Result -Name "Install Path" -Status "Warning" -Message "Install path could not be inferred. Provide -InstallPath for deeper checks."
}
elseif (-not (Test-Path $InstallPath)) {
    Add-Result -Name "Install Path" -Status "Fail" -Message ("Install directory '{0}' not found." -f $InstallPath)
} else {
    Add-Result -Name "Install Path" -Status "Pass" -Message ("Install directory: {0}" -f $InstallPath)
}

$binaryPath = $null
if ($InstallPath) {
    $binaryNames = New-Object System.Collections.Generic.List[string]
    if ($branding -and $branding.branding.binaryName) {
        $binaryNames.Add([string]$branding.branding.binaryName)
    }
    $binaryNames.Add("MeshService64.exe")
    $binaryNames.Add("MeshService.exe")

    foreach ($binaryName in ($binaryNames | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($binaryName)) { continue }
        $candidate = Join-Path $InstallPath $binaryName
        if (Test-Path $candidate) {
            $binaryPath = $candidate
            break
        }
    }
} elseif ($service -and $service.PathName) {
    $candidate = $service.PathName.Trim('"')
    if (Test-Path $candidate) {
        $binaryPath = $candidate
    }
}

if (-not $binaryPath -or -not (Test-Path $binaryPath)) {
    Add-Result -Name "Primary Binary" -Status "Fail" -Message "Service binary not located. Provide -InstallPath if non-standard."
} else {
    Add-Result -Name "Primary Binary" -Status "Pass" -Message ("Binary located at {0}" -f $binaryPath)

    try {
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binaryPath)
        if ($branding -and $branding.branding.versionInfo) {
            $expectedFileVersion = $branding.branding.versionInfo.fileVersion
            if ($expectedFileVersion) {
                if ($versionInfo.FileVersion -eq $expectedFileVersion) {
                    Add-Result -Name "File Version" -Status "Pass" -Message ("{0}" -f $versionInfo.FileVersion)
                } else {
                    Add-Result -Name "File Version" -Status "Fail" -Message ("Expected {0}, found {1}" -f $expectedFileVersion, $versionInfo.FileVersion)
                }
            }

            $expectedProductVersion = $branding.branding.versionInfo.productVersion
            if ($expectedProductVersion) {
                if ($versionInfo.ProductVersion -eq $expectedProductVersion) {
                    Add-Result -Name "Product Version" -Status "Pass" -Message ("{0}" -f $versionInfo.ProductVersion)
                } else {
                    Add-Result -Name "Product Version" -Status "Fail" -Message ("Expected {0}, found {1}" -f $expectedProductVersion, $versionInfo.ProductVersion)
                }
            }
        }
    } catch {
        Add-Result -Name "File Version" -Status "Warning" -Message ("Unable to read version information: {0}" -f $_.Exception.Message)
    }

    $signerScript = Join-Path $PSScriptRoot "SignerAllowlist.ps1"
    if (Test-Path $signerScript) {
        . $signerScript
        try {
            $allowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $repoRoot
            $enforcementEnabled = [bool]$script:MeshAgentEnforceSigning
            $thumbprint = Get-MeshAgentSignerThumbprint -Path $binaryPath
            if ($thumbprint) {
                try {
                    if ($enforcementEnabled) {
                        Assert-MeshAgentThumbprintAllowed -Thumbprint $thumbprint -AllowedThumbprints $allowedThumbprints
                    }
                    Add-Result -Name "Digital Signature" -Status "Pass" -Message ("Signed by {0}" -f $thumbprint)
                } catch {
                    Add-Result -Name "Digital Signature" -Status "Fail" -Message ("Signer {0} not allowlisted." -f $thumbprint)
                }
            } else {
                if ($enforcementEnabled) {
                    $status = 'Fail'
                    $message = "Binary is unsigned while signing enforcement is enabled."
                } else {
                    $status = 'Warning'
                    $message = "Binary is unsigned (signing enforcement disabled)."
                }
                Add-Result -Name "Digital Signature" -Status $status -Message $message
            }
        } catch {
            Add-Result -Name "Digital Signature" -Status "Fail" -Message ("Signature validation failed: {0}" -f $_.Exception.Message)
        }
    } else {
        Add-Result -Name "Digital Signature" -Status "Warning" -Message "SignerAllowlist.ps1 not found; skipping signature validation."
    }
}

if ($InstallPath) {
    $logFiles = Get-ChildItem -Path $InstallPath -Filter '*.log' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($logFiles) {
        $ageMinutes = [int][Math]::Round((New-TimeSpan -Start $logFiles.LastWriteTime -End (Get-Date)).TotalMinutes)
        Add-Result -Name "Recent Log Activity" -Status "Pass" -Message ("Latest log '{0}' updated {1} minute(s) ago." -f $logFiles.Name, $ageMinutes)
    } else {
        Add-Result -Name "Recent Log Activity" -Status "Warning" -Message "No log files discovered in the install directory."
    }
}
$passed  = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
$failed  = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
$warning = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
$total   = $results.Count

if (-not $Quiet) {
    Write-Host ""
    Write-Host "Summary: Total=$total, Passed=$passed, Warnings=$warning, Failed=$failed" -ForegroundColor Cyan
}

if ($ReportPath) {
    try {
        $reportDirectory = Split-Path -Path $ReportPath -Parent
        if ($reportDirectory -and -not (Test-Path $reportDirectory)) {
            New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
        }
        $report = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
            serviceName = $ServiceName
            installPath = $InstallPath
            summary = [ordered]@{
                total = $total
                passed = $passed
                warnings = $warning
                failed = $failed
            }
            checks = $results
        }
        $report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8
    } catch {
        Write-Warning ("Unable to write report to {0}: {1}" -f $ReportPath, $_.Exception.Message)
    }
}

if ($failed -gt 0) {
    exit 1
}
elseif ($warning -gt 0) {
    exit 2
}
else {
    exit 0
}
