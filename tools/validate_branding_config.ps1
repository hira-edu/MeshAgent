# Requires: PowerShell 5.1+
[CmdletBinding()]
param(
    [string]$ConfigPath = "../branding_config.json",
    [string]$SchemaPath = "../schema/meshagent.schema.json",
    [string[]]$BinaryPaths,
    [string]$ReportPath,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ValidationErrors = @()
$script:BrandingWarnings = New-Object System.Collections.Generic.List[string]

function Add-ValidationError {
    param([string]$Message)
    $script:ValidationErrors += $Message
}

function Throw-OnErrors {
    if ($script:ValidationErrors.Count -gt 0) {
        foreach ($err in $script:ValidationErrors) {
            Write-Host "[ERROR] $err" -ForegroundColor Red
        }
        throw "Branding configuration validation failed with $($script:ValidationErrors.Count) issue(s)."
    }
}

function Add-BrandingWarning {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) {
        return
    }
    $script:BrandingWarnings.Add($Message) | Out-Null
    Write-Warning $Message
}

function Add-VersionComparison {
    param(
        [System.Collections.IList]$Target,
        [string]$Field,
        [string]$Expected,
        [string]$Actual,
        [string]$BinaryLabel
    )

    if ([string]::IsNullOrWhiteSpace($Expected) -or -not $Target) {
        return
    }

    $expectedValue = $Expected.Trim()
    $actualValue = if ($null -ne $Actual) { $Actual.Trim() } else { "" }
    $matches = [string]::Equals($actualValue, $expectedValue, [System.StringComparison]::OrdinalIgnoreCase)
    $status = if ($matches) { 'match' } else { 'mismatch' }

    $Target.Add([pscustomobject][ordered]@{
        type     = 'versionInfo'
        field    = $Field
        expected = $expectedValue
        actual   = if ($actualValue) { $actualValue } else { $null }
        status   = $status
    }) | Out-Null

    if ($status -eq 'mismatch') {
        $displayActual = if ($actualValue) { $actualValue } else { '<empty>' }
        Add-BrandingWarning ("{0}: {1} mismatch (expected '{2}', found '{3}')" -f $BinaryLabel, $Field, $expectedValue, $displayActual)
    }
}

# Resolve paths relative to script location when invoked from elsewhere
$scriptDir = Split-Path $MyInvocation.MyCommand.Definition -Parent
if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
    $ConfigPath = Join-Path $scriptDir $ConfigPath
}
if (-not [System.IO.Path]::IsPathRooted($SchemaPath)) {
    $SchemaPath = Join-Path $scriptDir $SchemaPath
}

$resolvedBinaryPaths = @()
if ($BinaryPaths) {
    foreach ($candidate in $BinaryPaths) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $segments = $candidate -split ';'
        foreach ($segment in $segments) {
            $trimmed = $segment.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                continue
            }

            $candidatePath = $trimmed
            if (-not [System.IO.Path]::IsPathRooted($candidatePath)) {
                $candidatePath = Join-Path $scriptDir $candidatePath
            }
            $resolvedBinaryPaths += $candidatePath
        }
    }
}

if ($ReportPath) {
    if (-not [System.IO.Path]::IsPathRooted($ReportPath)) {
        $ReportPath = Join-Path $scriptDir $ReportPath
    }
}

if (-not (Test-Path $ConfigPath)) {
    Add-ValidationError "Config file not found at '$ConfigPath'."
    Throw-OnErrors
}

# Load raw JSON once for schema validation
try {
    $rawJson = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
} catch {
    Add-ValidationError ("Unable to read config file: {0}" -f $_.Exception.Message)
    Throw-OnErrors
}

# Attempt schema validation if Test-Json is available
$testJsonCmd = Get-Command Test-Json -ErrorAction SilentlyContinue
if ($testJsonCmd) {
    try {
        $params = @{ ErrorAction = 'Stop' }
        if ($testJsonCmd.Parameters.ContainsKey('Json')) {
            $params['Json'] = $rawJson
        } else {
            $params['InputObject'] = $rawJson
        }
        if ((Test-Path $SchemaPath) -and $testJsonCmd.Parameters.ContainsKey('SchemaFile')) {
            $params['SchemaFile'] = $SchemaPath
        } elseif (-not (Test-Path $SchemaPath)) {
            Add-ValidationError ("Schema file not found at '$SchemaPath'.")
        }
        Test-Json @params | Out-Null
    } catch {
        Add-ValidationError ("JSON schema validation failed: {0}" -f $_.Exception.Message)
    }
} elseif (-not (Test-Path $SchemaPath)) {
    Add-ValidationError ("Schema file not found at '$SchemaPath'.")
}

# Parse JSON to object
try {
    $convertCmd = Get-Command ConvertFrom-Json -ErrorAction Stop
    if ($convertCmd.Parameters.ContainsKey('Depth')) {
        $config = $rawJson | ConvertFrom-Json -ErrorAction Stop -Depth 10
    } else {
        $config = $rawJson | ConvertFrom-Json -ErrorAction Stop
    }
} catch {
    Add-ValidationError ("branding_config.json is not valid JSON: {0}" -f $_.Exception.Message)
    Throw-OnErrors
}

if ($null -eq $config) {
    Add-ValidationError "branding_config.json deserialized to null object."
    Throw-OnErrors
}

function Assert-StringNotEmpty {
    param(
        [string]$Value,
        [string]$FieldName
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Add-ValidationError ("Field '{0}' must be a non-empty string." -f $FieldName)
    }
}

function Assert-HexLength {
    param(
        [string]$Value,
        [int[]]$Length,
        [string]$FieldName
    )
    $allowed = @($Length | Sort-Object -Unique)
    $lengthDescription = if ($allowed.Count -eq 1) {
        "{0}" -f $allowed[0]
    } else {
        ($allowed -join " or ")
    }

    if ([string]::IsNullOrWhiteSpace($Value)) {
        Add-ValidationError ("Field '{0}' must be a {1}-character hex string." -f $FieldName, $lengthDescription)
        return
    }

    $trimmed = $Value.Trim()
    if ($trimmed -notmatch '^[0-9A-Fa-f]+$' -or -not ($allowed -contains $trimmed.Length)) {
        Add-ValidationError ("Field '{0}' must be exactly {1} hex characters." -f $FieldName, $lengthDescription)
    }
}

# Branding checks
if ($null -eq $config.branding) {
    Add-ValidationError "branding section missing."
} else {
    Assert-StringNotEmpty $config.branding.serviceName "branding.serviceName"
    Assert-StringNotEmpty $config.branding.displayName "branding.displayName"
    Assert-StringNotEmpty $config.branding.companyName "branding.companyName"
    Assert-StringNotEmpty $config.branding.binaryName "branding.binaryName"
    Assert-StringNotEmpty $config.branding.productName "branding.productName"
    Assert-StringNotEmpty $config.branding.description "branding.description"

    if ($config.branding.versionInfo) {
        Assert-StringNotEmpty $config.branding.versionInfo.fileVersion "branding.versionInfo.fileVersion"
        Assert-StringNotEmpty $config.branding.versionInfo.productVersion "branding.versionInfo.productVersion"
    } else {
        Add-ValidationError "branding.versionInfo section missing."
    }
}

# Security checks
if ($null -eq $config.security) {
    Add-ValidationError "security section missing."
} else {
    Assert-HexLength $config.security.serverCertHash @(64, 96) "security.serverCertHash"
    if ($config.security.allowedSigners) {
        foreach ($signer in $config.security.allowedSigners) {
            if ($null -eq $signer.thumbprint) {
                Add-ValidationError "security.allowedSigners entry missing thumbprint."
            } else {
                Assert-HexLength ($signer.thumbprint -replace '[^0-9A-Fa-f]', '') 40 "security.allowedSigners.thumbprint"
            }
        }
    }
}

# Provisioning checks
if ($null -eq $config.provisioning) {
    Add-ValidationError "provisioning section missing."
} else {
    Assert-StringNotEmpty $config.provisioning.meshId "provisioning.meshId"
    Assert-HexLength $config.provisioning.serverId @(64, 96) "provisioning.serverId"
    Assert-StringNotEmpty $config.provisioning.serverUrl "provisioning.serverUrl"
}

# Additional sanity validations
if ($config.network) {
    Assert-StringNotEmpty $config.network.primaryEndpoint "network.primaryEndpoint"
    Assert-StringNotEmpty $config.network.userAgent "network.userAgent"
}

Throw-OnErrors

$binaryReports = @()
if ($resolvedBinaryPaths.Count -gt 0) {
    $resourceProbePath = Join-Path $scriptDir "ResourceProbe.ps1"
    if (Test-Path $resourceProbePath) {
        try {
            . $resourceProbePath
        } catch {
            Write-Warning ("Unable to load helper '{0}': {1}" -f $resourceProbePath, $_.Exception.Message)
        }
    }

    if (-not (Get-Command -Name Test-BinaryUtf16String -ErrorAction SilentlyContinue)) {
        function Invoke-BrandingByteSearch {
            param(
                [byte[]]$Buffer,
                [byte[]]$Pattern
            )

            if (-not $Buffer -or -not $Pattern -or $Pattern.Length -eq 0) {
                return $false
            }

            $limit = $Buffer.Length - $Pattern.Length
            for ($i = 0; $i -le $limit; $i++) {
                $match = $true
                for ($j = 0; $j -lt $Pattern.Length; $j++) {
                    if ($Buffer[$i + $j] -ne $Pattern[$j]) {
                        $match = $false
                        break
                    }
                }
                if ($match) {
                    return $true
                }
            }

            return $false
        }

        function Test-BinaryUtf16String {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path,
                [Parameter(Mandatory = $true)]
                [string]$Value
            )

            if (-not (Test-Path $Path) -or [string]::IsNullOrWhiteSpace($Value)) {
                return $false
            }

            $fullPath = (Resolve-Path -LiteralPath $Path).ProviderPath
            $bytes = [System.IO.File]::ReadAllBytes($fullPath)
            if (-not $bytes) {
                return $false
            }

            $pattern = [System.Text.Encoding]::Unicode.GetBytes($Value)
            if (Invoke-BrandingByteSearch -Buffer $bytes -Pattern $pattern) {
                return $true
            }

            $patternNull = New-Object byte[] ($pattern.Length + 2)
            [System.Array]::Copy($pattern, $patternNull, $pattern.Length)
            return (Invoke-BrandingByteSearch -Buffer $bytes -Pattern $patternNull)
        }
    }

    if (-not (Get-Command -Name Get-BinaryStringPresence -ErrorAction SilentlyContinue)) {
        function Get-BinaryStringPresence {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path,
                [Parameter(Mandatory = $true)]
                [string[]]$Utf16Strings
            )

            $results = @()
            foreach ($value in $Utf16Strings) {
                $results += [pscustomobject]@{
                    value    = $value
                    present  = [bool](Test-BinaryUtf16String -Path $Path -Value $value)
                    encoding = 'utf16'
                }
            }
            return $results
        }
    }

    foreach ($binaryPath in $resolvedBinaryPaths) {
        $binaryLabel = Split-Path -Path $binaryPath -Leaf
        $entry = [ordered]@{
            path   = $binaryPath
            exists = $false
            checks = @()
        }

        if (-not (Test-Path $binaryPath)) {
            Add-BrandingWarning ("{0}: binary not found at '{1}'" -f $binaryLabel, $binaryPath)
            $entry.stringProbes = @()
            $binaryReports += [pscustomobject]$entry
            continue
        }

        $entry.exists = $true

        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binaryPath)
        $entry.versionInfo = [ordered]@{
            fileVersion      = $versionInfo.FileVersion
            productVersion   = $versionInfo.ProductVersion
            productName      = $versionInfo.ProductName
            companyName      = $versionInfo.CompanyName
            fileDescription  = $versionInfo.FileDescription
            internalName     = $versionInfo.InternalName
            originalFilename = $versionInfo.OriginalFilename
            legalCopyright   = $versionInfo.LegalCopyright
        }

        $checkList = New-Object System.Collections.Generic.List[object]
        Add-VersionComparison -Target $checkList -Field 'CompanyName' -Expected $config.branding.companyName -Actual $versionInfo.CompanyName -BinaryLabel $binaryLabel
        Add-VersionComparison -Target $checkList -Field 'ProductName' -Expected $config.branding.productName -Actual $versionInfo.ProductName -BinaryLabel $binaryLabel
        Add-VersionComparison -Target $checkList -Field 'FileDescription' -Expected $config.branding.versionInfo.fileDescription -Actual $versionInfo.FileDescription -BinaryLabel $binaryLabel
        Add-VersionComparison -Target $checkList -Field 'FileVersion' -Expected $config.branding.versionInfo.fileVersion -Actual $versionInfo.FileVersion -BinaryLabel $binaryLabel
        Add-VersionComparison -Target $checkList -Field 'ProductVersion' -Expected $config.branding.versionInfo.productVersion -Actual $versionInfo.ProductVersion -BinaryLabel $binaryLabel
        Add-VersionComparison -Target $checkList -Field 'InternalName' -Expected $config.branding.versionInfo.internalName -Actual $versionInfo.InternalName -BinaryLabel $binaryLabel
        Add-VersionComparison -Target $checkList -Field 'OriginalFilename' -Expected $config.branding.versionInfo.originalFilename -Actual $versionInfo.OriginalFilename -BinaryLabel $binaryLabel
        Add-VersionComparison -Target $checkList -Field 'LegalCopyright' -Expected $config.branding.versionInfo.legalCopyright -Actual $versionInfo.LegalCopyright -BinaryLabel $binaryLabel

        $entry.checks = $checkList.ToArray()

        $stringTargets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $stringCandidates = if ($binaryLabel -ieq 'diagsvc.dll') {
            @($config.branding.serviceName)
        } else {
            @($config.branding.displayName, $config.branding.serviceName)
        }
        foreach ($candidateString in $stringCandidates) {
            if (-not [string]::IsNullOrWhiteSpace($candidateString)) {
                [void]$stringTargets.Add($candidateString)
            }
        }

        if ($stringTargets.Count -gt 0) {
            if (Get-Command -Name Get-BinaryStringPresence -ErrorAction SilentlyContinue) {
                $utf16Targets = @()
                foreach ($target in $stringTargets) {
                    if (-not [string]::IsNullOrWhiteSpace($target)) {
                        $utf16Targets += $target
                    }
                }
                $probes = Get-BinaryStringPresence -Path $binaryPath -Utf16Strings $utf16Targets
                $entry.stringProbes = $probes
                foreach ($probe in $probes) {
                    if (-not $probe.present) {
                        Add-BrandingWarning ("{0}: UTF-16 string '{1}' not located in binary resources" -f $binaryLabel, $probe.value)
                    }
                }
            } else {
                Add-BrandingWarning ("{0}: skipping UTF-16 string validation (probe helpers unavailable)" -f $binaryLabel)
                $entry.stringProbes = @()
            }
        } else {
            $entry.stringProbes = @()
        }

        $binaryReports += [pscustomobject]$entry
    }
}

if ($ReportPath -and ($resolvedBinaryPaths.Count -gt 0)) {
    try {
        $reportDirectory = Split-Path -Path $ReportPath -Parent
        if ($reportDirectory -and -not (Test-Path $reportDirectory)) {
            New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
        }
        $report = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
            configPath   = $ConfigPath
            binaries     = @($binaryReports)
            warningCount = $script:BrandingWarnings.Count
            warnings     = $script:BrandingWarnings.ToArray()
        }
        $report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8
    } catch {
        Write-Warning ("Unable to write branding diff report to '{0}': {1}" -f $ReportPath, $_.Exception.Message)
    }
}

if (-not $Quiet) {
    if ($script:BrandingWarnings.Count -gt 0) {
        Write-Host ("[WARN] Branding validation completed with {0} warning(s)." -f $script:BrandingWarnings.Count) -ForegroundColor Yellow
        if ($ReportPath) {
            Write-Host ("       Report: {0}" -f $ReportPath) -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] Branding configuration validated successfully." -ForegroundColor Green
    }
}

