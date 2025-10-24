#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive verification of MeshAgent binary branding and configuration

.DESCRIPTION
    This script validates that built binaries correctly contain the branding
    configuration specified in branding_config.local.json (fallback: branding_config.json). It performs multiple checks:
    - Service name embedding
    - Network endpoint validation
    - Version information
    - Digital signature verification
    - Resource metadata validation

.PARAMETER BinaryPath
    Path to the binary file or directory containing binaries to verify

.PARAMETER ConfigPath
    Optional path to a branding configuration JSON file (defaults to branding_config.local.json when present)

.PARAMETER Detailed
    Show detailed verification output

.EXAMPLE
    .\verify_branded_build.ps1 -BinaryPath ..\meshservice\Release

.EXAMPLE
    .\verify_branded_build.ps1 -BinaryPath ..\MeshService64.exe -Detailed

.NOTES
    Author: Generated for MeshAgent branding validation
    Returns: 0 if all checks pass, 1 if any check fails
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [Parameter()]
    [string]$ConfigPath,

    [Parameter()]
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'

# Initialize paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$brandingHelper = Join-Path $projectRoot "tools\BrandingConfig.ps1"
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper
if (-not $ConfigPath) {
    $ConfigPath = Resolve-BrandingConfigPath -RepoRoot $projectRoot
} else {
    $ConfigPath = Resolve-BrandingConfigPath -RepoRoot $projectRoot -ConfigPath $ConfigPath
}

# Load helper scripts if available
$signerAllowlistScript = Join-Path $scriptDir "SignerAllowlist.ps1"
if (Test-Path $signerAllowlistScript) {
    . $signerAllowlistScript
}

# Validation results
$Script:Results = @{
    Passed = @()
    Failed = @()
    Warnings = @()
}

function Write-ValidationResult {
    param(
        [string]$Test,
        [string]$Status,  # Pass, Fail, Warning
        [string]$Message,
        [string]$Details = ""
    )

    $result = @{
        Test = $Test
        Status = $Status
        Message = $Message
        Details = $Details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    switch ($Status) {
        'Pass' {
            $Script:Results.Passed += $result
            Write-Host "[PASS] $Test" -ForegroundColor Green
        }
        'Fail' {
            $Script:Results.Failed += $result
            Write-Host "[FAIL] $Test" -ForegroundColor Red
        }
        'Warning' {
            $Script:Results.Warnings += $result
            Write-Host "[WARN] $Test" -ForegroundColor Yellow
        }
    }

    if ($Message) {
        Write-Host "       $Message" -ForegroundColor Gray
    }
    if ($Details -and $Detailed) {
        Write-Host "       Details: $Details" -ForegroundColor DarkGray
    }
}

function Get-BinaryStrings {
    param([string]$Path)

    # Read binary and extract ASCII strings (minimum 4 characters)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $strings = @()
    $currentString = ""

    foreach ($byte in $bytes) {
        if ($byte -ge 32 -and $byte -le 126) {
            # Printable ASCII character
            $currentString += [char]$byte
        } else {
            if ($currentString.Length -ge 4) {
                $strings += $currentString
            }
            $currentString = ""
        }
    }

    if ($currentString.Length -ge 4) {
        $strings += $currentString
    }

    return $strings
}

function Get-BinaryUnicodeStrings {
    param([string]$Path)

    # Read binary and extract UTF-16 strings
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $strings = @()

    for ($i = 0; $i -lt $bytes.Length - 1; $i += 2) {
        $char = [System.BitConverter]::ToChar($bytes, $i)
        if ($char -ge 32 -and $char -le 126) {
            # Start of potential string
            $str = ""
            $j = $i
            while ($j -lt $bytes.Length - 1) {
                $c = [System.BitConverter]::ToChar($bytes, $j)
                if ($c -ge 32 -and $c -le 126) {
                    $str += $c
                    $j += 2
                } else {
                    break
                }
            }
            if ($str.Length -ge 4) {
                $strings += $str
                $i = $j
            }
        }
    }

    return $strings | Select-Object -Unique
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MeshAgent Binary Branding Validator  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Load configuration
Write-Host "Loading configuration..." -ForegroundColor Yellow

if (-not (Test-Path $ConfigPath)) {
    Write-ValidationResult -Test "Configuration File" -Status "Fail" `
        -Message "Config file not found: $ConfigPath"
    exit 1
}

try {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    Write-ValidationResult -Test "Configuration File" -Status "Pass" `
        -Message "Successfully loaded: $ConfigPath"
} catch {
    Write-ValidationResult -Test "Configuration File" -Status "Fail" `
        -Message "Failed to parse JSON: $_"
    exit 1
}

# Step 2: Find binaries to validate
Write-Host ""
Write-Host "Locating binaries..." -ForegroundColor Yellow

$binaries = @()
if (Test-Path $BinaryPath -PathType Container) {
    $binaries = Get-ChildItem -Path $BinaryPath -Filter "*.exe" -File
    if ($binaries.Count -eq 0) {
        Write-ValidationResult -Test "Binary Discovery" -Status "Fail" `
            -Message "No .exe files found in: $BinaryPath"
        exit 1
    }
    Write-ValidationResult -Test "Binary Discovery" -Status "Pass" `
        -Message "Found $($binaries.Count) executable(s)"
} elseif (Test-Path $BinaryPath -PathType Leaf) {
    $binaries = @(Get-Item $BinaryPath)
    Write-ValidationResult -Test "Binary Discovery" -Status "Pass" `
        -Message "Validating single file: $(Split-Path $BinaryPath -Leaf)"
} else {
    Write-ValidationResult -Test "Binary Discovery" -Status "Fail" `
        -Message "Path not found: $BinaryPath"
    exit 1
}

# Step 3: Validate each binary
foreach ($binary in $binaries) {
    Write-Host ""
    Write-Host "Validating: $($binary.Name)" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    $binaryFullPath = $binary.FullName

    # Test 1: File size sanity check
    $sizeInMB = [math]::Round($binary.Length / 1MB, 2)
    if ($binary.Length -gt 1MB -and $binary.Length -lt 20MB) {
        Write-ValidationResult -Test "File Size Check" -Status "Pass" `
            -Message "$sizeInMB MB (within expected range)"
    } else {
        Write-ValidationResult -Test "File Size Check" -Status "Warning" `
            -Message "$sizeInMB MB (unusual size)"
    }

    # Test 2: PE header validation
    $peHeader = Get-Content -Path $binaryFullPath -AsByteStream -TotalCount 2
    if ($peHeader[0] -eq 0x4D -and $peHeader[1] -eq 0x5A) {
        Write-ValidationResult -Test "PE Header" -Status "Pass" `
            -Message "Valid Windows executable (MZ signature)"
    } else {
        Write-ValidationResult -Test "PE Header" -Status "Fail" `
            -Message "Invalid PE signature"
        continue
    }

    # Test 3: Extract strings for validation
    Write-Host "Extracting embedded strings..." -ForegroundColor Gray
    $asciiStrings = Get-BinaryStrings -Path $binaryFullPath
    $unicodeStrings = Get-BinaryUnicodeStrings -Path $binaryFullPath
    $allStrings = $asciiStrings + $unicodeStrings | Select-Object -Unique

    # Test 4: Service name validation
    if ($config.branding.serviceName) {
        $serviceName = $config.branding.serviceName
        if ($allStrings -contains $serviceName) {
            Write-ValidationResult -Test "Service Name" -Status "Pass" `
                -Message "Found: '$serviceName'"
        } else {
            Write-ValidationResult -Test "Service Name" -Status "Fail" `
                -Message "Not found: '$serviceName'"
        }
    }

    # Test 5: Display name validation
    if ($config.branding.displayName) {
        $displayName = $config.branding.displayName
        if ($allStrings | Where-Object { $_ -like "*$displayName*" }) {
            Write-ValidationResult -Test "Display Name" -Status "Pass" `
                -Message "Found: '$displayName'"
        } else {
            Write-ValidationResult -Test "Display Name" -Status "Warning" `
                -Message "Not found: '$displayName'"
        }
    }

    # Test 6: Company name validation
    if ($config.branding.companyName) {
        $companyName = $config.branding.companyName
        if ($allStrings | Where-Object { $_ -like "*$companyName*" }) {
            Write-ValidationResult -Test "Company Name" -Status "Pass" `
                -Message "Found: '$companyName'"
        } else {
            Write-ValidationResult -Test "Company Name" -Status "Warning" `
                -Message "Not found: '$companyName'"
        }
    }

    # Test 7: Network endpoint validation
    if ($config.network.primaryEndpoint) {
        $endpoint = $config.network.primaryEndpoint
        # Extract just the hostname/port part
        if ($endpoint -match '://([^/]+)') {
            $hostPort = $matches[1]
            if ($allStrings | Where-Object { $_ -like "*$hostPort*" }) {
                Write-ValidationResult -Test "Network Endpoint" -Status "Pass" `
                    -Message "Found: '$hostPort'"
            } else {
                Write-ValidationResult -Test "Network Endpoint" -Status "Fail" `
                    -Message "Not found: '$hostPort'"
            }
        }
    }

    # Test 8: Mesh ID validation
    if ($config.provisioning.meshId) {
        $meshId = $config.provisioning.meshId
        # Check for at least part of the mesh ID (first 20 chars)
        $meshIdPrefix = $meshId.Substring(0, [Math]::Min(20, $meshId.Length))
        if ($allStrings | Where-Object { $_ -like "*$meshIdPrefix*" }) {
            Write-ValidationResult -Test "Mesh ID" -Status "Pass" `
                -Message "Found mesh ID prefix"
        } else {
            Write-ValidationResult -Test "Mesh ID" -Status "Warning" `
                -Message "Mesh ID not found in binary"
        }
    }

    # Test 9: Version information
    try {
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binaryFullPath)

        if ($versionInfo.FileDescription) {
            Write-ValidationResult -Test "File Description" -Status "Pass" `
                -Message $versionInfo.FileDescription
        }

        if ($versionInfo.CompanyName) {
            $expectedCompany = $config.branding.companyName
            if ($versionInfo.CompanyName -eq $expectedCompany) {
                Write-ValidationResult -Test "Version Info Company" -Status "Pass" `
                    -Message "Matches configuration"
            } else {
                Write-ValidationResult -Test "Version Info Company" -Status "Warning" `
                    -Message "Found: '$($versionInfo.CompanyName)', Expected: '$expectedCompany'"
            }
        }
    } catch {
        Write-ValidationResult -Test "Version Information" -Status "Warning" `
            -Message "Could not extract version info"
    }

    # Test 10: Digital signature validation
    if (Test-Path $signerAllowlistScript) {
        try {
            $thumbprint = Get-MeshAgentSignerThumbprint -Path $binaryFullPath
            if ($thumbprint) {
                $allowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $projectRoot
                if ($allowedThumbprints -contains $thumbprint) {
                    Write-ValidationResult -Test "Digital Signature" -Status "Pass" `
                        -Message "Signed with allowlisted certificate: $thumbprint"
                } else {
                    Write-ValidationResult -Test "Digital Signature" -Status "Warning" `
                        -Message "Signed but not allowlisted: $thumbprint"
                }
            } else {
                Write-ValidationResult -Test "Digital Signature" -Status "Warning" `
                    -Message "Binary is not signed"
            }
        } catch {
            Write-ValidationResult -Test "Digital Signature" -Status "Warning" `
                -Message "Could not verify signature: $_"
        }
    }
}

# Step 4: Generate summary report
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         Validation Summary             " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$totalTests = $Script:Results.Passed.Count + $Script:Results.Failed.Count + $Script:Results.Warnings.Count

Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "  Passed:   $($Script:Results.Passed.Count)" -ForegroundColor Green
Write-Host "  Failed:   $($Script:Results.Failed.Count)" -ForegroundColor Red
Write-Host "  Warnings: $($Script:Results.Warnings.Count)" -ForegroundColor Yellow
Write-Host ""

# Generate detailed report if requested
if ($Detailed -or $Script:Results.Failed.Count -gt 0) {
    $reportPath = Join-Path $projectRoot "branding_verification_report.json"
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ConfigPath = $ConfigPath
        BinaryPath = $BinaryPath
        Summary = @{
            TotalTests = $totalTests
            Passed = $Script:Results.Passed.Count
            Failed = $Script:Results.Failed.Count
            Warnings = $Script:Results.Warnings.Count
        }
        Results = $Script:Results
    }

    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "Detailed report saved to: $reportPath" -ForegroundColor Cyan
}

# Exit with appropriate code
if ($Script:Results.Failed.Count -gt 0) {
    Write-Host "VALIDATION FAILED" -ForegroundColor Red

    Write-Host ""
    Write-Host "Failed tests:" -ForegroundColor Red
    foreach ($failure in $Script:Results.Failed) {
        Write-Host "  - $($failure.Test): $($failure.Message)" -ForegroundColor Red
    }

    exit 1
} elseif ($Script:Results.Warnings.Count -gt 0) {
    Write-Host "VALIDATION PASSED WITH WARNINGS" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "ALL VALIDATIONS PASSED" -ForegroundColor Green
    exit 0
}
