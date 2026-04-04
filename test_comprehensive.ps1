#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive testing suite for MeshAgent binaries with optimized binary analysis

.DESCRIPTION
    This script performs thorough validation of MeshAgent binaries including:
    - File existence and integrity checks
    - Digital signature validation
    - Branding configuration consistency
    - Binary string extraction and validation
    - Resource metadata verification
    - JSON report generation

.PARAMETER BinaryPath
    Path to binary directory. Default: meshservice\Release

.PARAMETER ConfigPath
    Optional path to the branding configuration JSON (defaults to branding_config.local.json when present)

.PARAMETER ReportPath
    Optional path to write JSON verification report

.PARAMETER SkipBinaryAnalysis
    Skip the binary string extraction (for faster execution)

.PARAMETER VerboseOutput
    Show detailed test output

.EXAMPLE
    .\test_comprehensive.ps1 -ReportPath "verification.json"

.EXAMPLE
    .\test_comprehensive.ps1 -VerboseOutput -SkipBinaryAnalysis

.NOTES
    Version: 2.0
    Optimized for performance with large binaries
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BinaryPath,

    [Parameter()]
    [string]$ConfigPath,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [switch]$SkipBinaryAnalysis,

    [Parameter()]
    [switch]$VerboseOutput
)

#region Initialize
$ErrorActionPreference = 'Stop'
$Script:StartTime = Get-Date

# Set defaults
$repoRoot = $PSScriptRoot
if (-not $BinaryPath) {
    $BinaryPath = Join-Path $repoRoot "meshservice\Release"
}
$brandingHelper = Join-Path $repoRoot "tools\BrandingConfig.ps1"
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper
if (-not $ConfigPath) {
    $ConfigPath = Resolve-BrandingConfigPath -RepoRoot $repoRoot
} else {
    $ConfigPath = Resolve-BrandingConfigPath -RepoRoot $repoRoot -ConfigPath $ConfigPath
}

# Test results structure
$Script:TestResults = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    BinaryPath = $BinaryPath
    ConfigPath = $ConfigPath
    Statistics = @{
        Passed = 0
        Failed = 0
        Warnings = 0
        Skipped = 0
        Total = 0
    }
    Tests = @()
    Duration = $null
}

# Load dependencies
$signerAllowlistScript = Join-Path $repoRoot "tools\SignerAllowlist.ps1"
if (Test-Path $signerAllowlistScript) {
    . $signerAllowlistScript
    $Script:AllowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $repoRoot -ErrorAction SilentlyContinue
} else {
    $Script:AllowedThumbprints = @()
    Write-Warning "SignerAllowlist.ps1 not found - signature validation will be limited"
}

#endregion

#region Helper Functions

function Write-TestResult {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TestName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Skip')]
        [string]$Status,

        [string]$Message = "",
        [string]$Details = "",
        [hashtable]$Data = @{}
    )

    # Update statistics
    switch ($Status) {
        'Pass'    { $Script:TestResults.Statistics.Passed++ }
        'Fail'    { $Script:TestResults.Statistics.Failed++ }
        'Warning' { $Script:TestResults.Statistics.Warnings++ }
        'Skip'    { $Script:TestResults.Statistics.Skipped++ }
    }
    $Script:TestResults.Statistics.Total++

    # Set display properties
    $color = @{
        'Pass' = 'Green'
        'Fail' = 'Red'
        'Warning' = 'Yellow'
        'Skip' = 'Gray'
    }[$Status]

    $icon = @{
        'Pass' = '[PASS]'
        'Fail' = '[FAIL]'
        'Warning' = '[WARN]'
        'Skip' = '[SKIP]'
    }[$Status]

    # Display to console
    Write-Host "$icon $TestName" -ForegroundColor $color
    if ($Message) {
        Write-Host "      $Message" -ForegroundColor Gray
    }
    if ($VerboseOutput -and $Details) {
        Write-Host "      Details: $Details" -ForegroundColor DarkGray
    }

    # Record test result
    $testRecord = @{
        Name = $TestName
        Status = $Status
        Message = $Message
        Details = $Details
        Data = $Data
        Timestamp = Get-Date -Format "HH:mm:ss.fff"
    }
    $Script:TestResults.Tests += $testRecord
}

function Test-BinaryFile {
    param(
        [string]$Path,
        [string]$Label
    )

    if (-not (Test-Path $Path)) {
        Write-TestResult -TestName "$Label Binary Exists" `
                        -Status "Fail" `
                        -Message "File not found: $Path"
        return $false
    }

    $file = Get-Item $Path
    $sizeInMB = [math]::Round($file.Length / 1MB, 2)

    Write-TestResult -TestName "$Label Binary Exists" `
                    -Status "Pass" `
                    -Message "Found: $(Split-Path $Path -Leaf)" `
                    -Details "Size: $sizeInMB MB" `
                    -Data @{ Path = $Path; Size = $file.Length }

    # Validate PE header
    try {
        $bytes = Get-Content -Path $Path -Encoding Byte -TotalCount 2
        if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            Write-TestResult -TestName "$Label PE Header" `
                            -Status "Pass" `
                            -Message "Valid Windows PE signature (MZ)"
        } else {
            Write-TestResult -TestName "$Label PE Header" `
                            -Status "Fail" `
                            -Message "Invalid PE signature"
        }
    } catch {
        Write-TestResult -TestName "$Label PE Header" `
                        -Status "Warning" `
                        -Message "Could not validate PE header: $_"
    }

    # Check digital signature
    if ($Script:AllowedThumbprints -and $Script:AllowedThumbprints.Count -gt 0) {
        try {
            # Use SignerAllowlist.ps1 functions if available
            if (Get-Command Assert-MeshAgentSignatureAllowed -ErrorAction SilentlyContinue) {
                Assert-MeshAgentSignatureAllowed -Path $Path `
                    -AllowedThumbprints $Script:AllowedThumbprints `
                    -RequireSignature:$false | Out-Null

                $thumbprint = Get-MeshAgentSignerThumbprint -Path $Path -ErrorAction SilentlyContinue
                if ($thumbprint) {
                    Write-TestResult -TestName "$Label Signature" `
                                    -Status "Pass" `
                                    -Message "Signed with allowlisted certificate" `
                                    -Details "Thumbprint: $thumbprint"
                } else {
                    Write-TestResult -TestName "$Label Signature" `
                                    -Status "Warning" `
                                    -Message "Not digitally signed"
                }
            }
        } catch {
            Write-TestResult -TestName "$Label Signature" `
                            -Status "Warning" `
                            -Message "Signature check failed: $_"
        }
    }

    return $true
}

function Get-BinaryStringsOptimized {
    param(
        [string]$Path,
        [int]$MinLength = 4,
        [int]$MaxBytes = 5242880  # 5MB limit by default
    )

    $strings = @()

    try {
        # Try to use strings.exe first (fastest method)
        $stringsExe = Get-Command strings.exe -ErrorAction SilentlyContinue
        if ($stringsExe) {
            Write-Verbose "Using strings.exe for binary analysis"
            $output = & strings.exe -n $MinLength $Path 2>$null
            return $output
        }

        # Fallback to findstr (available on all Windows)
        Write-Verbose "Using findstr for binary analysis"
        $tempFile = [System.IO.Path]::GetTempFileName()

        try {
            # Export first portion of file to temp
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $bytesToProcess = [Math]::Min($bytes.Length, $MaxBytes)
            [System.IO.File]::WriteAllBytes($tempFile, $bytes[0..($bytesToProcess-1)])

            # Use findstr to find ASCII strings
            $strings = cmd /c "findstr /R /C:`"[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]`" `"$tempFile`"" 2>$null

            # Clean up strings
            $cleanStrings = @()
            foreach ($line in $strings) {
                # Extract printable sequences
                $matches = [regex]::Matches($line, '[a-zA-Z0-9_\-\.:/\\]{4,}')
                foreach ($match in $matches) {
                    if ($match.Value.Length -ge $MinLength) {
                        $cleanStrings += $match.Value
                    }
                }
            }

            return $cleanStrings | Select-Object -Unique
        } finally {
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Warning "Failed to extract strings from $Path : $_"
        return @()
    }
}

function Test-ConfigurationFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-TestResult -TestName "Configuration File" `
                        -Status "Fail" `
                        -Message "Config file not found: $Path"
        return $null
    }

    try {
        $config = Get-Content $Path -Raw | ConvertFrom-Json
        Write-TestResult -TestName "Configuration File" `
                        -Status "Pass" `
                        -Message "Valid JSON configuration loaded" `
                        -Data @{ Path = $Path }

        # Validate required sections
        $requiredSections = @('branding', 'network', 'provisioning', 'security')
        $missingSections = @()

        foreach ($section in $requiredSections) {
            if (-not $config.$section) {
                $missingSections += $section
            }
        }

        if ($missingSections.Count -gt 0) {
            Write-TestResult -TestName "Config Structure" `
                            -Status "Warning" `
                            -Message "Missing sections: $($missingSections -join ', ')"
        } else {
            Write-TestResult -TestName "Config Structure" `
                            -Status "Pass" `
                            -Message "All required sections present"
        }

        return $config
    } catch {
        Write-TestResult -TestName "Configuration File" `
                        -Status "Fail" `
                        -Message "Failed to parse JSON: $_"
        return $null
    }
}

function Test-BrandingConsistency {
    param(
        [string]$BinaryPath,
        [object]$Config,
        [string]$Label
    )

    if ($SkipBinaryAnalysis) {
        Write-TestResult -TestName "$Label Branding Analysis" `
                        -Status "Skip" `
                        -Message "Binary analysis skipped by parameter"
        return
    }

    Write-Host ""
    Write-Host "Analyzing $Label binary for branding..." -ForegroundColor Gray

    # Extract strings from binary
    $strings = Get-BinaryStringsOptimized -Path $BinaryPath

    if ($strings.Count -eq 0) {
        Write-TestResult -TestName "$Label String Extraction" `
                        -Status "Warning" `
                        -Message "No strings extracted from binary"
        return
    }

    Write-Verbose "Extracted $($strings.Count) strings from binary"

    # Test service name
    if ($Config.branding.serviceName) {
        $serviceName = $Config.branding.serviceName
        if ($strings -contains $serviceName) {
            Write-TestResult -TestName "$Label Service Name" `
                            -Status "Pass" `
                            -Message "Found: '$serviceName'"
        } else {
            Write-TestResult -TestName "$Label Service Name" `
                            -Status "Warning" `
                            -Message "'$serviceName' not found in binary"
        }
    }

    # Test display name
    if ($Config.branding.displayName) {
        $displayName = $Config.branding.displayName
        $found = $strings | Where-Object { $_ -like "*$displayName*" }
        if ($found) {
            Write-TestResult -TestName "$Label Display Name" `
                            -Status "Pass" `
                            -Message "Found: '$displayName'"
        } else {
            Write-TestResult -TestName "$Label Display Name" `
                            -Status "Warning" `
                            -Message "'$displayName' not found in binary"
        }
    }

    # Test network endpoint
    if ($Config.network.primaryEndpoint) {
        $endpoint = $Config.network.primaryEndpoint
        if ($endpoint -match '://([^/]+)') {
            $hostPort = $matches[1]
            $found = $strings | Where-Object { $_ -like "*$hostPort*" }
            if ($found) {
                Write-TestResult -TestName "$Label Network Endpoint" `
                                -Status "Pass" `
                                -Message "Found: '$hostPort'"
            } else {
                Write-TestResult -TestName "$Label Network Endpoint" `
                                -Status "Warning" `
                                -Message "'$hostPort' not found in binary"
            }
        }
    }

    # Test company name
    if ($Config.branding.companyName) {
        $companyName = $Config.branding.companyName
        $found = $strings | Where-Object { $_ -like "*$companyName*" }
        if ($found) {
            Write-TestResult -TestName "$Label Company Name" `
                            -Status "Pass" `
                            -Message "Found: '$companyName'"
        } else {
            Write-TestResult -TestName "$Label Company Name" `
                            -Status "Warning" `
                            -Message "'$companyName' not found in binary"
        }
    }
}

function Test-ProvisioningFile {
    param(
        [string]$MshPath,
        [object]$Config
    )

    if (-not (Test-Path $MshPath)) {
        Write-TestResult -TestName "Provisioning File (.msh)" `
                        -Status "Warning" `
                        -Message "File not found: $MshPath"
        return
    }

    $mshContent = Get-Content $MshPath
    $mshMap = @{}

    foreach ($line in $mshContent) {
        if ($line -match '^([^=]+)=(.*)$') {
            $mshMap[$matches[1]] = $matches[2]
        }
    }

    Write-TestResult -TestName "Provisioning File (.msh)" `
                    -Status "Pass" `
                    -Message "Found and parsed: $(Split-Path $MshPath -Leaf)" `
                    -Data @{ Entries = $mshMap.Count }

    # Validate key fields
    if ($Config) {
        # Check service name
        if ($mshMap.meshServiceName -eq $Config.branding.serviceName) {
            Write-TestResult -TestName "MSH Service Name" `
                            -Status "Pass" `
                            -Message "Matches config: '$($mshMap.meshServiceName)'"
        } else {
            Write-TestResult -TestName "MSH Service Name" `
                            -Status "Fail" `
                            -Message "Expected: '$($Config.branding.serviceName)', Found: '$($mshMap.meshServiceName)'"
        }

        # Check display name
        if ($mshMap.displayName -eq $Config.branding.displayName) {
            Write-TestResult -TestName "MSH Display Name" `
                            -Status "Pass" `
                            -Message "Matches config: '$($mshMap.displayName)'"
        } else {
            Write-TestResult -TestName "MSH Display Name" `
                            -Status "Fail" `
                            -Message "Expected: '$($Config.branding.displayName)', Found: '$($mshMap.displayName)'"
        }

        # Check server URL
        if ($mshMap.MeshServer -eq $Config.provisioning.serverUrl) {
            Write-TestResult -TestName "MSH Server URL" `
                            -Status "Pass" `
                            -Message "Matches config: '$($mshMap.MeshServer)'"
        } else {
            Write-TestResult -TestName "MSH Server URL" `
                            -Status "Warning" `
                            -Message "Config mismatch - Expected: '$($Config.provisioning.serverUrl)'"
        }
    }
}

#endregion

#region Main Test Execution

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "           MeshAgent Comprehensive Test Suite v2.0             " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Binary Path: $BinaryPath" -ForegroundColor Gray
Write-Host "  Config Path: $ConfigPath" -ForegroundColor Gray
if ($ReportPath) {
    Write-Host "  Report Path: $ReportPath" -ForegroundColor Gray
}
if ($SkipBinaryAnalysis) {
    Write-Host "  [Binary analysis will be skipped]" -ForegroundColor Yellow
}
Write-Host ""

# Test Suite 1: Configuration Validation
Write-Host "Test Suite 1: Configuration Validation" -ForegroundColor Cyan
Write-Host "---------------------------------------" -ForegroundColor Cyan

$config = Test-ConfigurationFile -Path $ConfigPath

# Test Suite 2: Binary Files
Write-Host ""
Write-Host "Test Suite 2: Binary File Validation" -ForegroundColor Cyan
Write-Host "-------------------------------------" -ForegroundColor Cyan

$x64Binary = Join-Path $BinaryPath "MeshService64.exe"
$x86Binary = Join-Path $BinaryPath "MeshService.exe"

$x64Exists = Test-BinaryFile -Path $x64Binary -Label "x64"
$x86Exists = Test-BinaryFile -Path $x86Binary -Label "x86"

# Test Suite 3: Provisioning Files
Write-Host ""
Write-Host "Test Suite 3: Provisioning Files" -ForegroundColor Cyan
Write-Host "---------------------------------" -ForegroundColor Cyan

$mshPath = Join-Path $repoRoot "meshagent.msh"
Test-ProvisioningFile -MshPath $mshPath -Config $config

$brandingHeader = Join-Path $repoRoot "meshcore\generated\meshagent_branding.h"
if (Test-Path $brandingHeader) {
    Write-TestResult -TestName "Branding Header" `
                    -Status "Pass" `
                    -Message "Found: meshagent_branding.h" `
                    -Data @{ Path = $brandingHeader }

    # Check for required defines
    $headerContent = Get-Content $brandingHeader -Raw
    $requiredDefines = @(
        'MESH_AGENT_SERVICE_NAME',
        'MESH_AGENT_SERVICE_FILE',
        'MESH_AGENT_COMPANY_NAME'
    )

    $missingDefines = @()
    foreach ($define in $requiredDefines) {
        if ($headerContent -notmatch "#define\s+$define") {
            $missingDefines += $define
        }
    }

    if ($missingDefines.Count -eq 0) {
        Write-TestResult -TestName "Header Defines" `
                        -Status "Pass" `
                        -Message "All required defines present"
    } else {
        Write-TestResult -TestName "Header Defines" `
                        -Status "Fail" `
                        -Message "Missing: $($missingDefines -join ', ')"
    }
} else {
    Write-TestResult -TestName "Branding Header" `
                    -Status "Warning" `
                    -Message "Not found: meshagent_branding.h"
}

# Test Suite 4: Branding Consistency
if ($config -and -not $SkipBinaryAnalysis) {
    Write-Host ""
    Write-Host "Test Suite 4: Branding Consistency" -ForegroundColor Cyan
    Write-Host "-----------------------------------" -ForegroundColor Cyan

    if ($x64Exists) {
        Test-BrandingConsistency -BinaryPath $x64Binary -Config $config -Label "x64"
    }

    if ($x86Exists) {
        Test-BrandingConsistency -BinaryPath $x86Binary -Config $config -Label "x86"
    }
} elseif ($SkipBinaryAnalysis) {
    Write-Host ""
    Write-Host "Test Suite 4: Branding Consistency [SKIPPED]" -ForegroundColor Gray
}

#endregion

#region Results Summary and Reporting

$Script:TestResults.Duration = (Get-Date) - $Script:StartTime

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                      Test Results Summary                      " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$stats = $Script:TestResults.Statistics
Write-Host "Total Tests: $($stats.Total)" -ForegroundColor White
Write-Host "  ✓ Passed:   $($stats.Passed)" -ForegroundColor Green
Write-Host "  ✗ Failed:   $($stats.Failed)" -ForegroundColor Red
Write-Host "  ⚠ Warnings: $($stats.Warnings)" -ForegroundColor Yellow
Write-Host "  - Skipped:  $($stats.Skipped)" -ForegroundColor Gray
Write-Host ""
Write-Host "Duration: $([math]::Round($Script:TestResults.Duration.TotalSeconds, 2)) seconds" -ForegroundColor Gray
Write-Host ""

# Generate JSON report if requested
if ($ReportPath) {
    try {
        $Script:TestResults.Duration = $Script:TestResults.Duration.TotalSeconds
        $json = $Script:TestResults | ConvertTo-Json -Depth 5
        $json | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Host ('Report saved to: ' + $ReportPath) -ForegroundColor Green
    } catch {
        Write-Warning ('Failed to save report: ' + $_)
    }
}

# Determine exit code
$exitCode = 0
if ($stats.Failed -gt 0) {
    Write-Host ('FAIL: Test suite failed with ' + $stats.Failed + ' failures') -ForegroundColor Red
    $exitCode = 1

    # Show failed tests
    Write-Host ''
    Write-Host 'Failed tests:' -ForegroundColor Red
    $failedTests = $Script:TestResults.Tests | Where-Object { $_.Status -eq 'Fail' }
    foreach ($test in $failedTests) {
        $msg = '  - ' + $test.Name + ': ' + $test.Message
        Write-Host $msg -ForegroundColor Red
    }
} elseif ($stats.Warnings -gt 0) {
    Write-Host ('WARN: Test suite passed with ' + $stats.Warnings + ' warnings') -ForegroundColor Yellow

    if ($VerboseOutput) {
        Write-Host ''
        Write-Host 'Warnings:' -ForegroundColor Yellow
        $warningTests = $Script:TestResults.Tests | Where-Object { $_.Status -eq 'Warning' }
        foreach ($test in $warningTests) {
            $msg = '  - ' + $test.Name + ': ' + $test.Message
            Write-Host $msg -ForegroundColor Yellow
        }
    }
} else {
    Write-Host 'PASS: All tests passed successfully!' -ForegroundColor Green
}

exit $exitCode

#endregion
