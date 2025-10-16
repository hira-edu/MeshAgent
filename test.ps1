#Requires -Version 5.1
<#
.SYNOPSIS
    Automated testing suite for custom MeshAgent binaries

.DESCRIPTION
    This script performs comprehensive validation and testing of custom-branded
    MeshAgent binaries including:
    - Resource metadata validation
    - PE header verification
    - Branding consistency checks
    - File integrity validation

.PARAMETER BinaryPath
    Path to binary directory. Default: meshservice\Release

.PARAMETER Verbose
    Show detailed test output

.EXAMPLE
    .\test.ps1
    Run all tests with summary output

.EXAMPLE
    .\test.ps1 -Verbose
    Run all tests with detailed output

.NOTES
    Author: Generated with Claude Code
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BinaryPath,

    [Parameter()]
    [switch]$VerboseOutput
)

# Set default binary path
if (-not $BinaryPath) {
    $BinaryPath = Join-Path $PSScriptRoot "meshservice\Release"
}

$ErrorActionPreference = 'Stop'

# Test results
$Script:TestResults = @{
    Passed = 0
    Failed = 0
    Warnings = 0
    Tests = @()
}

function Write-TestResult {
    param(
        [string]$TestName,
        [string]$Status,  # Pass, Fail, Warning
        [string]$Message,
        [string]$Details = ""
    )

    $color = switch ($Status) {
        'Pass' { 'Green'; $Script:TestResults.Passed++ }
        'Fail' { 'Red'; $Script:TestResults.Failed++ }
        'Warning' { 'Yellow'; $Script:TestResults.Warnings++ }
    }

    $icon = switch ($Status) {
        'Pass' { '✅' }
        'Fail' { '❌' }
        'Warning' { '⚠️ ' }
    }

    Write-Host "$icon $TestName" -ForegroundColor $color
    if ($Message) {
        Write-Host "   $Message" -ForegroundColor Gray
    }
    if ($Details -and $VerboseOutput) {
        Write-Host "   Details: $Details" -ForegroundColor DarkGray
    }

    $Script:TestResults.Tests += @{
        Name = $TestName
        Status = $Status
        Message = $Message
        Details = $Details
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  MeshAgent Automated Test Suite" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

#region Test Suite 1: File Existence and Integrity
Write-Host "Test Suite 1: File Existence and Integrity" -ForegroundColor Cyan
Write-Host "-------------------------------------------" -ForegroundColor Cyan

$x64Binary = Join-Path $BinaryPath "MeshService64.exe"
$x86Binary = Join-Path $BinaryPath "MeshService.exe"

# Test 1.1: x64 Binary Exists
if (Test-Path $x64Binary) {
    $x64Size = (Get-Item $x64Binary).Length
    Write-TestResult -TestName "x64 Binary Exists" -Status "Pass" -Message "Found at $x64Binary" -Details "Size: $([math]::Round($x64Size/1MB,2)) MB"
} else {
    Write-TestResult -TestName "x64 Binary Exists" -Status "Fail" -Message "Not found at $x64Binary"
}

# Test 1.2: x86 Binary Exists
if (Test-Path $x86Binary) {
    $x86Size = (Get-Item $x86Binary).Length
    Write-TestResult -TestName "x86 Binary Exists" -Status "Pass" -Message "Found at $x86Binary" -Details "Size: $([math]::Round($x86Size/1MB,2)) MB"
} else {
    Write-TestResult -TestName "x86 Binary Exists" -Status "Fail" -Message "Not found at $x86Binary"
}

# Test 1.3: File Size Validation
if ((Test-Path $x64Binary) -and $x64Size -gt 3MB -and $x64Size -lt 10MB) {
    Write-TestResult -TestName "x64 Binary Size Valid" -Status "Pass" -Message "$([math]::Round($x64Size/1MB,2)) MB (expected 3-10 MB)"
} elseif (Test-Path $x64Binary) {
    Write-TestResult -TestName "x64 Binary Size Valid" -Status "Warning" -Message "$([math]::Round($x64Size/1MB,2)) MB (unusual size)"
}

if ((Test-Path $x86Binary) -and $x86Size -gt 3MB -and $x86Size -lt 10MB) {
    Write-TestResult -TestName "x86 Binary Size Valid" -Status "Pass" -Message "$([math]::Round($x86Size/1MB,2)) MB (expected 3-10 MB)"
} elseif (Test-Path $x86Binary) {
    Write-TestResult -TestName "x86 Binary Size Valid" -Status "Warning" -Message "$([math]::Round($x86Size/1MB,2)) MB (unusual size)"
}

# Test 1.4: PE Header Validation
if (Test-Path $x64Binary) {
    $peHeader = Get-Content -Path $x64Binary -Encoding Byte -TotalCount 2
    if ($peHeader[0] -eq 0x4D -and $peHeader[1] -eq 0x5A) {
        Write-TestResult -TestName "x64 PE Header Valid" -Status "Pass" -Message "Valid PE signature (MZ)"
    } else {
        Write-TestResult -TestName "x64 PE Header Valid" -Status "Fail" -Message "Invalid PE signature"
    }
}

if (Test-Path $x86Binary) {
    $peHeader = Get-Content -Path $x86Binary -Encoding Byte -TotalCount 2
    if ($peHeader[0] -eq 0x4D -and $peHeader[1] -eq 0x5A) {
        Write-TestResult -TestName "x86 PE Header Valid" -Status "Pass" -Message "Valid PE signature (MZ)"
    } else {
        Write-TestResult -TestName "x86 PE Header Valid" -Status "Fail" -Message "Invalid PE signature"
    }
}

Write-Host ""
#endregion

#region Test Suite 2: Branding Configuration
Write-Host "Test Suite 2: Branding Configuration" -ForegroundColor Cyan
Write-Host "------------------------------------" -ForegroundColor Cyan

$brandingConfigPath = Join-Path $PSScriptRoot "branding_config.json"
$brandingHeaderPath = Join-Path $PSScriptRoot "meshcore\generated\meshagent_branding.h"

# Test 2.1: Branding Config Exists
if (Test-Path $brandingConfigPath) {
    Write-TestResult -TestName "Branding Config Exists" -Status "Pass" -Message "Found at $brandingConfigPath"

    # Test 2.2: Branding Config is Valid JSON
    try {
        $brandingConfig = Get-Content -Path $brandingConfigPath -Raw | ConvertFrom-Json
        Write-TestResult -TestName "Branding Config Valid JSON" -Status "Pass" -Message "Successfully parsed JSON"

        # Test 2.3: Required Fields Present
        $requiredFields = @('branding', 'network')
        $missingFields = @()

        foreach ($field in $requiredFields) {
            if (-not ($brandingConfig.PSObject.Properties.Name -contains $field)) {
                $missingFields += $field
            }
        }

        if ($missingFields.Count -eq 0) {
            Write-TestResult -TestName "Branding Config Has Required Fields" -Status "Pass" -Message "All required fields present"
        } else {
            Write-TestResult -TestName "Branding Config Has Required Fields" -Status "Fail" -Message "Missing fields: $($missingFields -join ', ')"
        }

        # Test 2.4: Service Name Validation
        if ($brandingConfig.branding.serviceName) {
            $serviceName = $brandingConfig.branding.serviceName
            if ($serviceName -match '^[A-Za-z0-9_]+$') {
                Write-TestResult -TestName "Service Name Valid" -Status "Pass" -Message "Service name: $serviceName"
            } else {
                Write-TestResult -TestName "Service Name Valid" -Status "Warning" -Message "Service name contains special characters: $serviceName"
            }
        } else {
            Write-TestResult -TestName "Service Name Valid" -Status "Fail" -Message "Service name not defined"
        }

        # Test 2.5: Network Endpoint Validation
        if ($brandingConfig.network.primaryEndpoint) {
            $endpoint = $brandingConfig.network.primaryEndpoint
            if ($endpoint -match '^wss?://') {
                Write-TestResult -TestName "Network Endpoint Valid" -Status "Pass" -Message "Endpoint: $endpoint"
            } else {
                Write-TestResult -TestName "Network Endpoint Valid" -Status "Warning" -Message "Endpoint protocol unexpected: $endpoint"
            }
        } else {
            Write-TestResult -TestName "Network Endpoint Valid" -Status "Fail" -Message "Network endpoint not defined"
        }

    } catch {
        Write-TestResult -TestName "Branding Config Valid JSON" -Status "Fail" -Message "JSON parsing error: $_"
    }
} else {
    Write-TestResult -TestName "Branding Config Exists" -Status "Fail" -Message "Not found at $brandingConfigPath"
}

# Test 2.6: Branding Header Generated
if (Test-Path $brandingHeaderPath) {
    Write-TestResult -TestName "Branding Header Exists" -Status "Pass" -Message "Found at $brandingHeaderPath"

    # Test 2.7: Branding Header Has Required Defines
    $headerContent = Get-Content -Path $brandingHeaderPath -Raw
    $requiredDefines = @(
        'MESH_AGENT_SERVICE_FILE',
        'MESH_AGENT_SERVICE_NAME',
        'MESH_AGENT_COMPANY_NAME',
        'MESH_AGENT_PRODUCT_NAME'
    )

    $missingDefines = @()
    foreach ($define in $requiredDefines) {
        if ($headerContent -notmatch "#define\s+$define") {
            $missingDefines += $define
        }
    }

    if ($missingDefines.Count -eq 0) {
        Write-TestResult -TestName "Branding Header Has Required Defines" -Status "Pass" -Message "All required defines present"
    } else {
        Write-TestResult -TestName "Branding Header Has Required Defines" -Status "Fail" -Message "Missing defines: $($missingDefines -join ', ')"
    }
} else {
    Write-TestResult -TestName "Branding Header Exists" -Status "Fail" -Message "Not found at $brandingHeaderPath"
}

Write-Host ""
#endregion

#region Test Suite 3: Resource Metadata (Requires PowerShell 7+ or external tool)
Write-Host "Test Suite 3: Resource Metadata Validation" -ForegroundColor Cyan
Write-Host "-------------------------------------------" -ForegroundColor Cyan

# Note: Full resource extraction requires external tools like sigcheck or ResourceHacker
# For basic validation, we'll check what we can

if (Test-Path $x64Binary) {
    # Test 3.1: Check if binary contains resources
    try {
        $fileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($x64Binary)

        # Test 3.2: File Description
        if ($fileVersionInfo.FileDescription) {
            if ($fileVersionInfo.FileDescription -match "Acme") {
                Write-TestResult -TestName "x64 File Description Branded" -Status "Pass" -Message $fileVersionInfo.FileDescription
            } else {
                Write-TestResult -TestName "x64 File Description Branded" -Status "Warning" -Message "May not have custom branding: $($fileVersionInfo.FileDescription)"
            }
        } else {
            Write-TestResult -TestName "x64 File Description Branded" -Status "Warning" -Message "No file description found"
        }

        # Test 3.3: Company Name
        if ($fileVersionInfo.CompanyName) {
            if ($fileVersionInfo.CompanyName -match "Acme") {
                Write-TestResult -TestName "x64 Company Name Branded" -Status "Pass" -Message $fileVersionInfo.CompanyName
            } else {
                Write-TestResult -TestName "x64 Company Name Branded" -Status "Warning" -Message "May not have custom branding: $($fileVersionInfo.CompanyName)"
            }
        } else {
            Write-TestResult -TestName "x64 Company Name Branded" -Status "Warning" -Message "No company name found"
        }

        # Test 3.4: Product Name
        if ($fileVersionInfo.ProductName) {
            if ($fileVersionInfo.ProductName -match "Acme") {
                Write-TestResult -TestName "x64 Product Name Branded" -Status "Pass" -Message $fileVersionInfo.ProductName
            } else {
                Write-TestResult -TestName "x64 Product Name Branded" -Status "Warning" -Message "May not have custom branding: $($fileVersionInfo.ProductName)"
            }
        } else {
            Write-TestResult -TestName "x64 Product Name Branded" -Status "Warning" -Message "No product name found"
        }

    } catch {
        Write-TestResult -TestName "x64 Resource Metadata" -Status "Warning" -Message "Could not read version info: $_"
    }
}

Write-Host ""
#endregion

#region Test Suite 4: Build Environment
Write-Host "Test Suite 4: Build Environment" -ForegroundColor Cyan
Write-Host "-------------------------------" -ForegroundColor Cyan

# Test 4.1: Visual Studio Installation
$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if (Test-Path $vsPath) {
    Write-TestResult -TestName "Visual Studio 2022 Found" -Status "Pass" -Message "MSBuild found at $vsPath"
} else {
    Write-TestResult -TestName "Visual Studio 2022 Found" -Status "Warning" -Message "MSBuild not found (may affect future builds)"
}

# Test 4.2: Python Installation
try {
    $pythonVersion = python --version 2>&1
    Write-TestResult -TestName "Python Found" -Status "Pass" -Message $pythonVersion
} catch {
    Write-TestResult -TestName "Python Found" -Status "Warning" -Message "Python not found (required for builds)"
}

# Test 4.3: Git Installation
try {
    $gitVersion = git --version 2>&1
    Write-TestResult -TestName "Git Found" -Status "Pass" -Message $gitVersion
} catch {
    Write-TestResult -TestName "Git Found" -Status "Warning" -Message "Git not found (recommended for version control)"
}

Write-Host ""
#endregion

#region Test Results Summary
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Test Results Summary" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$total = $Script:TestResults.Passed + $Script:TestResults.Failed + $Script:TestResults.Warnings

Write-Host "Total Tests: $total" -ForegroundColor White
Write-Host "  ✅ Passed:   $($Script:TestResults.Passed)" -ForegroundColor Green
Write-Host "  ❌ Failed:   $($Script:TestResults.Failed)" -ForegroundColor Red
Write-Host "  ⚠️  Warnings: $($Script:TestResults.Warnings)" -ForegroundColor Yellow
Write-Host ""

if ($Script:TestResults.Failed -gt 0) {
    Write-Host "❌ TEST SUITE FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Failed tests:" -ForegroundColor Red
    foreach ($test in $Script:TestResults.Tests | Where-Object { $_.Status -eq 'Fail' }) {
        Write-Host "  - $($test.Name): $($test.Message)" -ForegroundColor Red
    }
    exit 1
} elseif ($Script:TestResults.Warnings -gt 0) {
    Write-Host "⚠️  TEST SUITE PASSED WITH WARNINGS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor Yellow
    foreach ($test in $Script:TestResults.Tests | Where-Object { $_.Status -eq 'Warning' }) {
        Write-Host "  - $($test.Name): $($test.Message)" -ForegroundColor Yellow
    }
    exit 0
} else {
    Write-Host "✅ ALL TESTS PASSED" -ForegroundColor Green
    exit 0
}
#endregion
