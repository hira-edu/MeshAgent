#Requires -Version 5.1
<#
.SYNOPSIS
    Deploy custom MeshAgent binaries to MeshCentral server

.DESCRIPTION
    This script deploys MeshService64.exe and MeshService.exe to the MeshCentral server
    and restarts the service.

.PARAMETER Server
    MeshCentral server DNS name. Default: high.support

.PARAMETER User
    SSH user. Default: root

.PARAMETER AgentsPath
    Path to agents directory on server. Default: /opt/meshcentral/meshcentral-data/agents

.PARAMETER RestartService
    Restart MeshCentral service after deployment. Default: $true

.PARAMETER VerifyOnly
    Only verify current deployment, don't upload new binaries

.EXAMPLE
    .\deploy.ps1
    Deploy binaries to default server

.EXAMPLE
    .\deploy.ps1 -VerifyOnly
    Check current deployment status

.NOTES
    Author: Generated with Claude Code
    Requires: SSH access to MeshCentral server
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Server = 'high.support',

    [Parameter()]
    [string]$User = 'root',

    [Parameter()]
    [string]$AgentsPath = '/opt/meshcentral/meshcentral-data/agents',

    [Parameter()]
    [bool]$RestartService = $true,

    [Parameter()]
    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'

# Paths
$RepoRoot = $PSScriptRoot
$LocalX64 = Join-Path $RepoRoot "meshservice\Release\MeshService64.exe"
$LocalX86 = Join-Path $RepoRoot "meshservice\Release\MeshService.exe"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  MeshAgent Deployment Script" -ForegroundColor Cyan
Write-Host "  Target: $User@$Server" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

#region Step 1: Validate Local Binaries
Write-Host "[1/5] Validating local binaries..." -ForegroundColor Green

if (-not (Test-Path $LocalX64)) {
    Write-Host "❌ x64 binary not found: $LocalX64" -ForegroundColor Red
    Write-Host "Run .\build.ps1 first to build binaries" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $LocalX86)) {
    Write-Host "❌ x86 binary not found: $LocalX86" -ForegroundColor Red
    Write-Host "Run .\build.ps1 first to build binaries" -ForegroundColor Yellow
    exit 1
}

$localX64Size = (Get-Item $LocalX64).Length
$localX86Size = (Get-Item $LocalX86).Length
$localX64MD5 = (Get-FileHash -Path $LocalX64 -Algorithm MD5).Hash
$localX86MD5 = (Get-FileHash -Path $LocalX86 -Algorithm MD5).Hash

Write-Host "✅ Local binaries found:" -ForegroundColor Gray
Write-Host "  MeshService64.exe: $([math]::Round($localX64Size/1MB,2)) MB (MD5: $localX64MD5)" -ForegroundColor Gray
Write-Host "  MeshService.exe:   $([math]::Round($localX86Size/1MB,2)) MB (MD5: $localX86MD5)" -ForegroundColor Gray
#endregion

#region Step 2: Check Server Connectivity
Write-Host "[2/5] Checking server connectivity..." -ForegroundColor Green

try {
    $sshTest = ssh "$User@$Server" "echo 'Connection successful'" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SSH connection failed"
    }
    Write-Host "✅ SSH connection successful" -ForegroundColor Gray
} catch {
    Write-Host "❌ Cannot connect to server: $_" -ForegroundColor Red
    Write-Host "Ensure SSH key is configured: ssh-copy-id $User@$Server" -ForegroundColor Yellow
    exit 1
}
#endregion

#region Step 3: Check Current Deployment
Write-Host "[3/5] Checking current server deployment..." -ForegroundColor Green

$remoteInfo = ssh "$User@$Server" @"
ls -lh $AgentsPath/MeshService*.exe 2>/dev/null
md5sum $AgentsPath/MeshService64.exe $AgentsPath/MeshService.exe 2>/dev/null
"@

if ($LASTEXITCODE -eq 0 -and $remoteInfo) {
    Write-Host "Current server deployment:" -ForegroundColor Gray
    $remoteInfo -split "`n" | ForEach-Object {
        if ($_ -match '(\w+)\s+/opt') {
            $remoteMD5 = $matches[1]
            $file = $_ -replace '.*/([^/]+)$', '$1'

            if ($file -eq "MeshService64.exe" -and $remoteMD5 -eq $localX64MD5) {
                Write-Host "  ✅ $file matches local (MD5: $remoteMD5)" -ForegroundColor Green
            } elseif ($file -eq "MeshService.exe" -and $remoteMD5 -eq $localX86MD5) {
                Write-Host "  ✅ $file matches local (MD5: $remoteMD5)" -ForegroundColor Green
            } else {
                Write-Host "  ⚠️  $file differs from local (MD5: $remoteMD5)" -ForegroundColor Yellow
            }
        }
    }
} else {
    Write-Host "⚠️  No existing deployment found on server" -ForegroundColor Yellow
}

if ($VerifyOnly) {
    Write-Host ""
    Write-Host "Verification complete (no changes made)" -ForegroundColor Cyan
    exit 0
}
#endregion

#region Step 4: Upload Binaries
Write-Host "[4/5] Uploading binaries to server..." -ForegroundColor Green

try {
    # Upload x64
    Write-Host "  Uploading MeshService64.exe..." -ForegroundColor Gray
    scp "$LocalX64" "${User}@${Server}:${AgentsPath}/"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upload MeshService64.exe"
    }

    # Upload x86
    Write-Host "  Uploading MeshService.exe..." -ForegroundColor Gray
    scp "$LocalX86" "${User}@${Server}:${AgentsPath}/"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upload MeshService.exe"
    }

    Write-Host "✅ Upload completed" -ForegroundColor Gray
} catch {
    Write-Host "❌ Upload failed: $_" -ForegroundColor Red
    exit 1
}
#endregion

#region Step 5: Restart Service
if ($RestartService) {
    Write-Host "[5/5] Restarting MeshCentral service..." -ForegroundColor Green

    try {
        $restartOutput = ssh "$User@$Server" "systemctl restart meshcentral && sleep 5 && systemctl status meshcentral --no-pager | head -20"

        if ($restartOutput -match 'Active: active \(running\)') {
            Write-Host "✅ MeshCentral service restarted successfully" -ForegroundColor Gray

            # Check if binaries were code-signed
            if ($restartOutput -match 'Code signed MeshService') {
                Write-Host "✅ Binaries code-signed by MeshCentral" -ForegroundColor Gray
            }
        } else {
            Write-Host "⚠️  Service may not have restarted correctly" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ Failed to restart service: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[5/5] Skipping service restart (as requested)" -ForegroundColor Yellow
}
#endregion

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  DEPLOYMENT SUCCESSFUL" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Test agent download: https://$Server" -ForegroundColor White
Write-Host "  2. Verify branding in downloaded agent" -ForegroundColor White
Write-Host "  3. Install agent on test machine" -ForegroundColor White
Write-Host "  4. Check service name: Get-Service 'AcmeTelemetryCore'" -ForegroundColor White
Write-Host ""
