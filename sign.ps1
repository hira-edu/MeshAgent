#Requires -Version 5.1
<#
.SYNOPSIS
    Code sign custom MeshAgent binaries with Authenticode

.DESCRIPTION
    This script signs MeshService64.exe and MeshService.exe with an Authenticode certificate.
    Supports PFX files and certificates from the Windows certificate store.

.PARAMETER CertificatePath
    Path to PFX certificate file

.PARAMETER CertificatePassword
    Password for PFX certificate (SecureString)

.PARAMETER Thumbprint
    Certificate thumbprint from Windows certificate store

.PARAMETER TimestampServer
    Timestamp server URL. Default: http://timestamp.digicert.com

.PARAMETER SkipValidation
    Skip signature validation after signing

.EXAMPLE
    .\sign.ps1 -CertificatePath "cert.pfx" -CertificatePassword (ConvertTo-SecureString "pass" -AsPlainText -Force)
    Sign using PFX file

.EXAMPLE
    .\sign.ps1 -Thumbprint "AB123..."
    Sign using certificate from Windows store

.NOTES
    Author: Generated with Claude Code
    Requires: Windows SDK (signtool.exe)
#>

[CmdletBinding(DefaultParameterSetName='PFX')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='PFX')]
    [string]$CertificatePath,

    [Parameter(Mandatory=$true, ParameterSetName='PFX')]
    [SecureString]$CertificatePassword,

    [Parameter(Mandatory=$true, ParameterSetName='Store')]
    [string]$Thumbprint,

    [Parameter()]
    [string]$TimestampServer = 'http://timestamp.digicert.com',

    [Parameter()]
    [switch]$SkipValidation
)

$ErrorActionPreference = 'Stop'

# Paths
$RepoRoot = $PSScriptRoot
$X64Binary = Join-Path $RepoRoot "meshservice\Release\MeshService64.exe"
$X86Binary = Join-Path $RepoRoot "meshservice\Release\MeshService.exe"

# Find signtool.exe
$SignToolPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
)

$SignTool = $SignToolPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $SignTool) {
    Write-Host "❌ signtool.exe not found. Please install Windows SDK" -ForegroundColor Red
    Write-Host "Download: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  MeshAgent Code Signing Script" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "SignTool: $SignTool" -ForegroundColor Gray
Write-Host ""

#region Validate Binaries
Write-Host "[1/4] Validating binaries..." -ForegroundColor Green

if (-not (Test-Path $X64Binary)) {
    Write-Host "❌ x64 binary not found: $X64Binary" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $X86Binary)) {
    Write-Host "❌ x86 binary not found: $X86Binary" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Binaries found" -ForegroundColor Gray
#endregion

#region Sign Binaries
Write-Host "[2/4] Signing binaries..." -ForegroundColor Green

if ($PSCmdlet.ParameterSetName -eq 'PFX') {
    # Sign using PFX file
    Write-Host "  Signing with PFX certificate: $CertificatePath" -ForegroundColor Gray

    # Convert SecureString password to plain text
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    # Sign x64
    Write-Host "  Signing MeshService64.exe..." -ForegroundColor Gray
    & $SignTool sign /f $CertificatePath /p $PlainPassword /fd SHA256 /tr $TimestampServer /td SHA256 /v $X64Binary

    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to sign MeshService64.exe" -ForegroundColor Red
        exit $LASTEXITCODE
    }

    # Sign x86
    Write-Host "  Signing MeshService.exe..." -ForegroundColor Gray
    & $SignTool sign /f $CertificatePath /p $PlainPassword /fd SHA256 /tr $TimestampServer /td SHA256 /v $X86Binary

    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to sign MeshService.exe" -ForegroundColor Red
        exit $LASTEXITCODE
    }

    # Clear password from memory
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

} elseif ($PSCmdlet.ParameterSetName -eq 'Store') {
    # Sign using certificate from Windows store
    Write-Host "  Signing with certificate from store: $Thumbprint" -ForegroundColor Gray

    # Sign x64
    Write-Host "  Signing MeshService64.exe..." -ForegroundColor Gray
    & $SignTool sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampServer /td SHA256 /v $X64Binary

    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to sign MeshService64.exe" -ForegroundColor Red
        exit $LASTEXITCODE
    }

    # Sign x86
    Write-Host "  Signing MeshService.exe..." -ForegroundColor Gray
    & $SignTool sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampServer /td SHA256 /v $X86Binary

    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to sign MeshService.exe" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host "✅ Signing completed" -ForegroundColor Gray
#endregion

#region Verify Signatures
if (-not $SkipValidation) {
    Write-Host "[3/4] Verifying signatures..." -ForegroundColor Green

    # Verify x64
    Write-Host "  Verifying MeshService64.exe..." -ForegroundColor Gray
    & $SignTool verify /pa /v $X64Binary

    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️  x64 signature verification returned warnings" -ForegroundColor Yellow
    } else {
        Write-Host "  ✅ x64 signature valid" -ForegroundColor Gray
    }

    # Verify x86
    Write-Host "  Verifying MeshService.exe..." -ForegroundColor Gray
    & $SignTool verify /pa /v $X86Binary

    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️  x86 signature verification returned warnings" -ForegroundColor Yellow
    } else {
        Write-Host "  ✅ x86 signature valid" -ForegroundColor Gray
    }

    Write-Host "✅ Verification completed" -ForegroundColor Gray
} else {
    Write-Host "[3/4] Skipping verification (as requested)" -ForegroundColor Yellow
}
#endregion

#region Display Summary
Write-Host "[4/4] Generating summary..." -ForegroundColor Green

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  CODE SIGNING SUCCESSFUL" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

# Get signature info
$x64Signature = Get-AuthenticodeSignature -FilePath $X64Binary
$x86Signature = Get-AuthenticodeSignature -FilePath $X86Binary

Write-Host "Signed binaries:" -ForegroundColor Cyan
Write-Host "  📦 MeshService64.exe" -ForegroundColor White
Write-Host "     Status: $($x64Signature.Status)" -ForegroundColor Gray
Write-Host "     Signer: $($x64Signature.SignerCertificate.Subject)" -ForegroundColor Gray
Write-Host ""
Write-Host "  📦 MeshService.exe" -ForegroundColor White
Write-Host "     Status: $($x86Signature.Status)" -ForegroundColor Gray
Write-Host "     Signer: $($x86Signature.SignerCertificate.Subject)" -ForegroundColor Gray
Write-Host ""

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Verify signatures: Get-AuthenticodeSignature .\meshservice\Release\*.exe" -ForegroundColor White
Write-Host "  2. Deploy to server: .\deploy.ps1" -ForegroundColor White
Write-Host "  3. Or create release: git tag v1.0.0 && git push origin v1.0.0" -ForegroundColor White
Write-Host ""
#endregion
