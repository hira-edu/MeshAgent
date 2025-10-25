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

.PARAMETER VerboseOutput
    Show detailed test output

.PARAMETER ReportPath
    Optional path to write a JSON summary of the verification results.

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
[switch]$VerboseOutput,

[Parameter()]
[string]$ReportPath,

[Parameter()]
[switch]$RuntimeValidation
)

# Set default binary path
if (-not $BinaryPath) {
    $BinaryPath = Join-Path $PSScriptRoot "meshservice\Release"
}

$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$signerAllowlistScript = Join-Path $repoRoot "tools\SignerAllowlist.ps1"
if (-not (Test-Path $signerAllowlistScript)) {
    throw "Signer allowlist helper not found at $signerAllowlistScript"
}
. $signerAllowlistScript
$AllowedThumbprints = Get-MeshAgentAllowedThumbprints -RepoRoot $repoRoot
$brandingHelper = Join-Path $repoRoot "tools\BrandingConfig.ps1"
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper
$brandingConfig = $null
$brandingConfigPath = $null
try {
    $brandingConfigInfo = Get-BrandingConfig -RepoRoot $repoRoot -Quiet
    $brandingConfigPath = $brandingConfigInfo.Path
    $brandingConfig = $brandingConfigInfo.Config
} catch {
    Write-Host ("[WARN] Unable to load branding configuration: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}
if (-not $brandingConfig) {
    Write-Host "[WARN] Branding configuration missing; branding consistency checks will be skipped." -ForegroundColor Yellow
}

$mshPath = Join-Path $repoRoot "WinDiagnosticHost.msh"

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

$Script:BinaryCache = @{}

function Get-BinaryBytes {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        return $null
    }
    if (-not $Script:BinaryCache.ContainsKey($Path)) {
        $Script:BinaryCache[$Path] = [System.IO.File]::ReadAllBytes($Path)
    }
    return $Script:BinaryCache[$Path]
}

function Ensure-BinaryProvisioningManifest {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [switch]$Quiet
    )

    $manifestPath = [System.IO.Path]::ChangeExtension($BinaryPath, '.msh')
    if (Test-Path -LiteralPath $manifestPath) {
        return $manifestPath
    }

    if (-not (Test-Path -LiteralPath $mshPath)) {
        if (-not $Quiet) {
            Write-Host ("[WARN] Provisioning manifest source missing at {0}" -f $mshPath) -ForegroundColor Yellow
        }
        return $manifestPath
    }

    try {
        Copy-Item -LiteralPath $mshPath -Destination $manifestPath -Force
        if (-not $Quiet) {
            Write-Host ("[INFO] Copied provisioning manifest to {0}" -f $manifestPath) -ForegroundColor Cyan
        }
    } catch {
        if (-not $Quiet) {
            Write-Host ("[WARN] Unable to copy provisioning manifest to {0}: {1}" -f $manifestPath, $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    return $manifestPath
}

function Test-BinaryContainsString {
    param(
        [string]$BinaryPath,
        [string]$ExpectedValue,
        [string]$TestName
    )

    if (-not (Test-Path $BinaryPath)) {
        Write-TestResult -TestName $TestName -Status "Fail" -Message "Binary not found: $BinaryPath"
        return
    }

    $bytes = Get-BinaryBytes -Path $BinaryPath
    if ($bytes -eq $null) {
        Write-TestResult -TestName $TestName -Status "Fail" -Message "Unable to read binary: $BinaryPath"
        return
    }

    $asciiNeedle = [System.Text.Encoding]::ASCII.GetBytes($ExpectedValue)
    $utf16Needle = [System.Text.Encoding]::Unicode.GetBytes($ExpectedValue)

    foreach ($needle in @($asciiNeedle, $utf16Needle)) {
        if ($needle.Length -eq 0 -or $needle.Length -gt $bytes.Length) { continue }
        for ($i = 0; $i -le $bytes.Length - $needle.Length; $i++) {
            $match = $true
            for ($j = 0; $j -lt $needle.Length; $j++) {
                if ($bytes[$i + $j] -ne $needle[$j]) {
                    $match = $false
                    break
                }
            }
            if ($match) {
                Write-TestResult -TestName $TestName -Status "Pass" -Message "$ExpectedValue found in $(Split-Path $BinaryPath -Leaf)"
                return
            }
        }
    }

    Write-TestResult -TestName $TestName -Status "Fail" -Message "$ExpectedValue not embedded in $(Split-Path $BinaryPath -Leaf)"
}

function Resolve-BinaryPath {
    param([string[]]$Candidates)

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-Path $candidate) {
            try { return (Get-Item $candidate).FullName } catch { return $candidate }
        }
    }
    return $null
}

$script:EmbeddedPayloadHeaderVerified = $false

function Ensure-EmbeddedPayloadHeader {
    if ($script:EmbeddedPayloadHeaderVerified) { return }
    $headerPath = Join-Path $repoRoot "meshcore\embedded\generated\svchost_payload.h"
    if (-not (Test-Path -LiteralPath $headerPath)) {
        throw "Embedded svchost payload header missing at $headerPath"
    }

    $metadataPath = Join-Path $repoRoot "meshcore\embedded\generated\svchost_payload.json"
    if (Test-Path -LiteralPath $metadataPath) {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($metadata -and $metadata.sha256 -and $metadata.input -and (Test-Path -LiteralPath $metadata.input)) {
            $expected = ($metadata.sha256.ToString()).ToLowerInvariant()
            $actual = ((Get-FileHash -Path $metadata.input -Algorithm SHA256).Hash).ToLowerInvariant()
            if ($expected -ne $actual) {
                throw "Embedded svchost payload metadata hash mismatch (expected $expected, actual $actual)"
            }
        }
    } else {
        Write-Warn "svchost payload metadata missing; unable to cross-check source DLL hash."
    }

    $script:EmbeddedPayloadHeaderVerified = $true
}

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Write-ServiceDebugInfo {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName
    )

    Write-Host ("[DEBUG] Inspecting service '{0}'" -f $ServiceName) -ForegroundColor Yellow
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host ("[DEBUG] Service state: {0}" -f $svc.Status) -ForegroundColor Yellow
    }
    else {
        Write-Host "[DEBUG] Service not found in SCM" -ForegroundColor Yellow
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Service Control Manager'
            } -MaxEvents 20 | Where-Object { $_.Message -like "*$ServiceName*" }

        foreach ($evt in $events | Select-Object -First 5) {
            Write-Host ("[DEBUG] SCM Event {0}: {1}" -f $evt.TimeCreated.ToString("u"), ($evt.Message -replace "`r?`n", ' ')) -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host ("[DEBUG] Unable to read SCM events: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

function Get-NativeExitCode {
    $var = Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue
    if ($null -eq $var -or $null -eq $var.Value) {
        return 0
    }
    return [int]$var.Value
}

function Invoke-RuntimeInstallValidation {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ServiceName
    )

    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        Write-TestResult -TestName "Runtime: Install" -Status "Warning" -Message "Binary not found at $BinaryPath"
        Write-TestResult -TestName "Runtime: Service State" -Status "Warning" -Message "Skipped install/state validation"
        Write-TestResult -TestName "Runtime: Uninstall" -Status "Warning" -Message "Skipped uninstall validation"
        return
    }

    Ensure-BinaryProvisioningManifest -BinaryPath $BinaryPath -Quiet | Out-Null

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-TestResult -TestName "Runtime: Install" -Status "Warning" -Message ("Service '{0}' already exists; skipping install/uninstall validation." -f $ServiceName)
        Write-TestResult -TestName "Runtime: Service State" -Status "Warning" -Message ("Skipped: service '{0}' pre-exists" -f $ServiceName)
        Write-TestResult -TestName "Runtime: Uninstall" -Status "Warning" -Message ("Skipped: service '{0}' pre-exists" -f $ServiceName)
        return
    }

    $installed = $false
    try {
        $installOutput = & $BinaryPath "-install" 2>&1
        $installExit = Get-NativeExitCode
        if ($installOutput) {
            Write-Host "[DEBUG] Install output:" -ForegroundColor Yellow
            $installOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }
        if ($installExit -ne 0) {
            Write-TestResult -TestName "Runtime: Install" -Status "Fail" -Message ("Install command exited with code {0}" -f $installExit)
            return
        }

        Start-Sleep -Milliseconds 500
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-TestResult -TestName "Runtime: Install" -Status "Pass" -Message ("Service '{0}' registered (Status: {1})" -f $ServiceName, $svc.Status)
            $installed = $true
        } else {
            Write-TestResult -TestName "Runtime: Install" -Status "Fail" -Message ("Service '{0}' not visible after install" -f $ServiceName)
            Write-ServiceDebugInfo -ServiceName $ServiceName
            return
        }

        $stateOutput = & $BinaryPath "-state" 2>&1
        $stateExit = Get-NativeExitCode
        if ($stateOutput) {
            Write-Host "[DEBUG] State output:" -ForegroundColor Yellow
            $stateOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }
        if ($stateExit -eq 0) {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) {
                Write-TestResult -TestName "Runtime: Service State" -Status "Pass" -Message ("'{0}' currently {1}" -f $ServiceName, $svc.Status)
            } else {
                Write-TestResult -TestName "Runtime: Service State" -Status "Warning" -Message ("State command succeeded but service '{0}' disappeared" -f $ServiceName)
                Write-ServiceDebugInfo -ServiceName $ServiceName
            }
        } else {
            Write-TestResult -TestName "Runtime: Service State" -Status "Warning" -Message ("State command exited with code {0}" -f $stateExit)
        }
    }
    finally {
        if ($installed) {
            $uninstallOutput = & $BinaryPath "-uninstall" 2>&1
            $uninstallExit = Get-NativeExitCode
            if ($uninstallOutput) {
                Write-Host "[DEBUG] Uninstall output:" -ForegroundColor Yellow
                $uninstallOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            }
            if ($uninstallExit -ne 0) {
                Write-TestResult -TestName "Runtime: Uninstall" -Status "Fail" -Message ("Uninstall command exited with code {0}" -f $uninstallExit)
            } else {
                $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                $attempts = 0
                while ($svc -and $attempts -lt 5) {
                    Start-Sleep -Milliseconds 500
                    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                    $attempts++
                }
                if ($svc) {
                    try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { }
                    Start-Sleep -Seconds 1
                    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                }
                if ($svc) {
                    try {
                        sc.exe delete $ServiceName 2>$null | Out-Null
                    } catch {}
                    Start-Sleep -Seconds 1
                    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                }

                if ($svc) {
                    Write-TestResult -TestName "Runtime: Uninstall" -Status "Fail" -Message ("Service '{0}' still registered after uninstall" -f $ServiceName)
                    Write-ServiceDebugInfo -ServiceName $ServiceName
                }
                else {
                    Write-TestResult -TestName "Runtime: Uninstall" -Status "Pass" -Message ("Service '{0}' removed" -f $ServiceName)
                }
            }
        }
    }
}

function Invoke-RuntimeSvchostValidation {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ServiceName
    )

    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        Write-TestResult -TestName "Runtime: Svchost Register" -Status "Warning" -Message "Binary not found at $BinaryPath"
        return
    }

    Ensure-BinaryProvisioningManifest -BinaryPath $BinaryPath -Quiet | Out-Null

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-TestResult -TestName "Runtime: Svchost Register" -Status "Warning" -Message ("Service '{0}' already exists; skipping runtime validation." -f $ServiceName)
        return
    }

    $stagedSvchostDll = $null
    $registered = $false
    try {
        $payloadCandidates = @(
            (Join-Path $repoRoot "meshservice\embedded\svchost_payload.dll"),
            (Join-Path $repoRoot "meshservice\x64\StealthLab_DLL\MeshService-2022.dll"),
            (Join-Path $repoRoot "meshservice\StealthLab_DLL\MeshService-2022.dll")
        )
        $payloadSource = $payloadCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($payloadSource) {
            $stagedSvchostDll = Join-Path ([System.IO.Path]::GetTempPath()) ("svchost_{0}.dll" -f ([guid]::NewGuid().ToString("N")))
            Copy-Item -LiteralPath $payloadSource -Destination $stagedSvchostDll -Force
        }
        $registerArgs = @("-svchost-register")
        if ($stagedSvchostDll) { $registerArgs += $stagedSvchostDll }
        $registerOutput = & $BinaryPath @registerArgs 2>&1
        $registerExit = Get-NativeExitCode
        if ($registerOutput) {
            Write-Host "[DEBUG] Svchost register output:" -ForegroundColor Yellow
            $registerOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }
        if ($registerExit -ne 0) {
            Write-TestResult -TestName "Runtime: Svchost Register" -Status "Fail" -Message ("Register command exited with code {0}" -f $registerExit)
            return
        }

        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-TestResult -TestName "Runtime: Svchost Register" -Status "Pass" -Message ("Service '{0}' registered (Status: {1})" -f $ServiceName, $svc.Status)
            $registered = $true
        }
        else {
            Write-TestResult -TestName "Runtime: Svchost Register" -Status "Fail" -Message ("Service '{0}' not found after registration" -f $ServiceName)
            Write-ServiceDebugInfo -ServiceName $ServiceName
            return
        }

        $statusOutput = & $BinaryPath "-svchost-status" 2>&1
        $statusExit = Get-NativeExitCode
        if ($statusOutput) {
            Write-Host "[DEBUG] Svchost status output:" -ForegroundColor Yellow
            $statusOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }
        if ($statusExit -eq 0) {
            Write-TestResult -TestName "Runtime: Svchost Status" -Status "Pass" -Message "svchost status command succeeded"
        } else {
            Write-TestResult -TestName "Runtime: Svchost Status" -Status "Warning" -Message ("Status command exited with code {0}" -f $statusExit)
        }
    }
    finally {
        if ($stagedSvchostDll -and (Test-Path -LiteralPath $stagedSvchostDll)) {
            Remove-Item -LiteralPath $stagedSvchostDll -Force -ErrorAction SilentlyContinue
        }
        if ($registered) {
            $unregOutput = & $BinaryPath "-svchost-unregister" 2>&1
            $unregExit = Get-NativeExitCode
            if ($unregOutput) {
                Write-Host "[DEBUG] Svchost unregister output:" -ForegroundColor Yellow
                $unregOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            }
            if ($unregExit -ne 0) {
                Write-TestResult -TestName "Runtime: Svchost Unregister" -Status "Fail" -Message ("Unregister command exited with code {0}" -f $unregExit)
            } else {
                $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($svc) {
                    Write-TestResult -TestName "Runtime: Svchost Unregister" -Status "Fail" -Message ("Service '{0}' still present after unregister" -f $ServiceName)
                } else {
                    Write-TestResult -TestName "Runtime: Svchost Unregister" -Status "Pass" -Message ("Service '{0}' removed" -f $ServiceName)
                }
            }
        }
    } finally {
        if ($stagedSvchostDll -and (Test-Path -LiteralPath $stagedSvchostDll)) {
            Remove-Item -LiteralPath $stagedSvchostDll -Force -ErrorAction SilentlyContinue
        }
    }
}

function Ensure-RuntimeServiceAbsent {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$BinaryPath
    )

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $existing) { return $true }

    Write-Host ("[INFO] Removing existing service '{0}' before runtime validation..." -f $ServiceName) -ForegroundColor Cyan
    if (Test-Path -LiteralPath $BinaryPath) {
        try {
            & $BinaryPath "-uninstall" | Out-Null
        } catch {
            Write-Host ("[WARN] Initial uninstall attempt failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    Start-Sleep -Milliseconds 750
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        try {
            sc.exe stop $ServiceName 2>$null | Out-Null
        } catch { }
        try {
            sc.exe delete $ServiceName 2>$null | Out-Null
        } catch {
            Write-Host ("[WARN] Unable to delete service via sc.exe: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
        Start-Sleep -Milliseconds 750
    }

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return (-not $existing)
}

function Test-BinaryContainsStringAny {
    param(
        [string[]]$BinaryPaths,
        [string]$ExpectedValue,
        [string]$TestName,
        [switch]$WarnOnly
    )

    $existing = @()
    foreach ($path in $BinaryPaths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (Test-Path $path) {
            $existing += (Get-Item $path).FullName
        }
    }

    if (-not $existing) {
        Write-TestResult -TestName $TestName -Status "Fail" -Message "No binaries available to validate. Checked: $($BinaryPaths -join '; ')"
        return
    }

    foreach ($path in $existing) {
        $bytes = Get-BinaryBytes -Path $path
        if ($bytes -eq $null) { continue }

        $asciiNeedle = [System.Text.Encoding]::ASCII.GetBytes($ExpectedValue)
        $utf16Needle = [System.Text.Encoding]::Unicode.GetBytes($ExpectedValue)

        foreach ($needle in @($asciiNeedle, $utf16Needle)) {
            if ($needle.Length -eq 0 -or $needle.Length -gt $bytes.Length) { continue }
            for ($i = 0; $i -le $bytes.Length - $needle.Length; $i++) {
                $match = $true
                for ($j = 0; $j -lt $needle.Length; $j++) {
                    if ($bytes[$i + $j] -ne $needle[$j]) {
                        $match = $false
                        break
                    }
                }
                if ($match) {
                    Write-TestResult -TestName $TestName -Status "Pass" -Message ("Found in {0}" -f (Split-Path $path -Leaf))
                    return
                }
            }
        }
    }

    $message = "Expected value not found. Checked: {0}" -f ($existing -join '; ')
    if ($WarnOnly) {
        Write-TestResult -TestName $TestName -Status "Warning" -Message $message
    } else {
        Write-TestResult -TestName $TestName -Status "Fail" -Message $message
    }
}

function Test-VersionField {
    param(
        [System.Diagnostics.FileVersionInfo]$Info,
        [string]$Property,
        [string]$Expected,
        [string]$BinaryLabel,
        [string]$Description
    )

    $testName = "{0} {1} matches branding" -f $BinaryLabel, $Description
    if ([string]::IsNullOrWhiteSpace($Expected)) {
        Write-TestResult -TestName $testName -Status "Warning" -Message "Expected value missing from branding configuration"
        return
    }

    $actual = $Info.$Property
    if ($null -eq $actual) { $actual = "" }

    $normalizedExpected = $Expected.Trim() -replace '©','c'
    $normalizedActual = $actual.Trim() -replace '©','c'

    if ($normalizedActual -eq $normalizedExpected) {
        Write-TestResult -TestName $testName -Status "Pass" -Message $actual
    } else {
        if ([string]::IsNullOrWhiteSpace($actual)) { $actual = "(missing)" }
        Write-TestResult -TestName $testName -Status "Fail" -Message ("Expected {0}, found {1}" -f $Expected, $actual)
    }
}

#region Test Suite 1: File Existence and Integrity
Write-Host "Test Suite 1: File Existence and Integrity" -ForegroundColor Cyan
Write-Host "-------------------------------------------" -ForegroundColor Cyan

$x64BinaryCandidates = @(
    Join-Path $BinaryPath "MeshService64.exe"
    Join-Path $BinaryPath "MeshService-2022.exe"
    Join-Path $repoRoot "meshservice\x64\StealthLab\MeshService-2022.exe"
)
$x64Binary = Resolve-BinaryPath -Candidates $x64BinaryCandidates
$x64Size = $null

$x86BinaryCandidates = @(
    Join-Path $BinaryPath "MeshService.exe"
    Join-Path $BinaryPath "MeshService-2022.exe"
    Join-Path $repoRoot "meshservice\StealthLab\MeshService-2022.exe"
)
$x86Binary = Resolve-BinaryPath -Candidates $x86BinaryCandidates
$x86Size = $null

# Test 1.1: x64 Binary Exists
if ($x64Binary -and (Test-Path $x64Binary)) {
    $x64Item = Get-Item $x64Binary
    $x64Size = $x64Item.Length
    Write-TestResult -TestName "x64 Binary Exists" -Status "Pass" -Message ("Found at {0}" -f $x64Item.FullName) -Details "Size: $([math]::Round($x64Size/1MB,2)) MB"
} else {
    Write-TestResult -TestName "x64 Binary Exists" -Status "Fail" -Message ("Not found. Checked paths: {0}" -f ($x64BinaryCandidates -join '; '))
}

# Test 1.2: x86 Binary Exists
if ($x86Binary -and (Test-Path $x86Binary)) {
    $x86Item = Get-Item $x86Binary
    $x86Size = $x86Item.Length
    Write-TestResult -TestName "x86 Binary Exists" -Status "Pass" -Message ("Found at {0}" -f $x86Item.FullName) -Details "Size: $([math]::Round($x86Size/1MB,2)) MB"
} else {
    Write-TestResult -TestName "x86 Binary Exists" -Status "Warning" -Message ("Not found. Checked paths: {0}" -f ($x86BinaryCandidates -join '; ')) -Details "Win32 payload optional; ensure not required for this release."
}

# Test 1.3: Signature (optional)
if ($x64Binary -and (Test-Path $x64Binary)) {
    try {
        $thumb = Get-MeshAgentSignerThumbprint -Path $x64Binary
        if ($null -eq $thumb) {
            Write-TestResult -TestName "x64 Signature Allowlisted" -Status "Warning" -Message "Binary is not Authenticode signed"
        } else {
            Assert-MeshAgentThumbprintAllowed -Thumbprint $thumb -AllowedThumbprints $AllowedThumbprints
            Write-TestResult -TestName "x64 Signature Allowlisted" -Status "Pass" -Message "Thumbprint: $thumb"
        }
    } catch {
        Write-TestResult -TestName "x64 Signature Allowlisted" -Status "Warning" -Message $_.Exception.Message
    }
}

if ($x86Binary -and (Test-Path $x86Binary)) {
    try {
        $thumb = Get-MeshAgentSignerThumbprint -Path $x86Binary
        if ($null -eq $thumb) {
            Write-TestResult -TestName "x86 Signature Allowlisted" -Status "Warning" -Message "Binary is not Authenticode signed"
        } else {
            Assert-MeshAgentThumbprintAllowed -Thumbprint $thumb -AllowedThumbprints $AllowedThumbprints
            Write-TestResult -TestName "x86 Signature Allowlisted" -Status "Pass" -Message "Thumbprint: $thumb"
        }
    } catch {
        Write-TestResult -TestName "x86 Signature Allowlisted" -Status "Warning" -Message $_.Exception.Message
    }
}

# Test 1.4: File Size Validation
if ($x64Binary -and $x64Size) {
    if ($x64Size -gt 3MB -and $x64Size -lt 10MB) {
        Write-TestResult -TestName "x64 Binary Size Valid" -Status "Pass" -Message "$([math]::Round($x64Size/1MB,2)) MB (expected 3-10 MB)"
    } else {
        Write-TestResult -TestName "x64 Binary Size Valid" -Status "Warning" -Message "$([math]::Round($x64Size/1MB,2)) MB (unusual size)"
    }
}

if ($x86Binary -and $x86Size) {
    if ($x86Size -gt 3MB -and $x86Size -lt 10MB) {
        Write-TestResult -TestName "x86 Binary Size Valid" -Status "Pass" -Message "$([math]::Round($x86Size/1MB,2)) MB (expected 3-10 MB)"
    } else {
        Write-TestResult -TestName "x86 Binary Size Valid" -Status "Warning" -Message "$([math]::Round($x86Size/1MB,2)) MB (unusual size)"
    }
}

# Test 1.5: PE Header Validation
if ($x64Binary -and (Test-Path $x64Binary)) {
    $peHeader = Get-BinaryBytes -Path $x64Binary
    if ($peHeader -and $peHeader.Length -ge 2 -and $peHeader[0] -eq 0x4D -and $peHeader[1] -eq 0x5A) {
        Write-TestResult -TestName "x64 PE Header Valid" -Status "Pass" -Message "Valid PE signature (MZ)"
    } else {
        Write-TestResult -TestName "x64 PE Header Valid" -Status "Fail" -Message "Invalid PE signature"
    }
}

if ($x86Binary -and (Test-Path $x86Binary)) {
    $peHeader = Get-BinaryBytes -Path $x86Binary
    if ($peHeader -and $peHeader.Length -ge 2 -and $peHeader[0] -eq 0x4D -and $peHeader[1] -eq 0x5A) {
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

if (-not $brandingConfigPath) {
    $brandingConfigPath = Join-Path $PSScriptRoot "branding_config.json"
}
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
    Write-TestResult -TestName "Branding Config Exists" -Status "Fail" -Message "Branding configuration not found at $brandingConfigPath"
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

#region Test Suite 2: Branding Consistency
Write-Host "Test Suite 2: Branding Consistency" -ForegroundColor Cyan
Write-Host "----------------------------------" -ForegroundColor Cyan

if ($brandingConfig) {
    if (Test-Path $mshPath) {
        $mshContent = Get-Content $mshPath
        $mshMap = @{}
        foreach ($line in $mshContent) {
            if ($line -match '^\s*([^=]+)=(.*)$') {
                $mshMap[$Matches[1]] = $Matches[2]
            }
        }

        $expectedServiceName = $brandingConfig.branding.serviceName
        $expectedDisplayName = $brandingConfig.branding.displayName

        if (($mshMap.ContainsKey('meshServiceName')) -and ($mshMap['meshServiceName'] -eq $expectedServiceName)) {
            Write-TestResult -TestName "MSH meshServiceName matches branding" -Status "Pass" -Message $expectedServiceName
        } else {
            Write-TestResult -TestName "MSH meshServiceName matches branding" -Status "Fail" -Message ("Expected {0}, found {1}" -f $expectedServiceName, ($mshMap['meshServiceName']))
        }

        if (($mshMap.ContainsKey('displayName')) -and ($mshMap['displayName'] -eq $expectedDisplayName)) {
            Write-TestResult -TestName "MSH displayName matches branding" -Status "Pass" -Message $expectedDisplayName
        } else {
            Write-TestResult -TestName "MSH displayName matches branding" -Status "Fail" -Message ("Expected {0}, found {1}" -f $expectedDisplayName, ($mshMap['displayName']))
        }
    } else {
        Write-TestResult -TestName "WinDiagnosticHost.msh present" -Status "Warning" -Message "Provisioning file not found at $mshPath"
    }

    $expectedServerHash = $brandingConfig.security.serverCertHash
    $serviceName = $brandingConfig.branding.serviceName
    $displayName = $brandingConfig.branding.displayName
    $expectedMeshId = $brandingConfig.provisioning.meshId

    $binarySet = @()
    $exeBinaries = @()
    if ($x64Binary) { $binarySet += $x64Binary; $exeBinaries += $x64Binary }
    if ($x86Binary) { $binarySet += $x86Binary; $exeBinaries += $x86Binary }
    $diagsvcCandidates = @(
        Join-Path $BinaryPath "diagsvc.dll"
        Join-Path $BinaryPath "MeshService-2022.dll"
        Join-Path $repoRoot "meshservice\x64\StealthLab_DLL\MeshService-2022.dll"
    )
    $diagsvcBinary = Resolve-BinaryPath -Candidates $diagsvcCandidates
    if ($diagsvcBinary) { $binarySet += $diagsvcBinary }

    foreach ($binary in $exeBinaries) {
        $manifestPath = [System.IO.Path]::ChangeExtension($binary, '.msh')
        $testName = ("Provisioning manifest staged ({0})" -f (Split-Path -Leaf $binary))
        if (Test-Path -LiteralPath $manifestPath) {
            Write-TestResult -TestName $testName -Status "Pass" -Message ("Found at {0}" -f $manifestPath)
        } else {
            Write-TestResult -TestName $testName -Status "Fail" -Message ("Missing at {0}" -f $manifestPath)
        }
    }

    if ($expectedServerHash) {
        Test-BinaryContainsStringAny -BinaryPaths $binarySet -ExpectedValue $expectedServerHash -TestName "Binaries embed ServerID" -WarnOnly
    }
    if ($serviceName) {
        Test-BinaryContainsStringAny -BinaryPaths $binarySet -ExpectedValue $serviceName -TestName "Binaries embed ServiceName"
    }
    if ($displayName) {
        Test-BinaryContainsStringAny -BinaryPaths $binarySet -ExpectedValue $displayName -TestName "Binaries embed DisplayName"
    }
    if ($expectedMeshId) {
        Test-BinaryContainsStringAny -BinaryPaths $binarySet -ExpectedValue $expectedMeshId -TestName "Binaries embed MeshID" -WarnOnly
    }

    Write-Host ""
} else {
    Write-TestResult -TestName "Branding configuration available" -Status "Warning" -Message "Branding configuration missing; branding consistency checks skipped."
    Write-Host ""
}
#endregion

if ($RuntimeValidation) {
    Write-Host "Test Suite 3: Runtime Validation" -ForegroundColor Cyan
    Write-Host "---------------------------------" -ForegroundColor Cyan

    function Write-RuntimeSkipResults([string]$Reason) {
        Write-TestResult -TestName "Runtime: Install" -Status "Warning" -Message ("Skipped: {0}" -f $Reason)
        Write-TestResult -TestName "Runtime: Service State" -Status "Warning" -Message ("Skipped: {0}" -f $Reason)
        Write-TestResult -TestName "Runtime: Uninstall" -Status "Warning" -Message ("Skipped: {0}" -f $Reason)
        Write-TestResult -TestName "Runtime: Svchost Register" -Status "Warning" -Message $Reason
        Write-TestResult -TestName "Runtime: Svchost Status" -Status "Warning" -Message ("Skipped: {0}" -f $Reason)
        Write-TestResult -TestName "Runtime: Svchost Unregister" -Status "Warning" -Message ("Skipped: {0}" -f $Reason)
    }

    if (-not (Test-IsAdmin)) {
        Write-RuntimeSkipResults "Administrator privileges are required for runtime validation."
    }
    elseif (-not $brandingConfig) {
        Write-RuntimeSkipResults "Branding configuration unavailable; cannot determine service metadata."
    }
    elseif (-not $x64Binary) {
        Write-RuntimeSkipResults "x64 binary not found; cannot perform runtime validation."
    }
    else {
        try {
            Ensure-EmbeddedPayloadHeader
            $runtimeServiceName = $null
            if ($brandingConfig.branding) {
                $runtimeServiceName = ($brandingConfig.branding | Select-Object -ExpandProperty serviceFile -ErrorAction SilentlyContinue)
                if (-not $runtimeServiceName) {
                    $runtimeServiceName = ($brandingConfig.branding | Select-Object -ExpandProperty serviceName -ErrorAction SilentlyContinue)
                }
                if (-not $runtimeServiceName) {
                    $runtimeServiceName = ($brandingConfig.branding | Select-Object -ExpandProperty binaryName -ErrorAction SilentlyContinue)
                }
            }
            if ([string]::IsNullOrWhiteSpace($runtimeServiceName)) {
                $runtimeServiceName = "WinDiagnosticHost"
            }
            if (-not (Ensure-RuntimeServiceAbsent -ServiceName $runtimeServiceName -BinaryPath $x64Binary)) {
                Write-RuntimeSkipResults ("Runtime validation aborted: Unable to remove existing service '{0}'." -f $runtimeServiceName)
            }
            else {
                Invoke-RuntimeInstallValidation -BinaryPath $x64Binary -ServiceName $runtimeServiceName
                Invoke-RuntimeSvchostValidation -BinaryPath $x64Binary -ServiceName $runtimeServiceName
            }
        } catch {
            Write-RuntimeSkipResults ("Runtime validation aborted: {0}" -f $_.Exception.Message)
        }
    }

    Write-Host ""
}

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
Write-Host "  ⚠  Warnings: $($Script:TestResults.Warnings)" -ForegroundColor Yellow
Write-Host ""
$exitCode = 0
if ($Script:TestResults.Failed -gt 0) {
    Write-Host "? TEST SUITE FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Failed tests:" -ForegroundColor Red
    foreach ($test in $Script:TestResults.Tests | Where-Object { $_.Status -eq 'Fail' }) {
        Write-Host "  - $($test.Name): $($test.Message)" -ForegroundColor Red
    }
    $exitCode = 1
} elseif ($Script:TestResults.Warnings -gt 0) {
    Write-Host "??  TEST SUITE PASSED WITH WARNINGS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor Yellow
    foreach ($test in $Script:TestResults.Tests | Where-Object { $_.Status -eq 'Warning' }) {
        Write-Host "  - $($test.Name): $($test.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "? ALL TESTS PASSED" -ForegroundColor Green
}
if ($ReportPath) {
    try {
        $reportDirectory = Split-Path -Path $ReportPath -Parent
        if ($reportDirectory -and -not (Test-Path $reportDirectory)) {
            New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
        }

        $report = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
            binaryPath = $BinaryPath
            summary = [ordered]@{
                total = $total
                passed = $Script:TestResults.Passed
                failed = $Script:TestResults.Failed
                warnings = $Script:TestResults.Warnings
                exitCode = $exitCode
            }
            tests = $Script:TestResults.Tests
        }

        $report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8
    } catch {
        Write-Host ("[WARN] Unable to write verification report to {0}: {1}" -f $ReportPath, $_.Exception.Message) -ForegroundColor Yellow
    }
}
exit $exitCode
#endregion
