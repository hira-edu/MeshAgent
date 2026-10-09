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

.PARAMETER MeshCentralAgentUrl
    Optional URL for downloading an agent from MeshCentral (e.g. http://127.0.0.1:3000/meshagents?id=4)
    so the script can verify the served binary matches the local build.

.PARAMETER MeshCentralUseProvisioning
    When specified with MeshCentralAgentUrl, appends provisioning query parameters (meshid/serverid/etc.)
    from branding_config.local.json so MeshCentral returns a fully provisioned agent.

.PARAMETER MeshCentralMeshId
    Mesh identifier (e.g. mesh//abcd...) to download via meshctrl with credentials.

.PARAMETER MeshCentralControlUrl
    MeshCentral WebSocket control URL (default ws://127.0.0.1:3000) used with meshctrl downloads.

.PARAMETER MeshCentralLoginUser
    Username for meshctrl AgentDownload (required when MeshCentralMeshId is provided).

.PARAMETER MeshCentralLoginPass
    Password for meshctrl AgentDownload (required when MeshCentralMeshId is provided).

.PARAMETER MeshCtrlPath
    Optional explicit path to meshctrl.js (defaults to ..\MeshCentral\meshctrl.js).

.PARAMETER BrandingConfigPath
    Branding configuration used for package validation and child runtime checks.

.PARAMETER RuntimeDllPath
    Explicit service bundle DLL for the grouped runtime lifecycle checks.

.PARAMETER RuntimeEvidencePath
    Evidence directory for grouped regression results. Defaults to artifacts/validation/runtime.

.EXAMPLE
    .\test.ps1
    Run all tests with summary output

.EXAMPLE
    .\test.ps1 -Verbose
    Run all tests with detailed output

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
[switch]$RuntimeValidation,

[Parameter()]
[string]$BrandingConfigPath,

[Parameter()]
[string]$RuntimeDllPath,

[Parameter()]
[string]$RuntimeEvidencePath,

[Parameter()]
[string]$MeshCentralAgentUrl,

[Parameter()]
[switch]$MeshCentralUseProvisioning,

[Parameter()]
[string]$MeshCentralMeshId,

[Parameter()]
[string]$MeshCentralControlUrl = "ws://127.0.0.1:3000",

[Parameter()]
[string]$MeshCentralLoginUser,

[Parameter()]
[string]$MeshCentralLoginPass,

[Parameter()]
[string]$MeshCtrlPath
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
$resolvedBrandingConfigPath = $null
try {
    $brandingConfigInfo = Get-BrandingConfig -RepoRoot $repoRoot -ConfigPath $BrandingConfigPath -Quiet
    $resolvedBrandingConfigPath = $brandingConfigInfo.Path
    $brandingConfig = $brandingConfigInfo.Config
} catch {
    Write-Host ("[WARN] Unable to load branding configuration: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}
if (-not $brandingConfig) {
    Write-Host "[WARN] Branding configuration missing; branding consistency checks will be skipped." -ForegroundColor Yellow
}

$mshFileName = if ($env:MESH_MSH_FILENAME) { $env:MESH_MSH_FILENAME } else { 'meshagent.msh' }
$mshPath = Join-Path $repoRoot $mshFileName

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

function Get-MeshCentralAgentDownload {
    param(
        [string]$AgentUrl,
        [string]$MeshCentralMeshId,
        [string]$MeshCentralControlUrl,
        [string]$MeshCentralLoginUser,
        [string]$MeshCentralLoginPass,
        [string]$MeshCtrlPath
    )

    $hasMeshId = -not [string]::IsNullOrWhiteSpace($MeshCentralMeshId)
    $hasMeshCredentials = (-not [string]::IsNullOrWhiteSpace($MeshCentralLoginUser)) -and (-not [string]::IsNullOrWhiteSpace($MeshCentralLoginPass))

    if ($hasMeshId -and -not $hasMeshCredentials) {
        throw "MeshCentralMeshId requires both MeshCentralLoginUser and MeshCentralLoginPass."
    }

    if ($hasMeshId -and $hasMeshCredentials) {
        $meshCtrl = $MeshCtrlPath
        if ([string]::IsNullOrWhiteSpace($meshCtrl)) {
            $candidate = Join-Path (Split-Path $repoRoot -Parent) "MeshCentral\meshctrl.js"
            if (Test-Path -LiteralPath $candidate) { $meshCtrl = $candidate }
        }
        if (-not (Test-Path -LiteralPath $meshCtrl)) {
            throw "meshctrl.js not found. Provide -MeshCtrlPath."
        }

        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("MeshCtrlDownload_{0}" -f ([guid]::NewGuid().ToString("N")))
        [System.IO.Directory]::CreateDirectory($tempDir) | Out-Null
        try {
            $arguments = @(
                $meshCtrl,
                'AgentDownload',
                '--loginuser', $MeshCentralLoginUser,
                '--loginpass', $MeshCentralLoginPass,
                '--url', $MeshCentralControlUrl,
                '--id', $MeshCentralMeshId,
                '--type', '4'
            )

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'node'
            $psi.WorkingDirectory = $tempDir
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.Arguments = [string]::Join(' ', $arguments)

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi
            $null = $proc.Start()
            $stdout = $proc.StandardOutput.ReadToEnd()
            $stderr = $proc.StandardError.ReadToEnd()
            $proc.WaitForExit()

            $match = [regex]::Match($stdout, 'Downloaded .* to \"(.*)\"')
            if (-not $match.Success) {
                throw ("meshctrl AgentDownload failed. Output:`n{0}``n{1}" -f $stdout, $stderr)
            }
            $fileName = $match.Groups[1].Value
            $downloadPath = Join-Path $tempDir $fileName
            if (-not (Test-Path -LiteralPath $downloadPath)) {
                throw "meshctrl reported '$fileName' but file not found."
            }
            $bytes = [System.IO.File]::ReadAllBytes($downloadPath)
            return @{ Bytes = $bytes; Message = ("Downloaded {0} byte(s) via meshctrl" -f $bytes.Length) }
        } finally {
            try { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        }
    } elseif ($AgentUrl) {
        $tempFile = New-TemporaryFile
        try {
            Invoke-WebRequest -Uri $AgentUrl -OutFile $tempFile -UseBasicParsing | Out-Null
            $bytes = [System.IO.File]::ReadAllBytes($tempFile)
            return @{ Bytes = $bytes; Message = ("Downloaded agent ({0} bytes)" -f $bytes.Length) }
        } finally {
            if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
        }
    }

    return $null
}

function Get-MeshCentralProvisionedUrl {
    param(
        [string]$BaseUrl,
        [object]$Provisioning
    )

    if (-not $Provisioning) { return $BaseUrl }

    try {
        Add-Type -AssemblyName System.Web -ErrorAction Stop
    } catch {
        Write-Host "[WARN] Unable to load System.Web for query manipulation; using base MeshCentral URL." -ForegroundColor Yellow
        return $BaseUrl
    }

    $builder = New-Object System.UriBuilder($BaseUrl)
    $query = [System.Web.HttpUtility]::ParseQueryString($builder.Query)

    function Get-ProvisioningValue {
        param($obj, [string]$name)
        if (-not $obj) { return $null }
        $prop = $obj.PSObject.Properties[$name]
        if ($prop) { return $prop.Value }
        return $null
    }

    $meshId = Get-ProvisioningValue -obj $Provisioning -name 'meshId'
    $serverId = Get-ProvisioningValue -obj $Provisioning -name 'serverId'
    $meshName = Get-ProvisioningValue -obj $Provisioning -name 'meshName'
    $meshType = Get-ProvisioningValue -obj $Provisioning -name 'meshType'
    $installFlags = Get-ProvisioningValue -obj $Provisioning -name 'installFlags'
    $tag = Get-ProvisioningValue -obj $Provisioning -name 'tag'

    if ($meshId) { $query["meshid"] = $meshId }
    if ($serverId) { $query["serverid"] = $serverId }
    if ($meshName) { $query["meshname"] = $meshName }
    if ($meshType) { $query["meshtype"] = $meshType }
    if ($installFlags) { $query["installflags"] = $installFlags }
    if ($tag) { $query["tag"] = $tag }

    $builder.Query = $query.ToString()
    return $builder.Uri.AbsoluteUri
}

function Convert-MshTextToDictionary {
    param([string]$Text)

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return $map }

    $lines = $Text -split "(`r`n|`n)"
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $index = $line.IndexOf('=')
        if ($index -lt 0) { continue }
        $key = $line.Substring(0, $index).Trim()
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $value = ''
        if ($line.Length -gt $index + 1) {
            $value = $line.Substring($index + 1).Trim()
        }
        $map[$key] = $value
    }

    return $map
}

function Get-ByteArrayHash {
    param([byte[]]$Bytes)

    if (-not $Bytes) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    return $hash.ToUpperInvariant()
}

function Get-PeCertificateTableInfo {
    param([byte[]]$Bytes)

    if (!$Bytes -or ($Bytes.Length -lt 0x40)) { return $null }

    try {
        $eLfanew = [System.BitConverter]::ToInt32($Bytes, 0x3C)
        $ntHeaderOffset = $eLfanew
        if ($ntHeaderOffset -lt 0 -or ($ntHeaderOffset + 0x18) -gt ($Bytes.Length - 2)) { return $null }

        $optionalHeaderOffset = $ntHeaderOffset + 4 + 20
        if ($optionalHeaderOffset -lt 0 -or ($optionalHeaderOffset + 2) -gt ($Bytes.Length)) { return $null }

        $magic = [System.BitConverter]::ToUInt16($Bytes, $optionalHeaderOffset)
        $directoryTableBase = if ($magic -eq 0x20B) { 0x70 } else { 0x60 }
        $dataDirectoryOffset = $optionalHeaderOffset + $directoryTableBase
        $certDirectoryOffset = $dataDirectoryOffset + (8 * 4)

        if (($certDirectoryOffset + 8) -gt $Bytes.Length) { return $null }

        $certTableOffset = [System.BitConverter]::ToUInt32($Bytes, $certDirectoryOffset)
        $certDirSizeOffset = $certDirectoryOffset + 4
        if ($certTableOffset -eq 0 -or ($certTableOffset + 4) -gt $Bytes.Length) { return $null }

        return [pscustomobject]@{
            CertDirSizeOffset  = [int]$certDirSizeOffset
            CertDwLengthOffset = [int]$certTableOffset
        }
    } catch {
        return $null
    }
}

function Normalize-AgentCertificateTable {
    param(
        [byte[]]$Bytes,
        [uint32]$Delta
    )

    if (!$Bytes) { return $null }
    if ($Delta -le 0) {
        $clone = New-Object byte[] $Bytes.Length
        [Array]::Copy($Bytes, $clone, $Bytes.Length)
        return $clone
    }

    $info = Get-PeCertificateTableInfo -Bytes $Bytes
    if ($null -eq $info) { return $null }

    $dirSize = [System.BitConverter]::ToUInt32($Bytes, $info.CertDirSizeOffset)
    $dwLength = [System.BitConverter]::ToUInt32($Bytes, $info.CertDwLengthOffset)
    if (($dirSize -lt $Delta) -or ($dwLength -lt $Delta)) { return $null }

    $normalized = New-Object byte[] $Bytes.Length
    [Array]::Copy($Bytes, $normalized, $Bytes.Length)
    [System.BitConverter]::GetBytes([uint32]($dirSize - $Delta)).CopyTo($normalized, $info.CertDirSizeOffset)
    [System.BitConverter]::GetBytes([uint32]($dwLength - $Delta)).CopyTo($normalized, $info.CertDwLengthOffset)
    return $normalized
}

function Invoke-MeshCentralDownloadValidation {
    param(
        [Parameter(Mandatory = $true)][byte[]]$DownloadedBytes,
        [Parameter(Mandatory = $true)][string]$ReferenceBinary,
        [Parameter(Mandatory = $true)][string]$LocalMshPath
    )

    if (-not (Test-Path -LiteralPath $ReferenceBinary)) {
        Write-TestResult -TestName "MeshCentral Download" -Status "Warning" -Message "Reference binary not found; skipping MeshCentral verification."
        return
    }

    try {
        $referenceHash = (Get-FileHash -LiteralPath $ReferenceBinary -Algorithm SHA256).Hash.ToUpperInvariant()
        $downloadBytes = $DownloadedBytes
        if ($downloadBytes.Length -lt 20) { throw "Downloaded agent is too small to contain embedded data." }

        $lengthBytes = New-Object byte[] 4
        [Array]::Copy($downloadBytes, $downloadBytes.Length - 20, $lengthBytes, 0, 4)
        [Array]::Reverse($lengthBytes)
        $embeddedLength = [System.BitConverter]::ToUInt32($lengthBytes, 0)

        if ($embeddedLength -le 0 -or $embeddedLength -gt $downloadBytes.Length) {
            throw "Invalid embedded MSH length ($embeddedLength)."
        }

        $referenceSize = (Get-Item -LiteralPath $ReferenceBinary).Length
        $padding = $downloadBytes.Length - ($referenceSize + $embeddedLength + 20)
        if ($padding -lt 0) { $padding = 0 }

        $trimLength = $downloadBytes.Length - ($embeddedLength + 20 + $padding)
        if ($trimLength -le 0) {
            throw "Calculated trimmed length invalid ($trimLength)."
        }

        $trimmedBytes = New-Object byte[] $trimLength
        [Array]::Copy($downloadBytes, 0, $trimmedBytes, 0, $trimLength)
        $trimmedHashUpper = Get-ByteArrayHash -Bytes $trimmedBytes

        $hashesMatch = $trimmedHashUpper -eq $referenceHash
        $certDelta = [uint32]($embeddedLength + 20 + $padding)
        $normalizedMessage = $null

        if (-not $hashesMatch -and $certDelta -gt 0) {
            $normalizedBytes = Normalize-AgentCertificateTable -Bytes $trimmedBytes -Delta $certDelta
            if ($normalizedBytes) {
                $normalizedHash = Get-ByteArrayHash -Bytes $normalizedBytes
                if ($normalizedHash -eq $referenceHash) {
                    $hashesMatch = $true
                    $normalizedMessage = ("Normalized SHA256 {0} (certificate delta {1} bytes)" -f $normalizedHash, $certDelta)
                }
            }
        }

        if ($hashesMatch) {
            $message = $normalizedMessage
            if (-not $message) { $message = ("Trimmed SHA256 {0}" -f $trimmedHashUpper) }
            Write-TestResult -TestName "MeshCentral Binary Matches MeshServiceRuntime" -Status "Pass" -Message $message
        } else {
            Write-TestResult -TestName "MeshCentral Binary Matches MeshServiceRuntime" -Status "Fail" -Message ("Expected SHA256 {0}, download trimmed SHA256 {1}" -f $referenceHash, $trimmedHashUpper)
        }

        $embeddedBytes = New-Object byte[] $embeddedLength
        [Array]::Copy($downloadBytes, $downloadBytes.Length - 20 - $embeddedLength, $embeddedBytes, 0, $embeddedLength)
        if (Test-Path -LiteralPath $LocalMshPath) {
            $embeddedText = [System.Text.Encoding]::UTF8.GetString($embeddedBytes)
            $serverMap = Convert-MshTextToDictionary -Text $embeddedText
            $localText = Get-Content -LiteralPath $LocalMshPath -Raw
            $localMap = Convert-MshTextToDictionary -Text $localText
            $differences = New-Object System.Collections.Generic.List[string]

            foreach ($key in $localMap.Keys) {
                $expected = if ($localMap[$key]) { $localMap[$key].Trim() } else { '' }
                if (-not $serverMap.ContainsKey($key)) {
                    $differences.Add(("Missing '{0}' in downloaded .msh" -f $key)) | Out-Null
                    continue
                }
                $actual = if ($serverMap[$key]) { $serverMap[$key].Trim() } else { '' }
                if (-not [string]::Equals($expected, $actual, [System.StringComparison]::Ordinal)) {
                    $differences.Add(("Field '{0}' mismatch (expected '{1}', got '{2}')" -f $key, $expected, $actual)) | Out-Null
                }
            }

            if ($differences.Count -eq 0) {
                Write-TestResult -TestName "MeshCentral Embedded MSH Matches Local" -Status "Pass" -Message ("Validated {0} provisioning fields" -f $localMap.Count)
            } else {
                $detail = [string]::Join('; ', $differences)
                Write-TestResult -TestName "MeshCentral Embedded MSH Matches Local" -Status "Fail" -Message $detail
            }
        } else {
            Write-TestResult -TestName "MeshCentral Embedded MSH Matches Local" -Status "Warning" -Message "Local meshagent.msh missing; skipped comparison."
        }
    } catch {
        Write-TestResult -TestName "MeshCentral Binary Matches MeshServiceRuntime" -Status "Warning" -Message ("MeshCentral comparison failed: {0}" -f $_.Exception.Message)
        Write-TestResult -TestName "MeshCentral Embedded MSH Matches Local" -Status "Warning" -Message "Skipped due to comparison failure."
    }
}

function Get-BrandingServiceMetadata {
    $serviceName = $null
    $serviceDisplayName = $null
    $installRoot = Join-Path $env:ProgramData "MeshAgent"
    $logDirectory = Join-Path $installRoot "logs"
    $serviceDllName = 'meshsvc.dll'
    $binaryName = 'meshagent.exe'
    $databaseName = 'meshagent.db'
    $configFileName = 'meshagent.conf'

    if ($brandingConfig -and $brandingConfig.branding) {
        $brandingProps = $brandingConfig.branding.PSObject.Properties
        if ($brandingProps['serviceName'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.branding.serviceName)) {
            $serviceName = $brandingConfig.branding.serviceName
        }
        if ($brandingProps['displayName'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.branding.displayName)) {
            $serviceDisplayName = $brandingConfig.branding.displayName
        } elseif ($brandingProps['serviceDisplayName'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.branding.serviceDisplayName)) {
            $serviceDisplayName = $brandingConfig.branding.serviceDisplayName
        }
        if ($brandingProps['installRoot'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.branding.installRoot)) {
            $installRoot = $brandingConfig.branding.installRoot.ToString().Replace('/','\')
        }
        if ($brandingProps['logPath'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.branding.logPath)) {
            $logDirectory = $brandingConfig.branding.logPath.ToString().Replace('/','\')
        } else {
            $logDirectory = Join-Path $installRoot 'logs'
        }
        if ($brandingProps['binaryName'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.branding.binaryName)) {
            $binaryName = $brandingConfig.branding.binaryName
        }
    }

    if ($brandingConfig) {
        $resolvedServiceDll = Get-BrandingServiceHostDllName -Config $brandingConfig
        if (-not [string]::IsNullOrWhiteSpace($resolvedServiceDll)) {
            $serviceDllName = $resolvedServiceDll
        }
        if ($brandingConfig.artifacts) {
            $artifactProps = $brandingConfig.artifacts.PSObject.Properties
            if ($artifactProps['databaseName'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.artifacts.databaseName)) {
                $databaseName = $brandingConfig.artifacts.databaseName
            }
            if ($artifactProps['configFileName'] -and -not [string]::IsNullOrWhiteSpace($brandingConfig.artifacts.configFileName)) {
                $configFileName = $brandingConfig.artifacts.configFileName
            }
        }
    }

    return [pscustomobject]@{
        ServiceName = $serviceName
        ServiceDisplayName = $serviceDisplayName
        InstallRoot = $installRoot
        LogDirectory = $logDirectory
        ServiceDllName = $serviceDllName
        BinaryName = $binaryName
        DatabaseName = $databaseName
        ConfigFileName = $configFileName
    }
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

function Convert-MeshIdToHexString {
    param([string]$MeshId)

    if ([string]::IsNullOrWhiteSpace($MeshId)) { return $MeshId }
    if ($MeshId.StartsWith('0x')) { return $MeshId.ToUpperInvariant() }

    try {
        $normalized = $MeshId.Replace('@', '+').Replace('$', '/')
        $bytes = [Convert]::FromBase64String($normalized)
        if ($null -eq $bytes -or $bytes.Length -eq 0) { return $MeshId }
        $hex = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
        return '0x' + $hex
    } catch {
        return $MeshId
    }
}

$script:EmbeddedBundleVerified = $false

function Ensure-EmbeddedBundleResource {
    if ($script:EmbeddedBundleVerified) { return }
    $resourcePath = Join-Path $repoRoot "meshservice\embedded\service_bundle.dll"
    if (-not (Test-Path -LiteralPath $resourcePath)) {
        throw "Embedded service bundle resource missing at $resourcePath"
    }

    $metadataPath = Join-Path $repoRoot "meshcore\embedded\generated\service_bundle.json"
    if (Test-Path -LiteralPath $metadataPath) {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($metadata -and $metadata.sha256) {
            $expected = ($metadata.sha256.ToString()).ToLowerInvariant()
            $resourceActual = ((Get-FileHash -LiteralPath $resourcePath -Algorithm SHA256).Hash).ToLowerInvariant()
            if ($expected -ne $resourceActual) {
                throw "Embedded service bundle resource hash mismatch (expected $expected, actual $resourceActual)"
            }
            if ($metadata.input -and (Test-Path -LiteralPath $metadata.input)) {
                $inputActual = ((Get-FileHash -LiteralPath $metadata.input -Algorithm SHA256).Hash).ToLowerInvariant()
                if ($expected -ne $inputActual) {
                    throw "Embedded service bundle metadata hash mismatch (source DLL drift)."
                }
            }
        }
    } else {
        Write-Warning "Service bundle metadata missing; unable to cross-check source DLL hash."
    }

    $script:EmbeddedBundleVerified = $true
}

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Invoke-GroupedRuntimeValidation {
    param(
        [string]$PackagePath,
        [string]$DllPath,
        [string]$ConfigPath,
        [string]$EvidencePath
    )
    $previousBrandingPath = $env:BRANDING_CONFIG_PATH
    try {
        if ($env:OS -ne 'Windows_NT') { throw "Runtime validation requires Windows." }
        if (-not (Test-IsAdmin)) { throw "Runtime validation requires an elevated Windows session." }
        foreach ($inputPath in @($PackagePath, $DllPath, $ConfigPath)) {
            if ([string]::IsNullOrWhiteSpace($inputPath) -or -not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
                throw "Required runtime package, DLL, or branding input is missing: $inputPath"
            }
        }
        $node = Get-Command node -CommandType Application -ErrorAction Stop
        $runner = Join-Path $repoRoot 'test/run_grouped_regression.js'
        if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw "Grouped runtime runner missing: $runner" }
        $runEvidence = Join-Path $EvidencePath ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $runEvidence -Force | Out-Null
        $env:BRANDING_CONFIG_PATH = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
        $arguments = @($runner,
            '--source-exe', (Resolve-Path -LiteralPath $PackagePath).ProviderPath,
            '--source-dll', (Resolve-Path -LiteralPath $DllPath).ProviderPath,
            '--evidence', $runEvidence)
        Push-Location $repoRoot
        try {
            & $node.Source @arguments | Out-Host
            $runnerExitCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($runnerExitCode -ne 0) { throw "Grouped runtime regression exited with code $runnerExitCode. Evidence: $runEvidence" }
        $resultsPath = Join-Path $runEvidence 'results.json'
        if (-not (Test-Path -LiteralPath $resultsPath -PathType Leaf)) { throw "Grouped runtime regression produced no results: $resultsPath" }
        $results = Get-Content -LiteralPath $resultsPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($results.allOk -ne $true -or $results.fatal) { throw "Grouped runtime regression reported failure. Evidence: $resultsPath" }
        foreach ($phase in @('package_preflight', 'js_local_tests', 'meshcentral_same_size_contracts', 'native_cli', 'gui_lifecycle')) {
            $completed = @($results.phaseResults | Where-Object { $_.name -eq $phase -and $_.passed -eq $true })
            if ($completed.Count -ne 1) { throw "Grouped runtime phase did not pass: $phase. Evidence: $resultsPath" }
        }
        Write-TestResult -TestName 'Runtime: Grouped Lifecycle' -Status 'Pass' -Message "All lifecycle phases passed. Evidence: $resultsPath"
    } catch {
        Write-TestResult -TestName 'Runtime: Grouped Lifecycle' -Status 'Fail' -Message $_.Exception.Message
    } finally {
        $env:BRANDING_CONFIG_PATH = $previousBrandingPath
    }
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
    Join-Path $repoRoot "meshservice\x64\MeshServiceRuntime\MeshService-2022.exe"
)
$x64Binary = Resolve-BinaryPath -Candidates $x64BinaryCandidates
$x64Size = $null

$x86BinaryCandidates = @(
    Join-Path $BinaryPath "MeshService.exe"
    Join-Path $BinaryPath "MeshService-2022.exe"
    Join-Path $repoRoot "meshservice\MeshServiceRuntime\MeshService-2022.exe"
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
    Write-TestResult -TestName "x86 Binary Exists" -Status "Warning" -Message ("Not found. Checked paths: {0}" -f ($x86BinaryCandidates -join '; ')) -Details "Win32 component optional; ensure it is not required for this release."
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

$effectiveMeshCentralUrl = $MeshCentralAgentUrl
if ($MeshCentralAgentUrl -and $MeshCentralUseProvisioning) {
    if ($brandingConfig -and $brandingConfig.provisioning) {
        $effectiveMeshCentralUrl = Get-MeshCentralProvisionedUrl -BaseUrl $MeshCentralAgentUrl -Provisioning $brandingConfig.provisioning
    } else {
        Write-Host "[WARN] Branding provisioning data missing; MeshCentral URL will be used without extra parameters." -ForegroundColor Yellow
    }
}

try {
    $download = Get-MeshCentralAgentDownload -AgentUrl $effectiveMeshCentralUrl -MeshCentralMeshId $MeshCentralMeshId -MeshCentralControlUrl $MeshCentralControlUrl -MeshCentralLoginUser $MeshCentralLoginUser -MeshCentralLoginPass $MeshCentralLoginPass -MeshCtrlPath $MeshCtrlPath
    if ($download) {
        Write-TestResult -TestName "MeshCentral Download" -Status "Pass" -Message $download.Message
        Invoke-MeshCentralDownloadValidation -DownloadedBytes $download.Bytes -ReferenceBinary $x64Binary -LocalMshPath $mshPath
    }
} catch {
    Write-TestResult -TestName "MeshCentral Download" -Status "Warning" -Message ("Unable to download agent: {0}" -f $_.Exception.Message)
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

if (-not $resolvedBrandingConfigPath) {
    $resolvedBrandingConfigPath = Join-Path $PSScriptRoot "branding_config.json"
}
$brandingHeaderPath = Join-Path $PSScriptRoot "meshcore\generated\meshagent_branding.h"

# Test 2.1: Branding Config Exists
if (Test-Path $resolvedBrandingConfigPath) {
    Write-TestResult -TestName "Branding Config Exists" -Status "Pass" -Message "Found at $resolvedBrandingConfigPath"

    # Test 2.2: Branding Config is Valid JSON
    try {
        $brandingConfig = Get-Content -Path $resolvedBrandingConfigPath -Raw | ConvertFrom-Json
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
        $networkSection = $brandingConfig | Select-Object -ExpandProperty network -ErrorAction SilentlyContinue
        if ($null -eq $networkSection) {
            Write-TestResult -TestName "Network Endpoint Valid" -Status "Fail" -Message "Network section missing from branding configuration"
        } else {
            $hasPrimaryProperty = $networkSection.PSObject.Properties.Match('primaryEndpoint').Count -gt 0
            $primaryEndpointValue = if ($hasPrimaryProperty) { $networkSection.primaryEndpoint } else { $null }
            $dynamicEnabled = $networkSection.PSObject.Properties.Match('dynamic').Count -gt 0 -and [bool]$networkSection.dynamic

            if ($dynamicEnabled -and ([string]::IsNullOrEmpty($primaryEndpointValue))) {
                Write-TestResult -TestName "Network Endpoint Valid" -Status "Pass" -Message "Dynamic MeshCentral provisioning enabled (no static endpoint embedded)"
            } elseif (-not [string]::IsNullOrWhiteSpace($primaryEndpointValue)) {
                if ($primaryEndpointValue -match '^wss?://') {
                    Write-TestResult -TestName "Network Endpoint Valid" -Status "Pass" -Message "Endpoint: $primaryEndpointValue"
                } else {
                    Write-TestResult -TestName "Network Endpoint Valid" -Status "Warning" -Message "Endpoint protocol unexpected: $primaryEndpointValue"
                }
            } else {
                Write-TestResult -TestName "Network Endpoint Valid" -Status "Fail" -Message "Network endpoint not defined"
            }
        }

    } catch {
        Write-TestResult -TestName "Branding Config Valid JSON" -Status "Fail" -Message "JSON parsing error: $_"
    }
} else {
    Write-TestResult -TestName "Branding Config Exists" -Status "Fail" -Message "Branding configuration not found at $resolvedBrandingConfigPath"
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
        Write-TestResult -TestName "meshagent.msh present" -Status "Warning" -Message "Provisioning file not found at $mshPath"
    }

    $expectedServerHash = $brandingConfig.security.serverCertHash
    $serviceName = $brandingConfig.branding.serviceName
    $displayName = $brandingConfig.branding.displayName
    $expectedMeshId = (Convert-MeshIdToHexString -MeshId $brandingConfig.provisioning.meshId)
    $serviceMetadata = Get-BrandingServiceMetadata

    $binarySet = @()
    $exeBinaries = @()
    if ($x64Binary) { $binarySet += $x64Binary; $exeBinaries += $x64Binary }
    if ($x86Binary) { $binarySet += $x86Binary; $exeBinaries += $x86Binary }
    $diagsvcCandidates = @(
        Join-Path $BinaryPath $serviceMetadata.ServiceDllName
        Join-Path $BinaryPath "MeshService-2022.dll"
        Join-Path $repoRoot "meshservice\x64\MeshServiceBundle\MeshService-2022.dll"
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
    if ([string]::IsNullOrWhiteSpace($RuntimeDllPath)) {
        $RuntimeDllPath = Resolve-BinaryPath -Candidates @(
            (Join-Path $BinaryPath 'MeshService-2022.dll'),
            (Join-Path $repoRoot 'meshservice/x64/MeshServiceBundle/MeshService-2022.dll')
        )
    }
    if ([string]::IsNullOrWhiteSpace($RuntimeEvidencePath)) {
        $RuntimeEvidencePath = Join-Path $repoRoot 'artifacts/validation/runtime'
    }
    Invoke-GroupedRuntimeValidation -PackagePath $x64Binary -DllPath $RuntimeDllPath -ConfigPath $resolvedBrandingConfigPath -EvidencePath $RuntimeEvidencePath
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
            brandingConfigPath = $resolvedBrandingConfigPath
            runtimeEvidencePath = $RuntimeEvidencePath
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
