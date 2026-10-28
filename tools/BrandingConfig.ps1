Set-StrictMode -Version Latest

function Get-BrandingOptionalValue {
    param(
        [Parameter()]
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

function Get-BrandingServiceHostDllName {
    param(
        [Parameter()]
        [object]$Config,

        [Parameter()]
        [string]$Default = 'meshsvc.dll'
    )

    if ($null -eq $Config) {
        return $Default
    }

    $brandingValue = Get-BrandingOptionalValue -Source (Get-BrandingOptionalValue -Source $Config -PropertyName 'branding') -PropertyName 'serviceDllName'
    if (-not [string]::IsNullOrWhiteSpace($brandingValue)) {
        return $brandingValue.Trim()
    }

    return $Default
}

function Resolve-BrandingConfigPath {
    param(
        [Parameter()]
        [string]$RepoRoot,

        [Parameter()]
        [string]$ConfigPath,

        [switch]$Quiet
    )

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        $RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
    }
    $RepoRoot = (Resolve-Path $RepoRoot).ProviderPath
    if (-not $ConfigPath) {
        $envPath = [Environment]::GetEnvironmentVariable('BRANDING_CONFIG_PATH')
        if (-not [string]::IsNullOrWhiteSpace($envPath)) {
            $ConfigPath = $envPath
        }
    }

    if ($ConfigPath) {
        if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
            $ConfigPath = Join-Path $RepoRoot $ConfigPath
        }
        if (-not (Test-Path -LiteralPath $ConfigPath)) {
            throw "Branding configuration not found: $ConfigPath"
        }
        return (Resolve-Path $ConfigPath).ProviderPath
    }

    $candidates = @(
        (Join-Path $RepoRoot 'branding_config.local.json')
        (Join-Path $RepoRoot 'branding_config.json')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            if (-not $Quiet) {
                $name = Split-Path -Leaf $candidate
                Write-Verbose ("Using branding configuration: {0}" -f $name)
            }
            return (Resolve-Path $candidate).ProviderPath
        }
    }

    throw "No branding configuration found. Create branding_config.local.json (preferred) or branding_config.json."
}

function Resolve-MeshAgentChannel {
    param([Parameter()][string]$Channel)

    if ([string]::IsNullOrWhiteSpace($Channel)) {
        $Channel = [Environment]::GetEnvironmentVariable('MESHAGENT_CHANNEL')
    }
    if ([string]::IsNullOrWhiteSpace($Channel)) { $Channel = 'production' }
    $Channel = $Channel.Trim().ToLowerInvariant()
    if ($Channel -ne 'production' -and $Channel -ne 'preview') {
        throw "unknown build channel '$Channel'; expected production or preview"
    }
    return $Channel
}

function script:Add-PreviewToken([string]$value, [string]$suffix) {
    if ([string]::IsNullOrWhiteSpace($value)) { return $value }
    return $value + $suffix
}

function script:Insert-PreviewBeforeExt([string]$name, [string]$token) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $name }
    $dot = $name.LastIndexOf('.')
    if ($dot -le 0) { return $name + $token }
    return $name.Substring(0, $dot) + $token + $name.Substring($dot)
}

<#
    Mirror of tools/generate_branding_assets.py apply_channel(). production leaves
    the config untouched; preview derives a distinct, visibly-labelled identity.
    Kept in lockstep with the Python generator (which is the build authority);
    the identity contract test asserts the two agree.
#>
function ConvertTo-MeshAgentChannelConfig {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config,

        [Parameter()]
        [string]$Channel = 'production'
    )

    $Channel = Resolve-MeshAgentChannel -Channel $Channel
    if ($Channel -ne 'preview' -or $null -eq $Config) { return $Config }

    $identity = '2'
    $visible = ' (Preview)'
    $product = ' Preview'

    # Deep copy so the caller's object is untouched.
    $cfg = ($Config | ConvertTo-Json -Depth 64) | ConvertFrom-Json

    $b = Get-BrandingOptionalValue -Source $cfg -PropertyName 'branding'
    if ($null -ne $b) {
        if (-not [string]::IsNullOrWhiteSpace($b.serviceName)) { $b.serviceName = $b.serviceName + $identity }
        if ($b.PSObject.Properties['displayName']) { $b.displayName = Add-PreviewToken $b.displayName $visible }
        if ($b.PSObject.Properties['productName']) { $b.productName = Add-PreviewToken $b.productName $product }
        if ($b.PSObject.Properties['description']) { $b.description = Add-PreviewToken $b.description $visible }
        if ($b.PSObject.Properties['binaryName'] -and -not [string]::IsNullOrWhiteSpace($b.binaryName)) { $b.binaryName = Insert-PreviewBeforeExt $b.binaryName $identity }
        if ($b.PSObject.Properties['serviceDllName'] -and -not [string]::IsNullOrWhiteSpace($b.serviceDllName)) { $b.serviceDllName = Insert-PreviewBeforeExt $b.serviceDllName $identity }

        $oldRoot = $b.installRoot
        if (-not [string]::IsNullOrWhiteSpace($oldRoot)) {
            $newRoot = ($oldRoot.TrimEnd('/','\')) + $identity
            $b.installRoot = $newRoot
            if ($b.PSObject.Properties['logPath'] -and -not [string]::IsNullOrWhiteSpace($b.logPath)) {
                if ($b.logPath -eq $oldRoot -or $b.logPath.StartsWith($oldRoot + '/') -or $b.logPath.StartsWith($oldRoot + '\')) {
                    $b.logPath = $newRoot + $b.logPath.Substring($oldRoot.Length)
                } else {
                    $b.logPath = ($b.logPath.TrimEnd('/','\')) + $identity
                }
            }
        }

        $vi = Get-BrandingOptionalValue -Source $b -PropertyName 'versionInfo'
        if ($null -ne $vi) {
            if ($vi.PSObject.Properties['fileDescription']) { $vi.fileDescription = Add-PreviewToken $vi.fileDescription $visible }
            if ($vi.PSObject.Properties['internalName'] -and -not [string]::IsNullOrWhiteSpace($vi.internalName)) { $vi.internalName = Insert-PreviewBeforeExt $vi.internalName $identity }
            if ($vi.PSObject.Properties['originalFilename'] -and -not [string]::IsNullOrWhiteSpace($vi.originalFilename)) { $vi.originalFilename = Insert-PreviewBeforeExt $vi.originalFilename $identity }
        }
    }

    $art = Get-BrandingOptionalValue -Source $cfg -PropertyName 'artifacts'
    if ($null -ne $art) {
        foreach ($key in @('databaseName', 'configFileName', 'logFileName')) {
            if ($art.PSObject.Properties[$key] -and -not [string]::IsNullOrWhiteSpace($art.$key)) {
                $art.$key = Insert-PreviewBeforeExt $art.$key $identity
            }
        }
    }

    $pers = Get-BrandingOptionalValue -Source $cfg -PropertyName 'persistence'
    if ($null -ne $pers) {
        foreach ($taskKey in @('scheduledTask', 'serviceRecoveryTask')) {
            $task = Get-BrandingOptionalValue -Source $pers -PropertyName $taskKey
            if ($null -ne $task -and $task.PSObject.Properties['taskName'] -and -not [string]::IsNullOrWhiteSpace($task.taskName)) {
                $task.taskName = $task.taskName + $product
            }
        }
    }

    return $cfg
}

function Get-BrandingConfig {
    param(
        [Parameter()]
        [string]$RepoRoot,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$Channel,

        [switch]$Quiet
    )

    $resolvedPath = Resolve-BrandingConfigPath -RepoRoot $RepoRoot -ConfigPath $ConfigPath -Quiet:$Quiet
    try {
        $rawJson = Get-Content -LiteralPath $resolvedPath -Raw
        $configObject = $rawJson | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw ("Unable to parse branding configuration at {0}: {1}" -f $resolvedPath, $_.Exception.Message)
    }

    if ($configObject -and ($resolvedPath -like '*branding_config.json')) {
        if ($rawJson -match 'REPLACE_WITH') {
            throw "branding_config.json still contains placeholder values. Copy it to branding_config.local.json and populate real settings."
        }
    }

    $resolvedChannel = Resolve-MeshAgentChannel -Channel $Channel
    if ($resolvedChannel -eq 'preview') {
        $configObject = ConvertTo-MeshAgentChannelConfig -Config $configObject -Channel $resolvedChannel
    }

    return [pscustomobject]@{
        Path    = $resolvedPath
        Config  = $configObject
        Channel = $resolvedChannel
    }
}
