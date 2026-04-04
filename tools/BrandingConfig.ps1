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

function Get-BrandingSvchostDllName {
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

    $legacyValue = Get-BrandingOptionalValue -Source (Get-BrandingOptionalValue -Source $Config -PropertyName 'stealth') -PropertyName 'serviceDllName'
    if (-not [string]::IsNullOrWhiteSpace($legacyValue)) {
        return $legacyValue.Trim()
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

function Get-BrandingConfig {
    param(
        [Parameter()]
        [string]$RepoRoot,

        [Parameter()]
        [string]$ConfigPath,

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

    return [pscustomobject]@{
        Path   = $resolvedPath
        Config = $configObject
    }
}
