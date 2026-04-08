Set-StrictMode -Version Latest

$brandingHelper = Join-Path $PSScriptRoot 'BrandingConfig.ps1'
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper

function Normalize-MeshAgentThumbprint {
    param([Parameter()][string]$Thumbprint)

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }

    $normalized = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($normalized.Length -ne 40) {
        throw "Thumbprint '$Thumbprint' is invalid. Expected 40 hex characters."
    }

    return $normalized
}

function Get-MeshAgentAllowedThumbprints {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
    )

    $brandingInfo = Get-BrandingConfig -RepoRoot $RepoRoot -Quiet
    $security = Get-BrandingOptionalValue -Source $brandingInfo.Config -PropertyName 'security'
    $enforceSigning = [bool](Get-BrandingOptionalValue -Source $security -PropertyName 'enforceSigning')

    Set-Variable -Scope Script -Name MeshAgentEnforceSigning -Value $enforceSigning -Force

    $allowedThumbprints = New-Object System.Collections.Generic.List[string]
    $allowedSigners = Get-BrandingOptionalValue -Source $security -PropertyName 'allowedSigners'
    if ($allowedSigners) {
        foreach ($signer in $allowedSigners) {
            $thumbprint = Get-BrandingOptionalValue -Source $signer -PropertyName 'thumbprint'
            if ([string]::IsNullOrWhiteSpace($thumbprint)) { continue }

            $normalized = Normalize-MeshAgentThumbprint -Thumbprint $thumbprint
            if (-not $allowedThumbprints.Contains($normalized)) {
                [void]$allowedThumbprints.Add($normalized)
            }
        }
    }

    return @($allowedThumbprints)
}

function Get-MeshAgentSignerThumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Binary not found: $Path"
    }

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if (-not $signature.SignerCertificate) {
        return $null
    }

    return Normalize-MeshAgentThumbprint -Thumbprint $signature.SignerCertificate.Thumbprint
}

function Assert-MeshAgentThumbprintAllowed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter()]
        [string[]]$AllowedThumbprints = @()
    )

    $normalizedThumbprint = Normalize-MeshAgentThumbprint -Thumbprint $Thumbprint
    $normalizedAllowed = @($AllowedThumbprints | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        Normalize-MeshAgentThumbprint -Thumbprint $_
    })

    if ($normalizedAllowed.Count -eq 0) {
        return $normalizedThumbprint
    }

    if ($normalizedAllowed -notcontains $normalizedThumbprint) {
        throw "Signer thumbprint '$normalizedThumbprint' is not in the MeshAgent allowlist."
    }

    return $normalizedThumbprint
}

function Assert-MeshAgentSignatureAllowed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [string[]]$AllowedThumbprints = @(),

        [Parameter()]
        [switch]$RequireSignature
    )

    $thumbprint = Get-MeshAgentSignerThumbprint -Path $Path
    if ($null -eq $thumbprint) {
        if ($RequireSignature) {
            throw "Binary '$Path' is not Authenticode signed."
        }

        return $null
    }

    return Assert-MeshAgentThumbprintAllowed -Thumbprint $thumbprint -AllowedThumbprints $AllowedThumbprints
}
