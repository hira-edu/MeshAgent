Set-StrictMode -Version Latest

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$brandingHelper = Join-Path $scriptDir 'BrandingConfig.ps1'
if (-not (Test-Path -LiteralPath $brandingHelper)) {
    throw "Branding helper missing at $brandingHelper"
}
. $brandingHelper

$script:MeshAgentEnforceSigning = $true

function Normalize-Thumbprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    $normalized = ($Thumbprint -replace '[^0-9a-fA-F]', '').ToUpperInvariant()
    if ($normalized.Length -ne 40) { return $null }
    return $normalized
}

function Get-MeshAgentBrandingConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $configInfo = Get-BrandingConfig -RepoRoot $RepoRoot -Quiet
    $config = $configInfo.Config
    if ($config.security -and $config.security.PSObject.Properties.Name -contains 'enforceSigning') {
        $script:MeshAgentEnforceSigning = [bool]$config.security.enforceSigning
    } else {
        $script:MeshAgentEnforceSigning = $true
    }
    return $config
}

function Get-MeshAgentAllowedThumbprints {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $config = Get-MeshAgentBrandingConfig -RepoRoot $RepoRoot
    if (-not $script:MeshAgentEnforceSigning) {
        return ,@()
    }

    if (-not ($config.security) -or -not ($config.security.allowedSigners)) {
        throw "Branding configuration does not define security.allowedSigners."
    }

    $thumbprints = @()
    foreach ($signer in $config.security.allowedSigners) {
        $normalized = Normalize-Thumbprint -Thumbprint ($signer.thumbprint)
        if ($null -eq $normalized) {
            Write-Warning "Ignoring malformed thumbprint entry: '$($signer.thumbprint)'"
            continue
        }
        if (-not ($thumbprints -contains $normalized)) {
            $thumbprints += $normalized
        }
    }

    if ($thumbprints.Count -eq 0) {
        throw "No valid thumbprints in security.allowedSigners."
    }
    return $thumbprints
}

function Assert-MeshAgentThumbprintAllowed {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter()]
        [string[]]$AllowedThumbprints
    )

    if (-not $script:MeshAgentEnforceSigning) { return }

    $normalized = Normalize-Thumbprint -Thumbprint $Thumbprint
    if ($null -eq $normalized) {
        throw "Thumbprint '$Thumbprint' is not a valid 40-character hex string."
    }

    if (-not ($AllowedThumbprints -contains $normalized)) {
        throw "Thumbprint '$normalized' is not in security.allowedSigners."
    }
}

function Get-MeshAgentSignerThumbprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -eq 'NotSigned') {
        return $null
    }
    if (-not $signature.SignerCertificate) {
        throw "Failed to retrieve signer certificate for $Path (status: $($signature.Status))."
    }

    return Normalize-Thumbprint -Thumbprint $signature.SignerCertificate.Thumbprint
}

function Assert-MeshAgentSignatureAllowed {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [string[]]$AllowedThumbprints,

        [switch]$RequireSignature
    )

    if (-not $script:MeshAgentEnforceSigning) { return $true }

    $thumbprint = Get-MeshAgentSignerThumbprint -Path $Path
    if ($null -eq $thumbprint) {
        if ($RequireSignature) {
            throw "File '$Path' is not signed."
        } else {
            return $false
        }
    }

    Assert-MeshAgentThumbprintAllowed -Thumbprint $thumbprint -AllowedThumbprints $AllowedThumbprints
    return $true
}
