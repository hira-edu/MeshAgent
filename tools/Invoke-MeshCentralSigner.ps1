#Requires -Version 5.1
<#
.SYNOPSIS
    Optional signer hook for build_complete.ps1 that (a) calls an external signing command and
    (b) stages the MeshCentral agent payload using Prepare-MeshCentralPayload.ps1.

.DESCRIPTION
    Intended to be passed through build_complete.ps1's -SignerScript parameter. After the main build
    completes, this helper can run a signing command (signtool/authenticode/HSM) and then reuse
    Prepare-MeshCentralPayload.ps1 to copy the freshly built binaries either into a MeshCentral repo
    (for local installs) or a hand-off folder (for CI artefacts).

.PARAMETER PackageDir
    Provided by build_complete.ps1. Points at the dist/<label>/ folder that contains MeshService*.exe,
    diagsvc.dll, WinDiagnosticHost.msh, manifest, etc.

.PARAMETER Configuration
    Provided for logging only. No build logic depends on the configuration here.

.PARAMETER SigningCommand
    Optional executable (signtool, pwsh, bash wrapper, etc.) to run before staging the payload.

.PARAMETER SigningArgument
    Additional arguments forwarded to SigningCommand (array preserves ordering).

.PARAMETER MeshCentralRepo
    Path to a local MeshCentral repository. When supplied, the payload is copied directly into
    <repo>/meshcentral-data/agents so the next MeshCentral restart can re-sign the binaries.

.PARAMETER OutputRoot
    When MeshCentralRepo is not supplied (e.g., CI), stage the payload underneath this root so it can
    be zipped or published as an artefact. Defaults to ../handoff/<yyyyMMdd-HHmmss>.

.EXAMPLE
    pwsh ./build_complete.ps1 -Configuration StealthLab `
         -SignerScript ./tools/Invoke-MeshCentralSigner.ps1 `
         -SignerScriptArgument '-MeshCentralRepo','..\MeshCentral'

.EXAMPLE
    pwsh ./build_complete.ps1 -Configuration StealthLab `
         -SignerScript ./tools/Invoke-MeshCentralSigner.ps1 `
         -SignerScriptArgument '-SigningCommand','signtool','-SigningArgument','sign','/fd','sha256','/a','-OutputRoot','handoff'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [Parameter(Mandatory = $true)][string]$Configuration,
    [string]$SigningCommand,
    [string[]]$SigningArgument,
    [string]$MeshCentralRepo,
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ExistingPath {
    param([string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    return $resolved.ProviderPath
}

$packageDir = Resolve-ExistingPath $PackageDir

if ($SigningCommand) {
    Write-Host ("[Signer] {0} {1}" -f $SigningCommand, ($SigningArgument -join ' '))
    & $SigningCommand @SigningArgument
    if ($LASTEXITCODE -ne 0) {
        throw ("Signing command exited with code {0}" -f $LASTEXITCODE)
    }
} else {
    Write-Host "[Signer] No SigningCommand supplied; skipping Authenticode step." -ForegroundColor Yellow
}

$prepareScript = Join-Path $PSScriptRoot 'Prepare-MeshCentralPayload.ps1'
if (-not (Test-Path -LiteralPath $prepareScript)) {
    throw "Prepare-MeshCentralPayload.ps1 not found alongside Invoke-MeshCentralSigner.ps1"
}

$prepareArgs = @{
    PackageDir = $packageDir
}

if ($MeshCentralRepo) {
    $prepareArgs['MeshCentralRepo'] = Resolve-ExistingPath $MeshCentralRepo
    Write-Host ("[Signer] Syncing payload into {0}" -f $prepareArgs['MeshCentralRepo'])
} else {
    $root = if ($OutputRoot) { Resolve-ExistingPath $OutputRoot } else { Join-Path $PSScriptRoot '..\handoff' }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $prepareArgs['OutputRoot'] = Join-Path $root $stamp
    Write-Host ("[Signer] Staging payload under {0}" -f $prepareArgs['OutputRoot'])
}

& $prepareScript @prepareArgs
if ($LASTEXITCODE -ne 0) {
    throw ("Prepare-MeshCentralPayload.ps1 exited with code {0}" -f $LASTEXITCODE)
}

Write-Host ("[Signer] Completed MeshCentral payload staging for {0}" -f $Configuration) -ForegroundColor Green
