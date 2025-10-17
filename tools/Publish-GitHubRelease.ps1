param(
  [Parameter(Mandatory=$true)][string]$Owner,
  [Parameter(Mandatory=$true)][string]$Repo,
  [Parameter(Mandatory=$true)][string]$Tag,
  [Parameter(Mandatory=$false)][string]$Title = $Tag,
  [Parameter(Mandatory=$false)][string]$Notes = "",
  [Parameter(Mandatory=$true)][string]$AssetPath
)

$ErrorActionPreference = 'Stop'

function Ensure-File([string]$p) {
  if (!(Test-Path -LiteralPath $p)) { throw "File not found: $p" }
  return (Resolve-Path -LiteralPath $p).Path
}

$asset = Ensure-File $AssetPath
$assetName = (Get-Item -LiteralPath $asset).Name

Write-Host "Owner/Repo: $Owner/$Repo" -ForegroundColor Cyan
Write-Host "Tag: $Tag" -ForegroundColor Cyan
Write-Host "Asset: $assetName" -ForegroundColor Cyan

# Prefer GitHub CLI if available and authenticated
if (Get-Command gh -ErrorAction SilentlyContinue) {
  Write-Host "Using GitHub CLI (gh) to publish release..." -ForegroundColor Yellow
  $args = @('release','create', $Tag, $asset, '-t', $Title, '-n', $Notes, '-R', "$Owner/$Repo")
  & gh @args
  if ($LASTEXITCODE -ne 0) { throw "gh release create failed with exit code $LASTEXITCODE" }
  Write-Host "Release published via gh." -ForegroundColor Green
  exit 0
}

# Fallback to REST API using token
$token = $env:GH_TOKEN
if (-not $token) { $token = $env:GITHUB_TOKEN }
if (-not $token) { throw "Missing token. Set GH_TOKEN or GITHUB_TOKEN to a PAT with repo scope." }

$headers = @{ Authorization = "Bearer $token"; 'User-Agent' = 'Publish-GitHubRelease.ps1' }
$apiBase = "https://api.github.com/repos/$Owner/$Repo"

Write-Host "Creating release via REST API..." -ForegroundColor Yellow
$body = @{ tag_name=$Tag; name=$Title; body=$Notes; draft=$false; prerelease=$false } | ConvertTo-Json
$rel = Invoke-RestMethod -Method POST -Uri "$apiBase/releases" -Headers $headers -ContentType 'application/json' -Body $body

$uploadUrl = $rel.upload_url -replace '{.*}$',''
if (-not $uploadUrl) { throw "Upload URL not found in release response" }

Write-Host "Uploading asset $assetName..." -ForegroundColor Yellow
$uploadUri = "$uploadUrl?name=$([uri]::EscapeDataString($assetName))"
$bytes = [System.IO.File]::ReadAllBytes($asset)
Invoke-RestMethod -Method POST -Uri $uploadUri -Headers $headers -ContentType 'application/zip' -Body $bytes | Out-Null

Write-Host "Release published via REST API." -ForegroundColor Green
