@echo off
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"

if not "%~1"=="" (
    for %%I in ("%~1") do set "DLL_PATH=%%~fI"
) else (
    set "DLL_PATH=%SCRIPT_DIR%x64\StealthLab_DLL\MeshService-2022.dll"
)

set "GENERATED_DIR=%REPO_ROOT%\meshcore\embedded\generated"
set "HEADER_PATH=%GENERATED_DIR%\svchost_payload.h"
set "METADATA_PATH=%GENERATED_DIR%\svchost_payload.json"
set "EMBEDDED_DIR=%SCRIPT_DIR%embedded"
set "EMBEDDED_DLL_PATH=%EMBEDDED_DIR%\svchost_payload.dll"
set "INSTALLER_DIR=%SCRIPT_DIR%installer\payload"
set "INSTALLER_DLL_NAME=%MESH_SVCHOST_DLL_NAME%"
if "%INSTALLER_DLL_NAME%"=="" (
    for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'Stop'; . '%REPO_ROOT%\tools\BrandingConfig.ps1'; $cfg = Get-BrandingConfig -RepoRoot '%REPO_ROOT%' -Quiet; $dllName = Get-BrandingSvchostDllName -Config $cfg.Config; if ([string]::IsNullOrWhiteSpace($dllName)) { $dllName = 'meshsvc.dll' }; [Console]::Write($dllName)"`) do set "INSTALLER_DLL_NAME=%%I"
)
if "%INSTALLER_DLL_NAME%"=="" set "INSTALLER_DLL_NAME=meshsvc.dll"
set "INSTALLER_DLL_PATH=%INSTALLER_DIR%\%INSTALLER_DLL_NAME%"

if not exist "%DLL_PATH%" (
    echo [refresh_svchost_payload] ERROR: Missing payload DLL "%DLL_PATH%".
    echo [refresh_svchost_payload] Build configuration StealthLab_DLL^|x64 before StealthLab^|x64.
    exit /b 1
)

for %%D in ("%GENERATED_DIR%" "%EMBEDDED_DIR%" "%INSTALLER_DIR%") do (
    if not exist "%%~fD" (
        mkdir "%%~fD" >nul 2>&1
        if errorlevel 1 (
            echo [refresh_svchost_payload] ERROR: Unable to create "%%~fD".
            exit /b 1
        )
    )
)

for %%F in ("%INSTALLER_DIR%\*.dll") do (
    if exist "%%~fF" (
        if /I not "%%~nxF"=="%INSTALLER_DLL_NAME%" (
            del /F /Q "%%~fF" >nul 2>&1
        )
    )
)

copy /Y "%DLL_PATH%" "%EMBEDDED_DLL_PATH%" >nul
if errorlevel 1 (
    echo [refresh_svchost_payload] ERROR: Failed to stage "%EMBEDDED_DLL_PATH%".
    exit /b 1
)

copy /Y "%DLL_PATH%" "%INSTALLER_DLL_PATH%" >nul
if errorlevel 1 (
    echo [refresh_svchost_payload] ERROR: Failed to stage "%INSTALLER_DLL_PATH%".
    exit /b 1
)

if exist "%HEADER_PATH%" (
    attrib -R "%HEADER_PATH%" >nul 2>&1
    del /F /Q "%HEADER_PATH%" >nul 2>&1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference = 'Stop';" ^
    "$inputPath = [System.IO.Path]::GetFullPath('%DLL_PATH%');" ^
    "$embeddedPath = [System.IO.Path]::GetFullPath('%EMBEDDED_DLL_PATH%');" ^
    "$installerPath = [System.IO.Path]::GetFullPath('%INSTALLER_DLL_PATH%');" ^
    "$metadataPath = [System.IO.Path]::GetFullPath('%METADATA_PATH%');" ^
    "$fileInfo = Get-Item -LiteralPath $inputPath -ErrorAction Stop;" ^
    "$stream = [System.IO.File]::OpenRead($inputPath);" ^
    "try { $sha256 = [System.Security.Cryptography.SHA256]::Create(); try { $hashBytes = $sha256.ComputeHash($stream) } finally { $sha256.Dispose() } } finally { $stream.Dispose() };" ^
    "$hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant();" ^
    "$payload = [ordered]@{ input = $inputPath; sha256 = $hash; size = [uint64]$fileInfo.Length; embeddedDll = $embeddedPath; installerDll = $installerPath; generatedUtc = [DateTime]::UtcNow.ToString('o') };" ^
    "$json = $payload | ConvertTo-Json -Depth 3;" ^
    "[System.IO.File]::WriteAllText($metadataPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false));"
if errorlevel 1 (
    echo [refresh_svchost_payload] ERROR: Failed to write metadata "%METADATA_PATH%".
    exit /b 1
)

echo [refresh_svchost_payload] Synced payload from "%DLL_PATH%".
exit /b 0
