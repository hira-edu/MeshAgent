@echo off
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"

set "DLL_PATH=%SCRIPT_DIR%x64\StealthLab_DLL\MeshService-2022.dll"
set "BIN2H_PATH=%REPO_ROOT%\tools\bin2h\x64\Release\bin2h.exe"
set "GENERATED_DIR=%REPO_ROOT%\meshcore\embedded\generated"
set "HEADER_PATH=%GENERATED_DIR%\svchost_payload.h"
set "METADATA_PATH=%GENERATED_DIR%\svchost_payload.json"
set "EMBEDDED_DLL_PATH=%SCRIPT_DIR%embedded\svchost_payload.dll"
set "INSTALLER_DLL_PATH=%SCRIPT_DIR%installer\payload\diagsvc.dll"

if not exist "%DLL_PATH%" (
    echo [refresh_svchost_payload] ERROR: Missing payload DLL "%DLL_PATH%".
    echo [refresh_svchost_payload] Build configuration StealthLab_DLL^|x64 before StealthLab^|x64.
    exit /b 1
)

if not exist "%BIN2H_PATH%" (
    echo [refresh_svchost_payload] ERROR: Missing tool "%BIN2H_PATH%".
    echo [refresh_svchost_payload] Build tools\bin2h\x64\Release first.
    exit /b 1
)

if not exist "%GENERATED_DIR%" (
    mkdir "%GENERATED_DIR%" >nul 2>&1
    if errorlevel 1 (
        echo [refresh_svchost_payload] ERROR: Unable to create "%GENERATED_DIR%".
        exit /b 1
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

"%BIN2H_PATH%" --input "%DLL_PATH%" --output "%HEADER_PATH%" --symbol g_SvchostPayload --metadata "%METADATA_PATH%"
if errorlevel 1 (
    echo [refresh_svchost_payload] ERROR: Failed to generate embedded payload header.
    exit /b 1
)

echo [refresh_svchost_payload] Synced payload from "%DLL_PATH%".
exit /b 0
