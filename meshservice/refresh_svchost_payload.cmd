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

if not exist "%DLL_PATH%" (
    echo [refresh_svchost_payload] ERROR: Missing payload DLL "%DLL_PATH%".
    echo [refresh_svchost_payload] Build configuration StealthLab_DLL^|x64 before StealthLab^|x64.
    exit /b 1
)

py -3 "%REPO_ROOT%\tools\refresh_svchost_payload.py" --repo-root "%REPO_ROOT%" --dll "%DLL_PATH%"
if errorlevel 1 (
    echo [refresh_svchost_payload] ERROR: Payload refresh failed.
    exit /b 1
)

echo [refresh_svchost_payload] Synced payload from "%DLL_PATH%".
exit /b 0
