@echo off
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"

if not "%~1"=="" (
    for %%I in ("%~1") do set "DLL_PATH=%%~fI"
) else (
    set "DLL_PATH=%SCRIPT_DIR%x64\MeshServiceBundle\MeshService-2022.dll"
)

set "GENERATED_DIR=%REPO_ROOT%\meshcore\embedded\generated"
set "HEADER_PATH=%GENERATED_DIR%\service_bundle.h"
set "METADATA_PATH=%GENERATED_DIR%\service_bundle.json"
set "EMBEDDED_DIR=%SCRIPT_DIR%embedded"
set "EMBEDDED_DLL_PATH=%EMBEDDED_DIR%\service_bundle.dll"
set "INSTALLER_DIR=%SCRIPT_DIR%installer\payload"

if not exist "%DLL_PATH%" (
    echo [refresh_service_bundle] ERROR: Missing payload DLL "%DLL_PATH%".
    echo [refresh_service_bundle] Build configuration MeshServiceBundle^|x64 before MeshServiceRuntime^|x64.
    exit /b 1
)

py -3 "%REPO_ROOT%\tools\refresh_service_bundle.py" --repo-root "%REPO_ROOT%" --dll "%DLL_PATH%"
if errorlevel 1 (
    echo [refresh_service_bundle] ERROR: Payload refresh failed.
    exit /b 1
)

echo [refresh_service_bundle] Synced payload from "%DLL_PATH%".
exit /b 0
