/*
 * MeshAgent runtime process lookup helpers
 *
 * Direct command-host execution is intentionally not supported in the
 * hosted-runtime contract.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "runtime_core.h"
#include "runtime_host_contract.h"
#include "service_utils.h"

BOOL Runtime_ExecuteCommand(const char* command, char* output, size_t outputSize)
{
    UNREFERENCED_PARAMETER(command);
    if (output != NULL && outputSize > 0) { output[0] = '\0'; }
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    ServiceUtil_DebugPrintfA("Runtime_ExecuteCommand blocked by hosted helper policy");
    return FALSE;
}

/**
 * Find a process by name.
 */
DWORD Runtime_FindProcessByName(const wchar_t* processName)
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    DWORD foundPid = 0;

    if (!processName)
    {
        return 0;
    }

    // Take snapshot of all processes.
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Get first process.
    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            // Check if process name matches.
            if (_wcsicmp(pe32.szExeFile, processName) == 0)
            {
                foundPid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return foundPid;
}

/**
 * Remote module loading is blocked by policy.
 */
BOOL Runtime_LoadRemoteModuleCompat(DWORD processId, const wchar_t* dllPath)
{
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(dllPath);
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    ServiceUtil_DebugPrintfA("Runtime_LoadRemoteModuleCompat blocked by hosted helper policy");
    return FALSE;
}

/* The loaded DLL plus the exact system service-host image identify the steady-state
 * service. The former callback is recognized only while an old binding
 * is running long enough to update or uninstall itself. */
BOOL Runtime_IsRunningServiceHost(void)
{
    wchar_t executable[MAX_PATH * 4] = {0};
    wchar_t serviceHost[MAX_PATH * 4] = {0};
    wchar_t legacyHost[MAX_PATH * 4] = {0};
    wchar_t serviceDll[MAX_PATH * 4] = {0};
    DWORD length = GetModuleFileNameW(NULL, executable, _countof(executable));
    if (!length || length >= _countof(executable)) { return FALSE; }
    if (MeshRuntimeHost_GetServiceHostPathW(serviceHost, _countof(serviceHost)) &&
        _wcsicmp(executable, serviceHost) == 0) { return TRUE; }
    return MeshRuntimeHost_GetSystemHostPathW(legacyHost, _countof(legacyHost)) &&
        _wcsicmp(executable, legacyHost) == 0 &&
        ServiceHost_ParseImagePath(GetCommandLineW(), serviceDll, _countof(serviceDll));
}
