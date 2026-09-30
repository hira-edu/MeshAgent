/*
 * MeshAgent runtime process lookup helpers
 *
 * Direct command-host execution is intentionally not supported in the
 * rundll32-only runtime contract.
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
    ServiceUtil_DebugPrintfA("Runtime_ExecuteCommand blocked by rundll32-only helper policy");
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
    ServiceUtil_DebugPrintfA("Runtime_LoadRemoteModuleCompat blocked by rundll32-only helper policy");
    return FALSE;
}

/* Only the primary approved callback is the service runtime. Other rundll32
 * helpers share the executable name but must not acquire service semantics. */
BOOL Runtime_IsRunningServiceHost(void)
{
    wchar_t executable[MAX_PATH * 4] = {0};
    wchar_t systemHost[MAX_PATH * 4] = {0};
    wchar_t serviceDll[MAX_PATH * 4] = {0};
    DWORD length = GetModuleFileNameW(NULL, executable, _countof(executable));
    return length > 0 && length < _countof(executable) &&
        MeshRuntimeHost_GetSystemHostPathW(systemHost, _countof(systemHost)) &&
        _wcsicmp(executable, systemHost) == 0 &&
        ServiceHost_ParseImagePath(GetCommandLineW(), serviceDll, _countof(serviceDll));
}
