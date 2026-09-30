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

/**
 * Check if currently running inside svchost.exe
 */
BOOL Runtime_IsRunningServiceHost(void)
{
    WCHAR exePath[MAX_PATH] = {0};

    // Get the path of the current process
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0)
    {
        return FALSE;
    }

    // Extract just the filename
    WCHAR* exeName = wcsrchr(exePath, L'\\');
    if (!exeName)
    {
        exeName = exePath;
    }
    else
    {
        exeName++;  // Skip the backslash
    }

    // Check if we're running as svchost.exe
    return (_wcsicmp(exeName, L"svchost.exe") == 0);
}
