/*
 * Stealth Watchdog Module
 *
 * Implements mutual watchdog mesh pattern where multiple lightweight processes
 * monitor each other and respawn on termination.
 *
 * Ported from:
 * - ecraft/ecraft-watchdogservice (MIT)
 * - onewe/watchDog-windows (MIT)
 * - anodejs/hongen (MIT)
 */

#ifndef STEALTH_WATCHDOG_H
#define STEALTH_WATCHDOG_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Boot start method for persistence */
typedef enum WatchdogBootMethod {
    WATCHDOG_BOOT_NONE = 0,         /* No boot persistence */
    WATCHDOG_BOOT_SERVICE,          /* Install as Windows service */
    WATCHDOG_BOOT_RUN_KEY,          /* HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run */
    WATCHDOG_BOOT_TASK_SCHEDULER,   /* Task Scheduler at boot */
    WATCHDOG_BOOT_WINLOGON          /* Winlogon Shell/Userinit append */
} WatchdogBootMethod;

/* Configuration for watchdog behavior */
typedef struct WatchdogConfig {
    DWORD checkIntervalMs;      /* How often to check processes (default: 8000ms) */
    DWORD restartDelayMs;       /* Delay before restarting (default: 1000ms) */
    DWORD maxRestartAttempts;   /* Max restarts before backing off (default: 10) */
    DWORD backoffMultiplier;    /* Multiplier for exponential backoff (default: 2) */
    BOOL useJobObject;          /* Use Job Object for child cleanup (default: TRUE) */
    BOOL hidden;                /* Run watchdog processes hidden (default: TRUE) */
    WatchdogBootMethod bootMethod; /* Method for boot persistence (default: NONE) */
    WCHAR bootName[64];         /* Name for boot entry (service name, run key, task name) */
} WatchdogConfig;

/* Process entry for watchdog monitoring */
typedef struct WatchedProcess {
    WCHAR exePath[MAX_PATH];    /* Full path to executable */
    WCHAR arguments[512];       /* Command line arguments */
    WCHAR workingDir[MAX_PATH]; /* Working directory */
    DWORD processId;            /* Current PID (0 if not running) */
    HANDLE hProcess;            /* Process handle */
    DWORD restartCount;         /* Number of restarts */
    ULONGLONG lastRestartTime;  /* Tick count of last restart */
    BOOL enabled;               /* Whether monitoring is enabled */
} WatchedProcess;

/* Shared memory structure for inter-process heartbeat */
typedef struct WatchdogHeartbeat {
    volatile LONG status;       /* 0=initializing, 1=running, 2=stopping */
    volatile LONGLONG timestamp;/* Last heartbeat timestamp */
    DWORD ownerPid;             /* PID of heartbeat owner */
    WCHAR serviceName[64];      /* Service being monitored */
} WatchdogHeartbeat;

/* Initialize watchdog with default configuration */
void Watchdog_InitConfig(WatchdogConfig* config);

/* Start watchdog monitoring thread */
BOOL Watchdog_Start(const WatchdogConfig* config);

/* Stop watchdog monitoring */
void Watchdog_Stop(void);

/* Add a process to watch list */
BOOL Watchdog_AddProcess(
    const WCHAR* exePath,
    const WCHAR* arguments,
    const WCHAR* workingDir);

/* Remove a process from watch list */
BOOL Watchdog_RemoveProcess(
    const WCHAR* exePath,
    const WCHAR* arguments);

/* Force restart of a watched process */
BOOL Watchdog_RestartProcess(
    const WCHAR* exePath,
    const WCHAR* arguments);

/* Get status of watched process */
BOOL Watchdog_GetProcessStatus(
    const WCHAR* exePath,
    const WCHAR* arguments,
    DWORD* outPid,
    DWORD* outRestartCount);

/* Create shared memory heartbeat for current process */
BOOL Watchdog_CreateHeartbeat(
    const WCHAR* serviceName,
    HANDLE* outMapHandle);

/* Send heartbeat signal */
void Watchdog_SendHeartbeat(void);

/* Open existing heartbeat and monitor it */
BOOL Watchdog_MonitorHeartbeat(
    const WCHAR* serviceName,
    DWORD timeoutMs,
    BOOL* outIsAlive);

/* Close heartbeat resources */
void Watchdog_CloseHeartbeat(HANDLE mapHandle);

/* Install watchdog as a secondary service */
BOOL Watchdog_InstallAsService(
    const WCHAR* serviceName,
    const WCHAR* displayName,
    const WCHAR* targetServiceName);

/* Uninstall watchdog service */
BOOL Watchdog_UninstallService(const WCHAR* serviceName);

/* Run watchdog main loop (for service mode) */
void Watchdog_ServiceMain(
    const WCHAR* targetServiceName,
    const WatchdogConfig* config);

/* ================================================================
 * Boot Start Functions
 * ================================================================ */

/* Enable boot start persistence using configured method */
BOOL Watchdog_EnableBootStart(
    const WCHAR* exePath,
    const WCHAR* arguments,
    const WatchdogConfig* config);

/* Disable boot start persistence */
BOOL Watchdog_DisableBootStart(
    const WatchdogConfig* config);

/* Check if boot start is currently enabled */
BOOL Watchdog_IsBootStartEnabled(
    const WatchdogConfig* config);

/* Enable boot start via Run registry key */
BOOL Watchdog_EnableRunKey(
    const WCHAR* name,
    const WCHAR* exePath,
    const WCHAR* arguments);

/* Disable boot start via Run registry key */
BOOL Watchdog_DisableRunKey(
    const WCHAR* name);

/* Enable boot start via Task Scheduler */
BOOL Watchdog_EnableTaskScheduler(
    const WCHAR* taskName,
    const WCHAR* exePath,
    const WCHAR* arguments,
    BOOL runAtBoot,      /* TRUE for boot trigger, FALSE for logon */
    BOOL runAsSystem);   /* TRUE for SYSTEM account, FALSE for current user */

/* Disable boot start via Task Scheduler */
BOOL Watchdog_DisableTaskScheduler(
    const WCHAR* taskName);

/* Enable boot start via Winlogon Shell append */
BOOL Watchdog_EnableWinlogon(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t outSize);

/* Disable boot start via Winlogon (restore original) */
BOOL Watchdog_DisableWinlogon(
    const WCHAR* exePath,
    const WCHAR* originalValue);

/* ================================================================
 * Helper Process Monitor (for KVM/RDP session helpers)
 * ================================================================ */

/* Helper process state */
typedef enum HelperProcessState {
    HELPER_STATE_IDLE = 0,          /* Not needed, waiting for request */
    HELPER_STATE_SPAWNING,          /* Currently attempting to spawn */
    HELPER_STATE_RUNNING,           /* Helper is running and responsive */
    HELPER_STATE_FAILED,            /* Spawn failed, will retry */
    HELPER_STATE_SESSION_WAIT       /* Waiting for valid user session */
} HelperProcessState;

/* Helper process configuration */
typedef struct HelperProcessConfig {
    WCHAR exePath[MAX_PATH];        /* Path to helper executable */
    WCHAR arguments[512];           /* Command line arguments */
    DWORD targetSessionId;          /* Target session ID (-1 for active console) */
    DWORD spawnRetryDelayMs;        /* Delay between spawn retries (default: 2000ms) */
    DWORD maxSpawnRetries;          /* Max retries before extended backoff (default: 10) */
    DWORD sessionCheckIntervalMs;   /* How often to check session validity (default: 5000ms) */
    BOOL persistentSpawn;           /* Keep retrying forever (default: TRUE) */
    BOOL monitorSession;            /* Monitor for session changes (default: TRUE) */
    BOOL strictServiceOnly;         /* Block user-session spawn unless desktop bridge is explicitly allowed */
    BOOL allowDesktopBridge;        /* Allow helper session spawn for desktop bridge workflows */
} HelperProcessConfig;

/* Helper process status */
typedef struct HelperProcessStatus {
    HelperProcessState state;       /* Current state */
    DWORD processId;                /* PID if running, 0 otherwise */
    DWORD sessionId;                /* Session ID where helper is running */
    DWORD spawnAttempts;            /* Total spawn attempts */
    DWORD failureCount;             /* Consecutive failures */
    ULONGLONG lastSpawnTime;        /* Tick count of last spawn attempt */
    ULONGLONG lastSuccessTime;      /* Tick count of last successful spawn */
    DWORD lastError;                /* Last Win32 error code */
    WCHAR lastErrorMessage[256];    /* Human-readable error message */
} HelperProcessStatus;

/* Callback for helper process events */
typedef void (*HelperProcessCallback)(
    HelperProcessState newState,
    const HelperProcessStatus* status,
    void* userData);

/* Initialize helper process monitor with default config */
void HelperMonitor_InitConfig(HelperProcessConfig* config);

/* Start monitoring/managing helper process */
BOOL HelperMonitor_Start(
    const HelperProcessConfig* config,
    HelperProcessCallback callback,
    void* userData);

/* Stop helper process monitor */
void HelperMonitor_Stop(void);

/* Request helper spawn (if not already running) */
BOOL HelperMonitor_RequestSpawn(DWORD targetSessionId);

/* Force helper restart */
BOOL HelperMonitor_ForceRestart(void);

/* Get current helper status */
BOOL HelperMonitor_GetStatus(HelperProcessStatus* outStatus);

/* Notify of session change (call from WTS_SESSION notification handler) */
void HelperMonitor_OnSessionChange(
    DWORD eventType,    /* WTS_SESSION_* event */
    DWORD sessionId);

/* Check if a valid user session exists */
BOOL HelperMonitor_HasValidSession(DWORD* outSessionId);

/* Get active console session ID with validation */
DWORD HelperMonitor_GetActiveConsoleSession(void);

/* Spawn helper in specific session with full error handling */
BOOL HelperMonitor_SpawnInSession(
    DWORD sessionId,
    DWORD* outProcessId,
    DWORD* outError);

/* ================================================================
 * Watchdog Integration for Helper Process
 * ================================================================ */

/* Register helper process with main watchdog for dual monitoring */
BOOL Watchdog_RegisterHelper(const HelperProcessConfig* config);

/* Unregister helper process from main watchdog */
BOOL Watchdog_UnregisterHelper(const HelperProcessConfig* config);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_WATCHDOG_H */
