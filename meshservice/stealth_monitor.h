/*
 * stealth_monitor.h - Continuous monitoring thread for service/task/registry integrity
 *
 * Implements W2 requirement: "Add a monitor thread/service that re-checks services,
 * tasks, and registry keys every ~8 seconds once MeshAgent_Start() returns."
 *
 * References:
 * - ecraft/ecraft-watchdogservice (MIT) - Generic watchdog patterns
 * - anodejs/hongen (MIT) - Never-stopping watchdog concepts
 */

#ifndef STEALTH_MONITOR_H
#define STEALTH_MONITOR_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Monitor check interval (default 8 seconds per service.md spec) */
#define MONITOR_DEFAULT_INTERVAL_MS 8000

/* Monitor status codes */
typedef enum MonitorStatus {
    MONITOR_STATUS_STOPPED = 0,
    MONITOR_STATUS_RUNNING = 1,
    MONITOR_STATUS_PAUSED = 2,
    MONITOR_STATUS_ERROR = 3
} MonitorStatus;

/* Types of monitored items */
typedef enum MonitorItemType {
    MONITOR_ITEM_SERVICE = 0,
    MONITOR_ITEM_TASK = 1,
    MONITOR_ITEM_REGISTRY = 2,
    MONITOR_ITEM_PROCESS = 3,
    MONITOR_ITEM_FILE = 4
} MonitorItemType;

/* Action to take when tampering is detected */
typedef enum MonitorAction {
    MONITOR_ACTION_LOG = 0,          /* Log the event only */
    MONITOR_ACTION_RESTORE = 1,      /* Attempt to restore original state */
    MONITOR_ACTION_ALERT = 2,        /* Send IPC alert */
    MONITOR_ACTION_RESTART = 3,      /* Restart service/process */
    MONITOR_ACTION_REAPPLY = 4       /* Re-apply policy/setting */
} MonitorAction;

/* Monitored item definition */
typedef struct MonitorItem {
    MonitorItemType type;
    MonitorAction action;
    WCHAR identifier[256];           /* Service name, task path, registry key, etc. */
    WCHAR expectedValue[512];        /* Expected state/value */
    BOOL enabled;
    DWORD failureCount;
    LONGLONG lastCheckTime;
    LONGLONG lastTamperTime;
} MonitorItem;

/* Monitor configuration */
typedef struct MonitorConfig {
    DWORD checkIntervalMs;           /* Check interval (default: 8000) */
    DWORD maxFailuresBeforeAlert;    /* Failures before escalating (default: 3) */
    BOOL logTamperEvents;            /* Log tampering to file (default: TRUE) */
    BOOL sendIpcAlerts;              /* Send alerts via IPC (default: TRUE) */
    BOOL autoRestore;                /* Auto-restore tampered items (default: TRUE) */
    WCHAR logFilePath[MAX_PATH];     /* Path to tamper log */
} MonitorConfig;

/* Tamper event callback */
typedef void (*MonitorTamperCallback)(
    const MonitorItem* item,
    const WCHAR* currentValue,
    void* context
);

/* Statistics */
typedef struct MonitorStats {
    DWORD totalChecks;
    DWORD tamperDetections;
    DWORD successfulRestores;
    DWORD failedRestores;
    LONGLONG uptimeMs;
    LONGLONG lastCheckTime;
} MonitorStats;

/* Process protection diagnostic details (NtQueryInformationProcess(ProcessProtectionInformation)). */
typedef struct MonitorProcessProtectionInfo {
    DWORD processId;
    DWORD sessionId;
    WCHAR imageName[MAX_PATH];
    WCHAR imagePath[MAX_PATH];
    DWORD openError;
    DWORD queryError;
    BOOL handleOpened;
    BOOL imagePathKnown;
    BOOL protectionKnown;
    BYTE protectionLevel;
    BYTE protectionType;
    BYTE protectionSigner;
    BOOL isProtected;
    BOOL isProtectedLight;
} MonitorProcessProtectionInfo;

/*
 * Initialize the monitor system
 * Returns TRUE on success
 */
BOOL Monitor_Init(const MonitorConfig* config);

/*
 * Start the monitor thread
 * Returns TRUE if started successfully
 */
BOOL Monitor_Start(void);

/*
 * Stop the monitor thread gracefully
 */
void Monitor_Stop(void);

/*
 * Get current monitor status
 */
MonitorStatus Monitor_GetStatus(void);

/*
 * Add an item to monitor
 * Returns TRUE if added successfully
 */
BOOL Monitor_AddItem(const MonitorItem* item);

/*
 * Remove a monitored item by identifier
 */
BOOL Monitor_RemoveItem(MonitorItemType type, const WCHAR* identifier);

/*
 * Add a service to monitor for running state
 */
BOOL Monitor_AddService(const WCHAR* serviceName, MonitorAction action);

/*
 * Add a scheduled task to monitor
 */
BOOL Monitor_AddTask(const WCHAR* taskPath, MonitorAction action);

/*
 * Add a registry key/value to monitor
 */
BOOL Monitor_AddRegistry(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const WCHAR* expectedValue,
    MonitorAction action
);

/*
 * Add a process to monitor (ensure it stays running)
 */
BOOL Monitor_AddProcess(const WCHAR* processName, const WCHAR* exePath, MonitorAction action);

/*
 * Register callback for tamper events
 */
void Monitor_SetTamperCallback(MonitorTamperCallback callback, void* context);

/*
 * Force an immediate check cycle
 */
void Monitor_ForceCheck(void);

/*
 * Get current statistics
 */
void Monitor_GetStats(MonitorStats* stats);

/*
 * Pause monitoring temporarily
 */
void Monitor_Pause(void);

/*
 * Resume monitoring after pause
 */
void Monitor_Resume(void);

/*
 * Clear all monitored items.
 * Useful when re-applying policies in long-lived svchost processes to avoid
 * stale/duplicated expectations after service restarts.
 */
void Monitor_Reset(void);

/*
 * Query process protection information for diagnostics and tamper classification.
 * Returns TRUE when ProcessProtectionInformation was queried successfully.
 */
BOOL Monitor_QueryProcessProtectionByPid(DWORD processId, MonitorProcessProtectionInfo* info);

/* Convert protection type/signer codes into stable diagnostic strings. */
const WCHAR* Monitor_GetProtectionTypeName(BYTE protectionType);
const WCHAR* Monitor_GetProtectionSignerName(BYTE protectionSigner);

/*
 * Cleanup and free resources
 */
void Monitor_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_MONITOR_H */
