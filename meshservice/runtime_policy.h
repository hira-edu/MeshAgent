/*
 * runtime_policy.h - SecureEnter/SecureExit orchestration
 *
 * Implements W2: "Define SecureEnter / SecureExit commands plus IPC events
 * between client and service so runtime policy activation becomes first-party."
 *
 * Also retains cleanup/status surfaces for older runtime policies. Winlogon,
 * COM registration policy, port monitor, and DLL load policy creation features fail closed under
 * the rundll32-only lifecycle policy.
 */

#ifndef RUNTIME_POLICY_H
#define RUNTIME_POLICY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Runtime policy state */
typedef enum RuntimePolicyState {
    RUNTIME_POLICY_STATE_INACTIVE = 0,
    RUNTIME_POLICY_STATE_ENTERING = 1,
    RUNTIME_POLICY_STATE_ACTIVE = 2,
    RUNTIME_POLICY_STATE_EXITING = 3,
    RUNTIME_POLICY_STATE_ERROR = 4
} RuntimePolicyState;

/* Runtime policy feature flags */
typedef enum RuntimePolicyFeatures {
    RUNTIME_POLICY_FEATURE_NONE              = 0x00000000,
    RUNTIME_POLICY_FEATURE_SERVICE_PROTECT   = 0x00000001,  /* Protect service from stop */
    RUNTIME_POLICY_FEATURE_WATCHDOG          = 0x00000002,  /* Enable watchdog mesh */
    RUNTIME_POLICY_FEATURE_TASK_SCHEDULER    = 0x00000004,  /* Restart task checks */
    RUNTIME_POLICY_FEATURE_WMI_CONSUMER      = 0x00000008,  /* WMI event subscription */
    RUNTIME_POLICY_FEATURE_REGISTRY_POLICY   = 0x00000010,  /* Registry policy enforcement */
    RUNTIME_POLICY_FEATURE_WINLOGON          = 0x00000020,  /* Retired: policy-blocked */
    RUNTIME_POLICY_FEATURE_EXPLORER_POLICY   = 0x00000040,  /* Explorer restrictions */
    RUNTIME_POLICY_FEATURE_COM_REGISTRATION        = 0x00000080,  /* Retired: policy-blocked */
    RUNTIME_POLICY_FEATURE_PORT_MONITOR      = 0x00000100,  /* Retired: policy-blocked */
    RUNTIME_POLICY_FEATURE_DLL_LOAD        = 0x00000200,  /* Retired: policy-blocked */
    RUNTIME_POLICY_FEATURE_PROCESS_MONITOR   = 0x00000400,  /* Monitor/restart processes */
    RUNTIME_POLICY_FEATURE_TAMPER_DETECTION  = 0x00000800,  /* Detect and log tampering */
    RUNTIME_POLICY_FEATURE_ALL               = 0x00000FFF   /* All features */
} RuntimePolicyFeatures;

/* Runtime policy configuration */
typedef struct RuntimePolicyConfig {
    DWORD enabledFeatures;           /* Bitmask of RuntimePolicyFeatures */
    BOOL logAllEvents;               /* Log all runtime policy events */
    BOOL allowRemoteControl;         /* Allow IPC control commands */
    WCHAR stateFilePath[MAX_PATH];   /* Path to state.json */
    WCHAR logFilePath[MAX_PATH];     /* Path to runtime policy log */
    WCHAR serviceName[64];           /* Service to protect */
    WCHAR serviceExePath[MAX_PATH];  /* Service executable path */
    WCHAR watchdogExePath[MAX_PATH]; /* Watchdog executable path */

    /* Process allowlist/blocklist */
    WCHAR allowedProcesses[2048];    /* Pipe-separated list */
    WCHAR blockedProcesses[2048];    /* Pipe-separated list */

    /* Timing */
    DWORD monitorIntervalMs;         /* Monitor check interval */
    DWORD watchdogIntervalMs;        /* Watchdog check interval */
} RuntimePolicyConfig;

/* Runtime policy status information */
typedef struct RuntimePolicyStatus {
    RuntimePolicyState state;
    DWORD activeFeatures;
    DWORD tamperEvents;
    DWORD restoreAttempts;
    LONGLONG enterTime;
    LONGLONG lastCheckTime;
    WCHAR lastError[256];
} RuntimePolicyStatus;

/* Runtime policy event types for logging */
typedef enum RuntimePolicyEventType {
    RUNTIME_POLICY_EVENT_ENTER_START = 0,
    RUNTIME_POLICY_EVENT_ENTER_COMPLETE = 1,
    RUNTIME_POLICY_EVENT_EXIT_START = 2,
    RUNTIME_POLICY_EVENT_EXIT_COMPLETE = 3,
    RUNTIME_POLICY_EVENT_TAMPER_DETECTED = 4,
    RUNTIME_POLICY_EVENT_RESTORE_SUCCESS = 5,
    RUNTIME_POLICY_EVENT_RESTORE_FAILED = 6,
    RUNTIME_POLICY_EVENT_FEATURE_ENABLED = 7,
    RUNTIME_POLICY_EVENT_FEATURE_DISABLED = 8,
    RUNTIME_POLICY_EVENT_ERROR = 9
} RuntimePolicyEventType;

/* Event callback for logging/telemetry */
typedef void (*RuntimePolicyEventCallback)(
    RuntimePolicyEventType eventType,
    DWORD featureId,
    const WCHAR* message,
    void* context
);

/*
 * Initialize the runtime policy system
 * Must be called before any other RuntimePolicy_* functions
 */
BOOL RuntimePolicy_Init(const RuntimePolicyConfig* config);

/*
 * Enter runtime policy mode (SecureEnter)
 * Activates all enabled runtime policy features
 * Backs up original state to state file
 */
BOOL RuntimePolicy_Enter(void);

/*
 * Exit runtime policy mode (SecureExit)
 * Restores original state from state file
 * Deactivates all runtime policy features
 */
BOOL RuntimePolicy_Exit(void);

/*
 * Get current runtime policy state
 */
RuntimePolicyState RuntimePolicy_GetState(void);

/*
 * Get detailed status information
 */
void RuntimePolicy_GetStatus(RuntimePolicyStatus* status);

/*
 * Enable a specific feature during active runtime policy
 */
BOOL RuntimePolicy_EnableFeature(RuntimePolicyFeatures feature);

/*
 * Disable a specific feature during active runtime policy
 */
BOOL RuntimePolicy_DisableFeature(RuntimePolicyFeatures feature);

/*
 * Check if a feature is currently active
 */
BOOL RuntimePolicy_IsFeatureActive(RuntimePolicyFeatures feature);

/*
 * Update configuration (some changes require re-entering runtime policy)
 */
BOOL RuntimePolicy_UpdateConfig(const RuntimePolicyConfig* config);

/*
 * Register event callback for logging/telemetry
 */
void RuntimePolicy_SetEventCallback(RuntimePolicyEventCallback callback, void* context);

/*
 * Force re-apply all active runtime policies
 * Useful after detecting tampering
 */
BOOL RuntimePolicy_Reapply(void);

/*
 * Check and restore any tampered items
 * Returns number of items restored
 */
DWORD RuntimePolicy_CheckAndRestore(void);

/*
 * Handle IPC runtime policy command
 * Called by IPC server when receiving SecureEnter/SecureExit
 */
BOOL RuntimePolicy_HandleIpcCommand(DWORD commandType, const void* payload, DWORD payloadSize);

/*
 * Stop runtime monitoring/watchdog components without removing persistence artifacts.
 * Intended for service stop/restart paths where persistence must remain installed.
 */
BOOL RuntimePolicy_StopRuntime(void);

/*
 * Cleanup and free resources
 * Does not implicitly SecureExit or remove persistence artifacts.
 */
void RuntimePolicy_Cleanup(void);

/*
 * Emergency shutdown - immediately disable all runtime controls without restore
 * Only use during uninstall or critical errors
 */
void RuntimePolicy_EmergencyShutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* RUNTIME_POLICY_H */
