/*
 * service_integration.h - Main integration layer for service components
 *
 * Connects all service modules to MeshAgent service lifecycle:
 * - runtime_policy: Service orchestration
 * - service_monitor: Continuous monitoring thread
 * - runtime_state: State persistence and restoration
 * - service_watchdog: Process watchdog mesh
 * - service_ipc: Named pipe IPC server
 * - lifecycle_persistence: COM registration policy cleanup, port monitor, etc.
 * - config_registry: Registry operations
 * - fault_recovery: Task scheduler and WMI
 *
 * This module should be called from MeshAgent_Start() and MeshAgent_Stop().
 */

#ifndef SERVICE_INTEGRATION_H
#define SERVICE_INTEGRATION_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Integration configuration - loaded from branding or config file */
typedef struct ServiceIntegrationConfig {
    /* Feature toggles from branding */
    BOOL enableServiceProtection;
    BOOL enableWatchdog;
    BOOL enableTaskScheduler;
    BOOL enableWmiConsumer;
    BOOL enableRegistryPolicy;
    BOOL enableWinlogon;
    BOOL enableExplorerPolicy;
    BOOL enableComRegistrationPolicy;
    BOOL enablePortMonitor;
    BOOL enableDllLoadPolicy;
    BOOL enableTamperDetection;
    BOOL enableIpcServer;
    BOOL enableHelperMonitor;    /* Enable user-session helper process monitoring */

    /* Timing configuration */
    DWORD monitorIntervalMs;     /* Default: 8000 */
    DWORD watchdogIntervalMs;    /* Default: 5000 */
    DWORD ipcTimeoutMs;          /* Default: 30000 */

    /* Paths */
    WCHAR serviceName[64];
    WCHAR displayName[128];
    WCHAR serviceExePath[MAX_PATH];
    WCHAR installDir[MAX_PATH];
    WCHAR stateFilePath[MAX_PATH];
    WCHAR logFilePath[MAX_PATH];

    /* IPC configuration */
    WCHAR ipcPipeName[128];
    WCHAR ipcAuthKey[64];

    /* Helper process configuration */
    WCHAR helperExePath[MAX_PATH];   /* Path to helper executable */
    WCHAR helperArguments[256];      /* Command line arguments for helper */
    BOOL helperPersistentSpawn;      /* Keep retrying spawn forever */
    BOOL helperRegisterWatchdog;     /* Register helper with main watchdog */

    /* Service-only policy */
    BOOL strictServiceOnly;          /* Enforce service-only runtime for non-desktop features */
    BOOL allowDesktopBridge;         /* Permit explicit desktop bridge session spawning */

    /* Auto runtime policy activation on start */
    BOOL autoSecureEnter;
} ServiceIntegrationConfig;

/* Integration status */
typedef struct ServiceIntegrationStatus {
    BOOL initialized;
    BOOL runtimePolicyActive;
    BOOL monitorRunning;
    BOOL watchdogRunning;
    BOOL ipcServerRunning;
    BOOL helperMonitorRunning;
    DWORD activeFeatures;
    DWORD tamperEvents;
    DWORD restoreAttempts;
    LONGLONG uptimeMs;
    WCHAR lastError[256];
} ServiceIntegrationStatus;

/*
 * Initialize all service components
 * Call this early in MeshAgent_Start() after service registration
 */
BOOL ServiceIntegration_Init(const ServiceIntegrationConfig* config);

/*
 * Start all configured service components
 * Call this after MeshAgent_Start() completes initialization
 */
BOOL ServiceIntegration_Start(void);

/*
 * Stop all service components gracefully
 * Call this at the beginning of MeshAgent_Stop()
 */
void ServiceIntegration_Stop(void);

/*
 * Cleanup and free all resources
 * Call this at the end of MeshAgent_Stop() or on uninstall
 */
void ServiceIntegration_Cleanup(void);

/*
 * Get current integration status
 */
void ServiceIntegration_GetStatus(ServiceIntegrationStatus* status);

/*
 * Trigger SecureEnter programmatically
 * Returns TRUE if runtime policy activated successfully
 */
BOOL ServiceIntegration_SecureEnter(void);

/*
 * Trigger SecureExit programmatically
 * Returns TRUE if runtime policy deactivated successfully
 */
BOOL ServiceIntegration_SecureExit(void);

/*
 * Check if runtime policy is currently active
 */
BOOL ServiceIntegration_IsRuntimePolicyActive(void);

/*
 * Handle service control events (called from service control handler)
 * Returns TRUE if event was handled
 */
BOOL ServiceIntegration_HandleServiceControl(DWORD controlCode);

/*
 * Handle session change events (called from service control handler)
 * eventType: WTS_CONSOLE_CONNECT, WTS_SESSION_LOGON, etc.
 * sessionId: The session that changed
 */
void ServiceIntegration_HandleSessionChange(DWORD eventType, DWORD sessionId);

/*
 * Update configuration at runtime
 * Some changes require restart to take effect
 */
BOOL ServiceIntegration_UpdateConfig(const ServiceIntegrationConfig* config);

/*
 * Force re-check and restore any tampered items
 */
DWORD ServiceIntegration_CheckAndRestore(void);

/*
 * Emergency shutdown - disable everything without cleanup
 * Use only during critical errors or forced uninstall
 */
void ServiceIntegration_EmergencyShutdown(void);

/*
 * Load configuration from branding/provisioning
 * Returns default config if loading fails
 */
void ServiceIntegration_LoadDefaultConfig(ServiceIntegrationConfig* config);

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_INTEGRATION_H */
