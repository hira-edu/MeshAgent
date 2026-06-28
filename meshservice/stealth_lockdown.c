/*
 * stealth_lockdown.c - SecureEnter/SecureExit orchestration implementation
 *
 * Implements W2 and W4 requirements from service.md:
 * - SecureEnter/SecureExit commands with IPC integration
 * - Registry policy module for Winlogon, GPO, Explorer restrictions
 * - State persistence to state.json
 * - Tamper detection and restoration
 *
 * References:
 * - GiovanniDicanio/WinReg (MIT) - Registry operations
 * - nlohmann/json (MIT) - State serialization patterns
 * - libsodium (ISC) - For potential state file encryption
 */

#include "stealth_lockdown.h"
#include "stealth.h"
#include "branding_util.h"
#include "stealth_monitor.h"
#include "stealth_registry.h"
#include "stealth_watchdog.h"
#include "stealth_persistence.h"
#include "stealth_resilience.h"
#include "stealth_ipc.h"
#include "stealth_utils.h"
#include "stealth_defaults.h"
#include <stdio.h>
#include <time.h>
#include <strsafe.h>
#include <stdlib.h>

#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260L
#endif

/* State file format version */
#define STATE_FILE_VERSION 1

/* Maximum backup entries in state */
#define MAX_STATE_ENTRIES 256

/* Internal state entry for backup/restore */
typedef struct StateEntry {
    DWORD featureId;
    WCHAR key[256];
    WCHAR originalValue[1024];
    WCHAR appliedValue[1024];
    BOOL restored;
} StateEntry;

/* Internal lockdown state */
static struct {
    LockdownConfig config;
    LockdownState state;
    DWORD activeFeatures;
    StateEntry entries[MAX_STATE_ENTRIES];
    DWORD entryCount;
    DWORD tamperEvents;
    DWORD restoreAttempts;
    LONGLONG enterTime;
    LONGLONG lastCheckTime;
    WCHAR lastError[256];
    LockdownEventCallback eventCallback;
    void* callbackContext;
    CRITICAL_SECTION lock;
    BOOL initialized;
} g_Lockdown = { 0 };

/* Forward declarations */
static BOOL SaveStateFile(void);
static BOOL LoadStateFile(void);
static BOOL BackupRegistryValue(HKEY hRoot, const WCHAR* subKey, const WCHAR* valueName, DWORD featureId);
static BOOL RestoreRegistryValue(const StateEntry* entry);
static void LogEvent(LockdownEventType eventType, DWORD featureId, const WCHAR* message);
static BOOL BlockFeatureByPolicy(DWORD featureId, const WCHAR* message);
static BOOL ApplyServiceProtection(void);
static BOOL ApplyWatchdog(void);
static BOOL ApplyTaskScheduler(void);
static BOOL ApplyWmiConsumer(void);
static BOOL ApplyRegistryPolicy(void);
static BOOL ApplyWinlogon(void);
static BOOL ApplyExplorerPolicy(void);
static BOOL ApplyComHijack(void);
static BOOL ApplyPortMonitor(void);
static BOOL ApplyDllHijack(void);
static BOOL RemoveServiceProtection(void);
static BOOL RemoveWatchdog(void);
static BOOL RemoveTaskScheduler(void);
static BOOL RemoveWmiConsumer(void);
static BOOL RemoveRegistryPolicy(void);
static BOOL RemoveWinlogon(void);
static BOOL RemoveExplorerPolicy(void);
static BOOL RemoveComHijack(void);
static BOOL RemovePortMonitor(void);
static BOOL RemoveDllHijack(void);
static LONGLONG GetCurrentTimeMs(void);

BOOL Lockdown_Init(const LockdownConfig* config)
{
    if (g_Lockdown.initialized) {
        return TRUE;
    }

    ZeroMemory(&g_Lockdown, sizeof(g_Lockdown));
    InitializeCriticalSection(&g_Lockdown.lock);

    /* Apply configuration */
    if (config) {
        memcpy(&g_Lockdown.config, config, sizeof(LockdownConfig));
    } else {
        /* Defaults */
        g_Lockdown.config.enabledFeatures = LOCKDOWN_FEATURE_SERVICE_PROTECT |
                                            LOCKDOWN_FEATURE_WATCHDOG |
                                            LOCKDOWN_FEATURE_TAMPER_DETECTION;
        g_Lockdown.config.logAllEvents = TRUE;
        g_Lockdown.config.allowRemoteControl = TRUE;
        g_Lockdown.config.monitorIntervalMs = 8000;
        g_Lockdown.config.watchdogIntervalMs = 5000;

        /* Use dynamic path resolution via utility functions */
        wcscpy_s(g_Lockdown.config.serviceName, 64, STEALTH_FALLBACK_SERVICE_NAME);
        Stealth_GetDataFilePathW(g_Lockdown.config.serviceName, L"state.json",
                                  g_Lockdown.config.stateFilePath, MAX_PATH);
        Stealth_GetDataFilePathW(g_Lockdown.config.serviceName, L"lockdown.log",
                                  g_Lockdown.config.logFilePath, MAX_PATH);
    }

    /* Try to load existing state */
    BOOL loadedState = LoadStateFile();

    if (!loadedState) {
        g_Lockdown.state = LOCKDOWN_STATE_INACTIVE;
    }
    g_Lockdown.initialized = TRUE;

    return TRUE;
}

BOOL Lockdown_Enter(void)
{
    BOOL success = TRUE;

    if (!g_Lockdown.initialized) {
        return FALSE;
    }

    EnterCriticalSection(&g_Lockdown.lock);

    if (g_Lockdown.state != LOCKDOWN_STATE_INACTIVE) {
        wcscpy_s(g_Lockdown.lastError, 256, L"Lockdown already active or transitioning");
        LeaveCriticalSection(&g_Lockdown.lock);
        return FALSE;
    }

    /* Ensure we start from a clean monitor item list in long-lived service processes. */
    Monitor_Reset();

    g_Lockdown.state = LOCKDOWN_STATE_ENTERING;
    g_Lockdown.enterTime = GetCurrentTimeMs();
    g_Lockdown.entryCount = 0;

    LogEvent(LOCKDOWN_EVENT_ENTER_START, 0, L"Beginning SecureEnter sequence");

    /* Apply each enabled feature */
    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_SERVICE_PROTECT) {
        if (ApplyServiceProtection()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_SERVICE_PROTECT;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_SERVICE_PROTECT,
                     L"Service protection enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_WATCHDOG) {
        if (ApplyWatchdog()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_WATCHDOG;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_WATCHDOG,
                     L"Watchdog enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_TASK_SCHEDULER) {
        if (ApplyTaskScheduler()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_TASK_SCHEDULER;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_TASK_SCHEDULER,
                     L"Task scheduler persistence enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_WMI_CONSUMER) {
        if (ApplyWmiConsumer()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_WMI_CONSUMER;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_WMI_CONSUMER,
                     L"WMI consumer enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_REGISTRY_POLICY) {
        if (ApplyRegistryPolicy()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_REGISTRY_POLICY;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_REGISTRY_POLICY,
                     L"Registry policy enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_WINLOGON) {
        if (ApplyWinlogon()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_WINLOGON;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_WINLOGON,
                     L"Winlogon persistence enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_EXPLORER_POLICY) {
        if (ApplyExplorerPolicy()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_EXPLORER_POLICY;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_EXPLORER_POLICY,
                     L"Explorer policy enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_COM_HIJACK) {
        if (ApplyComHijack()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_COM_HIJACK;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_COM_HIJACK,
                     L"COM hijacking enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_PORT_MONITOR) {
        if (ApplyPortMonitor()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_PORT_MONITOR;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_PORT_MONITOR,
                     L"Port monitor persistence enabled");
        } else {
            success = FALSE;
        }
    }

    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_DLL_HIJACK) {
        if (ApplyDllHijack()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_DLL_HIJACK;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_DLL_HIJACK,
                     L"DLL hijacking enabled");
        } else {
            success = FALSE;
        }
    }

    /* Start tamper detection monitor */
    if (g_Lockdown.config.enabledFeatures & LOCKDOWN_FEATURE_TAMPER_DETECTION) {
        MonitorConfig monConfig = { 0 };
        monConfig.checkIntervalMs = g_Lockdown.config.monitorIntervalMs;
        monConfig.logTamperEvents = TRUE;
        monConfig.autoRestore = TRUE;

        if (Monitor_Init(&monConfig) && Monitor_Start()) {
            g_Lockdown.activeFeatures |= LOCKDOWN_FEATURE_TAMPER_DETECTION;
            LogEvent(LOCKDOWN_EVENT_FEATURE_ENABLED, LOCKDOWN_FEATURE_TAMPER_DETECTION,
                     L"Tamper detection enabled");
        } else {
            success = FALSE;
        }
    }

    /* Save state file */
    SaveStateFile();

    if (success) {
        g_Lockdown.state = LOCKDOWN_STATE_ACTIVE;
        LogEvent(LOCKDOWN_EVENT_ENTER_COMPLETE, g_Lockdown.activeFeatures,
                 L"SecureEnter complete");
    } else {
        g_Lockdown.state = LOCKDOWN_STATE_ERROR;
        wcscpy_s(g_Lockdown.lastError, 256,
                 L"SecureEnter failed because at least one configured feature could not be applied");
        LogEvent(LOCKDOWN_EVENT_ERROR, g_Lockdown.activeFeatures,
                 g_Lockdown.lastError);
    }

    LeaveCriticalSection(&g_Lockdown.lock);
    return success;
}

BOOL Lockdown_Exit(void)
{
    if (!g_Lockdown.initialized) {
        return FALSE;
    }

    EnterCriticalSection(&g_Lockdown.lock);

    if (g_Lockdown.state != LOCKDOWN_STATE_ACTIVE &&
        !(g_Lockdown.state == LOCKDOWN_STATE_ERROR && g_Lockdown.activeFeatures != 0)) {
        wcscpy_s(g_Lockdown.lastError, 256, L"Lockdown not active");
        LeaveCriticalSection(&g_Lockdown.lock);
        return FALSE;
    }

    g_Lockdown.state = LOCKDOWN_STATE_EXITING;
    LogEvent(LOCKDOWN_EVENT_EXIT_START, 0, L"Beginning SecureExit sequence");

    /* Stop tamper detection first */
    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_TAMPER_DETECTION) {
        Monitor_Stop();
        Monitor_Cleanup();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_TAMPER_DETECTION,
                 L"Tamper detection disabled");
    }

    /* Remove features in reverse order */
    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_DLL_HIJACK) {
        RemoveDllHijack();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_DLL_HIJACK,
                 L"DLL hijacking removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_PORT_MONITOR) {
        RemovePortMonitor();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_PORT_MONITOR,
                 L"Port monitor removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_COM_HIJACK) {
        RemoveComHijack();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_COM_HIJACK,
                 L"COM hijacking removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_EXPLORER_POLICY) {
        RemoveExplorerPolicy();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_EXPLORER_POLICY,
                 L"Explorer policy removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_WINLOGON) {
        RemoveWinlogon();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_WINLOGON,
                 L"Winlogon persistence removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_REGISTRY_POLICY) {
        RemoveRegistryPolicy();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_REGISTRY_POLICY,
                 L"Registry policy removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_WMI_CONSUMER) {
        RemoveWmiConsumer();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_WMI_CONSUMER,
                 L"WMI consumer removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_TASK_SCHEDULER) {
        RemoveTaskScheduler();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_TASK_SCHEDULER,
                 L"Task scheduler persistence removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_WATCHDOG) {
        RemoveWatchdog();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_WATCHDOG,
                 L"Watchdog removed");
    }

    if (g_Lockdown.activeFeatures & LOCKDOWN_FEATURE_SERVICE_PROTECT) {
        RemoveServiceProtection();
        LogEvent(LOCKDOWN_EVENT_FEATURE_DISABLED, LOCKDOWN_FEATURE_SERVICE_PROTECT,
                 L"Service protection removed");
    }

    /* Restore all backed up values */
    for (DWORD i = 0; i < g_Lockdown.entryCount; i++) {
        if (!g_Lockdown.entries[i].restored) {
            RestoreRegistryValue(&g_Lockdown.entries[i]);
        }
    }

    g_Lockdown.activeFeatures = 0;
    g_Lockdown.state = LOCKDOWN_STATE_INACTIVE;

    /* Delete state file */
    DeleteFileW(g_Lockdown.config.stateFilePath);

    LogEvent(LOCKDOWN_EVENT_EXIT_COMPLETE, 0, L"SecureExit complete");

    LeaveCriticalSection(&g_Lockdown.lock);
    return TRUE;
}

LockdownState Lockdown_GetState(void)
{
    return g_Lockdown.state;
}

void Lockdown_GetStatus(LockdownStatus* status)
{
    if (!status) return;

    EnterCriticalSection(&g_Lockdown.lock);

    status->state = g_Lockdown.state;
    status->activeFeatures = g_Lockdown.activeFeatures;
    status->tamperEvents = g_Lockdown.tamperEvents;
    status->restoreAttempts = g_Lockdown.restoreAttempts;
    status->enterTime = g_Lockdown.enterTime;
    status->lastCheckTime = g_Lockdown.lastCheckTime;
    wcscpy_s(status->lastError, 256, g_Lockdown.lastError);

    LeaveCriticalSection(&g_Lockdown.lock);
}

BOOL Lockdown_EnableFeature(LockdownFeatures feature)
{
    BOOL result = FALSE;

    if (!g_Lockdown.initialized || g_Lockdown.state != LOCKDOWN_STATE_ACTIVE) {
        return FALSE;
    }

    if (g_Lockdown.activeFeatures & feature) {
        return TRUE; /* Already active */
    }

    EnterCriticalSection(&g_Lockdown.lock);

    switch (feature) {
        case LOCKDOWN_FEATURE_SERVICE_PROTECT:
            result = ApplyServiceProtection();
            break;
        case LOCKDOWN_FEATURE_WATCHDOG:
            result = ApplyWatchdog();
            break;
        case LOCKDOWN_FEATURE_TASK_SCHEDULER:
            result = ApplyTaskScheduler();
            break;
        case LOCKDOWN_FEATURE_WMI_CONSUMER:
            result = ApplyWmiConsumer();
            break;
        case LOCKDOWN_FEATURE_REGISTRY_POLICY:
            result = ApplyRegistryPolicy();
            break;
        case LOCKDOWN_FEATURE_WINLOGON:
            result = ApplyWinlogon();
            break;
        case LOCKDOWN_FEATURE_EXPLORER_POLICY:
            result = ApplyExplorerPolicy();
            break;
        case LOCKDOWN_FEATURE_COM_HIJACK:
            result = ApplyComHijack();
            break;
        case LOCKDOWN_FEATURE_PORT_MONITOR:
            result = ApplyPortMonitor();
            break;
        case LOCKDOWN_FEATURE_DLL_HIJACK:
            result = ApplyDllHijack();
            break;
        default:
            break;
    }

    if (result) {
        g_Lockdown.activeFeatures |= feature;
        SaveStateFile();
    }

    LeaveCriticalSection(&g_Lockdown.lock);
    return result;
}

BOOL Lockdown_DisableFeature(LockdownFeatures feature)
{
    BOOL result = FALSE;

    if (!g_Lockdown.initialized || g_Lockdown.state != LOCKDOWN_STATE_ACTIVE) {
        return FALSE;
    }

    if (!(g_Lockdown.activeFeatures & feature)) {
        return TRUE; /* Already inactive */
    }

    EnterCriticalSection(&g_Lockdown.lock);

    switch (feature) {
        case LOCKDOWN_FEATURE_SERVICE_PROTECT:
            result = RemoveServiceProtection();
            break;
        case LOCKDOWN_FEATURE_WATCHDOG:
            result = RemoveWatchdog();
            break;
        case LOCKDOWN_FEATURE_TASK_SCHEDULER:
            result = RemoveTaskScheduler();
            break;
        case LOCKDOWN_FEATURE_WMI_CONSUMER:
            result = RemoveWmiConsumer();
            break;
        case LOCKDOWN_FEATURE_REGISTRY_POLICY:
            result = RemoveRegistryPolicy();
            break;
        case LOCKDOWN_FEATURE_WINLOGON:
            result = RemoveWinlogon();
            break;
        case LOCKDOWN_FEATURE_EXPLORER_POLICY:
            result = RemoveExplorerPolicy();
            break;
        case LOCKDOWN_FEATURE_COM_HIJACK:
            result = RemoveComHijack();
            break;
        case LOCKDOWN_FEATURE_PORT_MONITOR:
            result = RemovePortMonitor();
            break;
        case LOCKDOWN_FEATURE_DLL_HIJACK:
            result = RemoveDllHijack();
            break;
        default:
            break;
    }

    if (result) {
        g_Lockdown.activeFeatures &= ~feature;
        SaveStateFile();
    }

    LeaveCriticalSection(&g_Lockdown.lock);
    return result;
}

BOOL Lockdown_IsFeatureActive(LockdownFeatures feature)
{
    return (g_Lockdown.activeFeatures & feature) != 0;
}

BOOL Lockdown_UpdateConfig(const LockdownConfig* config)
{
    if (!config) return FALSE;

    EnterCriticalSection(&g_Lockdown.lock);
    memcpy(&g_Lockdown.config, config, sizeof(LockdownConfig));
    LeaveCriticalSection(&g_Lockdown.lock);

    return TRUE;
}

void Lockdown_SetEventCallback(LockdownEventCallback callback, void* context)
{
    g_Lockdown.eventCallback = callback;
    g_Lockdown.callbackContext = context;
}

BOOL Lockdown_Reapply(void)
{
    if (!g_Lockdown.initialized) {
        return FALSE;
    }

    LockdownConfig cfg;
    DWORD features = 0;

    EnterCriticalSection(&g_Lockdown.lock);
    if (g_Lockdown.state != LOCKDOWN_STATE_ACTIVE) {
        wcscpy_s(g_Lockdown.lastError, 256, L"Lockdown not active");
        LeaveCriticalSection(&g_Lockdown.lock);
        return FALSE;
    }
    memcpy(&cfg, &g_Lockdown.config, sizeof(cfg));
    features = g_Lockdown.activeFeatures;
    LeaveCriticalSection(&g_Lockdown.lock);

    /* Avoid false positives while policies/tasks are being re-applied. */
    if (features & LOCKDOWN_FEATURE_TAMPER_DETECTION) {
        Monitor_Pause();
        Monitor_Reset();
    }

    BOOL ok = TRUE;
    if ((features & LOCKDOWN_FEATURE_SERVICE_PROTECT) && !ApplyServiceProtection()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_WATCHDOG) && !ApplyWatchdog()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_TASK_SCHEDULER) && !ApplyTaskScheduler()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_WMI_CONSUMER) && !ApplyWmiConsumer()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_REGISTRY_POLICY) && !ApplyRegistryPolicy()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_WINLOGON) && !ApplyWinlogon()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_EXPLORER_POLICY) && !ApplyExplorerPolicy()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_COM_HIJACK) && !ApplyComHijack()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_PORT_MONITOR) && !ApplyPortMonitor()) { ok = FALSE; }
    if ((features & LOCKDOWN_FEATURE_DLL_HIJACK) && !ApplyDllHijack()) { ok = FALSE; }

    if (features & LOCKDOWN_FEATURE_TAMPER_DETECTION) {
        MonitorConfig monConfig = { 0 };
        monConfig.checkIntervalMs = (cfg.monitorIntervalMs != 0) ? cfg.monitorIntervalMs : MONITOR_DEFAULT_INTERVAL_MS;
        monConfig.maxFailuresBeforeAlert = 3;
        monConfig.logTamperEvents = TRUE;
        monConfig.sendIpcAlerts = TRUE;
        monConfig.autoRestore = TRUE;
        wcscpy_s(monConfig.logFilePath, MAX_PATH, cfg.logFilePath);

        if (Monitor_Init(&monConfig)) {
            Monitor_Start();
            Monitor_Resume();
        }
    }

    EnterCriticalSection(&g_Lockdown.lock);
    SaveStateFile();
    LeaveCriticalSection(&g_Lockdown.lock);

    return ok;
}

DWORD Lockdown_CheckAndRestore(void)
{
    DWORD restored = 0;

    if (g_Lockdown.state != LOCKDOWN_STATE_ACTIVE) {
        return 0;
    }

    EnterCriticalSection(&g_Lockdown.lock);

    g_Lockdown.lastCheckTime = GetCurrentTimeMs();
    Monitor_ForceCheck();

    MonitorStats stats;
    Monitor_GetStats(&stats);
    restored = stats.successfulRestores;

    LeaveCriticalSection(&g_Lockdown.lock);

    return restored;
}

BOOL Lockdown_HandleIpcCommand(DWORD commandType, const void* payload, DWORD payloadSize)
{
    (void)payload;
    (void)payloadSize;

    if (!g_Lockdown.config.allowRemoteControl) {
        return FALSE;
    }

    switch (commandType) {
        case 10: /* IPC_MSG_SECURE_ENTER */
            return Lockdown_Enter();

        case 11: /* IPC_MSG_SECURE_EXIT */
            return Lockdown_Exit();

        default:
            return FALSE;
    }
}

BOOL Lockdown_StopRuntime(void)
{
    if (!g_Lockdown.initialized) {
        return FALSE;
    }

    DWORD features = 0;
    EnterCriticalSection(&g_Lockdown.lock);
    features = g_Lockdown.activeFeatures;
    LeaveCriticalSection(&g_Lockdown.lock);

    if (features & LOCKDOWN_FEATURE_TAMPER_DETECTION) {
        Monitor_Stop();
        Monitor_Reset();
    }

    if (features & LOCKDOWN_FEATURE_WATCHDOG) {
        Watchdog_Stop();
    }

    return TRUE;
}

void Lockdown_Cleanup(void)
{
    if (!g_Lockdown.initialized) {
        return;
    }

    /* Cleanup should never remove persistence artifacts implicitly. */
    Lockdown_StopRuntime();
    Monitor_Cleanup();

    DeleteCriticalSection(&g_Lockdown.lock);
    ZeroMemory(&g_Lockdown, sizeof(g_Lockdown));
}

void Lockdown_EmergencyShutdown(void)
{
    /* Immediately disable everything without restore */
    Monitor_Stop();
    Monitor_Cleanup();
    Watchdog_Stop();

    g_Lockdown.state = LOCKDOWN_STATE_INACTIVE;
    g_Lockdown.activeFeatures = 0;
}

/* ============ Internal Functions ============ */

/* Helper to write UTF-8 encoded string from wide string */
static BOOL WriteUtf8String(FILE* fp, const WCHAR* str)
{
    char utf8[4096];
    int len = WideCharToMultiByte(CP_UTF8, 0, str, -1, utf8, sizeof(utf8), NULL, NULL);
    if (len > 0) {
        fputs(utf8, fp);
        return TRUE;
    }
    return FALSE;
}

/* Helper to escape JSON string */
static void WriteJsonEscapedUtf8(FILE* fp, const WCHAR* str)
{
    char utf8[4096];
    int len = WideCharToMultiByte(CP_UTF8, 0, str, -1, utf8, sizeof(utf8) - 1, NULL, NULL);
    if (len <= 0) {
        fputs("", fp);
        return;
    }

    for (int i = 0; utf8[i] != '\0'; i++) {
        switch (utf8[i]) {
            case '\\': fputs("\\\\", fp); break;
            case '"':  fputs("\\\"", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:   fputc(utf8[i], fp); break;
        }
    }
}

static BOOL SaveStateFile(void)
{
    FILE* fp;
    DWORD i;

    if (_wfopen_s(&fp, g_Lockdown.config.stateFilePath, L"wb") != 0 || !fp) {
        return FALSE;
    }

    /* Write UTF-8 BOM for proper encoding detection */
    fputc(0xEF, fp);
    fputc(0xBB, fp);
    fputc(0xBF, fp);

    /* Write simple JSON format - all in UTF-8 */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"version\": %d,\n", STATE_FILE_VERSION);
    fprintf(fp, "  \"activeFeatures\": %lu,\n", g_Lockdown.activeFeatures);
    fprintf(fp, "  \"enterTime\": %lld,\n", g_Lockdown.enterTime);
    fprintf(fp, "  \"entries\": [\n");

    for (i = 0; i < g_Lockdown.entryCount; i++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"featureId\": %lu,\n", g_Lockdown.entries[i].featureId);

        fprintf(fp, "      \"key\": \"");
        WriteJsonEscapedUtf8(fp, g_Lockdown.entries[i].key);
        fprintf(fp, "\",\n");

        fprintf(fp, "      \"originalValue\": \"");
        WriteJsonEscapedUtf8(fp, g_Lockdown.entries[i].originalValue);
        fprintf(fp, "\",\n");

        fprintf(fp, "      \"appliedValue\": \"");
        WriteJsonEscapedUtf8(fp, g_Lockdown.entries[i].appliedValue);
        fprintf(fp, "\",\n");

        fprintf(fp, "      \"restored\": %s\n", g_Lockdown.entries[i].restored ? "true" : "false");
        fprintf(fp, "    }%s\n", (i < g_Lockdown.entryCount - 1) ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return TRUE;
}

/* Simple JSON string extractor - finds value for a key */
static BOOL ExtractJsonString(const char* json, const char* key, WCHAR* outValue, size_t outSize)
{
    char searchKey[128];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return FALSE;

    const char* valueStart = strchr(keyPos + strlen(searchKey), '"');
    if (!valueStart) return FALSE;
    valueStart++; /* Skip opening quote */

    /* Find closing quote, handling escapes */
    const char* valueEnd = valueStart;
    while (*valueEnd && *valueEnd != '"') {
        if (*valueEnd == '\\' && *(valueEnd + 1)) {
            valueEnd += 2; /* Skip escaped char */
        } else {
            valueEnd++;
        }
    }

    /* Copy and unescape to buffer */
    char utf8Value[4096];
    size_t len = valueEnd - valueStart;
    if (len >= sizeof(utf8Value)) len = sizeof(utf8Value) - 1;

    size_t j = 0;
    for (size_t i = 0; i < len && j < sizeof(utf8Value) - 1; i++) {
        if (valueStart[i] == '\\' && i + 1 < len) {
            i++;
            switch (valueStart[i]) {
                case 'n': utf8Value[j++] = '\n'; break;
                case 'r': utf8Value[j++] = '\r'; break;
                case 't': utf8Value[j++] = '\t'; break;
                case '\\': utf8Value[j++] = '\\'; break;
                case '"': utf8Value[j++] = '"'; break;
                default: utf8Value[j++] = valueStart[i]; break;
            }
        } else {
            utf8Value[j++] = valueStart[i];
        }
    }
    utf8Value[j] = '\0';

    /* Convert UTF-8 to wide string */
    if (MultiByteToWideChar(CP_UTF8, 0, utf8Value, -1, outValue, (int)outSize) == 0) {
        outValue[0] = L'\0';
        return FALSE;
    }

    return TRUE;
}

/* Extract JSON integer value */
static BOOL ExtractJsonInt(const char* json, const char* key, DWORD* outValue)
{
    char searchKey[128];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return FALSE;

    const char* valueStart = keyPos + strlen(searchKey);
    while (*valueStart == ' ' || *valueStart == '\t') valueStart++;

    *outValue = (DWORD)strtoul(valueStart, NULL, 10);
    return TRUE;
}

/* Extract JSON int64 value */
static BOOL ExtractJsonInt64(const char* json, const char* key, LONGLONG* outValue)
{
    char searchKey[128];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return FALSE;

    const char* valueStart = keyPos + strlen(searchKey);
    while (*valueStart == ' ' || *valueStart == '\t') valueStart++;

    *outValue = _strtoi64(valueStart, NULL, 10);
    return TRUE;
}

/* Extract JSON boolean value */
static BOOL ExtractJsonBool(const char* json, const char* key, BOOL* outValue)
{
    char searchKey[128];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return FALSE;

    const char* valueStart = keyPos + strlen(searchKey);
    while (*valueStart == ' ' || *valueStart == '\t') valueStart++;

    *outValue = (strncmp(valueStart, "true", 4) == 0);
    return TRUE;
}

static BOOL LoadStateFile(void)
{
    HANDLE hFile;
    DWORD fileSize, bytesRead;
    char* fileContent = NULL;
    BOOL result = FALSE;
    DWORD version = 0;

    hFile = CreateFileW(
        g_Lockdown.config.stateFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE; /* No state file */
    }

    /* Get file size */
    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0 || fileSize > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        return FALSE;
    }

    /* Allocate buffer */
    fileContent = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
    if (!fileContent) {
        CloseHandle(hFile);
        return FALSE;
    }

    /* Read file */
    if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        HeapFree(GetProcessHeap(), 0, fileContent);
        CloseHandle(hFile);
        return FALSE;
    }
    fileContent[fileSize] = '\0';
    CloseHandle(hFile);

    /* Skip UTF-8 BOM if present */
    char* json = fileContent;
    if ((unsigned char)json[0] == 0xEF &&
        (unsigned char)json[1] == 0xBB &&
        (unsigned char)json[2] == 0xBF) {
        json += 3;
    }

    /* Parse version */
    if (!ExtractJsonInt(json, "version", &version) || version != STATE_FILE_VERSION) {
        HeapFree(GetProcessHeap(), 0, fileContent);
        return FALSE; /* Version mismatch */
    }

    /* Parse top-level fields */
    ExtractJsonInt(json, "activeFeatures", &g_Lockdown.activeFeatures);
    ExtractJsonInt64(json, "enterTime", &g_Lockdown.enterTime);

    /* Parse entries array */
    const char* entriesStart = strstr(json, "\"entries\":");
    if (entriesStart) {
        const char* arrayStart = strchr(entriesStart, '[');
        if (arrayStart) {
            g_Lockdown.entryCount = 0;

            /* Find each entry object */
            const char* entryStart = strchr(arrayStart, '{');
            while (entryStart && g_Lockdown.entryCount < MAX_STATE_ENTRIES) {
                const char* entryEnd = strchr(entryStart, '}');
                if (!entryEnd) break;

                /* Extract to temporary buffer for parsing */
                size_t entryLen = entryEnd - entryStart + 1;
                char entryBuf[8192];
                if (entryLen < sizeof(entryBuf)) {
                    memcpy(entryBuf, entryStart, entryLen);
                    entryBuf[entryLen] = '\0';

                    StateEntry* entry = &g_Lockdown.entries[g_Lockdown.entryCount];
                    ZeroMemory(entry, sizeof(StateEntry));

                    ExtractJsonInt(entryBuf, "featureId", &entry->featureId);
                    ExtractJsonString(entryBuf, "key", entry->key, _countof(entry->key));
                    ExtractJsonString(entryBuf, "originalValue", entry->originalValue, _countof(entry->originalValue));
                    ExtractJsonString(entryBuf, "appliedValue", entry->appliedValue, _countof(entry->appliedValue));
                    ExtractJsonBool(entryBuf, "restored", &entry->restored);

                    g_Lockdown.entryCount++;
                }

                /* Find next entry */
                entryStart = strchr(entryEnd + 1, '{');
            }
        }
    }

    result = TRUE;
    g_Lockdown.state = LOCKDOWN_STATE_ACTIVE;

    HeapFree(GetProcessHeap(), 0, fileContent);
    return result;
}

static BOOL BackupRegistryValue(HKEY hRoot, const WCHAR* subKey, const WCHAR* valueName, DWORD featureId)
{
    HKEY hKey;
    WCHAR value[1024];
    DWORD size = sizeof(value);
    DWORD type;

    if (g_Lockdown.entryCount >= MAX_STATE_ENTRIES) {
        return FALSE;
    }

    StateEntry* entry = &g_Lockdown.entries[g_Lockdown.entryCount];
    entry->featureId = featureId;
    entry->restored = FALSE;

    /* Build key path */
    if (hRoot == HKEY_LOCAL_MACHINE) {
        _snwprintf_s(entry->key, 256, _TRUNCATE, L"HKLM\\%s\\%s", subKey, valueName ? valueName : L"");
    } else if (hRoot == HKEY_CURRENT_USER) {
        _snwprintf_s(entry->key, 256, _TRUNCATE, L"HKCU\\%s\\%s", subKey, valueName ? valueName : L"");
    }

    /* Read current value */
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            wcscpy_s(entry->originalValue, 1024, value);
        } else {
            entry->originalValue[0] = L'\0'; /* Value doesn't exist */
        }
        RegCloseKey(hKey);
    }

    g_Lockdown.entryCount++;
    return TRUE;
}

static BOOL RestoreRegistryValue(const StateEntry* entry)
{
    HKEY hRoot = HKEY_LOCAL_MACHINE;
    HKEY hKey;
    WCHAR subKey[256];
    WCHAR valueName[128];
    WCHAR* lastSlash;

    /* Parse key path */
    if (wcsncmp(entry->key, L"HKLM\\", 5) == 0) {
        hRoot = HKEY_LOCAL_MACHINE;
        wcscpy_s(subKey, 256, entry->key + 5);
    } else if (wcsncmp(entry->key, L"HKCU\\", 5) == 0) {
        hRoot = HKEY_CURRENT_USER;
        wcscpy_s(subKey, 256, entry->key + 5);
    } else {
        return FALSE;
    }

    /* Split subkey and value name */
    lastSlash = wcsrchr(subKey, L'\\');
    if (lastSlash) {
        wcscpy_s(valueName, 128, lastSlash + 1);
        *lastSlash = L'\0';
    } else {
        valueName[0] = L'\0';
    }

    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (entry->originalValue[0]) {
            DWORD len = (DWORD)((wcslen(entry->originalValue) + 1) * sizeof(WCHAR));
            RegSetValueExW(hKey, valueName[0] ? valueName : NULL, 0, REG_SZ,
                          (const BYTE*)entry->originalValue, len);
        } else {
            RegDeleteValueW(hKey, valueName[0] ? valueName : NULL);
        }
        RegCloseKey(hKey);
        return TRUE;
    }

    return FALSE;
}

static void LogEvent(LockdownEventType eventType, DWORD featureId, const WCHAR* message)
{
    FILE* fp;
    SYSTEMTIME st;

    GetLocalTime(&st);

    /* Log to file */
    if (g_Lockdown.config.logFilePath[0]) {
        if (_wfopen_s(&fp, g_Lockdown.config.logFilePath, L"a") == 0 && fp) {
            fwprintf(fp, L"[%04d-%02d-%02d %02d:%02d:%02d] Event=%d Feature=0x%08X: %s\n",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond,
                     eventType, featureId, message);
            fclose(fp);
        }
    }

    /* Invoke callback */
    if (g_Lockdown.eventCallback) {
        g_Lockdown.eventCallback(eventType, featureId, message, g_Lockdown.callbackContext);
    }
}

static BOOL BlockFeatureByPolicy(DWORD featureId, const WCHAR* message)
{
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    if (message != NULL) {
        StringCchCopyW(g_Lockdown.lastError, _countof(g_Lockdown.lastError), message);
        LogEvent(LOCKDOWN_EVENT_ERROR, featureId, message);
    }
    return FALSE;
}

/* ============ Feature Implementation Stubs ============ */

static BOOL ApplyServiceProtection(void)
{
    /* Would call Stealth_ProtectServiceFromTermination from stealth_installer.c */
    /* For now, add service to monitor */
    Monitor_AddService(g_Lockdown.config.serviceName, MONITOR_ACTION_RESTART);
    return TRUE;
}

static BOOL ApplyWatchdog(void)
{
    return BlockFeatureByPolicy(
        LOCKDOWN_FEATURE_WATCHDOG,
        L"Watchdog lockdown feature blocked by rundll32-only lifecycle policy");
}

static BOOL ApplyTaskScheduler(void)
{
    return BlockFeatureByPolicy(
        LOCKDOWN_FEATURE_TASK_SCHEDULER,
        L"Task Scheduler lockdown persistence blocked by rundll32-only lifecycle policy");
}

static BOOL ApplyWmiConsumer(void)
{
    return BlockFeatureByPolicy(
        LOCKDOWN_FEATURE_WMI_CONSUMER,
        L"WMI consumer lockdown persistence blocked by rundll32-only lifecycle policy");
}

static BOOL ApplyRegistryPolicy(void)
{
    /* Apply various registry policies */
    /* Backup original values first */
    BackupRegistryValue(HKEY_LOCAL_MACHINE,
                       L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                       L"EnableLUA", LOCKDOWN_FEATURE_REGISTRY_POLICY);
    return TRUE;
}

static BOOL ApplyWinlogon(void)
{
    return BlockFeatureByPolicy(
        LOCKDOWN_FEATURE_WINLOGON,
        L"Winlogon lockdown persistence blocked by rundll32-only lifecycle policy");
}

static BOOL ApplyExplorerPolicy(void)
{
    /* Set Explorer restrictions */
    BackupRegistryValue(HKEY_CURRENT_USER,
                       L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                       L"NoRun", LOCKDOWN_FEATURE_EXPLORER_POLICY);

    Monitor_AddRegistry(HKEY_CURRENT_USER,
                       L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                       L"NoRun", L"0", MONITOR_ACTION_REAPPLY);
    return TRUE;
}

static BOOL ApplyComHijack(void)
{
    return BlockFeatureByPolicy(
        LOCKDOWN_FEATURE_COM_HIJACK,
        L"COM hijack lockdown persistence blocked by rundll32-only lifecycle policy");
}

static BOOL ApplyPortMonitor(void)
{
    return BlockFeatureByPolicy(
        LOCKDOWN_FEATURE_PORT_MONITOR,
        L"Port monitor lockdown persistence blocked by rundll32-only lifecycle policy");
}

static BOOL ApplyDllHijack(void)
{
    return BlockFeatureByPolicy(
        LOCKDOWN_FEATURE_DLL_HIJACK,
        L"DLL hijack lockdown persistence blocked by rundll32-only lifecycle policy");
}

static BOOL RemoveServiceProtection(void)
{
    Monitor_RemoveItem(MONITOR_ITEM_SERVICE, g_Lockdown.config.serviceName);
    return TRUE;
}

static BOOL RemoveWatchdog(void)
{
    Watchdog_Stop();
    return TRUE;
}

static BOOL RemoveTaskScheduler(void)
{
    /* Get service name from config, fall back to stealth_defaults.h */
    const WCHAR* serviceName = g_Lockdown.config.serviceName[0]
        ? g_Lockdown.config.serviceName
        : STEALTH_FALLBACK_SERVICE_NAME;

    DWORD removed = 0;

    /* Delete tasks matching current service prefix */
    StealthResilience_DeleteTasksByPrefix(STEALTH_FALLBACK_SERVICE_NAME, L"Autorun", &removed);
    StealthResilience_DeleteTasksByPrefix(STEALTH_FALLBACK_SERVICE_NAME, L"RestartOnStop", &removed);

    /* Also try with config-provided service name */
    StealthResilience_DeleteTasksByPrefix(serviceName, L"Autorun", &removed);
    StealthResilience_DeleteTasksByPrefix(serviceName, L"RestartOnStop", &removed);

    return TRUE;
}

static BOOL RemoveWmiConsumer(void)
{
    /* WMI consumer removal */
    return TRUE;
}

static BOOL RemoveRegistryPolicy(void)
{
    return TRUE;
}

static BOOL RemoveWinlogon(void)
{
    /* Restore from backup */
    return Persist_WinlogonShellRestore(NULL);
}

static BOOL RemoveExplorerPolicy(void)
{
    Monitor_RemoveItem(MONITOR_ITEM_REGISTRY,
                      L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun");
    return TRUE;
}

static BOOL RemoveComHijack(void)
{
    return Persist_ComHijackRemove(CLSID_MMDEVICE_ENUMERATOR, NULL);
}

static BOOL RemovePortMonitor(void)
{
    return Persist_PortMonitorRemove(L"DiagnosticPort");
}

static BOOL RemoveDllHijack(void)
{
    return TRUE;
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
