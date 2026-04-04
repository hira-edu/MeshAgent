/*
 * stealth_monitor.c - Continuous monitoring thread implementation
 *
 * Implements W2: "Add a monitor thread/service that re-checks services,
 * tasks, and registry keys every ~8 seconds once MeshAgent_Start() returns."
 *
 * Also implements W4: "Monitor and re-apply those keys each loop and log tamper events."
 *
 * References:
 * - ecraft/ecraft-watchdogservice (MIT)
 * - anodejs/hongen (MIT)
 * - thijse/Watchdog (MIT)
 */

#include "stealth_monitor.h"
#include "stealth.h"
#include "stealth_utils.h"
#include "stealth_defaults.h"
#include <stdio.h>
#include <time.h>
#include <tlhelp32.h>
#include <stdlib.h>

/* Maximum monitored items */
#define MAX_MONITOR_ITEMS 128
#define MONITOR_PROCESS_PROTECTION_INFORMATION_CLASS 61UL

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* MonitorNtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct MonitorPsProtection {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} MonitorPsProtection;

/* Internal state */
static struct {
    MonitorConfig config;
    MonitorItem items[MAX_MONITOR_ITEMS];
    DWORD itemCount;
    HANDLE hThread;
    HANDLE hStopEvent;
    HANDLE hForceCheckEvent;
    volatile MonitorStatus status;
    MonitorStats stats;
    MonitorTamperCallback tamperCallback;
    void* callbackContext;
    CRITICAL_SECTION lock;
    BOOL initialized;
    LONGLONG startTime;
    LONGLONG lastNetworkMaintenanceTime;
} g_Monitor = { 0 };

/* Forward declarations */
static DWORD WINAPI MonitorThreadProc(LPVOID lpParam);
static BOOL CheckService(MonitorItem* item);
static BOOL CheckTask(MonitorItem* item);
static BOOL CheckRegistry(MonitorItem* item);
static BOOL CheckProcess(MonitorItem* item);
static BOOL RestoreService(MonitorItem* item);
static BOOL RestoreTask(MonitorItem* item);
static BOOL RestoreRegistry(MonitorItem* item);
static BOOL RestoreProcess(MonitorItem* item);
static void LogTamperEvent(const MonitorItem* item, const WCHAR* currentValue);
static LONGLONG GetCurrentTimeMs(void);
static const WCHAR* Monitor_FindFileNameComponent(const WCHAR* path);

const WCHAR* Monitor_GetProtectionTypeName(BYTE protectionType)
{
    switch (protectionType) {
        case 0: return L"None";
        case 1: return L"ProtectedLight";
        case 2: return L"Protected";
        default: return L"Unknown";
    }
}

const WCHAR* Monitor_GetProtectionSignerName(BYTE protectionSigner)
{
    switch (protectionSigner) {
        case 0: return L"None";
        case 1: return L"Authenticode";
        case 2: return L"CodeGen";
        case 3: return L"Antimalware";
        case 4: return L"Lsa";
        case 5: return L"Windows";
        case 6: return L"WinTcb";
        case 7: return L"WinSystem";
        case 8: return L"App";
        default: return L"Unknown";
    }
}

BOOL Monitor_QueryProcessProtectionByPid(DWORD processId, MonitorProcessProtectionInfo* info)
{
    HMODULE ntdll = NULL;
    MonitorNtQueryInformationProcessFn ntQueryInformationProcess = NULL;
    HANDLE processHandle = NULL;
    DWORD imagePathLength = 0;
    MonitorPsProtection protection;
    NTSTATUS status;
    BOOL ok = FALSE;

    if (info == NULL || processId == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(info, sizeof(MonitorProcessProtectionInfo));
    info->processId = processId;
    (void)ProcessIdToSessionId(processId, &info->sessionId);

    processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (processHandle == NULL) {
        processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    }
    if (processHandle == NULL) {
        info->openError = GetLastError();
        return FALSE;
    }

    info->handleOpened = TRUE;
    imagePathLength = (DWORD)_countof(info->imagePath);
    if (QueryFullProcessImageNameW(processHandle, 0, info->imagePath, &imagePathLength)) {
        info->imagePathKnown = TRUE;
        wcsncpy_s(info->imageName, _countof(info->imageName),
            Monitor_FindFileNameComponent(info->imagePath), _TRUNCATE);
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }
    if (ntdll == NULL) {
        info->queryError = GetLastError();
        goto cleanup;
    }

    ntQueryInformationProcess = (MonitorNtQueryInformationProcessFn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (ntQueryInformationProcess == NULL) {
        info->queryError = ERROR_PROC_NOT_FOUND;
        goto cleanup;
    }

    ZeroMemory(&protection, sizeof(protection));
    status = ntQueryInformationProcess(
        processHandle,
        MONITOR_PROCESS_PROTECTION_INFORMATION_CLASS,
        &protection,
        (ULONG)sizeof(protection),
        NULL);
    if (!NT_SUCCESS(status)) {
        info->queryError = (DWORD)status;
        goto cleanup;
    }

    info->protectionKnown = TRUE;
    info->protectionLevel = protection.Level;
    info->protectionType = protection.Type;
    info->protectionSigner = protection.Signer;
    info->isProtectedLight = (protection.Type == 1);
    info->isProtected = (protection.Type == 2);
    ok = TRUE;

cleanup:
    CloseHandle(processHandle);
    return ok;
}

BOOL Monitor_Init(const MonitorConfig* config)
{
    if (g_Monitor.initialized) {
        return TRUE; /* Already initialized */
    }

    ZeroMemory(&g_Monitor, sizeof(g_Monitor));

    /* Apply configuration or use defaults */
    if (config) {
        memcpy(&g_Monitor.config, config, sizeof(MonitorConfig));
    } else {
        g_Monitor.config.checkIntervalMs = MONITOR_DEFAULT_INTERVAL_MS;
        g_Monitor.config.maxFailuresBeforeAlert = 3;
        g_Monitor.config.logTamperEvents = TRUE;
        g_Monitor.config.sendIpcAlerts = TRUE;
        g_Monitor.config.autoRestore = TRUE;
    }

    /* Create synchronization objects */
    g_Monitor.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Monitor.hStopEvent) {
        return FALSE;
    }

    g_Monitor.hForceCheckEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_Monitor.hForceCheckEvent) {
        CloseHandle(g_Monitor.hStopEvent);
        return FALSE;
    }

    InitializeCriticalSection(&g_Monitor.lock);

    g_Monitor.status = MONITOR_STATUS_STOPPED;
    g_Monitor.initialized = TRUE;
    g_Monitor.startTime = GetCurrentTimeMs();

    return TRUE;
}

BOOL Monitor_Start(void)
{
    if (!g_Monitor.initialized) {
        return FALSE;
    }

    if (g_Monitor.status == MONITOR_STATUS_RUNNING) {
        return TRUE; /* Already running */
    }

    ResetEvent(g_Monitor.hStopEvent);

    g_Monitor.hThread = CreateThread(
        NULL,
        0,
        MonitorThreadProc,
        NULL,
        0,
        NULL
    );

    if (!g_Monitor.hThread) {
        return FALSE;
    }

    g_Monitor.status = MONITOR_STATUS_RUNNING;
    return TRUE;
}

void Monitor_Stop(void)
{
    if (!g_Monitor.initialized || g_Monitor.status == MONITOR_STATUS_STOPPED) {
        return;
    }

    /* Signal stop */
    SetEvent(g_Monitor.hStopEvent);

    /* Wait for thread to exit */
    if (g_Monitor.hThread) {
        WaitForSingleObject(g_Monitor.hThread, 5000);
        CloseHandle(g_Monitor.hThread);
        g_Monitor.hThread = NULL;
    }

    g_Monitor.status = MONITOR_STATUS_STOPPED;
}

MonitorStatus Monitor_GetStatus(void)
{
    return g_Monitor.status;
}

BOOL Monitor_AddItem(const MonitorItem* item)
{
    BOOL result = FALSE;

    if (!g_Monitor.initialized || !item) {
        return FALSE;
    }

    EnterCriticalSection(&g_Monitor.lock);

    if (g_Monitor.itemCount < MAX_MONITOR_ITEMS) {
        memcpy(&g_Monitor.items[g_Monitor.itemCount], item, sizeof(MonitorItem));
        g_Monitor.items[g_Monitor.itemCount].enabled = TRUE;
        g_Monitor.items[g_Monitor.itemCount].failureCount = 0;
        g_Monitor.items[g_Monitor.itemCount].lastCheckTime = 0;
        g_Monitor.items[g_Monitor.itemCount].lastTamperTime = 0;
        g_Monitor.itemCount++;
        result = TRUE;
    }

    LeaveCriticalSection(&g_Monitor.lock);
    return result;
}

BOOL Monitor_RemoveItem(MonitorItemType type, const WCHAR* identifier)
{
    BOOL result = FALSE;
    DWORD i;

    if (!g_Monitor.initialized || !identifier) {
        return FALSE;
    }

    EnterCriticalSection(&g_Monitor.lock);

    for (i = 0; i < g_Monitor.itemCount; i++) {
        if (g_Monitor.items[i].type == type &&
            wcscmp(g_Monitor.items[i].identifier, identifier) == 0) {
            /* Shift remaining items */
            if (i < g_Monitor.itemCount - 1) {
                memmove(&g_Monitor.items[i],
                        &g_Monitor.items[i + 1],
                        (g_Monitor.itemCount - i - 1) * sizeof(MonitorItem));
            }
            g_Monitor.itemCount--;
            result = TRUE;
            break;
        }
    }

    LeaveCriticalSection(&g_Monitor.lock);
    return result;
}

void Monitor_Reset(void)
{
    if (!g_Monitor.initialized) {
        return;
    }

    EnterCriticalSection(&g_Monitor.lock);
    ZeroMemory(g_Monitor.items, sizeof(g_Monitor.items));
    g_Monitor.itemCount = 0;
    LeaveCriticalSection(&g_Monitor.lock);
}

BOOL Monitor_AddService(const WCHAR* serviceName, MonitorAction action)
{
    MonitorItem item = { 0 };

    if (!serviceName) return FALSE;

    item.type = MONITOR_ITEM_SERVICE;
    item.action = action;
    wcsncpy_s(item.identifier, 256, serviceName, _TRUNCATE);
    wcscpy_s(item.expectedValue, 512, L"RUNNING");

    return Monitor_AddItem(&item);
}

BOOL Monitor_AddTask(const WCHAR* taskPath, MonitorAction action)
{
    MonitorItem item = { 0 };

    if (!taskPath) return FALSE;

    item.type = MONITOR_ITEM_TASK;
    item.action = action;
    wcsncpy_s(item.identifier, 256, taskPath, _TRUNCATE);
    wcscpy_s(item.expectedValue, 512, L"ENABLED");

    return Monitor_AddItem(&item);
}

BOOL Monitor_AddRegistry(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const WCHAR* expectedValue,
    MonitorAction action)
{
    MonitorItem item = { 0 };
    WCHAR rootName[32];

    if (!subKey) return FALSE;

    item.type = MONITOR_ITEM_REGISTRY;
    item.action = action;

    /* Encode root key in identifier */
    if (hRootKey == HKEY_LOCAL_MACHINE) {
        wcscpy_s(rootName, 32, L"HKLM");
    } else if (hRootKey == HKEY_CURRENT_USER) {
        wcscpy_s(rootName, 32, L"HKCU");
    } else if (hRootKey == HKEY_CLASSES_ROOT) {
        wcscpy_s(rootName, 32, L"HKCR");
    } else {
        wcscpy_s(rootName, 32, L"HKEY");
    }

    _snwprintf_s(item.identifier, 256, _TRUNCATE, L"%s\\%s\\%s",
                 rootName, subKey, valueName ? valueName : L"(Default)");

    if (expectedValue) {
        wcsncpy_s(item.expectedValue, 512, expectedValue, _TRUNCATE);
    }

    return Monitor_AddItem(&item);
}

BOOL Monitor_AddProcess(const WCHAR* processName, const WCHAR* exePath, MonitorAction action)
{
    MonitorItem item = { 0 };

    if (!processName) return FALSE;

    item.type = MONITOR_ITEM_PROCESS;
    item.action = action;
    wcsncpy_s(item.identifier, 256, processName, _TRUNCATE);

    if (exePath) {
        wcsncpy_s(item.expectedValue, 512, exePath, _TRUNCATE);
    }

    return Monitor_AddItem(&item);
}

void Monitor_SetTamperCallback(MonitorTamperCallback callback, void* context)
{
    EnterCriticalSection(&g_Monitor.lock);
    g_Monitor.tamperCallback = callback;
    g_Monitor.callbackContext = context;
    LeaveCriticalSection(&g_Monitor.lock);
}

void Monitor_ForceCheck(void)
{
    if (g_Monitor.initialized && g_Monitor.hForceCheckEvent) {
        SetEvent(g_Monitor.hForceCheckEvent);
    }
}

void Monitor_GetStats(MonitorStats* stats)
{
    if (!stats) return;

    EnterCriticalSection(&g_Monitor.lock);
    memcpy(stats, &g_Monitor.stats, sizeof(MonitorStats));
    stats->uptimeMs = GetCurrentTimeMs() - g_Monitor.startTime;
    LeaveCriticalSection(&g_Monitor.lock);
}

void Monitor_Pause(void)
{
    if (g_Monitor.status == MONITOR_STATUS_RUNNING) {
        g_Monitor.status = MONITOR_STATUS_PAUSED;
    }
}

void Monitor_Resume(void)
{
    if (g_Monitor.status == MONITOR_STATUS_PAUSED) {
        g_Monitor.status = MONITOR_STATUS_RUNNING;
    }
}

void Monitor_Cleanup(void)
{
    if (!g_Monitor.initialized) {
        return;
    }

    Monitor_Stop();

    if (g_Monitor.hStopEvent) {
        CloseHandle(g_Monitor.hStopEvent);
    }
    if (g_Monitor.hForceCheckEvent) {
        CloseHandle(g_Monitor.hForceCheckEvent);
    }

    DeleteCriticalSection(&g_Monitor.lock);

    ZeroMemory(&g_Monitor, sizeof(g_Monitor));
}

/* Structure to hold check work items collected under lock */
typedef struct MonitorCheckItem {
    DWORD index;
    MonitorItemType type;
    MonitorAction action;
    WCHAR identifier[256];
    WCHAR expectedValue[512];
    BOOL enabled;
} MonitorCheckItem;

/* Monitor thread procedure */
static DWORD WINAPI MonitorThreadProc(LPVOID lpParam)
{
    HANDLE waitHandles[2];
    DWORD waitResult;
    DWORD i;
    BOOL tampered;
    WCHAR currentValue[512];
    MonitorCheckItem checkItems[MAX_MONITOR_ITEMS];
    DWORD checkCount;
    MonitorTamperCallback callback;
    void* callbackContext;
    BOOL runNetworkMaintenance = FALSE;
    DWORD networkMaintenanceIntervalMs = 0;

    (void)lpParam;

    waitHandles[0] = g_Monitor.hStopEvent;
    waitHandles[1] = g_Monitor.hForceCheckEvent;

    while (TRUE) {
        /* Wait for interval or events */
        waitResult = WaitForMultipleObjects(
            2,
            waitHandles,
            FALSE,
            g_Monitor.config.checkIntervalMs
        );

        /* Check if we should stop */
        if (waitResult == WAIT_OBJECT_0) {
            break; /* Stop event signaled */
        }

        /* Skip if paused */
        if (g_Monitor.status == MONITOR_STATUS_PAUSED) {
            continue;
        }

        /* Phase 1: Copy items to check (with lock held briefly) */
        EnterCriticalSection(&g_Monitor.lock);
        checkCount = 0;
        callback = g_Monitor.tamperCallback;
        callbackContext = g_Monitor.callbackContext;

        for (i = 0; i < g_Monitor.itemCount && checkCount < MAX_MONITOR_ITEMS; i++) {
            if (g_Monitor.items[i].enabled) {
                checkItems[checkCount].index = i;
                checkItems[checkCount].type = g_Monitor.items[i].type;
                checkItems[checkCount].action = g_Monitor.items[i].action;
                wcscpy_s(checkItems[checkCount].identifier, 256, g_Monitor.items[i].identifier);
                wcscpy_s(checkItems[checkCount].expectedValue, 512, g_Monitor.items[i].expectedValue);
                checkItems[checkCount].enabled = TRUE;
                checkCount++;
            }
        }
        LeaveCriticalSection(&g_Monitor.lock);

        /* Phase 2: Perform checks OUTSIDE the lock */
        for (i = 0; i < checkCount; i++) {
            MonitorItem tempItem = {0};
            tempItem.type = checkItems[i].type;
            tempItem.action = checkItems[i].action;
            wcscpy_s(tempItem.identifier, 256, checkItems[i].identifier);
            wcscpy_s(tempItem.expectedValue, 512, checkItems[i].expectedValue);

            tampered = FALSE;
            currentValue[0] = L'\0';

            /* Check based on item type - these can be slow (SCM calls, registry access) */
            switch (tempItem.type) {
                case MONITOR_ITEM_SERVICE:
                    tampered = !CheckService(&tempItem);
                    break;

                case MONITOR_ITEM_TASK:
                    tampered = !CheckTask(&tempItem);
                    break;

                case MONITOR_ITEM_REGISTRY:
                    tampered = !CheckRegistry(&tempItem);
                    break;

                case MONITOR_ITEM_PROCESS:
                    tampered = !CheckProcess(&tempItem);
                    break;

                default:
                    break;
            }

            /* Phase 3: Update stats and take action (with lock) */
            EnterCriticalSection(&g_Monitor.lock);

            /* Verify the item still exists at the same index */
            DWORD origIndex = checkItems[i].index;
            if (origIndex < g_Monitor.itemCount) {
                g_Monitor.items[origIndex].lastCheckTime = GetCurrentTimeMs();
                g_Monitor.stats.totalChecks++;

                if (tampered) {
                    g_Monitor.items[origIndex].failureCount++;
                    g_Monitor.items[origIndex].lastTamperTime = GetCurrentTimeMs();
                    g_Monitor.stats.tamperDetections++;

                    /* Log tamper event - quick operation */
                    if (g_Monitor.config.logTamperEvents) {
                        LeaveCriticalSection(&g_Monitor.lock);
                        LogTamperEvent(&tempItem, currentValue);
                        EnterCriticalSection(&g_Monitor.lock);
                    }

                    /* Invoke callback outside lock to prevent deadlock */
                    if (callback) {
                        LeaveCriticalSection(&g_Monitor.lock);
                        callback(&tempItem, currentValue, callbackContext);
                        EnterCriticalSection(&g_Monitor.lock);
                    }

                    /* Take restore action - verify item still valid */
                    if (origIndex < g_Monitor.itemCount &&
                        g_Monitor.config.autoRestore &&
                        (g_Monitor.items[origIndex].action == MONITOR_ACTION_RESTORE ||
                         g_Monitor.items[origIndex].action == MONITOR_ACTION_REAPPLY ||
                         g_Monitor.items[origIndex].action == MONITOR_ACTION_RESTART)) {

                        BOOL restored = FALSE;
                        LeaveCriticalSection(&g_Monitor.lock);

                        /* Restore operations can be slow - do outside lock */
                        switch (tempItem.type) {
                            case MONITOR_ITEM_SERVICE:
                                restored = RestoreService(&tempItem);
                                break;

                            case MONITOR_ITEM_TASK:
                                restored = RestoreTask(&tempItem);
                                break;

                            case MONITOR_ITEM_REGISTRY:
                                restored = RestoreRegistry(&tempItem);
                                break;

                            case MONITOR_ITEM_PROCESS:
                                restored = RestoreProcess(&tempItem);
                                break;

                            default:
                                break;
                        }

                        EnterCriticalSection(&g_Monitor.lock);
                        if (restored) {
                            g_Monitor.stats.successfulRestores++;
                            if (origIndex < g_Monitor.itemCount) {
                                g_Monitor.items[origIndex].failureCount = 0;
                            }
                        } else {
                            g_Monitor.stats.failedRestores++;
                        }
                    }
                } else {
                    /* Reset failure count on successful check */
                    g_Monitor.items[origIndex].failureCount = 0;
                }
            }

            LeaveCriticalSection(&g_Monitor.lock);
        }

        /* Update overall stats */
        EnterCriticalSection(&g_Monitor.lock);
        g_Monitor.stats.lastCheckTime = GetCurrentTimeMs();
        networkMaintenanceIntervalMs = g_Monitor.config.checkIntervalMs;
        if (networkMaintenanceIntervalMs < 10000) { networkMaintenanceIntervalMs = 10000; }
        if (networkMaintenanceIntervalMs > 30000) { networkMaintenanceIntervalMs = 30000; }
        if ((g_Monitor.stats.lastCheckTime - g_Monitor.lastNetworkMaintenanceTime) >= networkMaintenanceIntervalMs)
        {
            g_Monitor.lastNetworkMaintenanceTime = g_Monitor.stats.lastCheckTime;
            runNetworkMaintenance = TRUE;
        }
        LeaveCriticalSection(&g_Monitor.lock);

        if (runNetworkMaintenance)
        {
            runNetworkMaintenance = FALSE;
            (void)Stealth_RunFirewallPolicyMaintenance();
        }
    }

    return 0;
}

/* Check if a service is running */
static BOOL CheckService(MonitorItem* item)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    BOOL isRunning = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        return FALSE;
    }

    hService = OpenServiceW(hSCM, item->identifier, SERVICE_QUERY_STATUS);
    if (hService) {
        if (QueryServiceStatusEx(
                hService,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp,
                sizeof(ssp),
                &bytesNeeded)) {
            isRunning = (ssp.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCM);
    return isRunning;
}

/* Check if a scheduled task exists and is enabled.
 * Uses registry-based detection which is faster than COM but less accurate.
 * Task paths should start with backslash, e.g., "\Microsoft\Windows\Task"
 */
static BOOL CheckTask(MonitorItem* item)
{
    HKEY hKey = NULL;
    HKEY hTaskKey = NULL;
    WCHAR treeKeyPath[512];
    WCHAR taskKeyPath[512];
    DWORD type;
    BOOL taskExists = FALSE;
    BOOL isEnabled = TRUE;

    if (item == NULL || item->identifier[0] == L'\0') {
        return FALSE;
    }

    /* Build registry path for task tree entry */
    _snwprintf_s(treeKeyPath, _countof(treeKeyPath), _TRUNCATE,
                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree%s",
                 item->identifier);

    /* Check if the task tree entry exists */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, treeKeyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        /* Task does not exist in tree */
        return FALSE;
    }

    /* Read the task's ID (GUID) from the tree entry */
    DWORD idSize = 0;
    if (RegQueryValueExW(hKey, L"Id", NULL, &type, NULL, &idSize) == ERROR_SUCCESS &&
        type == REG_SZ &&
        idSize >= (sizeof(WCHAR) * 3)) /* Minimum: "{X}" */
    {
        WCHAR* taskId = (WCHAR*)malloc(idSize);
        if (taskId == NULL) {
            RegCloseKey(hKey);
            return FALSE;
        }
        ZeroMemory(taskId, idSize);
        if (RegQueryValueExW(hKey, L"Id", NULL, &type, (LPBYTE)taskId, &idSize) == ERROR_SUCCESS &&
            type == REG_SZ &&
            taskId[0] != L'\0')
        {
            taskExists = TRUE;

            /* Now check the Tasks key for the actual task definition and state */
            _snwprintf_s(taskKeyPath, _countof(taskKeyPath), _TRUNCATE,
                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\%s",
                         taskId);

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, taskKeyPath, 0, KEY_READ, &hTaskKey) == ERROR_SUCCESS) {
                /* Check for triggers to verify task is properly configured */
                DWORD triggersSize = 0;
                if (RegQueryValueExW(hTaskKey, L"Triggers", NULL, NULL, NULL, &triggersSize) != ERROR_SUCCESS ||
                    triggersSize == 0) {
                    /* Task has no triggers - effectively disabled */
                    isEnabled = FALSE;
                }

                /* Check the DynamicInfo for last run/enabled state */
                BYTE dynamicInfo[64];
                DWORD dynamicSize = sizeof(dynamicInfo);
                if (RegQueryValueExW(hTaskKey, L"DynamicInfo", NULL, &type, dynamicInfo, &dynamicSize) == ERROR_SUCCESS) {
                    /* DynamicInfo contains last run time and state info */
                    /* If present and valid, task is likely active */
                }

                RegCloseKey(hTaskKey);
            } else {
                /* Task ID exists in tree but not in Tasks - corrupted/orphan */
                isEnabled = FALSE;
            }
        }
        free(taskId);
    } else {
        /* No ID means task tree entry is corrupted or placeholder */
        isEnabled = FALSE;
    }

    RegCloseKey(hKey);

    /* Return TRUE only if task exists and appears enabled */
    return taskExists && isEnabled;
}

/* Check a registry value */
static BOOL CheckRegistry(MonitorItem* item)
{
    HKEY hRootKey = HKEY_LOCAL_MACHINE;
    HKEY hKey = NULL;
    WCHAR subKey[256];
    WCHAR valueName[128];
    WCHAR currentValue[512];
    DWORD size = sizeof(currentValue);
    DWORD type;
    BOOL matches = FALSE;

    /* Parse identifier: ROOT\subkey\valuename */
    WCHAR* p = item->identifier;
    WCHAR* slash2;

    if (wcsncmp(p, L"HKLM\\", 5) == 0) {
        hRootKey = HKEY_LOCAL_MACHINE;
        p += 5;
    } else if (wcsncmp(p, L"HKCU\\", 5) == 0) {
        hRootKey = HKEY_CURRENT_USER;
        p += 5;
    } else if (wcsncmp(p, L"HKCR\\", 5) == 0) {
        hRootKey = HKEY_CLASSES_ROOT;
        p += 5;
    }

    /* Find last backslash to separate subkey from value name */
    slash2 = wcsrchr(p, L'\\');
    if (!slash2) {
        return FALSE;
    }

    size_t subKeyLen = slash2 - p;
    wcsncpy_s(subKey, 256, p, subKeyLen);
    subKey[subKeyLen] = L'\0';

    wcscpy_s(valueName, 128, slash2 + 1);
    if (wcscmp(valueName, L"(Default)") == 0) {
        valueName[0] = L'\0';
    }

    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = sizeof(currentValue);
        if (RegQueryValueExW(hKey, valueName[0] ? valueName : NULL,
                            NULL, &type, (LPBYTE)currentValue, &size) == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                matches = (wcscmp(currentValue, item->expectedValue) == 0);
            }
        }
        RegCloseKey(hKey);
    }

    return matches;
}

/* Check if a process is running */
static BOOL CheckProcess(MonitorItem* item)
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    BOOL found = FALSE;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, item->identifier) == 0) {
                if (item->expectedValue[0] == L'\0') {
                    found = TRUE;
                    break;
                } else {
                    MonitorProcessProtectionInfo protectionInfo;
                    ZeroMemory(&protectionInfo, sizeof(protectionInfo));
                    (void)Monitor_QueryProcessProtectionByPid(pe32.th32ProcessID, &protectionInfo);

                    if (protectionInfo.imagePathKnown &&
                        _wcsicmp(protectionInfo.imagePath, item->expectedValue) == 0) {
                        found = TRUE;
                        break;
                    }

                    /*
                     * Protected processes can reject image-path inspection even
                     * from a SYSTEM service. Matching the process name is enough
                     * to avoid a false tamper alarm in that case.
                     */
                    if ((protectionInfo.openError == ERROR_ACCESS_DENIED ||
                         protectionInfo.openError == ERROR_PRIVILEGE_NOT_HELD) &&
                        _wcsicmp(Monitor_FindFileNameComponent(item->expectedValue), item->identifier) == 0) {
                        found = TRUE;
                        break;
                    }
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

/* Restore a stopped service */
static BOOL RestoreService(MonitorItem* item)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        return FALSE;
    }

    hService = OpenServiceW(hSCM, item->identifier, SERVICE_START);
    if (hService) {
        result = StartServiceW(hService, 0, NULL);
        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCM);
    return result;
}

/* Restore a disabled task - requires COM, placeholder */
static BOOL RestoreTask(MonitorItem* item)
{
    (void)item;
    /* Full implementation would use ITaskService COM interface */
    /* For now, tasks are re-created by stealth_resilience.cpp */
    return FALSE;
}

/* Restore a registry value */
static BOOL RestoreRegistry(MonitorItem* item)
{
    HKEY hRootKey = HKEY_LOCAL_MACHINE;
    HKEY hKey = NULL;
    WCHAR subKey[256];
    WCHAR valueName[128];
    BOOL result = FALSE;

    /* Parse identifier */
    WCHAR* p = item->identifier;
    WCHAR* slash2;

    if (wcsncmp(p, L"HKLM\\", 5) == 0) {
        hRootKey = HKEY_LOCAL_MACHINE;
        p += 5;
    } else if (wcsncmp(p, L"HKCU\\", 5) == 0) {
        hRootKey = HKEY_CURRENT_USER;
        p += 5;
    } else if (wcsncmp(p, L"HKCR\\", 5) == 0) {
        hRootKey = HKEY_CLASSES_ROOT;
        p += 5;
    }

    slash2 = wcsrchr(p, L'\\');
    if (!slash2) {
        return FALSE;
    }

    size_t subKeyLen = slash2 - p;
    wcsncpy_s(subKey, 256, p, subKeyLen);
    subKey[subKeyLen] = L'\0';

    wcscpy_s(valueName, 128, slash2 + 1);
    if (wcscmp(valueName, L"(Default)") == 0) {
        valueName[0] = L'\0';
    }

    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD len = (DWORD)((wcslen(item->expectedValue) + 1) * sizeof(WCHAR));
        if (RegSetValueExW(hKey, valueName[0] ? valueName : NULL,
                          0, REG_SZ, (const BYTE*)item->expectedValue, len) == ERROR_SUCCESS) {
            result = TRUE;
        }
        RegCloseKey(hKey);
    }

    return result;
}

/* Restore/restart a process */
static BOOL RestoreProcess(MonitorItem* item)
{
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    BOOL result;

    if (item->expectedValue[0] == L'\0') {
        return FALSE; /* No exe path specified */
    }

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    result = CreateProcessW(
        item->expectedValue,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return result;
}

/* Log a tamper event to file */
static void LogTamperEvent(const MonitorItem* item, const WCHAR* currentValue)
{
    FILE* fp;
    WCHAR logPath[MAX_PATH];
    SYSTEMTIME st;
    const WCHAR* typeNames[] = { L"SERVICE", L"TASK", L"REGISTRY", L"PROCESS", L"FILE" };

    if (g_Monitor.config.logFilePath[0]) {
        wcscpy_s(logPath, MAX_PATH, g_Monitor.config.logFilePath);
    } else {
        /* Use dynamic path resolution utility */
        Stealth_GetDataFilePathW(STEALTH_FALLBACK_SERVICE_NAME, L"tamper.log",
                                  logPath, MAX_PATH);
    }

    GetLocalTime(&st);

    if (_wfopen_s(&fp, logPath, L"a") == 0 && fp) {
        fwprintf(fp, L"[%04d-%02d-%02d %02d:%02d:%02d] TAMPER: Type=%s Item=%s Expected=%s Current=%s\n",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond,
                 typeNames[item->type],
                 item->identifier,
                 item->expectedValue,
                 currentValue ? currentValue : L"(unknown)");
        fclose(fp);
    }
}

static const WCHAR* Monitor_FindFileNameComponent(const WCHAR* path)
{
    const WCHAR* fileName = NULL;

    if (path == NULL || path[0] == L'\0') { return L""; }
    fileName = wcsrchr(path, L'\\');
    if (fileName == NULL) { fileName = wcsrchr(path, L'/'); }
    return (fileName != NULL) ? (fileName + 1) : path;
}

/* Get current time in milliseconds */
static LONGLONG GetCurrentTimeMs(void)
{
    FILETIME ft;
    ULARGE_INTEGER uli;

    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    return (LONGLONG)(uli.QuadPart / 10000);
}
