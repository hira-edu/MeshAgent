/*
 * Stealth Watchdog Module - Implementation
 *
 * Implements mutual watchdog mesh pattern where multiple lightweight processes
 * monitor each other and respawn on termination.
 *
 * Ported from:
 * - ecraft/ecraft-watchdogservice (MIT)
 * - onewe/watchDog-windows (MIT)
 * - anodejs/hongen (MIT)
 */

#include "stealth_watchdog.h"
#include <stdio.h>
#include <strsafe.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "advapi32.lib")

/* Maximum processes to watch */
#define MAX_WATCHED_PROCESSES 16

/* Shared memory name prefix */
#define HEARTBEAT_PREFIX L"Global\\MeshAgentHB_"

/* Maximum backoff delay to prevent excessive waits (30 seconds) */
#define MAX_BACKOFF_DELAY_MS 30000

/* Time window for restart counter reset (1 minute) */
#define RESTART_STABILITY_WINDOW_MS 60000

/* Internal state */
static WatchedProcess g_WatchedProcesses[MAX_WATCHED_PROCESSES];
static DWORD g_WatchedCount = 0;
static CRITICAL_SECTION g_WatchLock;
static INIT_ONCE g_WatchLockInitOnce = INIT_ONCE_STATIC_INIT;
static HANDLE g_WatchThread = NULL;
static volatile LONG g_WatchRunning = 0;  /* Use LONG for Interlocked operations */
static volatile LONG g_WatchLockReady = 0; /* Track if lock is initialized */
static WatchdogConfig g_Config;
static HANDLE g_JobObject = NULL;

/* Heartbeat state */
static HANDLE g_HeartbeatMap = NULL;
static WatchdogHeartbeat* g_Heartbeat = NULL;
static CRITICAL_SECTION g_HeartbeatLock;
static INIT_ONCE g_HeartbeatLockInitOnce = INIT_ONCE_STATIC_INIT;
static volatile LONG g_HeartbeatLockReady = 0;

/* Thread-safe lock initialization callback */
static BOOL CALLBACK InitWatchLockOnce(PINIT_ONCE initOnce, PVOID param, PVOID* context)
{
    (void)initOnce; (void)param; (void)context;
    InitializeCriticalSection(&g_WatchLock);
    InterlockedExchange(&g_WatchLockReady, 1);
    return TRUE;
}

static BOOL CALLBACK InitHeartbeatLockOnce(PINIT_ONCE initOnce, PVOID param, PVOID* context)
{
    (void)initOnce; (void)param; (void)context;
    InitializeCriticalSection(&g_HeartbeatLock);
    InterlockedExchange(&g_HeartbeatLockReady, 1);
    return TRUE;
}

/* Safe lock acquisition */
static BOOL AcquireWatchLock(void)
{
    if (!InitOnceExecuteOnce(&g_WatchLockInitOnce, InitWatchLockOnce, NULL, NULL)) {
        return FALSE;
    }
    EnterCriticalSection(&g_WatchLock);
    return TRUE;
}

static void ReleaseWatchLock(void)
{
    if (InterlockedCompareExchange(&g_WatchLockReady, 0, 0) != 0) {
        LeaveCriticalSection(&g_WatchLock);
    }
}

static BOOL Watchdog_EnsureJobObjectLocked(void)
{
    if (g_JobObject != NULL) {
        return TRUE;
    }

    g_JobObject = CreateJobObjectW(NULL, NULL);
    if (g_JobObject == NULL) {
        return FALSE;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = {0};
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(g_JobObject, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo))) {
        CloseHandle(g_JobObject);
        g_JobObject = NULL;
        return FALSE;
    }

    return TRUE;
}

HANDLE Watchdog_GetOrCreateJobObject(void)
{
    HANDLE job = NULL;

    if (!AcquireWatchLock()) {
        return NULL;
    }

    if (Watchdog_EnsureJobObjectLocked()) {
        job = g_JobObject;
    }

    ReleaseWatchLock();
    return job;
}

static BOOL AcquireHeartbeatLock(void)
{
    if (!InitOnceExecuteOnce(&g_HeartbeatLockInitOnce, InitHeartbeatLockOnce, NULL, NULL)) {
        return FALSE;
    }
    EnterCriticalSection(&g_HeartbeatLock);
    return TRUE;
}

typedef struct _WatchdogProcessKey {
    WCHAR exePath[MAX_PATH];
    const WCHAR* arguments;
} WatchdogProcessKey;

/* Forward declarations */
static DWORD WINAPI WatchdogThreadProc(LPVOID param);
static BOOL CreateWatchedProcess(WatchedProcess* wp);
static void TerminateWatchedProcess(WatchedProcess* wp);
static BOOL WINAPI WatchdogConsoleHandler(DWORD ctrlType);
static BOOL Watchdog_NormalizePath(const WCHAR* inputPath, WCHAR* outputPath, size_t outputCount);
static void Watchdog_BuildProcessKey(WatchdogProcessKey* key, const WCHAR* exePath, const WCHAR* arguments);
static int Watchdog_FindProcessIndexLocked(const WatchdogProcessKey* key);

void Watchdog_InitConfig(WatchdogConfig* config)
{
    if (config == NULL) return;

    config->checkIntervalMs = 8000;      /* 8 seconds */
    config->restartDelayMs = 1000;       /* 1 second */
    config->maxRestartAttempts = 10;
    config->backoffMultiplier = 2;
    config->useJobObject = TRUE;
    config->hidden = TRUE;
}

BOOL Watchdog_Start(const WatchdogConfig* config)
{
    if (InterlockedCompareExchange(&g_WatchRunning, 0, 0) != 0) {
        return TRUE; /* Already running */
    }

    /* Initialize critical section using thread-safe InitOnce */
    if (!InitOnceExecuteOnce(&g_WatchLockInitOnce, InitWatchLockOnce, NULL, NULL)) {
        return FALSE;
    }

    /* Copy config under lock */
    if (!AcquireWatchLock()) {
        return FALSE;
    }

    if (config != NULL) {
        g_Config = *config;
    } else {
        Watchdog_InitConfig(&g_Config);
    }

    ReleaseWatchLock();

    /* Create job object for child process management */
    if (g_Config.useJobObject) {
        if (!AcquireWatchLock()) {
            return FALSE;
        }
        if (!Watchdog_EnsureJobObjectLocked()) {
            ReleaseWatchLock();
            return FALSE;
        }
        ReleaseWatchLock();
    }

    /* Start watchdog thread */
    InterlockedExchange(&g_WatchRunning, 1);
    g_WatchThread = CreateThread(NULL, 0, WatchdogThreadProc, NULL, 0, NULL);
    if (g_WatchThread == NULL) {
        InterlockedExchange(&g_WatchRunning, 0);
        if (g_JobObject) {
            CloseHandle(g_JobObject);
            g_JobObject = NULL;
        }
        return FALSE;
    }

    return TRUE;
}

void Watchdog_Stop(void)
{
    if (InterlockedCompareExchange(&g_WatchRunning, 0, 0) == 0) {
        return;
    }

    InterlockedExchange(&g_WatchRunning, 0);

    /* Wait for thread to exit - increased timeout to 15 seconds */
    if (g_WatchThread != NULL) {
        DWORD waitResult = WaitForSingleObject(g_WatchThread, 15000);
        if (waitResult == WAIT_TIMEOUT) {
            /* Thread didn't exit gracefully - force terminate */
            TerminateThread(g_WatchThread, 1);
        }
        CloseHandle(g_WatchThread);
        g_WatchThread = NULL;
    }

    /* Clean up job object (will terminate all child processes) */
    if (g_JobObject != NULL) {
        CloseHandle(g_JobObject);
        g_JobObject = NULL;
    }

    /* Clean up watched processes - use safe lock acquisition */
    if (InterlockedCompareExchange(&g_WatchLockReady, 0, 0) != 0) {
        if (AcquireWatchLock()) {
            for (DWORD i = 0; i < g_WatchedCount; i++) {
                if (g_WatchedProcesses[i].hProcess != NULL) {
                    CloseHandle(g_WatchedProcesses[i].hProcess);
                    g_WatchedProcesses[i].hProcess = NULL;
                }
            }
            g_WatchedCount = 0;
            ReleaseWatchLock();
        }
        /* Note: Critical section is not deleted since InitOnce
           doesn't support reinitialization. This is acceptable
           as the section is static and will be reused. */
    }
}

static BOOL Watchdog_NormalizePath(
    const WCHAR* inputPath,
    WCHAR* outputPath,
    size_t outputCount)
{
    if (outputPath == NULL || outputCount == 0) {
        return FALSE;
    }

    if (inputPath == NULL || inputPath[0] == L'\0') {
        outputPath[0] = L'\0';
        return FALSE;
    }

    WCHAR fullPath[MAX_PATH];
    DWORD copied = GetFullPathNameW(inputPath, (DWORD)_countof(fullPath), fullPath, NULL);
    if (copied == 0 || copied >= _countof(fullPath)) {
        StringCchCopyW(outputPath, outputCount, inputPath);
        return FALSE;
    }

    WCHAR longPath[MAX_PATH];
    DWORD longLen = GetLongPathNameW(fullPath, longPath, _countof(longPath));
    if (longLen > 0 && longLen < _countof(longPath)) {
        StringCchCopyW(outputPath, outputCount, longPath);
    } else {
        StringCchCopyW(outputPath, outputCount, fullPath);
    }

    return TRUE;
}

static const WCHAR* Watchdog_NormalizeArguments(const WCHAR* arguments)
{
    return (arguments != NULL && arguments[0] != L'\0') ? arguments : L"";
}

static const WCHAR* Watchdog_GetStoredArguments(const WatchedProcess* wp)
{
    if (wp == NULL || wp->arguments[0] == L'\0') {
        return L"";
    }
    return wp->arguments;
}

static void Watchdog_BuildProcessKey(
    WatchdogProcessKey* key,
    const WCHAR* exePath,
    const WCHAR* arguments)
{
    if (key == NULL) {
        return;
    }

    ZeroMemory(key, sizeof(*key));

    if (exePath != NULL && exePath[0] != L'\0') {
        Watchdog_NormalizePath(exePath, key->exePath, _countof(key->exePath));
    } else {
        key->exePath[0] = L'\0';
    }

    key->arguments = Watchdog_NormalizeArguments(arguments);
}

static int Watchdog_FindProcessIndexLocked(const WatchdogProcessKey* key)
{
    if (key == NULL || key->exePath[0] == L'\0') {
        return -1;
    }

    const WCHAR* normalizedArgs = (key->arguments != NULL) ? key->arguments : L"";

    for (DWORD i = 0; i < g_WatchedCount; i++) {
        const WCHAR* storedArgs = Watchdog_GetStoredArguments(&g_WatchedProcesses[i]);
        if (_wcsicmp(g_WatchedProcesses[i].exePath, key->exePath) == 0 &&
            _wcsicmp(storedArgs, normalizedArgs) == 0) {
            return (int)i;
        }
    }

    return -1;
}

/* Sanitize command-line arguments to prevent injection */
static BOOL Watchdog_SanitizeArguments(const WCHAR* input, WCHAR* output, size_t outputSize)
{
    if (output == NULL || outputSize == 0) {
        return FALSE;
    }

    output[0] = L'\0';

    if (input == NULL || input[0] == L'\0') {
        return TRUE; /* Empty is valid */
    }

    /* Check for dangerous characters that could enable command injection */
    static const WCHAR* dangerousChars = L"|&;<>`$";
    for (const WCHAR* p = input; *p != L'\0'; p++) {
        if (wcschr(dangerousChars, *p) != NULL) {
            /* Found dangerous character - reject */
            return FALSE;
        }
    }

    /* Check for dangerous command patterns */
    static const WCHAR* dangerousPatterns[] = {
        L"cmd.exe", L"cmd /c", L"powershell", L"wscript", L"cscript",
        L"../", L"..\\", L"%COMSPEC%", L"%SystemRoot%",
        NULL
    };

    WCHAR lowerInput[512];
    StringCchCopyW(lowerInput, _countof(lowerInput), input);
    _wcslwr_s(lowerInput, _countof(lowerInput));

    for (int i = 0; dangerousPatterns[i] != NULL; i++) {
        WCHAR lowerPattern[64];
        StringCchCopyW(lowerPattern, _countof(lowerPattern), dangerousPatterns[i]);
        _wcslwr_s(lowerPattern, _countof(lowerPattern));

        if (wcsstr(lowerInput, lowerPattern) != NULL) {
            return FALSE; /* Dangerous pattern found */
        }
    }

    StringCchCopyW(output, outputSize, input);
    return TRUE;
}

BOOL Watchdog_AddProcess(
    const WCHAR* exePath,
    const WCHAR* arguments,
    const WCHAR* workingDir)
{
    if (exePath == NULL || exePath[0] == L'\0') {
        return FALSE;
    }

    WatchdogProcessKey key;
    Watchdog_BuildProcessKey(&key, exePath, arguments);
    if (key.exePath[0] == L'\0') {
        return FALSE;
    }

    /* Sanitize arguments to prevent command injection */
    WCHAR sanitizedArgs[512] = {0};
    if (!Watchdog_SanitizeArguments(key.arguments, sanitizedArgs, _countof(sanitizedArgs))) {
        return FALSE; /* Arguments contain dangerous content */
    }

    if (!AcquireWatchLock()) {
        return FALSE;
    }

    /* Check if already watching */
    if (Watchdog_FindProcessIndexLocked(&key) >= 0) {
        ReleaseWatchLock();
        return TRUE; /* Already watching */
    }

    /* Check capacity */
    if (g_WatchedCount >= MAX_WATCHED_PROCESSES) {
        ReleaseWatchLock();
        return FALSE;
    }

    /* Add new entry */
    WatchedProcess* wp = &g_WatchedProcesses[g_WatchedCount];
    ZeroMemory(wp, sizeof(WatchedProcess));

    StringCchCopyW(wp->exePath, MAX_PATH, key.exePath);
    if (sanitizedArgs[0] != L'\0') {
        StringCchCopyW(wp->arguments, 512, sanitizedArgs);
    }
    if (workingDir != NULL && workingDir[0] != L'\0') {
        WCHAR normalizedDir[MAX_PATH];
        if (Watchdog_NormalizePath(workingDir, normalizedDir, _countof(normalizedDir))) {
            StringCchCopyW(wp->workingDir, MAX_PATH, normalizedDir);
        } else {
            StringCchCopyW(wp->workingDir, MAX_PATH, workingDir);
        }
    }
    wp->enabled = TRUE;

    g_WatchedCount++;

    /* Start the process immediately */
    CreateWatchedProcess(wp);

    ReleaseWatchLock();
    return TRUE;
}

BOOL Watchdog_RemoveProcess(
    const WCHAR* exePath,
    const WCHAR* arguments)
{
    if (exePath == NULL || exePath[0] == L'\0') {
        return FALSE;
    }

    WatchdogProcessKey key;
    Watchdog_BuildProcessKey(&key, exePath, arguments);
    if (key.exePath[0] == L'\0') {
        return FALSE;
    }

    if (!AcquireWatchLock()) {
        return FALSE;
    }

    int index = Watchdog_FindProcessIndexLocked(&key);
    if (index >= 0) {
        /* Bounds check before removal */
        if (g_WatchedCount == 0 || (DWORD)index >= g_WatchedCount) {
            ReleaseWatchLock();
            return FALSE;
        }

        /* Terminate if running */
        TerminateWatchedProcess(&g_WatchedProcesses[index]);

        /* Remove from array by shifting */
        for (DWORD j = (DWORD)index; j < g_WatchedCount - 1; j++) {
            g_WatchedProcesses[j] = g_WatchedProcesses[j + 1];
        }

        g_WatchedCount--;
        ZeroMemory(&g_WatchedProcesses[g_WatchedCount], sizeof(WatchedProcess));

        ReleaseWatchLock();
        return TRUE;
    }

    ReleaseWatchLock();
    return FALSE;
}

BOOL Watchdog_RestartProcess(
    const WCHAR* exePath,
    const WCHAR* arguments)
{
    if (exePath == NULL || exePath[0] == L'\0') {
        return FALSE;
    }

    WatchdogProcessKey key;
    Watchdog_BuildProcessKey(&key, exePath, arguments);
    if (key.exePath[0] == L'\0') {
        return FALSE;
    }

    DWORD restartDelay = g_Config.restartDelayMs;
    BOOL scheduled = FALSE;

    if (!AcquireWatchLock()) {
        return FALSE;
    }

    int index = Watchdog_FindProcessIndexLocked(&key);
    if (index >= 0) {
        TerminateWatchedProcess(&g_WatchedProcesses[index]);
        scheduled = TRUE;
    }

    ReleaseWatchLock();

    if (!scheduled) {
        return FALSE;
    }

    /* Sleep outside the critical section */
    Sleep(restartDelay);

    /* Re-acquire lock to restart */
    if (!AcquireWatchLock()) {
        return FALSE;
    }

    BOOL result = FALSE;
    index = Watchdog_FindProcessIndexLocked(&key);
    if (index >= 0) {
        result = CreateWatchedProcess(&g_WatchedProcesses[index]);
    }

    ReleaseWatchLock();
    return result;
}

BOOL Watchdog_GetProcessStatus(
    const WCHAR* exePath,
    const WCHAR* arguments,
    DWORD* outPid,
    DWORD* outRestartCount)
{
    if (exePath == NULL || exePath[0] == L'\0') {
        return FALSE;
    }

    WatchdogProcessKey key;
    Watchdog_BuildProcessKey(&key, exePath, arguments);
    if (key.exePath[0] == L'\0') {
        return FALSE;
    }

    if (!AcquireWatchLock()) {
        return FALSE;
    }

    int index = Watchdog_FindProcessIndexLocked(&key);
    if (index >= 0) {
        if (outPid != NULL) {
            *outPid = g_WatchedProcesses[index].processId;
        }
        if (outRestartCount != NULL) {
            *outRestartCount = g_WatchedProcesses[index].restartCount;
        }
        ReleaseWatchLock();
        return TRUE;
    }

    ReleaseWatchLock();
    return FALSE;
}

BOOL Watchdog_CreateHeartbeat(
    const WCHAR* serviceName,
    HANDLE* outMapHandle)
{
    if (serviceName == NULL || outMapHandle == NULL) {
        return FALSE;
    }

    /* Initialize heartbeat lock */
    if (!InitOnceExecuteOnce(&g_HeartbeatLockInitOnce, InitHeartbeatLockOnce, NULL, NULL)) {
        return FALSE;
    }

    if (!AcquireHeartbeatLock()) {
        return FALSE;
    }

    /* Clean up existing heartbeat if already created (prevent memory leak) */
    if (g_Heartbeat != NULL) {
        InterlockedExchange(&g_Heartbeat->status, 2); /* Mark as stopping */
        UnmapViewOfFile(g_Heartbeat);
        g_Heartbeat = NULL;
    }
    if (g_HeartbeatMap != NULL) {
        CloseHandle(g_HeartbeatMap);
        g_HeartbeatMap = NULL;
    }

    /* Build shared memory name */
    WCHAR mapName[128];
    StringCchPrintfW(mapName, 128, L"%s%s", HEARTBEAT_PREFIX, serviceName);

    /* Create file mapping */
    HANDLE hMap = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(WatchdogHeartbeat),
        mapName);

    if (hMap == NULL) {
        LeaveCriticalSection(&g_HeartbeatLock);
        return FALSE;
    }

    /* Map view */
    WatchdogHeartbeat* hb = (WatchdogHeartbeat*)MapViewOfFile(
        hMap,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(WatchdogHeartbeat));

    if (hb == NULL) {
        CloseHandle(hMap);
        LeaveCriticalSection(&g_HeartbeatLock);
        return FALSE;
    }

    /* Initialize heartbeat */
    hb->status = 1; /* Running */
    hb->timestamp = GetTickCount64();
    hb->ownerPid = GetCurrentProcessId();
    StringCchCopyW(hb->serviceName, 64, serviceName);

    /* Store globally */
    g_HeartbeatMap = hMap;
    g_Heartbeat = hb;
    *outMapHandle = hMap;

    LeaveCriticalSection(&g_HeartbeatLock);
    return TRUE;
}

void Watchdog_SendHeartbeat(void)
{
    /* Thread-safe check and update */
    WatchdogHeartbeat* hb = (WatchdogHeartbeat*)InterlockedCompareExchangePointer(
        (PVOID*)&g_Heartbeat, NULL, NULL);
    if (hb != NULL) {
        InterlockedExchange64(&hb->timestamp, GetTickCount64());
    }
}

BOOL Watchdog_MonitorHeartbeat(
    const WCHAR* serviceName,
    DWORD timeoutMs,
    BOOL* outIsAlive)
{
    if (serviceName == NULL || outIsAlive == NULL) {
        return FALSE;
    }

    *outIsAlive = FALSE;

    /* Build shared memory name */
    WCHAR mapName[128];
    StringCchPrintfW(mapName, 128, L"%s%s", HEARTBEAT_PREFIX, serviceName);

    /* Open existing mapping */
    HANDLE hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, mapName);
    if (hMap == NULL) {
        return FALSE; /* Heartbeat doesn't exist */
    }

    /* Map view */
    WatchdogHeartbeat* hb = (WatchdogHeartbeat*)MapViewOfFile(
        hMap,
        FILE_MAP_READ,
        0, 0,
        sizeof(WatchdogHeartbeat));

    if (hb == NULL) {
        CloseHandle(hMap);
        return FALSE;
    }

    /* Check if alive - use atomic reads for both status and timestamp */
    LONGLONG currentTime = GetTickCount64();
    LONGLONG lastHeartbeat = InterlockedCompareExchange64(
        (volatile LONGLONG*)&hb->timestamp, 0, 0);
    LONG currentStatus = InterlockedCompareExchange(
        (volatile LONG*)&hb->status, 0, 0);

    if (currentStatus == 1 && (currentTime - lastHeartbeat) < (LONGLONG)timeoutMs) {
        *outIsAlive = TRUE;
    }

    UnmapViewOfFile(hb);
    CloseHandle(hMap);
    return TRUE;
}

void Watchdog_CloseHeartbeat(HANDLE mapHandle)
{
    /* Mark as stopping before cleanup */
    if (g_Heartbeat != NULL) {
        InterlockedExchange(&g_Heartbeat->status, 2); /* Stopping - use atomic write */
        UnmapViewOfFile(g_Heartbeat);
        g_Heartbeat = NULL;
    }

    /* Close the global map handle */
    if (g_HeartbeatMap != NULL) {
        HANDLE localHandle = g_HeartbeatMap;
        g_HeartbeatMap = NULL;
        CloseHandle(localHandle);

        /* Only close mapHandle if it's different AND not already closed */
        if (mapHandle != NULL && mapHandle != localHandle) {
            CloseHandle(mapHandle);
        }
    } else if (mapHandle != NULL) {
        /* g_HeartbeatMap was already NULL, close mapHandle if provided */
        CloseHandle(mapHandle);
    }
}

BOOL Watchdog_InstallAsService(
    const WCHAR* serviceName,
    const WCHAR* displayName,
    const WCHAR* targetServiceName)
{
    if (serviceName == NULL || targetServiceName == NULL) {
        return FALSE;
    }

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm == NULL) {
        return FALSE;
    }

    /* Get current executable path */
    WCHAR exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        CloseServiceHandle(hScm);
        return FALSE;
    }

    /* Build command line with watchdog mode flag */
    WCHAR cmdLine[512];
    StringCchPrintfW(cmdLine, 512, L"\"%s\" -watchdog \"%s\"", exePath, targetServiceName);

    SC_HANDLE hService = CreateServiceW(
        hScm,
        serviceName,
        displayName ? displayName : serviceName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        cmdLine,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if (hService == NULL) {
        CloseServiceHandle(hScm);
        return FALSE;
    }

    /* Configure for restart on failure */
    SERVICE_FAILURE_ACTIONSW sfa = {0};
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 10000;
    actions[2].Type = SC_ACTION_RESTART;
    actions[2].Delay = 30000;
    sfa.dwResetPeriod = 86400;
    sfa.cActions = 3;
    sfa.lpsaActions = actions;

    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

    /* Set description */
    SERVICE_DESCRIPTIONW sd;
    sd.lpDescription = L"Monitors and maintains system diagnostic services.";
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
    return TRUE;
}

BOOL Watchdog_UninstallService(const WCHAR* serviceName)
{
    if (serviceName == NULL) {
        return FALSE;
    }

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hScm == NULL) {
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(hScm, serviceName, SERVICE_STOP | DELETE);
    if (hService == NULL) {
        CloseServiceHandle(hScm);
        return FALSE;
    }

    /* Stop service if running */
    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    /* Delete service */
    BOOL result = DeleteService(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
    return result;
}

void Watchdog_ServiceMain(
    const WCHAR* targetServiceName,
    const WatchdogConfig* config)
{
    if (targetServiceName == NULL) {
        return;
    }

    WatchdogConfig cfg;
    if (config != NULL) {
        cfg = *config;
    } else {
        Watchdog_InitConfig(&cfg);
    }

    InterlockedExchange(&g_WatchRunning, 1);
    SetConsoleCtrlHandler(WatchdogConsoleHandler, TRUE);

    /* Monitor target service via heartbeat */
    while (InterlockedCompareExchange(&g_WatchRunning, 0, 0) != 0) {
        BOOL isAlive = FALSE;

        if (Watchdog_MonitorHeartbeat(targetServiceName, cfg.checkIntervalMs * 2, &isAlive)) {
            if (!isAlive) {
                /* Target service appears dead, restart it */
                SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
                if (hScm != NULL) {
                    SC_HANDLE hService = OpenServiceW(hScm, targetServiceName, SERVICE_START);
                    if (hService != NULL) {
                        StartServiceW(hService, 0, NULL);
                        CloseServiceHandle(hService);
                    }
                    CloseServiceHandle(hScm);
                }
            }
        } else {
            /* Heartbeat doesn't exist, try to start service anyway */
            SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            if (hScm != NULL) {
                SC_HANDLE hService = OpenServiceW(hScm, targetServiceName,
                    SERVICE_QUERY_STATUS | SERVICE_START);
                if (hService != NULL) {
                    SERVICE_STATUS_PROCESS ssp;
                    DWORD needed;
                    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                        (LPBYTE)&ssp, sizeof(ssp), &needed)) {
                        if (ssp.dwCurrentState == SERVICE_STOPPED) {
                            StartServiceW(hService, 0, NULL);
                        }
                    }
                    CloseServiceHandle(hService);
                }
                CloseServiceHandle(hScm);
            }
        }

        Sleep(cfg.checkIntervalMs);
    }

    SetConsoleCtrlHandler(WatchdogConsoleHandler, FALSE);
    InterlockedExchange(&g_WatchRunning, 0);
}

/* ================================================================
 * Internal Functions
 * ================================================================ */

static BOOL CreateWatchedProcess(WatchedProcess* wp)
{
    if (wp == NULL || wp->exePath[0] == L'\0') {
        return FALSE;
    }

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};

    si.cb = sizeof(STARTUPINFOW);
    if (g_Config.hidden) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }

    /* Build command line */
    WCHAR cmdLine[1024];
    if (wp->arguments[0] != L'\0') {
        StringCchPrintfW(cmdLine, 1024, L"\"%s\" %s", wp->exePath, wp->arguments);
    } else {
        StringCchPrintfW(cmdLine, 1024, L"\"%s\"", wp->exePath);
    }

    /* Create process */
    BOOL result = CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_PROCESS_GROUP | (g_Config.hidden ? CREATE_NO_WINDOW : 0),
        NULL,
        wp->workingDir[0] != L'\0' ? wp->workingDir : NULL,
        &si,
        &pi);

    if (!result) {
        return FALSE;
    }

    /* Assign to job object if enabled */
    if (g_JobObject != NULL) {
        AssignProcessToJobObject(g_JobObject, pi.hProcess);
    }

    /* Update watched process info */
    wp->processId = pi.dwProcessId;
    wp->hProcess = pi.hProcess;
    wp->lastRestartTime = GetTickCount64();

    CloseHandle(pi.hThread);
    return TRUE;
}

static void TerminateWatchedProcess(WatchedProcess* wp)
{
    if (wp == NULL) {
        return;
    }

    if (wp->hProcess != NULL) {
        TerminateProcess(wp->hProcess, 0);
        CloseHandle(wp->hProcess);
        wp->hProcess = NULL;
    }
    wp->processId = 0;
}

/* Structure to hold pending restart information */
typedef struct {
    DWORD index;
    DWORD delay;
    BOOL shouldRestart;
} PendingRestart;

/* Calculate backoff delay with overflow protection */
static DWORD CalculateSafeBackoff(DWORD baseDelay, DWORD restartCount)
{
    if (baseDelay == 0) {
        baseDelay = 1000; /* Default to 1 second if not configured */
    }

    if (restartCount == 0) {
        return baseDelay;
    }

    /* Limit shift to prevent overflow: 2^10 = 1024 max multiplier */
    DWORD shift = (restartCount < 10 ? restartCount : 10);
    DWORD multiplier = (1U << shift);

    /* Check for overflow before multiplication */
    if (baseDelay > (MAX_BACKOFF_DELAY_MS / multiplier)) {
        return MAX_BACKOFF_DELAY_MS;
    }

    DWORD delay = baseDelay * multiplier;
    if (delay > MAX_BACKOFF_DELAY_MS) {
        delay = MAX_BACKOFF_DELAY_MS;
    }

    return delay;
}

static DWORD WINAPI WatchdogThreadProc(LPVOID param)
{
    (void)param;
    PendingRestart pendingRestarts[MAX_WATCHED_PROCESSES];
    DWORD pendingCount = 0;

    while (InterlockedCompareExchange(&g_WatchRunning, 0, 0) != 0) {
        pendingCount = 0;

        /* Phase 1: Collect restart information under lock */
        if (!AcquireWatchLock()) {
            Sleep(g_Config.checkIntervalMs);
            continue;
        }

        for (DWORD i = 0; i < g_WatchedCount; i++) {
            WatchedProcess* wp = &g_WatchedProcesses[i];

            if (!wp->enabled) {
                continue;
            }

            /* Check if process is still running - store handle locally to avoid race */
            BOOL needsRestart = FALSE;
            HANDLE hProc = wp->hProcess;

            if (hProc == NULL) {
                needsRestart = TRUE;
            } else {
                DWORD exitCode = 0;
                if (GetExitCodeProcess(hProc, &exitCode)) {
                    if (exitCode != STILL_ACTIVE) {
                        needsRestart = TRUE;
                        CloseHandle(hProc);
                        wp->hProcess = NULL;
                        wp->processId = 0;
                    }
                }
            }

            if (needsRestart && wp->restartCount < g_Config.maxRestartAttempts) {
                /* Calculate backoff delay with overflow protection */
                DWORD delay = g_Config.restartDelayMs;
                if (wp->restartCount > 0) {
                    ULONGLONG timeSinceLast = GetTickCount64() - wp->lastRestartTime;
                    if (timeSinceLast < RESTART_STABILITY_WINDOW_MS) {
                        delay = CalculateSafeBackoff(g_Config.restartDelayMs, wp->restartCount);
                    } else {
                        wp->restartCount = 0; /* Reset if stable for a minute */
                    }
                }

                /* Queue for restart */
                pendingRestarts[pendingCount].index = i;
                pendingRestarts[pendingCount].delay = delay;
                pendingRestarts[pendingCount].shouldRestart = TRUE;
                pendingCount++;
            }
        }

        ReleaseWatchLock();

        /* Phase 2: Perform restarts outside lock */
        for (DWORD j = 0; j < pendingCount; j++) {
            if (!pendingRestarts[j].shouldRestart) {
                continue;
            }

            /* Sleep outside the critical section */
            Sleep(pendingRestarts[j].delay);

            /* Check if still running before restart */
            if (InterlockedCompareExchange(&g_WatchRunning, 0, 0) == 0) {
                break;
            }

            /* Re-acquire lock for restart */
            if (!AcquireWatchLock()) {
                continue; /* Skip this restart if we can't get the lock */
            }

            DWORD idx = pendingRestarts[j].index;
            /* Verify index still valid and process still needs restart */
            if (idx < g_WatchedCount && g_WatchedProcesses[idx].enabled &&
                g_WatchedProcesses[idx].hProcess == NULL) {
                if (CreateWatchedProcess(&g_WatchedProcesses[idx])) {
                    g_WatchedProcesses[idx].restartCount++;
                }
            }

            ReleaseWatchLock();
        }

        Sleep(g_Config.checkIntervalMs);
    }

    return 0;
}

static BOOL WINAPI WatchdogConsoleHandler(DWORD ctrlType)
{
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        InterlockedExchange(&g_WatchRunning, 0);
        return TRUE;
    default:
        return FALSE;
    }
}

/* ================================================================
 * Boot Start Functions
 * ================================================================ */

BOOL Watchdog_EnableRunKey(
    const WCHAR* name,
    const WCHAR* exePath,
    const WCHAR* arguments)
{
    if (name == NULL || exePath == NULL) {
        return FALSE;
    }

    HKEY hKey = NULL;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    /* Build command line */
    WCHAR cmdLine[MAX_PATH * 2];
    if (arguments != NULL && arguments[0] != L'\0') {
        StringCchPrintfW(cmdLine, _countof(cmdLine), L"\"%s\" %s", exePath, arguments);
    } else {
        StringCchPrintfW(cmdLine, _countof(cmdLine), L"\"%s\"", exePath);
    }

    result = RegSetValueExW(
        hKey,
        name,
        0,
        REG_SZ,
        (BYTE*)cmdLine,
        (DWORD)((wcslen(cmdLine) + 1) * sizeof(WCHAR)));

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Watchdog_DisableRunKey(const WCHAR* name)
{
    if (name == NULL) {
        return FALSE;
    }

    HKEY hKey = NULL;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    result = RegDeleteValueW(hKey, name);
    RegCloseKey(hKey);

    /* Success if deleted or didn't exist */
    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
}

BOOL Watchdog_EnableTaskScheduler(
    const WCHAR* taskName,
    const WCHAR* exePath,
    const WCHAR* arguments,
    BOOL runAtBoot,
    BOOL runAsSystem)
{
    if (taskName == NULL || exePath == NULL) {
        return FALSE;
    }

    /* Security fix: Use GetTempFileNameW to create a unique, unpredictable temp file
     * instead of a predictable path based on taskName (prevents symlink attacks) */
    WCHAR tempDir[MAX_PATH];
    WCHAR xmlPath[MAX_PATH];

    if (GetTempPathW(MAX_PATH, tempDir) == 0) {
        return FALSE;
    }

    /* GetTempFileNameW creates a unique file - the 0 parameter means it creates
     * the file, which prevents race conditions */
    if (GetTempFileNameW(tempDir, L"TSK", 0, xmlPath) == 0) {
        return FALSE;
    }

    /* Open with exclusive write access - file will be read by schtasks later */
    FILE* fp = _wfopen(xmlPath, L"w, ccs=UTF-8");
    if (fp == NULL) {
        DeleteFileW(xmlPath);
        return FALSE;
    }

    /* Write XML header */
    fwprintf(fp, L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n");
    fwprintf(fp, L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n");
    fwprintf(fp, L"  <RegistrationInfo>\n");
    fwprintf(fp, L"    <Description>MeshAgent Watchdog Service</Description>\n");
    fwprintf(fp, L"  </RegistrationInfo>\n");

    /* Triggers */
    fwprintf(fp, L"  <Triggers>\n");
    if (runAtBoot) {
        fwprintf(fp, L"    <BootTrigger>\n");
        fwprintf(fp, L"      <Enabled>true</Enabled>\n");
        fwprintf(fp, L"    </BootTrigger>\n");
    } else {
        fwprintf(fp, L"    <LogonTrigger>\n");
        fwprintf(fp, L"      <Enabled>true</Enabled>\n");
        fwprintf(fp, L"    </LogonTrigger>\n");
    }
    fwprintf(fp, L"  </Triggers>\n");

    /* Principal */
    fwprintf(fp, L"  <Principals>\n");
    fwprintf(fp, L"    <Principal id=\"Author\">\n");
    if (runAsSystem) {
        fwprintf(fp, L"      <UserId>S-1-5-18</UserId>\n");  /* SYSTEM SID */
        fwprintf(fp, L"      <RunLevel>HighestAvailable</RunLevel>\n");
    } else {
        fwprintf(fp, L"      <GroupId>S-1-5-32-545</GroupId>\n");  /* Users group */
        fwprintf(fp, L"      <RunLevel>LeastPrivilege</RunLevel>\n");
    }
    fwprintf(fp, L"    </Principal>\n");
    fwprintf(fp, L"  </Principals>\n");

    /* Settings */
    fwprintf(fp, L"  <Settings>\n");
    fwprintf(fp, L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n");
    fwprintf(fp, L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n");
    fwprintf(fp, L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n");
    fwprintf(fp, L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n");
    fwprintf(fp, L"    <Priority>7</Priority>\n");
    fwprintf(fp, L"    <Hidden>true</Hidden>\n");
    fwprintf(fp, L"  </Settings>\n");

    /* Actions */
    fwprintf(fp, L"  <Actions Context=\"Author\">\n");
    fwprintf(fp, L"    <Exec>\n");
    fwprintf(fp, L"      <Command>%s</Command>\n", exePath);
    if (arguments != NULL && arguments[0] != L'\0') {
        fwprintf(fp, L"      <Arguments>%s</Arguments>\n", arguments);
    }
    fwprintf(fp, L"    </Exec>\n");
    fwprintf(fp, L"  </Actions>\n");
    fwprintf(fp, L"</Task>\n");

    fclose(fp);

    /* Create task using schtasks.exe */
    WCHAR cmdLine[MAX_PATH * 3];
    StringCchPrintfW(cmdLine, _countof(cmdLine),
        L"schtasks.exe /Create /TN \"%s\" /XML \"%s\" /F",
        taskName, xmlPath);

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL success = CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi);

    if (success) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        success = (exitCode == 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    /* Clean up temp XML file */
    DeleteFileW(xmlPath);

    return success;
}

BOOL Watchdog_DisableTaskScheduler(const WCHAR* taskName)
{
    if (taskName == NULL) {
        return FALSE;
    }

    WCHAR cmdLine[MAX_PATH * 2];
    StringCchPrintfW(cmdLine, _countof(cmdLine),
        L"schtasks.exe /Delete /TN \"%s\" /F",
        taskName);

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL success = CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi);

    if (success) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        /* Success if deleted or task didn't exist (exit code 1) */
        success = (exitCode == 0 || exitCode == 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return success;
}

BOOL Watchdog_EnableWinlogon(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t outSize)
{
    if (exePath == NULL) {
        return FALSE;
    }

    HKEY hKey = NULL;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0,
        KEY_READ | KEY_SET_VALUE,
        &hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    /* Read current Shell value */
    WCHAR currentShell[MAX_PATH * 2] = {0};
    DWORD shellSize = sizeof(currentShell);
    DWORD type = 0;

    result = RegQueryValueExW(hKey, L"Shell", NULL, &type, (BYTE*)currentShell, &shellSize);
    if (result != ERROR_SUCCESS || type != REG_SZ) {
        StringCchCopyW(currentShell, _countof(currentShell), L"explorer.exe");
    }

    /* Return original value if requested */
    if (outOriginalValue != NULL && outSize > 0) {
        StringCchCopyW(outOriginalValue, outSize, currentShell);
    }

    /* Check if already appended */
    if (wcsstr(currentShell, exePath) != NULL) {
        RegCloseKey(hKey);
        return TRUE;  /* Already present */
    }

    /* Append our exe path */
    WCHAR newShell[MAX_PATH * 3];
    StringCchPrintfW(newShell, _countof(newShell), L"%s,%s", currentShell, exePath);

    result = RegSetValueExW(
        hKey,
        L"Shell",
        0,
        REG_SZ,
        (BYTE*)newShell,
        (DWORD)((wcslen(newShell) + 1) * sizeof(WCHAR)));

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Watchdog_DisableWinlogon(
    const WCHAR* exePath,
    const WCHAR* originalValue)
{
    if (exePath == NULL) {
        return FALSE;
    }

    HKEY hKey = NULL;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0,
        KEY_READ | KEY_SET_VALUE,
        &hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    WCHAR newShell[MAX_PATH * 3];

    if (originalValue != NULL && originalValue[0] != L'\0') {
        /* Restore original value */
        StringCchCopyW(newShell, _countof(newShell), originalValue);
    } else {
        /* Read current and remove our entry */
        WCHAR currentShell[MAX_PATH * 3] = {0};
        DWORD shellSize = sizeof(currentShell);
        DWORD type = 0;

        result = RegQueryValueExW(hKey, L"Shell", NULL, &type, (BYTE*)currentShell, &shellSize);
        if (result != ERROR_SUCCESS || type != REG_SZ) {
            RegCloseKey(hKey);
            return FALSE;
        }

        /* Remove our exe from the shell value */
        WCHAR* found = wcsstr(currentShell, exePath);
        if (found != NULL) {
            /* Find the comma before our entry */
            WCHAR* comma = found - 1;
            if (comma >= currentShell && *comma == L',') {
                /* Remove ",exePath" */
                size_t exeLen = wcslen(exePath);
                memmove(comma, found + exeLen, (wcslen(found + exeLen) + 1) * sizeof(WCHAR));
            } else {
                /* Check for comma after our entry */
                size_t exeLen = wcslen(exePath);
                if (found[exeLen] == L',') {
                    /* Remove "exePath," */
                    memmove(found, found + exeLen + 1, (wcslen(found + exeLen + 1) + 1) * sizeof(WCHAR));
                } else {
                    /* Only entry, restore default */
                    StringCchCopyW(currentShell, _countof(currentShell), L"explorer.exe");
                }
            }
        }
        StringCchCopyW(newShell, _countof(newShell), currentShell);
    }

    result = RegSetValueExW(
        hKey,
        L"Shell",
        0,
        REG_SZ,
        (BYTE*)newShell,
        (DWORD)((wcslen(newShell) + 1) * sizeof(WCHAR)));

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Watchdog_EnableBootStart(
    const WCHAR* exePath,
    const WCHAR* arguments,
    const WatchdogConfig* config)
{
    if (config == NULL || exePath == NULL) {
        return FALSE;
    }

    switch (config->bootMethod) {
    case WATCHDOG_BOOT_NONE:
        return TRUE;  /* No-op */

    case WATCHDOG_BOOT_SERVICE:
        /* Service installation handled separately via Watchdog_InstallAsService */
        return TRUE;

    case WATCHDOG_BOOT_RUN_KEY:
        return Watchdog_EnableRunKey(config->bootName, exePath, arguments);

    case WATCHDOG_BOOT_TASK_SCHEDULER:
        return Watchdog_EnableTaskScheduler(config->bootName, exePath, arguments, TRUE, TRUE);

    case WATCHDOG_BOOT_WINLOGON:
        return Watchdog_EnableWinlogon(exePath, NULL, 0);

    default:
        return FALSE;
    }
}

BOOL Watchdog_DisableBootStart(const WatchdogConfig* config)
{
    if (config == NULL) {
        return FALSE;
    }

    switch (config->bootMethod) {
    case WATCHDOG_BOOT_NONE:
        return TRUE;  /* No-op */

    case WATCHDOG_BOOT_SERVICE:
        return Watchdog_UninstallService(config->bootName);

    case WATCHDOG_BOOT_RUN_KEY:
        return Watchdog_DisableRunKey(config->bootName);

    case WATCHDOG_BOOT_TASK_SCHEDULER:
        return Watchdog_DisableTaskScheduler(config->bootName);

    case WATCHDOG_BOOT_WINLOGON:
        /* Would need stored original value; caller should track this */
        return TRUE;

    default:
        return FALSE;
    }
}

BOOL Watchdog_IsBootStartEnabled(const WatchdogConfig* config)
{
    if (config == NULL) {
        return FALSE;
    }

    switch (config->bootMethod) {
    case WATCHDOG_BOOT_NONE:
        return FALSE;

    case WATCHDOG_BOOT_SERVICE: {
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (hSCM == NULL) return FALSE;
        SC_HANDLE hService = OpenServiceW(hSCM, config->bootName, SERVICE_QUERY_STATUS);
        BOOL exists = (hService != NULL);
        if (hService) CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return exists;
    }

    case WATCHDOG_BOOT_RUN_KEY: {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return FALSE;
        }
        WCHAR value[MAX_PATH];
        DWORD size = sizeof(value);
        LONG result = RegQueryValueExW(hKey, config->bootName, NULL, NULL, (BYTE*)value, &size);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }

    case WATCHDOG_BOOT_TASK_SCHEDULER: {
        /* Query task using schtasks */
        WCHAR cmdLine[MAX_PATH * 2];
        StringCchPrintfW(cmdLine, _countof(cmdLine),
            L"schtasks.exe /Query /TN \"%s\"", config->bootName);

        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            return FALSE;
        }
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return (exitCode == 0);
    }

    case WATCHDOG_BOOT_WINLOGON: {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return FALSE;
        }
        WCHAR shell[MAX_PATH * 2];
        DWORD size = sizeof(shell);
        LONG result = RegQueryValueExW(hKey, L"Shell", NULL, NULL, (BYTE*)shell, &size);
        RegCloseKey(hKey);
        if (result != ERROR_SUCCESS) return FALSE;
        /* Check if more than just explorer.exe */
        return (wcsstr(shell, L",") != NULL);
    }

    default:
        return FALSE;
    }
}

/* ================================================================
 * Helper Process Monitor Implementation
 *
 * Ported from best-practice open source implementations:
 * - murrayju/CreateProcessAsUser (MIT)
 * - ondrasek's spawn-interactive-process gist
 * - masthoon's SystemCMD.cpp gist
 *
 * This provides robust service-to-user-session process spawning
 * with session change detection, persistent retry, and idle state
 * management for KVM/RDP helpers.
 *
 * Key features:
 * - Infinite retry with exponential backoff (never gives up)
 * - Idle state when not actively connected (ready but low overhead)
 * - Session change detection and automatic recovery
 * - Integration with main watchdog for monitoring
 * ================================================================ */

#include <wtsapi32.h>
#include <userenv.h>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

/* Helper monitor internal state */
static HelperProcessConfig g_HelperConfig;
static HelperProcessStatus g_HelperStatus;
static CRITICAL_SECTION g_HelperLock;
static BOOL g_HelperLockInitialized = FALSE;
static HANDLE g_HelperThread = NULL;
static volatile LONG g_HelperRunning = 0;
static HelperProcessCallback g_HelperCallback = NULL;
static void* g_HelperUserData = NULL;
static HANDLE g_HelperProcess = NULL;

/* Maximum backoff delay (60 seconds) - keeps trying forever but not too aggressively */
#define HELPER_MAX_BACKOFF_MS 60000

/* Minimum delay between spawn attempts */
#define HELPER_MIN_RETRY_MS 1000
#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260L
#endif

/* Forward declarations for helper functions */
static DWORD WINAPI HelperMonitorThreadProc(LPVOID param);
static BOOL Helper_EnablePrivilege(LPCWSTR privilegeName);
static BOOL Helper_GetActiveUserSession(DWORD* outSessionId);
static BOOL Helper_SpawnProcessInSession(DWORD sessionId, const WCHAR* exePath,
	const WCHAR* arguments, DWORD* outPid, DWORD* outError);
static void Helper_UpdateStatus(HelperProcessState newState, DWORD error, const WCHAR* errorMsg);
static void Helper_NotifyCallback(void);
static BOOL Helper_IsProcessAlive(HANDLE hProcess);
static void Helper_SetLastErrorMessage(DWORD error, WCHAR* buffer, size_t bufferSize);
static void Helper_CloseProcessHandle(void);
static void Helper_TerminateProcessLocked(void);
static ULONGLONG Helper_HashCommandLine(const WCHAR* exePath, const WCHAR* arguments);
static void Helper_LogPolicyDecision(const WCHAR* decision, DWORD sessionId, const WCHAR* exePath, const WCHAR* arguments, DWORD errorCode);
static BOOL Helper_IsSessionSpawnAllowed(DWORD sessionId, const WCHAR* exePath, const WCHAR* arguments, DWORD* outError);
static BOOL Helper_EndsWithInsensitiveW(const WCHAR* value, const WCHAR* suffix);
static BOOL Helper_CommandLineContainsInsensitiveW(const WCHAR* value, const WCHAR* token);

void HelperMonitor_InitConfig(HelperProcessConfig* config)
{
    if (config == NULL) return;

    ZeroMemory(config, sizeof(HelperProcessConfig));
    config->targetSessionId = (DWORD)-1;  /* -1 means active console session */
    config->spawnRetryDelayMs = 2000;     /* 2 seconds between retries */
    config->maxSpawnRetries = 0;          /* 0 = infinite retries (never give up) */
    config->sessionCheckIntervalMs = 5000; /* 5 seconds */
    config->persistentSpawn = TRUE;       /* Keep retrying forever */
    config->monitorSession = TRUE;        /* Monitor for session changes */
    config->strictServiceOnly = TRUE;     /* Default to strict policy */
    config->allowDesktopBridge = FALSE;   /* Desktop bridge must be explicitly enabled */
}

BOOL HelperMonitor_Start(
    const HelperProcessConfig* config,
    HelperProcessCallback callback,
    void* userData)
{
    if (config == NULL) {
        return FALSE;
    }
    if (config->exePath[0] == L'\0') {
        return FALSE;
    }
    if (!HelperMonitor_IsApprovedDesktopBridgeCommand(config->exePath, config->arguments)) {
        SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return FALSE;
    }

    /* Check if already running */
    if (InterlockedCompareExchange(&g_HelperRunning, 0, 0) != 0) {
        return TRUE;
    }

    /* Initialize critical section */
    if (!g_HelperLockInitialized) {
        InitializeCriticalSection(&g_HelperLock);
        g_HelperLockInitialized = TRUE;
    }

    /* Copy configuration */
    EnterCriticalSection(&g_HelperLock);
    g_HelperConfig = *config;
    g_HelperCallback = callback;
    g_HelperUserData = userData;

    /* Initialize status */
    ZeroMemory(&g_HelperStatus, sizeof(g_HelperStatus));
    g_HelperStatus.state = HELPER_STATE_IDLE;
    LeaveCriticalSection(&g_HelperLock);

    /* Enable required privileges for WTSQueryUserToken */
    Helper_EnablePrivilege(L"SeTcbPrivilege");
    Helper_EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
    Helper_EnablePrivilege(L"SeIncreaseQuotaPrivilege");

    /* Start monitor thread */
    InterlockedExchange(&g_HelperRunning, 1);
    g_HelperThread = CreateThread(NULL, 0, HelperMonitorThreadProc, NULL, 0, NULL);

    if (g_HelperThread == NULL) {
        InterlockedExchange(&g_HelperRunning, 0);
        return FALSE;
    }

    return TRUE;
}

void HelperMonitor_Stop(void)
{
    if (InterlockedCompareExchange(&g_HelperRunning, 0, 0) == 0) {
        return;
    }

    InterlockedExchange(&g_HelperRunning, 0);

    /* Wait for thread to exit */
    if (g_HelperThread != NULL) {
        WaitForSingleObject(g_HelperThread, 10000);
        CloseHandle(g_HelperThread);
        g_HelperThread = NULL;
    }

    /* Terminate helper process if running */
    EnterCriticalSection(&g_HelperLock);
    Helper_TerminateProcessLocked();
    g_HelperStatus.state = HELPER_STATE_IDLE;
    g_HelperStatus.spawnAttempts = 0;
    g_HelperStatus.failureCount = 0;
    g_HelperStatus.lastSpawnTime = 0;
    g_HelperStatus.lastSuccessTime = 0;
    g_HelperStatus.lastError = 0;
    g_HelperStatus.lastErrorMessage[0] = L'\0';
    Helper_NotifyCallback();
    g_HelperCallback = NULL;
    g_HelperUserData = NULL;
    LeaveCriticalSection(&g_HelperLock);

    /* Clean up critical section */
    if (g_HelperLockInitialized) {
        DeleteCriticalSection(&g_HelperLock);
        g_HelperLockInitialized = FALSE;
    }
}

BOOL HelperMonitor_RequestSpawn(DWORD targetSessionId)
{
    if (InterlockedCompareExchange(&g_HelperRunning, 0, 0) == 0) {
        return FALSE;
    }
    BOOL notify = FALSE;

    EnterCriticalSection(&g_HelperLock);

    /* Update target session if specified */
    if (targetSessionId != (DWORD)-1) {
        g_HelperConfig.targetSessionId = targetSessionId;
    }

    if (g_HelperStatus.state == HELPER_STATE_RUNNING) {
        if (Helper_IsProcessAlive(g_HelperProcess)) {
            LeaveCriticalSection(&g_HelperLock);
            return TRUE;
        }

        /* Process handle is stale, clean up so we can respawn */
        Helper_CloseProcessHandle();
        g_HelperStatus.processId = 0;
        g_HelperStatus.sessionId = 0;
    }

    /* Request spawn by setting state */
    g_HelperStatus.state = HELPER_STATE_SPAWNING;
    g_HelperStatus.failureCount = 0;
    g_HelperStatus.lastSpawnTime = 0;
    notify = TRUE;

    if (notify) {
        Helper_NotifyCallback();
    }
    LeaveCriticalSection(&g_HelperLock);
    return TRUE;
}

BOOL HelperMonitor_ForceRestart(void)
{
    if (InterlockedCompareExchange(&g_HelperRunning, 0, 0) == 0) {
        return FALSE;
    }

    EnterCriticalSection(&g_HelperLock);

    /* Terminate existing process */
    Helper_TerminateProcessLocked();

    g_HelperStatus.processId = 0;
    g_HelperStatus.sessionId = 0;
    g_HelperStatus.state = HELPER_STATE_SPAWNING;
    g_HelperStatus.failureCount = 0;  /* Reset failure count on force restart */
    g_HelperStatus.lastSpawnTime = 0;
    g_HelperStatus.lastError = 0;
    g_HelperStatus.lastErrorMessage[0] = L'\0';
    Helper_NotifyCallback();

    LeaveCriticalSection(&g_HelperLock);
    return TRUE;
}

BOOL HelperMonitor_GetStatus(HelperProcessStatus* outStatus)
{
    if (outStatus == NULL) {
        return FALSE;
    }

    if (!g_HelperLockInitialized) {
        ZeroMemory(outStatus, sizeof(HelperProcessStatus));
        return FALSE;
    }

    EnterCriticalSection(&g_HelperLock);
    *outStatus = g_HelperStatus;
    LeaveCriticalSection(&g_HelperLock);

    return TRUE;
}

void HelperMonitor_OnSessionChange(DWORD eventType, DWORD sessionId)
{
    if (InterlockedCompareExchange(&g_HelperRunning, 0, 0) == 0) {
        return;
    }

    EnterCriticalSection(&g_HelperLock);
    BOOL notify = FALSE;

    switch (eventType) {
    case WTS_CONSOLE_CONNECT:
    case WTS_REMOTE_CONNECT:
    case WTS_SESSION_LOGON:
    case WTS_SESSION_UNLOCK:
        /* User session became active - ensure helper is spawned */
        if (g_HelperConfig.monitorSession) {
            if (g_HelperStatus.state == HELPER_STATE_SESSION_WAIT ||
                g_HelperStatus.state == HELPER_STATE_FAILED ||
                g_HelperStatus.state == HELPER_STATE_IDLE) {
                g_HelperStatus.state = HELPER_STATE_SPAWNING;
                g_HelperConfig.targetSessionId = sessionId;
                g_HelperStatus.failureCount = 0;  /* Reset on new session */
                g_HelperStatus.lastSpawnTime = 0; /* Allow immediate spawn */
                notify = TRUE;
            }
            /* If helper is running in a different session, terminate and respawn in new session */
            else if (g_HelperStatus.state == HELPER_STATE_RUNNING &&
                     g_HelperStatus.sessionId != sessionId) {
                Helper_TerminateProcessLocked();
                g_HelperStatus.state = HELPER_STATE_SPAWNING;
                g_HelperConfig.targetSessionId = sessionId;
                g_HelperStatus.failureCount = 0;
                g_HelperStatus.lastSpawnTime = 0;
                notify = TRUE;
            }
        }
        break;

    case WTS_CONSOLE_DISCONNECT:
    case WTS_REMOTE_DISCONNECT:
    case WTS_SESSION_LOGOFF:
    case WTS_SESSION_LOCK:
        /* Session changed - check if our helper's session is affected */
        if (g_HelperStatus.sessionId == sessionId) {
            Helper_TerminateProcessLocked();
            g_HelperStatus.state = HELPER_STATE_SESSION_WAIT;
            g_HelperConfig.targetSessionId = (DWORD)-1;  /* Will find new active session */
            g_HelperStatus.lastSpawnTime = 0;  /* Allow immediate respawn when new session available */
            notify = TRUE;
        }
        break;
    }

    if (notify) {
        Helper_NotifyCallback();
    }

    LeaveCriticalSection(&g_HelperLock);
}

BOOL HelperMonitor_HasValidSession(DWORD* outSessionId)
{
    return Helper_GetActiveUserSession(outSessionId);
}

DWORD HelperMonitor_GetActiveConsoleSession(void)
{
    DWORD sessionId = WTSGetActiveConsoleSessionId();

    /* Validate the session has an interactive user */
    if (sessionId != 0xFFFFFFFF) {
        HANDLE hToken = NULL;
        if (WTSQueryUserToken(sessionId, &hToken)) {
            CloseHandle(hToken);
            return sessionId;
        }
    }

    /* No valid console session, try to find any active user session */
    DWORD foundSession = 0;
    if (Helper_GetActiveUserSession(&foundSession)) {
        return foundSession;
    }

    return 0xFFFFFFFF;  /* No valid session */
}

BOOL HelperMonitor_SpawnInSession(
    DWORD sessionId,
    DWORD* outProcessId,
    DWORD* outError)
{
    if (!g_HelperLockInitialized) {
        if (outError) *outError = ERROR_NOT_READY;
        return FALSE;
    }

    EnterCriticalSection(&g_HelperLock);

    /* Terminate existing helper if running to avoid duplicates */
    if (g_HelperProcess != NULL && g_HelperStatus.state == HELPER_STATE_RUNNING) {
        Helper_TerminateProcessLocked();
    }

    DWORD newPid = 0;
    DWORD spawnError = 0;
    ULONGLONG now = GetTickCount64();
    BOOL notify = FALSE;

    BOOL result = Helper_SpawnProcessInSession(
        sessionId,
        g_HelperConfig.exePath,
        g_HelperConfig.arguments,
        &newPid,
        &spawnError);

    /* Update status based on result */
    g_HelperStatus.lastSpawnTime = now;
    g_HelperStatus.spawnAttempts++;

    if (result) {
        g_HelperStatus.state = HELPER_STATE_RUNNING;
        g_HelperStatus.processId = newPid;
        g_HelperStatus.sessionId = sessionId;
        g_HelperStatus.lastSuccessTime = now;
        g_HelperStatus.failureCount = 0;
        g_HelperStatus.lastError = 0;
        g_HelperStatus.lastErrorMessage[0] = L'\0';
        notify = TRUE;

        if (outProcessId) *outProcessId = newPid;
        if (outError) *outError = 0;
    } else {
        g_HelperStatus.failureCount++;
        g_HelperStatus.lastError = spawnError;
        Helper_SetLastErrorMessage(spawnError, g_HelperStatus.lastErrorMessage,
            _countof(g_HelperStatus.lastErrorMessage));

        /* Determine next state based on error */
        if (spawnError == ERROR_NO_SUCH_LOGON_SESSION ||
            spawnError == ERROR_ACCESS_DENIED ||
            spawnError == ERROR_PRIVILEGE_NOT_HELD) {
            g_HelperStatus.state = HELPER_STATE_SESSION_WAIT;
        } else {
            g_HelperStatus.state = HELPER_STATE_FAILED;
        }
        notify = TRUE;

        if (outProcessId) *outProcessId = 0;
        if (outError) *outError = spawnError;
    }

    if (notify) {
        Helper_NotifyCallback();
    }

    LeaveCriticalSection(&g_HelperLock);
    return result;
}

/* ================================================================
 * Internal Helper Functions
 * ================================================================ */

/**
 * Enable a Windows privilege for the current process.
 * Required for WTSQueryUserToken (SE_TCB_NAME).
 *
 * Ported from: ondrasek's adjustPrivileges() function
 */
static BOOL Helper_EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp,
        sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    DWORD lastError = GetLastError();
    CloseHandle(hToken);

    return (result && lastError == ERROR_SUCCESS);
}

/**
 * Find an active user session using WTSEnumerateSessionsEx.
 * This is more robust than just using WTSGetActiveConsoleSessionId
 * because it handles RDP sessions and multi-session scenarios.
 *
 * Ported from: ondrasek's WTSEnumerateSessionsEx usage
 */
static BOOL Helper_GetActiveUserSession(DWORD* outSessionId)
{
    if (outSessionId == NULL) {
        return FALSE;
    }

    *outSessionId = 0;

    PWTS_SESSION_INFO_1W pSessionInfo = NULL;
    DWORD sessionCount = 0;
    DWORD level = 1;

    if (!WTSEnumerateSessionsExW(WTS_CURRENT_SERVER_HANDLE, &level, 0,
            &pSessionInfo, &sessionCount)) {
        /* Fall back to WTSGetActiveConsoleSessionId */
        DWORD consoleSession = WTSGetActiveConsoleSessionId();
        if (consoleSession != 0xFFFFFFFF) {
            *outSessionId = consoleSession;
            return TRUE;
        }
        return FALSE;
    }

    BOOL found = FALSE;
    DWORD bestSession = 0xFFFFFFFF;

    /* Priority order: Active console > Active RDP > Connected sessions */
    for (DWORD i = 0; i < sessionCount; i++) {
        WTS_SESSION_INFO_1W* session = &pSessionInfo[i];

        /* Skip system sessions and listener sessions */
        if (session->SessionId == 0) continue;
        if (session->pSessionName != NULL &&
            _wcsicmp(session->pSessionName, L"Services") == 0) continue;

        /* Check if session has an interactive user */
        if (session->State == WTSActive) {
            /* Verify we can get a user token for this session */
            HANDLE hToken = NULL;
            if (WTSQueryUserToken(session->SessionId, &hToken)) {
                CloseHandle(hToken);

                /* Prefer console session over RDP */
                if (session->pSessionName != NULL &&
                    _wcsicmp(session->pSessionName, L"Console") == 0) {
                    bestSession = session->SessionId;
                    found = TRUE;
                    break;  /* Console is highest priority */
                } else if (!found) {
                    bestSession = session->SessionId;
                    found = TRUE;
                }
            }
        }
        else if (session->State == WTSConnected && !found) {
            /* Fallback to connected sessions */
            HANDLE hToken = NULL;
            if (WTSQueryUserToken(session->SessionId, &hToken)) {
                CloseHandle(hToken);
                bestSession = session->SessionId;
                found = TRUE;
            }
        }
    }

    WTSFreeMemoryExW(WTSTypeSessionInfoLevel1, pSessionInfo, sessionCount);

    if (found) {
        *outSessionId = bestSession;
    }

    return found;
}

static ULONGLONG Helper_HashCommandLine(const WCHAR* exePath, const WCHAR* arguments)
{
    const ULONGLONG fnvOffset = 14695981039346656037ULL;
    const ULONGLONG fnvPrime = 1099511628211ULL;
    ULONGLONG hash = fnvOffset;
    const WCHAR* current = NULL;

    current = (exePath != NULL ? exePath : L"");
    while (*current != L'\0')
    {
        hash ^= (ULONGLONG)(*current);
        hash *= fnvPrime;
        ++current;
    }

    hash ^= (ULONGLONG)L' ';
    hash *= fnvPrime;

    current = (arguments != NULL ? arguments : L"");
    while (*current != L'\0')
    {
        hash ^= (ULONGLONG)(*current);
        hash *= fnvPrime;
        ++current;
    }

    return hash;
}

static BOOL Helper_EndsWithInsensitiveW(const WCHAR* value, const WCHAR* suffix)
{
    size_t valueLen;
    size_t suffixLen;

    if (value == NULL || suffix == NULL) { return FALSE; }
    valueLen = wcslen(value);
    suffixLen = wcslen(suffix);
    if (valueLen < suffixLen || suffixLen == 0) { return FALSE; }
    return (_wcsicmp(value + (valueLen - suffixLen), suffix) == 0) ? TRUE : FALSE;
}

static BOOL Helper_CommandLineContainsInsensitiveW(const WCHAR* value, const WCHAR* token)
{
    WCHAR scratch[1024];
    WCHAR tokenScratch[128];
    WCHAR* found = NULL;

    if (value == NULL || token == NULL || value[0] == L'\0' || token[0] == L'\0') { return FALSE; }
    StringCchCopyW(scratch, _countof(scratch), value);
    StringCchCopyW(tokenScratch, _countof(tokenScratch), token);
    _wcslwr_s(scratch, _countof(scratch));
    _wcslwr_s(tokenScratch, _countof(tokenScratch));
    found = wcsstr(scratch, tokenScratch);
    return (found != NULL) ? TRUE : FALSE;
}

BOOL HelperMonitor_IsApprovedDesktopBridgeCommand(const WCHAR* exePath, const WCHAR* arguments)
{
    if (exePath == NULL || exePath[0] == L'\0' || arguments == NULL || arguments[0] == L'\0') {
        return FALSE;
    }
    if (!Helper_CommandLineContainsInsensitiveW(arguments, L"KvmSessionBridgeW")) {
        return FALSE;
    }
    return Helper_EndsWithInsensitiveW(exePath, L"\\rundll32.exe") ||
           Helper_EndsWithInsensitiveW(exePath, L"\\rundll32");
}

static void Helper_LogPolicyDecision(const WCHAR* decision, DWORD sessionId, const WCHAR* exePath, const WCHAR* arguments, DWORD errorCode)
{
    WCHAR logLine[512];
    ULONGLONG cmdHash = Helper_HashCommandLine(exePath, arguments);

    StringCchPrintfW(logLine, _countof(logLine),
        L"[HelperPolicy] decision=%ls class=desktop-bridge strict=%lu allowDesktopBridge=%lu session=%lu cmdHash=%016I64X error=%lu",
        (decision != NULL ? decision : L"unknown"),
        g_HelperConfig.strictServiceOnly ? 1UL : 0UL,
        g_HelperConfig.allowDesktopBridge ? 1UL : 0UL,
        sessionId,
        cmdHash,
        errorCode);
    OutputDebugStringW(logLine);
}

static BOOL Helper_IsSessionSpawnAllowed(DWORD sessionId, const WCHAR* exePath, const WCHAR* arguments, DWORD* outError)
{
    DWORD errorCode = ERROR_SUCCESS;

    if (g_HelperConfig.allowDesktopBridge &&
        HelperMonitor_IsApprovedDesktopBridgeCommand(exePath, arguments))
    {
        Helper_LogPolicyDecision(L"allow-kvm-bridge", sessionId, exePath, arguments, ERROR_SUCCESS);
        if (outError != NULL) { *outError = ERROR_SUCCESS; }
        return TRUE;
    }

    errorCode = ERROR_ACCESS_DISABLED_BY_POLICY;
    Helper_LogPolicyDecision(L"deny", sessionId, exePath, arguments, errorCode);
    if (outError != NULL) { *outError = errorCode; }
    return FALSE;
}

/**
 * Spawn a process in a specific user session.
 * Uses the complete CreateProcessAsUser workflow.
 *
 * Ported from:
 * - murrayju/CreateProcessAsUser's StartProcessAsCurrentUser
 * - ondrasek's spawnProcess function
 * - masthoon's SystemCMD.cpp
 */
static BOOL Helper_SpawnProcessInSession(
    DWORD sessionId,
    const WCHAR* exePath,
    const WCHAR* arguments,
    DWORD* outPid,
    DWORD* outError)
{
    HANDLE hUserToken = NULL;
    HANDLE hDuplicatedToken = NULL;
    LPVOID pEnvironment = NULL;
    BOOL result = FALSE;
    DWORD error = 0;

    if (outPid) *outPid = 0;
    if (outError) *outError = 0;

    if (exePath == NULL || exePath[0] == L'\0') {
        if (outError) *outError = ERROR_INVALID_PARAMETER;
        return FALSE;
    }

    if (!Helper_IsSessionSpawnAllowed(sessionId, exePath, arguments, &error)) {
        if (outError) *outError = error;
        return FALSE;
    }

    /* Step 1: Get user token for the session */
    if (!WTSQueryUserToken(sessionId, &hUserToken)) {
        error = GetLastError();
        if (outError) *outError = error;
        return FALSE;
    }

    /* Step 2: Duplicate token with specific required privileges only
     * Security fix: Use minimum required access instead of MAXIMUM_ALLOWED
     * to follow principle of least privilege and prevent escalation */
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    /* Use only the specific access rights required for CreateProcessAsUser */
    DWORD tokenAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                        TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

    if (!DuplicateTokenEx(hUserToken, tokenAccess, &sa,
            SecurityImpersonation, TokenPrimary, &hDuplicatedToken)) {
        error = GetLastError();
        CloseHandle(hUserToken);
        if (outError) *outError = error;
        return FALSE;
    }

    CloseHandle(hUserToken);
    hUserToken = NULL;

    /* Step 3: Create environment block for user */
    if (!CreateEnvironmentBlock(&pEnvironment, hDuplicatedToken, FALSE)) {
        /* Non-fatal - continue without custom environment */
        pEnvironment = NULL;
    }

    /* Step 4: Prepare startup info with correct desktop */
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = L"winsta0\\default";
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  /* Start hidden - helper runs in background */

    /* Step 5: Build command line */
    WCHAR cmdLine[1024];
    if (arguments != NULL && arguments[0] != L'\0') {
        StringCchPrintfW(cmdLine, _countof(cmdLine), L"\"%s\" %s", exePath, arguments);
    } else {
        StringCchPrintfW(cmdLine, _countof(cmdLine), L"\"%s\"", exePath);
    }

    /* Step 6: Create the process */
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    DWORD creationFlags = NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW;
    if (pEnvironment != NULL) {
        creationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    if (CreateProcessAsUserW(
            hDuplicatedToken,
            NULL,
            cmdLine,
            NULL,
            NULL,
            FALSE,
            creationFlags,
            pEnvironment,
            NULL,
            &si,
            &pi)) {

        result = TRUE;
        if (outPid) *outPid = pi.dwProcessId;

        /* Store process handle for monitoring */
        if (g_HelperProcess != NULL) {
            CloseHandle(g_HelperProcess);
        }
        g_HelperProcess = pi.hProcess;

        CloseHandle(pi.hThread);
    } else {
        error = GetLastError();
        if (outError) *outError = error;
    }

    /* Cleanup */
    if (pEnvironment != NULL) {
        DestroyEnvironmentBlock(pEnvironment);
    }
    CloseHandle(hDuplicatedToken);

    return result;
}

static BOOL Helper_IsProcessAlive(HANDLE hProcess)
{
    if (hProcess == NULL) {
        return FALSE;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(hProcess, &exitCode)) {
        return FALSE;
    }

    return (exitCode == STILL_ACTIVE);
}

static void Helper_UpdateStatus(HelperProcessState newState, DWORD error, const WCHAR* errorMsg)
{
    g_HelperStatus.state = newState;
    g_HelperStatus.lastError = error;

    if (errorMsg != NULL) {
        StringCchCopyW(g_HelperStatus.lastErrorMessage,
            _countof(g_HelperStatus.lastErrorMessage), errorMsg);
    } else if (error != 0) {
        Helper_SetLastErrorMessage(error, g_HelperStatus.lastErrorMessage,
            _countof(g_HelperStatus.lastErrorMessage));
    } else {
        g_HelperStatus.lastErrorMessage[0] = L'\0';
    }
}

/**
 * Notify callback with proper lock handling.
 * IMPORTANT: This function temporarily releases g_HelperLock to call the callback,
 * then re-acquires it. The caller MUST hold g_HelperLock when calling this function.
 * After return, the lock is still held but state may have changed due to other threads.
 */
static void Helper_NotifyCallback(void)
{
    if (g_HelperCallback == NULL) {
        return;
    }

    /* Copy callback and user data under lock (in case they're modified) */
    HelperProcessCallback callback = g_HelperCallback;
    void* userData = g_HelperUserData;
    HelperProcessStatus statusCopy = g_HelperStatus;

    /* Release lock before callback to prevent deadlock if callback
     * tries to call back into helper functions */
    LeaveCriticalSection(&g_HelperLock);

    /* Call callback outside lock - callback MUST NOT call helper functions
     * that acquire g_HelperLock or deadlock will occur */
    callback(statusCopy.state, &statusCopy, userData);

    /* Re-acquire lock */
    EnterCriticalSection(&g_HelperLock);
}

static void Helper_SetLastErrorMessage(DWORD error, WCHAR* buffer, size_t bufferSize)
{
    if (buffer == NULL || bufferSize == 0) return;

    DWORD result = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buffer,
        (DWORD)bufferSize,
        NULL);

    if (result == 0) {
        StringCchPrintfW(buffer, bufferSize, L"Error code: %lu", error);
    } else {
        /* Remove trailing newlines */
        size_t len = wcslen(buffer);
        while (len > 0 && (buffer[len-1] == L'\n' || buffer[len-1] == L'\r')) {
            buffer[--len] = L'\0';
        }
    }
}

static void Helper_CloseProcessHandle(void)
{
    if (g_HelperProcess != NULL) {
        CloseHandle(g_HelperProcess);
        g_HelperProcess = NULL;
    }
}

static void Helper_TerminateProcessLocked(void)
{
    if (g_HelperProcess != NULL) {
        TerminateProcess(g_HelperProcess, 0);
    }
    Helper_CloseProcessHandle();
    g_HelperStatus.processId = 0;
    g_HelperStatus.sessionId = 0;
}

/**
 * Calculate backoff delay with exponential increase, capped at maximum.
 * Never stops retrying - this is intentional for bulletproof persistence.
 */
static DWORD Helper_CalculateBackoff(DWORD failureCount, DWORD baseDelay)
{
    if (failureCount == 0) {
        return baseDelay;
    }

    DWORD cappedFailures = failureCount;
    if (g_HelperConfig.maxSpawnRetries > 0 &&
        cappedFailures > g_HelperConfig.maxSpawnRetries) {
        cappedFailures = g_HelperConfig.maxSpawnRetries;
    }

    /* Exponential backoff: 2s, 4s, 8s, 16s, 32s, 60s (capped) */
    DWORD shift = (cappedFailures < 6 ? cappedFailures : 6);
    DWORD delay = baseDelay * (1 << shift);

    if (delay > HELPER_MAX_BACKOFF_MS) {
        delay = HELPER_MAX_BACKOFF_MS;
    }
    if (delay < HELPER_MIN_RETRY_MS) {
        delay = HELPER_MIN_RETRY_MS;
    }

    return delay;
}

/**
 * Main helper monitor thread.
 * Continuously monitors helper process health and respawns as needed.
 *
 * Key behaviors:
 * - NEVER gives up - infinite retry with backoff
 * - When running and no connection, stays RUNNING (idle but ready)
 * - On session change, immediately attempts respawn in new session
 * - Integrates with main watchdog via callback notifications
 */
static DWORD WINAPI HelperMonitorThreadProc(LPVOID param)
{
    (void)param;

    DWORD consecutiveFailures = 0;

    while (InterlockedCompareExchange(&g_HelperRunning, 0, 0) != 0) {
        EnterCriticalSection(&g_HelperLock);

        HelperProcessState currentState = g_HelperStatus.state;
        ULONGLONG now = GetTickCount64();
        ULONGLONG lastSpawnAttempt = g_HelperStatus.lastSpawnTime;

        switch (currentState) {
        case HELPER_STATE_IDLE:
            /*
             * Idle state - helper not needed yet.
             * Transition to SPAWNING when a connection is requested
             * or when session becomes available.
             */
            if (g_HelperConfig.persistentSpawn) {
                /* If persistent mode, try to spawn immediately */
                DWORD sessionId = 0;
                if (Helper_GetActiveUserSession(&sessionId)) {
                    g_HelperStatus.state = HELPER_STATE_SPAWNING;
                    g_HelperConfig.targetSessionId = sessionId;
                }
            }
            break;

        case HELPER_STATE_SESSION_WAIT:
            /* Waiting for a valid user session */
            {
                DWORD foundSession = 0;
                if (Helper_GetActiveUserSession(&foundSession)) {
                    g_HelperConfig.targetSessionId = foundSession;
                    g_HelperStatus.state = HELPER_STATE_SPAWNING;
                    consecutiveFailures = 0;  /* Reset on new session */
                }
            }
            break;

        case HELPER_STATE_SPAWNING:
            /* Attempt to spawn helper process */
            {
                /* Calculate backoff delay based on failures */
                DWORD delay = Helper_CalculateBackoff(consecutiveFailures,
                    g_HelperConfig.spawnRetryDelayMs);

                /* Check if enough time has passed since last attempt */
                if (lastSpawnAttempt > 0 && (now - lastSpawnAttempt) < delay) {
                    /* Wait more - don't spam spawn attempts */
                    LeaveCriticalSection(&g_HelperLock);
                    Sleep(HELPER_MIN_RETRY_MS);
                    continue;
                }

                /* Determine target session */
                DWORD spawnSession = g_HelperConfig.targetSessionId;
                if (spawnSession == (DWORD)-1) {
                    if (!Helper_GetActiveUserSession(&spawnSession)) {
                        /* No valid session available - wait for one */
                        g_HelperStatus.state = HELPER_STATE_SESSION_WAIT;
                        Helper_UpdateStatus(HELPER_STATE_SESSION_WAIT,
                            ERROR_NO_SUCH_LOGON_SESSION, L"Waiting for user session");
                        g_HelperStatus.lastSpawnTime = now;
                        Helper_NotifyCallback();
                        break;
                    }
                }

                /* Attempt spawn */
                g_HelperStatus.spawnAttempts++;
                g_HelperStatus.lastSpawnTime = now;

                DWORD newPid = 0;
                DWORD spawnError = 0;

                BOOL success = Helper_SpawnProcessInSession(
                    spawnSession,
                    g_HelperConfig.exePath,
                    g_HelperConfig.arguments,
                    &newPid,
                    &spawnError);

                if (success) {
                    /* Success! Helper is now running */
                    g_HelperStatus.state = HELPER_STATE_RUNNING;
                    g_HelperStatus.processId = newPid;
                    g_HelperStatus.sessionId = spawnSession;
                    g_HelperStatus.lastSuccessTime = now;
                    g_HelperStatus.failureCount = 0;
                    g_HelperStatus.lastError = 0;
                    g_HelperStatus.lastErrorMessage[0] = L'\0';
                    consecutiveFailures = 0;

                    Helper_NotifyCallback();
                } else {
                    /* Failed - increment counters but KEEP TRYING */
                    consecutiveFailures++;
                    g_HelperStatus.failureCount++;
                    Helper_UpdateStatus(HELPER_STATE_FAILED, spawnError, NULL);

                    BOOL cappedOut = FALSE;
                    if (!g_HelperConfig.persistentSpawn &&
                        g_HelperConfig.maxSpawnRetries > 0 &&
                        consecutiveFailures >= g_HelperConfig.maxSpawnRetries) {
                        g_HelperStatus.state = HELPER_STATE_IDLE;
                        cappedOut = TRUE;
                        Helper_UpdateStatus(HELPER_STATE_IDLE, spawnError,
                            L"Helper monitor paused after max retries");
                    } else if (spawnError == ERROR_NO_SUCH_LOGON_SESSION ||
                               spawnError == ERROR_ACCESS_DENIED ||
                               spawnError == ERROR_PRIVILEGE_NOT_HELD) {
                        /* Session-related error - wait for valid session */
                        g_HelperStatus.state = HELPER_STATE_SESSION_WAIT;
                    } else {
                        /* Other error - stay in FAILED, will retry with backoff */
                        g_HelperStatus.state = HELPER_STATE_FAILED;
                    }

                    Helper_NotifyCallback();

                    if (cappedOut) {
                        /* Drop out of retry loop until explicitly requested */
                        consecutiveFailures = 0;
                    }
                }
            }
            break;

        case HELPER_STATE_RUNNING:
            /*
             * Helper is running (or supposed to be running).
             * This is the "idle but ready" state when no active KVM connection.
             * Check if process is still alive.
             */
            {
                if (!Helper_IsProcessAlive(g_HelperProcess)) {
                    /* Process died - respawn immediately */
                    Helper_CloseProcessHandle();
                    g_HelperStatus.processId = 0;
                    g_HelperStatus.sessionId = 0;
                    Helper_UpdateStatus(HELPER_STATE_SPAWNING, ERROR_PROC_NOT_FOUND,
                        L"Helper process exited");
                    g_HelperStatus.state = HELPER_STATE_SPAWNING;
                    /* Don't reset consecutiveFailures - process crashed */

                    Helper_NotifyCallback();
                }
                /* If process is alive, stay in RUNNING state (idle but ready) */
            }
            break;

        case HELPER_STATE_FAILED:
            /*
             * Failed state - but we NEVER give up.
             * Always retry after backoff delay.
             */
            {
                DWORD delay = Helper_CalculateBackoff(consecutiveFailures,
                    g_HelperConfig.spawnRetryDelayMs);

                if ((now - lastSpawnAttempt) >= delay) {
                    /* Time to retry */
                    g_HelperStatus.state = HELPER_STATE_SPAWNING;
                }
            }
            break;
        }

        LeaveCriticalSection(&g_HelperLock);

        /* Sleep interval based on state */
        DWORD sleepMs = g_HelperConfig.sessionCheckIntervalMs;
        if (currentState == HELPER_STATE_SPAWNING ||
            currentState == HELPER_STATE_FAILED ||
            currentState == HELPER_STATE_SESSION_WAIT) {
            sleepMs = HELPER_MIN_RETRY_MS;  /* Check more frequently during spawn/retry */
        }

        Sleep(sleepMs);
    }

    return 0;
}

/* ================================================================
 * Watchdog Integration for Helper Process
 *
 * These functions allow the main watchdog to monitor and manage
 * the helper process alongside other watched processes.
 * ================================================================ */

/**
 * Register the helper process with the main watchdog system.
 * This ensures the helper is monitored and restarted by the watchdog
 * in addition to the HelperMonitor's own monitoring.
 */
BOOL Watchdog_RegisterHelper(const HelperProcessConfig* config)
{
    if (config == NULL || config->exePath[0] == L'\0') {
        return FALSE;
    }

    /* Add helper to the watchdog's process list */
    return Watchdog_AddProcess(
        config->exePath,
        config->arguments,
        NULL);  /* Working dir not needed for helper */
}

/**
 * Unregister the helper process from the main watchdog.
 */
BOOL Watchdog_UnregisterHelper(const HelperProcessConfig* config)
{
    if (config == NULL || config->exePath[0] == L'\0') {
        return FALSE;
    }

    return Watchdog_RemoveProcess(
        config->exePath,
        config->arguments);
}
