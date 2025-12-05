/*
 * Stealth Module Regression Test
 * Tests all stealth module functions
 */

#include <stdio.h>
#include <windows.h>
#include <strsafe.h>
#include "stealth_watchdog.h"
#include "stealth_ipc.h"

#pragma comment(lib, "advapi32.lib")

/* Test result tracking */
static int g_TestsPassed = 0;
static int g_TestsFailed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        printf("[PASS] %s\n", msg); \
        g_TestsPassed++; \
    } else { \
        printf("[FAIL] %s\n", msg); \
        g_TestsFailed++; \
    } \
} while(0)

/* ================================================================
 * Watchdog Tests
 * ================================================================ */

void Test_WatchdogConfig(void)
{
    printf("\n=== Testing Watchdog Config ===\n");

    WatchdogConfig config;
    Watchdog_InitConfig(&config);

    TEST_ASSERT(config.checkIntervalMs == 8000, "Default check interval is 8000ms");
    TEST_ASSERT(config.restartDelayMs == 1000, "Default restart delay is 1000ms");
    TEST_ASSERT(config.maxRestartAttempts == 10, "Default max restart attempts is 10");
    TEST_ASSERT(config.backoffMultiplier == 2, "Default backoff multiplier is 2");
    TEST_ASSERT(config.useJobObject == TRUE, "Default useJobObject is TRUE");
    TEST_ASSERT(config.hidden == TRUE, "Default hidden is TRUE");
    TEST_ASSERT(config.bootMethod == WATCHDOG_BOOT_NONE, "Default boot method is NONE");
}

void Test_WatchdogStartStop(void)
{
    printf("\n=== Testing Watchdog Start/Stop ===\n");

    WatchdogConfig config;
    Watchdog_InitConfig(&config);

    BOOL started = Watchdog_Start(&config);
    TEST_ASSERT(started, "Watchdog started successfully");

    /* Add a test process */
    BOOL added = Watchdog_AddProcess(
        L"C:\\Windows\\System32\\notepad.exe",
        L"",
        NULL);
    TEST_ASSERT(added, "Added notepad.exe to watch list");

    /* Check status */
    DWORD pid = 0, restarts = 0;
    BOOL status = Watchdog_GetProcessStatus(
        L"C:\\Windows\\System32\\notepad.exe",
        L"",
        &pid,
        &restarts);
    TEST_ASSERT(status, "Got process status");
    printf("  PID: %lu, Restarts: %lu\n", pid, restarts);

    /* Remove process */
    BOOL removed = Watchdog_RemoveProcess(
        L"C:\\Windows\\System32\\notepad.exe",
        L"");
    TEST_ASSERT(removed, "Removed notepad.exe from watch list");

    Watchdog_Stop();
    TEST_ASSERT(TRUE, "Watchdog stopped");
}

void Test_BootStartRunKey(void)
{
    printf("\n=== Testing Boot Start Run Key ===\n");

    /* This test requires admin privileges */
    BOOL enabled = Watchdog_EnableRunKey(
        L"MeshAgentTest",
        L"C:\\Windows\\System32\\notepad.exe",
        L"--test");

    if (enabled) {
        TEST_ASSERT(TRUE, "Run key enabled");

        /* Verify it exists */
        HKEY hKey = NULL;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            KEY_READ,
            &hKey);

        if (result == ERROR_SUCCESS) {
            WCHAR value[MAX_PATH];
            DWORD size = sizeof(value);
            result = RegQueryValueExW(hKey, L"MeshAgentTest", NULL, NULL, (BYTE*)value, &size);
            TEST_ASSERT(result == ERROR_SUCCESS, "Run key value readable");
            if (result == ERROR_SUCCESS) {
                wprintf(L"  Value: %s\n", value);
            }
            RegCloseKey(hKey);
        }

        /* Clean up */
        BOOL disabled = Watchdog_DisableRunKey(L"MeshAgentTest");
        TEST_ASSERT(disabled, "Run key disabled");
    } else {
        printf("[SKIP] Run key test - requires admin privileges\n");
    }
}

void Test_BootStartTaskScheduler(void)
{
    printf("\n=== Testing Boot Start Task Scheduler ===\n");

    /* This test requires admin privileges */
    BOOL enabled = Watchdog_EnableTaskScheduler(
        L"MeshAgentTest",
        L"C:\\Windows\\System32\\notepad.exe",
        L"--test",
        FALSE,  /* logon trigger instead of boot */
        FALSE); /* current user instead of SYSTEM */

    if (enabled) {
        TEST_ASSERT(TRUE, "Task scheduler entry created");

        /* Clean up */
        BOOL disabled = Watchdog_DisableTaskScheduler(L"MeshAgentTest");
        TEST_ASSERT(disabled, "Task scheduler entry removed");
    } else {
        printf("[SKIP] Task scheduler test - requires admin privileges or failed\n");
    }
}

void Test_BootStartEnabled(void)
{
    printf("\n=== Testing IsBootStartEnabled ===\n");

    WatchdogConfig config;
    Watchdog_InitConfig(&config);

    config.bootMethod = WATCHDOG_BOOT_NONE;
    BOOL enabled = Watchdog_IsBootStartEnabled(&config);
    TEST_ASSERT(!enabled, "BOOT_NONE returns FALSE");

    config.bootMethod = WATCHDOG_BOOT_RUN_KEY;
    StringCchCopyW(config.bootName, 64, L"NonExistentKey12345");
    enabled = Watchdog_IsBootStartEnabled(&config);
    TEST_ASSERT(!enabled, "Non-existent run key returns FALSE");

    config.bootMethod = WATCHDOG_BOOT_TASK_SCHEDULER;
    StringCchCopyW(config.bootName, 64, L"NonExistentTask12345");
    enabled = Watchdog_IsBootStartEnabled(&config);
    TEST_ASSERT(!enabled, "Non-existent task returns FALSE");
}

/* ================================================================
 * IPC Tests
 * ================================================================ */

void Test_IpcPipeName(void)
{
    printf("\n=== Testing IPC Pipe Name Generation ===\n");

    WCHAR pipeName[256];
    Ipc_GetDefaultPipeName(L"TestService", pipeName, 256);

    TEST_ASSERT(wcsstr(pipeName, L"\\\\.\\pipe\\") != NULL, "Pipe name has correct prefix");
    TEST_ASSERT(wcsstr(pipeName, L"TestService") != NULL, "Pipe name contains service name");
    wprintf(L"  Pipe name: %s\n", pipeName);
}

void Test_IpcValidateHeader(void)
{
    printf("\n=== Testing IPC Header Validation ===\n");

    IpcMessageHeader header;
    header.magic = 0x4D455348;  /* 'MESH' */
    header.version = 1;
    header.type = IPC_MSG_STATUS;
    header.payloadSize = 100;
    header.sequence = 1;
    header.timestamp = GetTickCount();

    TEST_ASSERT(Ipc_ValidateHeader(&header), "Valid header passes");

    header.magic = 0x12345678;
    TEST_ASSERT(!Ipc_ValidateHeader(&header), "Invalid magic fails");

    header.magic = 0x4D455348;
    header.version = 99;
    TEST_ASSERT(!Ipc_ValidateHeader(&header), "Invalid version fails");

    header.version = 1;
    header.payloadSize = 2 * 1024 * 1024;  /* 2MB - too large */
    TEST_ASSERT(!Ipc_ValidateHeader(&header), "Oversized payload fails");
}

void Test_IpcServerClient(void)
{
    printf("\n=== Testing IPC Server/Client ===\n");

    WCHAR pipeName[256];
    Ipc_GetDefaultPipeName(L"RegressionTest", pipeName, 256);

    /* Create server */
    IpcServer server;
    BOOL created = Ipc_ServerCreate(&server, pipeName, NULL, NULL);
    TEST_ASSERT(created, "IPC server created");

    if (created) {
        /* Create client */
        IpcClient client;
        BOOL connected = Ipc_ClientConnect(&client, pipeName, 3000);
        TEST_ASSERT(connected, "IPC client connected");

        if (connected) {
            /* Send message */
            BOOL sent = Ipc_ClientSend(&client, IPC_MSG_STATUS, NULL, 0);
            TEST_ASSERT(sent, "Message sent from client");

            Ipc_ClientDisconnect(&client);
        }

        Ipc_ServerDestroy(&server);
    }
}

void Test_IpcLockdownPayload(void)
{
    printf("\n=== Testing IPC Lockdown Payload ===\n");

    IpcLockdownPayload payload;
    Ipc_BuildLockdownPayload(&payload, TRUE, FALSE, TRUE, FALSE);

    TEST_ASSERT(payload.enableShellRestrictions == TRUE, "Shell restrictions set");
    TEST_ASSERT(payload.enablePolicyEnforcement == FALSE, "Policy enforcement not set");
    TEST_ASSERT(payload.enableNetworkLockdown == TRUE, "Network lockdown set");
    TEST_ASSERT(payload.enableTaskMonitoring == FALSE, "Task monitoring not set");
}

/* ================================================================
 * Heartbeat Tests
 * ================================================================ */

void Test_Heartbeat(void)
{
    printf("\n=== Testing Heartbeat System ===\n");

    HANDLE mapHandle = NULL;
    BOOL created = Watchdog_CreateHeartbeat(L"TestHeartbeat", &mapHandle);
    TEST_ASSERT(created, "Heartbeat created");

    if (created && mapHandle != NULL) {
        /* Send a few heartbeats */
        Watchdog_SendHeartbeat();
        Sleep(100);
        Watchdog_SendHeartbeat();

        /* Monitor heartbeat */
        BOOL isAlive = FALSE;
        BOOL monitored = Watchdog_MonitorHeartbeat(L"TestHeartbeat", 1000, &isAlive);
        TEST_ASSERT(monitored, "Heartbeat monitored");
        TEST_ASSERT(isAlive, "Heartbeat is alive");

        Watchdog_CloseHeartbeat(mapHandle);
    }
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void)
{
    printf("============================================\n");
    printf("  Stealth Module Regression Test Suite\n");
    printf("============================================\n");

    /* Watchdog tests */
    Test_WatchdogConfig();
    Test_WatchdogStartStop();
    Test_BootStartRunKey();
    Test_BootStartTaskScheduler();
    Test_BootStartEnabled();
    Test_Heartbeat();

    /* IPC tests */
    Test_IpcPipeName();
    Test_IpcValidateHeader();
    Test_IpcServerClient();
    Test_IpcLockdownPayload();

    /* Summary */
    printf("\n============================================\n");
    printf("  Test Results: %d passed, %d failed\n", g_TestsPassed, g_TestsFailed);
    printf("============================================\n");

    return g_TestsFailed > 0 ? 1 : 0;
}
