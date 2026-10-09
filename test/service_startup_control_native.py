#!/usr/bin/env python3
"""Exercise the production service-start transition against concurrent stop requests."""

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def extract_function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise ValueError(f"unterminated function: {signature}")


def main() -> None:
    source = (ROOT / "meshservice" / "service_host.c").read_text(encoding="utf-8-sig")
    functions = "\n\n".join(
        extract_function(source, signature)
        for signature in (
            "static void ServiceHost_AgentChainStopping(void* chain, void* user)",
            "static void ServiceHost_PublishStatusHandle(SERVICE_STATUS_HANDLE statusHandle)",
            "static void ServiceHost_BeginStopRequest(void)",
            "static BOOL ServiceHost_IsStopRequested(void)",
            "static BOOL ServiceHost_PublishRunningAgent(MeshAgentHostContainer* agent)",
            "static void ServiceHost_ReportStopped(DWORD win32Error, DWORD serviceError)",
            "static void ServiceHost_CompleteStartupStop(void)",
            "static BOOL ServiceHost_CompleteAgentRun(\n    MeshAgentHostContainer* agent,\n    DWORD* completionError)",
            "static void ServiceHost_FinalizeAgentRun(\n    MeshAgentHostContainer* agent,\n    int startResult)",
            "static void ServiceHost_RefreshControlsAccepted(void)",
        )
    )
    fixture = r'''
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define TRUE 1
#define FALSE 0
#define NO_ERROR 0
#define ERROR_SERVICE_SPECIFIC_ERROR 1066
#define ERROR_PROCESS_ABORTED 1067
#define MESH_TELEMETRY_CLEAN_EXIT 1
#define MESH_TELEMETRY_UNEXPECTED_RETURN 2
#define SERVICE_STOPPED 1
#define SERVICE_STOP_PENDING 3
#define SERVICE_RUNNING 4
#define SERVICE_ACCEPT_STOP 0x1
#define SERVICE_ACCEPT_SHUTDOWN 0x4
#define SERVICE_ACCEPT_POWEREVENT 0x40
#define SERVICE_ACCEPT_SESSIONCHANGE 0x80
#define ALL_CONTROLS (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE)
#define STOP_CONTROLS (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
#define UNREFERENCED_PARAMETER(value) ((void)(value))
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* SERVICE_STATUS_HANDLE;
typedef struct MeshAgentHostContainer { int marker; int exitCode; } MeshAgentHostContainer;
typedef pthread_mutex_t SRWLOCK;
#define SRWLOCK_INIT PTHREAD_MUTEX_INITIALIZER
typedef struct SERVICE_STATUS {
    unsigned long dwCurrentState;
    unsigned long dwControlsAccepted;
    unsigned long dwWin32ExitCode;
    unsigned long dwServiceSpecificExitCode;
    unsigned long dwCheckPoint;
    unsigned long dwWaitHint;
} SERVICE_STATUS;

static SERVICE_STATUS_HANDLE g_ServiceHostStatusHandle;
static SERVICE_STATUS g_ServiceHostStatus;
static BOOL g_ServiceHostRunning;
static SRWLOCK g_ServiceHostControlLock = SRWLOCK_INIT;
static BOOL g_ServiceHostStopRequested;
static BOOL g_ServiceHostFinalStatusReserved;
static BOOL g_ServiceHostCompletionPlanned;
static BOOL g_ServiceHostStatusTerminal;
static MeshAgentHostContainer* g_ServiceHostAgent;
static unsigned statusReports;
static unsigned stopDispatches;
static unsigned destroyCalls;
static unsigned telemetryCalls;
static int g_ServiceHostTelemetry;

static void AcquireSRWLockExclusive(SRWLOCK* lock) { assert(pthread_mutex_lock(lock) == 0); }
static void ReleaseSRWLockExclusive(SRWLOCK* lock) { assert(pthread_mutex_unlock(lock) == 0); }
static void AcquireSRWLockShared(SRWLOCK* lock) { AcquireSRWLockExclusive(lock); }
static void ReleaseSRWLockShared(SRWLOCK* lock) { ReleaseSRWLockExclusive(lock); }
static BOOL SetServiceStatus(SERVICE_STATUS_HANDLE handle, SERVICE_STATUS* status) {
    (void)handle; (void)status; ++statusReports; return TRUE;
}
static BOOL ServiceHost_RequestAgentStop(MeshAgentHostContainer* agent) {
    if (agent == NULL) { return FALSE; }
    ++stopDispatches;
    return TRUE;
}
static void ServiceHost_LogLine(const wchar_t* format, ...) { (void)format; }
static void MeshServiceTelemetry_End(void* telemetry, int reason, DWORD error) {
    (void)telemetry; (void)reason; (void)error; ++telemetryCalls;
}
static void ServiceHost_DestroyAgent(MeshAgentHostContainer* agent) {
    assert(agent != NULL);
    ++destroyCalls;
}
'''
    fixture += functions
    fixture += r'''

static MeshAgentHostContainer agent;

static void reset(void) {
    memset(&g_ServiceHostStatus, 0, sizeof(g_ServiceHostStatus));
    g_ServiceHostStatus.dwControlsAccepted = ALL_CONTROLS;
    g_ServiceHostRunning = FALSE;
    g_ServiceHostStopRequested = FALSE;
    g_ServiceHostFinalStatusReserved = FALSE;
    g_ServiceHostCompletionPlanned = FALSE;
    g_ServiceHostStatusTerminal = FALSE;
    g_ServiceHostAgent = NULL;
    g_ServiceHostStatusHandle = (SERVICE_STATUS_HANDLE)1;
    statusReports = 0;
    stopDispatches = 0;
    destroyCalls = 0;
    telemetryCalls = 0;
}

static void* publish_thread(void* ignored) {
    (void)ignored;
    (void)ServiceHost_PublishRunningAgent(&agent);
    return NULL;
}

static void* stop_thread(void* ignored) {
    (void)ignored;
    ServiceHost_BeginStopRequest();
    return NULL;
}

static void* chain_stop_thread(void* ignored) {
    (void)ignored;
    ServiceHost_AgentChainStopping(NULL, &agent);
    return NULL;
}

int main(void) {
    unsigned index;
    reset();
    g_ServiceHostStatusHandle = NULL;
    ServiceHost_BeginStopRequest();
    assert(ServiceHost_IsStopRequested());
    assert(statusReports == 0);
    ServiceHost_PublishStatusHandle((SERVICE_STATUS_HANDLE)1);
    assert(statusReports == 1);
    assert(g_ServiceHostStatus.dwCurrentState == SERVICE_STOP_PENDING);

    reset();
    assert(ServiceHost_PublishRunningAgent(&agent));
    assert(g_ServiceHostAgent == &agent && g_ServiceHostRunning);
    assert(g_ServiceHostStatus.dwCurrentState == SERVICE_RUNNING);
    ServiceHost_RefreshControlsAccepted();
    assert(g_ServiceHostStatus.dwControlsAccepted == ALL_CONTROLS);

    reset();
    ServiceHost_BeginStopRequest();
    assert(ServiceHost_IsStopRequested());
    assert(!ServiceHost_PublishRunningAgent(&agent));
    assert(g_ServiceHostAgent == NULL && !g_ServiceHostRunning);
    assert(g_ServiceHostStatus.dwCurrentState == SERVICE_STOP_PENDING);
    /* A latched stop withdraws STOP/SHUTDOWN acceptance and INTERROGATE must not restore it. */
    assert((g_ServiceHostStatus.dwControlsAccepted & STOP_CONTROLS) == 0);
    assert((g_ServiceHostStatus.dwControlsAccepted & ALL_CONTROLS) == (ALL_CONTROLS & ~STOP_CONTROLS));
    ServiceHost_RefreshControlsAccepted();
    assert((g_ServiceHostStatus.dwControlsAccepted & STOP_CONTROLS) == 0);
    ServiceHost_CompleteStartupStop();
    assert(g_ServiceHostStatus.dwCurrentState == SERVICE_STOPPED);
    assert(g_ServiceHostStatusTerminal);
    {
        unsigned terminalReports = statusReports;
        ServiceHost_BeginStopRequest();
        ServiceHost_ReportStopped(99, 99);
        assert(statusReports == terminalReports);
        assert(g_ServiceHostStatus.dwCurrentState == SERVICE_STOPPED);
    }

    reset();
    assert(ServiceHost_PublishRunningAgent(&agent));
    {
        DWORD completionError = 0;
        unsigned reportsBeforeFinal = statusReports;
        assert(!ServiceHost_CompleteAgentRun(&agent, &completionError));
        assert(completionError == ERROR_PROCESS_ABORTED);
        assert(g_ServiceHostFinalStatusReserved);
        ServiceHost_BeginStopRequest();
        assert(statusReports == reportsBeforeFinal);
        ServiceHost_ReportStopped(ERROR_SERVICE_SPECIFIC_ERROR, completionError);
        assert(statusReports == reportsBeforeFinal + 1);
        assert(g_ServiceHostStatusTerminal && !g_ServiceHostFinalStatusReserved);
    }

    reset();
    assert(ServiceHost_PublishRunningAgent(&agent));
    ServiceHost_BeginStopRequest();
    ServiceHost_FinalizeAgentRun(&agent, 0);
    assert(destroyCalls == 1);
    assert(telemetryCalls == 1);
    assert(g_ServiceHostStatus.dwCurrentState == SERVICE_STOPPED);

    for (index = 0; index < 10000; ++index) {
        pthread_t publish;
        pthread_t stop;
        reset();
        assert(pthread_create(&publish, NULL, publish_thread, NULL) == 0);
        assert(pthread_create(&stop, NULL, stop_thread, NULL) == 0);
        assert(pthread_join(publish, NULL) == 0);
        assert(pthread_join(stop, NULL) == 0);
        assert(g_ServiceHostStopRequested);
        assert(g_ServiceHostStatus.dwCurrentState == SERVICE_STOP_PENDING);
        assert(!g_ServiceHostRunning);
        if (g_ServiceHostAgent != NULL) { assert(stopDispatches == 1); }
    }
    for (index = 0; index < 10000; ++index) {
        pthread_t chainStop;
        pthread_t stop;
        reset();
        assert(ServiceHost_PublishRunningAgent(&agent));
        assert(pthread_create(&chainStop, NULL, chain_stop_thread, NULL) == 0);
        assert(pthread_create(&stop, NULL, stop_thread, NULL) == 0);
        assert(pthread_join(chainStop, NULL) == 0);
        assert(pthread_join(stop, NULL) == 0);
        assert(g_ServiceHostAgent == NULL);
        assert(!g_ServiceHostRunning);
        assert(stopDispatches <= 1);
        assert(g_ServiceHostStatus.dwCurrentState ==
            (stopDispatches == 1 ? SERVICE_STOP_PENDING : SERVICE_RUNNING));
        {
            DWORD completionError = 0;
            BOOL planned = ServiceHost_CompleteAgentRun(&agent, &completionError);
            assert(planned == (stopDispatches == 1));
            if (!planned) { assert(completionError == ERROR_PROCESS_ABORTED); }
        }
    }
    puts("service startup control: early and concurrent stop requests remain latched");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="mesh-service-startup-control-") as directory:
        work = pathlib.Path(directory)
        source_path = work / "fixture.c"
        binary_path = work / "fixture"
        source_path.write_text(fixture)
        subprocess.run(
            [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-pthread",
                str(source_path),
                "-o",
                str(binary_path),
            ],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True, timeout=60)


if __name__ == "__main__":
    main()
