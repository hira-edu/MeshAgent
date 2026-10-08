#!/usr/bin/env python3
"""Run the production service-stop loop against a deterministic SCM and clock.

No services or processes are changed. POSIX builds use ASan/UBSan; when MinGW
is available, also compile against the real Windows status structures.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/service_deployment.c').read_text()
start = source.index('static BOOL ServiceDeploy_StopServiceAndWait(', source.index('static BOOL ServiceDeploy_ProcessHostsOnlyService('))
end = source.index('\nstatic void ServiceDeploy_TerminateProcessesByPath(', start)
production = source[start:end]

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#ifdef _WIN32
#include <windows.h>
#else
typedef int BOOL;
typedef uint32_t DWORD;
typedef unsigned char BYTE, *LPBYTE;
typedef void *HANDLE, *SC_HANDLE;
typedef struct { DWORD dwServiceType, dwCurrentState, dwControlsAccepted,
    dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
} SERVICE_STATUS, *LPSERVICE_STATUS;
typedef struct { DWORD dwServiceType, dwCurrentState, dwControlsAccepted,
    dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint,
    dwProcessId, dwServiceFlags;
} SERVICE_STATUS_PROCESS;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define ERROR_SUCCESS 0
#define ERROR_ACCESS_DENIED 5
#define ERROR_TIMEOUT 1460
#define ERROR_SERVICE_CANNOT_ACCEPT_CTRL 1061
#define SC_MANAGER_CONNECT 1
#define SERVICE_QUERY_STATUS 4
#define SERVICE_STOP 32
#define SERVICE_CONTROL_STOP 1
#define SERVICE_CONTROL_INTERROGATE 4
#define SC_STATUS_PROCESS_INFO 0
#define SERVICE_STOPPED 1
#define SERVICE_START_PENDING 2
#define SERVICE_STOP_PENDING 3
#define SERVICE_RUNNING 4
#define SERVICE_WIN32_OWN_PROCESS 16
#define SERVICE_WIN32_SHARE_PROCESS 32
#define PROCESS_TERMINATE 1
#define SYNCHRONIZE 0x100000
#endif
#ifndef _countof
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif
static DWORD ticks, origin, lastError, finishAt, controlCost;
static SERVICE_STATUS_PROCESS current;
static int queries, failQueryAt, stopCalls, pendingControls, interrogates;
static int allowOn, allowOff, closed, processOpens, kills, processCloses;
static int deniedControlAccess, rejectStops, pendingRace, autoStart, exclusive;
static int openProcessFails, terminateFails, queryWarnings, timeoutWarnings, ownershipWarnings;
static DWORD elapsed(void) { return ticks - origin; }
static SC_HANDLE open_scm(void) { return (SC_HANDLE)(uintptr_t)1; }
static SC_HANDLE open_service(DWORD access) {
    if (deniedControlAccess && (access & SERVICE_STOP)) { lastError=ERROR_ACCESS_DENIED; return NULL; }
    return (SC_HANDLE)(uintptr_t)2;
}
static BOOL close_service(SC_HANDLE h) {
    assert(h==(SC_HANDLE)(uintptr_t)1 || h==(SC_HANDLE)(uintptr_t)2);
    ++closed; lastError=183; return TRUE;
}
static BOOL allow_stop(BOOL allow) { if(allow)++allowOn; else ++allowOff; lastError=183; return TRUE; }
static void log_event(const wchar_t* fmt) {
    if(wcsstr(fmt,L"status query failed"))++queryWarnings;
    if(wcsstr(fmt,L"stop timed out"))++timeoutWarnings;
    if(wcsstr(fmt,L"exclusive process ownership"))++ownershipWarnings;
    lastError=183;
}
static BOOL query_status(SC_HANDLE h, BYTE* buffer, DWORD size, DWORD* needed) {
    assert(h==(SC_HANDLE)(uintptr_t)2 && size==sizeof(current));
    ++queries; *needed=sizeof(current);
    if(queries==failQueryAt) { lastError=ERROR_ACCESS_DENIED; return FALSE; }
    if(autoStart && current.dwCurrentState==SERVICE_START_PENDING && elapsed()>=1000)current.dwCurrentState=SERVICE_RUNNING;
    if(elapsed()>=finishAt)current.dwCurrentState=SERVICE_STOPPED;
    memcpy(buffer,&current,sizeof(current)); return TRUE;
}
static BOOL control_service(SC_HANDLE h, DWORD control, SERVICE_STATUS* status) {
    assert(h==(SC_HANDLE)(uintptr_t)2);
    if(control==SERVICE_CONTROL_INTERROGATE) { ++interrogates; return TRUE; }
    assert(control==SERVICE_CONTROL_STOP); ++stopCalls;
    if(current.dwCurrentState==SERVICE_STOP_PENDING || current.dwCurrentState==SERVICE_START_PENDING)++pendingControls;
    ticks+=controlCost;
    if(pendingRace) { current.dwCurrentState=SERVICE_STOP_PENDING; lastError=ERROR_SERVICE_CANNOT_ACCEPT_CTRL; return FALSE; }
    if(rejectStops || pendingControls) { lastError=ERROR_SERVICE_CANNOT_ACCEPT_CTRL; return FALSE; }
    current.dwCurrentState=SERVICE_STOP_PENDING;
    memcpy(status,&current,sizeof(*status)); return TRUE;
}
static HANDLE open_process(DWORD access, BOOL inherit, DWORD pid) {
    assert(access==(PROCESS_TERMINATE|SYNCHRONIZE) && !inherit && pid==123);
    ++processOpens; if(openProcessFails){lastError=ERROR_ACCESS_DENIED;return NULL;}
    return (HANDLE)(uintptr_t)3;
}
static BOOL terminate_process(HANDLE h, DWORD code) {
    assert(h==(HANDLE)(uintptr_t)3 && !code); ++kills;
    if(terminateFails){lastError=ERROR_ACCESS_DENIED;return FALSE;}
    finishAt=elapsed()+750; return TRUE;
}
static DWORD wait_process(HANDLE h, DWORD timeout) { assert(h==(HANDLE)(uintptr_t)3 && timeout==5000); return 0; }
static BOOL close_process(HANDLE h) { assert(h==(HANDLE)(uintptr_t)3); ++processCloses; lastError=183; return TRUE; }
#define OpenSCManagerW(...) open_scm()
#define OpenServiceW(s,n,a) open_service(a)
#define CloseServiceHandle close_service
#define ServiceDeploy_SetServiceAllowStop(n,a) allow_stop(a)
#define ServiceDeploy_LogInstallEvent(fmt,...) log_event(fmt)
#define QueryServiceStatusEx(h,l,b,s,n) query_status(h,b,s,n)
#define ControlService control_service
#define GetTickCount() ticks
#define GetLastError() lastError
#define SetLastError(e) (lastError=(e))
#define Sleep(ms) (ticks+=(ms))
#define ServiceDeploy_ResolveServiceDllPath(n,p,c) ((p)[0]=L'x',TRUE)
#define ServiceHost_ValidateServiceBinding(n,p) ((void)(p),exclusive)
#define ServiceDeploy_ProcessHostsOnlyService(n,p) ((void)(p),exclusive)
#define OpenProcess open_process
#define TerminateProcess terminate_process
#define WaitForSingleObject wait_process
#define CloseHandle close_process
'''
cases = r'''
static void reset(DWORD state) {
    memset(&current,0,sizeof(current)); current.dwCurrentState=state;
    current.dwServiceType=SERVICE_WIN32_SHARE_PROCESS; current.dwProcessId=123;
    ticks=origin=100; lastError=183; finishAt=UINT32_MAX; controlCost=0;
    queries=failQueryAt=stopCalls=pendingControls=interrogates=0;
    allowOn=allowOff=closed=processOpens=kills=processCloses=0;
    deniedControlAccess=rejectStops=pendingRace=autoStart=0; exclusive=1;
    openProcessFails=terminateFails=queryWarnings=timeoutWarnings=ownershipWarnings=0;
}
static void cleanup_checks(void) { assert(closed==2 && allowOff==(allowOn>0) && processCloses==processOpens-((openProcessFails&&processOpens)?1:0)); }
static BOOL run(DWORD timeout, BOOL force) {
    BOOL result=ServiceDeploy_StopServiceAndWait(L"Agent",timeout,force);
    cleanup_checks(); assert(!pendingControls); return result;
}
int main(void) {
    reset(SERVICE_RUNNING); finishAt=2500; assert(run(5000,TRUE)); assert(stopCalls==1&&!kills);
    reset(SERVICE_STOP_PENDING); finishAt=2500; assert(run(5000,TRUE)); assert(!stopCalls&&!kills);
    reset(SERVICE_START_PENDING); autoStart=1; finishAt=2500; assert(run(5000,FALSE)); assert(stopCalls==1);
    reset(SERVICE_START_PENDING); assert(!run(2000,FALSE)); assert(!stopCalls&&lastError==ERROR_TIMEOUT);
    reset(SERVICE_RUNNING); pendingRace=1; finishAt=2500; assert(run(5000,FALSE)); assert(stopCalls==1&&interrogates==1);
    /* Query at the deadline before claiming a timeout, including zero timeout. */
    reset(SERVICE_STOP_PENDING); finishAt=2000; assert(run(2000,FALSE)); assert(!timeoutWarnings);
    reset(SERVICE_STOPPED); assert(run(0,TRUE)); assert(!stopCalls&&!processOpens);
    /* Time in a synchronous SCM call counts against the stop budget. */
    reset(SERVICE_RUNNING); controlCost=2500; assert(!run(2000,FALSE)); assert(elapsed()==2500&&lastError==ERROR_TIMEOUT);
    reset(SERVICE_RUNNING); rejectStops=1; assert(!run(4000,FALSE)); assert(stopCalls==2&&elapsed()==4000);
    reset(SERVICE_RUNNING); ticks=origin=0; rejectStops=1; assert(!run(4000,FALSE)); assert(stopCalls==2);
    reset(SERVICE_STOP_PENDING); ticks=origin=UINT32_MAX-999; finishAt=2000; assert(run(2000,FALSE)); assert(elapsed()==2000);
    /* Never terminate a process using a stale status after a failed query. */
    reset(SERVICE_RUNNING); failQueryAt=4; assert(!run(2000,TRUE)); assert(!kills&&!processOpens&&queryWarnings==1&&!timeoutWarnings&&lastError==ERROR_ACCESS_DENIED);
    reset(SERVICE_STOP_PENDING); exclusive=0; assert(!run(2000,TRUE)); assert(!kills&&!processOpens&&ownershipWarnings==1&&lastError==ERROR_TIMEOUT);
    reset(SERVICE_STOP_PENDING); assert(!run(2000,FALSE)); assert(!kills&&!processOpens&&lastError==ERROR_TIMEOUT);
    reset(SERVICE_STOP_PENDING); assert(run(2000,TRUE)); assert(kills==1&&elapsed()==2750);
    reset(SERVICE_RUNNING); deniedControlAccess=1; assert(run(2000,TRUE)); assert(!stopCalls&&!allowOn&&kills==1);
    reset(SERVICE_STOP_PENDING); openProcessFails=1; assert(!run(2000,TRUE)); assert(!kills&&lastError==ERROR_ACCESS_DENIED);
    reset(SERVICE_STOP_PENDING); terminateFails=1; assert(!run(2000,TRUE)); assert(kills==1&&lastError==ERROR_ACCESS_DENIED);
    reset(SERVICE_STOP_PENDING); failQueryAt=7; assert(!run(2000,TRUE)); assert(kills==1&&lastError==ERROR_ACCESS_DENIED);
    puts("service stop: 19 cases passed (pending states, deadlines, retries, query faults, ownership, termination faults and cleanup)");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='mesh-service-stop-') as tmp:
    src, exe = Path(tmp) / 'stop.c', Path(tmp) / 'stop'
    src.write_text(fixture + production + cases)
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror']
    sanitizers = [] if os.name == 'nt' else ['-fsanitize=address,undefined']
    subprocess.run([os.environ.get('CC', 'clang'), *flags, *sanitizers, str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
    cross = shutil.which('x86_64-w64-mingw32-gcc')
    if os.name != 'nt' and cross:
        subprocess.run([cross, *flags, '-c', str(src), '-o', str(Path(tmp) / 'stop.o')], check=True)
        print('Windows status types: MinGW cross-compilation passed (execution requires Windows)')
