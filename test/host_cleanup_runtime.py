#!/usr/bin/env python3
"""Execute production host cleanup with deterministic Win32 API fault injection.

This portable test compiles extracted native functions; it does not install or
launch an agent. A Windows ConPTY/SCM runtime run remains a separate gate.
"""
import argparse
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def function(source, name):
    start = source.index(name + '(')
    start = source.rfind('\n', 0, start) + 1
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=pathlib.Path, default=ROOT / 'meshservice/runtime_host_contract.c')
    args = parser.parse_args()
    source = args.source.read_text()
    close_start = source.index('typedef struct MeshConsoleBridgeCloseContext')
    close_end = source.index('static BOOL MeshConsoleBridge_WriteReadyMarker', close_start)
    helpers = function(source, 'MeshConsoleBridge_StopCopyThread') + '\n' + source[close_start:close_end]
    redirect = function(source, 'MeshConsoleBridge_RunRedirectedShellW').split('\ncleanup:', 1)[1]
    conpty = function(source, 'MeshConsoleBridge_RunW').split('\ncleanup:', 1)[1]
    lifecycle = function(source, 'MeshRuntimeHost_LaunchLifecycleHostW').split('\ncleanup:', 1)[1]
    prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
typedef uintptr_t HANDLE;
typedef unsigned long DWORD;
typedef unsigned long long ULONGLONG;
typedef long LONG;
typedef int BOOL;
typedef void* LPVOID;
#define WINAPI
#define TRUE 1
#define FALSE 0
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define ERROR_SUCCESS 0
#define ERROR_TIMEOUT 1460
#define ERROR_OPERATION_ABORTED 995
#define ERROR_FILE_NOT_FOUND 2
#define MESH_CONSOLE_BRIDGE_EXEC_OUTPUT_DRAIN_MS 5000
#undef NULL
#define NULL 0
typedef void (*MeshConsoleBridge_ClosePseudoConsoleFn)(HANDLE);
static int stopped[16], closed[16], blocked, createFailed, closeCalled, closeWaits, deleted, removed;
static ULONGLONG ticks;
static volatile LONG* outputStop;
static wchar_t MeshRuntimeHost_TempLifecycleDir[16] = L"temp";
static void ServiceDeploy_LogInstallEvent(const wchar_t* fmt, ...) { (void)fmt; }
static DWORD GetLastError(void) { return 5; }
static void SetLastError(DWORD e) { (void)e; }
static ULONGLONG GetTickCount64(void) { return ++ticks; }
static LONG InterlockedExchange(volatile LONG* p, LONG value) { LONG prev = *p; *p = value; return prev; }
static void ExitProcess(DWORD code) { fprintf(stderr, "Unexpected host exit %lu\n", code); abort(); }
static BOOL CancelSynchronousIo(HANDLE h) { stopped[h] = 1; return TRUE; }
static DWORD WaitForSingleObject(HANDLE h, DWORD ms) {
    (void)ms;
    if (h == 3) {
        ++closeWaits;
        if (blocked && !closed[6]) return WAIT_TIMEOUT;
        stopped[3] = 1;
        return WAIT_OBJECT_0;
    }
    return stopped[h] ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
}
static BOOL CloseHandle(HANDLE h) {
    // Worker 1 owns stdin (4/5); worker 2 owns stdout (6/7).
    if (h == 4 || h == 5) assert(stopped[1]);
    if (h == 6 || h == 7) assert(stopped[2]);
    if (h == 1 || h == 2 || h == 3) assert(stopped[h]);
    closed[h] = 1;
    return TRUE;
}
static void MeshConsoleBridge_CloseHandle(HANDLE* h) { if (*h) { CloseHandle(*h); *h = 0; } }
static BOOL TerminateProcess(HANDLE h, DWORD code) { (void)h; (void)code; return TRUE; }
static HANDLE CreateThread(void* a, DWORD b, DWORD (*fn)(void*), void* arg, DWORD c, void* d) {
    (void)a; (void)b; (void)c; (void)d;
    if (createFailed) return NULL;
    // The simulated close signals asynchronously through WaitForSingleObject.
    fn(arg);
    return 3;
}
static void closeConsole(HANDLE h) {
    assert(h == 8);
    ++closeCalled;
    if (!createFailed) assert(*outputStop == 0); // Normal final output is still being drained.
    else assert(closed[6]); // Thread creation failure releases conhost output first.
}
static BOOL DeleteFileW(const wchar_t* p) { (void)p; ++deleted; return TRUE; }
static BOOL RemoveDirectoryW(const wchar_t* p) { (void)p; ++removed; return TRUE; }
static void reset(void) {
    for (int i=0; i<16; ++i) { stopped[i]=closed[i]=0; }
    ticks=0; blocked=createFailed=closeCalled=closeWaits=deleted=removed=0;
    MeshRuntimeHost_TempLifecycleDir[0]=L't';
}
'''
    common = r'''
    struct { HANDLE hProcess, hThread; } processInfo = {0, 0};
    HANDLE inputThread=1, outputThread=2, inputPipe=4, outputPipe=7;
    volatile LONG inputStopFlag=0, outputStopFlag=0;
    BOOL processCompleted=TRUE;
    DWORD exitCode=0;
    outputStop=&outputStopFlag;
'''
    c = prefix + helpers
    c += '\nstatic DWORD redirectCleanup(void) {\n' + common + '\nHANDLE childInputWrite=5, childInputRead=0, childOutputRead=6, childOutputWrite=0;\n' + redirect
    c += '\nstatic DWORD conptyCleanup(void) {\n' + common + '\nHANDLE ptyInputWrite=5, ptyInputRead=0, ptyOutputRead=6, ptyOutputWrite=0, pseudoConsole=8;\nstruct { MeshConsoleBridge_ClosePseudoConsoleFn ClosePseudoConsoleFn; } conptyApi = {closeConsole};\n' + conpty
    c += r'''
static BOOL lifecycleCleanup(BOOL childExists, BOOL childExited) {
    struct { HANDLE hProcess, hThread; } pi = {childExists ? 10 : 0, 0};
    BOOL waitForExit=TRUE, deleteHostDllOnExit=TRUE, ok=TRUE;
    wchar_t manifestPath[16]=L"manifest", hostDllPath[16]=L"dll";
    DWORD error=0;
''' + lifecycle
    c += r'''
int main(void) {
    reset(); assert(redirectCleanup()==0); assert(closed[4] && closed[5] && closed[6] && closed[7]);
    reset(); assert(conptyCleanup()==0); assert(closeCalled==1 && closeWaits==1);
    reset(); blocked=1; assert(conptyCleanup()==0); assert(closeCalled==1 && closeWaits==2 && closed[6]);
    reset(); createFailed=1; assert(conptyCleanup()==0); assert(closeCalled==1 && closed[6]);
    reset(); lifecycleCleanup(TRUE,FALSE); assert(deleted==0 && removed==0);
    reset(); lifecycleCleanup(TRUE,TRUE); assert(deleted==2 && removed==1);
    reset(); lifecycleCleanup(FALSE,FALSE); assert(deleted==2 && removed==1);
    puts("PASS: 7 production cleanup cases (blocked stdin, final drain, blocked stdout, close-worker failure, live child, exited child, launch failure)");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='mesh-host-cleanup-') as folder:
        path = pathlib.Path(folder)
        (path / 'fixture.c').write_text(c)
        subprocess.run(['cc', '-std=c11', '-fsanitize=address,undefined', '-g', str(path / 'fixture.c'), '-o', str(path / 'fixture')], check=True)
        subprocess.run([str(path / 'fixture')], check=True, timeout=15)


if __name__ == '__main__':
    main()
