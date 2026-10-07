#!/usr/bin/env python3
"""Run extracted production Windows pipe state machines with ASan/UBSan.

The fixture substitutes OS I/O and chain scheduling, not pipe lifecycle logic.
It needs Python 3 and a C compiler supporting -fsanitize=address,undefined.
Use --source with a pre-fix ILibProcessPipe.c to reproduce the failures.
This does not replace a Windows build or real overlapped-I/O validation.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess


FUNCTIONS = [
    "ILibProcessPipe_FreePipe_RequestClose",
    "ILibProcessPipe_FreePipe_TryFinalize",
    "ILibProcessPipe_FreePipe_TryFinalizeOnChain",
    "ILibProcessPipe_FreePipe_DeferredFinalize",
    "ILibProcessPipe_FreePipe_Finalize",
    "ILibProcessPipe_FreePipe",
    "ILibProcessPipe_Process_Destroy",
    "ILibProcessPipe_Process_RemoveHandlers",
    "ILibProcessPipe_Process_OnExit",
    "ILibProcessPipe_Process_OnExit_ChainSink",
    "ILibProcessPipe_Pipe_Resume_Continue",
    "ILibProcessPipe_Pipe_Resume_OnChain",
    "ILibProcessPipe_Process_ScheduleRead",
    "ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch",
    "ILibProcessPipe_Pipe_Resume",
    "ILibProcessPipe_Process_Pipe_ReadExHandler",
]


def extract(source, name):
    # Mask comments/literals while retaining offsets for balanced-brace extraction.
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: " " * len(m.group()), source, flags=re.S)
    for match in re.finditer(r"^(?:static )?(?:void|BOOL) " + name + r"\([^;\n]*\)", source, re.M):
        start = masked.find("{", match.end())
        if ";" in masked[match.end():start]:
            continue
        depth = 1
        end = start + 1
        while depth:
            depth += (masked[end] == "{") - (masked[end] == "}")
            end += 1
        return match.group(), source[start:end]
    raise ValueError("Production definition not found: " + name)


PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WIN32 1
#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((void *)(intptr_t)-1)
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define ILIBLOGMESSAGEX2(...) ((void)0)
#define ILibRemoteLogging_printf(...) ((void)0)
typedef int BOOL;
typedef unsigned long DWORD;
typedef long LONG;
typedef void *HANDLE;
typedef struct { HANDLE hEvent; } OVERLAPPED;
typedef enum { ILibWaitHandle_ErrorStatus_NONE, ILibWaitHandle_ErrorStatus_IO_ERROR } ILibWaitHandle_ErrorStatus;
typedef struct ILibProcessPipe_PipeObject ILibProcessPipe_PipeObject;
typedef ILibProcessPipe_PipeObject *ILibProcessPipe_Pipe;
typedef struct ILibProcessPipe_Process_Object ILibProcessPipe_Process_Object;
typedef ILibProcessPipe_Process_Object *ILibProcessPipe_Process;
typedef void (*ILibProcessPipe_GenericReadHandler)(char *, size_t, size_t *, void *, void *);
typedef struct { struct { void *ParentChain; } ChainLink; } Manager;
struct ILibProcessPipe_Process_Object {
    int exiting, hProcess_needAdd, disabled;
    void *chain;
    ILibProcessPipe_PipeObject *stdIn, *stdOut, *stdErr;
    void *metadata;
    HANDLE hProcess;
    void *userObject;
    void (*exitHandler)(ILibProcessPipe_Process, int, void *);
};
struct ILibProcessPipe_PipeObject {
    Manager *manager;
    ILibProcessPipe_Process_Object *mProcess;
    LONG activeReadCallbacks, activeWriteHandler, resumePending, pendingWrite;
    int writeClosing;
    LONG closeRequested, finalFreePending, finalizing;
    int PAUSED, bufferOwner;
    void *handler, *user1, *user2, *user3, *user4;
    void (*brokenPipeHandler)(ILibProcessPipe_PipeObject *);
    HANDLE mPipe_ReadEnd, mPipe_WriteEnd, mPipe_Reader_ResumeEvent;
    OVERLAPPED *mOverlapped, *mwOverlapped;
    void *metadata, *WriteBuffer;
    char *buffer;
    size_t bufferSize, readOffset, totalRead;
};
typedef void ILibProcessPipe_WriteData;
enum { ILibTransport_MemoryOwnership_CHAIN = 0 };
static Manager manager = {{(void *)1}};
static ILibProcessPipe_PipeObject *watched_pipe;
static int pipe_frees, reads_issued, data_calls, on_chain = 1;
static ILibProcessPipe_Process_Object *watched_process;
static int process_frees, process_wait, exit_calls;
static void (*queued)(void *, void *);
static void *queued_user;
static LONG InterlockedIncrement(LONG *v) { return ++*v; }
static LONG InterlockedDecrement(LONG *v) { return --*v; }
static LONG InterlockedExchange(LONG *v, LONG n) { LONG old = *v; *v = n; return old; }
static LONG InterlockedCompareExchange(LONG *v, LONG n, LONG expected) {
    LONG old = *v; if (old == expected) { *v = n; } return old;
}
static LONG ILibProcessPipe_GetStateLong(LONG *v) { return *v; }
static int ILibMemory_CanaryOK(void *p) { return p != NULL; }
static void ILibMemory_Free(void *p) { if (p && p == watched_pipe) { ++pipe_frees; } if (p && p == watched_process) { ++process_frees; } free(p); }
static BOOL GetExitCodeProcess(HANDLE h, DWORD *code) { (void)h; *code = 0; return TRUE; }
static int CloseHandle(HANDLE h) { (void)h; return 1; }
static void CancelIoEx(HANDLE h, OVERLAPPED *o) { (void)h; (void)o; }
static void SetEvent(HANDLE h) { (void)h; }
static void ILibChain_RemoveWaitHandleEx(void *c, HANDLE h, int n) { (void)c; (void)h; (void)n; }
static void ILibChain_RemoveWaitHandle(void *c, HANDLE h) { (void)c; if (h == (void *)4) { process_wait = 0; } }
static void ILibQueue_Lock(void *q) { (void)q; }
static void ILibQueue_UnLock(void *q) { (void)q; }
static void *ILibQueue_DeQueue(void *q) { (void)q; return NULL; }
static void ILibQueue_Destroy(void *q) { (void)q; }
static void ILibProcessPipe_WriteData_Destroy(void *d) { (void)d; }
static int ILibIsRunningOnChainThread(void *c) { (void)c; return on_chain; }
static void ILibChain_RunOnMicrostackThreadEx3(void *c, void (*f)(void *, void *), void (*a)(void *, void *), void *u) {
    (void)c; (void)a; assert(queued == NULL); queued = f; queued_user = u;
}
#define ILibChain_RunOnMicrostackThread(c,f,u) do { if(on_chain) { f(c,u); } else { ILibChain_RunOnMicrostackThreadEx3(c,f,NULL,u); } } while(0)
#define ILibChain_AddWaitHandle(...) ((void)0)
static void ILibChain_AddWaitHandleEx(void *c, HANDLE h, int timeout, BOOL (*f)(void *, HANDLE, ILibWaitHandle_ErrorStatus, void *), void *u, char *m) {
    (void)c; (void)timeout; (void)f; (void)u; (void)m;
    if (h == (void *)4) { assert(!process_wait); process_wait = 1; }
}
static BOOL ILibProcessPipe_ReadWindowIsValid(ILibProcessPipe_PipeObject *p) {
    return p->buffer && p->readOffset <= p->bufferSize && p->totalRead <= p->bufferSize-p->readOffset;
}
static BOOL ILibProcessPipe_ReadWindowCanAppend(ILibProcessPipe_PipeObject *p, DWORD n) {
    return ILibProcessPipe_ReadWindowIsValid(p) && n <= p->bufferSize-p->readOffset-p->totalRead;
}
static BOOL ILibProcessPipe_FailInvalidReadWindow(ILibProcessPipe_PipeObject *p, const char *site) {
    (void)p; fprintf(stderr, "invalid read window: %s\n", site); abort();
}
static void ILibChain_ReadEx2(void *c, HANDLE h, OVERLAPPED *o, char *b, DWORD n,
    BOOL (*f)(void *, HANDLE, ILibWaitHandle_ErrorStatus, char *, DWORD, void *), void *u, void *m) {
    (void)c; (void)h; (void)o; (void)b; (void)n; (void)f; (void)u; (void)m;
    ++reads_issued; // Hold completion until the test explicitly dispatches it.
}
#ifndef _WIN32
static void memmove_s(void *d, size_t cap, const void *s, size_t n) { assert(n <= cap); memmove(d,s,n); }
#endif
#define ILibMemory_ReallocateRaw(p,n) (*(p) = realloc(*(p),n))
'''

TESTS = r'''
static void exited(ILibProcessPipe_Process p, int code, void *u) { (void)p; (void)code; (void)u; ++exit_calls; }
static void consume(char *b, size_t n, size_t *used, void *u1, void *u2) {
    (void)b; (void)u1; (void)u2; ++data_calls; *used = n;
}
static void close_in_callback(char *b, size_t n, size_t *used, void *u1, void *u2) {
    consume(b,n,used,u1,u2);
    ILibProcessPipe_FreePipe(watched_pipe);
}
static ILibProcessPipe_PipeObject *new_pipe(void) {
    ILibProcessPipe_PipeObject *p = calloc(1,sizeof(*p));
    p->manager = &manager;
    p->mOverlapped = calloc(1,sizeof(*p->mOverlapped));
    p->mOverlapped->hEvent = (void *)2;
    p->mPipe_ReadEnd = (void *)3;
    p->buffer = calloc(1,16);
    p->bufferSize = 16;
    p->handler = (void *)consume;
    watched_pipe = p;
    return p;
}
static void run_queued(void) {
    void (*f)(void *, void *) = queued;
    void *u = queued_user;
    assert(f != NULL); queued = NULL; queued_user = NULL; f(manager.ChainLink.ParentChain,u);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    ILibProcessPipe_PipeObject *p = new_pipe();
    if (!strcmp(argv[1],"resume-close")) {
        p->PAUSED = 1; p->totalRead = 4; p->handler = (void *)close_in_callback;
        ILibProcessPipe_Pipe_Resume(p);
        assert(data_calls == 1 && pipe_frees == 1 && reads_issued == 0);
    } else if (!strcmp(argv[1],"resume-pending")) {
        assert(ILibProcessPipe_Process_ScheduleRead(p));
        p->PAUSED = 1;
        ILibProcessPipe_Pipe_Resume(p);
        run_queued();
        assert(reads_issued == 1 && p->activeReadCallbacks == 1);
        // The original read completion must still deliver output after resume.
        p->handler = (void *)close_in_callback;
        ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch(manager.ChainLink.ParentChain,p->mPipe_ReadEnd,
            ILibWaitHandle_ErrorStatus_NONE,p->buffer,4,p);
        assert(data_calls == 1 && pipe_frees == 1);
    } else if (!strcmp(argv[1],"process-close-pending")) {
        ILibProcessPipe_Process_Object *process = calloc(1,sizeof(*process));
        p->mProcess = process; process->stdOut = p;
        assert(ILibProcessPipe_Process_ScheduleRead(p));
        ILibProcessPipe_Process_Destroy(process);
        assert(pipe_frees == 0);
        ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch(manager.ChainLink.ParentChain,p->mPipe_ReadEnd,
            ILibWaitHandle_ErrorStatus_IO_ERROR,NULL,0,p);
        assert(pipe_frees == 1);
    } else if (!strcmp(argv[1],"pipe-close-process-free")) {
        ILibProcessPipe_Process_Object *process = calloc(1,sizeof(*process));
        p->mProcess = process; process->stdOut = p;
        assert(ILibProcessPipe_Process_ScheduleRead(p));
        ILibProcessPipe_FreePipe(p);
        assert(!process->stdOut && !p->mProcess && !pipe_frees);
        free(process);
        ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch(manager.ChainLink.ParentChain,p->mPipe_ReadEnd,
            ILibWaitHandle_ErrorStatus_IO_ERROR,NULL,0,p);
        assert(pipe_frees == 1);
    } else if (!strcmp(argv[1],"close-queued-resume")) {
        p->PAUSED = 1; on_chain = 0;
        ILibProcessPipe_Pipe_Resume(p);
        on_chain = 1;
        ILibProcessPipe_FreePipe(p);
        assert(pipe_frees == 0);
        run_queued();
        assert(pipe_frees == 1 && data_calls == 0 && reads_issued == 0);
    } else if (!strcmp(argv[1],"resume-buffered")) {
        p->PAUSED = 1; p->totalRead = 4;
        ILibProcessPipe_Pipe_Resume(p);
        assert(data_calls == 1 && reads_issued == 1 && p->activeReadCallbacks == 1);
        ILibProcessPipe_FreePipe(p);
        ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch(manager.ChainLink.ParentChain,p->mPipe_ReadEnd,
            ILibWaitHandle_ErrorStatus_IO_ERROR,NULL,0,p);
        assert(pipe_frees == 1);
    } else if (!strcmp(argv[1],"owner-collected") || !strcmp(argv[1],"owner-collected-paused") || !strcmp(argv[1],"owner-collected-deferred-exit")) {
        ILibProcessPipe_Process_Object *process = calloc(1,sizeof(*process));
        watched_process = process; process->chain = manager.ChainLink.ParentChain;
        process->hProcess = (void *)4; process->stdOut = p; p->mProcess = process;
        process->userObject = (void *)5; process->exitHandler = exited;
        process_wait = 1;
        assert(ILibProcessPipe_Process_ScheduleRead(p));
        if (!strcmp(argv[1],"owner-collected-paused")) {
            p->PAUSED = 1; p->totalRead = 4;
            assert(ILibProcessPipe_Process_OnExit(process->chain,process->hProcess,ILibWaitHandle_ErrorStatus_NONE,process));
            assert(!process_wait && process->hProcess_needAdd && !process_frees);
        }
        ILibProcessPipe_Process_RemoveHandlers(process);
        ILibProcessPipe_Process_RemoveHandlers(process); // Repeated finalization must not add a duplicate wait.
        assert(process_wait && process->disabled && !process->userObject && !process->exitHandler);
        if (!strcmp(argv[1],"owner-collected-deferred-exit")) {
            ILibProcessPipe_Process_OnExit_ChainSink(process->chain,process);
        } else {
            assert(!ILibProcessPipe_Process_OnExit(process->chain,process->hProcess,ILibWaitHandle_ErrorStatus_NONE,process));
        }
        assert(process_frees == 1 && !process_wait && !exit_calls && !pipe_frees && !p->mProcess);
        ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch(manager.ChainLink.ParentChain,p->mPipe_ReadEnd,
            ILibWaitHandle_ErrorStatus_IO_ERROR,NULL,0,p);
        assert(pipe_frees == 1 && !data_calls);
    } else { assert(!"unknown test"); }
    puts("PASS"); return 0;
}
'''


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=root / "microstack/ILibProcessPipe.c")
    parser.add_argument("--evidence", type=Path, default=root / "artifacts/validation/process-pipe-lifetime")
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    functions = [extract(args.source.read_text(), name) for name in FUNCTIONS]
    fixture = args.evidence / "process-pipe-lifetime.c"
    executable = args.evidence / ("process-pipe-lifetime.exe" if os.name == "nt" else "process-pipe-lifetime")
    fixture.write_text(PRELUDE + "\n".join(signature + ";" for signature, _ in functions) +
                       "\n" + "\n".join(signature + "\n" + body for signature, body in functions) + TESTS)
    subprocess.run([args.cc, "-std=c11", "-g", "-O1", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", str(fixture), "-o", str(executable)], check=True)
    runtime_env = os.environ.copy()
    if os.name == "nt":
        compiler = shutil.which(args.cc)
        if compiler:
            runtimes = list(Path(compiler).parent.parent.glob("lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll"))
            if runtimes:
                runtime_env["PATH"] = str(runtimes[0].parent) + os.pathsep + runtime_env.get("PATH", "")
    failures = []
    for case in ["resume-close", "resume-pending", "process-close-pending", "pipe-close-process-free", "close-queued-resume", "resume-buffered", "owner-collected", "owner-collected-paused", "owner-collected-deferred-exit"]:
        result = subprocess.run([str(executable.resolve()), case], text=True, capture_output=True, env=runtime_env)
        (args.evidence / (case + ".log")).write_text("exit=" + str(result.returncode) + "\n" + result.stdout + result.stderr)
        print(f"{'PASS' if result.returncode == 0 else 'FAIL'} {case}")
        if result.returncode:
            failures.append(case)
    if failures:
        raise SystemExit("Failed: " + ", ".join(failures) + "; see " + str(args.evidence))


if __name__ == "__main__":
    main()
