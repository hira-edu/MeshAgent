#!/usr/bin/env python3
"""Run the production update-quiesce helpers against a scripted file system and clock.

Processes that hold the runtime DLL or EXE are terminated only as a single, logged
last resort after the target is found locked, never on every poll and never when
the file is already free. No process or file is touched.
"""
import os
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def extract(source, name):
    match = re.search(r"(?m)^[^\n;]*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source)
    if not match:
        raise AssertionError("Missing production function: " + name)
    depth = 1
    for token in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[match.end():]):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():match.end() + token.end()]
    raise AssertionError("Unclosed function: " + name)


PRELUDE = r'''
#define _CRT_SECURE_NO_WARNINGS 1
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
typedef void *HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_ACCESS_DENIED 5
#define ERROR_SHARING_VIOLATION 32
#define ERROR_LOCK_VIOLATION 33
#define ERROR_DISK_FULL 112
#define DELETE 0x10000
#define GENERIC_WRITE 0x40000000
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x80
#endif
#ifndef ERROR_DISK_FULL
#define ERROR_DISK_FULL 112
#endif
#ifndef _countof
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif
typedef struct { wchar_t exePath[MAX_PATH]; wchar_t dllPath[MAX_PATH]; } ServiceInstallPaths;
static DWORD ticks, lastError;
static int holders, opens, kills, lastResortLogs, failureLogs, missing;
static DWORD otherLockUntil, openError;
static DWORD fs_attributes(const wchar_t *path) { (void)path; return missing ? INVALID_FILE_ATTRIBUTES : FILE_ATTRIBUTE_NORMAL; }
static BOOL fs_set_attributes(const wchar_t *path, DWORD value) { (void)path; (void)value; return TRUE; }
static HANDLE fs_open(const wchar_t *path, DWORD access, DWORD share) {
    (void)path; assert(share == 0 && (access & GENERIC_WRITE)); ++opens;
    if (openError) { lastError = openError; return INVALID_HANDLE_VALUE; }
    if (holders || ticks < otherLockUntil) { lastError = ERROR_SHARING_VIOLATION; return INVALID_HANDLE_VALUE; }
    return (HANDLE)(uintptr_t)7;
}
static BOOL fs_close(HANDLE h) { assert(h == (HANDLE)(uintptr_t)7); return TRUE; }
static void kill_dll_holders(const wchar_t *dll) { assert(wcscmp(dll, L"C:\\Agent\\agent.dll") == 0); ++kills; holders = 0; }
static void kill_exe_holders(const wchar_t *exe) { assert(wcscmp(exe, L"C:\\Agent\\agent.exe") == 0); }
static void log_event(const wchar_t *fmt) {
    if (wcsstr(fmt, L"Last resort")) ++lastResortLogs;
    if (wcsstr(fmt, L"Unable to quiesce")) ++failureLogs;
}
#define GetFileAttributesW fs_attributes
#define SetFileAttributesW fs_set_attributes
#define CreateFileW(p,a,s,sa,c,f,t) fs_open(p,a,s)
#define CloseHandle fs_close
#define GetLastError() lastError
#define SetLastError(e) (lastError=(e))
#define GetTickCount() ticks
#define Sleep(ms) (ticks+=(ms))
#define ServiceDeploy_LogInstallEvent(fmt,...) log_event(fmt)
#define ServiceDeploy_LogPathState(p) ((void)(p))
#define ServiceDeploy_TerminateProcessesByLoadedModulePath kill_dll_holders
#define ServiceDeploy_TerminateProcessesByPath kill_exe_holders
'''

MAIN = r'''
static ServiceInstallPaths paths;
static void reset(void) {
    wcscpy(paths.exePath, L"C:\\Agent\\agent.exe"); wcscpy(paths.dllPath, L"C:\\Agent\\agent.dll");
    ticks = 1000; lastError = 0; holders = opens = kills = lastResortLogs = failureLogs = missing = 0; otherLockUntil = 0; openError = 0;
}
static BOOL quiesce(DWORD timeout) { return ServiceDeploy_WaitForUpdateTargetQuiesced(&paths, paths.dllPath, timeout, L"[UPDATE]"); }
int main(void) {
    /* A free or missing file needs no termination. */
    reset(); assert(quiesce(60000) && opens == 1 && kills == 0 && !lastResortLogs);
    reset(); missing = 1; assert(quiesce(60000) && opens == 0 && kills == 0);
    /* A helper that outlived the service: terminated once, logged, then the file is free. */
    reset(); holders = 1; assert(quiesce(60000) && kills == 1 && lastResortLogs == 1 && ticks == 1000);
    /* A lock that termination does not release (scanner) is waited out, not killed again. */
    reset(); otherLockUntil = 4000; assert(quiesce(60000) && kills == 1 && lastResortLogs == 1 && ticks >= 4000);
    /* A lock that never clears fails the quiesce after one termination. */
    reset(); otherLockUntil = UINT32_MAX; assert(!quiesce(5000) && kills == 1 && failureLogs == 1 && lastError == ERROR_SHARING_VIOLATION);
    /* Any other error fails at once. */
    reset(); openError = ERROR_DISK_FULL; assert(!quiesce(5000) && kills == 0 && lastError == ERROR_DISK_FULL);

    /* Release: no termination while both files can be written. */
    reset(); ServiceDeploy_ReleaseRuntimeFiles(&paths, TRUE); assert(kills == 0 && opens == 2 && ticks == 1000);
    /* A locked DLL or EXE leads to one termination for the whole release. */
    reset(); holders = 1; ServiceDeploy_ReleaseRuntimeFiles(&paths, TRUE); assert(kills == 1 && lastResortLogs == 1);
    reset(); otherLockUntil = 3000; ServiceDeploy_ReleaseRuntimeFiles(&paths, TRUE); assert(kills == 1 && lastResortLogs == 1 && ticks >= 3000);
    reset(); holders = 1; ServiceDeploy_ReleaseRuntimeFiles(&paths, FALSE); assert(kills == 0 && ticks >= 11000);

    puts("PASS: update quiesce terminates runtime-file holders once, as a logged last resort, only while a file is locked");
    return 0;
}
'''


def main():
    source = (ROOT / 'meshservice/service_deployment.c').read_text(encoding='utf-8')
    body = '\n'.join(extract(source, name) for name in (
        'ServiceDeploy_TerminateRuntimeFileHolders',
        'ServiceDeploy_WaitForUpdateTargetQuiesced',
        'ServiceDeploy_ReleaseRuntimeFiles'))
    with tempfile.TemporaryDirectory(prefix='mesh-update-quiesce-') as folder:
        path = pathlib.Path(folder)
        (path / 'probe.c').write_text(PRELUDE + body + MAIN)
        flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter']
        sanitizers = [] if os.name == 'nt' else ['-fsanitize=address,undefined']
        subprocess.run([os.environ.get('CC', 'clang'), *flags, *sanitizers, str(path / 'probe.c'), '-o', str(path / 'probe')], check=True)
        subprocess.run([str(path / 'probe')], check=True, timeout=15)


if __name__ == '__main__':
    main()
