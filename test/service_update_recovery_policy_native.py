#!/usr/bin/env python3
"""Fault-inject delegated recovery and transaction-directory trust checks.

Compiles the production functions against deterministic API boundaries. Does
not query or change installed services, permissions, or transaction files.
An optional source argument verifies the same cases against an older revision.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'meshservice/service_deployment.c'
source = source_path.read_text(encoding='utf-8-sig')
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
                lambda m: ' ' * len(m.group()), source, flags=re.S)


def extract(name):
    match = re.search(r'static BOOL ' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]


fixture = r'''
#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL;
typedef uint32_t DWORD;
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_GEN_FAILURE 31
#define ERROR_ACCESS_DENIED 5
#define ERROR_TIMEOUT 1460
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define FILE_ATTRIBUTE_DIRECTORY 16
#define FILE_ATTRIBUTE_REPARSE_POINT 1024
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif
typedef struct { wchar_t installDir[16]; } ServiceInstallPaths;
typedef struct { wchar_t stateDir[16], stageDir[16], backupDir[16]; } ServiceUpdateTransaction;
static unsigned recoveryCalls, queryCalls, startCalls, sleeps, daclCalls;
static unsigned recoveryFailures, queryFailures, startFailures;
static BOOL serviceExists, safeDacl;
static DWORD lastError, queryFailureError;
static DWORD attributes[4], attributeErrors[4];
static const wchar_t* names[] = {L"install", L"state", L"stage", L"backup"};
static DWORD GetLastError(void) { return lastError; }
static void SetLastError(DWORD value) { lastError = value; }
static void Sleep(DWORD ms) { assert(ms == 10000); ++sleeps; lastError = 999; }
#define ServiceDeploy_LogInstallEvent(...) ((void)(lastError = 999))
static void ServiceDeploy_ResolveRuntimeServiceBranding(wchar_t* name, size_t count,
    void* a, int b, void* c, int d) {
    (void)a; (void)b; (void)c; (void)d;
    assert(count > 4); wcscpy(name, L"test");
}
static BOOL ServiceDeploy_RecoverInterruptedTransaction(void) {
    ++recoveryCalls;
    if (recoveryCalls <= recoveryFailures) { lastError = ERROR_ACCESS_DENIED; return FALSE; }
    return TRUE;
}
static BOOL ServiceBinding_QueryExists(const wchar_t* name, BOOL* exists) {
    assert(wcscmp(name, L"test") == 0); ++queryCalls;
    if (queryCalls <= queryFailures) { lastError = queryFailureError; return FALSE; }
    *exists = serviceExists; return TRUE;
}
static BOOL ServiceDeploy_StartServiceHostServiceAndWait(const wchar_t* name, DWORD timeout) {
    assert(wcscmp(name, L"test") == 0 && timeout == 30000); ++startCalls;
    if (startCalls <= startFailures) { lastError = ERROR_TIMEOUT; return FALSE; }
    return TRUE;
}
static DWORD GetFileAttributesW(const wchar_t* path) {
    for (size_t i = 0; i < _countof(names); ++i) {
        if (wcscmp(path, names[i]) == 0) { lastError = attributeErrors[i]; return attributes[i]; }
    }
    assert(0); return INVALID_FILE_ATTRIBUTES;
}
static BOOL ServiceDeploy_ValidateTransactionStateDacl(const wchar_t* path) {
    assert(wcscmp(path, L"state") == 0); ++daclCalls; return safeDacl;
}
static void reset(void) {
    recoveryCalls = queryCalls = startCalls = sleeps = daclCalls = 0;
    recoveryFailures = queryFailures = startFailures = 0;
    serviceExists = safeDacl = TRUE; SetLastError(0); queryFailureError = ERROR_ACCESS_DENIED;
    for (size_t i = 0; i < 4; ++i) { attributes[i] = FILE_ATTRIBUTE_DIRECTORY; attributeErrors[i] = 0; }
}
'''

cases = r'''
int main(void) {
    ServiceInstallPaths paths = {L"install"};
    ServiceUpdateTransaction tx = {L"state", L"stage", L"backup"};
    reset(); assert(ServiceDeploy_ValidateTransactionStateDacl(L"state"));
    reset(); assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 1 && startCalls == 1 && sleeps == 0);
    reset(); recoveryFailures = 2; assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 3 && queryCalls == 1 && startCalls == 1 && sleeps == 2);
    reset(); recoveryFailures = 3; assert(!ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 3 && queryCalls == 0 && startCalls == 0 && sleeps == 2);
    assert(GetLastError() == ERROR_ACCESS_DENIED);
    reset(); startFailures = 2; assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 3 && startCalls == 3 && sleeps == 2);
    reset(); startFailures = 3; assert(!ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 3 && startCalls == 3 && sleeps == 2);
    assert(GetLastError() == ERROR_TIMEOUT);
    reset(); queryFailures = 3; assert(!ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 3 && startCalls == 0 && sleeps == 2);
    assert(GetLastError() == ERROR_ACCESS_DENIED);
    reset(); queryFailures = 1; assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 2 && startCalls == 1 && sleeps == 1);
    reset(); queryFailures = 3; queryFailureError = 0;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(GetLastError() == ERROR_GEN_FAILURE);
    reset(); serviceExists = FALSE; assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 1 && startCalls == 0 && sleeps == 0);
    reset(); recoveryFailures = 1; startFailures = 1; assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 2 && queryCalls == 2 && startCalls == 2 && sleeps == 2);

    reset(); assert(ServiceDeploy_TransactionPathsSafe(&paths, &tx)); assert(daclCalls == 1);
    reset(); safeDacl = FALSE; assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx)); assert(daclCalls == 1);
    for (size_t i = 0; i < 4; ++i) {
        reset(); attributes[i] |= FILE_ATTRIBUTE_REPARSE_POINT;
        assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx));
        reset(); attributes[i] = 0; assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx));
        reset(); attributes[i] = INVALID_FILE_ATTRIBUTES; attributeErrors[i] = ERROR_ACCESS_DENIED;
        assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx));
        reset(); attributes[i] = INVALID_FILE_ATTRIBUTES; attributeErrors[i] = ERROR_FILE_NOT_FOUND;
        assert(ServiceDeploy_TransactionPathsSafe(&paths, &tx));
        reset(); attributes[i] = INVALID_FILE_ATTRIBUTES; attributeErrors[i] = ERROR_PATH_NOT_FOUND;
        assert(ServiceDeploy_TransactionPathsSafe(&paths, &tx));
    }
    puts("Delegated recovery: 10 failure/retry cases passed; transaction paths: 22 trust-boundary cases passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='meshagent-recovery-policy-') as directory:
    work = Path(directory)
    c_path = work / 'policy.c'
    binary = work / ('policy.exe' if os.name == 'nt' else 'policy')
    c_path.write_text(fixture + '\n' + extract('ServiceDeploy_RunDelegatedUpdateRecovery') +
                      '\n' + extract('ServiceDeploy_TransactionPathsSafe') + '\n' + cases, encoding='utf-8')
    compiler = os.environ.get('CC', 'clang' if os.name == 'nt' else 'cc')
    command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror']
    if os.name != 'nt': command += ['-fsanitize=address,undefined']
    subprocess.run(command + [str(c_path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
