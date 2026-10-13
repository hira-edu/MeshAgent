#!/usr/bin/env python3
"""Fault-inject delegated recovery, the update startup gate and
transaction-directory trust checks.

Compiles the production functions against deterministic API boundaries. Does
not query or change installed services, permissions, or transaction files.
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


def extract(name, kind='static BOOL'):
    match = re.search(kind + ' ' + name + r'\s*\([^;{]+\)\s*\{', masked)
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
typedef void* HANDLE;
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_GEN_FAILURE 31
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INVALID_DATA 13
#define ERROR_TIMEOUT 1460
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define FILE_ATTRIBUTE_DIRECTORY 16
#define FILE_ATTRIBUTE_REPARSE_POINT 1024
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define SERVICE_JOURNAL_PREPARED 1
#define SERVICE_JOURNAL_BACKED_UP 2
#define SERVICE_JOURNAL_COMMITTED 3
#define SERVICE_JOURNAL_ROLLED_BACK 4
#define SERVICE_JOURNAL_ACTIVATING 5
#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif
typedef enum { SERVICE_UPDATE_STARTUP_PROCEED = 0, SERVICE_UPDATE_STARTUP_QUIESCE_FOR_ACTIVE_LIFECYCLE,
    SERVICE_UPDATE_STARTUP_DELEGATE_RECOVERY } ServiceUpdateStartupDisposition;
typedef struct { wchar_t installDir[16]; } ServiceInstallPaths;
typedef struct { wchar_t stateDir[16], stageDir[16], backupDir[16], journalPath[16]; } ServiceUpdateTransaction;
typedef struct { DWORD phase; void* binding; } ServiceJournalRecord;
enum { JOURNAL_ABSENT, JOURNAL_UNREADABLE, JOURNAL_PRESENT };
static unsigned recoveryCalls, queryCalls, startCalls, sleeps, daclCalls, rearms, loads, frees, authorizations, closes;
static unsigned recoveryFailures, queryFailures, startFailures;
static BOOL serviceExists, safeDacl, lifecycleActive, startAuthorized, lifecycleQueryFails, authorizedStart;
static DWORD lastError, queryFailureError, journalPhase;
static int journalState, originalBinding;
static DWORD attributes[5], attributeErrors[5];
static const wchar_t* names[] = {L"install", L"state", L"stage", L"backup", L"journal"};
static DWORD GetLastError(void) { return lastError; }
static void SetLastError(DWORD value) { lastError = value; }
static void Sleep(DWORD ms) { assert(ms == 10000); ++sleeps; lastError = 999; }
#define ServiceDeploy_LogInstallEvent(...) ((void)(lastError = 999))
#define MeshConfig_GetPersistence() NULL
static void ServiceDeploy_ResolveRuntimeServiceBranding(wchar_t* name, size_t count,
    void* a, int b, void* c, int d) {
    (void)a; (void)b; (void)c; (void)d;
    assert(count > 4); wcscpy(name, L"test");
}
static BOOL ServiceDeploy_GetInstallPaths(ServiceInstallPaths* paths) { wcscpy(paths->installDir, L"install"); return TRUE; }
static BOOL ServiceDeploy_InitializeUpdateTransactionPaths(const ServiceInstallPaths* paths, ServiceUpdateTransaction* tx) {
    (void)paths; wcscpy(tx->stateDir, L"state"); wcscpy(tx->stageDir, L"stage");
    wcscpy(tx->backupDir, L"backup"); wcscpy(tx->journalPath, L"journal"); return TRUE;
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
    authorizedStart = authorizations > closes;
    if (startCalls <= startFailures) { lastError = ERROR_TIMEOUT; return FALSE; }
    return TRUE;
}
static BOOL ServiceDeploy_ConfigureServiceRecoveryIfEnabled(const void* persistence, const wchar_t* name) {
    (void)persistence; assert(wcscmp(name, L"test") == 0); ++rearms; return TRUE;
}
static BOOL ServiceDeploy_CreateRecoveryStartupAuthorization(HANDLE* out) { ++authorizations; *out = (HANDLE)1; return TRUE; }
static BOOL CloseHandle(HANDLE handle) { assert(handle == (HANDLE)1); ++closes; return TRUE; }
static DWORD GetFileAttributesW(const wchar_t* path) {
    for (size_t i = 0; i < _countof(names); ++i) {
        if (wcscmp(path, names[i]) == 0) { lastError = attributeErrors[i]; return attributes[i]; }
    }
    assert(0); return INVALID_FILE_ATTRIBUTES;
}
static BOOL ServiceDeploy_ValidateTransactionStateDacl(const wchar_t* path) {
    assert(wcscmp(path, L"state") == 0); ++daclCalls;
    if (!safeDacl) { lastError = ERROR_ACCESS_DENIED; }
    return safeDacl;
}
static ServiceJournalRecord loadedRecord;
static BOOL ServiceJournal_Load(const wchar_t* path, const wchar_t* name, ServiceJournalRecord** record) {
    assert(wcscmp(path, L"journal") == 0 && wcscmp(name, L"test") == 0); ++loads;
    *record = NULL;
    if (journalState == JOURNAL_UNREADABLE) { lastError = ERROR_INVALID_DATA; return FALSE; }
    if (journalState == JOURNAL_PRESENT) {
        loadedRecord.phase = journalPhase; loadedRecord.binding = originalBinding ? (void*)&loadedRecord : NULL;
        *record = &loadedRecord;
    }
    return TRUE;
}
static void ServiceJournal_Free(ServiceJournalRecord* record) { assert(record == &loadedRecord); ++frees; }
static BOOL ServiceDeploy_QueryLifecycleOperationActive(BOOL* active) {
    if (lifecycleQueryFails) { lastError = ERROR_ACCESS_DENIED; return FALSE; }
    *active = lifecycleActive; return TRUE;
}
static BOOL ServiceDeploy_QueryRecoveryStartupAuthorized(BOOL* authorized) { *authorized = startAuthorized; return TRUE; }
static BOOL ServiceDeploy_CheckTransactionPaths(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx, BOOL requireTrustedState);
static BOOL ServiceDeploy_JournalRecordAllowsRetainedStart(const ServiceJournalRecord* record);
static BOOL ServiceDeploy_RetainedTransactionAllowsStart(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx,
    const wchar_t* serviceName, DWORD* phaseOut);
static BOOL ServiceDeploy_TransactionPathsSafe(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx);
BOOL ServiceDeploy_GetUpdateStartupDisposition(ServiceUpdateStartupDisposition* dispositionOut, BOOL* retainedStartAllowedOut);
static void reset(void) {
    recoveryCalls = queryCalls = startCalls = sleeps = daclCalls = rearms = loads = frees = authorizations = closes = 0;
    recoveryFailures = queryFailures = startFailures = 0;
    serviceExists = safeDacl = TRUE; SetLastError(0); queryFailureError = ERROR_ACCESS_DENIED;
    lifecycleActive = startAuthorized = lifecycleQueryFails = authorizedStart = FALSE;
    journalState = JOURNAL_PRESENT; journalPhase = SERVICE_JOURNAL_BACKED_UP; originalBinding = 1;
    for (size_t i = 0; i < 4; ++i) { attributes[i] = FILE_ATTRIBUTE_DIRECTORY; attributeErrors[i] = 0; }
    attributes[4] = 0; attributeErrors[4] = 0;
}
static ServiceUpdateStartupDisposition disposition;
static BOOL retainedStart;
static BOOL gate(void) {
    disposition = (ServiceUpdateStartupDisposition)99; retainedStart = 99;
    return ServiceDeploy_GetUpdateStartupDisposition(&disposition, &retainedStart);
}
'''

cases = r'''
int main(void) {
    ServiceInstallPaths paths = {L"install"};
    ServiceUpdateTransaction tx = {L"state", L"stage", L"backup", L"journal"};
    reset(); assert(ServiceDeploy_ValidateTransactionStateDacl(L"state"));
    reset(); assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 1 && startCalls == 1 && sleeps == 0 && !rearms);
    reset(); recoveryFailures = 2; assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 3 && queryCalls == 1 && startCalls == 1 && sleeps == 2);
    reset(); startFailures = 2; assert(ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 3 && startCalls == 3 && sleeps == 2);
    reset(); startFailures = 3; assert(!ServiceDeploy_RunDelegatedUpdateRecovery());
    assert(recoveryCalls == 1 && queryCalls == 3 && startCalls == 3 && sleeps == 2 && !loads);
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

    /* Exhausted recovery keeps mid-commit phases, an unreadable journal and an
     * absent service stopped; coherent phases start under the authorization. */
    DWORD stopped[] = {SERVICE_JOURNAL_BACKED_UP, SERVICE_JOURNAL_ACTIVATING};
    for (size_t i = 0; i < _countof(stopped); ++i) {
        reset(); recoveryFailures = 3; journalPhase = stopped[i]; assert(!ServiceDeploy_RunDelegatedUpdateRecovery());
        assert(recoveryCalls == 3 && queryCalls == 1 && startCalls == 0 && !rearms && loads == 1 && frees == 1);
        assert(GetLastError() == ERROR_ACCESS_DENIED);
    }
    reset(); recoveryFailures = 3; journalPhase = SERVICE_JOURNAL_PREPARED; originalBinding = 0;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(startCalls == 0 && !rearms);
    reset(); recoveryFailures = 3; journalState = JOURNAL_UNREADABLE;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(startCalls == 0 && !rearms);
    reset(); recoveryFailures = 3; attributes[1] |= FILE_ATTRIBUTE_REPARSE_POINT;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(startCalls == 0 && !loads);
    reset(); recoveryFailures = 3; journalPhase = SERVICE_JOURNAL_COMMITTED; serviceExists = FALSE;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(startCalls == 0 && !loads);
    DWORD started[] = {SERVICE_JOURNAL_PREPARED, SERVICE_JOURNAL_COMMITTED, SERVICE_JOURNAL_ROLLED_BACK};
    for (size_t i = 0; i < _countof(started); ++i) {
        reset(); recoveryFailures = 3; journalPhase = started[i]; assert(!ServiceDeploy_RunDelegatedUpdateRecovery());
        assert(recoveryCalls == 3 && startCalls == 1 && rearms == 1 && authorizedStart);
        assert(authorizations == 1 && closes == 1 && frees == 1 && GetLastError() == ERROR_ACCESS_DENIED);
    }
    /* The degraded start ignores state DACL drift but not structural damage. */
    reset(); recoveryFailures = 3; journalPhase = SERVICE_JOURNAL_COMMITTED; safeDacl = FALSE;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(startCalls == 1 && !daclCalls);
    reset(); recoveryFailures = 3; journalPhase = SERVICE_JOURNAL_COMMITTED; startFailures = 1;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(startCalls == 1 && closes == 1);
    reset(); recoveryFailures = 3; journalState = JOURNAL_ABSENT;
    assert(!ServiceDeploy_RunDelegatedUpdateRecovery()); assert(startCalls == 1 && authorizedStart);

    /* Startup gate. */
    reset(); attributes[4] = INVALID_FILE_ATTRIBUTES; attributeErrors[4] = ERROR_FILE_NOT_FOUND; attributes[1] = 0;
    assert(gate() && disposition == SERVICE_UPDATE_STARTUP_PROCEED && !retainedStart && !loads);
    reset(); journalState = JOURNAL_UNREADABLE; assert(!gate() && GetLastError() == ERROR_INVALID_DATA);
    reset(); journalState = JOURNAL_ABSENT; assert(gate() && disposition == SERVICE_UPDATE_STARTUP_PROCEED);
    reset(); lifecycleActive = TRUE; journalPhase = SERVICE_JOURNAL_ROLLED_BACK;
    assert(gate() && disposition == SERVICE_UPDATE_STARTUP_PROCEED && frees == 1);
    for (DWORD phase = SERVICE_JOURNAL_PREPARED; phase <= SERVICE_JOURNAL_ACTIVATING; ++phase) {
        if (phase == SERVICE_JOURNAL_ROLLED_BACK) { continue; }
        BOOL coherent = phase == SERVICE_JOURNAL_PREPARED || phase == SERVICE_JOURNAL_COMMITTED;
        reset(); journalPhase = phase;
        assert(gate() && disposition == SERVICE_UPDATE_STARTUP_DELEGATE_RECOVERY && retainedStart == coherent && frees == 1);
        reset(); journalPhase = phase; lifecycleActive = TRUE;
        assert(gate() && retainedStart == coherent);
        assert(disposition == (phase == SERVICE_JOURNAL_PREPARED || phase == SERVICE_JOURNAL_BACKED_UP ?
            SERVICE_UPDATE_STARTUP_QUIESCE_FOR_ACTIVE_LIFECYCLE : SERVICE_UPDATE_STARTUP_PROCEED));
        reset(); journalPhase = phase; lifecycleActive = startAuthorized = TRUE;
        assert(gate() && disposition == SERVICE_UPDATE_STARTUP_PROCEED);
        reset(); journalPhase = phase; lifecycleQueryFails = TRUE; assert(!gate() && frees == 1);
        /* Untrusted state: never delegate; start only a coherent phase, and
         * still quiesce under an active lifecycle operation. */
        reset(); journalPhase = phase; safeDacl = FALSE;
        assert(gate() == coherent && disposition == SERVICE_UPDATE_STARTUP_PROCEED && retainedStart == coherent);
        if (!coherent) { assert(GetLastError() == ERROR_ACCESS_DENIED && frees == 1); }
        reset(); journalPhase = phase; safeDacl = FALSE; lifecycleActive = TRUE;
        assert(gate() == coherent);
        if (coherent) { assert(disposition == (phase == SERVICE_JOURNAL_PREPARED ?
            SERVICE_UPDATE_STARTUP_QUIESCE_FOR_ACTIVE_LIFECYCLE : SERVICE_UPDATE_STARTUP_PROCEED)); }
    }
    reset(); journalPhase = SERVICE_JOURNAL_PREPARED; originalBinding = 0;
    assert(gate() && disposition == SERVICE_UPDATE_STARTUP_DELEGATE_RECOVERY && !retainedStart);
    reset(); journalPhase = SERVICE_JOURNAL_ROLLED_BACK; safeDacl = FALSE;
    assert(gate() && disposition == SERVICE_UPDATE_STARTUP_PROCEED);
    reset(); journalPhase = SERVICE_JOURNAL_COMMITTED; safeDacl = FALSE; journalState = JOURNAL_UNREADABLE; assert(!gate());
    reset(); journalPhase = SERVICE_JOURNAL_COMMITTED; attributes[3] |= FILE_ATTRIBUTE_REPARSE_POINT; assert(!gate() && !loads);

    reset(); assert(ServiceDeploy_TransactionPathsSafe(&paths, &tx)); assert(daclCalls == 1);
    reset(); safeDacl = FALSE; assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx)); assert(daclCalls == 1);
    reset(); safeDacl = FALSE; assert(ServiceDeploy_CheckTransactionPaths(&paths, &tx, FALSE)); assert(daclCalls == 0);
    for (size_t i = 0; i < 4; ++i) {
        reset(); attributes[i] |= FILE_ATTRIBUTE_REPARSE_POINT;
        assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx) && !ServiceDeploy_CheckTransactionPaths(&paths, &tx, FALSE));
        reset(); attributes[i] = 0; assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx));
        reset(); attributes[i] = INVALID_FILE_ATTRIBUTES; attributeErrors[i] = ERROR_ACCESS_DENIED;
        assert(!ServiceDeploy_TransactionPathsSafe(&paths, &tx));
        reset(); attributes[i] = INVALID_FILE_ATTRIBUTES; attributeErrors[i] = ERROR_FILE_NOT_FOUND;
        assert(ServiceDeploy_TransactionPathsSafe(&paths, &tx));
        reset(); attributes[i] = INVALID_FILE_ATTRIBUTES; attributeErrors[i] = ERROR_PATH_NOT_FOUND;
        assert(ServiceDeploy_TransactionPathsSafe(&paths, &tx));
    }
    puts("Delegated recovery: retry and retained-phase start cases passed; startup gate: phase, lifecycle and trust cases passed; "
        "transaction paths: trust-boundary cases passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='meshagent-recovery-policy-') as directory:
    work = Path(directory)
    c_path = work / 'policy.c'
    binary = work / ('policy.exe' if os.name == 'nt' else 'policy')
    c_path.write_text(fixture + '\n' + '\n'.join(extract(name) for name in (
        'ServiceDeploy_CheckTransactionPaths', 'ServiceDeploy_TransactionPathsSafe',
        'ServiceDeploy_JournalRecordAllowsRetainedStart', 'ServiceDeploy_RetainedTransactionAllowsStart')) +
        '\n' + extract('ServiceDeploy_GetUpdateStartupDisposition', 'BOOL') +
        '\n' + extract('ServiceDeploy_StartWithRetainedTransaction', 'static void') +
        '\n' + extract('ServiceDeploy_RunDelegatedUpdateRecovery') + '\n' + cases, encoding='utf-8')
    compiler = os.environ.get('CC', 'clang' if os.name == 'nt' else 'cc')
    command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror']
    if os.name != 'nt': command += ['-fsanitize=address,undefined']
    subprocess.run(command + [str(c_path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)

# Committed reconciliation: the agent starts before COM companion work, and
# companion or firewall failures are reported without retaining the journal.
reconcile_fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL;
typedef uint32_t DWORD;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif
typedef struct { wchar_t installDir[8], logsDir[8], dllPath[8], exePath[8], dbPath[8]; } ServiceInstallPaths;
typedef struct { wchar_t journalPath[8]; void* originalBinding; } ServiceUpdateTransaction;
typedef struct { BOOL firewallHealthy, persistenceHealthy, serviceDaclValid, serviceAliasClean, updateStageArtifactsPresent; } ServiceLifecycleDiscovery;
static int step, startedAt, companionsAt, firewallAt, activationAt, retired, deleted;
static BOOL bindingOk, startOk, restartersOk, rulesOk, activationOk, pendingUpdate, stageArtifacts, deleteOk;
#define ServiceDeploy_LogInstallEvent(...) ((void)0)
#define MeshConfig_GetPersistence() NULL
#define ServiceDeploy_VerifyServiceHostServiceBinding(n, d) bindingOk
#define ServiceDeploy_ConfigureServiceRecoveryIfEnabled(p, n) TRUE
#define MeshService_HardenServiceDaclByName(n) ((void)0)
#define ServiceUtil_ProtectServiceFromTermination(n) ((void)0)
#define Security_CreateInstallRootDirectory(p) ((void)0)
#define Security_CreateInstallationDirectory(p) ((void)0)
#define ServiceDeploy_CleanupConflictingServiceAliases(p, n) 0
#define MeshRuntimeHost_GetServiceHostPathW(p, n) (wcscpy(p, L"host"), TRUE)
#define ServiceDeploy_StartServiceHostServiceAndWait(n, t) (startedAt = ++step, startOk)
#define ServiceDeploy_ReconcileServiceRecovery() (companionsAt = ++step, restartersOk)
#define ServiceDeploy_RefreshFirewallRulesWithRetry(n, h, e) (firewallAt = ++step, rulesOk)
static BOOL ServiceDeploy_WaitForTransactionActivation(DWORD timeout, ServiceLifecycleDiscovery* state) {
    assert(timeout == 30000); activationAt = ++step;
    state->updateStageArtifactsPresent = stageArtifacts; return activationOk;
}
#define ServiceDeploy_IsPrimaryLifecycleOperational(s) ((s)->firewallHealthy && (s)->persistenceHealthy)
#define ServiceDeploy_DataStoreValueExists(p, k, b, l, o) pendingUpdate
#define ServiceDeploy_RetireIncumbentFiles(p, b) (++retired, TRUE)
#define ServiceDeploy_DeleteUpdateTransactionArtifacts(tx) (++deleted, deleteOk)
static void reset(void) {
    step = startedAt = companionsAt = firewallAt = activationAt = retired = deleted = 0;
    bindingOk = startOk = restartersOk = rulesOk = activationOk = deleteOk = TRUE; pendingUpdate = stageArtifacts = FALSE;
}
'''

reconcile_cases = r'''
int main(void) {
    ServiceInstallPaths paths = {L"root", L"logs", L"a.dll", L"a.exe", L"a.db"};
    ServiceUpdateTransaction tx = {L"journal", NULL};
    BOOL companions;
    reset(); companions = 99; assert(ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions));
    assert(companions == TRUE && startedAt == 1 && companionsAt == 2 && firewallAt == 3 && activationAt == 4 && retired == 1 && deleted == 1);
    /* Companion or firewall failures resolve the journal but are reported. */
    reset(); restartersOk = FALSE; assert(ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions));
    assert(!companions && startedAt == 1 && deleted == 1);
    reset(); rulesOk = FALSE; assert(ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions));
    assert(!companions && deleted == 1);
    reset(); restartersOk = FALSE; assert(ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, NULL));
    /* Binding, start, activation, staged files and the PendingUpdate marker retain it. */
    reset(); bindingOk = FALSE; assert(!ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions));
    assert(startedAt == 1 && !retired && !deleted);
    reset(); startOk = FALSE; assert(!ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions));
    assert(companionsAt && !activationAt && !deleted);
    reset(); activationOk = FALSE; assert(!ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions)); assert(!deleted);
    reset(); stageArtifacts = TRUE; assert(!ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions)); assert(!deleted);
    reset(); pendingUpdate = TRUE; assert(!ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions)); assert(!deleted);
    reset(); deleteOk = FALSE; assert(!ServiceDeploy_ReconcileCommittedTransaction(&paths, L"svc", &tx, &companions)); assert(deleted == 1);
    puts("Committed reconciliation: start-first ordering, reported companion failures and journal retention cases passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='meshagent-committed-reconcile-') as directory:
    work = Path(directory)
    c_path = work / 'reconcile.c'
    binary = work / ('reconcile.exe' if os.name == 'nt' else 'reconcile')
    c_path.write_text(reconcile_fixture + '\n' + extract('ServiceDeploy_ReconcileCommittedTransaction') +
                      '\n' + reconcile_cases, encoding='utf-8')
    compiler = os.environ.get('CC', 'clang' if os.name == 'nt' else 'cc')
    command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter']
    if os.name != 'nt': command += ['-fsanitize=address,undefined']
    subprocess.run(command + [str(c_path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
