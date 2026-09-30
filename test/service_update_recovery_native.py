#!/usr/bin/env python3
"""Fault-inject the production update flow at its filesystem/SCM boundaries.

Requires Python 3 and a C compiler (CC or cc). Does not change services or files
outside a temporary build directory. An optional source path tests an old revision.
This exercises control flow, not Windows API integration or actual file copying.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'meshservice/service_deployment.c'
source = SOURCE.read_text()
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                lambda m: ' ' * len(m.group()), source, flags=re.S)
def extract(name):
    match = re.search(r'static BOOL ' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]

flow = extract('ServiceDeploy_ApplyUpdateFlow')
install = extract('ServiceDeploy_ApplyInstallFlow')

prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define SERVICE_AUTO_START 2
#define SERVICE_LIFECYCLE_STATE_HEALTHY 0
#define SERVICE_UPDATE_STAGE_DIR_NAME L"stage"
#define SERVICE_UPDATE_BACKUP_DIR_NAME L"backup"
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_WRITE 1
#define OPEN_EXISTING 1
#define FILE_ATTRIBUTE_NORMAL 1
#define ERROR_SHARING_VIOLATION 32
#define ERROR_LOCK_VIOLATION 33
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#define ZeroMemory(p,n) memset(p,0,n)
#define UNREFERENCED_PARAMETER(p) ((void)p)
typedef struct { wchar_t installDir[MAX_PATH], logsDir[MAX_PATH], exePath[MAX_PATH], dllPath[MAX_PATH], confPath[MAX_PATH], dbPath[MAX_PATH]; } ServiceInstallPaths;
typedef struct { int unused; } ServiceIdentitySnapshot;
typedef struct {
    BOOL backupsReady, liveDbExists, stagedMshReady, postUpdateIdentityReady, rollbackIdentityReady;
    wchar_t stagedMshPath[MAX_PATH], stagedConfPath[MAX_PATH], backupDir[MAX_PATH];
    ServiceIdentitySnapshot postUpdateIdentity, rollbackIdentity;
    BOOL pendingUpdateMarked;
} ServiceUpdateTransaction;
typedef struct { BOOL configAvailable, sourceEmbeddedConfigPresent, sourceSidecarConfigPresent; } ServicePackagePreflight;
typedef struct { wchar_t WmiFilter[MAX_PATH], WmiConsumer[MAX_PATH]; } ServicePersistenceState;
typedef struct { int enabled; } persistence_toggle;
typedef struct { int runKey; persistence_toggle autorunTask, restartTask, watchdog; } mesh_persistence_profile_t;
typedef struct {
    int stateKind, pendingUpdate, updateStageArtifactsPresent, updateBackupArtifactsPresent, firewallHealthy, persistenceHealthy;
    int serviceExists, serviceTypeValid, serviceImageValid, serviceGroupValid, serviceAccountValid, serviceDllValid, dllExists, serviceMainValid, serviceUnloadValid;
} ServiceLifecycleDiscovery;
static int failAt, running, liveVersion, startType, starts, mixedStarts, stops, prepared, rolledBack, convergence, discarded, recoveryRestored, incumbentRepairs;
static int installed = 1, supportedHost = 1, packageHasConfig = 1;
static mesh_persistence_profile_t profile;
static void log_event(const wchar_t* fmt, ...) { (void)fmt; }
static BOOL mock_paths(ServiceInstallPaths* p) {
    memset(p, 0, sizeof(*p)); wcscpy(p->exePath,L"agent.exe"); wcscpy(p->dllPath,L"agent.dll"); return TRUE;
}
static BOOL mock_preflight(BOOL requireConfig, ServicePackagePreflight* p) {
    memset(p,0,sizeof(*p)); p->configAvailable = packageHasConfig;
    return failAt != 5 && (!requireConfig || packageHasConfig);
}
static BOOL discover(ServiceLifecycleDiscovery* p) {
    memset(p,0,sizeof(*p)); p->serviceExists = installed; p->serviceTypeValid = supportedHost;
    p->serviceImageValid = p->serviceGroupValid = p->serviceAccountValid = p->serviceDllValid = 1;
    p->dllExists = p->serviceMainValid = p->serviceUnloadValid = 1;
    return TRUE;
}
static BOOL prepare(ServiceUpdateTransaction* tx) { ++prepared; tx->liveDbExists = TRUE; return failAt != 6; }
static BOOL backup(ServiceUpdateTransaction* tx) {
    assert(!running); if (failAt == 1) return FALSE;
    tx->backupsReady = tx->rollbackIdentityReady = tx->postUpdateIdentityReady = TRUE; return TRUE;
}
static BOOL commit(void) { assert(!running); liveVersion = failAt == 2 || failAt == 3 ? 2 : 3; return liveVersion == 3; }
static BOOL rollback(void) { assert(!running); ++rolledBack; if (failAt == 3) return FALSE; liveVersion = 1; return TRUE; }
static BOOL stop_service(void) { ++stops; running = 0; return TRUE; }
static BOOL start_service(BOOL allowRepair) {
    ++starts; if (liveVersion == 2) ++mixedStarts;
    assert(startType == SERVICE_AUTO_START);
    if (liveVersion == 1 && allowRepair) ++incumbentRepairs;
    if (failAt == 7 && liveVersion == 3) return FALSE;
    running = 1; return TRUE;
}
static BOOL query_start(DWORD* out) { *out = startType; return failAt != 4; }
static BOOL set_start(DWORD value) { startType = (int)value; return TRUE; }
static BOOL wait_operational(ServiceLifecycleDiscovery* state) {
    ++convergence; memset(state,0,sizeof(*state)); return running && liveVersion != 2;
}
static BOOL discard(ServiceUpdateTransaction* tx) { ++discarded; tx->backupsReady = FALSE; return TRUE; }
#define ServiceDeploy_LogInstallEvent log_event
#define MeshConfig_GetPersistence() (&profile)
#define ServiceDeploy_GetInstallPaths(p) mock_paths(p)
#define ServiceDeploy_CleanupConflictingServiceAliases(...) 0
#define ServiceDeploy_IsAlreadyInstalled() installed
#define ServiceDeploy_DiscoverCurrentState(p) discover(p)
#define ServiceDeploy_ServiceIsRunning(...) running
#define ServiceDeploy_PreflightPackageSource(a,b,p,d,e) mock_preflight(b,p)
#define ServiceDeploy_PrepareUpdateTransaction(a,b,c,d,tx) prepare(tx)
#define ServiceDeploy_BackupUpdateTransaction(p,tx) backup(tx)
#define ServiceDeploy_CommitUpdateTransaction(...) commit()
#define ServiceDeploy_RollbackUpdateTransaction(...) rollback()
#define ServiceDeploy_StopServiceAndWait(...) stop_service()
#define ServiceDeploy_StartServiceHostServiceAndWait(a,b,c,repair) start_service(repair)
#define ServiceDeploy_QueryServiceStartType(a,out) query_start(out)
#define ServiceDeploy_SetServiceStartType(a,value) set_start(value)
#define ServiceDeploy_LoadPersistenceState(...) FALSE
#define ServiceDeploy_WaitForPrimaryLifecycleOperational(t,s) wait_operational(s)
#define ServiceDeploy_WaitForPrimaryLifecycleHealthy(t,s) wait_operational(s)
#define ServiceDeploy_LifecycleStateToString(...) L"state"
#define ServiceDeploy_WaitForExpectedIdentity(...) (failAt != 8 || liveVersion == 1)
#define ServiceDeploy_DiscardUpdateBackup(tx) discard(tx)
#define ServiceDeploy_ConfigureServiceRecoveryIfEnabled(...) (++recoveryRestored)
#define Security_InstallFiles(...) (liveVersion = 3, TRUE)
#define GetFileAttributesW(...) INVALID_FILE_ATTRIBUTES
#define GetLastError() 1
#define GetTickCount() 1
#define CreateFileW(...) INVALID_HANDLE_VALUE
'''

# Non-mutating collaborators succeed. The transaction, SCM, identity and startup
# boundaries above have explicit stateful mocks; production orchestration is intact.
mocked = set(re.findall(r'^#define (\w+)', prelude, re.M))
calls = set(re.findall(r'\b((?:ServiceDeploy_|Security_|MeshInstaller_|FaultRecovery_|MeshService_|ServiceUtil_|ServiceHost_)\w+)\s*\(', flow + install))
generic = '\n'.join(f'#define {name}(...) 1' for name in sorted(calls - mocked - {'ServiceDeploy_ApplyUpdateFlow', 'ServiceDeploy_ApplyInstallFlow'}))
generic += '\n#define Sleep(...) ((void)0)\n#define CloseHandle(...) 1\n#define StringCchCopyW(a,b,c) wcscpy(a,c)\n#define StringCchCatW(a,b,c) wcscat(a,c)\n'

cases = r'''
static void run_case(int failure, int wasRunning, int originalStart, int expectedStarts) {
    failAt = failure; running = wasRunning; liveVersion = 1; startType = originalStart;
    starts = mixedStarts = stops = prepared = rolledBack = convergence = discarded = recoveryRestored = incumbentRepairs = 0;
    BOOL result = ServiceDeploy_ApplyUpdateFlow(L"new.exe",L"new.dll",TRUE,TRUE);
    if (starts != expectedStarts || mixedStarts != 0) {
        fprintf(stderr,"failure=%d priorRunning=%d: starts=%d expected=%d mixedStarts=%d\n",
            failure,wasRunning,starts,expectedStarts,mixedStarts);
        assert(0);
    }
    assert(result == (failure == 0));
    assert(incumbentRepairs == 0); /* Recovery must not rewrite retained payloads. */
    if (!failure) { assert(running && liveVersion == 3); return; }
    assert(startType == originalStart);
    if (failure == 3) { assert(!running && liveVersion == 2 && !discarded); return; }
    assert(running == wasRunning && liveVersion == 1);
    if (!wasRunning) assert(convergence == 0);
    if (failure == 4 || failure == 5 || failure == 6) assert(stops == 0);
    else assert(recoveryRestored > 0);
    if (failure == 2 || failure == 7 || failure == 8) assert(rolledBack == 1 && discarded == 1);
}
static void install_case(int failure, int config, int exists, int supported, int expectedPrepared) {
    failAt = failure; packageHasConfig = config; installed = exists; supportedHost = supported;
    running = exists; liveVersion = 1; startType = SERVICE_AUTO_START;
    starts = mixedStarts = stops = prepared = rolledBack = convergence = discarded = recoveryRestored = incumbentRepairs = 0;
    BOOL result = ServiceDeploy_ApplyInstallFlow(L"new.exe",L"new.dll",TRUE);
    assert(prepared == expectedPrepared && mixedStarts == 0);
    assert(result == (failure == 0 && config));
    if (!config || failure == 6) assert(stops == 0 && running == exists && liveVersion == 1);
    if (failure == 1 || failure == 2) assert(running == exists && liveVersion == 1);
    if (result) assert(running && liveVersion == 3);
}
int main(void) {
    run_case(2,1,3,1); /* Partial commit is never started; rollback starts retained bytes. */
    run_case(2,0,4,0); /* A previously stopped/disabled incumbent remains stopped. */
    run_case(1,1,3,1); /* Incomplete backup left live bytes unchanged: recover running state. */
    run_case(1,0,4,0);
    run_case(1,1,4,1); /* Restore disabled configuration after restarting, not before. */
    run_case(3,1,3,0); /* Failed rollback preserves backup and does not start mixed files. */
    run_case(4,1,3,0); /* Cannot snapshot start type: fail before stopping. */
    run_case(5,1,3,0); /* Package preflight failure keeps incumbent running. */
    run_case(6,1,3,0); /* Staging failure keeps incumbent running. */
    run_case(7,1,3,2); /* New startup failure, then old startup. */
    run_case(8,1,3,2); /* New identity failure, then old startup. */
    run_case(0,0,4,1); /* Successful update still starts and repairs auto-start. */
    packageHasConfig = 0;
    run_case(0,1,3,1); /* Binary-only update still uses installed provisioning. */
    install_case(6,1,1,1,1); /* Incumbent install stages before stopping. */
    install_case(1,1,1,1,1); /* Backup failure recovers incumbent install. */
    install_case(2,1,1,1,1); /* Partial install rolls back through update transaction. */
    install_case(0,0,1,1,0); /* Install still requires package provisioning. */
    install_case(0,1,1,1,1); /* Supported install uses transaction on success too. */
    install_case(0,1,1,0,0); /* Legacy migration keeps its existing path. */
    install_case(0,1,0,0,0); /* Fresh install keeps its existing path. */
    puts("Service update/install native recovery: 20 cases passed");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='meshagent-update-recovery-') as directory:
    c_path = Path(directory) / 'recovery.c'
    executable = Path(directory) / ('recovery.exe' if os.name == 'nt' else 'recovery')
    c_path.write_text(prelude + generic + '\n' + flow + '\n' + install + '\n' + cases)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wno-unused-value', str(c_path), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
