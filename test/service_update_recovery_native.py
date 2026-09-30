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
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define SERVICE_AUTO_START 2
#define SERVICE_DISABLED 4
#define SERVICE_WIN32_SHARE_PROCESS 32
#define SERVICE_JOURNAL_PREPARED 1
#define SERVICE_JOURNAL_BACKED_UP 2
#define SERVICE_JOURNAL_COMMITTED 3
#define SERVICE_JOURNAL_ROLLED_BACK 4
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
#define _wcsicmp wcscmp
#define UNREFERENCED_PARAMETER(p) ((void)p)
typedef struct { wchar_t installDir[MAX_PATH], logsDir[MAX_PATH], exePath[MAX_PATH], dllPath[MAX_PATH], confPath[MAX_PATH], dbPath[MAX_PATH]; } ServiceInstallPaths;
typedef struct { int unused; } ServiceIdentitySnapshot;
typedef struct { DWORD dwStartType, dwServiceType; } binding_config;
typedef struct { binding_config* config; BOOL running, legacy; } ServiceBindingSnapshot;
typedef struct {
    BOOL backupsReady, liveDbExists, stagedMshReady, postUpdateIdentityReady, rollbackIdentityReady;
    wchar_t stagedMshPath[MAX_PATH], stagedConfPath[MAX_PATH], backupDir[MAX_PATH];
    ServiceIdentitySnapshot postUpdateIdentity, rollbackIdentity;
    BOOL pendingUpdateMarked;
    DWORD journalPhase;
    ServiceBindingSnapshot* originalBinding;
    void* originalFileDacl[5];
} ServiceUpdateTransaction;
typedef struct { BOOL configAvailable, sourceEmbeddedConfigPresent, sourceSidecarConfigPresent; } ServicePackagePreflight;
typedef struct { int enabled; } persistence_toggle;
typedef struct { int runKey; persistence_toggle autorunTask, restartTask, watchdog; } mesh_persistence_profile_t;
typedef struct {
    int stateKind, pendingUpdate, updateStageArtifactsPresent, updateBackupArtifactsPresent, firewallHealthy, persistenceHealthy;
    int serviceExists, serviceTypeValid, serviceImageValid, serviceGroupValid, serviceAccountValid, serviceDllValid, dllExists, serviceMainValid, serviceUnloadValid;
} ServiceLifecycleDiscovery;
static int failAt, running, liveVersion, bindingVersion, startType, starts, mixedStarts, stops, prepared, rolledBack, convergence, discarded, restoredBindings, deletedArtifacts;
static DWORD publishedPhase;
static int installed = 1, legacy = 0, packageHasConfig = 1, originalExists = 1;
static mesh_persistence_profile_t profile;
static binding_config savedConfig;
static ServiceBindingSnapshot savedBinding;
static void log_event(const wchar_t* fmt, ...) { (void)fmt; }
static BOOL mock_paths(ServiceInstallPaths* p) {
    memset(p, 0, sizeof(*p)); wcscpy(p->exePath,L"agent.exe"); wcscpy(p->dllPath,L"agent.dll"); wcscpy(p->dbPath,L"agent.db"); return TRUE;
}
static BOOL mock_preflight(BOOL requireConfig, ServicePackagePreflight* p) {
    memset(p,0,sizeof(*p)); p->configAvailable = packageHasConfig;
    return failAt != 5 && (!requireConfig || packageHasConfig);
}
static BOOL query_exists(BOOL* out) { *out = installed; return TRUE; }
static ServiceBindingSnapshot* capture(void) {
    if (failAt == 4) return NULL;
    savedConfig.dwStartType = startType; savedConfig.dwServiceType = 16; savedBinding.config = &savedConfig;
    savedBinding.running = running; savedBinding.legacy = legacy; return &savedBinding;
}
static BOOL restore_binding(void) {
    ++restoredBindings; if (failAt == 10) return FALSE;
    bindingVersion = 1; installed = 1;
    startType = savedBinding.running && savedConfig.dwStartType == SERVICE_DISABLED ? 3 : (int)savedConfig.dwStartType;
    return TRUE;
}
static BOOL sibling(const wchar_t* ext, wchar_t* out) { wcscpy(out, wcscmp(ext,L".db") == 0 ? L"agent.db" : L"agent.mshx"); return TRUE; }
static BOOL prepare(ServiceUpdateTransaction* tx) { ++prepared; tx->liveDbExists = originalExists; return failAt != 6; }
static BOOL backup(ServiceUpdateTransaction* tx) {
    assert(!running); if (failAt == 1 || failAt == 18) return FALSE;
    tx->backupsReady = TRUE; tx->rollbackIdentityReady = tx->postUpdateIdentityReady = originalExists; return TRUE;
}
static BOOL commit(void) { assert(!running); liveVersion = failAt == 2 || failAt == 3 || failAt == 10 ? 2 : 3; return liveVersion == 3; }
static BOOL registration(void) { bindingVersion = 3; installed = 1; return failAt != 11; }
static BOOL rollback(ServiceUpdateTransaction* tx) {
    assert(!running); ++rolledBack; if (failAt == 3) return FALSE;
    liveVersion = originalExists ? 1 : 0;
    if (tx->originalBinding) return restore_binding();
    bindingVersion = 0; installed = 0; return TRUE;
}
static BOOL stop_service(void) { ++stops; if (failAt == 9 || (failAt == 12 && liveVersion == 3)) return FALSE; running = 0; return TRUE; }
static BOOL start_service(void) {
    ++starts; if (liveVersion == 2 || liveVersion != bindingVersion) ++mixedStarts;
    assert(startType != SERVICE_DISABLED);
    if ((failAt == 7 && liveVersion == 3) || (failAt == 18 && liveVersion == 1)) return FALSE;
    running = 1; return TRUE;
}
static BOOL set_start(DWORD value) { startType = (int)value; return TRUE; }
static BOOL wait_operational(ServiceLifecycleDiscovery* state) {
    ++convergence; memset(state,0,sizeof(*state)); return running && liveVersion == 3 && bindingVersion == 3;
}
static BOOL write_phase(ServiceUpdateTransaction* tx, DWORD phase) {
    if ((failAt == 13 && phase == SERVICE_JOURNAL_PREPARED) ||
        (failAt == 14 && phase == SERVICE_JOURNAL_BACKED_UP) ||
        (failAt == 15 && phase == SERVICE_JOURNAL_COMMITTED)) return FALSE;
    tx->journalPhase = publishedPhase = phase; return TRUE;
}
static BOOL resolve(ServiceUpdateTransaction* tx, DWORD phase) {
    if (!write_phase(tx,phase)) return FALSE;
    ++discarded; return TRUE;
}
#define ServiceDeploy_LogInstallEvent log_event
#define MeshConfig_GetPersistence() (&profile)
#define ServiceDeploy_GetInstallPaths(p) mock_paths(p)
#define ServiceBinding_QueryExists(n,out) query_exists(out)
#define ServiceBinding_Capture(n,e,d) capture()
#define ServiceBinding_Free(...) ((void)0)
#define ServiceBinding_Restore(...) restore_binding()
#define ServiceDeploy_ServiceIsRunning(...) running
#define ServiceDeploy_PreflightPackageSource(a,b,p,d,e) mock_preflight(b,p)
#define ServiceDeploy_PrepareUpdateTransaction(a,b,c,d,tx) prepare(tx)
#define ServiceDeploy_BackupUpdateTransaction(p,tx) backup(tx)
#define ServiceDeploy_CommitUpdateTransaction(...) commit()
#define ServiceHost_RegisterServiceHostService(...) registration()
#define ServiceDeploy_RollbackUpdateTransaction(p,n,tx) rollback(tx)
#define ServiceDeploy_StopServiceAndWait(...) stop_service()
#define ServiceDeploy_StartServiceHostServiceAndWait(name,timeout) start_service()
#define ServiceDeploy_SetServiceStartType(a,value) set_start(value)
#define ServiceDeploy_WaitForTransactionActivation(t,s) wait_operational(s)
#define ServiceDeploy_WaitForPrimaryLifecycleHealthy(t,s) wait_operational(s)
#define ServiceDeploy_LifecycleStateToString(...) L"state"
#define ServiceDeploy_WaitForExpectedIdentity(...) ((failAt != 8 && failAt != 12) || liveVersion == 1)
#define ServiceDeploy_WriteTransactionPhase(tx,n,p) write_phase(tx,p)
#define ServiceDeploy_ResolveUpdateTransaction(tx,n,p) resolve(tx,p)
#define ServiceDeploy_ReconcileCommittedInstallation(...) (failAt != 16)
#define ServiceDeploy_DeleteResolvedCheckpoint(...) (failAt != 17)
#define ServiceDeploy_DeleteUpdateTransactionArtifacts(...) (++deletedArtifacts)
#define ServiceDeploy_BuildSiblingPathWithExtension(e,x,o,c) sibling(x,o)
#define ServiceDeploy_PathExists(p) (wcscmp(p,L"agent.mshx") != 0)
#define ServiceDeploy_TerminateProcessesByLoadedModulePath(...) ((void)0)
#define ServiceDeploy_TerminateProcessesByPath(...) ((void)0)
#define GetFileAttributesW(...) INVALID_FILE_ATTRIBUTES
#define GetLastError() 1
#define GetTickCount() 1
#define CreateFileW(...) INVALID_HANDLE_VALUE
'''

# Non-mutating collaborators succeed. The transaction, SCM, identity and startup
# boundaries above have explicit stateful mocks; production orchestration is intact.
mocked = set(re.findall(r'^#define (\w+)', prelude, re.M))
calls = set(re.findall(r'\b((?:ServiceDeploy_|ServiceBinding_|Security_|MeshInstaller_|MeshRundll32_|FaultRecovery_|MeshService_|ServiceUtil_|ServiceHost_)\w+)\s*\(', flow + install))
generic = '\n'.join(f'#define {name}(...) 1' for name in sorted(calls - mocked - {'ServiceDeploy_ApplyUpdateFlow', 'ServiceDeploy_ApplyInstallFlow'}))
generic += '\n#define Sleep(...) ((void)0)\n#define CloseHandle(...) 1\n#define StringCchCopyW(a,b,c) wcscpy(a,c)\n#define StringCchCatW(a,b,c) wcscat(a,c)\n'

cases = r'''
static void reset(int failure, int exists, int wasRunning, int originalStart, int ownProcess) {
    publishedPhase = 0; failAt = failure; originalExists = installed = exists; legacy = ownProcess;
    running = wasRunning; liveVersion = bindingVersion = exists ? 1 : 0; startType = originalStart;
    starts = mixedStarts = stops = prepared = rolledBack = convergence = discarded = restoredBindings = deletedArtifacts = 0;
}
static void run_case(int failure, int exists, int wasRunning, int originalStart, int ownProcess) {
    reset(failure, exists, wasRunning, originalStart, ownProcess);
    BOOL result = ServiceDeploy_ApplyUpdateFlow(L"new.exe",L"new.dll",FALSE);
    assert(result == (failure == 0));
    assert(mixedStarts == 0);
    if (!failure) { assert(running && liveVersion == 3 && installed); return; }
    if (failure == 16 || failure == 17) {
        assert(running && liveVersion == 3 && installed && !rolledBack && publishedPhase == SERVICE_JOURNAL_COMMITTED); return;
    }
    if (failure == 9) { assert(running && liveVersion == 1 && !rolledBack && !discarded && !deletedArtifacts && publishedPhase == SERVICE_JOURNAL_PREPARED); return; }
    if (failure == 12) { assert(running && liveVersion == 3 && !rolledBack && !discarded && !deletedArtifacts && publishedPhase == SERVICE_JOURNAL_BACKED_UP); return; }
    if (failure == 18) { assert(!running && liveVersion == 1 && !discarded && !deletedArtifacts && publishedPhase == SERVICE_JOURNAL_PREPARED); return; }
    if (failure != 10 && failure != 3 && exists) assert(startType == originalStart);
    if (failure == 3) { assert(!running && liveVersion == 2 && !discarded && !deletedArtifacts); return; }
    if (failure == 10) { assert(!running && !discarded && !deletedArtifacts); return; }
    assert(running == wasRunning && liveVersion == (exists ? 1 : 0) && installed == exists);
    if (failure == 4 || failure == 5 || failure == 6 || failure == 13) assert(stops == 0);
    if (failure == 2 || failure == 7 || failure == 8 || failure == 11 || failure == 15) assert(rolledBack == 1 && discarded == 1);
}
static void orphan_files_case(int failure) {
    reset(failure,0,0,SERVICE_AUTO_START,0);
    originalExists = 1; liveVersion = 1;
    BOOL result = ServiceDeploy_ApplyUpdateFlow(L"new.exe",L"new.dll",TRUE);
    assert(result == (failure == 0) && !mixedStarts);
    if (result) assert(installed && running && liveVersion == 3);
    else assert(!installed && !running && liveVersion == 1 && rolledBack && publishedPhase == SERVICE_JOURNAL_ROLLED_BACK);
}
static void install_case(int config, int exists, int ownProcess, int failure) {
    packageHasConfig = config;
    reset(failure,exists,exists,SERVICE_AUTO_START,ownProcess);
    BOOL result = ServiceDeploy_ApplyInstallFlow(L"new.exe",L"new.dll");
    assert(result == (config && failure == 0));
    assert(mixedStarts == 0);
    if (!config) assert(!prepared && !stops && running == exists && liveVersion == (exists ? 1 : 0));
    if (result) assert(prepared == 1 && running && liveVersion == 3);
    packageHasConfig = 1;
}
int main(void) {
    int count = 0;
    for (int own = 0; own < 2; ++own) {
        for (int active = 0; active < 2; ++active) {
            for (int failure = 0; failure <= 8; ++failure) {
                run_case(failure,1,active,active ? 3 : 4,own); ++count;
            }
        }
        run_case(2,1,1,4,own); ++count; /* Running but disabled: restart before restoring DISABLED. */
        run_case(9,1,1,3,own); ++count; /* Stop failure leaves incumbent intact. */
        for (int failure = 10; failure <= 18; ++failure) { run_case(failure,1,1,3,own); ++count; } /* Partially applied registration is rolled back. */
    }
    for (int failure = 0; failure <= 8; ++failure) {
        if (failure == 4 || failure == 3) continue;
        run_case(failure,0,0,2,0); ++count;
    }
    for (int failure = 11; failure <= 17; ++failure) { run_case(failure,0,0,2,0); ++count; }
    for (int own = 0; own < 2; ++own) {
        install_case(1,1,own,0); install_case(0,1,own,0); install_case(1,1,own,2); count += 3;
    }
    install_case(1,0,0,0); install_case(0,0,0,0); install_case(1,0,0,2); count += 3;
    orphan_files_case(0); orphan_files_case(2); orphan_files_case(7); orphan_files_case(8); count += 4;
    packageHasConfig = 0; run_case(0,1,1,3,0); ++count; /* Binary-only update retains installed identity. */
    printf("Service transaction native orchestration: %d cases passed\n",count);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='meshagent-update-recovery-') as directory:
    c_path = Path(directory) / 'recovery.c'
    executable = Path(directory) / ('recovery.exe' if os.name == 'nt' else 'recovery')
    c_path.write_text(prelude + generic + '\n' + flow + '\n' + install + '\n' + cases)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wno-unused-value', str(c_path), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
