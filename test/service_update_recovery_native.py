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
#define _CRT_SECURE_NO_WARNINGS
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
#define SERVICE_WIN32_OWN_PROCESS 16
#define SERVICE_JOURNAL_PREPARED 1
#define SERVICE_JOURNAL_BACKED_UP 2
#define SERVICE_JOURNAL_COMMITTED 3
#define SERVICE_JOURNAL_ROLLED_BACK 4
#define SERVICE_JOURNAL_ACTIVATING 5
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
#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif
#define ZeroMemory(p,n) memset(p,0,n)
#define _wcsicmp wcscmp
#define UNREFERENCED_PARAMETER(p) ((void)p)
typedef struct { wchar_t installDir[MAX_PATH], logsDir[MAX_PATH], exePath[MAX_PATH], dllPath[MAX_PATH], confPath[MAX_PATH], dbPath[MAX_PATH]; } ServiceInstallPaths;
typedef struct { int unused; BOOL nodeIdPresent; } ServiceIdentitySnapshot;
typedef struct { DWORD dwStartType, dwServiceType; } binding_config;
typedef struct { binding_config* config; BOOL running, legacy; wchar_t incumbentExePath[MAX_PATH],incumbentDllPath[MAX_PATH],incumbentDbPath[MAX_PATH]; } ServiceBindingSnapshot;
typedef struct {
    BOOL backupsReady, liveDbExists, stagedMshReady, postUpdateIdentityReady, rollbackIdentityReady;
    wchar_t stagedMshPath[MAX_PATH], stagedConfPath[MAX_PATH], backupDir[MAX_PATH];
    ServiceIdentitySnapshot postUpdateIdentity, rollbackIdentity;
    DWORD journalPhase;
    BOOL pendingUpdateMarked;
    BOOL stagingOwned;
    ServiceBindingSnapshot* originalBinding;
    void* originalFileDacl[5];
} ServiceUpdateTransaction;
typedef struct { BOOL configAvailable, sourceEmbeddedConfigPresent, sourceSidecarConfigPresent; } ServicePackagePreflight;
typedef struct { int enabled; } persistence_toggle;
typedef struct { int runKey; persistence_toggle autorunTask, serviceRecoveryTask, serviceRecoveryMonitor, watchdog; } mesh_persistence_profile_t;
typedef struct {
    int stateKind, pendingUpdate, updateStageArtifactsPresent, updateBackupArtifactsPresent, firewallHealthy, persistenceHealthy;
    int serviceExists, serviceTypeValid, serviceImageValid, serviceGroupValid, serviceAccountValid, serviceDllValid, dllExists, serviceMainValid, serviceUnloadValid;
} ServiceLifecycleDiscovery;
static int failAt, running, liveVersion, bindingVersion, startType, starts, mixedStarts, stops, prepared, rolledBack, convergence, discarded, incumbentRepairs, restoredBindings, deletedArtifacts;
static int installed = 1, legacy = 0, packageHasConfig = 1, originalExists = 1;
static DWORD retainedPhase;
static mesh_persistence_profile_t profile;
static binding_config savedConfig;
static ServiceBindingSnapshot savedBinding;
static ServiceInstallPaths g_IncumbentPaths;
static BOOL g_HaveIncumbentPaths;
static int migratedCopies, copyFailure, identityCaptureFailure, failureHolds, noDb, dbWithoutNode;
static long g_MeshDiagnosticLogDisabled;
#define InterlockedExchange(p,v) (*(p)=(v))
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
    savedConfig.dwServiceType = legacy ? SERVICE_WIN32_OWN_PROCESS : SERVICE_WIN32_SHARE_PROCESS; savedConfig.dwStartType = startType; savedBinding.config = &savedConfig;
    savedBinding.running = running; savedBinding.legacy = legacy; return &savedBinding;
}
static BOOL restore_binding(void) {
    ++restoredBindings; if (failAt == 10 || failAt == 16) return FALSE;
    bindingVersion = 1; installed = 1;
    startType = savedBinding.running && savedConfig.dwStartType == SERVICE_DISABLED ? 3 : (int)savedConfig.dwStartType;
    return TRUE;
}
static BOOL sibling(const wchar_t* ext, wchar_t* out) { wcscpy(out, wcscmp(ext,L".db") == 0 ? L"agent.db" : L"agent.mshx"); return TRUE; }
/* Scenario 6 fails after the staging area is owned, so its cleanup is expected. */
static BOOL prepare(ServiceUpdateTransaction* tx) { ++prepared; tx->liveDbExists = originalExists && !noDb; tx->stagingOwned = TRUE; return failAt != 6; }
static BOOL backup(ServiceUpdateTransaction* tx) {
    assert(!running); if (failAt == 1 || failAt == 16) return FALSE;
    tx->backupsReady = TRUE; tx->rollbackIdentity.nodeIdPresent = originalExists && !noDb && !dbWithoutNode;
    tx->rollbackIdentityReady = tx->postUpdateIdentityReady = originalExists && !noDb; return TRUE;
}
static BOOL commit(void) { assert(!running); liveVersion = failAt == 2 || failAt == 3 || failAt == 10 || failAt == 17 ? 2 : 3; return liveVersion == 3; }
static BOOL registration(void) { bindingVersion = 3; installed = 1; return failAt != 11; }
static BOOL rollback(void) {
    assert(!running); ++rolledBack; if (failAt == 3) return FALSE;
    liveVersion = (originalExists || g_HaveIncumbentPaths) ? 1 : 0;
    if (originalExists || g_HaveIncumbentPaths) return restore_binding();
    bindingVersion = 0; installed = 0; return TRUE;
}
static BOOL stop_service(void) { ++stops; if (failAt == 9) return FALSE; running = 0; return TRUE; }
static BOOL start_service(BOOL allowRepair) {
    ++starts; if (liveVersion == 2 || liveVersion != bindingVersion) ++mixedStarts;
    assert(startType != SERVICE_DISABLED);
    if (liveVersion == 1 && allowRepair) ++incumbentRepairs;
    if (failAt == 7 && liveVersion == 3) return FALSE;
    running = 1; return TRUE;
}
static BOOL set_start(DWORD value) { startType = (int)value; return TRUE; }
static BOOL wait_operational(ServiceLifecycleDiscovery* state) {
    ++convergence; memset(state,0,sizeof(*state)); return running && liveVersion == 3 && bindingVersion == 3;
}
static BOOL publish(ServiceUpdateTransaction* tx, DWORD phase) {
    if ((failAt == 12 && phase == SERVICE_JOURNAL_PREPARED) ||
        (failAt == 13 && phase == SERVICE_JOURNAL_BACKED_UP) ||
        (failAt == 14 && phase == SERVICE_JOURNAL_COMMITTED) ||
        (failAt == 17 && phase == SERVICE_JOURNAL_ROLLED_BACK)) return FALSE;
    retainedPhase = tx->journalPhase = phase; return TRUE;
}
static BOOL resolve(ServiceUpdateTransaction* tx) {
    if (!publish(tx, SERVICE_JOURNAL_ROLLED_BACK)) return FALSE;
    ++discarded; ++deletedArtifacts; retainedPhase = 0; return TRUE;
}
static BOOL reconcile(ServiceUpdateTransaction* tx) {
    assert(tx->journalPhase == SERVICE_JOURNAL_COMMITTED);
    if (failAt == 15) return FALSE;
    running = 1; ++discarded; ++deletedArtifacts; retainedPhase = 0; return TRUE;
}
static BOOL migration_copy(void) {
    assert(!running && retainedPhase == SERVICE_JOURNAL_BACKED_UP);
    ++migratedCopies; return !copyFailure;
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
#define ServiceDeploy_RollbackUpdateTransaction(...) rollback()
#define ServiceDeploy_StopServiceAndWait(...) stop_service()
#define ServiceDeploy_StartServiceHostServiceAndWait(a,b) start_service(FALSE)
#define ServiceDeploy_SetServiceStartType(a,value) set_start(value)
#define ServiceDeploy_WaitForTransactionActivation(t,s) wait_operational(s)
#define ServiceDeploy_WaitForPrimaryLifecycleHealthy(t,s) wait_operational(s)
#define ServiceDeploy_LifecycleStateToString(...) L"state"
#define ServiceDeploy_WaitForExpectedIdentity(...) (failAt != 8 || liveVersion == 1)
#define ServiceDeploy_FlushUpdateFiles(...) (failAt != 18 || liveVersion == 1)
#define ServiceDeploy_RefreshQuiescedFileCheckpoint(...) (failAt != 19)
#define ServiceDeploy_BindingHasMovedRoot(...) g_HaveIncumbentPaths
#define ServiceDeploy_CaptureIdentitySnapshot(p,s) ((s)->nodeIdPresent=TRUE,!identityCaptureFailure)
#define ServiceDeploy_CopyFileOverwrite(a,b) migration_copy()
/* Update holds were removed: a call would count here, and no case may record one. */
#define ServiceDeploy_RecordUpdateActivationFailureHold(p) (++failureHolds,FALSE)
#define ServiceDeploy_WriteTransactionPhase(tx,n,p) publish(tx,p)
#define ServiceDeploy_ResolveUpdateTransaction(tx,n) resolve(tx)
#define ServiceDeploy_ReconcileCommittedTransaction(p,n,tx) reconcile(tx)
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
calls = set(re.findall(r'\b((?:ServiceDeploy_|ServiceBinding_|Security_|MeshInstaller_|MeshRuntimeHost_|FaultRecovery_|MeshService_|ServiceUtil_|ServiceHost_)\w+)\s*\(', flow + install))
generic = '\n'.join(f'#define {name}(...) 1' for name in sorted(calls - mocked - {'ServiceDeploy_ApplyUpdateFlow', 'ServiceDeploy_ApplyInstallFlow'}))
generic += '\n#define Sleep(...) ((void)0)\n#define CloseHandle(...) 1\n#define StringCchCopyW(a,b,c) wcscpy(a,c)\n#define StringCchCatW(a,b,c) wcscat(a,c)\n'

cases = r'''
static void reset(int failure, int exists, int wasRunning, int originalStart, int ownProcess) {
    retainedPhase = 0; failAt = failure; originalExists = installed = exists; legacy = ownProcess;
    running = wasRunning; liveVersion = bindingVersion = exists ? 1 : 0; startType = originalStart;
    starts = mixedStarts = stops = prepared = rolledBack = convergence = discarded = incumbentRepairs = restoredBindings = deletedArtifacts = 0;
}
static void run_case(int failure, int exists, int wasRunning, int originalStart, int ownProcess) {
    reset(failure, exists, wasRunning, originalStart, ownProcess);
    BOOL result = ServiceDeploy_ApplyUpdateFlow(L"new.exe",L"new.dll",FALSE);
    if (result != (failure == 0)) fprintf(stderr,"unexpected failure=%d result=%d exists=%d active=%d\n",failure,result,exists,wasRunning);
    assert(result == (failure == 0));
    assert(mixedStarts == 0 && incumbentRepairs == 0 && failureHolds == 0);
    if (!failure) { assert(running && liveVersion == 3 && installed); return; }
    if (failure == 15) { assert(!running && liveVersion == 3 && bindingVersion == 3 && !rolledBack && retainedPhase == SERVICE_JOURNAL_COMMITTED && !deletedArtifacts); return; }
    if (failure == 17) { assert(running && liveVersion == 1 && retainedPhase == SERVICE_JOURNAL_BACKED_UP && !deletedArtifacts); return; }
    if (failure == 16) { assert(!running && liveVersion == 1 && !deletedArtifacts && retainedPhase == SERVICE_JOURNAL_PREPARED); return; }
    if (exists && failure != 3 && failure != 10) assert(startType == originalStart);
    if (failure == 3) { assert(!running && liveVersion == 2 && !discarded && !deletedArtifacts); return; }
    if (failure == 10) { assert(!running && !discarded && !deletedArtifacts); return; }
    assert(running == wasRunning && liveVersion == (exists ? 1 : 0) && installed == exists);
    if (failure == 9) assert(stops == 1 && restoredBindings == 1 && discarded == 1);
    if (failure == 4 || failure == 5 || failure == 6 || failure == 12) assert(stops == 0);
    if (failure == 6) assert(deletedArtifacts == 1);
    if (failure == 2 || failure == 7 || failure == 8 || failure == 11 || failure == 14) assert(rolledBack == 1 && discarded == 1);
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
static void migration_case(int copyFail, int identityFail, int commitFail) {
    reset(commitFail?2:0,1,1,3,1);
    originalExists=0; /* New branding root is empty; old service/DB still exist. */
    g_HaveIncumbentPaths=TRUE;wcscpy(g_IncumbentPaths.dbPath,L"old-identity.db");
    copyFailure=copyFail;identityCaptureFailure=identityFail;migratedCopies=failureHolds=0;
    BOOL result=ServiceDeploy_ApplyUpdateFlow(L"new.exe",L"new.dll",FALSE);
    assert(result == !(copyFail||identityFail||commitFail));
    assert(migratedCopies == !identityFail && mixedStarts==0);
    if(copyFail||identityFail||commitFail)assert(installed&&running&&bindingVersion==1&&rolledBack==1&&!failureHolds);
    else assert(installed&&running&&bindingVersion==3);
    g_HaveIncumbentPaths=FALSE;copyFailure=identityCaptureFailure=0;
    memset(&g_IncumbentPaths,0,sizeof(g_IncumbentPaths));
}
/* A registration without an identity DB stays repairable; a DB without a NodeID is never replaced. */
static void identity_case(int withoutDb) {
    packageHasConfig=1; reset(0,1,1,3,0); noDb=withoutDb; dbWithoutNode=!withoutDb;
    BOOL result=ServiceDeploy_ApplyUpdateFlow(L"new.exe",L"new.dll",FALSE);
    assert(result==withoutDb && mixedStarts==0 && running && !failureHolds);
    if(withoutDb)assert(liveVersion==3&&bindingVersion==3);
    else assert(liveVersion==1&&bindingVersion==1&&rolledBack==1);
    noDb=dbWithoutNode=0;
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
        run_case(11,1,1,3,own); ++count; /* Partially applied registration is rolled back. */
    }
    for (int failure = 12; failure <= 19; ++failure) { run_case(failure,1,1,3,0); ++count; }
    for (int failure = 0; failure <= 8; ++failure) {
        if (failure == 4 || failure == 3) continue;
        run_case(failure,0,0,2,0); ++count;
    }
    for (int own = 0; own < 2; ++own) {
        install_case(1,1,own,0); install_case(0,1,own,0); install_case(1,1,own,2); count += 3;
    }
    install_case(1,0,0,0); install_case(0,0,0,0); install_case(1,0,0,2); count += 3;
    packageHasConfig = 0; run_case(0,1,1,3,0); ++count; /* Binary-only update retains installed identity. */
    migration_case(0,0,0);migration_case(1,0,0);migration_case(0,1,0);migration_case(0,0,1);count+=4;
    identity_case(1);identity_case(0);count+=2;
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

# Exercise actual crash-recovery and cleanup orchestration separately from the
# activation harness. Keep SCM/filesystem boundaries stateful and injectable.
recovery_prelude = r'''
#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL; typedef unsigned long DWORD; typedef void* HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#ifndef _countof
#define _countof(x) (sizeof(x)/sizeof(*(x)))
#endif
#ifndef _TRUNCATE
#define _TRUNCATE 0
#endif
#define SERVICE_JOURNAL_PREPARED 1
#define SERVICE_JOURNAL_BACKED_UP 2
#define SERVICE_JOURNAL_COMMITTED 3
#define SERVICE_JOURNAL_ROLLED_BACK 4
#define SERVICE_JOURNAL_ACTIVATING 5
#define SERVICE_DISABLED 4
#define SERVICE_WIN32_SHARE_PROCESS 32
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define FILE_ATTRIBUTE_DIRECTORY 16
#define FILE_ATTRIBUTE_REPARSE_POINT 1024
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_ACCESS_DENIED 5
typedef struct { DWORD dwServiceType, dwStartType; } Config;
typedef struct { Config* config; BOOL running, legacy; wchar_t incumbentExePath[MAX_PATH],incumbentDllPath[MAX_PATH],incumbentDbPath[MAX_PATH]; } ServiceBindingSnapshot;
typedef struct { DWORD phase,fileMask; ServiceBindingSnapshot* binding; void* dacl[5]; DWORD attributes[5]; } ServiceJournalRecord;
typedef struct { wchar_t exePath[MAX_PATH],dllPath[MAX_PATH],dbPath[MAX_PATH]; } ServiceInstallPaths;
typedef struct {
    DWORD journalPhase; ServiceBindingSnapshot* originalBinding;
    BOOL liveExeExists,liveDllExists,liveConfExists,liveMshExists,liveDbExists,backupsReady,backupDbReady,rollbackIdentityReady;
    void* originalFileDacl[5];DWORD originalFileAttributes[5];struct {BOOL nodeIdPresent;} rollbackIdentity;
    wchar_t journalPath[MAX_PATH],stageDir[MAX_PATH],backupDir[MAX_PATH],backupExePath[MAX_PATH],backupDllPath[MAX_PATH],backupConfPath[MAX_PATH],backupMshPath[MAX_PATH],backupDbPath[MAX_PATH];
} ServiceUpdateTransaction;
static Config config={16,3};static ServiceBindingSnapshot binding={&config,TRUE,FALSE};
static ServiceJournalRecord saved;
static int loadOk,journalExists,unknownBackup,unknownBinding,missingBackup,failRestore,failReconcile,failCleanup,failPublish;
static int mutations,stops,starts,restores,rollbacks,reconciles,deleted,phaseWritten;static DWORD error;
static int movedRoot, missingOldIdentity, holds, identityChecks;
static void log_event(const wchar_t* f,...){(void)f;}
static BOOL mock_recovery_paths(ServiceInstallPaths* p){memset(p,0,sizeof(*p));wcscpy(p->dbPath,L"current.db");return TRUE;}
static BOOL binding_payload(wchar_t* p){wcscpy(p,L"old-agent.exe");return TRUE;}
static BOOL original_paths(ServiceInstallPaths* p){memset(p,0,sizeof(*p));wcscpy(p->dbPath,L"old.db");return !missingOldIdentity;}
static BOOL capture_identity(const wchar_t* p,void* identity){*(BOOL*)identity=TRUE;return wcscmp(p,L"old.db")||!missingOldIdentity;}
static BOOL wait_identity(const wchar_t* p){assert(!movedRoot||!wcscmp(p,L"old.db"));++identityChecks;return TRUE;}
static BOOL txpaths(ServiceUpdateTransaction* t){wcscpy(t->journalPath,L"journal");wcscpy(t->stageDir,L"stage");wcscpy(t->backupDir,L"backup");wcscpy(t->backupExePath,L"exe");return TRUE;}
static BOOL load(ServiceJournalRecord** out){*out=journalExists?&saved:NULL;return loadOk;}
static BOOL capture_ok(void){return !unknownBinding;}
static BOOL set_start(void){++mutations;return TRUE;}
static BOOL stop(void){++mutations;++stops;return TRUE;}
static BOOL restore(void){++mutations;++restores;return !failRestore;}
static BOOL rollback(void){++mutations;++rollbacks;return !failRestore;}
static BOOL start(void){++mutations;++starts;return TRUE;}
static BOOL publish(ServiceUpdateTransaction* tx,DWORD phase){if(failPublish)return FALSE;phaseWritten=saved.phase=tx->journalPhase=phase;return TRUE;}
static BOOL remove_dir(void){++deleted;return !failCleanup;}
static DWORD GetFileAttributesW(const wchar_t* p){if(!wcscmp(p,L"journal")){error=ERROR_FILE_NOT_FOUND;return journalExists?0:INVALID_FILE_ATTRIBUTES;}return missingBackup?INVALID_FILE_ATTRIBUTES:0;}
static DWORD GetLastError(void){return error;}
static BOOL DeleteFileW(const wchar_t* p){++deleted;if(!wcscmp(p,L"journal"))journalExists=0;return TRUE;}
static int mock_snwprintf(wchar_t* out,size_t size,size_t trunc,const wchar_t* fmt,...){(void)trunc;(void)fmt;return swprintf(out,size,L"journal.tmp");}
#define ServiceDeploy_LogInstallEvent log_event
#define ServiceDeploy_GetInstallPaths(p) mock_recovery_paths(p)
#define ServiceDeploy_InitializeUpdateTransactionPaths(p,t) txpaths(t)
#define ServiceDeploy_ResolveRuntimeServiceBranding(...) ((void)0)
#define ServiceJournal_Load(p,n,r) load(r)
#define ServiceJournal_Free(...) ((void)0)
#define ServiceDeploy_TransactionPathsSafe(...) TRUE
#define ServiceBinding_SharedPayloadSupported(...) TRUE
#define ServiceDeploy_SuspendOriginalRestarters(...) TRUE
#define ServiceDeploy_BindingHasMovedRoot(...) movedRoot
#define ServiceDeploy_BindingPayloadPath(b,p,n) binding_payload(p)
#define ServiceDeploy_FindIncumbentPaths(payload,p) original_paths(p)
#define ServiceDeploy_CheckpointIncumbentPaths(b,p) original_paths(p)
#define _wcsicmp wcscmp
#define _snwprintf_s mock_snwprintf
#define ServiceDeploy_TransactionDirectoryEmpty(...) (!unknownBackup)
#define ServiceBinding_ImageSupported(n,c,e,d,l) (*(l)=FALSE,TRUE)
#define ServiceBinding_QueryExists(n,e) (*(e)=TRUE,TRUE)
#define ServiceBinding_Capture(...) (capture_ok()?&binding:NULL)
#define ServiceBinding_Free(...) ((void)0)
#define ServiceDeploy_SetServiceStartType(...) set_start()
#define ServiceDeploy_ClearServiceRecovery(...) set_start()
#define ServiceDeploy_SuspendServiceRecoveryRestarters(...) TRUE
#define ServiceDeploy_StopServiceAndWait(...) stop()
#define ServiceDeploy_RestoreUpdateFileSecurity(...) restore()
#define ServiceBinding_Restore(...) restore()
#define ServiceHost_UnregisterServiceHostService(...) restore()
#define ServiceDeploy_RollbackUpdateTransaction(...) rollback()
#define ServiceDeploy_StartServiceHostServiceAndWait(...) start()
#define ServiceDeploy_CaptureIdentitySnapshot(p,s) capture_identity(p,s)
#define ServiceDeploy_WaitForExpectedIdentity(p,s,t) wait_identity(p)
/* No hold is recorded, and a missing activation target never blocks recovery. */
#define ServiceDeploy_RecordUpdateActivationFailureHold(p) (++holds,FALSE)
#define ServiceDeploy_ReconcileServiceRecovery(...) TRUE
#define ServiceDeploy_CreateRecoveryStartupAuthorization(out) (*(out)=(HANDLE)1,TRUE)
#define CloseHandle(...) TRUE
#define ServiceJournal_PhaseRequiresBackups(p) ((p)==SERVICE_JOURNAL_BACKED_UP || (p)==SERVICE_JOURNAL_ACTIVATING)
#define ServiceDeploy_WriteTransactionPhase(tx,n,phase) publish(tx,phase)
#define ServiceDeploy_RemoveDirectoryTree(...) remove_dir()
static BOOL ServiceDeploy_DeleteUpdateTransactionArtifacts(const ServiceUpdateTransaction*);
static BOOL reconcile(ServiceUpdateTransaction* tx){++reconciles;if(failReconcile)return FALSE;return ServiceDeploy_DeleteUpdateTransactionArtifacts(tx);}
#define ServiceDeploy_ReconcileCommittedTransaction(p,n,t) reconcile(t)
'''
recovery_cases = r'''
static void reset(DWORD phase){
    memset(&saved,0,sizeof(saved));saved.phase=phase;saved.fileMask=1;saved.binding=&binding;saved.dacl[0]=(void*)1;saved.attributes[0]=32;
    loadOk=journalExists=1;unknownBackup=unknownBinding=missingBackup=failRestore=failReconcile=failCleanup=failPublish=0;
    mutations=stops=starts=restores=rollbacks=reconciles=deleted=phaseWritten=0;
    movedRoot=missingOldIdentity=holds=identityChecks=0;
}
int main(void){
    reset(1);journalExists=0;assert(ServiceDeploy_RecoverInterruptedTransaction()&&!mutations&&!deleted);
    reset(1);journalExists=0;unknownBackup=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&!mutations&&!deleted);
    reset(1);loadOk=0;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&!mutations&&!deleted);
    reset(1);unknownBinding=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&!mutations&&!deleted);
    reset(1);failRestore=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&!deleted&&!starts&&!rollbacks);
    reset(1);assert(ServiceDeploy_RecoverInterruptedTransaction()&&!journalExists&&starts==1&&restores==2&&!rollbacks&&phaseWritten==4);
    reset(2);missingBackup=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&!mutations&&!deleted);
    reset(2);failRestore=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&rollbacks==1&&!deleted&&!starts);
    reset(2);assert(ServiceDeploy_RecoverInterruptedTransaction()&&!journalExists&&rollbacks==1&&starts==1&&phaseWritten==4);
    reset(5);assert(ServiceDeploy_RecoverInterruptedTransaction()&&!journalExists&&rollbacks==1&&starts==1&&phaseWritten==4);
    reset(2);failPublish=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&rollbacks==1&&!deleted);
    reset(3);failReconcile=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&reconciles==1&&!rollbacks&&!mutations&&!deleted);
    reset(3);assert(ServiceDeploy_RecoverInterruptedTransaction()&&!journalExists&&reconciles==1&&!mutations);
    reset(4);failCleanup=1;assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&!mutations&&!reconciles);
    reset(4);assert(ServiceDeploy_RecoverInterruptedTransaction()&&!journalExists&&!mutations&&!reconciles);
    for(int phase=1;phase<=5;++phase){if(phase==3||phase==4)continue;
        reset(phase);movedRoot=1;saved.fileMask=0;
        assert(ServiceDeploy_RecoverInterruptedTransaction()&&!journalExists&&starts==1&&!holds&&identityChecks==1);
    }
    reset(2);movedRoot=missingOldIdentity=1;saved.fileMask=0;
    assert(!ServiceDeploy_RecoverInterruptedTransaction()&&journalExists&&!mutations&&!deleted);
    puts("Service crash recovery: 19 preservation, retry, rollback, migration and cleanup cases passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='meshagent-crash-recovery-') as directory:
    c_path = Path(directory) / 'crash.c'
    executable = Path(directory) / 'crash'
    recovery_flow = '\n'.join(extract(name) for name in (
        'ServiceDeploy_DeleteUpdateTransactionArtifacts',
        'ServiceDeploy_ResolveUpdateTransaction',
        'ServiceDeploy_RecoverInterruptedTransaction'))
    if os.name == 'nt':
        recovery_flow = recovery_flow.replace('_snwprintf_s(', 'mock_snwprintf(')
    c_path.write_text(recovery_prelude + '\n' + recovery_flow + '\n' + recovery_cases)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wno-unused-value', str(c_path), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
