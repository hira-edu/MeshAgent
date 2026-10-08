#!/usr/bin/env python3
"""Exercise interrupted transaction recovery using the actual deployment function.

No Windows services/files are changed. The journal codec and binding operations
have separate native suites; this suite tests the recovery decision boundaries.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/service_deployment.c').read_text()
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' ' * len(m.group()), source, flags=re.S)
match = re.search(r'static BOOL ServiceDeploy_RecoverInterruptedTransaction\(void\)\s*\{', masked)
assert match
end, depth = match.end(), 1
while depth:
    depth += (masked[end] == '{') - (masked[end] == '}')
    end += 1
recovery = source[match.start():end]
prelude = r'''
#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL;typedef uint32_t DWORD;typedef void* PSECURITY_DESCRIPTOR;typedef void* HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#ifndef _countof
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif
#define SERVICE_WIN32_OWN_PROCESS 16
#define SERVICE_WIN32_SHARE_PROCESS 32
#define SERVICE_DISABLED 4
#define SERVICE_JOURNAL_PREPARED 1
#define SERVICE_JOURNAL_BACKED_UP 2
#define SERVICE_JOURNAL_COMMITTED 3
#define SERVICE_JOURNAL_ROLLED_BACK 4
#define SERVICE_JOURNAL_ACTIVATING 5
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_ACCESS_DENIED 5
#define ZeroMemory(p,n) memset(p,0,n)
typedef struct {DWORD dwServiceType,dwStartType;} QUERY_SERVICE_CONFIGW;
typedef struct {QUERY_SERVICE_CONFIGW* config;BOOL running,legacy;wchar_t incumbentDbPath[MAX_PATH];} ServiceBindingSnapshot;
typedef struct {int value;BOOL nodeIdPresent;} ServiceIdentitySnapshot;
typedef struct {wchar_t exePath[MAX_PATH],dllPath[MAX_PATH],dbPath[MAX_PATH];} ServiceInstallPaths;
typedef struct {DWORD phase,fileMask;ServiceBindingSnapshot* binding;PSECURITY_DESCRIPTOR dacl[5];DWORD attributes[5];} ServiceJournalRecord;
typedef struct {wchar_t journalPath[MAX_PATH],backupDir[MAX_PATH],backupExePath[MAX_PATH],backupDllPath[MAX_PATH],backupConfPath[MAX_PATH],backupMshPath[MAX_PATH],backupDbPath[MAX_PATH];DWORD journalPhase;ServiceBindingSnapshot* originalBinding;BOOL liveExeExists,liveDllExists,liveConfExists,liveMshExists,liveDbExists,backupsReady,backupDbReady,rollbackIdentityReady;PSECURITY_DESCRIPTOR originalFileDacl[5];DWORD originalFileAttributes[5];ServiceIdentitySnapshot rollbackIdentity;} ServiceUpdateTransaction;
static ServiceJournalRecord checkpoint;static ServiceBindingSnapshot binding;static QUERY_SERVICE_CONFIGW config;
static int present,loadFail,unowned,unsafePath,owned,missingBackup,failAt,currentExists,running,liveVersion,startType;
static int stops,starts,rollbacks,restores,securityRestores,reconciles,cleanups,resolves,frees,holds;static DWORD lastError;
static BOOL get_paths(ServiceInstallPaths* p){wcscpy(p->exePath,L"agent.exe");wcscpy(p->dllPath,L"agent.dll");wcscpy(p->dbPath,L"agent.db");return TRUE;}
static BOOL init_paths(ServiceUpdateTransaction* tx){wcscpy(tx->journalPath,L"journal");wcscpy(tx->backupDir,L"backups");wcscpy(tx->backupExePath,L"backup.exe");wcscpy(tx->backupDllPath,L"backup.dll");wcscpy(tx->backupConfPath,L"backup.conf");wcscpy(tx->backupMshPath,L"backup.msh");wcscpy(tx->backupDbPath,L"backup.db");return TRUE;}
static BOOL load(ServiceJournalRecord** out){*out=present?&checkpoint:NULL;return !loadFail;}
static DWORD attrs(const wchar_t* path){if(!wcscmp(path,L"journal")){lastError=ERROR_FILE_NOT_FOUND;return present?0:INVALID_FILE_ATTRIBUTES;}lastError=ERROR_FILE_NOT_FOUND;return missingBackup?INVALID_FILE_ATTRIBUTES:0;}
static BOOL image(BOOL* legacy){*legacy=binding.legacy;return owned;}
static BOOL query(BOOL* exists){*exists=currentExists;return failAt!=1;}
static BOOL start_type(DWORD value){startType=value;return TRUE;}
static BOOL stop(BOOL force){assert(force);++stops;if(failAt==2)return FALSE;running=0;return TRUE;}
static BOOL rollback(void){++rollbacks;assert(!running);if(failAt==3)return FALSE;liveVersion=1;currentExists=checkpoint.binding!=NULL;return TRUE;}
static BOOL restore_security(void){++securityRestores;return failAt!=4;}
static BOOL restore_binding(void){++restores;return failAt!=4;}
static BOOL start(void){++starts;assert(liveVersion==1);if(failAt==5)return FALSE;running=1;return TRUE;}
static BOOL resolve(DWORD phase){++resolves;assert(phase==SERVICE_JOURNAL_ROLLED_BACK);if(failAt==6)return FALSE;checkpoint.phase=phase;present=0;return TRUE;}
static BOOL reconcile(void){++reconciles;return failAt!=7;}
static BOOL remove_checkpoint(void){if(failAt==8)return FALSE;present=0;return TRUE;}
static BOOL unregister(void){currentExists=0;return TRUE;}
#define ServiceDeploy_GetInstallPaths(p) get_paths(p)
#define ServiceDeploy_InitializeUpdateTransactionPaths(p,tx) init_paths(tx)
#define ServiceDeploy_TransactionPathsSafe(p,tx) (!unsafePath)
#define ServiceDeploy_ResolveRuntimeServiceBranding(name,n,...) wcscpy(name,L"Agent")
#define ServiceJournal_Load(path,name,out) load(out)
#define ServiceJournal_Free(r) (++frees)
#define ServiceDeploy_LogInstallEvent(...) ((void)0)
#define ServiceDeploy_TransactionDirectoryEmpty(path) (!unowned)
#define ServiceBinding_ImageSupported(n,c,e,d,l) image(l)
#define ServiceBinding_SharedPayloadSupported(s,d) owned
#define ServiceDeploy_SuspendOriginalRestarters(...) TRUE
#define ServiceDeploy_BindingHasMovedRoot(...) FALSE
#define ServiceDeploy_FindIncumbentPaths(...) FALSE
#define ServiceDeploy_CheckpointIncumbentPaths(b,p) (wcscpy((p)->dbPath,(b)->incumbentDbPath),TRUE)
#define _wcsicmp wcscmp
#define ServiceDeploy_BindingPayloadPath(b,p,n) ((void)(b),(void)(p),(void)(n),FALSE)
#define ServiceDeploy_DeleteUpdateTransactionArtifacts(tx) (++cleanups,remove_checkpoint())
#define ServiceDeploy_ReconcileCommittedTransaction(p,n,tx) (reconcile() && (++cleanups, remove_checkpoint()))
#define ServiceDeploy_DeleteResolvedCheckpoint(tx) remove_checkpoint()
#define GetFileAttributesW(path) attrs(path)
#define GetLastError() lastError
#define ServiceDeploy_CaptureIdentitySnapshot(p,s) ((s)->value=1,(s)->nodeIdPresent=TRUE,TRUE)
#define ServiceBinding_Capture(...) (owned ? &binding : NULL)
#define ServiceBinding_Free(...) ((void)0)
#define ServiceBinding_QueryExists(n,out) query(out)
#define ServiceDeploy_SetServiceStartType(n,type) start_type(type)
#define ServiceDeploy_ClearServiceRecovery(n) TRUE
#define ServiceDeploy_SuspendServiceRecoveryRestarters() TRUE
#define ServiceDeploy_StopServiceAndWait(n,t,force) stop(force)
#define ServiceDeploy_RollbackUpdateTransaction(p,n,tx) rollback()
#define ServiceDeploy_RestoreUpdateFileSecurity(p,tx) restore_security()
#define ServiceBinding_Restore(n,s) restore_binding()
#define ServiceHost_UnregisterServiceHostService(n) unregister()
#define ServiceDeploy_StartServiceHostServiceAndWait(n,t) start()
#define ServiceDeploy_WaitForExpectedIdentity(p,s,t) (failAt!=9)
/* Update holds were removed: a call would count here and model a missing target key. */
#define ServiceDeploy_RecordUpdateActivationFailureHold(p) (++holds,FALSE)
#define ServiceDeploy_ReconcileServiceRecovery() TRUE
#define ServiceDeploy_CreateRecoveryStartupAuthorization(out) (*(out)=(HANDLE)1,TRUE)
#define CloseHandle(...) TRUE
#define ServiceJournal_PhaseRequiresBackups(p) ((p)==SERVICE_JOURNAL_BACKED_UP || (p)==SERVICE_JOURNAL_ACTIVATING)
#define ServiceDeploy_ResolveUpdateTransaction(tx,n) resolve(SERVICE_JOURNAL_ROLLED_BACK)
'''
cases = r'''
static void setup(DWORD phase,int priorRunning,int originalExists){
    memset(&checkpoint,0,sizeof(checkpoint));memset(&binding,0,sizeof(binding));memset(&config,0,sizeof(config));
    config.dwServiceType=SERVICE_WIN32_SHARE_PROCESS;config.dwStartType=priorRunning?4:3;binding.config=&config;binding.running=priorRunning;
    checkpoint.phase=phase;checkpoint.fileMask=31;checkpoint.binding=originalExists?&binding:NULL;
    for(int i=0;i<5;++i){checkpoint.dacl[i]=(void*)(uintptr_t)1;checkpoint.attributes[i]=32;}
    present=owned=currentExists=1;loadFail=unowned=unsafePath=missingBackup=failAt=0;running=phase==1?priorRunning:1;liveVersion=phase==1?1:2;startType=2;
    stops=starts=rollbacks=restores=securityRestores=reconciles=cleanups=resolves=frees=holds=0;
}
int main(void){
    for(int prior=0;prior<=1;++prior)for(int existed=0;existed<=1;++existed){
        setup(1,prior,existed);assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&!rollbacks&&securityRestores==1);assert(starts==(prior&&existed));assert(!existed||startType==(prior?4:3));
        setup(2,prior,existed);assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&rollbacks==1&&liveVersion==1);assert(starts==(prior&&existed));assert(!existed||startType==(prior?4:3));
        setup(5,prior,existed);assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&rollbacks==1&&liveVersion==1);assert(starts==(prior&&existed));assert(!existed||startType==(prior?4:3));
    }
    for(int phase=3;phase<=4;++phase){setup(phase,1,1);assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&!rollbacks&&!restores&&!stops&&!starts&&cleanups==1);assert(reconciles==(phase==3));}
    for(int failure=1;failure<=6;++failure){setup(failure==4?1:2,1,1);failAt=failure;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!cleanups);}
    /* A PREPARED checkpoint owns unchanged live bytes. Restore incumbent policy
     * even if another stop would fail; later phases still require quiescence. */
    setup(1,1,1);failAt=2;assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&!stops&&restores==1&&starts==1);
    setup(1,1,0);failAt=2;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&stops==1&&!restores&&!starts);
    setup(5,1,1);failAt=2;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&stops==1&&!rollbacks&&!restores&&!starts);
    setup(2,1,1);failAt=9;assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&rollbacks==1&&resolves==1);
    /* Recovery records no update hold and needs no activation target key. */
    setup(2,1,1);wcscpy(binding.incumbentDbPath,L"old.db");assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&!holds&&starts==1&&resolves==1);
    setup(5,1,1);assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!present&&rollbacks==1&&!holds&&starts==1&&resolves==1);
    setup(3,1,1);failAt=7;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!rollbacks&&!stops&&reconciles==1);
    setup(3,1,1);failAt=8;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!rollbacks&&!stops);
    setup(2,1,1);missingBackup=1;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!stops&&!rollbacks);
    setup(2,1,1);owned=0;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!stops&&!rollbacks);
    setup(2,1,1);loadFail=1;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!stops&&!rollbacks&&!cleanups);
    setup(2,1,1);unsafePath=1;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!stops&&!rollbacks&&!cleanups);
    setup(1,1,1);checkpoint.dacl[0]=NULL;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(present&&!stops);
    setup(1,1,1);present=0;unowned=1;assert(!ServiceDeploy_RecoverInterruptedTransaction());assert(!stops&&!cleanups);
    setup(1,1,1);present=0;assert(ServiceDeploy_RecoverInterruptedTransaction());assert(!stops&&!cleanups);
    puts("service transaction recovery: all five phases, fresh/running/stopped originals, retained failure checkpoints, committed cleanup and orphan protection passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-service-recovery-') as tmp:
    src, exe = Path(tmp) / 'recovery.c', Path(tmp) / 'recovery'
    src.write_text(prelude + recovery + cases)
    compile_args = [os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror']
    if os.name != 'nt':
        compile_args.append('-fsanitize=address,undefined')
    subprocess.run(compile_args + [str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
