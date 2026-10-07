"""Fault-inject persistence cleanup without touching Windows services or COM."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/service_deployment.c').read_text()

def extract(name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'static (?:BOOL|void) ' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]

prelude = r'''
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <stdio.h>
#define SERVICE_TASK_NAME_MAX 260
typedef struct { int unused; } mesh_persistence_profile_t;
typedef struct { wchar_t AutorunTask[260],RecoveryTask[260],RecoveryMonitorFilter[260],RecoveryMonitorHandler[260]; } ServiceRecoveryState;
static int failAt,cleared,hasState=1,attributesPresent=1,tasksRemain,monitorsRemain;
static BOOL g_HaveServiceRecoveryStatePath=TRUE;
static wchar_t g_ServiceRecoveryStatePath[]=L"state.ini";
static size_t prefixes(const mesh_persistence_profile_t* p,const wchar_t* d,const wchar_t* n,wchar_t out[][260],size_t cap){(void)p;(void)d;(void)n;(void)cap;StringCchCopyW(out[0],260,L"Agent");return 1;}
static BOOL fixture_state(ServiceRecoveryState* out){if(!hasState)return FALSE;StringCchCopyW(out->AutorunTask,260,L"Agent-Autorun-1");StringCchCopyW(out->RecoveryTask,260,L"Agent-ServiceRecovery-1");StringCchCopyW(out->RecoveryMonitorFilter,260,L"Agent_ServiceStateMonitor_1");return TRUE;}
static BOOL clear(void){if(failAt==8)return FALSE;++cleared;return TRUE;}
static DWORD fixture_attributes(const wchar_t* path){(void)path;SetLastError(ERROR_FILE_NOT_FOUND);return attributesPresent?0:INVALID_FILE_ATTRIBUTES;}
static BOOL inspect(wchar_t p[][260],size_t count,BOOL* tasks,BOOL* monitors){(void)p;(void)count;*tasks=tasksRemain;*monitors=monitorsRemain;return failAt!=7;}
static BOOL delete_task(const wchar_t* task){return failAt!=(wcsstr(task,L"Autorun")?1:2);}
static void log_event(const wchar_t* format,...){(void)format;}
#define ServiceDeploy_BuildTaskPrefixCandidates prefixes
#define ServiceDeploy_LoadServiceRecoveryState fixture_state
#define ServiceDeploy_ClearServiceRecoveryState clear
#define ServiceDeploy_LogInstallEvent log_event
#define FaultRecovery_DeleteTask delete_task
#define FaultRecovery_DeleteTasksByPrefix(...) (failAt!=4)
#define FaultRecovery_RemoveServiceRecoveryMonitor(...) (failAt!=3)
#define FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(...) (failAt!=5)
#define ServiceDeploy_RemoveLegacyRecoveryArtifacts(...) (failAt!=6)
#define ServiceDeploy_FindTaskByPrefixCandidates(...) FALSE
#define ServiceDeploy_RemoveScheduledTaskByName(...) TRUE
#define ServiceDeploy_QueryRecoveryArtifacts inspect
#define GetFileAttributesW fixture_attributes
'''
cases = r'''
int main(void){
    for(failAt=1;failAt<=8;++failAt){
        cleared=0;assert(!ServiceDeploy_RemoveScheduledTasks(NULL,L"Agent",L"Agent"));assert(!cleared);
    }
    failAt=0;assert(ServiceDeploy_RemoveScheduledTasks(NULL,L"Agent",L"Agent")&&cleared==1);
    cleared=0;tasksRemain=1;assert(!ServiceDeploy_RemoveScheduledTasks(NULL,L"Agent",L"Agent")&&!cleared);
    tasksRemain=0;monitorsRemain=1;assert(!ServiceDeploy_RemoveScheduledTasks(NULL,L"Agent",L"Agent")&&!cleared);
    monitorsRemain=0;hasState=0;
    assert(!ServiceDeploy_RemoveScheduledTasks(NULL,L"Agent",L"Agent")&&!cleared); /* corrupt present state */
    attributesPresent=0;
    assert(ServiceDeploy_RemoveScheduledTasks(NULL,L"Agent",L"Agent")&&cleared==1); /* no state: still inspect */
    cleared=0;failAt=5;assert(!ServiceDeploy_RemoveScheduledTasks(NULL,L"Agent",L"Agent")&&!cleared);
    puts("Persistence cleanup: eight injected boundaries, orphan verification, missing/corrupt state and safe retry passed");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-persistence-cleanup-') as directory:
    c = Path(directory) / 'cleanup.c'
    exe = Path(directory) / 'cleanup.exe'
    c.write_text(prelude + extract('ServiceDeploy_RemoveScheduledTasks') + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

# Exercise the actual uninstall orchestrator. All SCM/filesystem collaborators
# are mocked; failure to quiesce must precede payload or identity deletion.
uninstall_prelude = r'''
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <stdio.h>
#define SERVICE_MASTER_SERVICE_NAME L"FixtureCompanion"
#define SERVICE_LIFECYCLE_STATE_CLEAN 1
typedef struct { wchar_t installDir[260],logsDir[260],exePath[260],dllPath[260],dbPath[260],confPath[260],logPath[260]; } ServiceInstallPaths;
typedef struct { int unused; } ServiceBindingSnapshot;
typedef struct { int unused; } mesh_persistence_profile_t;
typedef struct { int stateKind,serviceExists,exeExists,dllExists,confExists,dbExists,firewallRulePresent,anyPersistenceArtifacts; } ServiceLifecycleDiscovery;
static ServiceInstallPaths g_IncumbentPaths;
static int failAt,files,unregistered,absent;static LONG g_MeshDiagnosticLogDisabled;
static BOOL get_paths(ServiceInstallPaths* p){ZeroMemory(p,sizeof(*p));return failAt!=1;}
static BOOL query_exists(BOOL* out){*out=!absent;return failAt!=2;}
static BOOL discover(ServiceLifecycleDiscovery* state){ZeroMemory(state,sizeof(*state));state->stateKind=SERVICE_LIFECYCLE_STATE_CLEAN;return failAt!=14;}
#define ServiceDeploy_GetInstallPaths get_paths
#define ServiceBinding_QueryExists(n,out) query_exists(out)
#define ServiceDeploy_ClearServiceRecovery(...) (assert(!absent),failAt!=3)
#define ServiceDeploy_RemoveRunKeyEntry(...) (failAt!=4)
#define ServiceDeploy_RemoveScheduledTasks(...) (failAt!=5)
#define ServiceDeploy_StopServiceAndWait(...) (failAt!=6)
#define ServiceHost_UnregisterServiceHostService(...) (++unregistered,failAt!=7)
#define ServiceDeploy_WaitForServiceAbsence(...) (failAt!=8)
#define Security_RemoveFirewallRuleForService(...) (failAt!=9)
#define ServiceDeploy_DeleteServiceStateRegistryTree(...) (failAt!=10)
#define Security_RemoveFirewallRulesByExePath(...) (failAt!=11)
#define ServiceDeploy_RemoveFileIfExists(...) (++files,failAt!=12)
#define ServiceDeploy_RemoveDirectoryTree(...) (++files,failAt!=13)
#define ServiceDeploy_DiscoverCurrentState discover
#define ServiceDeploy_LogInstallEvent(...) ((void)0)
#define ServiceBinding_Capture(...) ((ServiceBindingSnapshot*)1)
#define ServiceDeploy_CleanupConflictingServiceAliases(...) 0
#define ServiceDeploy_CollectConflictingServiceAliases(...) (failAt==15?(size_t)-1:0)
#define MeshConfig_GetPersistence() ((const mesh_persistence_profile_t*)1)
#define Sleep(...) ((void)0)
'''
uninstall_cases = r'''
int main(void){
    for(failAt=1;failAt<=14;++failAt){
        files=unregistered=0;assert(!ServiceDeploy_ApplyUninstallFlow());
        if(failAt<=11)assert(!files);
        if(failAt<=6||(failAt>=9&&failAt<=11))assert(!unregistered);
    }
    failAt=0;assert(ServiceDeploy_ApplyUninstallFlow());
    failAt=15;files=unregistered=0;assert(!ServiceDeploy_ApplyUninstallFlow()&&!files&&!unregistered);
    failAt=0;
    absent=1;assert(ServiceDeploy_ApplyUninstallFlow());
    puts("Uninstall orchestration: 15 failures, retained identity before metadata/SCM cleanup, no false clean success and absent-service retry passed");return 0;
}
'''
uninstall_flow = extract('ServiceDeploy_ApplyUninstallFlow')
mocked = set(re.findall(r'^#define (\w+)', uninstall_prelude, re.M))
calls = set(re.findall(r'\b((?:ServiceDeploy_|ServiceBinding_|ServiceHost_|Security_|MeshInstaller_)\w+)\s*\(', uninstall_flow))
generic = '\n'.join(f'#define {name}(...) 1' for name in sorted(calls - mocked - {'ServiceDeploy_ApplyUninstallFlow'}))
with tempfile.TemporaryDirectory(prefix='mesh-persistence-uninstall-') as directory:
    c = Path(directory) / 'uninstall.c'
    exe = Path(directory) / 'uninstall.exe'
    c.write_text(uninstall_prelude + generic + '\n' + uninstall_flow + uninstall_cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wno-unused-value', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

stop_prelude = r'''
#include <windows.h>
#include <assert.h>
#include <stdio.h>
static int opens,closes,denied,managerDenied,raced;
static SC_HANDLE fixture_manager(void){return managerDenied?NULL:(SC_HANDLE)1;}
static SC_HANDLE fixture_service(void){++opens;SetLastError(denied&&!(raced&&opens==2)?ERROR_ACCESS_DENIED:ERROR_SERVICE_DOES_NOT_EXIST);return NULL;}
static BOOL fixture_close(SC_HANDLE h){assert(h==(SC_HANDLE)1);++closes;SetLastError(ERROR_INVALID_HANDLE);return TRUE;}
#define OpenSCManagerW(...) fixture_manager()
#define OpenServiceW(...) fixture_service()
#define CloseServiceHandle fixture_close
#define ChangeServiceConfig2W(...) FALSE
#define QueryServiceStatusEx(...) FALSE
#define ControlService(...) FALSE
#define OpenProcess(...) NULL
#define TerminateProcess(...) FALSE
#define ServiceDeploy_LogInstallEvent(...) ((void)0)
'''
stop_cases = r'''
int main(void){
    assert(ServiceDeploy_StopServiceAndWait(L"AbsentAgent",0,TRUE)&&opens==1&&closes==1);
    opens=closes=0;assert(ServiceDeploy_ClearServiceRecovery(L"AbsentAgent")&&opens==1&&closes==1);
    opens=closes=0;denied=1;assert(!ServiceDeploy_StopServiceAndWait(L"AbsentAgent",0,TRUE)&&GetLastError()==ERROR_ACCESS_DENIED);
    opens=closes=0;assert(!ServiceDeploy_ClearServiceRecovery(L"AbsentAgent")&&GetLastError()==ERROR_ACCESS_DENIED);
    opens=closes=0;raced=1;assert(ServiceDeploy_StopServiceAndWait(L"AbsentAgent",0,TRUE)&&opens==2);
    managerDenied=1;assert(!ServiceDeploy_StopServiceAndWait(L"AbsentAgent",0,TRUE));
    puts("SCM quiescence: confirmed absence is idempotent; denied inspection remains failure");return 0;
}
'''
stop_flow = extract('ServiceDeploy_StopServiceAndWait') + extract('ServiceDeploy_ClearServiceRecovery')
mocked = set(re.findall(r'^#define (\w+)', stop_prelude, re.M))
calls = set(re.findall(r'\b((?:ServiceDeploy_|ServiceBinding_|ServiceHost_|ServiceUtil_|MeshService_|Security_)\w+)\s*\(', stop_flow))
generic = '\n'.join(f'#define {name}(...) 1' for name in sorted(calls - mocked - {'ServiceDeploy_StopServiceAndWait', 'ServiceDeploy_ClearServiceRecovery'}))
with tempfile.TemporaryDirectory(prefix='mesh-persistence-stop-') as directory:
    c = Path(directory) / 'stop.c'
    exe = Path(directory) / 'stop.exe'
    c.write_text(stop_prelude + generic + '\n' + stop_flow + stop_cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wno-unused-value', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

# Raw presence queries must not confuse malformed values or denied access with
# absence. Compile the real query helpers against injected registry/COM APIs.
query_prelude = r'''
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <stdio.h>
#define SERVICE_TASK_NAME_MAX 260
static LONG openResult,queryResult;static int closes,queryFailure,taskPresent,monitorPresent;
static BOOL g_HaveServiceRecoveryStatePath=TRUE;
static wchar_t g_ServiceRecoveryStatePath[]=L"state.ini";
static int statePresent,stateDenied;
static LSTATUS fixture_open(HKEY root,const wchar_t* path,DWORD options,REGSAM access,HKEY* out){(void)root;(void)path;(void)options;(void)access;*out=(HKEY)1;return openResult;}
static LSTATUS fixture_query(HKEY key,const wchar_t* name,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD bytes){(void)key;(void)name;(void)reserved;assert(!type&&!data);*bytes=65536;return queryResult;}
static LSTATUS fixture_close(HKEY key){(void)key;++closes;SetLastError(ERROR_INVALID_HANDLE);return ERROR_SUCCESS;}
static DWORD fixture_attributes(const wchar_t* path){(void)path;SetLastError(stateDenied?ERROR_ACCESS_DENIED:ERROR_FILE_NOT_FOUND);return statePresent?0:INVALID_FILE_ATTRIBUTES;}
static BOOL query_tasks(const wchar_t* prefix,BOOL* found){assert(!wcscmp(prefix,L"Agent-West-"));*found=taskPresent;return queryFailure!=1;}
static BOOL query_monitors(const wchar_t* f,const wchar_t* c,BOOL* found){(void)c;assert(wcsstr(f,L"Agent-West_")==f);*found=monitorPresent;return queryFailure!=2;}
#define RegOpenKeyExW fixture_open
#define RegQueryValueExW fixture_query
#define RegCloseKey fixture_close
#define GetFileAttributesW fixture_attributes
#define FaultRecovery_QueryTasksByPrefix query_tasks
#define FaultRecovery_QueryServiceRecoveryMonitorsByPrefix query_monitors
#define ServiceDeploy_GetServiceRecoveryStateDirectory(out,n) SUCCEEDED(StringCchCopyW(out,n,L"state"))
#define MeshInstaller_CombinePath(out,n,dir,leaf) SUCCEEDED(StringCchPrintfW(out,n,L"%ls\\%ls",dir,leaf))
'''
query_cases = r'''
int main(void){
    BOOL present=FALSE;
    assert(ServiceDeploy_QueryRunKeyPresence(L"Agent",&present)&&present&&closes==1);
    queryResult=ERROR_FILE_NOT_FOUND;assert(ServiceDeploy_QueryRunKeyPresence(L"Agent",&present)&&!present);
    queryResult=ERROR_ACCESS_DENIED;assert(!ServiceDeploy_QueryRunKeyPresence(L"Agent",&present)&&GetLastError()==ERROR_ACCESS_DENIED);
    openResult=ERROR_ACCESS_DENIED;assert(!ServiceDeploy_QueryRunKeyPresence(L"Agent",&present));
    openResult=ERROR_PATH_NOT_FOUND;assert(ServiceDeploy_QueryRunKeyPresence(L"Agent",&present)&&!present);
    assert(ServiceDeploy_QueryRecoveryStatePresence(&present)&&!present);
    statePresent=1;assert(ServiceDeploy_QueryRecoveryStatePresence(&present)&&present);
    statePresent=0;stateDenied=1;assert(!ServiceDeploy_QueryRecoveryStatePresence(&present));
    wchar_t candidates[1][260]={L"Agent-West"};BOOL tasks=FALSE,monitors=FALSE;
    assert(ServiceDeploy_QueryRecoveryArtifacts(candidates,1,&tasks,&monitors)&&!tasks&&!monitors);
    taskPresent=monitorPresent=1;assert(ServiceDeploy_QueryRecoveryArtifacts(candidates,1,&tasks,&monitors)&&tasks&&monitors);
    for(queryFailure=1;queryFailure<=2;++queryFailure)assert(!ServiceDeploy_QueryRecoveryArtifacts(candidates,1,&tasks,&monitors));
    wchar_t sanitized[260],longName[260];
    ServiceDeploy_SanitizeTaskHint(L"Agent-West.One",sanitized,260);assert(!wcscmp(sanitized,L"Agent-West_One"));
    for(int i=0;i<259;++i)longName[i]=L'A';longName[259]=0;
    ServiceDeploy_SanitizeTaskHint(longName,sanitized,260);assert(wcslen(sanitized)==120);
    puts("Persistence inspection: raw registry values, denied enumeration, orphan presence and name normalization passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-persistence-query-') as directory:
    c = Path(directory) / 'query.c'
    exe = Path(directory) / 'query.exe'
    c.write_text(query_prelude + '\n'.join(extract(n) for n in ('ServiceDeploy_QueryRunKeyPresence',
        'ServiceDeploy_QueryRecoveryStatePresence', 'ServiceDeploy_QueryRecoveryArtifacts', 'ServiceDeploy_SanitizeTaskHint')) + query_cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
