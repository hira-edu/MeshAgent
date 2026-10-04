"""Exercise production migration ownership and cleanup with real temporary files.

SCM/datastore observations are injected; filesystem enumeration and deletion
use Win32. No services, real agent keys, or non-fixture files are changed.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/service_deployment.c').read_text()


def extract(name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'static (?:BOOL|const wchar_t\*)\s*' + name + r'\s*\([^;{]+\)\s*\{', masked)
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
#include <wchar.h>
#define IDR_SERVICE_BUNDLE_DLL 101
typedef struct {wchar_t installDir[MAX_PATH],logsDir[MAX_PATH],exePath[MAX_PATH],dllPath[MAX_PATH],dbPath[MAX_PATH],confPath[MAX_PATH],logPath[MAX_PATH];} ServiceInstallPaths;
typedef struct {BOOL nodeIdPresent,meshIdPresent,serverIdPresent,meshServerPresent;int nodeIdLen;char nodeId[256];} ServiceIdentitySnapshot;
typedef struct {wchar_t payload[MAX_PATH],incumbentExePath[MAX_PATH],incumbentDllPath[MAX_PATH],incumbentDbPath[MAX_PATH];} ServiceBindingSnapshot;
typedef struct {wchar_t serviceKeyName[256];BOOL hasServiceKeyName;} Overrides;
static Overrides g_RuntimeBrandingOverrides;
static ServiceInstallPaths g_IncumbentPaths,current;
static BOOL g_HaveIncumbentPaths;
static wchar_t fixtureDir[MAX_PATH],payload[MAX_PATH],missingPayload[MAX_PATH],secondDb[MAX_PATH],alien[MAX_PATH];
static int services,enumFailure,known=1,accountAllowed=1,identityReadable=1,activeExists,canonicalMismatch,deleteFault;
static void ServiceDeploy_LogInstallEvent(const wchar_t* f,...){(void)f;}
static BOOL MeshInstaller_CombinePath(wchar_t* o,size_t c,const wchar_t* r,const wchar_t* l){return SUCCEEDED(StringCchPrintfW(o,c,L"%ls\\%ls",r,l));}
static const wchar_t* MeshInstaller_GetPathLeaf(const wchar_t* p){const wchar_t* leaf=wcsrchr(p,L'\\');return leaf?leaf+1:p;}
static BOOL ServiceDeploy_CaptureIdentitySnapshot(const wchar_t* p,ServiceIdentitySnapshot* s){
    ZeroMemory(s,sizeof(*s));if(!identityReadable||GetFileAttributesW(p)==INVALID_FILE_ATTRIBUTES)return FALSE;
    size_t length=wcslen(p);if(length<4||(_wcsicmp(p+length-3,L".db")&&_wcsicmp(p+length-4,L".ini")&&_wcsicmp(p+length-4,L".bak")&&_wcsicmp(p+length-4,L".tmp")))return FALSE;
    s->nodeIdPresent=s->meshIdPresent=s->serverIdPresent=s->meshServerPresent=TRUE;s->nodeIdLen=48;memset(s->nodeId,3,48);
    if(canonicalMismatch&&!_wcsicmp(p,current.dbPath))memset(s->nodeId,4,48);return TRUE;
}
static BOOL ServiceDeploy_PathExists(const wchar_t* p){return GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}
static BOOL ServiceDeploy_SelectJournalService(const ServiceInstallPaths* p,BOOL* found){(void)p;*found=FALSE;return TRUE;}
static BOOL ServiceDeploy_GetInstallPaths(ServiceInstallPaths* p){*p=current;return TRUE;}
static void ServiceDeploy_ResolveRuntimeServiceBranding(wchar_t* o,size_t n,...){StringCchCopyW(o,n,g_RuntimeBrandingOverrides.hasServiceKeyName?g_RuntimeBrandingOverrides.serviceKeyName:L"CurrentAgent");}
static BOOL ServiceBinding_QueryExists(const wchar_t* n,BOOL* out){(void)n;*out=activeExists;return TRUE;}
static BOOL ServiceDeploy_IsLegacyMeshAgentService(const wchar_t* n,wchar_t* o,size_t cap){(void)n;StringCchCopyW(o,cap,payload);return known;}
static BOOL ServiceDeploy_QueryServiceImagePathW(const wchar_t* n,wchar_t* o,size_t cap){(void)n;return SUCCEEDED(StringCchPrintfW(o,cap,L"\"%ls\" -run",payload));}
static BOOL ServiceDeploy_ExtractExecutableFromCommand(const wchar_t* n,wchar_t* o,size_t cap){(void)n;return SUCCEEDED(StringCchCopyW(o,cap,payload));}
static BOOL ServiceDeploy_BindingPayloadPath(const ServiceBindingSnapshot* b,wchar_t* p,size_t n){return SUCCEEDED(StringCchCopyW(p,n,b->payload));}
static ServiceBindingSnapshot binding;
static ServiceBindingSnapshot* ServiceBinding_Capture(const wchar_t* n,const wchar_t* e,const wchar_t* d){(void)n;(void)e;(void)d;return accountAllowed?&binding:NULL;}
static void ServiceBinding_Free(ServiceBindingSnapshot* b){(void)b;}
static LSTATUS openServices(HKEY k,const wchar_t* p,DWORD r,REGSAM a,HKEY* o){(void)k;(void)p;(void)r;(void)a;*o=(HKEY)1;return ERROR_SUCCESS;}
static LSTATUS enumServices(HKEY k,DWORD i,wchar_t* n,DWORD* len,DWORD* r,wchar_t* c,DWORD* cl,FILETIME* t){
    (void)k;(void)r;(void)c;(void)cl;(void)t;if(enumFailure&&i==1)return ERROR_ACCESS_DENIED;
    if(i>=(DWORD)services)return ERROR_NO_MORE_ITEMS;StringCchPrintfW(n,*len,L"HistoricalService%lu",i);return ERROR_SUCCESS;
}
static LSTATUS closeServices(HKEY k){(void)k;return ERROR_SUCCESS;}
#define RegOpenKeyExW openServices
#define RegEnumKeyExW enumServices
#define RegCloseKey closeServices
static BOOL ServiceDeploy_BuildInstalledMshPath(const wchar_t* p,wchar_t* o,size_t c);
static void ServiceDeploy_LogPathState(const wchar_t* p){(void)p;}
static BOOL fixtureDeleteFile(const wchar_t* p){if(deleteFault&&!_wcsicmp(p,payload)){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return DeleteFileW(p);}
#define DeleteFileW fixtureDeleteFile
'''

cases = r'''
static BOOL ServiceDeploy_BuildInstalledMshPath(const wchar_t* p,wchar_t* o,size_t c){return ServiceDeploy_BuildSiblingPathWithExtension(p,L".msh",o,c);}
static void create(const wchar_t* p){HANDLE h=CreateFileW(p,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);assert(h!=INVALID_HANDLE_VALUE);CloseHandle(h);}
static void reset(void){ZeroMemory(&g_RuntimeBrandingOverrides,sizeof(g_RuntimeBrandingOverrides));services=1;enumFailure=0;known=accountAllowed=identityReadable=1;activeExists=canonicalMismatch=deleteFault=0;}
int wmain(int argc,wchar_t** argv){
    assert(argc==4);StringCchCopyW(fixtureDir,_countof(fixtureDir),argv[1]);
    assert(ServiceDeploy_EmbeddedPayloadMatchesDll(argv[2],argv[3]));
    assert(MeshInstaller_CombinePath(current.installDir,_countof(current.installDir),fixtureDir,L"current"));assert(CreateDirectoryW(current.installDir,NULL));
    assert(MeshInstaller_CombinePath(current.exePath,_countof(current.exePath),current.installDir,L"diaghost.exe"));
    assert(MeshInstaller_CombinePath(current.dllPath,_countof(current.dllPath),current.installDir,L"diagsvc.dll"));
    assert(MeshInstaller_CombinePath(current.dbPath,_countof(current.dbPath),current.installDir,L"diaghost.db"));
    assert(MeshInstaller_CombinePath(current.confPath,_countof(current.confPath),current.installDir,L"diaghost.conf"));
    assert(MeshInstaller_CombinePath(payload,_countof(payload),fixtureDir,L"Custom Telemetry.exe"));create(payload);
    wchar_t db[MAX_PATH],msh[MAX_PATH],conf[MAX_PATH];ServiceInstallPaths found;
    assert(MeshInstaller_CombinePath(db,_countof(db),fixtureDir,L"HistoricalIdentity.db"));create(db);
    assert(MeshInstaller_CombinePath(secondDb,_countof(secondDb),fixtureDir,L"OtherIdentity.db"));
    assert(MeshInstaller_CombinePath(alien,_countof(alien),fixtureDir,L"unrelated.txt"));create(alien);
    reset();assert(ServiceDeploy_FindIncumbentPaths(payload,&found));assert(!_wcsicmp(found.dbPath,db));
    wchar_t renamedDb[MAX_PATH];assert(MeshInstaller_CombinePath(renamedDb,_countof(renamedDb),fixtureDir,L"LegacyState.ini"));
    assert(MoveFileW(db,renamedDb));assert(ServiceDeploy_FindIncumbentPaths(payload,&found)&&!_wcsicmp(found.dbPath,renamedDb));assert(MoveFileW(renamedDb,db));
    assert(ServiceDeploy_SelectIncumbent()&&g_HaveIncumbentPaths&&!wcscmp(g_RuntimeBrandingOverrides.serviceKeyName,L"HistoricalService0"));
    reset();known=0;assert(ServiceDeploy_SelectIncumbent()&&g_HaveIncumbentPaths); /* custom branded EXE */
    reset();services=2;assert(!ServiceDeploy_SelectIncumbent()&&!g_RuntimeBrandingOverrides.hasServiceKeyName);
    reset();services=40;assert(!ServiceDeploy_SelectIncumbent()); /* no fixed-capacity truncation */
    reset();enumFailure=1;assert(!ServiceDeploy_SelectIncumbent()&&!g_RuntimeBrandingOverrides.hasServiceKeyName);
    reset();accountAllowed=0;assert(!ServiceDeploy_SelectIncumbent());
    reset();identityReadable=0;assert(!ServiceDeploy_SelectIncumbent()); /* no accidental fresh identity */
    wchar_t backup[MAX_PATH];assert(SUCCEEDED(StringCchPrintfW(backup,_countof(backup),L"%ls.bak",db)));assert(CopyFileW(db,backup,TRUE));
    reset();assert(ServiceDeploy_FindIncumbentPaths(payload,&found)&&!_wcsicmp(found.dbPath,db));assert(DeleteFileW(backup));
    /* Interrupted copy and compaction temporaries duplicate the identity; they are ignored, not deleted. */
    wchar_t copyTemp[MAX_PATH],compactTemp[MAX_PATH];
    assert(MeshInstaller_CombinePath(copyTemp,_countof(copyTemp),fixtureDir,L"mcu1A2B.tmp"));assert(CopyFileW(db,copyTemp,TRUE));
    assert(SUCCEEDED(StringCchPrintfW(compactTemp,_countof(compactTemp),L"%ls.tmp",db)));assert(CopyFileW(db,compactTemp,TRUE));
    reset();assert(ServiceDeploy_FindIncumbentPaths(payload,&found)&&!_wcsicmp(found.dbPath,db));
    assert(ServiceDeploy_PathExists(copyTemp)&&ServiceDeploy_PathExists(compactTemp));assert(DeleteFileW(copyTemp)&&DeleteFileW(compactTemp));
    reset();create(secondDb);assert(!ServiceDeploy_FindIncumbentPaths(payload,&found));assert(!ServiceDeploy_SelectIncumbent());assert(DeleteFileW(secondDb));
    reset();create(current.dbPath);canonicalMismatch=1;assert(!ServiceDeploy_SelectIncumbent());assert(DeleteFileW(current.dbPath));
    reset();activeExists=1;StringCchCopyW(g_RuntimeBrandingOverrides.serviceKeyName,256,L"HistoricalService0");g_RuntimeBrandingOverrides.hasServiceKeyName=TRUE;
    assert(ServiceDeploy_SelectIncumbent()&&g_HaveIncumbentPaths&&!_wcsicmp(g_IncumbentPaths.dbPath,db)); /* active service in a moved root */
    /* The ordinary installed path skips the historical scan and keeps no incumbent paths. */
    reset();activeExists=1;identityReadable=0;
    wchar_t originalExe[MAX_PATH];StringCchCopyW(originalExe,MAX_PATH,current.exePath);StringCchCopyW(current.exePath,MAX_PATH,payload);
    assert(ServiceDeploy_SelectIncumbent()&&!g_HaveIncumbentPaths&&!g_IncumbentPaths.dbPath[0]);StringCchCopyW(current.exePath,MAX_PATH,originalExe);
    reset();assert(ServiceDeploy_SelectIncumbent());found=g_IncumbentPaths;
    assert(ServiceDeploy_BuildSiblingPathWithExtension(db,L".msh",msh,_countof(msh)));create(msh);
    assert(ServiceDeploy_BuildSiblingPathWithExtension(payload,L".conf",conf,_countof(conf)));create(conf);
    deleteFault=1;assert(!ServiceDeploy_RemoveIncumbentFiles(&found,&current,TRUE));assert(ServiceDeploy_PathExists(db));
    deleteFault=0;assert(ServiceDeploy_RemoveIncumbentFiles(&found,&current,FALSE));assert(!ServiceDeploy_PathExists(payload)&&ServiceDeploy_PathExists(db));
    assert(ServiceDeploy_RemoveIncumbentFiles(&found,&current,TRUE));assert(!ServiceDeploy_PathExists(db)&&ServiceDeploy_PathExists(alien));
    assert(ServiceDeploy_RemoveIncumbentFiles(&found,&current,TRUE));
    wchar_t dllRoot[MAX_PATH],dll[MAX_PATH],companion[MAX_PATH],duplicate[MAX_PATH],dllDb[MAX_PATH],state[MAX_PATH],stateFile[MAX_PATH];
    assert(MeshInstaller_CombinePath(dllRoot,_countof(dllRoot),fixtureDir,L"DLL Product"));assert(CreateDirectoryW(dllRoot,NULL));
    assert(MeshInstaller_CombinePath(dll,_countof(dll),dllRoot,L"Old Service.dll"));assert(CopyFileW(argv[3],dll,TRUE));
    assert(MeshInstaller_CombinePath(companion,_countof(companion),dllRoot,L"Old Product.exe"));assert(CopyFileW(argv[2],companion,TRUE));
    assert(MeshInstaller_CombinePath(duplicate,_countof(duplicate),dllRoot,L"Other Product.exe"));
    assert(MeshInstaller_CombinePath(dllDb,_countof(dllDb),dllRoot,L"Legacy Identity.db"));create(dllDb);
    assert(ServiceDeploy_FindIncumbentPaths(dll,&found)&&!_wcsicmp(found.exePath,companion)&&!_wcsicmp(found.dllPath,dll));
    assert(CopyFileW(argv[2],duplicate,TRUE));assert(ServiceDeploy_FindIncumbentPaths(dll,&found)&&!found.exePath[0]);assert(DeleteFileW(duplicate));
    create(duplicate);assert(ServiceDeploy_FindIncumbentPaths(dll,&found)); /* Unrelated EXE cannot establish ownership. */
    assert(MeshInstaller_CombinePath(state,_countof(state),dllRoot,L"state"));assert(CreateDirectoryW(state,NULL));
    assert(MeshInstaller_CombinePath(stateFile,_countof(stateFile),state,L"service-recovery.ini"));create(stateFile);
    StringCchCopyW(payload,_countof(payload),stateFile);deleteFault=1;
    assert(!ServiceDeploy_RemoveIncumbentFiles(&found,&current,TRUE)&&ServiceDeploy_PathExists(dllDb));
    deleteFault=0;assert(ServiceDeploy_RemoveIncumbentFiles(&found,&current,TRUE));
    assert(!ServiceDeploy_PathExists(dll)&&!ServiceDeploy_PathExists(companion)&&!ServiceDeploy_PathExists(dllDb)&&ServiceDeploy_PathExists(duplicate));
    /* Activation in the same root creates a second DB. Retirement uses the saved
     * paths instead of rediscovering the now-ambiguous directory. */
    assert(MeshInstaller_CombinePath(payload,MAX_PATH,fixtureDir,L"Old.exe"));create(payload);create(db);
    assert(ServiceDeploy_FindIncumbentPaths(payload,&found));
    StringCchCopyW(binding.payload,MAX_PATH,payload);StringCchCopyW(binding.incumbentExePath,MAX_PATH,found.exePath);StringCchCopyW(binding.incumbentDbPath,MAX_PATH,found.dbPath);
    ServiceInstallPaths activated={0};StringCchCopyW(activated.installDir,MAX_PATH,fixtureDir);
    assert(MeshInstaller_CombinePath(activated.exePath,MAX_PATH,fixtureDir,L"New.exe"));create(activated.exePath);
    StringCchCopyW(activated.dbPath,MAX_PATH,secondDb);create(secondDb);
    assert(ServiceDeploy_BuildSiblingPathWithExtension(activated.exePath,L".conf",activated.confPath,MAX_PATH));
    assert(!ServiceDeploy_FindIncumbentPaths(payload,&found));
    assert(ServiceDeploy_CheckpointIncumbentPaths(&binding,&found)&&!_wcsicmp(found.dbPath,db));
    StringCchCopyW(binding.incumbentExePath,MAX_PATH,activated.exePath);
    assert(!ServiceDeploy_CheckpointIncumbentPaths(&binding,&found)); /* Saved payload must match SCM ownership. */
    StringCchCopyW(binding.incumbentExePath,MAX_PATH,payload);
    assert(ServiceDeploy_RetireIncumbentFiles(&activated,&binding));
    assert(!ServiceDeploy_PathExists(db)&&ServiceDeploy_PathExists(secondDb)&&ServiceDeploy_PathExists(activated.exePath));
    assert(ServiceDeploy_RetireIncumbentFiles(&activated,&binding)); /* Retry after old DB deletion. */
    puts("Historical install paths: renamed/custom SCM selection, ambiguity, errors, identity conflict, bounded cleanup and retry passed");return 0;
}
'''
functions = '\n'.join(extract(n) for n in (
    'ServiceDeploy_wcsistr', 'ServiceDeploy_PathContainsLeafInsensitive',
    'ServiceDeploy_ExtractDirectoryFromPath', 'ServiceDeploy_BuildSiblingPathWithExtension',
    'ServiceDeploy_EmbeddedPayloadMatchesDll', 'ServiceDeploy_IsDuplicateDatabaseBackup', 'ServiceDeploy_FindIncumbentPaths', 'ServiceDeploy_SelectIncumbent', 'ServiceDeploy_RemoveFileIfExists', 'ServiceDeploy_RemoveIncumbentFiles', 'ServiceDeploy_CheckpointIncumbentPaths', 'ServiceDeploy_RetireIncumbentFiles'))
with tempfile.TemporaryDirectory(prefix='historical-install-') as temporary:
    path = Path(temporary)
    c, exe = path / 'fixture.c', path / 'fixture.exe'
    files = path / 'Old Product'
    files.mkdir()
    c.write_text(prelude + functions + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c), '-ladvapi32', '-o', str(exe)], check=True)
    subprocess.run([str(exe), str(files), str(ROOT / 'meshservice/x64/MeshServiceRuntime/MeshService-2022.exe'),
                    str(ROOT / 'meshservice/x64/MeshServiceBundle/MeshService-2022.dll')], check=True)
