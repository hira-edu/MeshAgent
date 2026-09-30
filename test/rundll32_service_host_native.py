#!/usr/bin/env python3
"""Compile the production primary-host contract with fault-injected Win32 APIs.

No services are installed or processes launched. Requires Python and a C compiler.
This covers command admission, SCM registration and callback dispatch; Windows
SCM/rundll32 integration still requires the built bundle on an approved host.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'meshservice/service_host.c').read_text()
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                lambda m: ' ' * len(m.group()), source, flags=re.S)
def extract(name):
    match = re.search(r'(?:static )?(?:BOOL|void) (?:CALLBACK )?' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]

prelude = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <setjmp.h>
typedef int BOOL;
typedef uint32_t DWORD;
typedef unsigned char BYTE;
typedef long LONG;
typedef void *HKEY, *SC_HANDLE, *HWND, *HINSTANCE;
typedef wchar_t* LPWSTR;
typedef struct { DWORD dwServiceType, dwStartType; wchar_t* lpServiceStartName; } QUERY_SERVICE_CONFIGW;
typedef struct { DWORD dwServiceSidType; } SERVICE_SID_INFO;
typedef struct { wchar_t* lpDescription; } SERVICE_DESCRIPTIONW;
typedef struct { wchar_t* lpServiceName; void (*lpServiceProc)(DWORD, LPWSTR*); } SERVICE_TABLE_ENTRYW;
#define TRUE 1
#define FALSE 0
#define CALLBACK
#define MAX_PATH 260
#define ERROR_SUCCESS 0
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INVALID_NAME 123
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_SERVICE_EXISTS 1073
#define ERROR_SERVICE_SPECIFIC_ERROR 1066
#define ERROR_NOT_SUPPORTED 50
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_ACCESS_DENIED 5
#define SERVICE_WIN32_OWN_PROCESS 16
#define SERVICE_AUTO_START 2
#define SERVICE_ERROR_NORMAL 1
#define SERVICE_QUERY_CONFIG 1
#define SERVICE_CHANGE_CONFIG 2
#define SERVICE_START 4
#define SERVICE_QUERY_STATUS 8
#define DELETE 16
#define SC_MANAGER_CONNECT 1
#define SC_MANAGER_CREATE_SERVICE 2
#define SERVICE_SID_TYPE_UNRESTRICTED 1
#define SERVICE_CONFIG_SERVICE_SID_INFO 5
#define SERVICE_CONFIG_DESCRIPTION 1
#define KEY_QUERY_VALUE 1
#define KEY_SET_VALUE 2
#define REG_MULTI_SZ 7
#define HKEY_LOCAL_MACHINE ((HKEY)1)
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#define _wcsicmp wcscasecmp
#define FAILED(x) ((x) < 0)
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define CP_UTF8 65001
#define WC_ERR_INVALID_CHARS 128
#define wcsnlen_s wcsnlen
#define StringCchCopyW(a,b,c) wcscpy(a,c)
#define MESH_RUNDLL32_ENTRY_SERVICE_W L"MeshServiceHostW"
static DWORD lastError, exitCode;
static wchar_t g_ServiceHostServiceName[256];
static char g_ServiceHostServiceNameUtf8[1024], runtimeServiceName[1024];
static int WideCharToMultiByte(unsigned cp,unsigned flags,const wchar_t* input,int n,char* output,int capacity,void* fallback,void* used) {
    (void)cp;(void)flags;(void)n;(void)fallback;(void)used;
    size_t length=wcslen(input); if(length+1>(size_t)capacity)return 0;
    for(size_t i=0;i<=length;++i)output[i]=(char)input[i]; return (int)length+1;
}
static void ServiceDeploy_SetRuntimeServiceKeyNameUtf8(const char* value) { strcpy(runtimeServiceName,value); }

static int installed, customAccount, changeCalls, config2Calls, deletes, registryWrites, dispatches;
static int failApi, apiIndex, badModule, badProcess, dispatcherFails, runtimeFails;
static wchar_t command[2080], registeredCommand[2080], group[64];
static DWORD groupBytes;
static DWORD registeredType;
static jmp_buf exitJump;
static struct { DWORD dwWin32ExitCode, dwServiceSpecificExitCode; } g_ServiceHostStatus;
static int step(void) { if (++apiIndex == failApi) { lastError = ERROR_ACCESS_DENIED; return 0; } return 1; }
static void SetLastError(DWORD value) { lastError = value; }
static DWORD GetLastError(void) { return lastError; }
static int StringCchPrintfW(wchar_t* out, size_t count, const wchar_t* format, ...) {
    va_list args; va_start(args,format); int result = vswprintf(out,count,format,args); va_end(args);
    return result < 0 || (size_t)result >= count ? -1 : 0;
}
static DWORD GetFullPathNameW(const wchar_t* path, DWORD count, wchar_t* out, void* unused) {
    (void)unused; if (!path[0] || count < wcslen(path)+1) return 0;
    if (path[0] != L'C' || path[1] != L':') { wcscpy(out,L"C:\\relative"); return (DWORD)wcslen(out); }
    wcscpy(out,path); return (DWORD)wcslen(out);
}
static BOOL MeshRundll32_GetSystemRundll32PathW(wchar_t* out, size_t count) {
    const wchar_t* value=L"C:\\Windows\\System32\\rundll32.exe";
    if (count <= wcslen(value)) return FALSE; wcscpy(out,value); return TRUE;
}
static const wchar_t* GetCommandLineW(void) { return command; }
static DWORD GetModuleFileNameW(HINSTANCE module, wchar_t* out, DWORD count) {
    (void)count; wcscpy(out,module ? (badModule ? L"C:\\wrong.dll" : L"C:\\Agent\\bundle.dll") :
        (badProcess ? L"C:\\fake\\rundll32.exe" : L"C:\\Windows\\System32\\rundll32.exe")); return (DWORD)wcslen(out);
}
static void ServiceDeploy_ResolveRuntimeServiceBranding(wchar_t* name,size_t nameCount,wchar_t* display,size_t displayCount,wchar_t* description,size_t descriptionCount) {
    (void)name;(void)nameCount;(void)displayCount;(void)descriptionCount;
    wcscpy(display,L"Operator Display Override"); wcscpy(description,L"Operator Description Override");
}
#define ServiceHost_LogLine(...) ((void)0)
static void ServiceHost_ServiceMain(DWORD argc, LPWSTR* argv) {
    (void)argc; (void)argv; g_ServiceHostStatus.dwWin32ExitCode = runtimeFails ? ERROR_SERVICE_SPECIFIC_ERROR : 0;
    g_ServiceHostStatus.dwServiceSpecificExitCode = runtimeFails ? 71 : 0;
}
static BOOL StartServiceCtrlDispatcherW(SERVICE_TABLE_ENTRYW* table) {
    ++dispatches; assert(table[0].lpServiceName && table[0].lpServiceName[0]==0); assert(!table[1].lpServiceName && !table[1].lpServiceProc);
    if (dispatcherFails) { lastError=1063; return FALSE; } table[0].lpServiceProc(0,NULL); return TRUE;
}
static void ExitProcess(DWORD code) { exitCode=code; longjmp(exitJump,1); }
static SC_HANDLE OpenSCManagerW(void* a,void* b,DWORD access) { (void)a;(void)b;(void)access; return step() ? (SC_HANDLE)1 : NULL; }
static SC_HANDLE CreateServiceW(SC_HANDLE scm,const wchar_t* name,const wchar_t* display,DWORD access,DWORD type,DWORD start,DWORD error,
    const wchar_t* image,const wchar_t* groupName,DWORD* tag,const wchar_t* deps,const wchar_t* account,const wchar_t* password) {
    (void)scm;(void)name;(void)display;(void)access;(void)start;(void)error;(void)groupName;(void)tag;(void)deps;
    assert(wcscmp(display,L"Operator Display Override")==0); assert(!password && wcscmp(account,L"LocalSystem")==0); if (!step()) return NULL;
    if (installed) { lastError=ERROR_SERVICE_EXISTS; return NULL; }
    installed=1; registeredType=type; wcscpy(registeredCommand,image); return (SC_HANDLE)2;
}
static SC_HANDLE OpenServiceW(SC_HANDLE scm,const wchar_t* name,DWORD access) { (void)scm;(void)name;(void)access; return step()?(SC_HANDLE)2:NULL; }
static BOOL QueryServiceConfigW(SC_HANDLE service,QUERY_SERVICE_CONFIGW* config,DWORD size,DWORD* bytes) {
    (void)service;(void)size; *bytes=sizeof(*config); if (!step()) return FALSE;
    if (!config) { lastError=ERROR_INSUFFICIENT_BUFFER; return FALSE; }
    config->lpServiceStartName=customAccount?L"Domain\\operator":L"LocalSystem"; return TRUE;
}
static BOOL ChangeServiceConfigW(SC_HANDLE service,DWORD type,DWORD start,DWORD error,const wchar_t* image,const wchar_t* groupName,
    DWORD* tag,const wchar_t* deps,const wchar_t* account,const wchar_t* password,const wchar_t* display) {
    (void)service;(void)start;(void)error;(void)groupName;(void)tag;(void)deps;(void)display;
    assert(wcscmp(display,L"Operator Display Override")==0); assert(!account && !password); ++changeCalls; if (!step()) return FALSE;
    registeredType=type; wcscpy(registeredCommand,image); return TRUE;
}
static BOOL ChangeServiceConfig2W(SC_HANDLE service,DWORD level,void* config) { (void)service; if(level==SERVICE_CONFIG_DESCRIPTION) assert(wcscmp(((SERVICE_DESCRIPTIONW*)config)->lpDescription,L"Operator Description Override")==0); ++config2Calls; return step(); }
#define CloseServiceHandle(x) ((void)(x))
static LONG RegOpenKeyExW(HKEY root,const wchar_t* name,DWORD options,DWORD access,HKEY* key) {
    (void)root;(void)options;(void)access; if (!step()) return ERROR_ACCESS_DENIED;
    *key=wcsstr(name,L"Parameters")?(HKEY)2:(HKEY)3; return ERROR_SUCCESS;
}
static LONG RegDeleteValueW(HKEY key,const wchar_t* name) {
    (void)key; assert(wcscmp(name,L"ServiceDllHash")!=0); ++deletes; return step()?ERROR_SUCCESS:ERROR_ACCESS_DENIED;
}
static LONG RegQueryValueExW(HKEY key,const wchar_t* name,void* reserved,DWORD* type,BYTE* bytes,DWORD* size) {
    (void)key;(void)name;(void)reserved; if (!step()) return ERROR_ACCESS_DENIED; *type=REG_MULTI_SZ;
    if (bytes) { assert(*size>=groupBytes); memcpy(bytes,group,groupBytes); } *size=groupBytes; return ERROR_SUCCESS;
}
static LONG RegSetValueExW(HKEY key,const wchar_t* name,DWORD reserved,DWORD type,const BYTE* bytes,DWORD size) {
    (void)key;(void)reserved; assert(wcscmp(name,L"netsvcs")==0 && type==REG_MULTI_SZ); ++registryWrites;
    if (!step()) return ERROR_ACCESS_DENIED; memcpy(group,bytes,size); groupBytes=size; return ERROR_SUCCESS;
}
#define RegCloseKey(x) ((void)(x))
static void reset(void) {
    installed=1; customAccount=changeCalls=config2Calls=deletes=registryWrites=dispatches=0;
    failApi=apiIndex=badModule=badProcess=dispatcherFails=runtimeFails=0; registeredType=32; registeredCommand[0]=0;
    static const wchar_t members[]=L"Other\0Agent\0Third\0"; memcpy(group,members,sizeof(members)); groupBytes=sizeof(members);
}
'''
prelude = prelude.replace('#include <setjmp.h>', '#include <setjmp.h>\n#include <stdarg.h>')
functions = '\n'.join(extract(name) for name in [
    'ServiceHost_BuildImagePath', 'ServiceHost_ParseImagePath', 'ServiceHost_AcceptScmName', 'MeshServiceHostW',
    'ServiceHost_RemoveLegacyGroupMembership', 'ServiceHost_RemoveLegacyParameters', 'ServiceHost_RegisterServiceHostService'])
cases = r'''
int main(void) {
    wchar_t parsed[1040]; reset();
    wchar_t* scmArgs[] = {L"Operator Renamed Service", NULL};
    assert(ServiceHost_AcceptScmName(1,scmArgs));
    assert(wcscmp(g_ServiceHostServiceName,scmArgs[0])==0 && strcmp(runtimeServiceName,"Operator Renamed Service")==0);
    assert(!ServiceHost_AcceptScmName(0,scmArgs) && !ServiceHost_AcceptScmName(1,NULL));
    scmArgs[0]=L"invalid\\key"; assert(!ServiceHost_AcceptScmName(1,scmArgs));
    scmArgs[0]=L""; assert(!ServiceHost_AcceptScmName(1,scmArgs));
    wchar_t oversized[257]; for(int i=0;i<256;++i)oversized[i]=L'x'; oversized[256]=0;
    scmArgs[0]=oversized; assert(!ServiceHost_AcceptScmName(1,scmArgs));
    assert(ServiceHost_BuildImagePath(L"C:\\Agent\\bundle.dll",command,2080));
    assert(ServiceHost_ParseImagePath(command,parsed,1040) && wcscmp(parsed,L"C:\\Agent\\bundle.dll")==0);
    assert(!ServiceHost_BuildImagePath(L"relative.dll",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"C:\\Agent\\bundle.exe",parsed,1040));
    assert(ServiceHost_BuildImagePath(L"C:\\Agent\\BUNDLE.DLL",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"C:\\bad,name.dll",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"C:\\bad:name.dll",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"C:/bad.dll",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"C:\\bad*.dll",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"\\\\server\\share\\bundle.dll",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"C:\\bad\"name.dll",parsed,1040));
    assert(!ServiceHost_BuildImagePath(L"C:\\Agent\\bundle.dll",parsed,8));
    assert(!ServiceHost_ParseImagePath(L"\"C:\\fake\\rundll32.exe\" \"C:\\Agent\\bundle.dll\",MeshServiceHostW",parsed,1040));
    assert(!ServiceHost_ParseImagePath(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\bundle.dll\",MeshLifecycleHostW",parsed,1040));
    wcscat(command,L" extra"); assert(!ServiceHost_ParseImagePath(command,parsed,1040));
    ServiceHost_BuildImagePath(L"C:\\Agent\\bundle.dll",command,2080);
    for (int mode=0;mode<5;++mode) {
        reset(); badModule=mode==1; badProcess=mode==2; dispatcherFails=mode==3; runtimeFails=mode==4;
        if (!setjmp(exitJump)) MeshServiceHostW(NULL,(HINSTANCE)1,L"untrusted ANSI bytes",0);
        assert(exitCode==(mode==0?0:mode==3?1063:mode==4?71:ERROR_INVALID_PARAMETER));
        assert(dispatches==(mode==1||mode==2?0:1));
    }
    reset(); assert(ServiceHost_RegisterServiceHostService(L"Agent",L"C:\\Agent\\bundle.dll"));
    int boundaries=apiIndex; assert(changeCalls==1 && registeredType==SERVICE_WIN32_OWN_PROCESS && deletes==3 && registryWrites==1);
    assert(ServiceHost_ParseImagePath(registeredCommand,parsed,1040));
    static const wchar_t expected[]=L"Other\0Third\0";
    assert(groupBytes==sizeof(expected) && memcmp(group,expected,sizeof(expected))==0);
    for (int fail=1;fail<=boundaries;++fail) {
        reset(); failApi=fail; assert(!ServiceHost_RegisterServiceHostService(L"Agent",L"C:\\Agent\\bundle.dll"));
    }
    reset(); customAccount=1; assert(!ServiceHost_RegisterServiceHostService(L"Agent",L"C:\\Agent\\bundle.dll"));
    assert(changeCalls==0 && config2Calls==0 && deletes==0 && registryWrites==0);
    reset(); installed=0; assert(ServiceHost_RegisterServiceHostService(L"Agent",L"C:\\Agent\\bundle.dll"));
    assert(changeCalls==0 && registeredType==SERVICE_WIN32_OWN_PROCESS);
    puts("rundll32 primary host: command admission, callback dispatch, account preservation and registration faults passed");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='meshagent-service-host-') as directory:
    c_path = Path(directory) / 'host.c'
    executable = Path(directory) / ('host.exe' if os.name == 'nt' else 'host')
    c_path.write_text(prelude + functions + cases)
    subprocess.run([os.environ.get('CC','cc'), '-std=c11', '-Wall', '-Wextra', str(c_path), '-o', str(executable)],check=True)
    subprocess.run([str(executable)],check=True)
