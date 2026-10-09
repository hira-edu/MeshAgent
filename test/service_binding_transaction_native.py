#!/usr/bin/env python3
"""Run production binding selection/membership/restore helpers with Win32 mocks.

The portable harness never calls SCM or the registry. Journal test prelude supplies
fixed-width Win32 types and UTF-16 helpers; production functions are extracted.
"""
import ast
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/service_binding_transaction.h').read_text()
prefix = source[:source.index('static BOOL ServiceBinding_ReadValue')]
prefix = prefix.replace('#ifndef MESH_SERVICE_BINDING_TRANSACTION_H', '').replace('#define MESH_SERVICE_BINDING_TRANSACTION_H', '')
# Read shared test definitions as data, without running another suite.
module = ast.parse((ROOT / 'test/service_transaction_journal_native.py').read_text())
prelude = next(ast.literal_eval(node.value) for node in module.body if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'prelude' for t in node.targets))
# Only the UTF-16/types portion is needed here; atomic file mocks are separate.
prelude = prelude[:prelude.index('/* Two files model atomic replacement')].replace('#include <wchar.h>', '')
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' ' * len(m.group()), source, flags=re.S)
def extract(name):
    match = re.search(r'static BOOL ' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]

mocks = r'''
typedef intptr_t HKEY; typedef intptr_t SC_HANDLE; typedef int LONG; typedef unsigned int UINT;
#define HKEY_LOCAL_MACHINE 1
#define KEY_QUERY_VALUE 1
#define KEY_SET_VALUE 2
#define KEY_CREATE_SUB_KEY 4
#define KEY_ENUMERATE_SUB_KEYS 8
#define ERROR_SUCCESS 0
#define ERROR_SERVICE_DOES_NOT_EXIST 1060
#define SC_MANAGER_CONNECT 1
#define SERVICE_QUERY_CONFIG 1
#define SERVICE_QUERY_STATUS 2
#define SERVICE_CHANGE_CONFIG 4
#define SERVICE_START 8
#define SERVICE_DEMAND_START 3
#define SERVICE_NO_CHANGE 0xffffffffUL
#define wcslen wide_len
static wchar_t* wide_chr(const wchar_t* p,wchar_t c){for(;;++p){if(*p==c)return (wchar_t*)p;if(!*p)return NULL;}}
#define wcschr wide_chr
static int wide_compare(const wchar_t* a,const wchar_t* b){while(*a&&*a==*b){++a;++b;}return *a-*b;}
#define wcscmp wide_compare
static int wide_nicmp(const wchar_t* a,const wchar_t* b,size_t n){for(size_t i=0;i<n;++i){int x=a[i],y=b[i];if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;if(x!=y||!x)return x-y;}return 0;}
#define _wcsnicmp wide_nicmp
static BYTE group[4096];static DWORD groupSize,groupType=REG_MULTI_SZ;
static int groupPresent=1,groupOpenError,regWrites,serviceChanges,extraChanges,failAt,ops;
typedef struct { DWORD LowPart; int HighPart; } LUID;
typedef struct { DWORD PrivilegeCount; struct { LUID Luid; DWORD Attributes; } Privileges[1]; } TOKEN_PRIVILEGES;
#define TOKEN_ADJUST_PRIVILEGES 1
#define TOKEN_QUERY 2
#define SE_PRIVILEGE_ENABLED 2
#define SC_ACTION_REBOOT 2
static DWORD privilegeError;static int privilegeEnabled,privilegeDenied,parameterWrites;
static HANDLE GetCurrentProcess(void){return 1;}
static BOOL OpenProcessToken(HANDLE process,DWORD rights,HANDLE* out){(void)process;(void)rights;*out=1;return TRUE;}
static BOOL LookupPrivilegeValueW(void* system,const wchar_t* name,LUID* out){(void)system;(void)name;out->LowPart=1;return TRUE;}
static void SetLastError(DWORD error){privilegeError=error;}
static DWORD GetLastError(void){return privilegeError;}
static BOOL AdjustTokenPrivileges(HANDLE token,BOOL all,TOKEN_PRIVILEGES* requested,DWORD size,TOKEN_PRIVILEGES* previous,DWORD* used){(void)token;(void)all;(void)size;(void)used;if(privilegeDenied){privilegeError=1300;return TRUE;}if(previous){*previous=*requested;previous->Privileges[0].Attributes=privilegeEnabled?2:0;}privilegeEnabled=requested->Privileges[0].Attributes==2;return TRUE;}
static BOOL CloseHandle(HANDLE token){(void)token;return TRUE;}
static DWORD changedStart,changedType;static int clearActions,clearDescription,valuesAfterExtras,deletedParameters;
static BOOL step(void){return !failAt||++ops!=failAt;}
static LONG RegOpenKeyExW(HKEY key,const wchar_t* path,DWORD unused,DWORD access,HKEY* out){(void)key;(void)unused;(void)access;if(!step())return 5;if(wide_chr(path,L'S')&&path[0]=='S'&&path[1]=='O'&&groupOpenError)return groupOpenError;*out=2;return ERROR_SUCCESS;}
static LONG RegQueryValueExW(HKEY key,const wchar_t* name,void* unused,DWORD* type,BYTE* data,DWORD* size){(void)key;(void)name;(void)unused;if(!step())return 5;if(!groupPresent)return ERROR_FILE_NOT_FOUND;*type=groupType;if(!data){*size=groupSize;return ERROR_SUCCESS;}assert(*size>=groupSize);memcpy(data,group,groupSize);*size=groupSize;return ERROR_SUCCESS;}
static LONG RegSetValueExW(HKEY key,const wchar_t* name,DWORD unused,DWORD type,const BYTE* data,DWORD size){(void)key;(void)unused;if(!step())return 5;++regWrites;if(!_wcsicmp(name,L"netsvcs")){assert(size<=sizeof(group));memcpy(group,data,size);groupSize=size;groupType=type;groupPresent=1;}else{if(key==3){assert(serviceChanges==0);++parameterWrites;}else{assert(extraChanges==3);++valuesAfterExtras;}}return ERROR_SUCCESS;}
static LONG RegDeleteValueW(HKEY key,const wchar_t* name){(void)key;(void)name;if(!step())return 5;if(key==3){assert(serviceChanges==0);++parameterWrites;}else{assert(extraChanges==3);++valuesAfterExtras;}return ERROR_FILE_NOT_FOUND;}
static LONG RegCloseKey(HKEY key){(void)key;return ERROR_SUCCESS;}
static LONG RegCreateKeyExW(HKEY key,const wchar_t* path,DWORD a,void* b,DWORD c,DWORD d,void* e,HKEY* out,void* f){(void)key;(void)path;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;if(!step())return 5;*out=3;return ERROR_SUCCESS;}
static LONG RegQueryInfoKeyW(HKEY key,void* a,void* b,void* c,DWORD* subs,void* d,void* e,DWORD* values,void* f,void* g,void* h,void* i){(void)key;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;if(!step())return 5;*subs=*values=0;return ERROR_SUCCESS;}
static LONG RegDeleteKeyW(HKEY key,const wchar_t* name){(void)key;(void)name;if(!step())return 5;++deletedParameters;return ERROR_SUCCESS;}
static SC_HANDLE OpenSCManagerW(void* a,void* b,DWORD access){(void)a;(void)b;(void)access;return step()?1:0;}
static SC_HANDLE OpenServiceW(SC_HANDLE scm,const wchar_t* name,DWORD access){(void)scm;(void)name;(void)access;return step()?2:0;}
static BOOL CloseServiceHandle(SC_HANDLE h){(void)h;return TRUE;}
static BOOL ChangeServiceConfigW(SC_HANDLE h,DWORD type,DWORD start,DWORD error,const wchar_t* image,const wchar_t* groupName,void* tag,const wchar_t* deps,const wchar_t* account,const wchar_t* pass,const wchar_t* display){(void)h;(void)error;(void)image;(void)display;assert(!groupName&&!tag&&!deps&&!account&&!pass);if(!step())return FALSE;assert(parameterWrites==5);if(type==SERVICE_NO_CHANGE){assert(extraChanges==5);}else{assert(start==SERVICE_DISABLED);}changedStart=start;if(type!=SERVICE_NO_CHANGE)changedType=type;++serviceChanges;return TRUE;}
static BOOL ChangeServiceConfig2W(SC_HANDLE h,DWORD level,void* data){(void)h;if(!step())return FALSE;++extraChanges;if(level==SERVICE_CONFIG_DESCRIPTION)clearDescription=((SERVICE_DESCRIPTIONW*)data)->lpDescription&&!*(((SERVICE_DESCRIPTIONW*)data)->lpDescription);if(level==SERVICE_CONFIG_FAILURE_ACTIONS){SERVICE_FAILURE_ACTIONSW* a=data;if(a->cActions&&a->lpsaActions[0].Type==SC_ACTION_REBOOT)assert(privilegeEnabled);clearActions=a->lpCommand&&!*a->lpCommand&&a->lpRebootMsg&&!*a->lpRebootMsg&&a->lpsaActions&&a->cActions==0;}return TRUE;}
static UINT GetSystemDirectoryW(wchar_t* out,UINT cap){const wchar_t* p=L"C:\\Windows\\System32";assert(cap>wide_len(p));memcpy(out,p,(wide_len(p)+1)*2);return (UINT)wide_len(p);}
static DWORD ExpandEnvironmentStringsW(const wchar_t* source,wchar_t* out,DWORD cap){DWORD n=(DWORD)wide_len(source)+1;if(n<=cap)memcpy(out,source,n*2);return n;}
/* A parent-relative segment is not canonical; any change models normalization. */
static DWORD GetFullPathNameW(const wchar_t* path,DWORD cap,wchar_t* out,wchar_t** part){(void)part;DWORD n=(DWORD)wide_len(path)+1;if(n>cap)return n;memcpy(out,path,n*2);for(wchar_t* p=out;*p;++p)if(p[0]=='\\'&&p[1]=='.'&&p[2]=='.')p[1]='_';return n-1;}

        static BOOL ServiceHost_IsServiceImagePath(const wchar_t* name,const wchar_t* command){(void)name;return !_wcsicmp(command,L"\"C:\\Windows\\System32\\svchost.exe\" -k MeshAgent-Test");}
static BOOL ServiceHost_BuildGroupName(const wchar_t* name,wchar_t* groupName,size_t cap){(void)name;const wchar_t* value=L"MeshAgent-Test";if(cap<=wide_len(value))return FALSE;memcpy(groupName,value,(wide_len(value)+1)*2);return TRUE;}
'''
cases = r'''
static void set_group(const wchar_t* entries,size_t chars){memcpy(group,entries,chars*2);groupSize=(DWORD)(chars*2);groupType=REG_MULTI_SZ;groupPresent=1;groupOpenError=0;regWrites=ops=failAt=0;}
static void reset_restore(void){serviceChanges=extraChanges=valuesAfterExtras=deletedParameters=ops=failAt=parameterWrites=0;}
int main(void){
    /* Mark shared journal-only helpers used while keeping warning gates strict. */
    SECURITY_DESCRIPTOR_RELATIVE sd={1,0,SE_SELF_RELATIVE,0,0,0,0};assert(IsValidSecurityDescriptor(&sd)&&GetSecurityDescriptorLength(&sd)==sizeof(sd));
    BOOL member=FALSE;set_group(L"Other\0Agent\0Third\0",19);assert(ServiceBinding_Group(L"netsvcs",L"Agent",FALSE,&member,FALSE)&&member&&regWrites==0);
    member=FALSE;assert(ServiceBinding_Group(L"netsvcs",L"Agent",TRUE,&member,FALSE));assert(!_wcsicmp((wchar_t*)group,L"Other"));assert(!_wcsicmp((wchar_t*)group+6,L"Third"));
    member=TRUE;assert(ServiceBinding_Group(L"netsvcs",L"Agent",TRUE,&member,FALSE));assert(!_wcsicmp((wchar_t*)group+12,L"Agent"));
    groupPresent=0;member=TRUE;assert(ServiceBinding_Group(L"netsvcs",L"Agent",TRUE,&member,FALSE));assert(groupSize==14&&!_wcsicmp((wchar_t*)group,L"Agent"));
    groupPresent=0;member=TRUE;assert(ServiceBinding_Group(L"netsvcs",L"Agent",FALSE,&member,FALSE)&&!member);
    groupOpenError=ERROR_FILE_NOT_FOUND;assert(ServiceBinding_Group(L"netsvcs",L"Agent",FALSE,&member,FALSE)&&!member);groupOpenError=0;
    set_group(L"Other\0",7);groupType=REG_SZ;member=TRUE;assert(!ServiceBinding_Group(L"netsvcs",L"Agent",TRUE,&member,FALSE)&&regWrites==0);
    set_group(L"Other\0",7);((wchar_t*)group)[6]='x';assert(!ServiceBinding_Group(L"netsvcs",L"Agent",TRUE,&member,FALSE));
    QUERY_SERVICE_CONFIGW config={0};BOOL legacy=FALSE;config.dwServiceType=SERVICE_WIN32_OWN_PROCESS;config.lpBinaryPathName=L"\"C:\\Agent\\agent.exe\"";
    assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"\"C:\\Agent\\agent.exe\" -other";assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"C:\\Another\\agent.exe";assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.dwServiceType=0x110;config.lpBinaryPathName=L"\"C:\\Agent\\agent.exe\"";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"\"C:\\Program Files\\Mesh Agent\\MeshAgent.exe\" -run";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"C:\\Program Files\\Mesh Agent\\MeshAgent.exe -run";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"C:\\Program Files\\Mesh Agent\\MeshAgent.exe";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"\"C:\\Mesh\\MeshService64.exe\"";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"C:\\Mesh\\diaghost.exe  \r\n";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
    config.lpBinaryPathName=L"C:\\Agent\\agent.exe\t-run";
    assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\agent.dll\",MeshServiceHostW";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Other\\agent.dll",&legacy));
    config.lpBinaryPathName=L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\agent.dll\",Stealth_SvchostServiceMain";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Other\\agent.dll",&legacy));
    config.lpBinaryPathName=L"\"C:\\fake\\rundll32.exe\" \"C:\\Agent\\agent.dll\",Stealth_SvchostServiceMain";assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\agent.dll\",Stealth_SvchostServiceMain extra";assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"C:\\Windows\\System32\\rundll32.exe \"C:\\Agent\\agent.dll\",Stealth_SvchostServiceMain";
    assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"\"C:\\Windows\\System32\\rundll32.exe\"\t\"C:\\Agent\\agent.dll\",MeshServiceHostW  ";
    assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    /* The parsed callback DLL keeps the loader contract: .dll suffix, valid characters, canonical path. */
    wchar_t parsed[MAX_PATH];
    assert(ServiceBinding_ParseCallbackImage(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\agent.dll\",MeshServiceHostW",parsed,MAX_PATH)&&!_wcsicmp(parsed,L"C:\\Agent\\agent.dll"));
    assert(!ServiceBinding_ParseCallbackImage(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\agent.exe\",MeshServiceHostW",parsed,MAX_PATH)&&!parsed[0]);
    assert(!ServiceBinding_ParseCallbackImage(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\..\\agent.dll\",MeshServiceHostW",parsed,MAX_PATH)&&!parsed[0]);
    assert(!ServiceBinding_ParseCallbackImage(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\a|b.dll\",MeshServiceHostW",parsed,MAX_PATH)&&!parsed[0]);
    assert(!ServiceBinding_ParseCallbackImage(L"C:\\Windows\\System32\\rundll32.exe C:\\Agent\\a:b.dll,Stealth_SvchostServiceMain",parsed,MAX_PATH)&&!parsed[0]);
    config.dwServiceType=SERVICE_WIN32_SHARE_PROCESS;config.lpBinaryPathName=L"\"C:\\Windows\\System32\\svchost.exe\" -k MeshAgent-Test";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);
    config.lpBinaryPathName=L"%SystemRoot%\\System32\\svchost.exe -k netsvcs";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);
    config.lpBinaryPathName=L"C:\\Windows\\System32\\svchost.exe -k netsvcs";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);
    config.lpBinaryPathName=L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);
    config.lpBinaryPathName=L"\"C:\\Windows\\System32\\svchost.exe\" -k netsvcs -p";assert(ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);
    config.lpBinaryPathName=L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p extra";assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"C:\\Malware\\svchost.exe -k netsvcs";assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.dwServiceType=1;assert(!ServiceBinding_ImageSupported(L"Agent",&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    ServiceBindingSnapshot owner={0};owner.config=&config;config.dwServiceType=SERVICE_WIN32_SHARE_PROCESS;
    const wchar_t* knownDll=L"C:\\Agent\\agent.dll";const wchar_t* knownEntry=L"ServiceHost_ServiceMain";
    owner.values[9]=(ServiceBindingValue){(BYTE*)knownDll,(DWORD)((wide_len(knownDll)+1)*2),REG_SZ,TRUE};
    owner.values[10]=(ServiceBindingValue){(BYTE*)knownEntry,(DWORD)((wide_len(knownEntry)+1)*2),REG_SZ,TRUE};
    assert(ServiceBinding_SharedImageSupported(&owner,knownDll));assert(!ServiceBinding_SharedImageSupported(&owner,L"C:\\Other\\agent.dll"));
    const wchar_t* oldEntry=L"Stealth_SvchostServiceMain";owner.values[10]=(ServiceBindingValue){(BYTE*)oldEntry,(DWORD)((wide_len(oldEntry)+1)*2),REG_SZ,TRUE};assert(ServiceBinding_SharedImageSupported(&owner,knownDll));
    owner.values[10]=(ServiceBindingValue){(BYTE*)knownEntry,(DWORD)((wide_len(knownEntry)+1)*2),REG_SZ,TRUE};
    owner.values[10].present=FALSE;assert(!ServiceBinding_SharedImageSupported(&owner,knownDll));owner.values[10].present=TRUE;
    DWORD entrySize=owner.values[10].size;
    owner.values[10].size=0;assert(!ServiceBinding_SharedImageSupported(&owner,knownDll));
    owner.values[10].size=entrySize-1;assert(!ServiceBinding_SharedImageSupported(&owner,knownDll));
    owner.values[10].size=entrySize-2;assert(!ServiceBinding_SharedImageSupported(&owner,knownDll));
    owner.values[10].size=entrySize;
    owner.values[9].size-=2;assert(!ServiceBinding_SharedImageSupported(&owner,knownDll));
    config.dwServiceType=SERVICE_WIN32_OWN_PROCESS;assert(ServiceBinding_SharedImageSupported(&owner,knownDll));
    ServiceBindingSnapshot* s=calloc(1,sizeof(*s));s->config=calloc(1,sizeof(*s->config));s->config->dwServiceType=SERVICE_WIN32_SHARE_PROCESS;s->config->dwStartType=SERVICE_DISABLED;s->running=TRUE;s->legacyGroupMember=TRUE;
    for(size_t i=0;i<5;++i)s->extra[i]=calloc(1,128);
    set_group(L"Other\0",7);reset_restore();assert(ServiceBinding_Restore(L"Agent",s));assert(serviceChanges==2&&changedType==SERVICE_WIN32_SHARE_PROCESS&&changedStart==SERVICE_DEMAND_START&&clearActions&&clearDescription&&valuesAfterExtras==8&&parameterWrites==5&&deletedParameters==1);
    int operationCount=ops; /* Every mutation/query boundary must fail closed. */
    for(int failure=1;failure<=operationCount;++failure){set_group(L"Other\0",7);reset_restore();failAt=failure;assert(!ServiceBinding_Restore(L"Agent",s));}
    /* Reboot action restoration acquires and restores the shutdown privilege. */
    SERVICE_FAILURE_ACTIONSW* actions=(SERVICE_FAILURE_ACTIONSW*)s->extra[1];SC_ACTION reboot={SC_ACTION_REBOOT,1000};actions->cActions=1;actions->lpsaActions=&reboot;
    set_group(L"Other\0",7);reset_restore();privilegeDenied=1;assert(!ServiceBinding_Restore(L"Agent",s)&&!serviceChanges&&!parameterWrites&&!privilegeEnabled);
    privilegeDenied=0;reset_restore();assert(ServiceBinding_Restore(L"Agent",s)&&!privilegeEnabled);
    ServiceBinding_Free(s);puts("service binding transaction: owned image selection, membership restoration, exact value ordering, disabled running state and failure propagation passed");return 0;
}
'''
functions = '\n'.join(extract(name) for name in ['ServiceBinding_ReadValue', 'ServiceBinding_Group', 'ServiceBinding_IsLegacyExe', 'ServiceBinding_ParseCallbackImage', 'ServiceBinding_ImageSupported', 'ServiceBinding_SharedImageSupported', 'ServiceBinding_AcquireRecoveryPrivilege', 'ServiceBinding_ReleaseRecoveryPrivilege', 'ServiceBinding_ApplyExtra', 'ServiceBinding_Restore'])
with tempfile.TemporaryDirectory(prefix='mesh-service-binding-') as tmp:
    src, exe = Path(tmp) / 'binding.c', Path(tmp) / 'binding'
    harness = prelude + prefix + mocks + functions + cases
    # Keep the portable mocks distinct from Windows UCRT names when clang
    # discovers the host SDK through its default include path.
    for system_name, mock_name in (('_countof', 'mock_countof'),
                                   ('_TRUNCATE', 'MOCK_TRUNCATE'),
                                   ('_snwprintf_s', 'mock_snwprintf_s')):
        harness = harness.replace(system_name, mock_name)
    src.write_text(harness)
    compiler = [os.environ.get('CC', 'clang'), '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror', '-Wno-int-conversion']
    if os.name != 'nt':
        compiler.append('-fsanitize=address,undefined')
    subprocess.run(compiler + [str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
