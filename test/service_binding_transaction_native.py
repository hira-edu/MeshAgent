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
#define wcslen wide_len
static wchar_t* wide_chr(const wchar_t* p,wchar_t c){for(;;++p){if(*p==c)return (wchar_t*)p;if(!*p)return NULL;}}
#define wcschr wide_chr
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
static LONG RegSetValueExW(HKEY key,const wchar_t* name,DWORD unused,DWORD type,const BYTE* data,DWORD size){(void)key;(void)unused;if(!step())return 5;++regWrites;if(!_wcsicmp(name,L"netsvcs")){assert(size<=sizeof(group));memcpy(group,data,size);groupSize=size;groupType=type;groupPresent=1;}else{if(key==3){assert(serviceChanges==0);++parameterWrites;}else{assert(extraChanges==5);++valuesAfterExtras;}}return ERROR_SUCCESS;}
static LONG RegDeleteValueW(HKEY key,const wchar_t* name){(void)key;(void)name;if(!step())return 5;if(key==3){assert(serviceChanges==0);++parameterWrites;}else{assert(extraChanges==5);++valuesAfterExtras;}return ERROR_FILE_NOT_FOUND;}
static LONG RegCloseKey(HKEY key){(void)key;return ERROR_SUCCESS;}
static LONG RegCreateKeyExW(HKEY key,const wchar_t* path,DWORD a,void* b,DWORD c,DWORD d,void* e,HKEY* out,void* f){(void)key;(void)path;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;if(!step())return 5;*out=3;return ERROR_SUCCESS;}
static LONG RegQueryInfoKeyW(HKEY key,void* a,void* b,void* c,DWORD* subs,void* d,void* e,DWORD* values,void* f,void* g,void* h,void* i){(void)key;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;if(!step())return 5;*subs=*values=0;return ERROR_SUCCESS;}
static LONG RegDeleteKeyW(HKEY key,const wchar_t* name){(void)key;(void)name;if(!step())return 5;++deletedParameters;return ERROR_SUCCESS;}
static SC_HANDLE OpenSCManagerW(void* a,void* b,DWORD access){(void)a;(void)b;(void)access;return step()?1:0;}
static SC_HANDLE OpenServiceW(SC_HANDLE scm,const wchar_t* name,DWORD access){(void)scm;(void)name;(void)access;return step()?2:0;}
static BOOL CloseServiceHandle(SC_HANDLE h){(void)h;return TRUE;}
static BOOL ChangeServiceConfigW(SC_HANDLE h,DWORD type,DWORD start,DWORD error,const wchar_t* image,const wchar_t* groupName,void* tag,const wchar_t* deps,const wchar_t* account,const wchar_t* pass,const wchar_t* display){(void)h;(void)error;(void)image;(void)display;assert(!groupName&&!tag&&!deps&&!account&&!pass);if(!step())return FALSE;assert(parameterWrites==5);changedStart=start;changedType=type;++serviceChanges;return TRUE;}
static BOOL ChangeServiceConfig2W(SC_HANDLE h,DWORD level,void* data){(void)h;if(!step())return FALSE;++extraChanges;if(level==SERVICE_CONFIG_DESCRIPTION)clearDescription=((SERVICE_DESCRIPTIONW*)data)->lpDescription&&!*(((SERVICE_DESCRIPTIONW*)data)->lpDescription);if(level==SERVICE_CONFIG_FAILURE_ACTIONS){SERVICE_FAILURE_ACTIONSW* a=data;if(a->cActions&&a->lpsaActions[0].Type==SC_ACTION_REBOOT)assert(privilegeEnabled);clearActions=a->lpCommand&&!*a->lpCommand&&a->lpRebootMsg&&!*a->lpRebootMsg&&a->lpsaActions&&a->cActions==0;}return TRUE;}
static UINT GetSystemDirectoryW(wchar_t* out,UINT cap){const wchar_t* p=L"C:\\Windows\\System32";assert(cap>wide_len(p));memcpy(out,p,(wide_len(p)+1)*2);return (UINT)wide_len(p);}
static BOOL ServiceHost_ParseImagePath(const wchar_t* command,wchar_t* dll,size_t cap){const wchar_t* path=L"C:\\Agent\\agent.dll";const wchar_t* expected=L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\agent.dll\",MeshServiceHostW";if(_wcsicmp(command,expected))return FALSE;assert(cap>wide_len(path));memcpy(dll,path,(wide_len(path)+1)*2);return TRUE;}
'''
cases = r'''
static void set_group(const wchar_t* entries,size_t chars){memcpy(group,entries,chars*2);groupSize=(DWORD)(chars*2);groupType=REG_MULTI_SZ;groupPresent=1;groupOpenError=0;regWrites=ops=failAt=0;}
static void reset_restore(void){serviceChanges=extraChanges=valuesAfterExtras=deletedParameters=ops=failAt=parameterWrites=0;}
int main(void){
    /* Mark shared journal-only helpers used while keeping warning gates strict. */
    SECURITY_DESCRIPTOR_RELATIVE sd={1,0,SE_SELF_RELATIVE,0,0,0,0};assert(IsValidSecurityDescriptor(&sd)&&GetSecurityDescriptorLength(&sd)==sizeof(sd));
    BOOL member=FALSE;set_group(L"Other\0Agent\0Third\0",19);assert(ServiceBinding_Group(L"Agent",FALSE,&member)&&member&&regWrites==0);
    member=FALSE;assert(ServiceBinding_Group(L"Agent",TRUE,&member));assert(!_wcsicmp((wchar_t*)group,L"Other"));assert(!_wcsicmp((wchar_t*)group+6,L"Third"));
    member=TRUE;assert(ServiceBinding_Group(L"Agent",TRUE,&member));assert(!_wcsicmp((wchar_t*)group+12,L"Agent"));
    groupPresent=0;member=TRUE;assert(ServiceBinding_Group(L"Agent",TRUE,&member));assert(groupSize==14&&!_wcsicmp((wchar_t*)group,L"Agent"));
    groupPresent=0;member=TRUE;assert(ServiceBinding_Group(L"Agent",FALSE,&member)&&!member);
    groupOpenError=ERROR_FILE_NOT_FOUND;assert(ServiceBinding_Group(L"Agent",FALSE,&member)&&!member);groupOpenError=0;
    set_group(L"Other\0",7);groupType=REG_SZ;member=TRUE;assert(!ServiceBinding_Group(L"Agent",TRUE,&member)&&regWrites==0);
    set_group(L"Other\0",7);((wchar_t*)group)[6]='x';assert(!ServiceBinding_Group(L"Agent",TRUE,&member));
    QUERY_SERVICE_CONFIGW config={0};BOOL legacy=FALSE;config.dwServiceType=SERVICE_WIN32_OWN_PROCESS;config.lpBinaryPathName=L"\"C:\\Agent\\agent.exe\"";
    assert(ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&legacy);
    config.lpBinaryPathName=L"\"C:\\Agent\\agent.exe\" -other";assert(!ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"C:\\Another\\agent.exe";assert(!ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Agent\\agent.dll\",MeshServiceHostW";assert(ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);assert(!ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Other\\agent.dll",&legacy));
    config.dwServiceType=SERVICE_WIN32_SHARE_PROCESS;config.lpBinaryPathName=L"%SystemRoot%\\System32\\svchost.exe -k netsvcs";assert(ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy)&&!legacy);
    config.lpBinaryPathName=L"C:\\Windows\\System32\\svchost.exe -k netsvcs";assert(ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.lpBinaryPathName=L"C:\\Malware\\svchost.exe -k netsvcs";assert(!ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    config.dwServiceType=1;assert(!ServiceBinding_ImageSupported(&config,L"C:\\Agent\\agent.exe",L"C:\\Agent\\agent.dll",&legacy));
    ServiceBindingSnapshot* s=calloc(1,sizeof(*s));s->config=calloc(1,sizeof(*s->config));s->config->dwServiceType=SERVICE_WIN32_SHARE_PROCESS;s->config->dwStartType=SERVICE_DISABLED;s->running=TRUE;s->groupMember=TRUE;
    for(size_t i=0;i<5;++i)s->extra[i]=calloc(1,128);
    set_group(L"Other\0",7);reset_restore();assert(ServiceBinding_Restore(L"Agent",s));assert(serviceChanges==1&&changedType==SERVICE_WIN32_SHARE_PROCESS&&changedStart==SERVICE_DEMAND_START&&clearActions&&clearDescription&&valuesAfterExtras==8&&parameterWrites==5&&deletedParameters==1);
    int operationCount=ops; /* Every mutation/query boundary must fail closed. */
    for(int failure=1;failure<=operationCount;++failure){set_group(L"Other\0",7);reset_restore();failAt=failure;assert(!ServiceBinding_Restore(L"Agent",s));}
    /* Reboot action restoration acquires and restores the shutdown privilege. */
    SERVICE_FAILURE_ACTIONSW* actions=(SERVICE_FAILURE_ACTIONSW*)s->extra[1];SC_ACTION reboot={SC_ACTION_REBOOT,1000};actions->cActions=1;actions->lpsaActions=&reboot;
    set_group(L"Other\0",7);reset_restore();privilegeDenied=1;assert(!ServiceBinding_Restore(L"Agent",s)&&!serviceChanges&&!parameterWrites&&!privilegeEnabled);
    privilegeDenied=0;reset_restore();assert(ServiceBinding_Restore(L"Agent",s)&&!privilegeEnabled);
    ServiceBinding_Free(s);puts("service binding transaction: owned image selection, membership restoration, exact value ordering, disabled running state and failure propagation passed");return 0;
}
'''
functions = '\n'.join(extract(name) for name in ['ServiceBinding_ReadValue', 'ServiceBinding_Group', 'ServiceBinding_ImageSupported', 'ServiceBinding_AcquireRecoveryPrivilege', 'ServiceBinding_ReleaseRecoveryPrivilege', 'ServiceBinding_Restore'])
with tempfile.TemporaryDirectory(prefix='mesh-service-binding-') as tmp:
    src, exe = Path(tmp) / 'binding.c', Path(tmp) / 'binding'
    src.write_text(prelude + prefix + mocks + functions + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror', '-Wno-int-conversion', '-fsanitize=address,undefined', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
