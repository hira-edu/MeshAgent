"""Compile actual recovery-state load/save functions and exercise real files.

Runs only in a temporary directory. No services, tasks or registry are touched.
Task/monitor calls and error injection are mocked; state files are real.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/service_deployment.c').read_text(encoding='utf-8-sig')


def extract(name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'(?:static )?(?:BOOL|void)\s+' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]


prelude = r'''
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef struct {wchar_t AutorunTask[260],RecoveryTask[260],RecoveryMonitorFilter[128],RecoveryMonitorHandler[128];} ServiceRecoveryState;
typedef struct {int unused;} ServiceInstallPaths;
static wchar_t g_ServiceRecoveryStatePath[MAX_PATH],directory[MAX_PATH];
static BOOL g_HaveServiceRecoveryStatePath=TRUE;
static int injectReadError;
static BOOL ServiceDeploy_GetInstallPaths(ServiceInstallPaths* paths){(void)paths;return FALSE;}
static void Security_CreateInstallationDirectory(const wchar_t* path){assert(!_wcsicmp(path,directory));}
static int injected_ferror(FILE* file){return injectReadError||ferror(file);}
#define ferror injected_ferror
static int taskCalls,monitorCalls,failTaskCall,denyLegacy;
static wchar_t lastTask[260];
static BOOL FaultRecovery_DeleteTask(const wchar_t* name){++taskCalls;if(taskCalls==failTaskCall)return FALSE;assert(SUCCEEDED(StringCchCopyW(lastTask,_countof(lastTask),name)));return TRUE;}
static BOOL FaultRecovery_RemoveServiceRecoveryMonitor(const wchar_t* filter,const wchar_t* consumer){assert(*filter&&*consumer);++monitorCalls;return TRUE;}
static void ServiceDeploy_LogInstallEvent(const wchar_t* format,...){(void)format;}
static DWORD fixture_attributes(const wchar_t* path){const wchar_t* leaf=wcsrchr(path,L'\\');if(denyLegacy&&leaf&&!_wcsicmp(leaf+1,L"persistence.ini")){SetLastError(ERROR_ACCESS_DENIED);return INVALID_FILE_ATTRIBUTES;}return GetFileAttributesW(path);}
#define GetFileAttributesW fixture_attributes
'''
cases = r'''
static void select_file(const wchar_t* name){assert(SUCCEEDED(StringCchPrintfW(g_ServiceRecoveryStatePath,MAX_PATH,L"%ls\\%ls",directory,name)));}
static ServiceRecoveryState load(const wchar_t* name,BOOL expected){
    ServiceRecoveryState state;memset(&state,0x55,sizeof(state));select_file(name);
    BOOL result=ServiceDeploy_LoadServiceRecoveryState(&state);
    if(result!=expected)fwprintf(stderr,L"unexpected load result: %ls result=%d expected=%d\n",name,result,expected);
    assert(result==expected);
    if(!expected){ServiceRecoveryState zero={0};assert(!memcmp(&state,&zero,sizeof(state)));}
    return state;
}
static void standard(const wchar_t* name){
    ServiceRecoveryState s=load(name,TRUE);
    assert(!wcscmp(s.AutorunTask,L"\\Tasks\\Autorun"));
    assert(!wcscmp(s.RecoveryTask,L"\\Tasks\\Restart"));
    assert(!wcscmp(s.RecoveryMonitorFilter,L"Filter"));
    assert(!wcscmp(s.RecoveryMonitorHandler,L"Consumer"));
}
static void copy_fixture(const wchar_t* source,const wchar_t* dest){
    wchar_t from[MAX_PATH],to[MAX_PATH];
    assert(SUCCEEDED(StringCchPrintfW(from,MAX_PATH,L"%ls\\%ls",directory,source)));
    assert(SUCCEEDED(StringCchPrintfW(to,MAX_PATH,L"%ls\\%ls",directory,dest)));
    assert(CopyFileW(from,to,FALSE));
}
static BOOL exists(const wchar_t* name){select_file(name);return GetFileAttributesW(g_ServiceRecoveryStatePath)!=INVALID_FILE_ATTRIBUTES;}
static void remove_fixture(const wchar_t* name){select_file(name);assert(DeleteFileW(g_ServiceRecoveryStatePath));}
static void suspend_case(BOOL expected){select_file(L"service-recovery.ini");assert(ServiceDeploy_SuspendServiceRecoveryRestarters()==expected);}
int main(int argc,char** argv){
    assert(argc==2&&MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,argv[1],-1,directory,MAX_PATH));
    standard(L"current-utf16.ini");standard(L"legacy-utf16.ini");
    standard(L"legacy-ascii.ini");standard(L"legacy-utf8-bom.ini");
    standard(L"mixed.ini");standard(L"duplicates.ini");standard(L"no-final-newline.ini");
    ServiceRecoveryState endpoint=load(L"endpoint.ini",TRUE);
    assert(!wcscmp(endpoint.AutorunTask,L"\\Microsoft\\Windows\\Diagnostics\\Windows_Diagnostic_Host_Task-Autorun-11BBF523-C210-4B24-BDC4-9EF3664E85F3"));
    assert(!wcscmp(endpoint.RecoveryTask,L"\\Microsoft\\Windows\\Diagnostics\\WinDiagnosticHost_RestartOnStop-RestartOnStop-3C166888-4BB0-4897-8030-7A7D75EDC49B"));
    assert(!*endpoint.RecoveryMonitorFilter&&!*endpoint.RecoveryMonitorHandler);
    /* Read legacy, save current format, read again: all companions survive. */
    select_file(L"saved.ini");assert(ServiceDeploy_SaveServiceRecoveryState(&endpoint));
    ServiceRecoveryState saved=load(L"saved.ini",TRUE);assert(!memcmp(&endpoint,&saved,sizeof(saved)));
    FILE* file=NULL;assert(!_wfopen_s(&file,g_ServiceRecoveryStatePath,L"r, ccs=UNICODE")&&file);
    wchar_t text[2048];size_t used=0;wint_t c;while((c=fgetwc(file))!=WEOF){assert(used+1<_countof(text));text[used++]=(wchar_t)c;}text[used]=0;fclose(file);
    assert(wcsstr(text,L"RecoveryTask=")&&wcsstr(text,L"RecoveryMonitorFilter=")&&wcsstr(text,L"RecoveryMonitorHandler="));
    assert(!wcsstr(text,L"RestartTask=")&&!wcsstr(text,L"WmiFilter=")&&!wcsstr(text,L"WmiConsumer="));
    ServiceRecoveryState unicode=load(L"unicode-utf8.ini",TRUE);assert(!wcscmp(unicode.RecoveryTask,L"T\u00e2che"));
    unicode=load(L"unicode-utf16.ini",TRUE);assert(!wcscmp(unicode.RecoveryTask,L"T\u00e2che"));
    const wchar_t* invalid[]={L"conflict.ini",L"reverse-conflict.ini",L"duplicate-conflict.ini",L"empty-conflict.ini",L"filter-conflict.ini",L"consumer-conflict.ini",L"blank.ini",L"unknown.ini",L"long-value.ini",L"long-task.ini",L"long-line.ini",L"nul.ini",L"bad-utf8.ini",L"absent.ini"};
    for(size_t i=0;i<_countof(invalid);++i)load(invalid[i],FALSE);
    ServiceRecoveryState empty=load(L"empty-values.ini",TRUE);assert(!*empty.AutorunTask&&!*empty.RecoveryTask&&!*empty.RecoveryMonitorFilter&&!*empty.RecoveryMonitorHandler);
    injectReadError=1;load(L"legacy-ascii.ini",FALSE);injectReadError=0;
    /* Actual old filename is discovered before any restarter removal. Partial
     * progress remains on that file, and a retry sees the remaining task. */
    copy_fixture(L"endpoint.ini",L"persistence.ini");
    ServiceRecoveryState discovered=load(L"service-recovery.ini",TRUE);assert(!memcmp(&endpoint,&discovered,sizeof(endpoint)));
    failTaskCall=2;suspend_case(FALSE);assert(taskCalls==2&&!monitorCalls);
    assert(exists(L"persistence.ini")&&!exists(L"service-recovery.ini"));
    discovered=load(L"service-recovery.ini",TRUE);assert(!*discovered.AutorunTask&&!wcscmp(discovered.RecoveryTask,endpoint.RecoveryTask));
    taskCalls=failTaskCall=0;suspend_case(TRUE);assert(taskCalls==1&&!wcscmp(lastTask,endpoint.RecoveryTask));
    assert(!exists(L"persistence.ini")&&!exists(L"service-recovery.ini"));
    /* Both files, denied legacy access, malformed legacy and a directory in
     * place of legacy state all refuse suspension without touching tasks. */
    taskCalls=0;copy_fixture(L"endpoint.ini",L"persistence.ini");copy_fixture(L"current-utf16.ini",L"service-recovery.ini");
    load(L"service-recovery.ini",FALSE);suspend_case(FALSE);assert(!taskCalls&&exists(L"persistence.ini")&&exists(L"service-recovery.ini"));
    remove_fixture(L"service-recovery.ini");denyLegacy=1;suspend_case(FALSE);assert(!taskCalls);denyLegacy=0;
    remove_fixture(L"persistence.ini");copy_fixture(L"conflict.ini",L"persistence.ini");suspend_case(FALSE);assert(!taskCalls);
    remove_fixture(L"persistence.ini");select_file(L"persistence.ini");assert(CreateDirectoryW(g_ServiceRecoveryStatePath,NULL));
    suspend_case(FALSE);assert(!taskCalls);select_file(L"persistence.ini");assert(RemoveDirectoryW(g_ServiceRecoveryStatePath));
    suspend_case(TRUE);assert(!taskCalls);
    copy_fixture(L"current-utf16.ini",L"service-recovery.ini");suspend_case(TRUE);
    assert(taskCalls==2&&monitorCalls==1&&!exists(L"service-recovery.ini"));
    puts("Recovery-state native files: legacy filename discovery, suspension retry, ambiguity/error refusal, UTF16/UTF8 aliases, canonical save and parser bounds passed");
    return 0;
}
'''

canonical = 'AutorunTask=\\Tasks\\Autorun\nRecoveryTask=\\Tasks\\Restart\nRecoveryMonitorFilter=Filter\nRecoveryMonitorHandler=Consumer\n'
legacy = canonical.replace('RecoveryTask=', 'RestartTask=').replace('RecoveryMonitorFilter=', 'WmiFilter=').replace('RecoveryMonitorHandler=', 'WmiConsumer=')
endpoint = ('AutorunTask=\\Microsoft\\Windows\\Diagnostics\\Windows_Diagnostic_Host_Task-Autorun-11BBF523-C210-4B24-BDC4-9EF3664E85F3\r\n'
            'RestartTask=\\Microsoft\\Windows\\Diagnostics\\WinDiagnosticHost_RestartOnStop-RestartOnStop-3C166888-4BB0-4897-8030-7A7D75EDC49B\r\n'
            'WmiFilter=\r\nWmiConsumer=\r\n')
with tempfile.TemporaryDirectory(prefix='service-recovery-state-') as temporary:
    path = Path(temporary)
    files = {
        'current-utf16.ini': canonical.encode('utf-16'),
        'legacy-utf16.ini': legacy.encode('utf-16'),
        'legacy-ascii.ini': legacy.encode('ascii'),
        'legacy-utf8-bom.ini': legacy.encode('utf-8-sig'),
        'mixed.ini': canonical.replace('RecoveryTask=', 'RestartTask=').encode(),
        'duplicates.ini': (legacy + canonical).encode(),
        'no-final-newline.ini': legacy.rstrip('\n').encode(),
        'endpoint.ini': endpoint.encode('utf-16'),
        'unicode-utf8.ini': 'RestartTask=Tâche\n'.encode(),
        'unicode-utf16.ini': 'RestartTask=Tâche\n'.encode('utf-16'),
        'conflict.ini': b'RestartTask=old\nRecoveryTask=new\n',
        'reverse-conflict.ini': b'RecoveryTask=new\nRestartTask=old\n',
        'duplicate-conflict.ini': b'AutorunTask=one\nAutorunTask=two\n',
        'empty-conflict.ini': b'RestartTask=\nRecoveryTask=other\n',
        'filter-conflict.ini': b'WmiFilter=old\nRecoveryMonitorFilter=new\n',
        'consumer-conflict.ini': b'WmiConsumer=old\nRecoveryMonitorHandler=new\n',
        'blank.ini': b'\n\r\n',
        'unknown.ini': b'Unknown=1\n',
        'empty-values.ini': b'AutorunTask=\nRestartTask=\nWmiFilter=\nWmiConsumer=\n',
        'long-value.ini': b'AutorunTask=valid\nWmiFilter=' + b'x' * 128 + b'\n',
        'long-task.ini': b'RestartTask=' + b'x' * 260 + b'\n',
        'long-line.ini': b'AutorunTask=valid\nUnknown=' + b'x' * 512 + b'\n',
        'nul.ini': b'AutorunTask=valid\nRestartTask=bad\x00hidden\n',
        'bad-utf8.ini': b'AutorunTask=valid\nRestartTask=\xff\n',
    }
    for name, data in files.items():
        (path / name).write_bytes(data)
    production = '\n'.join(extract(name) for name in (
        'ServiceDeploy_GetServiceRecoveryStateDirectory', 'ServiceDeploy_SelectServiceRecoveryStateFile',
        'ServiceDeploy_SaveServiceRecoveryState', 'ServiceDeploy_ParseServiceRecoveryStateLine',
        'ServiceDeploy_LoadServiceRecoveryState', 'ServiceDeploy_ClearServiceRecoveryState',
        'ServiceDeploy_SaveSuspendedServiceRecoveryState', 'ServiceDeploy_SuspendServiceRecoveryRestarters'))
    src, exe = path / 'fixture.c', path / 'fixture.exe'
    src.write_text(prelude + production + cases, encoding='utf-8')
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe), str(path)], check=True)
