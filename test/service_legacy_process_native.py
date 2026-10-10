"""Execute copied-host process admission with mocked read-only Win32 APIs.

No real process or SCM handles are opened. Production path normalization and
the complete production process guard are compiled into the fixture.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
host = (ROOT / 'meshservice/service_legacy_host.h').read_text()


def extract(source, name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'static BOOL\s+' + name + r'\s*\([^;{]+\)\s*\{', masked)
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
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
enum Failure { NONE, SCM_OPEN, SERVICE_OPEN, STATUS_FIRST, PROCESS_OPEN,
    PROCESS_IMAGE, ENUM_SIZE, ENUM_DATA, STATUS_SECOND };
static enum Failure failure;
static DWORD firstState, secondState, firstPid, secondPid, waitResult;
static int serviceHandles, processHandles, statusQueries, processOpens;
static int shared, missing, incomplete, oversized;
static const wchar_t* processImage;
static SC_HANDLE mockOpenSCManagerW(LPCWSTR machine,LPCWSTR db,DWORD access) {
    assert(!machine&&!db&&access==(SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE));
    if(failure==SCM_OPEN)return NULL;++serviceHandles;return (SC_HANDLE)(ULONG_PTR)1;
}
static SC_HANDLE mockOpenServiceW(SC_HANDLE scm,LPCWSTR name,DWORD access) {
    assert(scm&&!wcscmp(name,L"Agent")&&access==SERVICE_QUERY_STATUS);
    if(failure==SERVICE_OPEN)return NULL;++serviceHandles;return (SC_HANDLE)(ULONG_PTR)2;
}
static BOOL mockQueryServiceStatusEx(SC_HANDLE service,SC_STATUS_TYPE level,LPBYTE data,DWORD size,LPDWORD needed) {
    assert(service&&level==SC_STATUS_PROCESS_INFO&&size>=sizeof(SERVICE_STATUS_PROCESS));
    ++statusQueries;if((statusQueries==1&&failure==STATUS_FIRST)||(statusQueries==2&&failure==STATUS_SECOND))return FALSE;
    SERVICE_STATUS_PROCESS* status=(SERVICE_STATUS_PROCESS*)data;ZeroMemory(status,sizeof(*status));
    status->dwCurrentState=statusQueries==1?firstState:secondState;
    status->dwProcessId=statusQueries==1?firstPid:secondPid;*needed=sizeof(*status);return TRUE;
}
static HANDLE mockOpenProcess(DWORD access,BOOL inherit,DWORD pid) {
    assert(access==(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE)&&!inherit&&pid==firstPid);
    ++processOpens;if(failure==PROCESS_OPEN)return NULL;++processHandles;return (HANDLE)(ULONG_PTR)3;
}
static BOOL mockQueryFullProcessImageNameW(HANDLE process,DWORD flags,LPWSTR output,PDWORD size) {
    assert(process&&!flags);if(failure==PROCESS_IMAGE)return FALSE;
    if(FAILED(StringCchCopyW(output,*size,processImage)))return FALSE;*size=(DWORD)wcslen(output);return TRUE;
}
static BOOL mockEnumServicesStatusExW(SC_HANDLE scm,SC_ENUM_TYPE level,DWORD type,DWORD state,
    LPBYTE output,DWORD size,LPDWORD needed,LPDWORD count,LPDWORD resume,LPCWSTR group) {
    assert(scm&&level==SC_ENUM_PROCESS_INFO&&type==SERVICE_WIN32&&state==SERVICE_ACTIVE&&!group);
    *needed=oversized?256*1024+1:3*sizeof(ENUM_SERVICE_STATUS_PROCESSW);
    if(!output){assert(!size);SetLastError(failure==ENUM_SIZE?ERROR_ACCESS_DENIED:ERROR_MORE_DATA);return FALSE;}
    if(failure==ENUM_DATA){SetLastError(ERROR_MORE_DATA);return FALSE;}
    assert(size>=3*sizeof(ENUM_SERVICE_STATUS_PROCESSW));
    ENUM_SERVICE_STATUS_PROCESSW* rows=(ENUM_SERVICE_STATUS_PROCESSW*)output;
    ZeroMemory(rows,3*sizeof(*rows));*count=3;*resume=incomplete?1:0;
    rows[0].lpServiceName=L"Unrelated";rows[0].ServiceStatusProcess.dwProcessId=99;
    rows[1].lpServiceName=missing?L"Absent":L"Agent";
    rows[1].ServiceStatusProcess.dwProcessId=missing?77:firstPid;
    rows[2].lpServiceName=L"Other";rows[2].ServiceStatusProcess.dwProcessId=shared?firstPid:88;
    return TRUE;
}
static DWORD mockWaitForSingleObject(HANDLE process,DWORD timeout){assert(process&&!timeout);return waitResult;}
static BOOL mockCloseHandle(HANDLE process){assert(process&&processHandles>0);--processHandles;return TRUE;}
static BOOL mockCloseServiceHandle(SC_HANDLE service){assert(service&&serviceHandles>0);--serviceHandles;return TRUE;}
#define OpenSCManagerW mockOpenSCManagerW
#define OpenServiceW mockOpenServiceW
#define QueryServiceStatusEx mockQueryServiceStatusEx
#define OpenProcess mockOpenProcess
#define QueryFullProcessImageNameW mockQueryFullProcessImageNameW
#define EnumServicesStatusExW mockEnumServicesStatusExW
#define WaitForSingleObject mockWaitForSingleObject
#define CloseHandle mockCloseHandle
#define CloseServiceHandle mockCloseServiceHandle
'''
cases = r'''
static void reset(void){
    assert(!serviceHandles&&!processHandles);failure=NONE;
    firstState=secondState=SERVICE_RUNNING;firstPid=secondPid=42;waitResult=WAIT_TIMEOUT;
    statusQueries=processOpens=shared=missing=incomplete=oversized=0;processImage=L"C:\\Agent\\svchost.exe";
}
static void check(BOOL expected){
    assert(ServiceLegacyHost_ProcessSafe(L"Agent",L"C:\\Agent\\svchost.exe")==expected);
    assert(!serviceHandles&&!processHandles);
}
int main(void){
    reset();check(TRUE);assert(statusQueries==2&&processOpens==1);
    for(enum Failure f=SCM_OPEN;f<=STATUS_SECOND;f=(enum Failure)(f+1)){reset();failure=f;check(FALSE);}
    reset();shared=1;check(FALSE);
    reset();missing=1;check(FALSE);
    reset();incomplete=1;check(FALSE);
    reset();oversized=1;check(FALSE);
    reset();processImage=L"C:\\Other\\svchost.exe";check(FALSE);
    reset();processImage=L"C:\\\\Agent\\\\svchost.exe";check(FALSE);
    reset();processImage=L"c:\\agent\\SVCHOST.EXE";check(TRUE);
    reset();secondPid=43;check(FALSE);
    reset();secondState=SERVICE_STOPPED;check(FALSE);
    reset();waitResult=WAIT_OBJECT_0;check(FALSE);
    reset();waitResult=WAIT_FAILED;check(FALSE);
    reset();firstPid=0;check(FALSE);assert(!processOpens);
    reset();firstState=SERVICE_STOP_PENDING;check(FALSE);assert(!processOpens);
    reset();firstState=SERVICE_START_PENDING;check(FALSE);assert(!processOpens);
    reset();firstState=SERVICE_PAUSED;check(FALSE);assert(!processOpens);
    reset();firstState=SERVICE_STOPPED;firstPid=0;check(TRUE);assert(!processOpens&&statusQueries==1);
    reset();firstState=SERVICE_STOPPED;check(FALSE);assert(!processOpens);
    reset();assert(!ServiceLegacyHost_ProcessSafe(NULL,L"C:\\Agent\\svchost.exe"));
    assert(!ServiceLegacyHost_ProcessSafe(L"Agent",NULL));assert(!serviceHandles&&!processHandles);
    puts("Copied-host process guard: running/stopped ownership, shared PID, image mismatch, exit/race/query failures and handle cleanup passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='legacy-process-') as temporary:
    path = Path(temporary)
    source, exe = path / 'fixture.c', path / 'fixture.exe'
    production = (extract(host, 'ServiceLegacyHost_NormalizePath') + '\n' +
                  (ROOT / 'meshservice/service_legacy_process.h').read_text())
    source.write_text(prelude + production + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
