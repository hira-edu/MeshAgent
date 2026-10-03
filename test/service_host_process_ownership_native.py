"""Exercise production shared-host PID ownership without changing Windows services."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/service_deployment.c').read_text()
start = source.index('static BOOL ServiceDeploy_ProcessHostsOnlyService(')
end = source.index('\nstatic BOOL ServiceDeploy_StopServiceAndWait(', start)
production = source[start:end]
fixture = r'''
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
static DWORD lastError;
static int fault, calls, closes;
static ENUM_SERVICE_STATUS_PROCESSW entries[3];
static SC_HANDLE fixtureOpen(void* machine, void* database, DWORD access) {
    assert(!machine && !database && access == SC_MANAGER_ENUMERATE_SERVICE);
    return fault == 1 ? NULL : (SC_HANDLE)1;
}
static BOOL fixtureClose(SC_HANDLE handle) { assert(handle == (SC_HANDLE)1); ++closes; return TRUE; }
static BOOL fixtureEnum(SC_HANDLE scm, SC_ENUM_TYPE level, DWORD type, DWORD state,
    BYTE* buffer, DWORD capacity, DWORD* needed, DWORD* count, DWORD* resume, const wchar_t* group) {
    assert(scm == (SC_HANDLE)1 && level == SC_ENUM_PROCESS_INFO && type == SERVICE_WIN32 && state == SERVICE_ACTIVE);
    assert(!*resume && !group); ++calls;
    *needed = fault == 4 ? 300 * 1024 : sizeof(entries);
    if (!buffer) { lastError = fault == 2 ? ERROR_ACCESS_DENIED : ERROR_MORE_DATA; return FALSE; }
    assert(capacity == sizeof(entries));
    if (fault == 3) { lastError = ERROR_ACCESS_DENIED; return FALSE; }
    memcpy(buffer, entries, sizeof(entries)); *count = 3; return TRUE;
}
#define OpenSCManagerW fixtureOpen
#define CloseServiceHandle fixtureClose
#define EnumServicesStatusExW fixtureEnum
#define GetLastError() lastError
'''
cases = r'''
int main(void) {
    entries[0].lpServiceName = L"Agent"; entries[0].ServiceStatusProcess.dwProcessId = 123;
    entries[1].lpServiceName = L"Other"; entries[1].ServiceStatusProcess.dwProcessId = 456;
    entries[2].lpServiceName = L"Third"; entries[2].ServiceStatusProcess.dwProcessId = 789;
    assert(ServiceDeploy_ProcessHostsOnlyService(L"agent", 123));
    assert(!ServiceDeploy_ProcessHostsOnlyService(L"Missing", 123));
    assert(!ServiceDeploy_ProcessHostsOnlyService(L"Agent", 999));
    entries[1].ServiceStatusProcess.dwProcessId = 123;
    assert(!ServiceDeploy_ProcessHostsOnlyService(L"Agent", 123));
    entries[1].ServiceStatusProcess.dwProcessId = 456;
    for (fault = 1; fault <= 4; ++fault) {
        calls = closes = 0;
        assert(!ServiceDeploy_ProcessHostsOnlyService(L"Agent", 123));
        assert(closes == (fault == 1 ? 0 : 1));
    }
    assert(!ServiceDeploy_ProcessHostsOnlyService(NULL, 123));
    assert(!ServiceDeploy_ProcessHostsOnlyService(L"", 123));
    assert(!ServiceDeploy_ProcessHostsOnlyService(L"Agent", 0));
    puts("Shared-host ownership: exclusive PID, stale binding, missing service and enumeration faults passed");
    return 0;
}
'''
if os.name != 'nt':
    raise SystemExit('This SCM type harness requires Windows headers')
with tempfile.TemporaryDirectory(prefix='mesh-service-pid-') as directory:
    c_path = Path(directory) / 'ownership.c'
    executable = Path(directory) / 'ownership.exe'
    c_path.write_text(fixture + production + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c_path), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
