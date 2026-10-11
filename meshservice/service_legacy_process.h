/* Read-only running-process admission for copied-host migration. This is not
 * permission to terminate a process. The caller validates the SCM binding and
 * host file separately. service_legacy_host.h supplies path normalization. */
#ifndef MESH_SERVICE_LEGACY_PROCESS_H
#define MESH_SERVICE_LEGACY_PROCESS_H

#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

static BOOL ServiceLegacyHost_ProcessSafe(const wchar_t* serviceName, const wchar_t* hostPath)
{
    SC_HANDLE scm = NULL, service = NULL;
    HANDLE process = NULL;
    SERVICE_STATUS_PROCESS before = {0}, after = {0};
    ENUM_SERVICE_STATUS_PROCESSW* services = NULL;
    wchar_t actual[MAX_PATH], normalizedActual[MAX_PATH], expected[MAX_PATH];
    DWORD bytes = 0, count = 0, resume = 0, length = _countof(actual);
    BOOL found = FALSE, ok = FALSE;
    if (!serviceName || !*serviceName ||
        !ServiceLegacyHost_NormalizePath(hostPath, expected, _countof(expected))) { return FALSE; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { goto done; }
    service = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
    if (!service || !QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        (BYTE*)&before, sizeof(before), &bytes)) { goto done; }
    if (before.dwCurrentState == SERVICE_STOPPED)
    {
        ok = before.dwProcessId == 0;
        goto done;
    }
    if (before.dwCurrentState != SERVICE_RUNNING || !before.dwProcessId) { goto done; }
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, before.dwProcessId);
    if (!process || !QueryFullProcessImageNameW(process, 0, actual, &length) ||
        !length || length >= _countof(actual) ||
        !ServiceLegacyHost_NormalizePath(actual, normalizedActual, _countof(normalizedActual)) ||
        _wcsicmp(normalizedActual, expected)) { goto done; }
    bytes = count = resume = 0;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
        NULL, 0, &bytes, &count, &resume, NULL) || GetLastError() != ERROR_MORE_DATA ||
        !bytes || bytes > 256 * 1024) { goto done; }
    services = (ENUM_SERVICE_STATUS_PROCESSW*)calloc(1, bytes);
    if (!services) { goto done; }
    resume = 0;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
        (BYTE*)services, bytes, &bytes, &count, &resume, NULL) || resume != 0) { goto done; }
    for (DWORD i = 0; i < count; ++i)
    {
        if (services[i].ServiceStatusProcess.dwProcessId != before.dwProcessId) { continue; }
        if (!services[i].lpServiceName || _wcsicmp(services[i].lpServiceName, serviceName)) { goto done; }
        found = TRUE;
    }
    if (!found || !QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        (BYTE*)&after, sizeof(after), &bytes) || after.dwCurrentState != SERVICE_RUNNING ||
        after.dwProcessId != before.dwProcessId || WaitForSingleObject(process, 0) != WAIT_TIMEOUT) { goto done; }
    ok = TRUE;
done:
    free(services);
    if (process) { CloseHandle(process); }
    if (service) { CloseServiceHandle(service); }
    if (scm) { CloseServiceHandle(scm); }
    return ok;
}

#endif
