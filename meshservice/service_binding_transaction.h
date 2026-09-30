/* Bounded, in-memory checkpoint of the SCM/registry fields deployment mutates.
 * Do not save service trees: Parameters can contain unrelated private data.
 * Account credentials are never changed; only LocalSystem is compatible with
 * this package's primary service registration policy. */
#ifndef MESH_SERVICE_BINDING_TRANSACTION_H
#define MESH_SERVICE_BINDING_TRANSACTION_H

#define SERVICE_BINDING_MAX_BYTES (64 * 1024)
static const wchar_t* const ServiceBinding_ValueNames[] = {
    L"Type", L"Start", L"ErrorControl", L"ImagePath", L"DisplayName",
    L"Description", L"ObjectName", L"ServiceSidType", L"DelayedAutoStart",
    L"ServiceDll", L"ServiceMain", L"ServiceDllUnloadOnStop", L"ServiceDllHash", L"AllowStop"
};
#define SERVICE_BINDING_PARAMETER_FIRST 9
static const DWORD ServiceBinding_ConfigLevels[] = {
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO
};
typedef struct ServiceBindingValue {
    BYTE* data;
    DWORD size, type;
    BOOL present;
} ServiceBindingValue;
typedef struct ServiceBindingSnapshot {
    QUERY_SERVICE_CONFIGW* config;
    DWORD configBytes, extraBytes[_countof(ServiceBinding_ConfigLevels)];
    BYTE* extra[_countof(ServiceBinding_ConfigLevels)];
    ServiceBindingValue values[_countof(ServiceBinding_ValueNames)];
    BOOL running, legacy, groupMember, parametersExisted;
} ServiceBindingSnapshot;

static void ServiceBinding_Free(ServiceBindingSnapshot* snapshot)
{
    size_t i;
    if (!snapshot) { return; }
    free(snapshot->config);
    for (i = 0; i < _countof(snapshot->extra); ++i) { free(snapshot->extra[i]); }
    for (i = 0; i < _countof(snapshot->values); ++i) { free(snapshot->values[i].data); }
    free(snapshot);
}

static BOOL ServiceBinding_ReadValue(HKEY key, const wchar_t* name, ServiceBindingValue* value)
{
    LONG result = RegQueryValueExW(key, name, NULL, &value->type, NULL, &value->size);
    if (result == ERROR_FILE_NOT_FOUND) { return TRUE; }
    if (result != ERROR_SUCCESS || value->size > SERVICE_BINDING_MAX_BYTES) { return FALSE; }
    value->data = (BYTE*)calloc(1, value->size + sizeof(wchar_t) * 2);
    if (!value->data) { return FALSE; }
    result = RegQueryValueExW(key, name, NULL, &value->type, value->data, &value->size);
    if (result != ERROR_SUCCESS) { return FALSE; }
    value->present = TRUE;
    return TRUE;
}

/* Change only our membership, preserving other services added during activation. */
static BOOL ServiceBinding_Group(const wchar_t* name, BOOL restore, BOOL* member)
{
    HKEY key = NULL;
    ServiceBindingValue value = {0};
    BOOL ok = FALSE, found = FALSE;
    size_t read = 0, write = 0, chars = 0;
    wchar_t* list;
    {
        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", 0,
            KEY_QUERY_VALUE | (restore ? KEY_SET_VALUE : 0), &key);
        if (result == ERROR_FILE_NOT_FOUND && !restore) { *member = FALSE; return TRUE; }
        if (result == ERROR_FILE_NOT_FOUND && restore && !*member) { return TRUE; }
        if (result != ERROR_SUCCESS) { return FALSE; }
    }
    if (!ServiceBinding_ReadValue(key, L"netsvcs", &value)) { goto done; }
    if (!value.present)
    {
        if (!restore) { *member = FALSE; ok = TRUE; goto done; }
        if (!*member) { ok = TRUE; goto done; }
        value.size = 2 * sizeof(wchar_t); value.type = REG_MULTI_SZ;
        value.data = (BYTE*)calloc(1, value.size);
        if (!value.data) { goto done; }
    }
    if (value.type != REG_MULTI_SZ || value.size < 2 * sizeof(wchar_t) || value.size % sizeof(wchar_t)) { goto done; }
    list = (wchar_t*)value.data;
    chars = value.size / sizeof(wchar_t);
    if (list[chars - 1] != 0 || list[chars - 2] != 0) { goto done; }
    while (read < chars && list[read])
    {
        size_t length = wcslen(list + read) + 1;
        BOOL ours = _wcsicmp(list + read, name) == 0;
        found = found || ours;
        if (!restore || *member || !ours)
        {
            memmove(list + write, list + read, length * sizeof(wchar_t));
            write += length;
        }
        read += length;
    }
    if (!restore) { *member = found; ok = TRUE; goto done; }
    if (*member && !found)
    {
        size_t length = wcslen(name) + 1;
        BYTE* expanded;
        if ((write + length + 1) * sizeof(wchar_t) > SERVICE_BINDING_MAX_BYTES) { goto done; }
        expanded = (BYTE*)realloc(value.data, (write + length + 1) * sizeof(wchar_t));
        if (!expanded) { goto done; }
        value.data = expanded; list = (wchar_t*)expanded;
        memcpy(list + write, name, length * sizeof(wchar_t)); write += length;
        list[write++] = 0;
        ok = RegSetValueExW(key, L"netsvcs", 0, REG_MULTI_SZ, value.data, (DWORD)(write * sizeof(wchar_t))) == ERROR_SUCCESS;
        goto done;
    }
    if (!*member && found)
    {
        list[write++] = 0;
        if (write == 1) { list[write++] = 0; }
        ok = RegSetValueExW(key, L"netsvcs", 0, REG_MULTI_SZ, value.data, (DWORD)(write * sizeof(wchar_t))) == ERROR_SUCCESS;
    }
    else { ok = TRUE; }
done:
    free(value.data);
    RegCloseKey(key);
    return ok;
}

// Failure to inspect SCM is not evidence that a service is absent.
static BOOL ServiceBinding_QueryExists(const wchar_t* name, BOOL* exists)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service;
    DWORD error;
    if (!scm) { return FALSE; }
    service = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    error = service ? ERROR_SUCCESS : GetLastError();
    if (service) { CloseServiceHandle(service); }
    CloseServiceHandle(scm);
    if (error != ERROR_SUCCESS && error != ERROR_SERVICE_DOES_NOT_EXIST) { return FALSE; }
    *exists = service != NULL;
    return TRUE;
}

/* Ownership is established from the executable/DLL command only. Parameters
 * may be malformed: their exact prior values must remain repairable. */
static BOOL ServiceBinding_ImageSupported(const QUERY_SERVICE_CONFIGW* config,
    const wchar_t* installedExe, const wchar_t* installedDll, BOOL* legacy)
{
    wchar_t expected[2 * MAX_PATH], systemDir[MAX_PATH], parsedDll[MAX_PATH];
    const wchar_t* image = config->lpBinaryPathName;
    UINT length;
    *legacy = FALSE;
    if (!image || !installedExe || !installedDll) { return FALSE; }
    if (config->dwServiceType == SERVICE_WIN32_OWN_PROCESS)
    {
        if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"\"%ls\"", installedExe) < 0) { return FALSE; }
        if (!_wcsicmp(image, expected) || (!wcschr(installedExe, L' ') && !_wcsicmp(image, installedExe)))
        { *legacy = TRUE; return TRUE; }
        return ServiceHost_ParseImagePath(image, parsedDll, _countof(parsedDll)) && !_wcsicmp(parsedDll, installedDll);
    }
    if (config->dwServiceType != SERVICE_WIN32_SHARE_PROCESS) { return FALSE; }
    length = GetSystemDirectoryW(systemDir, _countof(systemDir));
    if (!length || length >= _countof(systemDir)) { return FALSE; }
    if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"\"%ls\\svchost.exe\" -k netsvcs", systemDir) < 0) { return FALSE; }
    if (!_wcsicmp(image, expected)) { return TRUE; }
    if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"%ls\\svchost.exe -k netsvcs", systemDir) < 0) { return FALSE; }
    return !_wcsicmp(image, expected) || !_wcsicmp(image, L"%SystemRoot%\\System32\\svchost.exe -k netsvcs") ||
        !_wcsicmp(image, L"\"%SystemRoot%\\System32\\svchost.exe\" -k netsvcs");
}

/* Reboot recovery policies require a privilege even when merely restoring
 * their configuration. Probe it before accepting a checkpoint, and restore the
 * token's previous privilege state after every attempt. */
static BOOL ServiceBinding_AcquireRecoveryPrivilege(const ServiceBindingSnapshot* snapshot,
    HANDLE* token, TOKEN_PRIVILEGES* previous)
{
    const SERVICE_FAILURE_ACTIONSW* actions = (const SERVICE_FAILURE_ACTIONSW*)snapshot->extra[1];
    TOKEN_PRIVILEGES requested = {0};
    DWORD bytes = sizeof(*previous), i;
    *token = NULL;
    for (i = 0; actions && i < actions->cActions; ++i)
    {
        if (actions->lpsaActions[i].Type != SC_ACTION_REBOOT) { continue; }
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token)) { return FALSE; }
        requested.PrivilegeCount = 1;
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!LookupPrivilegeValueW(NULL, L"SeShutdownPrivilege", &requested.Privileges[0].Luid)) { CloseHandle(*token); *token = NULL; return FALSE; }
        SetLastError(ERROR_SUCCESS);
        if (!AdjustTokenPrivileges(*token, FALSE, &requested, sizeof(*previous), previous, &bytes) || GetLastError() != ERROR_SUCCESS)
        { CloseHandle(*token); *token = NULL; return FALSE; }
        return TRUE;
    }
    return TRUE;
}
static BOOL ServiceBinding_ReleaseRecoveryPrivilege(HANDLE token, TOKEN_PRIVILEGES* previous)
{
    BOOL ok;
    if (!token) { return TRUE; }
    SetLastError(ERROR_SUCCESS);
    ok = AdjustTokenPrivileges(token, FALSE, previous, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

static ServiceBindingSnapshot* ServiceBinding_Capture(const wchar_t* name, const wchar_t* installedExe, const wchar_t* installedDll)
{
    ServiceBindingSnapshot* snapshot = (ServiceBindingSnapshot*)calloc(1, sizeof(*snapshot));
    SC_HANDLE scm = NULL, service = NULL;
    HKEY key = NULL, parameters = NULL;
    wchar_t keyPath[512];
    DWORD size = 0;
    SERVICE_STATUS_PROCESS status = {0};
    BOOL ok = FALSE;
    size_t i;
    if (!snapshot) { return NULL; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { goto done; }
    service = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
    if (!service) { goto done; }
    QueryServiceConfigW(service, NULL, 0, &size);
    if (!size || size > SERVICE_BINDING_MAX_BYTES) { goto done; }
    snapshot->configBytes = size;
    snapshot->config = (QUERY_SERVICE_CONFIGW*)calloc(1, size);
    if (!snapshot->config || !QueryServiceConfigW(service, snapshot->config, size, &size)) { goto done; }
    /* No password can be recovered through SCM. Never convert an account. */
    if (!snapshot->config->lpServiceStartName || _wcsicmp(snapshot->config->lpServiceStartName, L"LocalSystem") != 0) { goto done; }
    if (!ServiceBinding_ImageSupported(snapshot->config, installedExe, installedDll, &snapshot->legacy)) { goto done; }
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &size) ||
        (status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_STOPPED)) { goto done; }
    snapshot->running = status.dwCurrentState == SERVICE_RUNNING;
    for (i = 0; i < _countof(snapshot->extra); ++i)
    {
        size = 0;
        QueryServiceConfig2W(service, ServiceBinding_ConfigLevels[i], NULL, 0, &size);
        if (!size || size > SERVICE_BINDING_MAX_BYTES) { goto done; }
        snapshot->extraBytes[i] = size;
        snapshot->extra[i] = (BYTE*)calloc(1, size);
        if (!snapshot->extra[i] || !QueryServiceConfig2W(service, ServiceBinding_ConfigLevels[i], snapshot->extra[i], size, &size)) { goto done; }
    }
    _snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%ls", name);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) { goto done; }
    {
        LONG result = RegOpenKeyExW(key, L"Parameters", 0, KEY_QUERY_VALUE, &parameters);
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) { goto done; }
        snapshot->parametersExisted = result == ERROR_SUCCESS;
    }
    for (i = 0; i < _countof(snapshot->values); ++i)
    {
        HKEY target = i < SERVICE_BINDING_PARAMETER_FIRST ? key : parameters;
        if (target && !ServiceBinding_ReadValue(target, ServiceBinding_ValueNames[i], &snapshot->values[i])) { goto done; }
    }
    if (snapshot->config->dwServiceType == SERVICE_WIN32_SHARE_PROCESS)
    {
        /* A generic svchost command does not establish ownership. Require its
         * ServiceDll to resolve to this installation before any SCM mutation. */
        const ServiceBindingValue* dll = &snapshot->values[SERVICE_BINDING_PARAMETER_FIRST];
        wchar_t expanded[MAX_PATH];
        DWORD length;
        if (!dll->present || (dll->type != REG_SZ && dll->type != REG_EXPAND_SZ) ||
            dll->size < sizeof(wchar_t) || dll->size % sizeof(wchar_t) ||
            ((const wchar_t*)dll->data)[dll->size / sizeof(wchar_t) - 1] != L'\0' ||
            (wcslen((const wchar_t*)dll->data) + 1) * sizeof(wchar_t) != dll->size) { goto done; }
        length = ExpandEnvironmentStringsW((const wchar_t*)dll->data, expanded, _countof(expanded));
        if (!length || length > _countof(expanded) || _wcsicmp(expanded, installedDll)) { goto done; }
    }
    if (!ServiceBinding_Group(name, FALSE, &snapshot->groupMember)) { goto done; }
    {
        HANDLE privilegeToken = NULL;
        TOKEN_PRIVILEGES previous = {0};
        if (!ServiceBinding_AcquireRecoveryPrivilege(snapshot, &privilegeToken, &previous) ||
            !ServiceBinding_ReleaseRecoveryPrivilege(privilegeToken, &previous)) { goto done; }
    }
    ok = TRUE;
done:
    if (parameters) { RegCloseKey(parameters); }
    if (key) { RegCloseKey(key); }
    if (service) { CloseServiceHandle(service); }
    if (scm) { CloseServiceHandle(scm); }
    if (!ok) { ServiceBinding_Free(snapshot); snapshot = NULL; }
    return snapshot;
}

static BOOL ServiceBinding_Restore(const wchar_t* name, const ServiceBindingSnapshot* snapshot)
{
    SC_HANDLE scm = NULL, service = NULL;
    HKEY key = NULL, parameters = NULL;
    wchar_t keyPath[512];
    BOOL ok = FALSE;
    HANDLE privilegeToken = NULL;
    TOKEN_PRIVILEGES previous = {0};
    size_t i;
    const QUERY_SERVICE_CONFIGW* config;
    if (!snapshot) { return FALSE; }
    config = snapshot->config;
    if (!ServiceBinding_AcquireRecoveryPrivilege(snapshot, &privilegeToken, &previous)) { return FALSE; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { goto done; }
    service = OpenServiceW(scm, name, SERVICE_CHANGE_CONFIG | SERVICE_START);
    if (!service) { goto done; }
    _snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%ls", name);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY, &key) != ERROR_SUCCESS) { goto done; }
    if (RegCreateKeyExW(key, L"Parameters", 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &parameters, NULL) != ERROR_SUCCESS) { goto done; }
    /* Restore DLL metadata before switching back to a shared host. An
     * interruption must always leave a binding whose ownership can be proven. */
    for (i = SERVICE_BINDING_PARAMETER_FIRST; i < _countof(snapshot->values); ++i)
    {
        const ServiceBindingValue* value = &snapshot->values[i];
        HKEY target = i < SERVICE_BINDING_PARAMETER_FIRST ? key : parameters;
        LONG result;
        /* Keep SCM's temporary start permission consistent until restart. */
        if (i == 1 && snapshot->running && config->dwStartType == SERVICE_DISABLED) { continue; }
        result = value->present ? RegSetValueExW(target, ServiceBinding_ValueNames[i], 0, value->type, value->data, value->size) :
            RegDeleteValueW(target, ServiceBinding_ValueNames[i]);
        if (result != ERROR_SUCCESS && !(result == ERROR_FILE_NOT_FOUND && !value->present)) { goto done; }
    }
    /* Temporarily enable a disabled incumbent so its former running state can
     * be restored. The caller reapplies the original start type after startup. */
    if (!ChangeServiceConfigW(service, config->dwServiceType,
        snapshot->running && config->dwStartType == SERVICE_DISABLED ? SERVICE_DEMAND_START : config->dwStartType,
        config->dwErrorControl, config->lpBinaryPathName, NULL, NULL, NULL,
        NULL, NULL, config->lpDisplayName)) { goto done; }
    for (i = 0; i < _countof(snapshot->extra); ++i)
    {
        BYTE* extra = snapshot->extra[i];
        /* NULL strings/actions mean 'unchanged', not 'clear', to SCM. */
        if (ServiceBinding_ConfigLevels[i] == SERVICE_CONFIG_FAILURE_ACTIONS)
        {
            SERVICE_FAILURE_ACTIONSW actions = *(SERVICE_FAILURE_ACTIONSW*)extra;
            SC_ACTION empty = {0};
            if (!actions.lpCommand) { actions.lpCommand = L""; }
            if (!actions.lpRebootMsg) { actions.lpRebootMsg = L""; }
            if (!actions.lpsaActions) { actions.lpsaActions = &empty; }
            if (!ChangeServiceConfig2W(service, ServiceBinding_ConfigLevels[i], &actions)) { goto done; }
        }
        else if (ServiceBinding_ConfigLevels[i] == SERVICE_CONFIG_DESCRIPTION)
        {
            SERVICE_DESCRIPTIONW description = *(SERVICE_DESCRIPTIONW*)extra;
            if (!description.lpDescription) { description.lpDescription = L""; }
            if (!ChangeServiceConfig2W(service, ServiceBinding_ConfigLevels[i], &description)) { goto done; }
        }
        else if (!ChangeServiceConfig2W(service, ServiceBinding_ConfigLevels[i], extra)) { goto done; }
    }
    for (i = 0; i < SERVICE_BINDING_PARAMETER_FIRST; ++i)
    {
        const ServiceBindingValue* value = &snapshot->values[i];
        HKEY target = i < SERVICE_BINDING_PARAMETER_FIRST ? key : parameters;
        LONG result;
        /* Keep SCM's temporary start permission consistent until restart. */
        if (i == 1 && snapshot->running && config->dwStartType == SERVICE_DISABLED) { continue; }
        result = value->present ? RegSetValueExW(target, ServiceBinding_ValueNames[i], 0, value->type, value->data, value->size) :
            RegDeleteValueW(target, ServiceBinding_ValueNames[i]);
        if (result != ERROR_SUCCESS && !(result == ERROR_FILE_NOT_FOUND && !value->present)) { goto done; }
    }
    RegCloseKey(parameters); parameters = NULL;
    if (!snapshot->parametersExisted)
    {
        DWORD subkeys = 0, values = 0;
        if (RegOpenKeyExW(key, L"Parameters", 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &parameters) != ERROR_SUCCESS) { goto done; }
        if (RegQueryInfoKeyW(parameters, NULL, NULL, NULL, &subkeys, NULL, NULL, &values, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) { goto done; }
        RegCloseKey(parameters); parameters = NULL;
        if (!subkeys && !values && RegDeleteKeyW(key, L"Parameters") != ERROR_SUCCESS) { goto done; }
    }
    {
        BOOL member = snapshot->groupMember;
        if (!ServiceBinding_Group(name, TRUE, &member)) { goto done; }
    }
    ok = TRUE;
done:
    if (!ServiceBinding_ReleaseRecoveryPrivilege(privilegeToken, &previous)) { ok = FALSE; }
    if (parameters) { RegCloseKey(parameters); }
    if (key) { RegCloseKey(key); }
    if (service) { CloseServiceHandle(service); }
    if (scm) { CloseServiceHandle(scm); }
    return ok;
}
#endif
