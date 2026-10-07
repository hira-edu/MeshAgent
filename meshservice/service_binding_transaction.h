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
    BOOL running, legacy, legacyGroupMember, serviceGroupMember, parametersExisted;
    /* Verified before PREPARED; immutable during activation and retirement. */
    wchar_t incumbentExePath[MAX_PATH], incumbentDllPath[MAX_PATH], incumbentDbPath[MAX_PATH];
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
static BOOL ServiceBinding_Group(const wchar_t* groupName, const wchar_t* name, BOOL restore, BOOL* member, BOOL deleteEmptyValue)
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
    if (!ServiceBinding_ReadValue(key, groupName, &value)) { goto done; }
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
        ok = RegSetValueExW(key, groupName, 0, REG_MULTI_SZ, value.data, (DWORD)(write * sizeof(wchar_t))) == ERROR_SUCCESS;
        goto done;
    }
    if (!*member && found)
    {
        if (write == 0 && deleteEmptyValue)
        {
            LONG result = RegDeleteValueW(key, groupName);
            ok = result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
        }
        else
        {
            list[write++] = 0;
            if (write == 1) { list[write++] = 0; }
            ok = RegSetValueExW(key, groupName, 0, REG_MULTI_SZ, value.data, (DWORD)(write * sizeof(wchar_t))) == ERROR_SUCCESS;
        }
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

static BOOL ServiceBinding_IsLegacyExe(const wchar_t* path)
{
    const wchar_t* leaf;
    const wchar_t* p;
    if (!path || !*path) { return FALSE; }
    leaf = path;
    p = path;
    while (*p)
    {
        if (*p == L'\\' || *p == L'/') { leaf = p + 1; }
        ++p;
    }
    if (!*leaf) { return FALSE; }
    return !_wcsicmp(leaf, L"meshagent.exe") ||
           !_wcsicmp(leaf, L"MeshAgent.exe") ||
           !_wcsicmp(leaf, L"MeshService.exe") ||
           !_wcsicmp(leaf, L"MeshService64.exe") ||
           !_wcsicmp(leaf, L"MeshService-2022.exe") ||
           !_wcsicmp(leaf, L"diaghost.exe");
}

/* Migration accepts historical serialization, while requiring the actual
 * system loader and an exact supported callback. Final bindings stay canonical. */
static BOOL ServiceBinding_ParseCallbackImage(const wchar_t* image, wchar_t* dll, size_t capacity)
{
    wchar_t expanded[MAX_PATH * 4], loader[MAX_PATH], system[MAX_PATH];
    const wchar_t *p, *end, *start;
    size_t length;
    DWORD count;
    if (!image || !dll || !capacity) { return FALSE; }
    dll[0] = 0;
    count = ExpandEnvironmentStringsW(image, expanded, _countof(expanded));
    if (!count || count > _countof(expanded)) { return FALSE; }
    length = wcslen(expanded);
    while (length && (expanded[length - 1] == L' ' || expanded[length - 1] == L'\t')) { expanded[--length] = 0; }
    p = expanded;
    while (*p == L' ' || *p == L'\t') { ++p; }
    count = GetSystemDirectoryW(system, _countof(system));
    if (!count || count >= _countof(system) ||
        _snwprintf_s(loader, _countof(loader), _TRUNCATE, L"%ls\\rundll32.exe", system) < 0) { return FALSE; }
    if (*p == L'"')
    {
        start = ++p; end = wcschr(p, L'"');
        if (!end || (size_t)(end - start) != wcslen(loader) || _wcsnicmp(start, loader, end - start)) { return FALSE; }
        p = end + 1;
    }
    else
    {
        length = wcslen(loader);
        if (_wcsnicmp(p, loader, length)) { return FALSE; }
        p += length;
    }
    if (*p != L' ' && *p != L'\t') { return FALSE; }
    while (*p == L' ' || *p == L'\t') { ++p; }
    if (*p == L'"')
    {
        start = ++p; end = wcschr(p, L'"');
        if (!end || end[1] != L',') { return FALSE; }
        p = end + 2;
    }
    else
    {
        start = p; end = wcschr(p, L',');
        if (!end) { return FALSE; }
        for (p = start; p < end; ++p) { if (*p == L' ' || *p == L'\t' || *p == L'"') { return FALSE; } }
        p = end + 1;
    }
    if (wcscmp(p, L"MeshServiceHostW") && wcscmp(p, L"Stealth_SvchostServiceMain")) { return FALSE; }
    length = end - start;
    if (length < 3 || length >= capacity || start[1] != L':' || start[2] != L'\\') { return FALSE; }
    memcpy(dll, start, length * sizeof(wchar_t)); dll[length] = 0;
    /* The loader DLL contract: drive-absolute, canonical, and a .dll file. */
    if (length < 7 || length >= MAX_PATH || _wcsicmp(dll + length - 4, L".dll") ||
        !((dll[0] >= L'A' && dll[0] <= L'Z') || (dll[0] >= L'a' && dll[0] <= L'z'))) { dll[0] = 0; return FALSE; }
    for (p = dll; *p; ++p)
    {
        if (*p < L' ' || wcschr(L"\",/*?|<>", *p) || (*p == L':' && p != dll + 1)) { dll[0] = 0; return FALSE; }
    }
    count = GetFullPathNameW(dll, _countof(expanded), expanded, NULL);
    if (!count || count >= _countof(expanded) || _wcsicmp(expanded, dll)) { dll[0] = 0; return FALSE; }
    return TRUE;
}

/* Ownership is established from the executable/DLL command only. Parameters
 * may be malformed: their exact prior values must remain repairable. */
static BOOL ServiceBinding_ImageSupported(const wchar_t* name, const QUERY_SERVICE_CONFIGW* config,
    const wchar_t* installedExe, const wchar_t* installedDll, BOOL* legacy)
{
    wchar_t expected[2 * MAX_PATH], systemDir[MAX_PATH], parsedDll[MAX_PATH];
    wchar_t cleanImage[2 * MAX_PATH], extractedExe[MAX_PATH], resolvedImage[MAX_PATH * 4];
    const wchar_t* image = config->lpBinaryPathName;
    const wchar_t* imgStart;
    const wchar_t* imgEnd;
    const wchar_t* space;
    size_t cleanLen;
    UINT length;
    DWORD ownProcessMask = 0x00000010;
    *legacy = FALSE;
    if (!image || !installedExe || !installedDll) { return FALSE; }
    DWORD expandedCount = ExpandEnvironmentStringsW(image, resolvedImage, _countof(resolvedImage));
    if (!expandedCount || expandedCount > _countof(resolvedImage)) { return FALSE; }
    image = resolvedImage;
    if ((config->dwServiceType & ownProcessMask) == ownProcessMask &&
        (config->dwServiceType & ~0x00000110) == 0)
    {
        if (ServiceBinding_ParseCallbackImage(image, parsedDll, _countof(parsedDll)))
        {
            return !_wcsicmp(parsedDll, installedDll);
        }

        /* Check legacy own-process standalone executable commands. */
        imgStart = image;
        while (*imgStart == L' ' || *imgStart == L'\t') { ++imgStart; }
        imgEnd = imgStart + wcslen(imgStart);
        while (imgEnd > imgStart && (imgEnd[-1] == L' ' || imgEnd[-1] == L'\t' || imgEnd[-1] == L'\r' || imgEnd[-1] == L'\n')) { --imgEnd; }
        cleanLen = (size_t)(imgEnd - imgStart);
        if (cleanLen == 0 || cleanLen >= _countof(cleanImage)) { return FALSE; }
        memcpy(cleanImage, imgStart, cleanLen * sizeof(wchar_t));
        cleanImage[cleanLen] = L'\0';

        if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"\"%ls\"", installedExe) < 0) { return FALSE; }
        if (!_wcsicmp(cleanImage, expected) || !_wcsicmp(cleanImage, installedExe))
        {
            *legacy = TRUE;
            return TRUE;
        }

        if (cleanImage[0] == L'"')
        {
            const wchar_t* closeQuote = wcschr(cleanImage + 1, L'"');
            if (!closeQuote) { return FALSE; }
            size_t exeLen = (size_t)(closeQuote - (cleanImage + 1));
            if (exeLen == 0 || exeLen >= _countof(extractedExe)) { return FALSE; }
            memcpy(extractedExe, cleanImage + 1, exeLen * sizeof(wchar_t));
            extractedExe[exeLen] = L'\0';

            const wchar_t* after = closeQuote + 1;
            while (*after == L' ' || *after == L'\t') { ++after; }
            if (*after == L'\0')
            {
                if (!_wcsicmp(extractedExe, installedExe) || ServiceBinding_IsLegacyExe(extractedExe))
                {
                    *legacy = TRUE;
                    return TRUE;
                }
            }
            else
            {
                if ((!_wcsicmp(extractedExe, installedExe) && !_wcsicmp(after, L"-run")) || ServiceBinding_IsLegacyExe(extractedExe))
                {
                    *legacy = TRUE;
                    return TRUE;
                }
            }
        }
        else
        {
            if (!_wcsicmp(cleanImage, installedExe) || ServiceBinding_IsLegacyExe(cleanImage))
            {
                *legacy = TRUE;
                return TRUE;
            }
            space = cleanImage;
            while (*space)
            {
                if (*space != L' ' && *space != L'\t') { ++space; continue; }
                size_t partLen = (size_t)(space - cleanImage);
                if (partLen > 0 && partLen < _countof(extractedExe))
                {
                    memcpy(extractedExe, cleanImage, partLen * sizeof(wchar_t));
                    extractedExe[partLen] = L'\0';
                    const wchar_t* after = space;
                    while (*after == L' ' || *after == L'\t') { ++after; }
                    if ((!_wcsicmp(extractedExe, installedExe) && !_wcsicmp(after, L"-run")) || ServiceBinding_IsLegacyExe(extractedExe))
                    {
                        *legacy = TRUE;
                        return TRUE;
                    }
                }
                ++space;
            }
        }
        return FALSE;
    }
    if (config->dwServiceType != SERVICE_WIN32_SHARE_PROCESS) { return FALSE; }
    if (ServiceHost_IsServiceImagePath(name, image)) { return TRUE; }
    length = GetSystemDirectoryW(systemDir, _countof(systemDir));
    if (!length || length >= _countof(systemDir)) { return FALSE; }
    if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"\"%ls\\svchost.exe\" -k netsvcs", systemDir) < 0) { return FALSE; }
    if (!_wcsicmp(image, expected)) { return TRUE; }
    if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"%ls\\svchost.exe -k netsvcs", systemDir) < 0) { return FALSE; }
    if (!_wcsicmp(image, expected) || !_wcsicmp(image, L"%SystemRoot%\\System32\\svchost.exe -k netsvcs") ||
        !_wcsicmp(image, L"\"%SystemRoot%\\System32\\svchost.exe\" -k netsvcs")) { return TRUE; }
    /* Older Windows registrations append -p to isolate a shared host. */
    if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"\"%ls\\svchost.exe\" -k netsvcs -p", systemDir) < 0) { return FALSE; }
    if (!_wcsicmp(image, expected)) { return TRUE; }
    if (_snwprintf_s(expected, _countof(expected), _TRUNCATE, L"%ls\\svchost.exe -k netsvcs -p", systemDir) < 0) { return FALSE; }
    return !_wcsicmp(image, expected) || !_wcsicmp(image, L"%SystemRoot%\\System32\\svchost.exe -k netsvcs -p") ||
        !_wcsicmp(image, L"\"%SystemRoot%\\System32\\svchost.exe\" -k netsvcs -p");
}

static BOOL ServiceBinding_SharedPayloadSupported(const ServiceBindingSnapshot* snapshot, const wchar_t* installedDll)
{
    const ServiceBindingValue* dll = &snapshot->values[9];
    const ServiceBindingValue* entry = &snapshot->values[10];
    const wchar_t* dllText;
    wchar_t expanded[MAX_PATH];
    DWORD count;
    if (snapshot->config->dwServiceType != SERVICE_WIN32_SHARE_PROCESS) { return TRUE; }
    if (!dll->present || (dll->type != REG_SZ && dll->type != REG_EXPAND_SZ) ||
        !dll->data || dll->size < sizeof(wchar_t) || dll->size % sizeof(wchar_t)) { return FALSE; }
    dllText = (const wchar_t*)dll->data;
    if (dllText[dll->size / sizeof(wchar_t) - 1] ||
        (wcslen(dllText) + 1) * sizeof(wchar_t) != dll->size) { return FALSE; }
    if (!entry->present || entry->type != REG_SZ || !entry->data ||
        entry->size < sizeof(wchar_t) || entry->size % sizeof(wchar_t) ||
        ((const wchar_t*)entry->data)[entry->size / sizeof(wchar_t) - 1] != 0 ||
        (wcslen((const wchar_t*)entry->data) + 1) * sizeof(wchar_t) != entry->size ||
        (_wcsicmp((const wchar_t*)entry->data, L"ServiceHost_ServiceMain") != 0 &&
         _wcsicmp((const wchar_t*)entry->data, L"Stealth_SvchostServiceMain") != 0)) { return FALSE; }
    if (dll->type == REG_EXPAND_SZ)
    {
        count = ExpandEnvironmentStringsW(dllText, expanded, _countof(expanded));
        if (!count || count > _countof(expanded)) { return FALSE; }
        dllText = expanded;
    }
    return !_wcsicmp(dllText, installedDll);
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
    const wchar_t* failure = L"allocation";
    size_t i = 0;
    if (!snapshot) { return NULL; }
    failure = L"OpenSCManager";
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { goto done; }
    failure = L"OpenService";
    service = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
    if (!service) { goto done; }
    failure = L"QueryServiceConfig-size";
    QueryServiceConfigW(service, NULL, 0, &size);
    if (!size || size > SERVICE_BINDING_MAX_BYTES) { goto done; }
    snapshot->configBytes = size;
    failure = L"QueryServiceConfig-data";
    snapshot->config = (QUERY_SERVICE_CONFIGW*)calloc(1, size);
    if (!snapshot->config || !QueryServiceConfigW(service, snapshot->config, size, &size)) { goto done; }
    /* No password can be recovered through SCM. Never convert an account. */
    failure = L"service-account";
    if (!snapshot->config->lpServiceStartName ||
        (_wcsicmp(snapshot->config->lpServiceStartName, L"LocalSystem") != 0 &&
         _wcsicmp(snapshot->config->lpServiceStartName, L".\\LocalSystem") != 0 &&
         _wcsicmp(snapshot->config->lpServiceStartName, L"NT AUTHORITY\\System") != 0)) { goto done; }
    failure = L"service-image";
    if (!ServiceBinding_ImageSupported(name, snapshot->config, installedExe, installedDll, &snapshot->legacy)) { goto done; }
    failure = L"QueryServiceStatus";
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &size) ||
        (status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_STOPPED)) { goto done; }
    snapshot->running = status.dwCurrentState == SERVICE_RUNNING;
    for (i = 0; i < _countof(snapshot->extra); ++i)
    {
        failure = L"QueryServiceConfig2-size";
        size = 0;
        QueryServiceConfig2W(service, ServiceBinding_ConfigLevels[i], NULL, 0, &size);
        if (!size || size > SERVICE_BINDING_MAX_BYTES) { goto done; }
        failure = L"QueryServiceConfig2-data";
        snapshot->extraBytes[i] = size;
        snapshot->extra[i] = (BYTE*)calloc(1, size);
        if (!snapshot->extra[i] || !QueryServiceConfig2W(service, ServiceBinding_ConfigLevels[i], snapshot->extra[i], size, &size)) { goto done; }
    }
    _snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%ls", name);
    failure = L"service-registry";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) { goto done; }
    {
        failure = L"parameters-registry";
        LONG result = RegOpenKeyExW(key, L"Parameters", 0, KEY_QUERY_VALUE, &parameters);
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) { goto done; }
        snapshot->parametersExisted = result == ERROR_SUCCESS;
    }
    for (i = 0; i < _countof(snapshot->values); ++i)
    {
        failure = L"service-registry-value";
        HKEY target = i < SERVICE_BINDING_PARAMETER_FIRST ? key : parameters;
        if (target && !ServiceBinding_ReadValue(target, ServiceBinding_ValueNames[i], &snapshot->values[i])) { goto done; }
    }
    failure = L"shared-payload";
    if (!ServiceBinding_SharedPayloadSupported(snapshot, installedDll)) { goto done; }
    failure = L"group-membership";
    {
        wchar_t serviceGroup[64] = {0};
        if (!ServiceHost_BuildGroupName(name, serviceGroup, _countof(serviceGroup)) ||
            !ServiceBinding_Group(serviceGroup, name, FALSE, &snapshot->serviceGroupMember, TRUE) ||
            !ServiceBinding_Group(L"netsvcs", name, FALSE, &snapshot->legacyGroupMember, FALSE)) { goto done; }
    }
    {
        failure = L"recovery-privilege";
        HANDLE privilegeToken = NULL;
        TOKEN_PRIVILEGES previous = {0};
        if (!ServiceBinding_AcquireRecoveryPrivilege(snapshot, &privilegeToken, &previous) ||
            !ServiceBinding_ReleaseRecoveryPrivilege(privilegeToken, &previous)) { goto done; }
    }
    ok = TRUE;
done:
    if (!ok) { ServiceDeploy_LogInstallEvent(L"[BINDING] Capture failed at %ls (index=%Iu error=%lu type=%lu image=%ls account=%ls state=%lu)",
        failure, i, GetLastError(), snapshot && snapshot->config ? snapshot->config->dwServiceType : 0,
        snapshot && snapshot->config && snapshot->config->lpBinaryPathName ? snapshot->config->lpBinaryPathName : L"",
        snapshot && snapshot->config && snapshot->config->lpServiceStartName ? snapshot->config->lpServiceStartName : L"",
        status.dwCurrentState); }
    if (parameters) { RegCloseKey(parameters); }
    if (key) { RegCloseKey(key); }
    if (service) { CloseServiceHandle(service); }
    if (scm) { CloseServiceHandle(scm); }
    if (!ok) { ServiceBinding_Free(snapshot); snapshot = NULL; }
    return snapshot;
}

static BOOL ServiceBinding_ApplyExtra(SC_HANDLE service, size_t index, BYTE* extra)
{
    DWORD level = ServiceBinding_ConfigLevels[index];
    /* NULL strings/actions mean unchanged to SCM, not clear. */
    if (level == SERVICE_CONFIG_FAILURE_ACTIONS)
    {
        SERVICE_FAILURE_ACTIONSW actions = *(SERVICE_FAILURE_ACTIONSW*)extra;
        SC_ACTION empty = {0};
        if (!actions.lpCommand) { actions.lpCommand = L""; }
        if (!actions.lpRebootMsg) { actions.lpRebootMsg = L""; }
        if (!actions.lpsaActions) { actions.lpsaActions = &empty; }
        return ChangeServiceConfig2W(service, level, &actions);
    }
    if (level == SERVICE_CONFIG_DESCRIPTION)
    {
        SERVICE_DESCRIPTIONW description = *(SERVICE_DESCRIPTIONW*)extra;
        if (!description.lpDescription) { description.lpDescription = L""; }
        return ChangeServiceConfig2W(service, level, &description);
    }
    return ChangeServiceConfig2W(service, level, extra);
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
        if (i == 1) { continue; }
        result = value->present ? RegSetValueExW(target, ServiceBinding_ValueNames[i], 0, value->type, value->data, value->size) :
            RegDeleteValueW(target, ServiceBinding_ValueNames[i]);
        if (result != ERROR_SUCCESS && !(result == ERROR_FILE_NOT_FOUND && !value->present)) { goto done; }
    }
    /* Keep launches disabled until binding and recovery restoration finish. */
    if (!ChangeServiceConfigW(service, config->dwServiceType,
        SERVICE_DISABLED,
        config->dwErrorControl, config->lpBinaryPathName, NULL, NULL, NULL,
        NULL, NULL, config->lpDisplayName)) { goto done; }
    for (i = 0; i < _countof(snapshot->extra); ++i)
    {
        if (i == 1 || i == 2) { continue; }
        if (!ServiceBinding_ApplyExtra(service, i, snapshot->extra[i])) { goto done; }
    }
    for (i = 0; i < SERVICE_BINDING_PARAMETER_FIRST; ++i)
    {
        const ServiceBindingValue* value = &snapshot->values[i];
        HKEY target = i < SERVICE_BINDING_PARAMETER_FIRST ? key : parameters;
        LONG result;
        /* Keep SCM's temporary start permission consistent until restart. */
        if (i == 1) { continue; }
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
        wchar_t serviceGroup[64] = {0};
        BOOL serviceMember = snapshot->serviceGroupMember;
        BOOL legacyMember = snapshot->legacyGroupMember;
        if (!ServiceHost_BuildGroupName(name, serviceGroup, _countof(serviceGroup)) ||
            !ServiceBinding_Group(serviceGroup, name, TRUE, &serviceMember, TRUE) ||
            !ServiceBinding_Group(L"netsvcs", name, TRUE, &legacyMember, FALSE)) { goto done; }
    }
    if (!ServiceBinding_ApplyExtra(service, 1, snapshot->extra[1]) ||
        !ServiceBinding_ApplyExtra(service, 2, snapshot->extra[2])) { goto done; }
    if (!ChangeServiceConfigW(service, SERVICE_NO_CHANGE,
        snapshot->running && config->dwStartType == SERVICE_DISABLED ? SERVICE_DEMAND_START : config->dwStartType,
        SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) { goto done; }
    if (!(snapshot->running && config->dwStartType == SERVICE_DISABLED))
    {
        const ServiceBindingValue* value = &snapshot->values[1];
        LONG result = value->present ? RegSetValueExW(key, L"Start", 0, value->type, value->data, value->size) : RegDeleteValueW(key, L"Start");
        if (result != ERROR_SUCCESS && !(result == ERROR_FILE_NOT_FOUND && !value->present)) { goto done; }
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
