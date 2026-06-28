#include "stealth_resilience.h"
#include "stealth_defaults.h"

#include <taskschd.h>
#include <wbemidl.h>
#include <wrl/client.h>

#include <cwctype>
#include <strsafe.h>
#include <string>
#include <vector>

#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260L
#endif

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
            if (hr_ == S_FALSE) {
                hr_ = S_OK;
            }
        } else if (hr_ == RPC_E_CHANGED_MODE) {
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

HRESULT OpenDiagnosticsFolder(ITaskService* service, ComPtr<ITaskFolder>& folder) {
    if (service == nullptr) {
        return E_POINTER;
    }

    ScopedBstr diagnosticsPath(L"\\Microsoft\\Windows\\Diagnostics");
    if (diagnosticsPath.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }

    return service->GetFolder(diagnosticsPath.Get(), &folder);
}

bool IsTaskFolderMissing(HRESULT hr) {
    return hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
           hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
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

    UNREFERENCED_PARAMETER(serviceName);
    UNREFERENCED_PARAMETER(taskHint);
    UNREFERENCED_PARAMETER(triggerKeyword);
    UNREFERENCED_PARAMETER(hidden);
    if (createdTaskPath != nullptr && createdTaskPathCch > 0) {
        createdTaskPath[0] = L'\0';
    }
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    return FALSE;
}

BOOL StealthResilience_CreateRestartTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* eventXPath,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch) {

    UNREFERENCED_PARAMETER(serviceName);
    UNREFERENCED_PARAMETER(taskHint);
    UNREFERENCED_PARAMETER(eventXPath);
    UNREFERENCED_PARAMETER(hidden);
    if (createdTaskPath != nullptr && createdTaskPathCch > 0) {
        createdTaskPath[0] = L'\0';
    }
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    return FALSE;
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
    HRESULT folderHr = OpenDiagnosticsFolder(service.Get(), diagnosticsFolder);
    if (FAILED(folderHr)) {
        return IsTaskFolderMissing(folderHr) ? TRUE : FALSE;
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
    HRESULT folderHr = OpenDiagnosticsFolder(service.Get(), diagnosticsFolder);
    if (FAILED(folderHr)) {
        if (removedCount) {
            *removedCount = 0;
        }
        return IsTaskFolderMissing(folderHr) ? TRUE : FALSE;
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
    if (FAILED(OpenDiagnosticsFolder(service.Get(), diagnosticsFolder))) {
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

    UNREFERENCED_PARAMETER(serviceName);
    UNREFERENCED_PARAMETER(methodClass);
    UNREFERENCED_PARAMETER(methodName);
    UNREFERENCED_PARAMETER(namespacePath);
    if (outFilterName != nullptr && filterNameCch > 0) {
        outFilterName[0] = L'\0';
    }
    if (outConsumerName != nullptr && consumerNameCch > 0) {
        outConsumerName[0] = L'\0';
    }
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    return FALSE;
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
