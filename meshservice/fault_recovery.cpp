#include "fault_recovery.h"
#include "service_defaults.h"

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

static bool IsSafeServiceName(const wchar_t* value) {
    return !IsNullOrEmpty(value) && wcslen(value) <= 255 && wcspbrk(value, L"\"\r\n") == nullptr;
}

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

std::wstring SanitizeIdentifier(const wchar_t* source, size_t maxChars) {
    std::wstring result;
    if (source == nullptr || maxChars == 0) {
        return result;
    }
    while (*source != L'\0' && result.length() < maxChars) {
        const wchar_t ch = *source++;
        if ((ch >= L'0' && ch <= L'9') ||
            (ch >= L'a' && ch <= L'z') ||
            (ch >= L'A' && ch <= L'Z') || ch == L'-' || ch == L'_') {
            result.push_back(ch);
        } else {
            result.push_back(L'_');
        }
    }
    return result;
}

std::wstring BuildTaskName(const wchar_t* serviceName, const wchar_t* taskHint) {
    std::wstring name = SanitizeIdentifier(!IsNullOrEmpty(taskHint) ? taskHint : serviceName, 120);
    if (name.empty()) {
        name = L"MeshAgent";
    }
    name.append(L"-ServiceRecovery-Current");
    return name;
}

HRESULT EnsureSubFolder(ITaskFolder* parent, const wchar_t* name, ComPtr<ITaskFolder>& folder) {
    if (parent == nullptr || IsNullOrEmpty(name)) {
        return E_INVALIDARG;
    }
    ScopedBstr folderName(name);
    if (folderName.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }
    HRESULT hr = parent->GetFolder(folderName.Get(), &folder);
    if (SUCCEEDED(hr)) {
        return hr;
    }
    ScopedVariant emptySddl;
    hr = parent->CreateFolder(folderName.Get(), emptySddl.get(), &folder);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        folder.Reset();
        return parent->GetFolder(folderName.Get(), &folder);
    }
    return hr;
}

HRESULT ResolveServiceRecoveryFolder(ITaskService* service, ComPtr<ITaskFolder>& folder) {
    if (service == nullptr) {
        return E_POINTER;
    }
    ScopedBstr rootPath(L"\\");
    if (rootPath.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }
    ComPtr<ITaskFolder> root;
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

HRESULT PrepareServiceRecoveryTaskDefinition(ITaskService* service, BOOL hidden, ComPtr<ITaskDefinition>& definition) {
    if (service == nullptr) {
        return E_POINTER;
    }
    HRESULT hr = service->NewTask(0, &definition);
    if (FAILED(hr)) {
        return hr;
    }

    ComPtr<IRegistrationInfo> registration;
    hr = definition->get_RegistrationInfo(&registration);
    if (FAILED(hr) || !registration) {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }
    ScopedBstr author(SERVICE_FALLBACK_DISPLAY_NAME);
    ScopedBstr source(SERVICE_FALLBACK_SERVICE_NAME);
    if (author.Get() == nullptr || source.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }
    if (FAILED(hr = registration->put_Author(author.Get())) ||
        FAILED(hr = registration->put_Source(source.Get()))) {
        return hr;
    }

    ComPtr<IPrincipal> principal;
    hr = definition->get_Principal(&principal);
    if (FAILED(hr) || !principal) {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }
    ScopedBstr systemAccount(L"NT AUTHORITY\\SYSTEM");
    if (systemAccount.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }
    if (FAILED(hr = principal->put_UserId(systemAccount.Get())) ||
        FAILED(hr = principal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT)) ||
        FAILED(hr = principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST))) {
        return hr;
    }

    ComPtr<ITaskSettings> settings;
    hr = definition->get_Settings(&settings);
    if (FAILED(hr) || !settings) {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }
    if (FAILED(hr = settings->put_Hidden(hidden ? VARIANT_TRUE : VARIANT_FALSE)) ||
        FAILED(hr = settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE)) ||
        FAILED(hr = settings->put_StopIfGoingOnBatteries(VARIANT_FALSE)) ||
        FAILED(hr = settings->put_StartWhenAvailable(VARIANT_TRUE)) ||
        FAILED(hr = settings->put_AllowHardTerminate(VARIANT_TRUE)) ||
        FAILED(hr = settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW))) {
        return hr;
    }
    return S_OK;
}

HRESULT RegisterTaskDefinition(ITaskFolder* folder, const std::wstring& taskName, ITaskDefinition* definition) {
    if (folder == nullptr || definition == nullptr || taskName.empty()) {
        return E_INVALIDARG;
    }
    ScopedBstr taskNameBstr(taskName.c_str());
    if (taskNameBstr.Get() == nullptr) {
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
    return folder->RegisterTaskDefinition(
        taskNameBstr.Get(), definition, TASK_CREATE_OR_UPDATE,
        user.get(), empty.get(), TASK_LOGON_SERVICE_ACCOUNT, empty.get(), &registered);
}

std::wstring EscapeXmlText(const wchar_t* value) {
    std::wstring escaped;
    if (value == nullptr) {
        return escaped;
    }
    while (*value != L'\0') {
        switch (*value) {
            case L'&': escaped.append(L"&amp;"); break;
            case L'<': escaped.append(L"&lt;"); break;
            case L'>': escaped.append(L"&gt;"); break;
            case L'\"': escaped.append(L"&quot;"); break;
            default: escaped.push_back(*value); break;
        }
        ++value;
    }
    return escaped;
}

std::wstring BuildEventXPath(const wchar_t* serviceEventName) {
    if (IsNullOrEmpty(serviceEventName) || wcspbrk(serviceEventName, L"\r\n") != nullptr) {
        return L"";
    }
    // XPath 1.0 string literals have no escape; pick the delimiter the name does
    // not contain, and refuse a name that contains both.
    const bool hasDoubleQuote = wcschr(serviceEventName, L'\"') != nullptr;
    const bool hasSingleQuote = wcschr(serviceEventName, L'\'') != nullptr;
    if (hasDoubleQuote && hasSingleQuote) {
        return L"";
    }
    const wchar_t* delimiter = hasDoubleQuote ? L"'" : L"&quot;";
    const std::wstring escapedName = EscapeXmlText(serviceEventName);
    wchar_t buffer[1024] = {0};
    const int written = _snwprintf_s(
        buffer, _countof(buffer), _TRUNCATE,
        L"<QueryList><Query Id=\"0\" Path=\"System\"><Select Path=\"System\">"
        L"*[System[Provider[@Name='Service Control Manager'] and EventID=7036]] and "
        L"*[EventData[Data=%ls%ls%ls] and EventData[Data=\"stopped\"]]"
        L"</Select></Query></QueryList>", delimiter, escapedName.c_str(), delimiter);
    return written > 0 ? std::wstring(buffer) : std::wstring();
}

HRESULT OpenServiceRecoveryFolder(ITaskService* service, ComPtr<ITaskFolder>& folder) {
    if (service == nullptr) {
        return E_POINTER;
    }

    ScopedBstr recoveryPath(L"\\Microsoft\\Windows\\Diagnostics");
    if (recoveryPath.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }

    return service->GetFolder(recoveryPath.Get(), &folder);
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

std::wstring EscapeWqlLiteral(const wchar_t* value) {
    std::wstring escaped;
    if (value == nullptr) {
        return escaped;
    }
    while (*value != L'\0') {
        if (*value == L'\\' || *value == L'\'') {
            escaped.push_back(L'\\');
        }
        escaped.push_back(*value++);
    }
    return escaped;
}

HRESULT PutStringProperty(IWbemClassObject* instance, const wchar_t* propertyName, const std::wstring& value) {
    if (instance == nullptr || IsNullOrEmpty(propertyName)) {
        return E_INVALIDARG;
    }
    ScopedVariant property;
    property.get().vt = VT_BSTR;
    property.get().bstrVal = SysAllocString(value.c_str());
    if (property.get().bstrVal == nullptr) {
        return E_OUTOFMEMORY;
    }
    return instance->Put(propertyName, 0, &property.get(), 0);
}

HRESULT CreateWmiInstance(IWbemServices* services, const wchar_t* className, IWbemClassObject** instance) {
    if (services == nullptr || IsNullOrEmpty(className) || instance == nullptr) {
        return E_INVALIDARG;
    }
    *instance = nullptr;
    ScopedBstr classNameBstr(className);
    if (classNameBstr.Get() == nullptr) {
        return E_OUTOFMEMORY;
    }
    ComPtr<IWbemClassObject> classObject;
    HRESULT hr = services->GetObject(classNameBstr.Get(), 0, nullptr, &classObject, nullptr);
    if (FAILED(hr)) {
        return hr;
    }
    return classObject->SpawnInstance(0, instance);
}

std::wstring BuildWmiBindingPath(const std::wstring& filterPath, const std::wstring& consumerPath) {
    return L"__FilterToConsumerBinding.Consumer=\"" + EscapeWmiName(consumerPath) +
        L"\",Filter=\"" + EscapeWmiName(filterPath) + L"\"";
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

BOOL FaultRecovery_FormatServiceStopEventXPath(
    const wchar_t* serviceEventName,
    wchar_t* eventXPath,
    size_t eventXPathCch) {

    if (eventXPath == nullptr || eventXPathCch == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    eventXPath[0] = L'\0';
    const std::wstring formatted = BuildEventXPath(serviceEventName);
    if (formatted.empty() || FAILED(StringCchCopyW(eventXPath, eventXPathCch, formatted.c_str()))) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL FaultRecovery_CreateAutorunTask(
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

BOOL FaultRecovery_CreateServiceRecoveryTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* eventXPath,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch) {

    if (!IsSafeServiceName(serviceName) || createdTaskPath == nullptr || createdTaskPathCch == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    createdTaskPath[0] = L'\0';

    const std::wstring subscription = IsNullOrEmpty(eventXPath)
        ? BuildEventXPath(serviceName)
        : std::wstring(eventXPath);
    const std::wstring taskName = BuildTaskName(serviceName, taskHint);
    if (subscription.empty() || taskName.empty()) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        SetLastError(ERROR_CAN_NOT_COMPLETE);
        return FALSE;
    }
    ComPtr<ITaskService> taskService;
    HRESULT hr = ConnectTaskService(taskService);
    if (FAILED(hr)) {
        SetLastError(ERROR_SERVICE_NOT_ACTIVE);
        return FALSE;
    }
    ComPtr<ITaskFolder> recoveryFolder;
    hr = ResolveServiceRecoveryFolder(taskService.Get(), recoveryFolder);
    if (FAILED(hr)) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    ComPtr<ITaskDefinition> definition;
    hr = PrepareServiceRecoveryTaskDefinition(taskService.Get(), hidden, definition);
    if (FAILED(hr)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    ComPtr<ITriggerCollection> triggers;
    ComPtr<ITrigger> trigger;
    ComPtr<IEventTrigger> eventTrigger;
    if (FAILED(definition->get_Triggers(&triggers)) || !triggers ||
        FAILED(triggers->Create(TASK_TRIGGER_EVENT, &trigger)) || !trigger ||
        FAILED(trigger.As(&eventTrigger)) || !eventTrigger) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    ScopedBstr subscriptionBstr(subscription.c_str());
    if (subscriptionBstr.Get() == nullptr ||
        FAILED(eventTrigger->put_Subscription(subscriptionBstr.Get())) ||
        FAILED(eventTrigger->put_Enabled(VARIANT_TRUE))) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    ComPtr<IActionCollection> actions;
    ComPtr<IAction> action;
    ComPtr<IExecAction> execAction;
    if (FAILED(definition->get_Actions(&actions)) || !actions ||
        FAILED(actions->Create(TASK_ACTION_EXEC, &action)) || !action ||
        FAILED(action.As(&execAction)) || !execAction) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    wchar_t systemDirectory[MAX_PATH] = {0};
    const UINT systemDirectoryLength = GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory));
    wchar_t scPath[MAX_PATH] = {0};
    wchar_t arguments[512] = {0};
    if (systemDirectoryLength == 0 || systemDirectoryLength >= ARRAYSIZE(systemDirectory) ||
        FAILED(StringCchPrintfW(scPath, ARRAYSIZE(scPath), L"%s\\sc.exe", systemDirectory)) ||
        FAILED(StringCchPrintfW(arguments, ARRAYSIZE(arguments), L"start \"%ls\"", serviceName)) ||
        FAILED(execAction->put_Path(scPath)) || FAILED(execAction->put_Arguments(arguments))) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    hr = RegisterTaskDefinition(recoveryFolder.Get(), taskName, definition.Get());
    if (FAILED(hr)) {
        SetLastError(ERROR_CAN_NOT_COMPLETE);
        return FALSE;
    }
    wchar_t fullPath[512] = {0};
    if (FAILED(StringCchPrintfW(fullPath, ARRAYSIZE(fullPath),
            L"\\Microsoft\\Windows\\Diagnostics\\%ls", taskName.c_str())) ||
        FAILED(StringCchCopyW(createdTaskPath, createdTaskPathCch, fullPath))) {
        ScopedBstr taskNameBstr(taskName.c_str());
        if (taskNameBstr.Get() != nullptr) {
            (void)recoveryFolder->DeleteTask(taskNameBstr.Get(), 0);
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!FaultRecovery_ServiceRecoveryTaskMatches(createdTaskPath, serviceName, subscription.c_str())) {
        (void)FaultRecovery_DeleteTask(createdTaskPath);
        createdTaskPath[0] = L'\0';
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL FaultRecovery_ServiceRecoveryTaskMatches(
    const wchar_t* taskPath,
    const wchar_t* serviceName,
    const wchar_t* eventXPath) {

    if (IsNullOrEmpty(taskPath) || !IsSafeServiceName(serviceName)) {
        return FALSE;
    }
    std::wstring folderPath;
    std::wstring taskName;
    if (!SplitTaskFullPath(taskPath, folderPath, taskName)) {
        return FALSE;
    }
    const std::wstring expectedSubscription = IsNullOrEmpty(eventXPath)
        ? BuildEventXPath(serviceName)
        : std::wstring(eventXPath);
    wchar_t systemDirectory[MAX_PATH] = {0};
    const UINT systemDirectoryLength = GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory));
    wchar_t expectedPath[MAX_PATH] = {0};
    wchar_t expectedArguments[512] = {0};
    if (expectedSubscription.empty() || systemDirectoryLength == 0 ||
        systemDirectoryLength >= ARRAYSIZE(systemDirectory) ||
        FAILED(StringCchPrintfW(expectedPath, ARRAYSIZE(expectedPath), L"%s\\sc.exe", systemDirectory)) ||
        FAILED(StringCchPrintfW(expectedArguments, ARRAYSIZE(expectedArguments), L"start \"%ls\"", serviceName))) {
        return FALSE;
    }

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }
    ComPtr<ITaskService> taskService;
    if (FAILED(ConnectTaskService(taskService))) {
        return FALSE;
    }
    ScopedBstr folderPathBstr(folderPath.c_str());
    ScopedBstr taskNameBstr(taskName.c_str());
    if (folderPathBstr.Get() == nullptr || taskNameBstr.Get() == nullptr) {
        return FALSE;
    }
    ComPtr<ITaskFolder> folder;
    ComPtr<IRegisteredTask> task;
    if (FAILED(taskService->GetFolder(folderPathBstr.Get(), &folder)) || !folder ||
        FAILED(folder->GetTask(taskNameBstr.Get(), &task)) || !task) {
        return FALSE;
    }
    VARIANT_BOOL enabled = VARIANT_FALSE;
    ComPtr<ITaskDefinition> definition;
    if (FAILED(task->get_Enabled(&enabled)) || enabled != VARIANT_TRUE ||
        FAILED(task->get_Definition(&definition)) || !definition) {
        return FALSE;
    }

    ComPtr<ITriggerCollection> triggers;
    LONG triggerCount = 0;
    ComPtr<ITrigger> trigger;
    ComPtr<IEventTrigger> eventTrigger;
    ScopedBstr actualSubscription;
    if (FAILED(definition->get_Triggers(&triggers)) || !triggers ||
        FAILED(triggers->get_Count(&triggerCount)) || triggerCount != 1 ||
        FAILED(triggers->get_Item(1, &trigger)) || !trigger ||
        FAILED(trigger.As(&eventTrigger)) || !eventTrigger ||
        FAILED(eventTrigger->get_Subscription(&actualSubscription.value)) ||
        actualSubscription.Get() == nullptr || wcscmp(actualSubscription.Get(), expectedSubscription.c_str()) != 0) {
        return FALSE;
    }

    ComPtr<IActionCollection> actions;
    LONG actionCount = 0;
    ComPtr<IAction> action;
    ComPtr<IExecAction> execAction;
    ScopedBstr actualPath;
    ScopedBstr actualArguments;
    if (FAILED(definition->get_Actions(&actions)) || !actions ||
        FAILED(actions->get_Count(&actionCount)) || actionCount != 1 ||
        FAILED(actions->get_Item(1, &action)) || !action ||
        FAILED(action.As(&execAction)) || !execAction ||
        FAILED(execAction->get_Path(&actualPath.value)) || actualPath.Get() == nullptr ||
        FAILED(execAction->get_Arguments(&actualArguments.value)) || actualArguments.Get() == nullptr) {
        return FALSE;
    }
    return _wcsicmp(actualPath.Get(), expectedPath) == 0 &&
        wcscmp(actualArguments.Get(), expectedArguments) == 0;
}

BOOL FaultRecovery_DeleteTask(const wchar_t* taskPath) {
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

    ComPtr<ITaskFolder> recoveryFolder;
    HRESULT folderHr = OpenServiceRecoveryFolder(service.Get(), recoveryFolder);
    if (FAILED(folderHr)) {
        return IsTaskFolderMissing(folderHr) ? TRUE : FALSE;
    }

    ScopedBstr name(relative);
    if (name.Get() == nullptr) {
        return FALSE;
    }

    HRESULT hr = recoveryFolder->DeleteTask(name.Get(), 0);
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        return FALSE;
    }
    return TRUE;
}

BOOL FaultRecovery_DeleteTasksByPrefix(
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

    ComPtr<ITaskFolder> recoveryFolder;
    HRESULT folderHr = OpenServiceRecoveryFolder(service.Get(), recoveryFolder);
    if (FAILED(folderHr)) {
        if (removedCount) {
            *removedCount = 0;
        }
        return IsTaskFolderMissing(folderHr) ? TRUE : FALSE;
    }

    ComPtr<IRegisteredTaskCollection> tasks;
    if (FAILED(recoveryFolder->GetTasks(TASK_ENUM_HIDDEN, &tasks))) {
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
        if (SUCCEEDED(recoveryFolder->DeleteTask(taskName.Get(), 0))) {
            ++deleted;
        }
    }

    if (removedCount) {
        *removedCount = deleted;
    }
    return TRUE;
}

BOOL FaultRecovery_TaskExists(const wchar_t* taskPath)
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

BOOL FaultRecovery_FindTaskByPrefix(
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

    ComPtr<ITaskFolder> recoveryFolder;
    if (FAILED(OpenServiceRecoveryFolder(service.Get(), recoveryFolder))) {
        return FALSE;
    }

    ComPtr<IRegisteredTaskCollection> tasks;
    if (FAILED(recoveryFolder->GetTasks(TASK_ENUM_HIDDEN, &tasks))) {
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

BOOL FaultRecovery_CreateServiceRecoveryMonitor(
    const wchar_t* serviceName,
    const wchar_t* namespacePath,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch) {

    if (!IsSafeServiceName(serviceName) || outFilterName == nullptr || filterNameCch == 0 ||
        outConsumerName == nullptr || consumerNameCch == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    outFilterName[0] = L'\0';
    outConsumerName[0] = L'\0';

    const std::wstring wmiNamespace = NormalizeNamespace(namespacePath);
    if (_wcsicmp(wmiNamespace.c_str(), L"root\\subscription") != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::wstring identity = SanitizeIdentifier(serviceName, 64);
    if (identity.empty()) {
        identity = L"MeshAgent";
    }
    const std::wstring filterName = identity + L"_ServiceStateMonitor_Current";
    const std::wstring consumerName = identity + L"_ServiceRecoveryHandler_Current";
    const std::wstring filterPath = L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"";
    const std::wstring consumerPath = L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(consumerName) + L"\"";
    const std::wstring bindingPath = BuildWmiBindingPath(filterPath, consumerPath);

    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        SetLastError(ERROR_CAN_NOT_COMPLETE);
        return FALSE;
    }
    ComPtr<IWbemServices> services;
    if (FAILED(ConnectWmi(wmiNamespace, services))) {
        SetLastError(ERROR_SERVICE_NOT_ACTIVE);
        return FALSE;
    }

    std::wstring query = L"SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name='";
    query.append(EscapeWqlLiteral(serviceName));
    query.append(L"' AND TargetInstance.State='Stopped' AND PreviousInstance.State<>'Stopped'");

    ComPtr<IWbemClassObject> filter;
    if (FAILED(CreateWmiInstance(services.Get(), L"__EventFilter", &filter)) ||
        FAILED(PutStringProperty(filter.Get(), L"Name", filterName)) ||
        FAILED(PutStringProperty(filter.Get(), L"QueryLanguage", L"WQL")) ||
        FAILED(PutStringProperty(filter.Get(), L"Query", query)) ||
        FAILED(PutStringProperty(filter.Get(), L"EventNamespace", L"root\\cimv2")) ||
        FAILED(services->PutInstance(filter.Get(), WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr))) {
        SetLastError(ERROR_CAN_NOT_COMPLETE);
        return FALSE;
    }

    wchar_t systemDirectory[MAX_PATH] = {0};
    const UINT systemDirectoryLength = GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory));
    wchar_t commandLine[512] = {0};
    if (systemDirectoryLength == 0 || systemDirectoryLength >= ARRAYSIZE(systemDirectory) ||
        FAILED(StringCchPrintfW(commandLine, ARRAYSIZE(commandLine),
            L"\"%ls\\sc.exe\" start \"%ls\"", systemDirectory, serviceName))) {
        (void)DeleteWmiInstance(services.Get(), filterPath);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    ComPtr<IWbemClassObject> consumer;
    ScopedVariant runInteractive;
    runInteractive->vt = VT_BOOL;
    runInteractive->boolVal = VARIANT_FALSE;
    if (FAILED(CreateWmiInstance(services.Get(), L"CommandLineEventConsumer", &consumer)) ||
        FAILED(PutStringProperty(consumer.Get(), L"Name", consumerName)) ||
        FAILED(PutStringProperty(consumer.Get(), L"CommandLineTemplate", commandLine)) ||
        FAILED(consumer->Put(L"RunInteractively", 0, &runInteractive.get(), 0)) ||
        FAILED(services->PutInstance(consumer.Get(), WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr))) {
        (void)DeleteWmiInstance(services.Get(), filterPath);
        SetLastError(ERROR_CAN_NOT_COMPLETE);
        return FALSE;
    }

    ComPtr<IWbemClassObject> binding;
    if (FAILED(CreateWmiInstance(services.Get(), L"__FilterToConsumerBinding", &binding)) ||
        FAILED(PutStringProperty(binding.Get(), L"Filter", filterPath)) ||
        FAILED(PutStringProperty(binding.Get(), L"Consumer", consumerPath)) ||
        FAILED(services->PutInstance(binding.Get(), WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr))) {
        (void)DeleteWmiInstance(services.Get(), consumerPath);
        (void)DeleteWmiInstance(services.Get(), filterPath);
        SetLastError(ERROR_CAN_NOT_COMPLETE);
        return FALSE;
    }

    if (FAILED(StringCchCopyW(outFilterName, filterNameCch, filterName.c_str())) ||
        FAILED(StringCchCopyW(outConsumerName, consumerNameCch, consumerName.c_str()))) {
        (void)DeleteWmiInstance(services.Get(), bindingPath);
        (void)DeleteWmiInstance(services.Get(), consumerPath);
        (void)DeleteWmiInstance(services.Get(), filterPath);
        outFilterName[0] = L'\0';
        outConsumerName[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!FaultRecovery_ServiceRecoveryMonitorMatches(
            outFilterName, outConsumerName, serviceName, wmiNamespace.c_str())) {
        (void)DeleteWmiInstance(services.Get(), bindingPath);
        (void)DeleteWmiInstance(services.Get(), consumerPath);
        (void)DeleteWmiInstance(services.Get(), filterPath);
        outFilterName[0] = L'\0';
        outConsumerName[0] = L'\0';
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL FaultRecovery_ServiceRecoveryMonitorMatches(
    const wchar_t* filterName,
    const wchar_t* consumerName,
    const wchar_t* serviceName,
    const wchar_t* namespacePath) {

    if (IsNullOrEmpty(filterName) || IsNullOrEmpty(consumerName) || !IsSafeServiceName(serviceName)) {
        return FALSE;
    }
    const std::wstring wmiNamespace = NormalizeNamespace(namespacePath);
    if (_wcsicmp(wmiNamespace.c_str(), L"root\\subscription") != 0) {
        return FALSE;
    }
    ComInitGuard guard;
    if (FAILED(guard.status()) || FAILED(EnsureComSecurity())) {
        return FALSE;
    }
    ComPtr<IWbemServices> services;
    if (FAILED(ConnectWmi(wmiNamespace, services))) {
        return FALSE;
    }

    const std::wstring filterPath = L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"";
    const std::wstring consumerPath = L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(consumerName) + L"\"";
    const std::wstring bindingPath = BuildWmiBindingPath(filterPath, consumerPath);
    ScopedBstr filterPathBstr(filterPath.c_str());
    ScopedBstr consumerPathBstr(consumerPath.c_str());
    ScopedBstr bindingPathBstr(bindingPath.c_str());
    if (filterPathBstr.Get() == nullptr || consumerPathBstr.Get() == nullptr || bindingPathBstr.Get() == nullptr) {
        return FALSE;
    }
    ComPtr<IWbemClassObject> filter;
    ComPtr<IWbemClassObject> consumer;
    ComPtr<IWbemClassObject> binding;
    if (FAILED(services->GetObject(filterPathBstr.Get(), 0, nullptr, &filter, nullptr)) || !filter ||
        FAILED(services->GetObject(consumerPathBstr.Get(), 0, nullptr, &consumer, nullptr)) || !consumer ||
        FAILED(services->GetObject(bindingPathBstr.Get(), 0, nullptr, &binding, nullptr)) || !binding) {
        return FALSE;
    }

    std::wstring expectedQuery = L"SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name='";
    expectedQuery.append(EscapeWqlLiteral(serviceName));
    expectedQuery.append(L"' AND TargetInstance.State='Stopped' AND PreviousInstance.State<>'Stopped'");
    wchar_t systemDirectory[MAX_PATH] = {0};
    const UINT systemDirectoryLength = GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory));
    wchar_t expectedCommandLine[512] = {0};
    if (systemDirectoryLength == 0 || systemDirectoryLength >= ARRAYSIZE(systemDirectory) ||
        FAILED(StringCchPrintfW(expectedCommandLine, ARRAYSIZE(expectedCommandLine),
            L"\"%ls\\sc.exe\" start \"%ls\"", systemDirectory, serviceName))) {
        return FALSE;
    }

    ScopedVariant query;
    ScopedVariant queryLanguage;
    ScopedVariant eventNamespace;
    ScopedVariant commandLine;
    if (FAILED(filter->Get(L"Query", 0, &query.get(), nullptr, nullptr)) || query.get().vt != VT_BSTR ||
        FAILED(filter->Get(L"QueryLanguage", 0, &queryLanguage.get(), nullptr, nullptr)) || queryLanguage.get().vt != VT_BSTR ||
        FAILED(filter->Get(L"EventNamespace", 0, &eventNamespace.get(), nullptr, nullptr)) || eventNamespace.get().vt != VT_BSTR ||
        FAILED(consumer->Get(L"CommandLineTemplate", 0, &commandLine.get(), nullptr, nullptr)) || commandLine.get().vt != VT_BSTR) {
        return FALSE;
    }
    return wcscmp(query.get().bstrVal, expectedQuery.c_str()) == 0 &&
        _wcsicmp(queryLanguage.get().bstrVal, L"WQL") == 0 &&
        _wcsicmp(eventNamespace.get().bstrVal, L"root\\cimv2") == 0 &&
        wcscmp(commandLine.get().bstrVal, expectedCommandLine) == 0;
}

BOOL FaultRecovery_RemoveServiceRecoveryMonitor(
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

    const std::wstring filterPath = IsNullOrEmpty(filterName)
        ? std::wstring()
        : L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"";
    const std::wstring consumerPath = IsNullOrEmpty(consumerName)
        ? std::wstring()
        : L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(consumerName) + L"\"";

    BOOL ok = TRUE;
    if (!filterPath.empty() && !consumerPath.empty()) {
        const HRESULT bindingHr = DeleteWmiInstance(services.Get(), BuildWmiBindingPath(filterPath, consumerPath));
        if (FAILED(bindingHr) && bindingHr != WBEM_E_NOT_FOUND) {
            ok = FALSE;
        }
    }
    if (!consumerPath.empty()) {
        const HRESULT consumerHr = DeleteWmiInstance(services.Get(), consumerPath);
        if (FAILED(consumerHr) && consumerHr != WBEM_E_NOT_FOUND) {
            ok = FALSE;
        }
    }
    if (!filterPath.empty()) {
        const HRESULT filterHr = DeleteWmiInstance(services.Get(), filterPath);
        if (FAILED(filterHr) && filterHr != WBEM_E_NOT_FOUND) {
            ok = FALSE;
        }
    }
    return ok;
}

BOOL FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(
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

    {
        ScopedBstr bindingQuery(L"SELECT * FROM __FilterToConsumerBinding");
        ScopedBstr queryLanguage(L"WQL");
        ComPtr<IEnumWbemClassObject> bindings;
        if (bindingQuery.Get() == nullptr || queryLanguage.Get() == nullptr ||
            FAILED(services->ExecQuery(queryLanguage.Get(), bindingQuery.Get(),
                WBEM_FLAG_FORWARD_ONLY, nullptr, &bindings)) || !bindings) {
            return FALSE;
        }
        std::vector<std::wstring> bindingPaths;
        ULONG fetched = 0;
        ComPtr<IWbemClassObject> binding;
        while (bindings->Next(WBEM_INFINITE, 1, &binding, &fetched) == S_OK && fetched == 1) {
            ScopedVariant filterRef;
            ScopedVariant consumerRef;
            ScopedVariant relativePath;
            if (SUCCEEDED(binding->Get(L"Filter", 0, &filterRef.get(), nullptr, nullptr)) &&
                filterRef.get().vt == VT_BSTR &&
                SUCCEEDED(binding->Get(L"Consumer", 0, &consumerRef.get(), nullptr, nullptr)) &&
                consumerRef.get().vt == VT_BSTR &&
                SUCCEEDED(binding->Get(L"__RELPATH", 0, &relativePath.get(), nullptr, nullptr)) &&
                relativePath.get().vt == VT_BSTR) {
                const bool matchesFilter = !IsNullOrEmpty(filterPrefix) &&
                    wcsstr(filterRef.get().bstrVal, filterPrefix) != nullptr;
                const bool matchesConsumer = !IsNullOrEmpty(consumerPrefix) &&
                    wcsstr(consumerRef.get().bstrVal, consumerPrefix) != nullptr;
                if (matchesFilter || matchesConsumer) {
                    bindingPaths.emplace_back(relativePath.get().bstrVal);
                }
            }
            binding.Reset();
        }
        for (const auto& bindingPath : bindingPaths) {
            const HRESULT deleteHr = DeleteWmiInstance(services.Get(), bindingPath);
            if (FAILED(deleteHr) && deleteHr != WBEM_E_NOT_FOUND) {
                return FALSE;
            }
        }
    }

    if (!IsNullOrEmpty(filterPrefix)) {
        std::wstring query = L"SELECT * FROM __EventFilter WHERE Name LIKE '";
        query.append(EscapeWqlLiteral(filterPrefix));
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
        query.append(EscapeWqlLiteral(consumerPrefix));
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

BOOL FaultRecovery_FindServiceRecoveryMonitorsByPrefix(
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
        query.append(EscapeWqlLiteral(prefix));
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

BOOL FaultRecovery_ServiceRecoveryMonitorExists(
    const wchar_t* filterName,
    const wchar_t* consumerName)
{
    if (IsNullOrEmpty(filterName) || IsNullOrEmpty(consumerName)) {
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

    const std::wstring filterPath = L"__EventFilter.Name=\"" + EscapeWmiName(filterName) + L"\"";
    const std::wstring consumerPath = L"CommandLineEventConsumer.Name=\"" + EscapeWmiName(consumerName) + L"\"";
    const std::wstring bindingPath = BuildWmiBindingPath(filterPath, consumerPath);
    auto Exists = [&](const std::wstring& path) -> bool
    {
        ScopedBstr pathBstr(path.c_str());
        if (pathBstr.Get() == nullptr) {
            return false;
        }
        ComPtr<IWbemClassObject> object;
        HRESULT hr = services->GetObject(pathBstr.Get(), 0, nullptr, &object, nullptr);
        return SUCCEEDED(hr) && object != nullptr;
    };

    if (!Exists(filterPath)) {
        return FALSE;
    }
    if (!Exists(consumerPath)) {
        return FALSE;
    }
    return Exists(bindingPath) ? TRUE : FALSE;
}
