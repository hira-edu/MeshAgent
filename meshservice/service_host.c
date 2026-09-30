/*
 * MeshAgent rundll32 Service Hosting Implementation
 *
 * Hosts MeshAgent through the approved MeshServiceHostW rundll32 callback
 * and an own-process SCM service. The selected host mode remains visible in service
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

// Global state for rundll32-hosted service
static SERVICE_STATUS_HANDLE g_ServiceHostStatusHandle = NULL;
static SERVICE_STATUS g_ServiceHostStatus = {0};
static BOOL g_ServiceHostRunning = FALSE;
static wchar_t g_ServiceHostServiceName[256] = {0};
static char g_ServiceHostServiceNameUtf8[1024] = {0};

static void ServiceHost_ReportStopDenial(void)
{
    wchar_t logName[256] = {0};
    StringCchCopyW(logName, _countof(logName), g_ServiceHostServiceName);
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
    // SCM's actual key is authoritative even when the installed service was renamed.
    const wchar_t* serviceKeyName = g_ServiceHostServiceName;
    if (!serviceKeyName[0]) { return FALSE; }

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
    OVERLAPPED overlapped;

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
    ZeroMemory(&overlapped, sizeof(overlapped));
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (overlapped.hEvent == NULL)
    {
        ctx->readError = GetLastError();
        ServiceHost_LogLine(L"KvmSessionBridgeW input event creation failed (error=%lu)", ctx->readError);
        kvm_server_request_shutdown();
        return 0;
    }

    // The control pipe is opened for overlapped I/O, so this thread blocks in
    // the read itself: input reaches the capture code as soon as it arrives
    // instead of on the next polling slice, and the main thread's CancelIoEx
    // ends the read when the helper shuts down.
    while (!g_shutdown)
    {
        DWORD read = 0;
        DWORD readError = ERROR_SUCCESS;

        if (len >= (int)sizeof(packetBuffer))
        {
            ctx->readError = ERROR_INSUFFICIENT_BUFFER;
            kvm_server_request_shutdown();
            break;
        }

        ResetEvent(overlapped.hEvent);
        if (!ReadFile(inputHandle, packetBuffer + len, (DWORD)(sizeof(packetBuffer) - len), NULL, &overlapped))
        {
            readError = GetLastError();
            if (readError != ERROR_IO_PENDING)
            {
                ctx->readError = (readError != ERROR_SUCCESS) ? readError : ERROR_BROKEN_PIPE;
                ServiceHost_LogLine(L"KvmSessionBridgeW input pipe closed (error=%lu read=%lu)", ctx->readError, read);
                kvm_server_request_shutdown();
                break;
            }
        }
        if (!GetOverlappedResult(inputHandle, &overlapped, &read, TRUE) || read == 0)
        {
            ctx->readError = GetLastError();
            if (ctx->readError == ERROR_SUCCESS) { ctx->readError = ERROR_BROKEN_PIPE; }
            if (g_shutdown == 0)
            {
                ServiceHost_LogLine(L"KvmSessionBridgeW input pipe closed (error=%lu read=%lu)", ctx->readError, read);
            }
            kvm_server_request_shutdown();
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
                kvm_server_request_shutdown();
                CloseHandle(overlapped.hEvent);
                return 0;
            }
            if ((len - ptr) < size) { break; }

            if (type == MNG_KVM_DISCONNECT)
            {
                ptr += size;
                kvm_server_request_shutdown();
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

    CloseHandle(overlapped.hEvent);
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

static DWORD KvmBridge_ErrorOr(DWORD errorCode, DWORD fallback)
{
    return (errorCode != ERROR_SUCCESS) ? errorCode : fallback;
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
    // Non-zero when the helper ends because of a failure. The parent logs the exit code and applies
    // its restart backoff, so each refusal and transport error gets its own code instead of 0.
    DWORD bridgeExitCode = ERROR_SUCCESS;

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
        ExitProcess(ERROR_INVALID_PARAMETER);
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
        bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_PIPE_NOT_CONNECTED);
        ServiceHost_LogLine(L"KvmSessionBridgeW WaitNamedPipeW failed (error=%lu, pipe=%ls)", bridgeExitCode, controlPipeName);
        ExitProcess(bridgeExitCode);
    }
    if (useNamedPipeBridge && !WaitNamedPipeW(dataPipeName, KVM_BRIDGE_CONNECT_TIMEOUT_MS))
    {
        bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_PIPE_NOT_CONNECTED);
        ServiceHost_LogLine(L"KvmSessionBridgeW WaitNamedPipeW failed (error=%lu, pipe=%ls)", bridgeExitCode, dataPipeName);
        ExitProcess(bridgeExitCode);
    }

    if (useNamedPipeBridge)
    {
        ctx.controlPipeHandle = CreateFileW(controlPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
        if (ctx.controlPipeHandle == INVALID_HANDLE_VALUE)
        {
            bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_PIPE_NOT_CONNECTED);
            ServiceHost_LogLine(L"KvmSessionBridgeW CreateFileW failed (error=%lu, pipe=%ls)", bridgeExitCode, controlPipeName);
            goto cleanup;
        }
        ServiceHost_LogLine(L"KvmSessionBridgeW control pipe connected after %llu ms", (unsigned long long)(GetTickCount64() - bridgeStartTickMs));
        ctx.dataPipeHandle = CreateFileW(dataPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (ctx.dataPipeHandle == INVALID_HANDLE_VALUE)
        {
            bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_PIPE_NOT_CONNECTED);
            ServiceHost_LogLine(L"KvmSessionBridgeW CreateFileW failed (error=%lu, pipe=%ls)", bridgeExitCode, dataPipeName);
            goto cleanup;
        }
        ServiceHost_LogLine(L"KvmSessionBridgeW data pipe connected after %llu ms", (unsigned long long)(GetTickCount64() - bridgeStartTickMs));
        if (!DuplicateHandle(GetCurrentProcess(), ctx.controlPipeHandle, GetCurrentProcess(), &bridgeStdIn, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_INVALID_HANDLE);
            ServiceHost_LogLine(L"KvmSessionBridgeW DuplicateHandle(stdin) failed (error=%lu)", bridgeExitCode);
            goto cleanup;
        }
        if (!DuplicateHandle(GetCurrentProcess(), ctx.dataPipeHandle, GetCurrentProcess(), &bridgeStdOut, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_INVALID_HANDLE);
            ServiceHost_LogLine(L"KvmSessionBridgeW DuplicateHandle(stdout) failed (error=%lu)", bridgeExitCode);
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
        bridgeExitCode = ERROR_NOT_ENOUGH_MEMORY;
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
        bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_NOT_ENOUGH_MEMORY);
        ServiceHost_LogLine(L"KvmSessionBridgeW mainloop CreateThread failed (error=%lu)", bridgeExitCode);
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
                if (shutdownObservedTickMs == 0)
                {
                    bridgeExitCode = (ctx.readError != ERROR_SUCCESS) ? ctx.readError : ctx.writeError;
                }
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
                    // Errors after this point come from cancelling I/O below, not from the cause.
                    bridgeExitCode = (ctx.readError != ERROR_SUCCESS) ? ctx.readError : ctx.writeError;
                    ServiceHost_LogLine(L"KvmSessionBridgeW observed shutdown (cause=%lu); cancelling bridge transport I/O", bridgeExitCode);
                    // Whatever set g_shutdown, also release a mainloop parked in
                    // its startup resume wait so it exits within the grace period.
                    kvm_server_request_shutdown();
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
        // The input thread reads through the duplicated stdin handle; cancel
        // on both handles so its pending overlapped read completes.
        KvmBridge_CancelTransportIo(&ctx, bridgeStdIn, NULL);
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
    if (bridgeExitCode != ERROR_SUCCESS)
    {
        ServiceHost_LogLine(L"KvmSessionBridgeW exiting with code %lu", bridgeExitCode);
        ExitProcess(bridgeExitCode);
    }
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
    ServiceUtil_DebugPrintfW(L"[service-host] CRT invalid parameter: expr=%ls func=%ls file=%ls line=%u",
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
        ServiceUtil_DebugPrintfW(L"[service-host] module path: %ls", g_ServiceHostModulePath);
        ServiceUtil_DebugPrintfW(L"[service-host] install directory: %ls", g_ServiceHostInstallDir);
        _snwprintf_s(g_ServiceHostLogFile, _countof(g_ServiceHostLogFile), _TRUNCATE, L"%s\\service-host-debug.log", g_ServiceHostInstallDir);
        ServiceHost_LogLine(L"module path: %ls", g_ServiceHostModulePath);
        ServiceHost_LogLine(L"install directory: %ls", g_ServiceHostInstallDir);
        ServiceHost_InstallCrtHandlers();
        if (ServiceHost_CanHardenModuleDacl())
        {
            if (!ServiceHost_EnsureModuleDacl())
            {
                DWORD aclError = GetLastError();
                if (aclError == ERROR_SUCCESS) { aclError = ERROR_ACCESS_DENIED; }
                ServiceUtil_DebugPrintfW(L"[service-host] failed to apply DLL DACL to %ls (error=%lu)", g_ServiceHostModulePath, aclError);
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
        ServiceUtil_DebugPrintfW(L"[service-host] unable to resolve module path for DLL");
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

        MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), brandedName, _countof(brandedName));
        if (brandedName[0] == L'\0')
        {
            lstrcpynW(brandedName, SERVICE_FALLBACK_EXE_NAME, (int)_countof(brandedName));
        }
        ServiceHost_LogLine(L"branding binary name resolved: %ls", brandedName[0] != L'\0' ? brandedName : L"(empty)");

        if (g_ServiceHostInstallDir[0] != L'\0')
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
                    ServiceUtil_DebugPrintfW(L"[service-host] helper executable detected: %ls", helperPath);
                    ServiceHost_LogLine(L"helper executable: %ls", helperPath);
                }
                else
                {
                    ServiceUtil_DebugPrintfW(L"[service-host] configured helper executable is missing: %ls", helperPath);
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
        ServiceUtil_DebugPrintfA("[service-host] failed to initialise UTF-8 module buffer");
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
        ServiceUtil_DebugPrintfW(L"[service-host] install directory unavailable; provisioning files cannot be validated");
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
            ServiceUtil_DebugPrintfW(L"[service-host] executable sibling provisioning file %ls (%ls)",
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
        ServiceUtil_DebugPrintfW(L"[service-host] configuration file %ls (%ls)",
                             candidatePath,
                             (attr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
        ServiceHost_LogLine(L"configuration file %ls (%ls)",
                               candidatePath,
                               (attr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
    }
}

/**
 * Service control handler for rundll32-hosted mode
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
            ServiceUtil_DebugPrintfA("[service-host] Forwarding KVM session change event=%lu session=%lu", (unsigned long)dwEventType, (unsigned long)sessionId);
            ServiceHost_LogLine(L"Forwarding KVM session change event=%lu session=%lu", (unsigned long)dwEventType, (unsigned long)sessionId);
            kvm_notify_session_change(dwEventType, sessionId);
#endif
            return NO_ERROR;
        }

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static BOOL ServiceHost_AcceptScmName(DWORD argc, LPWSTR* argv)
{
    size_t length;
    if (!argc || !argv || !argv[0]) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    length = wcsnlen_s(argv[0], _countof(g_ServiceHostServiceName));
    if (!length || length >= _countof(g_ServiceHostServiceName)) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    for (size_t i = 0; i < length; ++i)
    {
        if (argv[0][i] < L' ' || argv[0][i] == L'\\' || argv[0][i] == L'/')
        {
            SetLastError(ERROR_INVALID_NAME);
            return FALSE;
        }
    }
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[0], -1,
        g_ServiceHostServiceNameUtf8, sizeof(g_ServiceHostServiceNameUtf8), NULL, NULL)) { return FALSE; }
    StringCchCopyW(g_ServiceHostServiceName, _countof(g_ServiceHostServiceName), argv[0]);
    ServiceDeploy_SetRuntimeServiceKeyNameUtf8(g_ServiceHostServiceNameUtf8);
    return TRUE;
}

/**
 * Private SCM entry point dispatched by MeshServiceHostW.
 */
static VOID WINAPI ServiceHost_ServiceMain(DWORD dwArgc, LPWSTR* lpszArgv)
{
    if (!ServiceHost_AcceptScmName(dwArgc, lpszArgv))
    {
        g_ServiceHostStatus.dwWin32ExitCode = GetLastError();
        return;
    }

    // Register service control handler
    ServiceHost_LogLine(L"ServiceMain invoked (argc=%lu)", (unsigned long)dwArgc);
    g_ServiceHostStatusHandle = RegisterServiceCtrlHandlerExW(
        g_ServiceHostServiceName,
        (LPHANDLER_FUNCTION_EX)ServiceHost_CtrlHandler,
        NULL                    // Context
    );

    if (!g_ServiceHostStatusHandle)
    {
        g_ServiceHostStatus.dwWin32ExitCode = GetLastError();
        ServiceUtil_DebugLastErrorW(L"RegisterServiceCtrlHandlerExW");
        return;  // Failed to register handler
    }

    // Initialize service status structure
    g_ServiceHostStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
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
        ServiceUtil_DebugPrintfA("MeshAgent_Create failed in rundll32 service main");
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

    g_ServiceHostAgent->meshServiceName = ILibString_Copy(g_ServiceHostServiceNameUtf8, 0);
    ServiceHost_LogLine(L"SCM service name set to %hs", g_ServiceHostAgent->meshServiceName);
    mesh_branding_text_t serviceDisplayText = MeshService_GetServiceNameText();
#if defined(UNICODE) || defined(_UNICODE)
    if (serviceDisplayText != NULL)
    {
        char utf8Display[256] = {0};
        if (WideCharToMultiByte(CP_UTF8, 0, serviceDisplayText, -1, utf8Display, (int)sizeof(utf8Display), NULL, NULL) > 0)
        {
            g_ServiceHostAgent->displayName = ILibString_Copy(utf8Display, 0);
        }
    }
#else
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
    // This prevents Task Manager and TerminateProcess() from killing the service host process
    // NOTE: This is different from ServiceUtil_ProtectServiceFromTermination() which only
    // protects the SERVICE object in SCM. This protects the actual PROCESS.
    if (ServiceUtil_ProtectCurrentProcess())
    {
        ServiceHost_LogLine(L"Process termination protection applied successfully");
        ServiceUtil_DebugPrintfW(L"[service-host] Process DACL protection active - TerminateProcess blocked");
    }
    else
    {
        ServiceHost_LogLine(L"WARNING: Failed to apply process termination protection");
        ServiceUtil_DebugPrintfW(L"[service-host] WARNING: Process DACL protection failed");
    }

    g_ServiceHostRunning = TRUE;

    char* startArgv[2] = { NULL, NULL };
    if (g_ServiceHostArgv[0] != NULL)
    {
        startArgv[0] = g_ServiceHostArgv[0];
    }
    if (startArgv[0] == NULL)
    {
        ServiceUtil_DebugPrintfA("[service-host] configured helper path is unavailable; refusing to start MeshAgent core");
        ServiceHost_LogLine(L"configured helper path unavailable; MeshAgent_Start skipped");
        g_ServiceHostStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceHostStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_ServiceHostStatus.dwServiceSpecificExitCode = 2;
        SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);
        return;
    }
    int startArgc = 1;

    ServiceUtil_DebugPrintfA("[service-host] launching MeshAgent_Start (argv[0]=%s)", startArgv[0]);
    ServiceHost_LogLine(L"launching MeshAgent_Start (argv0=%hs)", startArgv[0]);
    int startResult = MeshAgent_Start(g_ServiceHostAgent, startArgc, startArgv);
    ServiceUtil_DebugPrintfA("[service-host] MeshAgent_Start returned %d", startResult);
    ServiceHost_LogLine(L"MeshAgent_Start returned %d", startResult);
    if (g_ServiceHostAgent != NULL)
    {
        ServiceHost_LogLine(L"MeshAgent exit code %d", g_ServiceHostAgent->exitCode);
    }
    // A normal core return is not an SCM stop request. Report an unexpected
    // return as failure so the configured non-crash recovery actions can run.
    if (g_ServiceHostStatus.dwCurrentState != SERVICE_STOP_PENDING)
    {
        g_ServiceHostStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_ServiceHostStatus.dwServiceSpecificExitCode =
            (g_ServiceHostAgent != NULL && g_ServiceHostAgent->exitCode != 0) ?
                (DWORD)g_ServiceHostAgent->exitCode : ERROR_PROCESS_ABORTED;
        ServiceHost_LogLine(L"Agent returned without a service stop request; reporting failure to SCM (%lu)",
            g_ServiceHostStatus.dwServiceSpecificExitCode);
    }
    g_ServiceHostAgent = NULL;
    g_ServiceHostRunning = FALSE;

    // Service has stopped
    g_ServiceHostStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_ServiceHostStatusHandle, &g_ServiceHostStatus);
}

/* One command contract for registration, discovery and the runtime callback.
 * Reject relative paths and syntax that could alter rundll32's entry selection. */
BOOL ServiceHost_BuildImagePath(const wchar_t* dllPath, wchar_t* command, size_t commandCch)
{
    wchar_t host[MAX_PATH * 4] = {0};
    wchar_t absolute[MAX_PATH * 4] = {0};
    DWORD length;
    if (!dllPath || !command || !commandCch) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    command[0] = 0;
    length = (DWORD)wcslen(dllPath);
    if (length < 4 || length >= MAX_PATH || _wcsicmp(dllPath + length - 4, L".dll") != 0 ||
        !((dllPath[0] >= L'A' && dllPath[0] <= L'Z') || (dllPath[0] >= L'a' && dllPath[0] <= L'z')) ||
        dllPath[1] != L':' || dllPath[2] != L'\\') { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    for (DWORD i = 0; i < length; ++i)
    {
        if (dllPath[i] < L' ' || wcschr(L"\",/*?|<>", dllPath[i]) || (dllPath[i] == L':' && i != 1))
        {
            SetLastError(ERROR_INVALID_NAME);
            return FALSE;
        }
    }
    length = GetFullPathNameW(dllPath, _countof(absolute), absolute, NULL);
    if (!length || length >= _countof(absolute) || _wcsicmp(absolute, dllPath) != 0) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    if (!MeshRundll32_GetSystemRundll32PathW(host, _countof(host))) { return FALSE; }
    if (FAILED(StringCchPrintfW(command, commandCch, L"\"%ls\" \"%ls\",%ls", host, dllPath, MESH_RUNDLL32_ENTRY_SERVICE_W)))
    {
        command[0] = 0;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

BOOL ServiceHost_ParseImagePath(const wchar_t* command, wchar_t* dllPath, size_t dllPathCch)
{
    const wchar_t* hostEnd;
    const wchar_t* dllStart;
    const wchar_t* dllEnd;
    wchar_t canonical[MAX_PATH * 8] = {0};
    size_t length;
    if (!command || !dllPath || !dllPathCch) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    dllPath[0] = 0;
    if (command[0] != L'"' || !(hostEnd = wcschr(command + 1, L'"')) ||
        wcsncmp(hostEnd, L"\" \"", 3) != 0) { return FALSE; }
    dllStart = hostEnd + 3;
    dllEnd = wcschr(dllStart, L'"');
    if (!dllEnd || wcscmp(dllEnd, L"\"," MESH_RUNDLL32_ENTRY_SERVICE_W) != 0) { return FALSE; }
    length = (size_t)(dllEnd - dllStart);
    if (!length || length >= dllPathCch) { return FALSE; }
    memcpy(dllPath, dllStart, length * sizeof(wchar_t));
    dllPath[length] = 0;
    if (!ServiceHost_BuildImagePath(dllPath, canonical, _countof(canonical)) || _wcsicmp(canonical, command) != 0)
    {
        dllPath[0] = 0;
        return FALSE;
    }
    return TRUE;
}

void CALLBACK MeshServiceHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t configuredDll[MAX_PATH * 4] = {0};
    wchar_t loadedDll[MAX_PATH * 4] = {0};
    wchar_t process[MAX_PATH * 4] = {0};
    wchar_t systemHost[MAX_PATH * 4] = {0};
    SERVICE_TABLE_ENTRYW table[2] = {0};
    DWORD length, exitCode = ERROR_INVALID_PARAMETER;
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);
    /* W-suffix rundll32 callbacks must parse the authoritative Unicode command
     * line, not lpCmdLine (which can carry ANSI bytes on some Windows paths). */
    if (!hinstDLL || !ServiceHost_ParseImagePath(GetCommandLineW(), configuredDll, _countof(configuredDll))) { goto done; }
    length = GetModuleFileNameW(hinstDLL, loadedDll, _countof(loadedDll));
    if (!length || length >= _countof(loadedDll) || _wcsicmp(loadedDll, configuredDll) != 0) { goto done; }
    length = GetModuleFileNameW(NULL, process, _countof(process));
    if (!length || length >= _countof(process) ||
        !MeshRundll32_GetSystemRundll32PathW(systemHost, _countof(systemHost)) || _wcsicmp(process, systemHost) != 0) { goto done; }
    // SCM ignores this entry name for OWN_PROCESS services and supplies the
    // actual installed key as ServiceMain argv[0].
    table[0].lpServiceName = L"";
    table[0].lpServiceProc = ServiceHost_ServiceMain;
    if (!StartServiceCtrlDispatcherW(table)) { exitCode = GetLastError(); goto done; }
    exitCode = g_ServiceHostStatus.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR ?
        g_ServiceHostStatus.dwServiceSpecificExitCode : g_ServiceHostStatus.dwWin32ExitCode;
done:
    if (exitCode != ERROR_SUCCESS) { ServiceHost_LogLine(L"Primary rundll32 service host exited with error %lu", exitCode); }
    ExitProcess(exitCode);
}

/* Migration/uninstall cleanup only: the current runtime never joins a shared
 * host group. Preserve every unrelated membership and registry value. */
static BOOL ServiceHost_RemoveLegacyGroupMembership(const wchar_t* serviceName)
{
    HKEY key = NULL;
    DWORD size = 0, type = 0;
    wchar_t* list = NULL;
    size_t read = 0, written = 0, chars;
    BOOL found = FALSE, ok = FALSE;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) { return TRUE; }
    if (result != ERROR_SUCCESS) { return FALSE; }
    result = RegQueryValueExW(key, L"netsvcs", NULL, &type, NULL, &size);
    if (result == ERROR_FILE_NOT_FOUND) { ok = TRUE; goto done; }
    if (result != ERROR_SUCCESS || type != REG_MULTI_SZ || size < 2 * sizeof(wchar_t) ||
        size > 65536 || size % sizeof(wchar_t)) { goto done; }
    list = (wchar_t*)calloc(1, size);
    if (!list || RegQueryValueExW(key, L"netsvcs", NULL, &type, (BYTE*)list, &size) != ERROR_SUCCESS || type != REG_MULTI_SZ) { goto done; }
    if (size < 2 * sizeof(wchar_t) || size % sizeof(wchar_t)) { goto done; }
    chars = size / sizeof(wchar_t);
    if (list[chars - 1] || list[chars - 2]) { goto done; }
    while (read < chars && list[read])
    {
        size_t length = wcslen(list + read) + 1;
        if (_wcsicmp(list + read, serviceName) == 0) { found = TRUE; }
        else { memmove(list + written, list + read, length * sizeof(wchar_t)); written += length; }
        read += length;
    }
    if (!found) { ok = TRUE; goto done; }
    list[written++] = 0;
    if (written == 1) { list[written++] = 0; }
    ok = RegSetValueExW(key, L"netsvcs", 0, REG_MULTI_SZ, (BYTE*)list, (DWORD)(written * sizeof(wchar_t))) == ERROR_SUCCESS;
done:
    free(list);
    RegCloseKey(key);
    return ok;
}

static BOOL ServiceHost_RemoveLegacyParameters(const wchar_t* serviceName)
{
    const wchar_t* names[] = {L"ServiceDll", L"ServiceMain", L"ServiceDllUnloadOnStop"};
    wchar_t keyPath[512] = {0};
    HKEY key = NULL;
    size_t i;
    LONG result;
    if (FAILED(StringCchPrintfW(keyPath, _countof(keyPath), L"SYSTEM\\CurrentControlSet\\Services\\%ls\\Parameters", serviceName))) { return FALSE; }
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &key);
    if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) { return TRUE; }
    if (result != ERROR_SUCCESS) { return FALSE; }
    for (i = 0; i < _countof(names); ++i)
    {
        result = RegDeleteValueW(key, names[i]);
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) { RegCloseKey(key); return FALSE; }
    }
    RegCloseKey(key);
    return TRUE;
}

BOOL ServiceHost_RegisterServiceHostService(const wchar_t* serviceName, const wchar_t* dllPath)
{
    SC_HANDLE scm = NULL, service = NULL;
    wchar_t command[MAX_PATH * 8] = {0}, displayName[256] = {0}, description[512] = {0};
    SERVICE_SID_INFO sid = {SERVICE_SID_TYPE_UNRESTRICTED};
    SERVICE_DESCRIPTIONW descriptionInfo;
    BOOL ok = FALSE;
    DWORD error = ERROR_SUCCESS;
    if (!serviceName || !serviceName[0] || !ServiceHost_BuildImagePath(dllPath, command, _countof(command))) { return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(NULL, 0, displayName, _countof(displayName), description, _countof(description));
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) { goto done; }
    service = CreateServiceW(scm, serviceName, displayName[0] ? displayName : serviceName,
        SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS | DELETE,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command,
        NULL, NULL, NULL, L"LocalSystem", NULL);
    if (!service)
    {
        DWORD bytes = 0;
        QUERY_SERVICE_CONFIGW* config = NULL;
        BOOL compatible = FALSE;
        if (GetLastError() != ERROR_SERVICE_EXISTS) { goto done; }
        service = OpenServiceW(scm, serviceName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
        if (!service) { goto done; }
        QueryServiceConfigW(service, NULL, 0, &bytes);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes && bytes <= 65536)
        {
            config = (QUERY_SERVICE_CONFIGW*)calloc(1, bytes);
            if (config && QueryServiceConfigW(service, config, bytes, &bytes))
            {
                compatible = config->lpServiceStartName && _wcsicmp(config->lpServiceStartName, L"LocalSystem") == 0;
            }
        }
        free(config);
        if (!compatible) { SetLastError(ERROR_NOT_SUPPORTED); goto done; }
        /* NULL account AND NULL password preserve SCM-held credentials. */
        if (!ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL, command, NULL, NULL, NULL, NULL, NULL,
            displayName[0] ? displayName : NULL)) { goto done; }
    }
    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid)) { goto done; }
    descriptionInfo.lpDescription = description;
    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &descriptionInfo)) { goto done; }
    if (!ServiceHost_RemoveLegacyParameters(serviceName) || !ServiceHost_RemoveLegacyGroupMembership(serviceName)) { goto done; }
    ok = TRUE;
done:
    error = GetLastError();
    if (service) { CloseServiceHandle(service); }
    if (scm) { CloseServiceHandle(scm); }
    if (!ok) { SetLastError(error); }
    return ok;
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
    if (!ServiceHost_RemoveLegacyGroupMembership(serviceName)) { success = FALSE; }

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
    UNREFERENCED_PARAMETER(lpvReserved);
    // Do not initialize the agent, touch files/DACLs or stop worker threads under
    // the loader lock. Each approved callback initializes its own runtime.
    if (fdwReason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(hinstDLL); }
    return TRUE;
}
#endif // BUILD_SERVICE_BUNDLE_DLL
