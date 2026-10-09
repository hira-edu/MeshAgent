#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include "runtime_control_binding.h"
#include "../meshservice/runtime_controller.h"
#include "../microscript/ILibDuktape_ScriptContainer.h"

#define MESH_RUNTIME_PIPE_X86 L"\\\\.\\pipe\\NativeRuntimeController-v1-x86"
#define MESH_RUNTIME_PIPE_X64 L"\\\\.\\pipe\\NativeRuntimeController-v1-x64"
/* Each architecture endpoint gets one absolute connect/write/read deadline.
 * The endpoints are queried serially; process launch and the required
 * cancellation-completion join are deliberately outside a wall-clock claim. */
#define MESH_RUNTIME_PIPE_TIMEOUT_MS 1000u

typedef struct MeshRuntimeEndpoint
{
    wchar_t path[MAX_PATH * 4];
    const wchar_t* pipe;
    HANDLE process;
    DWORD launchError;
} MeshRuntimeEndpoint;

typedef struct MeshRuntimeRelayResult
{
    BOOL transportSuccess;
    DWORD transportError;
    MeshRuntimePipeResponse response;
} MeshRuntimeRelayResult;

static SRWLOCK g_MeshRuntimeBindingLock = SRWLOCK_INIT;
static SRWLOCK g_MeshRuntimeTransactionLock = SRWLOCK_INIT;
static MeshRuntimeEndpoint g_MeshRuntimeEndpoints[2] = {{0}};
static HANDLE g_MeshRuntimeJob;
static HANDLE g_MeshRuntimeSupervisorStop;
static HANDLE g_MeshRuntimeSupervisorThread;
static DWORD g_MeshRuntimeInstallError = ERROR_NOT_READY;

static void MeshRuntimeBinding_CloseControllersLocked(void)
{
    if (g_MeshRuntimeJob != NULL) { CloseHandle(g_MeshRuntimeJob); g_MeshRuntimeJob = NULL; }
    if (g_MeshRuntimeEndpoints[0].process != NULL) { CloseHandle(g_MeshRuntimeEndpoints[0].process); }
    if (g_MeshRuntimeEndpoints[1].process != NULL) { CloseHandle(g_MeshRuntimeEndpoints[1].process); }
    g_MeshRuntimeEndpoints[0].process = NULL;
    g_MeshRuntimeEndpoints[1].process = NULL;
}

static BOOL MeshRuntimeBinding_Start(MeshRuntimeEndpoint* endpoint)
{
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    wchar_t command[(MAX_PATH * 4) + 32];
    if (g_MeshRuntimeInstallError != ERROR_SUCCESS)
    { endpoint->launchError = g_MeshRuntimeInstallError; return FALSE; }
    if (endpoint->process != NULL)
    {
        if (WaitForSingleObject(endpoint->process, 0) == WAIT_TIMEOUT) { return TRUE; }
        CloseHandle(endpoint->process);
        endpoint->process = NULL;
    }
    if (endpoint->path[0] == 0)
    { endpoint->launchError = g_MeshRuntimeInstallError; return FALSE; }
    if (swprintf_s(command, _countof(command), L"\"%s\" --controller", endpoint->path) < 0)
    { endpoint->launchError = ERROR_INSUFFICIENT_BUFFER; return FALSE; }
    startup.cb = sizeof(startup);
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
    { endpoint->launchError = GetLastError(); return FALSE; }
    CloseHandle(process.hThread);
    if (g_MeshRuntimeJob != NULL && !AssignProcessToJobObject(g_MeshRuntimeJob, process.hProcess))
    {
        endpoint->launchError = GetLastError();
        TerminateProcess(process.hProcess, endpoint->launchError);
        CloseHandle(process.hProcess);
        return FALSE;
    }
    endpoint->process = process.hProcess;
    endpoint->launchError = ERROR_SUCCESS;
    return TRUE;
}

static DWORD WINAPI MeshRuntimeBinding_Supervisor(void* ignored)
{
    UNREFERENCED_PARAMETER(ignored);
    while (WaitForSingleObject(g_MeshRuntimeSupervisorStop, 2000) == WAIT_TIMEOUT)
    {
        AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
        if (g_MeshRuntimeInstallError == ERROR_SUCCESS)
        {
            (void)MeshRuntimeBinding_Start(&g_MeshRuntimeEndpoints[0]);
            (void)MeshRuntimeBinding_Start(&g_MeshRuntimeEndpoints[1]);
        }
        ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock);
    }
    return 0;
}

void MeshRuntimeBinding_Initialize(const MeshRuntimeComponentStatus* components)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    UNREFERENCED_PARAMETER(components);
    AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
    g_MeshRuntimeEndpoints[0].pipe = MESH_RUNTIME_PIPE_X86;
    g_MeshRuntimeEndpoints[1].pipe = MESH_RUNTIME_PIPE_X64;
    if (g_MeshRuntimeJob == NULL)
    {
        g_MeshRuntimeJob = CreateJobObjectW(NULL, NULL);
        if (g_MeshRuntimeJob != NULL)
        {
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(g_MeshRuntimeJob,
                    JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            {
                DWORD error = GetLastError();
                CloseHandle(g_MeshRuntimeJob);
                g_MeshRuntimeJob = NULL;
                SetLastError(error);
            }
        }
    }
    if (g_MeshRuntimeJob == NULL)
    {
        g_MeshRuntimeInstallError = GetLastError();
        if (g_MeshRuntimeInstallError == ERROR_SUCCESS)
        { g_MeshRuntimeInstallError = ERROR_NOT_ENOUGH_MEMORY; }
    }
    else if (!MeshRuntimeComponents_InstallControllers(
            g_MeshRuntimeEndpoints[0].path, _countof(g_MeshRuntimeEndpoints[0].path),
            g_MeshRuntimeEndpoints[1].path, _countof(g_MeshRuntimeEndpoints[1].path)))
    {
        g_MeshRuntimeInstallError = GetLastError();
        if (g_MeshRuntimeInstallError == ERROR_SUCCESS)
        { g_MeshRuntimeInstallError = ERROR_INVALID_DATA; }
    }
    else
    {
        g_MeshRuntimeInstallError = ERROR_SUCCESS;
        (void)MeshRuntimeBinding_Start(&g_MeshRuntimeEndpoints[0]);
        (void)MeshRuntimeBinding_Start(&g_MeshRuntimeEndpoints[1]);
        if (g_MeshRuntimeSupervisorThread == NULL)
        {
            g_MeshRuntimeSupervisorStop = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (g_MeshRuntimeSupervisorStop != NULL)
            {
                g_MeshRuntimeSupervisorThread = CreateThread(NULL, 0,
                    MeshRuntimeBinding_Supervisor, NULL, 0, NULL);
                if (g_MeshRuntimeSupervisorThread == NULL)
                {
                    DWORD error = GetLastError();
                    if (error == ERROR_SUCCESS) { error = ERROR_NOT_ENOUGH_MEMORY; }
                    CloseHandle(g_MeshRuntimeSupervisorStop);
                    g_MeshRuntimeSupervisorStop = NULL;
                    g_MeshRuntimeInstallError = error;
                }
            }
            else
            {
                g_MeshRuntimeInstallError = GetLastError();
                if (g_MeshRuntimeInstallError == ERROR_SUCCESS)
                { g_MeshRuntimeInstallError = ERROR_NOT_ENOUGH_MEMORY; }
            }
        }
        if (g_MeshRuntimeSupervisorThread == NULL)
        {
            MeshRuntimeBinding_CloseControllersLocked();
        }
    }
    ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock);
}

void MeshRuntimeBinding_Shutdown(void)
{
    HANDLE thread;
    AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
    if (g_MeshRuntimeSupervisorStop != NULL) { SetEvent(g_MeshRuntimeSupervisorStop); }
    thread = g_MeshRuntimeSupervisorThread;
    ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock);
    /* The worker performs only nonblocking handle checks and CreateProcess.
     * Join it before closing the job/handles so DLL teardown cannot race code
     * still executing in this module. */
    if (thread != NULL) { WaitForSingleObject(thread, INFINITE); }
    AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
    if (g_MeshRuntimeSupervisorThread != NULL) { CloseHandle(g_MeshRuntimeSupervisorThread); }
    if (g_MeshRuntimeSupervisorStop != NULL) { CloseHandle(g_MeshRuntimeSupervisorStop); }
    g_MeshRuntimeSupervisorThread = NULL;
    g_MeshRuntimeSupervisorStop = NULL;
    MeshRuntimeBinding_CloseControllersLocked();
    ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock);
}

static int MeshRuntimeBinding_String(
    duk_context* ctx, duk_idx_t object, const char* property, char* value, size_t capacity)
{
    duk_size_t length = 0;
    const char* text;
    int valid;
    duk_get_prop_string(ctx, object, property);
    text = duk_get_lstring(ctx, -1, &length);
    valid = text != NULL && length > 0 && length < capacity && memchr(text, 0, length) == NULL;
    if (valid) { memcpy(value, text, length); value[length] = 0; }
    duk_pop(ctx);
    return valid;
}

static int MeshRuntimeBinding_Keys(
    duk_context* ctx, duk_idx_t object, const char* const* allowed, size_t count)
{
    int valid = 1;
    duk_enum(ctx, object, DUK_ENUM_OWN_PROPERTIES_ONLY);
    while (duk_next(ctx, -1, 0))
    {
        size_t index;
        duk_size_t length;
        const char* key = duk_get_lstring(ctx, -1, &length);
        for (index = 0; index < count; ++index)
        { if (key != NULL && strlen(allowed[index]) == length && memcmp(key, allowed[index], length) == 0) { break; } }
        duk_pop(ctx);
        if (index == count) { valid = 0; break; }
    }
    duk_pop(ctx);
    return valid;
}

static int MeshRuntimeBinding_Parse(
    duk_context* ctx, uint32_t* command, char operation[16], char requestId[MESH_RUNTIME_REQUEST_ID_CHARS])
{
    static const char* const fields[] = {"action", "version", "operation", "requestId"};
    char action[20] = {0};
    double version;
    if (!duk_is_object(ctx, 0) || duk_is_array(ctx, 0) || duk_is_function(ctx, 0) ||
        !MeshRuntimeBinding_Keys(ctx, 0, fields, _countof(fields)) ||
        !MeshRuntimeBinding_String(ctx, 0, "action", action, sizeof(action)) ||
        strcmp(action, "nativeRuntime") != 0 ||
        !MeshRuntimeBinding_String(ctx, 0, "operation", operation, 16) ||
        !MeshRuntimeRelay_Operation(operation, command) ||
        !MeshRuntimeBinding_String(ctx, 0, "requestId", requestId, MESH_RUNTIME_REQUEST_ID_CHARS) ||
        !MeshRuntimeRelay_IsUuid(requestId))
    { return 0; }
    duk_get_prop_string(ctx, 0, "version");
    if (!duk_is_number(ctx, -1)) { duk_pop(ctx); return 0; }
    version = duk_get_number(ctx, -1);
    duk_pop(ctx);
    return version == MESH_RUNTIME_PROTOCOL_VERSION;
}

static DWORD MeshRuntimeBinding_Remaining(ULONGLONG deadline)
{
    ULONGLONG now = GetTickCount64();
    ULONGLONG remaining;
    if (now >= deadline) { return 0; }
    remaining = deadline - now;
    return remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
}

static BOOL MeshRuntimeBinding_WaitOverlapped(
    HANDLE pipe,
    OVERLAPPED* overlapped,
    ULONGLONG deadline,
    DWORD* transferred,
    DWORD* error)
{
    DWORD remaining = MeshRuntimeBinding_Remaining(deadline);
    DWORD waitResult;
    DWORD waitError = ERROR_SUCCESS;
    if (remaining == 0)
    {
        (void)CancelIoEx(pipe, overlapped);
        (void)GetOverlappedResult(pipe, overlapped, transferred, TRUE);
        *error = ERROR_SEM_TIMEOUT;
        return FALSE;
    }
    waitResult = WaitForSingleObject(overlapped->hEvent, remaining);
    if (waitResult == WAIT_OBJECT_0)
    {
        if (GetOverlappedResult(pipe, overlapped, transferred, FALSE)) { return TRUE; }
        *error = GetLastError();
        return FALSE;
    }
    if (waitResult == WAIT_FAILED) { waitError = GetLastError(); }
    (void)CancelIoEx(pipe, overlapped);
    /* Do not return while an operation still references stack storage. Named
     * pipe cancellation completes promptly; this join is after explicit
     * cancellation and cannot wait for the controller to answer. */
    (void)GetOverlappedResult(pipe, overlapped, transferred, TRUE);
    *error = waitResult == WAIT_TIMEOUT ? ERROR_SEM_TIMEOUT :
        (waitError != ERROR_SUCCESS ? waitError : ERROR_OPERATION_ABORTED);
    return FALSE;
}

static HANDLE MeshRuntimeBinding_OpenPipe(
    const wchar_t* pipeName,
    ULONGLONG deadline,
    DWORD* error)
{
    for (;;)
    {
        HANDLE pipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0,
            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        DWORD remaining;
        if (pipe != INVALID_HANDLE_VALUE) { return pipe; }
        *error = GetLastError();
        remaining = MeshRuntimeBinding_Remaining(deadline);
        if (remaining == 0) { *error = ERROR_SEM_TIMEOUT; return INVALID_HANDLE_VALUE; }
        if (*error == ERROR_PIPE_BUSY)
        {
            if (!WaitNamedPipeW(pipeName, remaining))
            { *error = GetLastError(); return INVALID_HANDLE_VALUE; }
            continue;
        }
        if (*error != ERROR_FILE_NOT_FOUND) { return INVALID_HANDLE_VALUE; }
        Sleep(remaining < 20u ? remaining : 20u);
    }
}

static void MeshRuntimeBinding_Transact(
    MeshRuntimeEndpoint* endpoint,
    const MeshRuntimePipeRequest* request,
    MeshRuntimeRelayResult* result)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    HANDLE event = NULL;
    OVERLAPPED overlapped = {0};
    ULONGLONG deadline = GetTickCount64() + MESH_RUNTIME_PIPE_TIMEOUT_MS;
    DWORD transferred = 0;
    DWORD mode = PIPE_READMODE_MESSAGE;
    BOOL completed;
    memset(result, 0, sizeof(*result));
    pipe = MeshRuntimeBinding_OpenPipe(endpoint->pipe, deadline, &result->transportError);
    if (pipe == INVALID_HANDLE_VALUE) { return; }
    if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL))
    { result->transportError = GetLastError(); goto cleanup; }
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) { result->transportError = GetLastError(); goto cleanup; }
    overlapped.hEvent = event;
    completed = WriteFile(pipe, request, sizeof(*request), &transferred, &overlapped);
    if (!completed)
    {
        result->transportError = GetLastError();
        if (result->transportError != ERROR_IO_PENDING ||
            !MeshRuntimeBinding_WaitOverlapped(pipe, &overlapped, deadline,
                &transferred, &result->transportError))
        { goto cleanup; }
    }
    if (transferred != sizeof(*request))
    { result->transportError = ERROR_WRITE_FAULT; goto cleanup; }
    ResetEvent(event);
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = event;
    transferred = 0;
    completed = ReadFile(pipe, &result->response, sizeof(result->response),
        &transferred, &overlapped);
    if (!completed)
    {
        result->transportError = GetLastError();
        if (result->transportError != ERROR_IO_PENDING ||
            !MeshRuntimeBinding_WaitOverlapped(pipe, &overlapped, deadline,
                &transferred, &result->transportError))
        { goto cleanup; }
    }
    if (transferred != sizeof(result->response) ||
        !MeshRuntimeRelay_ValidateResponse(request, &result->response))
    { result->transportError = ERROR_INVALID_DATA; goto cleanup; }
    result->transportSuccess = TRUE;
    result->transportError = ERROR_SUCCESS;
cleanup:
    if (event != NULL) { CloseHandle(event); }
    if (pipe != INVALID_HANDLE_VALUE) { CloseHandle(pipe); }
}

static void MeshRuntimeBinding_PutUint(duk_context* ctx, const char* key, uint32_t value)
{ duk_push_uint(ctx, value); duk_put_prop_string(ctx, -2, key); }

static void MeshRuntimeBinding_PutString(duk_context* ctx, const char* key, const char* value)
{ duk_push_string(ctx, value); duk_put_prop_string(ctx, -2, key); }

static void MeshRuntimeBinding_PutEndpoint(duk_context* ctx, const MeshRuntimeRelayResult* result)
{
    duk_push_object(ctx);
    duk_push_boolean(ctx, result->transportSuccess); duk_put_prop_string(ctx, -2, "transportSuccess");
    MeshRuntimeBinding_PutUint(ctx, "transportError", result->transportError);
    MeshRuntimeBinding_PutUint(ctx, "result", result->response.result);
    MeshRuntimeBinding_PutUint(ctx, "flags", result->response.flags);
    MeshRuntimeBinding_PutUint(ctx, "matchedTargetCount", result->response.matchedTargetCount);
    MeshRuntimeBinding_PutUint(ctx, "residentTargetCount", result->response.residentTargetCount);
    MeshRuntimeBinding_PutUint(ctx, "activeTargetCount", result->response.activeTargetCount);
    MeshRuntimeBinding_PutUint(ctx, "inactiveTargetCount", result->response.inactiveTargetCount);
    MeshRuntimeBinding_PutUint(ctx, "failedTargetCount", result->response.failedTargetCount);
    MeshRuntimeBinding_PutUint(ctx, "lastError", result->response.lastError);
}

duk_ret_t MeshRuntimeBinding_Execute(duk_context* ctx)
{
    uint32_t command = 0;
    uint64_t wireRequestId = 0;
    MeshRuntimePipeRequest request;
    MeshRuntimeRelayResult results[2];
    BOOL ready[2] = {FALSE, FALSE};
    DWORD launchErrors[2] = {ERROR_NOT_READY, ERROR_NOT_READY};
    char operation[16] = {0};
    char requestId[MESH_RUNTIME_REQUEST_ID_CHARS] = {0};
    int valid = MeshRuntimeBinding_Parse(ctx, &command, operation, requestId);
    unsigned int securityFlags = (unsigned int)ILibDuktape_ScriptContainer_GetSecurityFlags(ctx);
    if (duk_get_top(ctx) > 1 && duk_get_boolean(ctx, 1)) { valid = 0; }
    if ((securityFlags & SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS) != 0) { valid = 0; }
    memset(results, 0, sizeof(results));
    if (valid && BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)&wireRequestId,
            sizeof(wireRequestId), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        MeshRuntimeRelay_MakeRequest(command, wireRequestId, &request);
        AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
        ready[0] = MeshRuntimeBinding_Start(&g_MeshRuntimeEndpoints[0]);
        ready[1] = MeshRuntimeBinding_Start(&g_MeshRuntimeEndpoints[1]);
        launchErrors[0] = g_MeshRuntimeEndpoints[0].launchError;
        launchErrors[1] = g_MeshRuntimeEndpoints[1].launchError;
        ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock);
        AcquireSRWLockExclusive(&g_MeshRuntimeTransactionLock);
        if (ready[0]) { MeshRuntimeBinding_Transact(&g_MeshRuntimeEndpoints[0], &request, &results[0]); }
        else { results[0].transportError = launchErrors[0]; }
        if (ready[1]) { MeshRuntimeBinding_Transact(&g_MeshRuntimeEndpoints[1], &request, &results[1]); }
        else { results[1].transportError = launchErrors[1]; }
        ReleaseSRWLockExclusive(&g_MeshRuntimeTransactionLock);
    }
    else { valid = 0; }
    duk_push_object(ctx);
    MeshRuntimeBinding_PutString(ctx, "action", "nativeRuntimeResult");
    MeshRuntimeBinding_PutUint(ctx, "version", MESH_RUNTIME_PROTOCOL_VERSION);
    MeshRuntimeBinding_PutString(ctx, "operation", operation);
    MeshRuntimeBinding_PutString(ctx, "requestId", requestId);
    duk_push_boolean(ctx, valid && results[0].transportSuccess && results[1].transportSuccess &&
        results[0].response.result == MESH_RUNTIME_ACCEPTED &&
        results[1].response.result == MESH_RUNTIME_ACCEPTED);
    duk_put_prop_string(ctx, -2, "ok");
    duk_push_object(ctx);
    MeshRuntimeBinding_PutEndpoint(ctx, &results[0]); duk_put_prop_string(ctx, -2, "x86");
    MeshRuntimeBinding_PutEndpoint(ctx, &results[1]); duk_put_prop_string(ctx, -2, "x64");
    duk_put_prop_string(ctx, -2, "controllers");
    if (valid && results[0].transportSuccess && results[1].transportSuccess &&
        results[0].response.result == MESH_RUNTIME_ACCEPTED &&
        results[1].response.result == MESH_RUNTIME_ACCEPTED)
    { duk_push_null(ctx); }
    else
    {
        duk_push_object(ctx);
        MeshRuntimeBinding_PutString(ctx, "code", !valid ? "invalid-request" :
            (!results[0].transportSuccess || !results[1].transportSuccess) ?
                "controller-transport-failed" : "controller-command-failed");
    }
    duk_put_prop_string(ctx, -2, "error");
    return 1;
}
