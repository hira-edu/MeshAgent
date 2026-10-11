#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "runtime_control_binding.h"
#include "../meshservice/runtime_controller.h"
#include "../microscript/ILibDuktape_ScriptContainer.h"

#ifndef _countof
#define _countof(array) (sizeof(array) / sizeof((array)[0]))
#endif

typedef struct MeshRuntimeEndpoint
{
    wchar_t path[MAX_PATH * 4];
    HANDLE process;
    DWORD launchError;
} MeshRuntimeEndpoint;

typedef struct MeshRuntimeEndpointResult
{
    BOOL transportSuccess;
    DWORD transportError;
    BOOL active;
} MeshRuntimeEndpointResult;

static SRWLOCK g_MeshRuntimeBindingLock = SRWLOCK_INIT;
static MeshRuntimeEndpoint g_MeshRuntimeEndpoints[2] = {{0}};
static HANDLE g_MeshRuntimeJob = NULL;
static DWORD g_MeshRuntimeInstallError = ERROR_NOT_READY;

static HANDLE MeshRuntimeBinding_CreateJob(void)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job != NULL)
    {
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        {
            DWORD error = GetLastError();
            CloseHandle(job);
            job = NULL;
            SetLastError(error);
        }
    }
    return job;
}

void MeshRuntimeBinding_Initialize(const MeshRuntimeComponentStatus* components)
{
    UNREFERENCED_PARAMETER(components);
    AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
    if (g_MeshRuntimeJob == NULL)
    {
        g_MeshRuntimeJob = MeshRuntimeBinding_CreateJob();
        if (g_MeshRuntimeJob == NULL)
        {
            g_MeshRuntimeInstallError = GetLastError();
            if (g_MeshRuntimeInstallError == ERROR_SUCCESS)
            { g_MeshRuntimeInstallError = ERROR_NOT_ENOUGH_MEMORY; }
        }
    }
    if (g_MeshRuntimeJob != NULL)
    {
        if (!MeshRuntimeComponents_InstallControllers(
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
        }
    }
    ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock);
}

void MeshRuntimeBinding_Shutdown(void)
{
    AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
    if (g_MeshRuntimeJob != NULL)
    {
        TerminateJobObject(g_MeshRuntimeJob, 0);
        CloseHandle(g_MeshRuntimeJob);
        g_MeshRuntimeJob = NULL;
    }
    if (g_MeshRuntimeEndpoints[0].process != NULL)
    {
        TerminateProcess(g_MeshRuntimeEndpoints[0].process, 0);
        CloseHandle(g_MeshRuntimeEndpoints[0].process);
        g_MeshRuntimeEndpoints[0].process = NULL;
    }
    if (g_MeshRuntimeEndpoints[1].process != NULL)
    {
        TerminateProcess(g_MeshRuntimeEndpoints[1].process, 0);
        CloseHandle(g_MeshRuntimeEndpoints[1].process);
        g_MeshRuntimeEndpoints[1].process = NULL;
    }
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

static void MeshRuntimeBinding_PutUint(duk_context* ctx, const char* key, uint32_t value)
{ duk_push_uint(ctx, value); duk_put_prop_string(ctx, -2, key); }

static void MeshRuntimeBinding_PutString(duk_context* ctx, const char* key, const char* value)
{ duk_push_string(ctx, value); duk_put_prop_string(ctx, -2, key); }

static void MeshRuntimeBinding_PutEndpoint(duk_context* ctx, const MeshRuntimeEndpointResult* result)
{
    duk_push_object(ctx);
    duk_push_boolean(ctx, result->transportSuccess);
    duk_put_prop_string(ctx, -2, "transportSuccess");
    MeshRuntimeBinding_PutUint(ctx, "transportError", result->transportError);
    MeshRuntimeBinding_PutUint(ctx, "result", 0);
    MeshRuntimeBinding_PutUint(ctx, "flags", result->active ? 1u : 0u);
    MeshRuntimeBinding_PutUint(ctx, "matchedTargetCount", 0);
    MeshRuntimeBinding_PutUint(ctx, "residentTargetCount", 0);
    MeshRuntimeBinding_PutUint(ctx, "activeTargetCount", result->active ? 1u : 0u);
    MeshRuntimeBinding_PutUint(ctx, "inactiveTargetCount", result->active ? 0u : 1u);
    MeshRuntimeBinding_PutUint(ctx, "failedTargetCount", 0);
    MeshRuntimeBinding_PutUint(ctx, "lastError", result->transportError);
}

duk_ret_t MeshRuntimeBinding_Execute(duk_context* ctx)
{
    uint32_t command = 0;
    MeshRuntimeEndpointResult results[2] = {{0}};
    char operation[16] = {0};
    char requestId[MESH_RUNTIME_REQUEST_ID_CHARS] = {0};
    int valid = MeshRuntimeBinding_Parse(ctx, &command, operation, requestId);
    unsigned int securityFlags = (unsigned int)ILibDuktape_ScriptContainer_GetSecurityFlags(ctx);
    if (duk_get_top(ctx) > 1 && duk_get_boolean(ctx, 1)) { valid = 0; }
    if ((securityFlags & SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS) != 0) { valid = 0; }

    if (valid)
    {
        AcquireSRWLockExclusive(&g_MeshRuntimeBindingLock);
        if (command == MESH_RUNTIME_LOAD)
        {
            DWORD jobError = ERROR_SUCCESS;
            if (g_MeshRuntimeJob == NULL)
            {
                g_MeshRuntimeJob = MeshRuntimeBinding_CreateJob();
                if (g_MeshRuntimeJob == NULL)
                {
                    jobError = GetLastError();
                    if (jobError == ERROR_SUCCESS) { jobError = ERROR_NOT_ENOUGH_MEMORY; }
                }
            }
            for (size_t i = 0; i < 2; ++i)
            {
                MeshRuntimeEndpoint* endpoint = &g_MeshRuntimeEndpoints[i];
                STARTUPINFOW startup = {0};
                PROCESS_INFORMATION process = {0};
                wchar_t commandLine[(MAX_PATH * 4) + 32];

                /* Check if process is already running */
                if (endpoint->process != NULL)
                {
                    if (WaitForSingleObject(endpoint->process, 0) == WAIT_TIMEOUT)
                    {
                        results[i].transportSuccess = TRUE;
                        results[i].transportError = ERROR_SUCCESS;
                        results[i].active = TRUE;
                        continue;
                    }
                    CloseHandle(endpoint->process);
                    endpoint->process = NULL;
                }

                /* Binaries are installed and validated only at startup; command
                 * processing never re-hashes or rewrites images on the event loop. */
                if (g_MeshRuntimeInstallError != ERROR_SUCCESS || endpoint->path[0] == 0)
                {
                    endpoint->launchError = g_MeshRuntimeInstallError != ERROR_SUCCESS ?
                        g_MeshRuntimeInstallError : ERROR_FILE_NOT_FOUND;
                    results[i].transportSuccess = FALSE;
                    results[i].transportError = endpoint->launchError;
                    results[i].active = FALSE;
                    continue;
                }

                /* Never launch outside the kill-on-close job. */
                if (g_MeshRuntimeJob == NULL)
                {
                    endpoint->launchError = jobError;
                    results[i].transportSuccess = FALSE;
                    results[i].transportError = endpoint->launchError;
                    results[i].active = FALSE;
                    continue;
                }

                if (swprintf_s(commandLine, _countof(commandLine), L"\"%s\"", endpoint->path) < 0)
                {
                    endpoint->launchError = ERROR_INSUFFICIENT_BUFFER;
                    results[i].transportSuccess = FALSE;
                    results[i].transportError = endpoint->launchError;
                    results[i].active = FALSE;
                    continue;
                }

                startup.cb = sizeof(startup);
                if (!CreateProcessW(NULL, commandLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &startup, &process))
                {
                    endpoint->launchError = GetLastError();
                    results[i].transportSuccess = FALSE;
                    results[i].transportError = endpoint->launchError;
                    results[i].active = FALSE;
                    continue;
                }

                if (g_MeshRuntimeJob != NULL && !AssignProcessToJobObject(g_MeshRuntimeJob, process.hProcess))
                {
                    endpoint->launchError = GetLastError();
                    TerminateProcess(process.hProcess, endpoint->launchError);
                    CloseHandle(process.hThread);
                    CloseHandle(process.hProcess);
                    results[i].transportSuccess = FALSE;
                    results[i].transportError = endpoint->launchError;
                    results[i].active = FALSE;
                    continue;
                }
                ResumeThread(process.hThread);
                CloseHandle(process.hThread);

                endpoint->process = process.hProcess;
                endpoint->launchError = ERROR_SUCCESS;
                results[i].transportSuccess = TRUE;
                results[i].transportError = ERROR_SUCCESS;
                results[i].active = TRUE;
            }
        }
        else if (command == MESH_RUNTIME_UNLOAD)
        {
            if (g_MeshRuntimeJob != NULL)
            {
                TerminateJobObject(g_MeshRuntimeJob, 0);
                CloseHandle(g_MeshRuntimeJob);
                g_MeshRuntimeJob = NULL;
            }
            for (size_t i = 0; i < 2; ++i)
            {
                MeshRuntimeEndpoint* endpoint = &g_MeshRuntimeEndpoints[i];
                if (endpoint->process != NULL)
                {
                    TerminateProcess(endpoint->process, 0);
                    CloseHandle(endpoint->process);
                    endpoint->process = NULL;
                }
                endpoint->launchError = ERROR_SUCCESS;
                results[i].transportSuccess = TRUE;
                results[i].transportError = ERROR_SUCCESS;
                results[i].active = FALSE;
            }
            g_MeshRuntimeJob = MeshRuntimeBinding_CreateJob();
        }
        else if (command == MESH_RUNTIME_STATUS)
        {
            for (size_t i = 0; i < 2; ++i)
            {
                MeshRuntimeEndpoint* endpoint = &g_MeshRuntimeEndpoints[i];
                BOOL active = FALSE;
                if (endpoint->process != NULL)
                {
                    if (WaitForSingleObject(endpoint->process, 0) == WAIT_TIMEOUT)
                    {
                        active = TRUE;
                    }
                    else
                    {
                        /* Only UNLOAD stops a controller; any other exit is a crash,
                         * which must stay distinguishable from never-started. */
                        CloseHandle(endpoint->process);
                        endpoint->process = NULL;
                        endpoint->launchError = ERROR_PROCESS_ABORTED;
                        active = FALSE;
                    }
                }
                results[i].transportSuccess = TRUE;
                results[i].transportError = endpoint->launchError;
                results[i].active = active;
            }
        }
        ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock);
    }

    int ok = valid && results[0].transportSuccess && results[1].transportSuccess;

    duk_push_object(ctx);
    MeshRuntimeBinding_PutString(ctx, "action", "nativeRuntimeResult");
    MeshRuntimeBinding_PutUint(ctx, "version", MESH_RUNTIME_PROTOCOL_VERSION);
    MeshRuntimeBinding_PutString(ctx, "operation", operation);
    MeshRuntimeBinding_PutString(ctx, "requestId", requestId);
    duk_push_boolean(ctx, ok);
    duk_put_prop_string(ctx, -2, "ok");

    duk_push_object(ctx);
    MeshRuntimeBinding_PutEndpoint(ctx, &results[0]); duk_put_prop_string(ctx, -2, "x86");
    MeshRuntimeBinding_PutEndpoint(ctx, &results[1]); duk_put_prop_string(ctx, -2, "x64");
    duk_put_prop_string(ctx, -2, "controllers");

    if (ok)
    {
        duk_push_null(ctx);
    }
    else
    {
        duk_push_object(ctx);
        MeshRuntimeBinding_PutString(ctx, "code", !valid ? "invalid-request" : "controller-transport-failed");
    }
    duk_put_prop_string(ctx, -2, "error");

    return 1;
}
