#ifndef MESH_SERVICE_TELEMETRY_H
#define MESH_SERVICE_TELEMETRY_H

#include "../meshcore/diagnostic_log.h"

enum MeshServiceTelemetryPhase
{
    MESH_TELEMETRY_STARTING = 1,
    MESH_TELEMETRY_RUNNING,
    MESH_TELEMETRY_STOP_REQUESTED,
    MESH_TELEMETRY_CLEAN_EXIT,
    MESH_TELEMETRY_CRASH,
    MESH_TELEMETRY_START_FAILURE,
    MESH_TELEMETRY_UNEXPECTED_RETURN
};

typedef struct MeshServiceTelemetrySession
{
    DWORD version, pid, phase, error;
    FILETIME processCreated, started;
} MeshServiceTelemetrySession;

typedef struct MeshServiceTelemetry
{
    HKEY key;
    SRWLOCK lock;
    MeshServiceTelemetrySession session;
} MeshServiceTelemetry;

static __inline const char* MeshServiceTelemetry_ExceptionName(DWORD code)
{
    switch (code)
    {
        case EXCEPTION_ACCESS_VIOLATION: return "access_violation";
        case EXCEPTION_STACK_OVERFLOW: return "stack_overflow";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal_instruction";
        case EXCEPTION_IN_PAGE_ERROR: return "in_page_error";
        case 0xC0000374u: return "heap_corruption_reported";
        case 0xC0000409u: return "fail_fast_or_security_check";
        default: return "unhandled_exception";
    }
}

static __inline void MeshServiceTelemetry_Update(MeshServiceTelemetry* telemetry, DWORD phase, DWORD code)
{
    DWORD savedError = GetLastError();
    LSTATUS status;
    if (!TryAcquireSRWLockExclusive(&telemetry->lock))
    {
        MeshDiagnosticLog_Write("service-host", "[TELEMETRY_FAILURE] session marker busy; update skipped");
        SetLastError(savedError);
        return;
    }
    if (!telemetry->key) { ReleaseSRWLockExclusive(&telemetry->lock); SetLastError(savedError); return; }
    telemetry->session.phase = phase;
    telemetry->session.error = code;
    status = RegSetValueExW(telemetry->key, L"TelemetrySession", 0, REG_BINARY,
        (const BYTE*)&telemetry->session, sizeof(telemetry->session));
    ReleaseSRWLockExclusive(&telemetry->lock);
    if (status != ERROR_SUCCESS)
    { MeshDiagnosticLog_PrintfW("service-host", L"[TELEMETRY_FAILURE] session_marker phase=%lu error=%ld", phase, status); }
    SetLastError(savedError);
}

static __inline void MeshServiceTelemetry_Begin(MeshServiceTelemetry* telemetry, HKEY root, const wchar_t* keyPath)
{
    MeshServiceTelemetrySession previous = {0};
    DWORD type = 0, length = sizeof(previous), savedError = GetLastError();
    FILETIME exitTime, kernelTime, userTime;
    LSTATUS status;
    InitializeSRWLock(&telemetry->lock);
    status = RegCreateKeyExW(root, keyPath, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &telemetry->key, NULL);
    if (status != ERROR_SUCCESS)
    {
        telemetry->key = NULL;
        MeshDiagnosticLog_PrintfW("service-host", L"[TELEMETRY_FAILURE] open_session_marker error=%ld", status);
        SetLastError(savedError);
        return;
    }
    status = RegQueryValueExW(telemetry->key, L"TelemetrySession", NULL, &type, (BYTE*)&previous, &length);
    if (status == ERROR_SUCCESS && type == REG_BINARY && length == sizeof(previous) && previous.version == 1 &&
        (previous.phase == MESH_TELEMETRY_STARTING || previous.phase == MESH_TELEMETRY_RUNNING ||
         previous.phase == MESH_TELEMETRY_STOP_REQUESTED || previous.phase == MESH_TELEMETRY_CRASH))
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, previous.pid);
        FILETIME created;
        DWORD queryError = process ? ERROR_SUCCESS : GetLastError();
        BOOL sameLiveProcess = FALSE;
        if (process)
        {
            if (!GetProcessTimes(process, &created, &exitTime, &kernelTime, &userTime)) { queryError = GetLastError(); }
            else if (CompareFileTime(&created, &previous.processCreated) == 0)
            {
                DWORD waitResult = WaitForSingleObject(process, 0);
                sameLiveProcess = waitResult == WAIT_TIMEOUT;
                if (waitResult == WAIT_FAILED) { queryError = GetLastError(); }
            }
        }
        if (process) { CloseHandle(process); }
        // An absent clean-exit marker is evidence of interruption, not evidence of who killed the process.
        MeshDiagnosticLog_PrintfW("service-host",
            L"[PREVIOUS_SESSION] pid=%lu phase=%lu exception=0x%08lX classification=%hs processQueryError=%lu startedFileTime=%08lX%08lX cause=%hs",
            previous.pid, previous.phase, previous.phase == MESH_TELEMETRY_CRASH ? previous.error : 0,
            sameLiveProcess ? "overlapping_session" : previous.phase == MESH_TELEMETRY_CRASH ? "recorded_crash" :
                queryError != ERROR_SUCCESS && queryError != ERROR_INVALID_PARAMETER ? "session_status_unknown" : "unclean_exit",
            queryError, previous.started.dwHighDateTime, previous.started.dwLowDateTime,
            previous.phase == MESH_TELEMETRY_CRASH ? MeshServiceTelemetry_ExceptionName(previous.error) : "unknown_crash_external_termination_power_loss_or_interrupted_shutdown");
    }
    else if (status != ERROR_FILE_NOT_FOUND && (status != ERROR_SUCCESS || type != REG_BINARY || length != sizeof(previous) || previous.version != 1))
    { MeshDiagnosticLog_PrintfW("service-host", L"[TELEMETRY_FAILURE] invalid_session_marker error=%ld size=%lu type=%lu", status, length, type); }
    ZeroMemory(&telemetry->session, sizeof(telemetry->session));
    telemetry->session.version = 1;
    telemetry->session.pid = GetCurrentProcessId();
    GetProcessTimes(GetCurrentProcess(), &telemetry->session.processCreated, &exitTime, &kernelTime, &userTime);
    GetSystemTimeAsFileTime(&telemetry->session.started);
    MeshServiceTelemetry_Update(telemetry, MESH_TELEMETRY_STARTING, 0);
    status = RegFlushKey(telemetry->key);
    if (status != ERROR_SUCCESS) { MeshDiagnosticLog_PrintfW("service-host", L"[TELEMETRY_FAILURE] flush_session_marker error=%ld", status); }
    MeshDiagnosticLog_Write("service-host", "[SERVICE_START] phase=starting");
    SetLastError(savedError);
}

static __declspec(noinline) LONG MeshServiceTelemetry_RecordException(MeshServiceTelemetry* telemetry, EXCEPTION_POINTERS* exception)
{
    if (exception && exception->ExceptionRecord)
    {
        EXCEPTION_RECORD* record = exception->ExceptionRecord;
        HMODULE module = NULL;
        wchar_t path[MAX_PATH * 4] = L"(unresolved)";
        ULONG_PTR operation = 0, target = 0;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)record->ExceptionAddress, &module)) { GetModuleFileNameW(module, path, _countof(path)); }
        if ((record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || record->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) && record->NumberParameters >= 2)
        { operation = record->ExceptionInformation[0]; target = record->ExceptionInformation[1]; }
        MeshDiagnosticLog_PrintfW("service-host",
            L"[AGENT_CRASH] exception=0x%08lX classification=%hs address=%p module=%ls moduleOffset=0x%llX operation=%llu target=0x%llX parameters=%lu",
            record->ExceptionCode, MeshServiceTelemetry_ExceptionName(record->ExceptionCode), record->ExceptionAddress,
            path, module ? (unsigned long long)((ULONG_PTR)record->ExceptionAddress - (ULONG_PTR)module) : 0,
            (unsigned long long)operation, (unsigned long long)target, record->NumberParameters);
        MeshServiceTelemetry_Update(telemetry, MESH_TELEMETRY_CRASH, record->ExceptionCode);
    }
    // Never resume a corrupted process or turn its crash into a successful service stop.
    return EXCEPTION_CONTINUE_SEARCH;
}

static __inline void MeshServiceTelemetry_End(MeshServiceTelemetry* telemetry, DWORD phase, DWORD code)
{
    DWORD savedError = GetLastError();
    LSTATUS status = ERROR_SUCCESS;
    AcquireSRWLockExclusive(&telemetry->lock);
    if (telemetry->key)
    {
        telemetry->session.phase = phase;
        telemetry->session.error = code;
        status = RegSetValueExW(telemetry->key, L"TelemetrySession", 0, REG_BINARY,
            (const BYTE*)&telemetry->session, sizeof(telemetry->session));
        RegCloseKey(telemetry->key);
        telemetry->key = NULL;
    }
    ReleaseSRWLockExclusive(&telemetry->lock);
    if (status != ERROR_SUCCESS)
    { MeshDiagnosticLog_PrintfW("service-host", L"[TELEMETRY_FAILURE] final_session_marker phase=%lu error=%ld", phase, status); }
    SetLastError(savedError);
}
#endif
