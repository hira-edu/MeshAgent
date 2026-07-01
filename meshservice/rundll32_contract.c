#include "rundll32_contract.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <strsafe.h>
#include <WtsApi32.h>
#include "stealth.h"
#include "svchost_payload.h"

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260L
#endif

#define MESH_CONSOLE_BRIDGE_PIPE_PREFIX_W L"\\\\.\\pipe\\MeshConsoleBridge_"
#define MESH_CONSOLE_BRIDGE_CONNECT_TIMEOUT_MS 15000UL
#define MESH_CONSOLE_BRIDGE_IO_BUFFER_SIZE 8192
#define MESH_CONSOLE_BRIDGE_NO_SESSION 0xFFFFFFFFUL
#define MESH_CONSOLE_BRIDGE_SHELL_SPAWN_ATTEMPTS 3UL
#define MESH_CONSOLE_BRIDGE_SHELL_SPAWN_RETRY_DELAY_MS 500UL

typedef HRESULT (WINAPI* MeshConsoleBridge_CreatePseudoConsoleFn)(COORD, HANDLE, HANDLE, DWORD, HANDLE*);
typedef void (WINAPI* MeshConsoleBridge_ClosePseudoConsoleFn)(HANDLE);
typedef BOOL (WINAPI* MeshConsoleBridge_CreateEnvironmentBlockFn)(LPVOID*, HANDLE, BOOL);
typedef BOOL (WINAPI* MeshConsoleBridge_DestroyEnvironmentBlockFn)(LPVOID);

typedef struct MeshConsoleBridgeConptyApi
{
    MeshConsoleBridge_CreatePseudoConsoleFn CreatePseudoConsoleFn;
    MeshConsoleBridge_ClosePseudoConsoleFn ClosePseudoConsoleFn;
} MeshConsoleBridgeConptyApi;

typedef struct MeshConsoleBridgeCopyContext
{
    HANDLE readHandle;
    HANDLE writeHandle;
    HANDLE* closeWriteHandleRef;
    volatile LONG* stopFlag;
    BOOL signalStopOnExit;
    DWORD errorCode;
} MeshConsoleBridgeCopyContext;

BOOL MeshAgent_RunPreProtectionCaptureValidationW(const wchar_t* outputPath);
int MeshService_RunSelfTestHostW(const wchar_t* arguments);
int MeshService_RunKvmProbeHostW(const wchar_t* arguments);

#define MESH_LIFECYCLE_SECTION_W L"Lifecycle"
#define MESH_LIFECYCLE_KEY_ACTION_W L"Action"
#define MESH_LIFECYCLE_KEY_SOURCE_EXE_W L"SourceExe"
#define MESH_LIFECYCLE_KEY_SOURCE_DLL_W L"SourceDll"
#define MESH_LIFECYCLE_KEY_DISPLAY_NAME_W L"DisplayName"
#define MESH_LIFECYCLE_KEY_DESCRIPTION_W L"Description"
#define MESH_LIFECYCLE_KEY_REQUIRE_CONFIG_W L"RequireConfig"

#define MESH_UMH_SECTION_W L"UMH"
#define MESH_UMH_KEY_EXE_PATH_W L"ExePath"
#define MESH_UMH_KEY_ARG_COUNT_W L"ArgCount"
#define MESH_UMH_KEY_TIMEOUT_MS_W L"TimeoutMs"
#define MESH_UMH_MAX_ARGS 8
#define MESH_UMH_MAX_ARG_CCH 128
#define MESH_UMH_DEFAULT_TIMEOUT_MS 120000UL
#define MESH_UMH_MAX_TIMEOUT_MS 600000UL

typedef struct MeshUmhHostManifest
{
    wchar_t manifestPath[MAX_PATH * 4];
    wchar_t exePath[MAX_PATH * 4];
    wchar_t args[MESH_UMH_MAX_ARGS][MESH_UMH_MAX_ARG_CCH];
    DWORD argCount;
    DWORD timeoutMs;
} MeshUmhHostManifest;

static BOOL MeshRundll32_FileExistsW(const wchar_t* path)
{
    DWORD attrs = INVALID_FILE_ATTRIBUTES;
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) ? TRUE : FALSE;
}

static BOOL MeshRundll32_DirectoryExistsW(const wchar_t* path)
{
    DWORD attrs = INVALID_FILE_ATTRIBUTES;
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) ? TRUE : FALSE;
}

static BOOL MeshRundll32_CopyFirstTokenW(const wchar_t* input, wchar_t* output, size_t outputCch)
{
    const wchar_t* cursor = NULL;
    const wchar_t* tokenStart = NULL;
    size_t tokenLen = 0;

    if (output == NULL || outputCch == 0) { return FALSE; }
    output[0] = L'\0';
    if (input == NULL) { return FALSE; }

    cursor = input;
    while (*cursor == L' ' || *cursor == L'\t') { ++cursor; }
    if (*cursor == L'\0') { return FALSE; }

    if (*cursor == L'"')
    {
        ++cursor;
        tokenStart = cursor;
        while (*cursor != L'\0' && *cursor != L'"') { ++cursor; }
        tokenLen = (size_t)(cursor - tokenStart);
    }
    else
    {
        tokenStart = cursor;
        while (*cursor != L'\0' && *cursor != L' ' && *cursor != L'\t') { ++cursor; }
        tokenLen = (size_t)(cursor - tokenStart);
    }

    if (tokenLen == 0 || tokenLen >= outputCch)
    {
        SetLastError(tokenLen == 0 ? ERROR_INVALID_PARAMETER : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (FAILED(StringCchCopyNW(output, outputCch, tokenStart, tokenLen)))
    {
        output[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    output[tokenLen] = L'\0';
    return TRUE;
}

static BOOL MeshRundll32_CopyNextTokenW(const wchar_t** cursorRef, wchar_t* output, size_t outputCch)
{
    const wchar_t* cursor = NULL;
    const wchar_t* tokenStart = NULL;
    size_t tokenLen = 0;

    if (cursorRef == NULL || output == NULL || outputCch == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    output[0] = L'\0';
    cursor = *cursorRef;
    if (cursor == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    while (*cursor == L' ' || *cursor == L'\t') { ++cursor; }
    if (*cursor == L'\0')
    {
        *cursorRef = cursor;
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }

    if (*cursor == L'"')
    {
        ++cursor;
        tokenStart = cursor;
        while (*cursor != L'\0' && *cursor != L'"') { ++cursor; }
        tokenLen = (size_t)(cursor - tokenStart);
        if (*cursor == L'"') { ++cursor; }
    }
    else
    {
        tokenStart = cursor;
        while (*cursor != L'\0' && *cursor != L' ' && *cursor != L'\t') { ++cursor; }
        tokenLen = (size_t)(cursor - tokenStart);
    }

    while (*cursor == L' ' || *cursor == L'\t') { ++cursor; }
    *cursorRef = cursor;
    if (tokenLen == 0 || tokenLen >= outputCch)
    {
        SetLastError(tokenLen == 0 ? ERROR_INVALID_PARAMETER : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (FAILED(StringCchCopyNW(output, outputCch, tokenStart, tokenLen)))
    {
        output[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    output[tokenLen] = L'\0';
    return TRUE;
}

static BOOL MeshRundll32_GetEntryTailW(const wchar_t* entryName, const wchar_t* lpCmdLine, wchar_t* tail, size_t tailCch)
{
    LPWSTR fullCmdLine = NULL;
    LPWSTR entryPoint = NULL;

    if (tail == NULL || tailCch == 0 || entryName == NULL || entryName[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    tail[0] = L'\0';

    fullCmdLine = GetCommandLineW();
    if (fullCmdLine != NULL)
    {
        entryPoint = wcsstr(fullCmdLine, entryName);
        if (entryPoint != NULL)
        {
            entryPoint += wcslen(entryName);
            if (*entryPoint == L'"') { ++entryPoint; }
            while (*entryPoint == L' ' || *entryPoint == L'\t' || *entryPoint == L',') { ++entryPoint; }
            return SUCCEEDED(StringCchCopyW(tail, tailCch, entryPoint)) ? TRUE : FALSE;
        }
    }

    if (lpCmdLine != NULL && lpCmdLine[0] != L'\0')
    {
        return SUCCEEDED(StringCchCopyW(tail, tailCch, lpCmdLine)) ? TRUE : FALSE;
    }

    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static BOOL MeshRundll32_ManifestBoolW(const wchar_t* manifestPath, const wchar_t* keyName, BOOL defaultValue)
{
    wchar_t value[32] = {0};
    DWORD read = GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, keyName, defaultValue ? L"1" : L"0", value, (DWORD)_countof(value), manifestPath);
    if (read == 0) { return defaultValue; }
    if (_wcsicmp(value, L"1") == 0 || _wcsicmp(value, L"true") == 0 || _wcsicmp(value, L"yes") == 0 || _wcsicmp(value, L"on") == 0) { return TRUE; }
    if (_wcsicmp(value, L"0") == 0 || _wcsicmp(value, L"false") == 0 || _wcsicmp(value, L"no") == 0 || _wcsicmp(value, L"off") == 0) { return FALSE; }
    return defaultValue;
}

static BOOL MeshRundll32_WriteManifestStringW(const wchar_t* manifestPath, const wchar_t* keyName, const wchar_t* value)
{
    if (value == NULL || value[0] == L'\0') { return TRUE; }
    return WritePrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, keyName, value, manifestPath);
}

static BOOL MeshUmhHost_ValueIsSafeW(const wchar_t* value)
{
    if (value == NULL || value[0] == L'\0') { return FALSE; }
    return (wcschr(value, L'"') == NULL &&
            wcschr(value, L'\r') == NULL &&
            wcschr(value, L'\n') == NULL) ? TRUE : FALSE;
}

static BOOL MeshUmhHost_IsAbsolutePathW(const wchar_t* path)
{
    if (!MeshUmhHost_ValueIsSafeW(path)) { return FALSE; }
    if (((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' &&
        (path[2] == L'\\' || path[2] == L'/'))
    {
        return TRUE;
    }
    return (path[0] == L'\\' && path[1] == L'\\' && path[2] != L'\0') ? TRUE : FALSE;
}

static const wchar_t* MeshUmhHost_BaseNameW(const wchar_t* path)
{
    const wchar_t* slash = NULL;
    const wchar_t* backslash = NULL;
    if (path == NULL) { return NULL; }
    slash = wcsrchr(path, L'/');
    backslash = wcsrchr(path, L'\\');
    if (slash == NULL && backslash == NULL) { return path; }
    if (slash == NULL) { return backslash + 1; }
    if (backslash == NULL) { return slash + 1; }
    return (slash > backslash) ? (slash + 1) : (backslash + 1);
}

static BOOL MeshUmhHost_IsApprovedMasterServicePathW(const wchar_t* path)
{
    const wchar_t* baseName = MeshUmhHost_BaseNameW(path);
    if (!MeshUmhHost_IsAbsolutePathW(path)) { SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY); return FALSE; }
    if (baseName == NULL || _wcsicmp(baseName, L"MasterService.exe") != 0) { SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY); return FALSE; }
    if (!MeshRundll32_FileExistsW(path)) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    return TRUE;
}

static BOOL MeshUmhHost_ArgEquals(const MeshUmhHostManifest* manifest, DWORD index, const wchar_t* expected)
{
    if (manifest == NULL || expected == NULL || index >= manifest->argCount || index >= MESH_UMH_MAX_ARGS) { return FALSE; }
    return (_wcsicmp(manifest->args[index], expected) == 0) ? TRUE : FALSE;
}

static BOOL MeshUmhHost_ArgsAreApproved(const MeshUmhHostManifest* manifest)
{
    if (manifest == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (manifest->argCount == 3 &&
        MeshUmhHost_ArgEquals(manifest, 0, L"--status") &&
        MeshUmhHost_ArgEquals(manifest, 1, L"--output") &&
        MeshUmhHost_ArgEquals(manifest, 2, L"json"))
    {
        return TRUE;
    }
    if (manifest->argCount == 5 &&
        MeshUmhHost_ArgEquals(manifest, 0, L"--install") &&
        MeshUmhHost_ArgEquals(manifest, 1, L"--silent") &&
        MeshUmhHost_ArgEquals(manifest, 2, L"--output") &&
        MeshUmhHost_ArgEquals(manifest, 3, L"json") &&
        MeshUmhHost_ArgEquals(manifest, 4, L"--require-install-contract"))
    {
        return TRUE;
    }
    if (manifest->argCount == 7 &&
        (MeshUmhHost_ArgEquals(manifest, 0, L"--quit") || MeshUmhHost_ArgEquals(manifest, 0, L"--uninstall")) &&
        MeshUmhHost_ArgEquals(manifest, 1, L"--silent") &&
        MeshUmhHost_ArgEquals(manifest, 2, L"--wait") &&
        MeshUmhHost_ArgEquals(manifest, 3, L"--timeout") &&
        MeshUmhHost_ArgEquals(manifest, 4, L"120") &&
        MeshUmhHost_ArgEquals(manifest, 5, L"--output") &&
        MeshUmhHost_ArgEquals(manifest, 6, L"json"))
    {
        return TRUE;
    }
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    return FALSE;
}

static BOOL MeshUmhHost_ReadManifestW(const wchar_t* manifestPath, MeshUmhHostManifest* manifestOut)
{
    wchar_t countText[32] = {0};
    wchar_t key[32] = {0};
    DWORD read = 0;
    wchar_t* end = NULL;
    unsigned long parsedCount = 0;
    unsigned long parsedTimeout = 0;
    DWORD i = 0;

    if (manifestPath == NULL || manifestPath[0] == L'\0' || manifestOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!MeshRundll32_FileExistsW(manifestPath))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    ZeroMemory(manifestOut, sizeof(*manifestOut));
    if (FAILED(StringCchCopyW(manifestOut->manifestPath, _countof(manifestOut->manifestPath), manifestPath)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    read = GetPrivateProfileStringW(MESH_UMH_SECTION_W, MESH_UMH_KEY_EXE_PATH_W, L"", manifestOut->exePath, (DWORD)_countof(manifestOut->exePath), manifestPath);
    if (read == 0 || !MeshUmhHost_IsApprovedMasterServicePathW(manifestOut->exePath)) { return FALSE; }

    read = GetPrivateProfileStringW(MESH_UMH_SECTION_W, MESH_UMH_KEY_ARG_COUNT_W, L"", countText, (DWORD)_countof(countText), manifestPath);
    if (read == 0) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    parsedCount = wcstoul(countText, &end, 10);
    if (end == NULL || *end != L'\0' || parsedCount > MESH_UMH_MAX_ARGS)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    manifestOut->argCount = (DWORD)parsedCount;
    for (i = 0; i < manifestOut->argCount; ++i)
    {
        if (FAILED(StringCchPrintfW(key, _countof(key), L"Arg%lu", (unsigned long)i)))
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        read = GetPrivateProfileStringW(MESH_UMH_SECTION_W, key, L"", manifestOut->args[i], (DWORD)_countof(manifestOut->args[i]), manifestPath);
        if (read == 0 || !MeshUmhHost_ValueIsSafeW(manifestOut->args[i]))
        {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
    }
    if (!MeshUmhHost_ArgsAreApproved(manifestOut)) { return FALSE; }

    read = GetPrivateProfileStringW(MESH_UMH_SECTION_W, MESH_UMH_KEY_TIMEOUT_MS_W, L"", countText, (DWORD)_countof(countText), manifestPath);
    if (read == 0)
    {
        manifestOut->timeoutMs = MESH_UMH_DEFAULT_TIMEOUT_MS;
    }
    else
    {
        parsedTimeout = wcstoul(countText, &end, 10);
        if (end == NULL || *end != L'\0' || parsedTimeout < 1000UL || parsedTimeout > MESH_UMH_MAX_TIMEOUT_MS)
        {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
        manifestOut->timeoutMs = (DWORD)parsedTimeout;
    }
    return TRUE;
}

static BOOL MeshUmhHost_GetWorkingDirectoryW(const wchar_t* exePath, wchar_t* workDir, size_t workDirCch)
{
    wchar_t* slash = NULL;
    wchar_t* backslash = NULL;
    wchar_t* cut = NULL;
    if (exePath == NULL || workDir == NULL || workDirCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (FAILED(StringCchCopyW(workDir, workDirCch, exePath))) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    slash = wcsrchr(workDir, L'/');
    backslash = wcsrchr(workDir, L'\\');
    if (slash == NULL) { cut = backslash; }
    else if (backslash == NULL) { cut = slash; }
    else { cut = (slash > backslash) ? slash : backslash; }
    if (cut == NULL || cut == workDir) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *cut = L'\0';
    return TRUE;
}

static BOOL MeshUmhHost_AppendQuotedCommandLineArgumentW(wchar_t* output, size_t outputCch, size_t* offset, const wchar_t* value)
{
    if (output == NULL || outputCch == 0 || offset == NULL || !MeshUmhHost_ValueIsSafeW(value))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (*offset > 0)
    {
        if (*offset + 1 >= outputCch) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        output[(*offset)++] = L' ';
        output[*offset] = L'\0';
    }
    if (FAILED(StringCchPrintfW(output + *offset, outputCch - *offset, L"\"%ls\"", value)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    *offset += wcslen(output + *offset);
    return TRUE;
}

static BOOL MeshUmhHost_BuildCommandLineW(const MeshUmhHostManifest* manifest, wchar_t* commandLine, size_t commandLineCch)
{
    DWORD i = 0;
    size_t offset = 0;
    if (manifest == NULL || commandLine == NULL || commandLineCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    commandLine[0] = L'\0';
    if (!MeshUmhHost_AppendQuotedCommandLineArgumentW(commandLine, commandLineCch, &offset, manifest->exePath)) { return FALSE; }
    for (i = 0; i < manifest->argCount; ++i)
    {
        if (!MeshUmhHost_AppendQuotedCommandLineArgumentW(commandLine, commandLineCch, &offset, manifest->args[i])) { return FALSE; }
    }
    return TRUE;
}

static void MeshUmhHost_WriteStderrW(const wchar_t* message, DWORD errorCode)
{
    fwprintf(stderr, L"MeshUmhHostW: %ls (error=%lu)\r\n", message != NULL ? message : L"failed", (unsigned long)errorCode);
    fflush(stderr);
}

static DWORD MeshUmhHost_RunManifestCommandW(const MeshUmhHostManifest* manifest)
{
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;
    wchar_t commandLine[MAX_PATH * 8] = {0};
    wchar_t workingDirectory[MAX_PATH * 4] = {0};
    HANDLE job = NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo;
    DWORD waitResult = WAIT_FAILED;
    DWORD exitCode = ERROR_GEN_FAILURE;

    if (manifest == NULL) { return ERROR_INVALID_PARAMETER; }
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    ZeroMemory(&jobInfo, sizeof(jobInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    if (!MeshUmhHost_BuildCommandLineW(manifest, commandLine, _countof(commandLine)) ||
        !MeshUmhHost_GetWorkingDirectoryW(manifest->exePath, workingDirectory, _countof(workingDirectory)))
    {
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"failed to build command line", exitCode);
        return exitCode;
    }

    job = CreateJobObjectW(NULL, NULL);
    if (job != NULL)
    {
        jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo)))
        {
            CloseHandle(job);
            job = NULL;
        }
    }

    if (!CreateProcessW(
        manifest->exePath,
        commandLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        workingDirectory,
        &startupInfo,
        &processInfo))
    {
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"CreateProcessW failed for MasterService.exe", exitCode);
        if (job != NULL) { CloseHandle(job); }
        return exitCode;
    }

    if (job != NULL && !AssignProcessToJobObject(job, processInfo.hProcess))
    {
        CloseHandle(job);
        job = NULL;
    }

    waitResult = WaitForSingleObject(processInfo.hProcess, manifest->timeoutMs);
    if (waitResult == WAIT_TIMEOUT)
    {
        TerminateProcess(processInfo.hProcess, ERROR_TIMEOUT);
        exitCode = ERROR_TIMEOUT;
        MeshUmhHost_WriteStderrW(L"MasterService.exe timed out", exitCode);
    }
    else if (waitResult == WAIT_OBJECT_0)
    {
        if (!GetExitCodeProcess(processInfo.hProcess, &exitCode)) { exitCode = GetLastError(); }
    }
    else
    {
        exitCode = GetLastError();
        TerminateProcess(processInfo.hProcess, exitCode);
        MeshUmhHost_WriteStderrW(L"wait failed for MasterService.exe", exitCode);
    }

    if (processInfo.hThread != NULL) { CloseHandle(processInfo.hThread); }
    if (processInfo.hProcess != NULL) { CloseHandle(processInfo.hProcess); }
    if (job != NULL) { CloseHandle(job); }
    return exitCode;
}

static BOOL MeshRundll32_CreateDirectoryIfMissingW(const wchar_t* path)
{
    DWORD err = ERROR_SUCCESS;
    if (path == NULL || path[0] == L'\0') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (MeshRundll32_DirectoryExistsW(path)) { return TRUE; }
    if (CreateDirectoryW(path, NULL)) { return TRUE; }
    err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS && MeshRundll32_DirectoryExistsW(path)) { return TRUE; }
    SetLastError(err);
    return FALSE;
}

static BOOL MeshRundll32_CombinePathW(wchar_t* output, size_t outputCch, const wchar_t* root, const wchar_t* leaf)
{
    size_t rootLen = 0;
    if (output == NULL || outputCch == 0 || root == NULL || root[0] == L'\0' || leaf == NULL || leaf[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    output[0] = L'\0';
    if (FAILED(StringCchCopyW(output, outputCch, root))) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    rootLen = wcslen(output);
    if (rootLen > 0 && output[rootLen - 1] != L'\\' && output[rootLen - 1] != L'/')
    {
        if (FAILED(StringCchCatW(output, outputCch, L"\\"))) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    }
    if (FAILED(StringCchCatW(output, outputCch, leaf))) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    return TRUE;
}

static BOOL MeshRundll32_PrepareLifecycleStateDirectoryW(wchar_t* stateDir, size_t stateDirCch)
{
    StealthInstallPaths paths;
    wchar_t stateRoot[MAX_PATH * 4] = {0};
    wchar_t lifecycleDir[MAX_PATH * 4] = {0};

    if (stateDir == NULL || stateDirCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    stateDir[0] = L'\0';
    ZeroMemory(&paths, sizeof(paths));

    if (!Stealth_GetInstallPaths(&paths) || paths.installDir[0] == L'\0')
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    if (!Stealth_CreateInstallRootDirectory(paths.installDir))
    {
        return FALSE;
    }
    if (!MeshRundll32_CombinePathW(stateRoot, _countof(stateRoot), paths.installDir, L"state"))
    {
        return FALSE;
    }
    if (!MeshRundll32_CreateDirectoryIfMissingW(stateRoot))
    {
        return FALSE;
    }
    if (!MeshRundll32_CombinePathW(lifecycleDir, _countof(lifecycleDir), stateRoot, L"rundll32-lifecycle"))
    {
        return FALSE;
    }
    if (!MeshRundll32_CreateDirectoryIfMissingW(lifecycleDir))
    {
        return FALSE;
    }
    return SUCCEEDED(StringCchCopyW(stateDir, stateDirCch, lifecycleDir)) ? TRUE : FALSE;
}

static BOOL MeshRundll32_PrepareTempLifecycleDirectoryW(wchar_t* tempDir, size_t tempDirCch)
{
    wchar_t tempRoot[MAX_PATH * 4] = {0};
    DWORD tempLen = 0;

    if (tempDir == NULL || tempDirCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    tempDir[0] = L'\0';

    tempLen = GetTempPathW((DWORD)_countof(tempRoot), tempRoot);
    if (tempLen == 0 || tempLen >= (DWORD)_countof(tempRoot))
    {
        SetLastError(tempLen == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!MeshRundll32_CombinePathW(tempDir, tempDirCch, tempRoot, L"MeshAgent-rundll32-lifecycle"))
    {
        return FALSE;
    }
    return MeshRundll32_CreateDirectoryIfMissingW(tempDir);
}

static BOOL MeshRundll32_PrepareTempHostDllPathW(wchar_t* hostDllPath, size_t hostDllPathCch)
{
    wchar_t tempDir[MAX_PATH * 4] = {0};
    wchar_t fileName[128] = {0};

    if (hostDllPath == NULL || hostDllPathCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    hostDllPath[0] = L'\0';
    if (!MeshRundll32_PrepareTempLifecycleDirectoryW(tempDir, _countof(tempDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"host-%lu-%llu.dll", GetCurrentProcessId(), (unsigned long long)GetTickCount64())))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return MeshRundll32_CombinePathW(hostDllPath, hostDllPathCch, tempDir, fileName);
}

static BOOL MeshRundll32_PrepareLifecycleHostDllW(
    MeshRundll32LifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    wchar_t* hostDllPath,
    size_t hostDllPathCch,
    BOOL* deleteHostDllOnExit)
{
    StealthInstallPaths paths;
    wchar_t stateDir[MAX_PATH * 4] = {0};
    wchar_t fileName[128] = {0};

    if (hostDllPath == NULL || hostDllPathCch == 0 || deleteHostDllOnExit == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    hostDllPath[0] = L'\0';
    *deleteHostDllOnExit = FALSE;

    ZeroMemory(&paths, sizeof(paths));
    if (!Stealth_GetInstallPaths(&paths))
    {
        ZeroMemory(&paths, sizeof(paths));
    }

    if (paths.dllPath[0] != L'\0' && MeshRundll32_FileExistsW(paths.dllPath) &&
        (action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL ||
         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE ||
         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL ||
         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_PACKAGE))
    {
        return SUCCEEDED(StringCchCopyW(hostDllPath, hostDllPathCch, paths.dllPath)) ? TRUE : FALSE;
    }

    if (action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL)
    {
        wchar_t installedDllPath[MAX_PATH * 4] = {0};
        const wchar_t* uninstallSourceDll = NULL;

        if (sourceDllPath != NULL && sourceDllPath[0] != L'\0')
        {
            uninstallSourceDll = sourceDllPath;
        }
        else if (paths.dllPath[0] != L'\0' && MeshRundll32_FileExistsW(paths.dllPath) &&
                 SUCCEEDED(StringCchCopyW(installedDllPath, _countof(installedDllPath), paths.dllPath)))
        {
            uninstallSourceDll = installedDllPath;
        }

        if (!MeshRundll32_PrepareTempHostDllPathW(hostDllPath, hostDllPathCch))
        {
            return FALSE;
        }
        if (!Stealth_StageSvchostDllForLifecycleHost(sourceExePath, uninstallSourceDll, hostDllPath))
        {
            return FALSE;
        }
        *deleteHostDllOnExit = TRUE;
        return TRUE;
    }

    if (!MeshRundll32_PrepareLifecycleStateDirectoryW(stateDir, _countof(stateDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"host-%lu-%llu.dll", GetCurrentProcessId(), (unsigned long long)GetTickCount64())))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!MeshRundll32_CombinePathW(hostDllPath, hostDllPathCch, stateDir, fileName))
    {
        return FALSE;
    }

    if (!Stealth_StageSvchostDllForLifecycleHost(sourceExePath, sourceDllPath, hostDllPath))
    {
        return FALSE;
    }
    *deleteHostDllOnExit = TRUE;
    return TRUE;
}

static BOOL MeshRundll32_GetInstalledLifecycleHostDllW(wchar_t* hostDllPath, size_t hostDllPathCch)
{
    StealthInstallPaths paths;

    if (hostDllPath == NULL || hostDllPathCch == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    hostDllPath[0] = L'\0';
    ZeroMemory(&paths, sizeof(paths));
    if (!Stealth_GetInstallPaths(&paths) || paths.dllPath[0] == L'\0' || !MeshRundll32_FileExistsW(paths.dllPath))
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    if (FAILED(StringCchCopyW(hostDllPath, hostDllPathCch, paths.dllPath)))
    {
        hostDllPath[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

static BOOL MeshRundll32_PrepareManifestPathW(wchar_t* manifestPath, size_t manifestPathCch)
{
    wchar_t stateDir[MAX_PATH * 4] = {0};
    wchar_t fileName[128] = {0};
    if (manifestPath == NULL || manifestPathCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    manifestPath[0] = L'\0';
    if (!MeshRundll32_PrepareLifecycleStateDirectoryW(stateDir, _countof(stateDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"manifest-%lu-%llu.ini", GetCurrentProcessId(), (unsigned long long)GetTickCount64())))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return MeshRundll32_CombinePathW(manifestPath, manifestPathCch, stateDir, fileName);
}

static BOOL MeshRundll32_PrepareTempManifestPathW(wchar_t* manifestPath, size_t manifestPathCch)
{
    wchar_t tempDir[MAX_PATH * 4] = {0};
    wchar_t fileName[128] = {0};

    if (manifestPath == NULL || manifestPathCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    manifestPath[0] = L'\0';

    if (!MeshRundll32_PrepareTempLifecycleDirectoryW(tempDir, _countof(tempDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"manifest-%lu-%llu.ini", GetCurrentProcessId(), (unsigned long long)GetTickCount64())))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return MeshRundll32_CombinePathW(manifestPath, manifestPathCch, tempDir, fileName);
}

static void MeshRundll32_ApplyBrandingFromManifest(const MeshRundll32LifecycleManifest* manifest)
{
    char utf8[2048];
    int converted = 0;

    if (manifest == NULL) { return; }
    Stealth_ClearRuntimeBrandingOverrides();

    if (manifest->displayName[0] != L'\0')
    {
        ZeroMemory(utf8, sizeof(utf8));
        converted = WideCharToMultiByte(CP_UTF8, 0, manifest->displayName, -1, utf8, (int)sizeof(utf8), NULL, NULL);
        if (converted > 0) { Stealth_SetRuntimeDisplayNameUtf8(utf8); }
    }
    if (manifest->serviceDescription[0] != L'\0')
    {
        ZeroMemory(utf8, sizeof(utf8));
        converted = WideCharToMultiByte(CP_UTF8, 0, manifest->serviceDescription, -1, utf8, (int)sizeof(utf8), NULL, NULL);
        if (converted > 0) { Stealth_SetRuntimeServiceDescriptionUtf8(utf8); }
    }
}

const wchar_t* MeshRundll32_LifecycleActionNameW(MeshRundll32LifecycleAction action)
{
    switch (action)
    {
        case MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL: return MESH_LIFECYCLE_ACTION_INSTALL_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE: return MESH_LIFECYCLE_ACTION_UPDATE_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_REPAIR: return MESH_LIFECYCLE_ACTION_REPAIR_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_REINSTALL: return MESH_LIFECYCLE_ACTION_REINSTALL_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL: return MESH_LIFECYCLE_ACTION_UNINSTALL_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL: return MESH_LIFECYCLE_ACTION_VALIDATE_INSTALL_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE: return MESH_LIFECYCLE_ACTION_VALIDATE_UPDATE_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL: return MESH_LIFECYCLE_ACTION_VALIDATE_UNINSTALL_W;
        case MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_PACKAGE: return MESH_LIFECYCLE_ACTION_VALIDATE_PACKAGE_W;
        default: return L"unknown";
    }
}

BOOL MeshRundll32_LifecycleActionFromStringW(const wchar_t* value, MeshRundll32LifecycleAction* actionOut)
{
    MeshRundll32LifecycleAction action = MESH_RUNDLL32_LIFECYCLE_ACTION_UNKNOWN;
    if (actionOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *actionOut = MESH_RUNDLL32_LIFECYCLE_ACTION_UNKNOWN;
    if (value == NULL || value[0] == L'\0') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }

    if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_INSTALL_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_UPDATE_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_REPAIR_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_REPAIR; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_REINSTALL_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_REINSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_UNINSTALL_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_INSTALL_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_UPDATE_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_UNINSTALL_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_PACKAGE_W) == 0) { action = MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_PACKAGE; }
    else { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }

    *actionOut = action;
    return TRUE;
}

BOOL MeshRundll32_ReadLifecycleManifestW(const wchar_t* manifestPath, MeshRundll32LifecycleManifest* manifestOut)
{
    wchar_t actionName[64] = {0};
    DWORD actionLen = 0;

    if (manifestPath == NULL || manifestPath[0] == L'\0' || manifestOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!MeshRundll32_FileExistsW(manifestPath))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    ZeroMemory(manifestOut, sizeof(*manifestOut));
    if (FAILED(StringCchCopyW(manifestOut->manifestPath, _countof(manifestOut->manifestPath), manifestPath)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    actionLen = GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_ACTION_W, L"", actionName, (DWORD)_countof(actionName), manifestPath);
    if (actionLen == 0 || !MeshRundll32_LifecycleActionFromStringW(actionName, &manifestOut->action))
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_SOURCE_EXE_W, L"", manifestOut->sourceExePath, (DWORD)_countof(manifestOut->sourceExePath), manifestPath);
    GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_SOURCE_DLL_W, L"", manifestOut->sourceDllPath, (DWORD)_countof(manifestOut->sourceDllPath), manifestPath);
    GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_DISPLAY_NAME_W, L"", manifestOut->displayName, (DWORD)_countof(manifestOut->displayName), manifestPath);
    GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_DESCRIPTION_W, L"", manifestOut->serviceDescription, (DWORD)_countof(manifestOut->serviceDescription), manifestPath);
    manifestOut->requireConfig = MeshRundll32_ManifestBoolW(manifestPath, MESH_LIFECYCLE_KEY_REQUIRE_CONFIG_W, TRUE);
    return TRUE;
}

BOOL MeshRundll32_WriteLifecycleManifestW(
    const wchar_t* manifestPath,
    MeshRundll32LifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    BOOL requireConfig)
{
    const wchar_t* actionName = MeshRundll32_LifecycleActionNameW(action);
    if (manifestPath == NULL || manifestPath[0] == L'\0' || action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNKNOWN)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    DeleteFileW(manifestPath);
    if (!WritePrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_ACTION_W, actionName, manifestPath)) { return FALSE; }
    if (!MeshRundll32_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_SOURCE_EXE_W, sourceExePath)) { return FALSE; }
    if (!MeshRundll32_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_SOURCE_DLL_W, sourceDllPath)) { return FALSE; }
    if (!MeshRundll32_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_DISPLAY_NAME_W, displayName)) { return FALSE; }
    if (!MeshRundll32_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_DESCRIPTION_W, serviceDescription)) { return FALSE; }
    if (!WritePrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_REQUIRE_CONFIG_W, requireConfig ? L"1" : L"0", manifestPath)) { return FALSE; }
    return TRUE;
}

BOOL MeshRundll32_GetSystemRundll32PathW(wchar_t* rundll32Path, size_t rundll32PathCch)
{
    UINT len = 0;
    if (rundll32Path == NULL || rundll32PathCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    rundll32Path[0] = L'\0';
    len = GetSystemDirectoryW(rundll32Path, (UINT)rundll32PathCch);
    if (len == 0 || len >= rundll32PathCch)
    {
        SetLastError(len == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER);
        rundll32Path[0] = L'\0';
        return FALSE;
    }
    if (FAILED(StringCchCatW(rundll32Path, rundll32PathCch, L"\\rundll32.exe")))
    {
        rundll32Path[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return MeshRundll32_FileExistsW(rundll32Path);
}

BOOL MeshRundll32_LaunchLifecycleHostW(
    MeshRundll32LifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    BOOL requireConfig,
    BOOL waitForExit,
    DWORD timeoutMs,
    DWORD* exitCodeOut)
{
    wchar_t rundll32Path[MAX_PATH] = {0};
    wchar_t hostDllPath[MAX_PATH * 4] = {0};
    wchar_t manifestPath[MAX_PATH * 4] = {0};
    wchar_t commandLine[MAX_PATH * 12] = {0};
    BOOL deleteHostDllOnExit = FALSE;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    DWORD waitResult = WAIT_OBJECT_0;
    DWORD exitCode = STILL_ACTIVE;
    BOOL ok = FALSE;

    if (exitCodeOut != NULL) { *exitCodeOut = ERROR_GEN_FAILURE; }
    if (action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNKNOWN) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL)
    {
        Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log");
    }

    if (!MeshRundll32_GetSystemRundll32PathW(rundll32Path, _countof(rundll32Path)) ||
        !MeshRundll32_PrepareLifecycleHostDllW(action, sourceExePath, sourceDllPath, hostDllPath, _countof(hostDllPath), &deleteHostDllOnExit) ||
        !((action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL ||
           action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL) ?
            MeshRundll32_PrepareTempManifestPathW(manifestPath, _countof(manifestPath)) :
            MeshRundll32_PrepareManifestPathW(manifestPath, _countof(manifestPath))))
    {
        return FALSE;
    }

    if (!MeshRundll32_WriteLifecycleManifestW(
            manifestPath,
            action,
            sourceExePath,
            hostDllPath,
            displayName,
            serviceDescription,
            requireConfig))
    {
        goto cleanup;
    }

    if (FAILED(StringCchPrintfW(
            commandLine,
            _countof(commandLine),
            L"\"%ls\" \"%ls\",%ls \"%ls\"",
            rundll32Path,
            hostDllPath,
            MESH_RUNDLL32_ENTRY_LIFECYCLE_W,
            manifestPath)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        goto cleanup;
    }

    Stealth_LogInstallEvent(L"[RUNDLL32_CONTRACT] Launching lifecycle action=%ls dll=%ls manifest=%ls",
        MeshRundll32_LifecycleActionNameW(action),
        hostDllPath,
        manifestPath);

    if (!CreateProcessW(rundll32Path, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        Stealth_LogInstallEvent(L"[RUNDLL32_CONTRACT] CreateProcessW failed for lifecycle host (error=%lu)", GetLastError());
        goto cleanup;
    }

    ok = TRUE;
    if (waitForExit)
    {
        waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
        if (waitResult != WAIT_OBJECT_0)
        {
            Stealth_LogInstallEvent(L"[RUNDLL32_CONTRACT] lifecycle host wait failed/timed out (wait=%lu error=%lu)", waitResult, GetLastError());
            ok = FALSE;
            if (waitResult == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, ERROR_TIMEOUT); }
        }
        if (!GetExitCodeProcess(pi.hProcess, &exitCode))
        {
            exitCode = GetLastError();
            ok = FALSE;
        }
        if (exitCodeOut != NULL) { *exitCodeOut = exitCode; }
        if (exitCode != ERROR_SUCCESS)
        {
            ok = FALSE;
            Stealth_LogInstallEvent(L"[RUNDLL32_CONTRACT] lifecycle host action=%ls exited with %lu",
                MeshRundll32_LifecycleActionNameW(action),
                exitCode);
        }
    }
    else if (exitCodeOut != NULL)
    {
        *exitCodeOut = ERROR_SUCCESS;
    }

cleanup:
    if (pi.hThread != NULL) { CloseHandle(pi.hThread); }
    if (pi.hProcess != NULL) { CloseHandle(pi.hProcess); }
    if (waitForExit && manifestPath[0] != L'\0') { DeleteFileW(manifestPath); }
    if (waitForExit && deleteHostDllOnExit && hostDllPath[0] != L'\0') { DeleteFileW(hostDllPath); }
    return ok;
}

BOOL MeshRundll32_LaunchLauncherCleanupW(const wchar_t* targetPath, DWORD parentPid, DWORD timeoutMs)
{
    wchar_t rundll32Path[MAX_PATH] = {0};
    wchar_t hostDllPath[MAX_PATH * 4] = {0};
    wchar_t commandLine[MAX_PATH * 12] = {0};
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;

    if (targetPath == NULL || targetPath[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (timeoutMs == 0) { timeoutMs = 60000; }
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (!MeshRundll32_GetSystemRundll32PathW(rundll32Path, _countof(rundll32Path)) ||
        !MeshRundll32_GetInstalledLifecycleHostDllW(hostDllPath, _countof(hostDllPath)))
    {
        Stealth_LogInstallEvent(L"[LAUNCHER_CLEANUP] Unable to resolve cleanup host for target=%ls error=%lu", targetPath, GetLastError());
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(
            commandLine,
            _countof(commandLine),
            L"\"%ls\" \"%ls\",%ls \"%ls\" %lu %lu",
            rundll32Path,
            hostDllPath,
            MESH_RUNDLL32_ENTRY_LAUNCHER_CLEANUP_W,
            targetPath,
            (unsigned long)parentPid,
            (unsigned long)timeoutMs)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (!CreateProcessW(rundll32Path, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        Stealth_LogInstallEvent(L"[LAUNCHER_CLEANUP] CreateProcessW failed target=%ls error=%lu", targetPath, GetLastError());
        return FALSE;
    }

    if (pi.hThread != NULL) { CloseHandle(pi.hThread); }
    if (pi.hProcess != NULL) { CloseHandle(pi.hProcess); }
    Stealth_LogInstallEvent(L"[LAUNCHER_CLEANUP] Scheduled cleanup target=%ls parentPid=%lu timeoutMs=%lu",
        targetPath,
        (unsigned long)parentPid,
        (unsigned long)timeoutMs);
    return TRUE;
}

BOOL MeshRundll32_LaunchSelfTestHostW(const wchar_t* arguments, DWORD timeoutMs, DWORD* exitCodeOut)
{
    wchar_t rundll32Path[MAX_PATH] = {0};
    wchar_t hostDllPath[MAX_PATH * 4] = {0};
    wchar_t commandLine[32768] = {0};
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    DWORD waitResult = WAIT_OBJECT_0;
    DWORD exitCode = ERROR_GEN_FAILURE;
    BOOL ok = FALSE;

    if (exitCodeOut != NULL) { *exitCodeOut = ERROR_GEN_FAILURE; }
    if (arguments == NULL || arguments[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (timeoutMs == 0) { timeoutMs = INFINITE; }

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (!MeshRundll32_GetSystemRundll32PathW(rundll32Path, _countof(rundll32Path)) ||
        !MeshRundll32_GetInstalledLifecycleHostDllW(hostDllPath, _countof(hostDllPath)))
    {
        Stealth_LogInstallEvent(L"[SELFTEST_HOST] Unable to resolve rundll32 self-test host (error=%lu)", GetLastError());
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(
            commandLine,
            _countof(commandLine),
            L"\"%ls\" \"%ls\",%ls %ls",
            rundll32Path,
            hostDllPath,
            MESH_RUNDLL32_ENTRY_SELFTEST_W,
            arguments)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    Stealth_LogInstallEvent(L"[SELFTEST_HOST] Launching rundll32 self-test host dll=%ls", hostDllPath);
    if (!CreateProcessW(rundll32Path, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        Stealth_LogInstallEvent(L"[SELFTEST_HOST] CreateProcessW failed (error=%lu)", GetLastError());
        return FALSE;
    }

    waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (waitResult != WAIT_OBJECT_0)
    {
        Stealth_LogInstallEvent(L"[SELFTEST_HOST] Wait failed/timed out (wait=%lu error=%lu)", waitResult, GetLastError());
        if (waitResult == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, ERROR_TIMEOUT); }
        ok = FALSE;
    }
    else
    {
        ok = TRUE;
    }

    if (!GetExitCodeProcess(pi.hProcess, &exitCode))
    {
        exitCode = GetLastError();
        ok = FALSE;
    }
    if (exitCodeOut != NULL) { *exitCodeOut = exitCode; }
    if (exitCode != ERROR_SUCCESS)
    {
        ok = FALSE;
        Stealth_LogInstallEvent(L"[SELFTEST_HOST] self-test host exited with %lu", exitCode);
    }

    if (pi.hThread != NULL) { CloseHandle(pi.hThread); }
    if (pi.hProcess != NULL) { CloseHandle(pi.hProcess); }
    return ok;
}

static DWORD MeshRundll32_DeleteLauncherAfterParentExitW(const wchar_t* targetPath, DWORD parentPid, DWORD timeoutMs)
{
    HANDLE parentProcess = NULL;
    ULONGLONG deadline = 0;
    DWORD lastError = ERROR_SUCCESS;

    if (targetPath == NULL || targetPath[0] == L'\0') { return ERROR_INVALID_PARAMETER; }
    if (timeoutMs == 0) { timeoutMs = 60000; }

    if (parentPid != 0)
    {
        parentProcess = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
        if (parentProcess != NULL)
        {
            (void)WaitForSingleObject(parentProcess, timeoutMs);
            CloseHandle(parentProcess);
        }
    }

    deadline = GetTickCount64() + timeoutMs;
    for (;;)
    {
        DWORD attrs = GetFileAttributesW(targetPath);
        if (attrs == INVALID_FILE_ATTRIBUTES)
        {
            lastError = GetLastError();
            return (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND) ? ERROR_SUCCESS : lastError;
        }
        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            return ERROR_DIRECTORY;
        }
        if ((attrs & FILE_ATTRIBUTE_READONLY) != 0)
        {
            SetFileAttributesW(targetPath, attrs & ~FILE_ATTRIBUTE_READONLY);
        }
        if (DeleteFileW(targetPath))
        {
            return ERROR_SUCCESS;
        }

        lastError = GetLastError();
        if (GetTickCount64() >= deadline) { break; }
        Sleep(250);
    }

    if (MoveFileExW(targetPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
    {
        Stealth_LogInstallEvent(L"[LAUNCHER_CLEANUP] Deferred launcher delete until reboot target=%ls lastError=%lu", targetPath, lastError);
        return ERROR_SUCCESS;
    }
    return GetLastError();
}

static void MeshConsoleBridge_CloseHandle(HANDLE* handleRef)
{
    if (handleRef == NULL) { return; }
    if (*handleRef != NULL && *handleRef != INVALID_HANDLE_VALUE) { CloseHandle(*handleRef); }
    *handleRef = NULL;
}

static BOOL MeshConsoleBridge_HasSuffixW(const wchar_t* value, const wchar_t* suffix)
{
    size_t valueLen = 0;
    size_t suffixLen = 0;
    if (value == NULL || suffix == NULL) { return FALSE; }
    valueLen = wcslen(value);
    suffixLen = wcslen(suffix);
    if (valueLen <= suffixLen) { return FALSE; }
    return (_wcsicmp(value + (valueLen - suffixLen), suffix) == 0) ? TRUE : FALSE;
}

static BOOL MeshConsoleBridge_IsApprovedPipeNameW(const wchar_t* value, const wchar_t* suffix)
{
    size_t valueLen = 0;
    size_t prefixLen = wcslen(MESH_CONSOLE_BRIDGE_PIPE_PREFIX_W);
    size_t suffixLen = 0;
    size_t i = 0;
    if (value == NULL || suffix == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    valueLen = wcslen(value);
    suffixLen = wcslen(suffix);
    if (valueLen <= (prefixLen + suffixLen) || _wcsnicmp(value, MESH_CONSOLE_BRIDGE_PIPE_PREFIX_W, prefixLen) != 0 || !MeshConsoleBridge_HasSuffixW(value, suffix))
    {
        SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return FALSE;
    }
    for (i = prefixLen; i < valueLen - suffixLen; ++i)
    {
        wchar_t c = value[i];
        if (!((c >= L'0' && c <= L'9') || c == L'_'))
        {
            SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL MeshConsoleBridge_ParseUnsignedTokenW(const wchar_t* value, DWORD minValue, DWORD maxValue, DWORD* output)
{
    wchar_t* end = NULL;
    unsigned long parsed = 0;
    if (output == NULL || value == NULL || value[0] == L'\0') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    parsed = wcstoul(value, &end, 10);
    if (end == value || end == NULL || *end != L'\0' || parsed < minValue || parsed > maxValue)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *output = (DWORD)parsed;
    return TRUE;
}

static BOOL MeshConsoleBridge_ResolveShellW(const wchar_t* shellName, BOOL nonInteractive, wchar_t* shellPath, size_t shellPathCch, wchar_t* commandLine, size_t commandLineCch)
{
    DWORD systemDirLen = 0;
    const wchar_t* shellSuffix = L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    const wchar_t* shellArgs = nonInteractive ? L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -" : L" -NoLogo -NoProfile";
    if (shellName == NULL || shellPath == NULL || shellPathCch == 0 || commandLine == NULL || commandLineCch == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    shellPath[0] = L'\0';
    commandLine[0] = L'\0';
    if (_wcsicmp(shellName, L"powershell") != 0)
    {
        SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return FALSE;
    }
    systemDirLen = GetSystemDirectoryW(shellPath, (UINT)shellPathCch);
    if (systemDirLen == 0 || systemDirLen >= shellPathCch)
    {
        shellPath[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (FAILED(StringCchCatW(shellPath, shellPathCch, shellSuffix)) ||
        FAILED(StringCchPrintfW(commandLine, commandLineCch, L"\"%ls\"%ls", shellPath, shellArgs)))
    {
        shellPath[0] = L'\0';
        commandLine[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!MeshRundll32_FileExistsW(shellPath)) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    return TRUE;
}

static BOOL MeshConsoleBridge_LoadConptyApi(MeshConsoleBridgeConptyApi* api)
{
    HMODULE kernel32Module = NULL;
    if (api == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    ZeroMemory(api, sizeof(*api));
    kernel32Module = GetModuleHandleW(L"kernel32.dll");
    if (kernel32Module == NULL) { kernel32Module = LoadLibraryW(L"kernel32.dll"); }
    if (kernel32Module == NULL) { return FALSE; }
    api->CreatePseudoConsoleFn = (MeshConsoleBridge_CreatePseudoConsoleFn)GetProcAddress(kernel32Module, "CreatePseudoConsole");
    api->ClosePseudoConsoleFn = (MeshConsoleBridge_ClosePseudoConsoleFn)GetProcAddress(kernel32Module, "ClosePseudoConsole");
    if (api->CreatePseudoConsoleFn == NULL || api->ClosePseudoConsoleFn == NULL)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    return TRUE;
}

static HANDLE MeshConsoleBridge_OpenPipeClientW(const wchar_t* pipeName, DWORD desiredAccess, DWORD timeoutMs)
{
    ULONGLONG deadline = 0;
    DWORD lastError = ERROR_SUCCESS;
    if (pipeName == NULL || pipeName[0] == L'\0') { SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    deadline = GetTickCount64() + timeoutMs;
    for (;;)
    {
        HANDLE pipeHandle = CreateFileW(pipeName, desiredAccess, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (pipeHandle != INVALID_HANDLE_VALUE) { return pipeHandle; }
        lastError = GetLastError();
        if (lastError != ERROR_PIPE_BUSY && lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND)
        {
            SetLastError(lastError);
            return INVALID_HANDLE_VALUE;
        }
        if (GetTickCount64() >= deadline)
        {
            SetLastError(lastError == ERROR_SUCCESS ? ERROR_SEM_TIMEOUT : lastError);
            return INVALID_HANDLE_VALUE;
        }
        if (!WaitNamedPipeW(pipeName, 250))
        {
            lastError = GetLastError();
            if (lastError != ERROR_SEM_TIMEOUT && lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND && lastError != ERROR_PIPE_BUSY)
            {
                SetLastError(lastError);
                return INVALID_HANDLE_VALUE;
            }
            Sleep(50);
        }
    }
}

static BOOL MeshConsoleBridge_OpenElevatedPrimaryTokenForSession(DWORD sessionId, HANDLE* userTokenOut)
{
    HANDLE currentToken = NULL;
    HANDLE userToken = NULL;
    BOOL ok = FALSE;
    if (userTokenOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *userTokenOut = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &currentToken)) { return FALSE; }
    ok = DuplicateTokenEx(currentToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, NULL, SecurityImpersonation, TokenPrimary, &userToken);
    CloseHandle(currentToken);
    if (!ok) { return FALSE; }
    if (!SetTokenInformation(userToken, TokenSessionId, &sessionId, sizeof(sessionId)))
    {
        CloseHandle(userToken);
        return FALSE;
    }
    *userTokenOut = userToken;
    return TRUE;
}

static BOOL MeshConsoleBridge_TryCreateEnvironmentBlock(HANDLE userToken, LPVOID* environment, MeshConsoleBridge_DestroyEnvironmentBlockFn* destroyFnOut, HMODULE* moduleOut)
{
    HMODULE userEnvModule = NULL;
    MeshConsoleBridge_CreateEnvironmentBlockFn createFn = NULL;
    MeshConsoleBridge_DestroyEnvironmentBlockFn destroyFn = NULL;
    if (environment == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *environment = NULL;
    if (destroyFnOut != NULL) { *destroyFnOut = NULL; }
    if (moduleOut != NULL) { *moduleOut = NULL; }
    if (userToken == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    userEnvModule = LoadLibraryExW(L"userenv.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (userEnvModule == NULL && GetLastError() == ERROR_INVALID_PARAMETER) { userEnvModule = LoadLibraryW(L"userenv.dll"); }
    if (userEnvModule == NULL) { return FALSE; }
    createFn = (MeshConsoleBridge_CreateEnvironmentBlockFn)GetProcAddress(userEnvModule, "CreateEnvironmentBlock");
    destroyFn = (MeshConsoleBridge_DestroyEnvironmentBlockFn)GetProcAddress(userEnvModule, "DestroyEnvironmentBlock");
    if (createFn == NULL || destroyFn == NULL)
    {
        FreeLibrary(userEnvModule);
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    if (!createFn(environment, userToken, FALSE))
    {
        DWORD error = GetLastError();
        FreeLibrary(userEnvModule);
        SetLastError(error);
        return FALSE;
    }
    if (destroyFnOut != NULL) { *destroyFnOut = destroyFn; }
    if (moduleOut != NULL) { *moduleOut = userEnvModule; }
    else { FreeLibrary(userEnvModule); }
    return TRUE;
}

static BOOL MeshConsoleBridge_CreateShellProcessW(HANDLE pseudoConsole, const wchar_t* shellPath, wchar_t* commandLine, DWORD targetSessionId, PROCESS_INFORMATION* processInfo)
{
    STARTUPINFOEXW startupInfo;
    SIZE_T attributeListSize = 0;
    HANDLE userToken = NULL;
    LPVOID environment = NULL;
    HMODULE userEnvModule = NULL;
    MeshConsoleBridge_DestroyEnvironmentBlockFn destroyEnvironmentFn = NULL;
    DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    wchar_t systemDirectory[MAX_PATH] = { 0 };
    DWORD systemDirectoryLen = 0;
    BOOL ok = FALSE;
    DWORD lastError = ERROR_SUCCESS;
    if (pseudoConsole == NULL || shellPath == NULL || shellPath[0] == L'\0' || commandLine == NULL || commandLine[0] == L'\0' || processInfo == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(processInfo, sizeof(*processInfo));
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.StartupInfo.lpDesktop = L"winsta0\\default";
    startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);
    if (attributeListSize == 0) { return FALSE; }
    startupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeListSize);
    if (startupInfo.lpAttributeList == NULL) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    if (!InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &attributeListSize))
    {
        lastError = GetLastError();
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
        SetLastError(lastError);
        return FALSE;
    }
    if (!UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, pseudoConsole, sizeof(pseudoConsole), NULL, NULL))
    {
        lastError = GetLastError();
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
        SetLastError(lastError);
        return FALSE;
    }
    systemDirectoryLen = GetSystemDirectoryW(systemDirectory, (UINT)_countof(systemDirectory));
    if (systemDirectoryLen == 0 || systemDirectoryLen >= _countof(systemDirectory))
    {
        lastError = (GetLastError() == ERROR_SUCCESS) ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
        SetLastError(lastError);
        return FALSE;
    }
    if (targetSessionId != MESH_CONSOLE_BRIDGE_NO_SESSION)
    {
        if (!MeshConsoleBridge_OpenElevatedPrimaryTokenForSession(targetSessionId, &userToken))
        {
            lastError = GetLastError();
            DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
            HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
            SetLastError(lastError);
            return FALSE;
        }
        if (!MeshConsoleBridge_TryCreateEnvironmentBlock(userToken, &environment, &destroyEnvironmentFn, &userEnvModule))
        {
            Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] CreateEnvironmentBlock failed session=%lu error=%lu; using default environment", (unsigned long)targetSessionId, (unsigned long)GetLastError());
            environment = NULL;
        }
        ok = CreateProcessAsUserW(userToken, shellPath, commandLine, NULL, NULL, FALSE, creationFlags, environment, systemDirectory, &startupInfo.StartupInfo, processInfo);
    }
    else
    {
        ok = CreateProcessW(shellPath, commandLine, NULL, NULL, FALSE, creationFlags, NULL, systemDirectory, &startupInfo.StartupInfo, processInfo);
    }
    lastError = ok ? ERROR_SUCCESS : GetLastError();
    if (environment != NULL && destroyEnvironmentFn != NULL) { destroyEnvironmentFn(environment); }
    if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
    if (userToken != NULL) { CloseHandle(userToken); }
    DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
    if (!ok) { SetLastError(lastError); }
    return ok;
}

static BOOL MeshConsoleBridge_IsSessionSpawnFallbackError(DWORD errorCode)
{
    return (errorCode == ERROR_ACCESS_DENIED ||
        errorCode == ERROR_PRIVILEGE_NOT_HELD ||
        errorCode == ERROR_NOT_ALL_ASSIGNED) ? TRUE : FALSE;
}

static BOOL MeshConsoleBridge_CreateShellProcessWithRetryW(HANDLE pseudoConsole, const wchar_t* shellPath, wchar_t* commandLine, DWORD targetSessionId, PROCESS_INFORMATION* processInfo)
{
    DWORD attempt = 0;
    DWORD lastError = ERROR_SUCCESS;

    if (processInfo == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (attempt = 1; attempt <= MESH_CONSOLE_BRIDGE_SHELL_SPAWN_ATTEMPTS; ++attempt)
    {
        ZeroMemory(processInfo, sizeof(*processInfo));
        if (MeshConsoleBridge_CreateShellProcessW(pseudoConsole, shellPath, commandLine, targetSessionId, processInfo))
        {
            if (attempt > 1)
            {
                Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Shell spawn recovered inside same rundll32 attempt=%lu session=%lu",
                    (unsigned long)attempt,
                    (unsigned long)targetSessionId);
            }
            return TRUE;
        }

        lastError = GetLastError();
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Shell spawn failed inside same rundll32 attempt=%lu/%lu session=%lu error=%lu",
            (unsigned long)attempt,
            (unsigned long)MESH_CONSOLE_BRIDGE_SHELL_SPAWN_ATTEMPTS,
            (unsigned long)targetSessionId,
            (unsigned long)lastError);

        if (attempt < MESH_CONSOLE_BRIDGE_SHELL_SPAWN_ATTEMPTS)
        {
            Sleep(MESH_CONSOLE_BRIDGE_SHELL_SPAWN_RETRY_DELAY_MS);
        }
    }

    if (targetSessionId != MESH_CONSOLE_BRIDGE_NO_SESSION && MeshConsoleBridge_IsSessionSpawnFallbackError(lastError))
    {
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Falling back to bridge token inside same rundll32 after session spawn denial session=%lu error=%lu",
            (unsigned long)targetSessionId,
            (unsigned long)lastError);
        ZeroMemory(processInfo, sizeof(*processInfo));
        if (MeshConsoleBridge_CreateShellProcessW(pseudoConsole, shellPath, commandLine, MESH_CONSOLE_BRIDGE_NO_SESSION, processInfo))
        {
            return TRUE;
        }
        lastError = GetLastError();
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Bridge-token shell fallback failed inside same rundll32 error=%lu", (unsigned long)lastError);
    }

    SetLastError(lastError == ERROR_SUCCESS ? ERROR_GEN_FAILURE : lastError);
    return FALSE;
}

static BOOL MeshConsoleBridge_CreateInheritablePipePair(HANDLE* readHandle, HANDLE* writeHandle, BOOL inheritRead, BOOL inheritWrite)
{
    SECURITY_ATTRIBUTES securityAttributes;
    DWORD lastError = ERROR_SUCCESS;

    if (readHandle == NULL || writeHandle == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *readHandle = NULL;
    *writeHandle = NULL;
    ZeroMemory(&securityAttributes, sizeof(securityAttributes));
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.bInheritHandle = TRUE;

    if (!CreatePipe(readHandle, writeHandle, &securityAttributes, 0)) { return FALSE; }
    if (!SetHandleInformation(*readHandle, HANDLE_FLAG_INHERIT, inheritRead ? HANDLE_FLAG_INHERIT : 0))
    {
        lastError = GetLastError();
        MeshConsoleBridge_CloseHandle(readHandle);
        MeshConsoleBridge_CloseHandle(writeHandle);
        SetLastError(lastError);
        return FALSE;
    }
    if (!SetHandleInformation(*writeHandle, HANDLE_FLAG_INHERIT, inheritWrite ? HANDLE_FLAG_INHERIT : 0))
    {
        lastError = GetLastError();
        MeshConsoleBridge_CloseHandle(readHandle);
        MeshConsoleBridge_CloseHandle(writeHandle);
        SetLastError(lastError);
        return FALSE;
    }
    return TRUE;
}

static BOOL MeshConsoleBridge_CreateRedirectedShellProcessW(HANDLE stdinRead, HANDLE stdoutWrite, const wchar_t* shellPath, wchar_t* commandLine, DWORD targetSessionId, PROCESS_INFORMATION* processInfo)
{
    STARTUPINFOW startupInfo;
    HANDLE userToken = NULL;
    LPVOID environment = NULL;
    HMODULE userEnvModule = NULL;
    MeshConsoleBridge_DestroyEnvironmentBlockFn destroyEnvironmentFn = NULL;
    DWORD creationFlags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    wchar_t systemDirectory[MAX_PATH] = { 0 };
    DWORD systemDirectoryLen = 0;
    BOOL ok = FALSE;
    DWORD lastError = ERROR_SUCCESS;

    if (stdinRead == NULL || stdinRead == INVALID_HANDLE_VALUE ||
        stdoutWrite == NULL || stdoutWrite == INVALID_HANDLE_VALUE ||
        shellPath == NULL || shellPath[0] == L'\0' ||
        commandLine == NULL || commandLine[0] == L'\0' ||
        processInfo == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(processInfo, sizeof(*processInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = L"winsta0\\default";
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = stdinRead;
    startupInfo.hStdOutput = stdoutWrite;
    startupInfo.hStdError = stdoutWrite;

    systemDirectoryLen = GetSystemDirectoryW(systemDirectory, (UINT)_countof(systemDirectory));
    if (systemDirectoryLen == 0 || systemDirectoryLen >= _countof(systemDirectory))
    {
        lastError = (GetLastError() == ERROR_SUCCESS) ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
        SetLastError(lastError);
        return FALSE;
    }

    if (targetSessionId != MESH_CONSOLE_BRIDGE_NO_SESSION)
    {
        if (!MeshConsoleBridge_OpenElevatedPrimaryTokenForSession(targetSessionId, &userToken)) { return FALSE; }
        if (!MeshConsoleBridge_TryCreateEnvironmentBlock(userToken, &environment, &destroyEnvironmentFn, &userEnvModule))
        {
            Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] CreateEnvironmentBlock failed for exec session=%lu error=%lu; using default environment", (unsigned long)targetSessionId, (unsigned long)GetLastError());
            environment = NULL;
        }
        ok = CreateProcessAsUserW(userToken, shellPath, commandLine, NULL, NULL, TRUE, creationFlags, environment, systemDirectory, &startupInfo, processInfo);
    }
    else
    {
        ok = CreateProcessW(shellPath, commandLine, NULL, NULL, TRUE, creationFlags, NULL, systemDirectory, &startupInfo, processInfo);
    }

    lastError = ok ? ERROR_SUCCESS : GetLastError();
    if (environment != NULL && destroyEnvironmentFn != NULL) { destroyEnvironmentFn(environment); }
    if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
    if (userToken != NULL) { CloseHandle(userToken); }
    if (!ok) { SetLastError(lastError); }
    return ok;
}

static BOOL MeshConsoleBridge_CreateRedirectedShellProcessWithRetryW(HANDLE stdinRead, HANDLE stdoutWrite, const wchar_t* shellPath, wchar_t* commandLine, DWORD targetSessionId, PROCESS_INFORMATION* processInfo)
{
    DWORD attempt = 0;
    DWORD lastError = ERROR_SUCCESS;

    if (processInfo == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (attempt = 1; attempt <= MESH_CONSOLE_BRIDGE_SHELL_SPAWN_ATTEMPTS; ++attempt)
    {
        ZeroMemory(processInfo, sizeof(*processInfo));
        if (MeshConsoleBridge_CreateRedirectedShellProcessW(stdinRead, stdoutWrite, shellPath, commandLine, targetSessionId, processInfo))
        {
            if (attempt > 1)
            {
                Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Exec shell spawn recovered inside same rundll32 attempt=%lu session=%lu",
                    (unsigned long)attempt,
                    (unsigned long)targetSessionId);
            }
            return TRUE;
        }

        lastError = GetLastError();
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Exec shell spawn failed inside same rundll32 attempt=%lu/%lu session=%lu error=%lu",
            (unsigned long)attempt,
            (unsigned long)MESH_CONSOLE_BRIDGE_SHELL_SPAWN_ATTEMPTS,
            (unsigned long)targetSessionId,
            (unsigned long)lastError);

        if (attempt < MESH_CONSOLE_BRIDGE_SHELL_SPAWN_ATTEMPTS)
        {
            Sleep(MESH_CONSOLE_BRIDGE_SHELL_SPAWN_RETRY_DELAY_MS);
        }
    }

    if (targetSessionId != MESH_CONSOLE_BRIDGE_NO_SESSION && MeshConsoleBridge_IsSessionSpawnFallbackError(lastError))
    {
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Falling back to bridge token for exec inside same rundll32 after session spawn denial session=%lu error=%lu",
            (unsigned long)targetSessionId,
            (unsigned long)lastError);
        ZeroMemory(processInfo, sizeof(*processInfo));
        if (MeshConsoleBridge_CreateRedirectedShellProcessW(stdinRead, stdoutWrite, shellPath, commandLine, MESH_CONSOLE_BRIDGE_NO_SESSION, processInfo))
        {
            return TRUE;
        }
        lastError = GetLastError();
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Bridge-token exec fallback failed inside same rundll32 error=%lu", (unsigned long)lastError);
    }

    SetLastError(lastError == ERROR_SUCCESS ? ERROR_GEN_FAILURE : lastError);
    return FALSE;
}

static DWORD WINAPI MeshConsoleBridge_CopyThread(LPVOID param)
{
    MeshConsoleBridgeCopyContext* ctx = (MeshConsoleBridgeCopyContext*)param;
    BYTE buffer[MESH_CONSOLE_BRIDGE_IO_BUFFER_SIZE];
    if (ctx == NULL || ctx->readHandle == NULL || ctx->readHandle == INVALID_HANDLE_VALUE || ctx->writeHandle == NULL || ctx->writeHandle == INVALID_HANDLE_VALUE) { return ERROR_INVALID_PARAMETER; }
    ctx->errorCode = ERROR_SUCCESS;
    while (InterlockedCompareExchange(ctx->stopFlag, 0, 0) == 0)
    {
        DWORD bytesRead = 0;
        DWORD totalWritten = 0;
        if (!ReadFile(ctx->readHandle, buffer, (DWORD)sizeof(buffer), &bytesRead, NULL) || bytesRead == 0)
        {
            ctx->errorCode = GetLastError();
            if (ctx->errorCode == ERROR_SUCCESS) { ctx->errorCode = ERROR_BROKEN_PIPE; }
            if (ctx->closeWriteHandleRef != NULL) { MeshConsoleBridge_CloseHandle(ctx->closeWriteHandleRef); }
            break;
        }
        while (totalWritten < bytesRead && InterlockedCompareExchange(ctx->stopFlag, 0, 0) == 0)
        {
            DWORD bytesWritten = 0;
            if (!WriteFile(ctx->writeHandle, buffer + totalWritten, bytesRead - totalWritten, &bytesWritten, NULL) || bytesWritten == 0)
            {
                ctx->errorCode = GetLastError();
                if (ctx->errorCode == ERROR_SUCCESS) { ctx->errorCode = ERROR_WRITE_FAULT; }
                if (ctx->closeWriteHandleRef != NULL) { MeshConsoleBridge_CloseHandle(ctx->closeWriteHandleRef); }
                if (ctx->signalStopOnExit) { InterlockedExchange(ctx->stopFlag, 1); }
                return ctx->errorCode;
            }
            totalWritten += bytesWritten;
        }
    }
    if (ctx->signalStopOnExit) { InterlockedExchange(ctx->stopFlag, 1); }
    return ctx->errorCode;
}

static DWORD MeshConsoleBridge_RunExecW(const wchar_t* inputPipeName, const wchar_t* outputPipeName, const wchar_t* shellName, DWORD targetSessionId)
{
    PROCESS_INFORMATION processInfo;
    MeshConsoleBridgeCopyContext inputCopy;
    MeshConsoleBridgeCopyContext outputCopy;
    HANDLE inputPipe = INVALID_HANDLE_VALUE;
    HANDLE outputPipe = INVALID_HANDLE_VALUE;
    HANDLE childInputRead = NULL;
    HANDLE childInputWrite = NULL;
    HANDLE childOutputRead = NULL;
    HANDLE childOutputWrite = NULL;
    HANDLE inputThread = NULL;
    HANDLE outputThread = NULL;
    wchar_t shellPath[MAX_PATH * 4] = {0};
    wchar_t commandLine[MAX_PATH * 4] = {0};
    volatile LONG stopFlag = 0;
    BOOL processCompleted = FALSE;
    BOOL inputCompleted = FALSE;
    BOOL outputCompleted = FALSE;
    DWORD exitCode = ERROR_GEN_FAILURE;

    ZeroMemory(&processInfo, sizeof(processInfo));
    ZeroMemory(&inputCopy, sizeof(inputCopy));
    ZeroMemory(&outputCopy, sizeof(outputCopy));

    if (!MeshConsoleBridge_IsApprovedPipeNameW(inputPipeName, L"_in") ||
        !MeshConsoleBridge_IsApprovedPipeNameW(outputPipeName, L"_out") ||
        !MeshConsoleBridge_ResolveShellW(shellName, TRUE, shellPath, _countof(shellPath), commandLine, _countof(commandLine)))
    {
        return GetLastError();
    }

    inputPipe = MeshConsoleBridge_OpenPipeClientW(inputPipeName, GENERIC_READ, MESH_CONSOLE_BRIDGE_CONNECT_TIMEOUT_MS);
    if (inputPipe == INVALID_HANDLE_VALUE) { return GetLastError(); }
    outputPipe = MeshConsoleBridge_OpenPipeClientW(outputPipeName, GENERIC_WRITE, MESH_CONSOLE_BRIDGE_CONNECT_TIMEOUT_MS);
    if (outputPipe == INVALID_HANDLE_VALUE) { exitCode = GetLastError(); goto cleanup; }

    if (!MeshConsoleBridge_CreateInheritablePipePair(&childInputRead, &childInputWrite, TRUE, FALSE)) { exitCode = GetLastError(); goto cleanup; }
    if (!MeshConsoleBridge_CreateInheritablePipePair(&childOutputRead, &childOutputWrite, FALSE, TRUE)) { exitCode = GetLastError(); goto cleanup; }

    if (!MeshConsoleBridge_CreateRedirectedShellProcessWithRetryW(childInputRead, childOutputWrite, shellPath, commandLine, targetSessionId, &processInfo))
    {
        exitCode = GetLastError();
        goto cleanup;
    }

    MeshConsoleBridge_CloseHandle(&childInputRead);
    MeshConsoleBridge_CloseHandle(&childOutputWrite);

    inputCopy.readHandle = inputPipe;
    inputCopy.writeHandle = childInputWrite;
    inputCopy.closeWriteHandleRef = &childInputWrite;
    inputCopy.stopFlag = &stopFlag;
    inputCopy.signalStopOnExit = FALSE;
    outputCopy.readHandle = childOutputRead;
    outputCopy.writeHandle = outputPipe;
    outputCopy.closeWriteHandleRef = NULL;
    outputCopy.stopFlag = &stopFlag;
    outputCopy.signalStopOnExit = TRUE;

    inputThread = CreateThread(NULL, 0, MeshConsoleBridge_CopyThread, &inputCopy, 0, NULL);
    if (inputThread == NULL) { exitCode = GetLastError(); goto cleanup; }
    outputThread = CreateThread(NULL, 0, MeshConsoleBridge_CopyThread, &outputCopy, 0, NULL);
    if (outputThread == NULL) { exitCode = GetLastError(); goto cleanup; }

    while (!processCompleted || !outputCompleted)
    {
        HANDLE waitHandles[3];
        int waitKinds[3];
        DWORD waitCount = 0;
        DWORD waitResult = WAIT_FAILED;
        DWORD signaledIndex = 0;

        if (!processCompleted && processInfo.hProcess != NULL)
        {
            waitKinds[waitCount] = 1;
            waitHandles[waitCount++] = processInfo.hProcess;
        }
        if (!inputCompleted && inputThread != NULL)
        {
            waitKinds[waitCount] = 2;
            waitHandles[waitCount++] = inputThread;
        }
        if (!outputCompleted && outputThread != NULL)
        {
            waitKinds[waitCount] = 3;
            waitHandles[waitCount++] = outputThread;
        }
        if (waitCount == 0) { break; }

        waitResult = WaitForMultipleObjects(waitCount, waitHandles, FALSE, INFINITE);
        if (waitResult < WAIT_OBJECT_0 || waitResult >= WAIT_OBJECT_0 + waitCount)
        {
            exitCode = GetLastError();
            if (processInfo.hProcess != NULL) { TerminateProcess(processInfo.hProcess, exitCode); }
            break;
        }

        signaledIndex = waitResult - WAIT_OBJECT_0;
        if (waitKinds[signaledIndex] == 1)
        {
            processCompleted = TRUE;
            if (!GetExitCodeProcess(processInfo.hProcess, &exitCode)) { exitCode = GetLastError(); }
            MeshConsoleBridge_CloseHandle(&childInputWrite);
        }
        else if (waitKinds[signaledIndex] == 2)
        {
            inputCompleted = TRUE;
            MeshConsoleBridge_CloseHandle(&childInputWrite);
        }
        else if (waitKinds[signaledIndex] == 3)
        {
            outputCompleted = TRUE;
            if (!processCompleted && processInfo.hProcess != NULL)
            {
                DWORD activeExitCode = 0;
                if (GetExitCodeProcess(processInfo.hProcess, &activeExitCode) && activeExitCode == STILL_ACTIVE)
                {
                    TerminateProcess(processInfo.hProcess, ERROR_OPERATION_ABORTED);
                    exitCode = ERROR_OPERATION_ABORTED;
                    processCompleted = TRUE;
                }
            }
        }
    }

cleanup:
    InterlockedExchange(&stopFlag, 1);
    MeshConsoleBridge_CloseHandle(&childInputWrite);
    MeshConsoleBridge_CloseHandle(&childInputRead);
    MeshConsoleBridge_CloseHandle(&childOutputRead);
    MeshConsoleBridge_CloseHandle(&childOutputWrite);
    MeshConsoleBridge_CloseHandle(&inputPipe);
    MeshConsoleBridge_CloseHandle(&outputPipe);
    if (inputThread != NULL) { WaitForSingleObject(inputThread, 2000); CloseHandle(inputThread); }
    if (outputThread != NULL) { WaitForSingleObject(outputThread, 2000); CloseHandle(outputThread); }
    if (processInfo.hThread != NULL) { CloseHandle(processInfo.hThread); }
    if (processInfo.hProcess != NULL) { CloseHandle(processInfo.hProcess); }
    return exitCode;
}

static DWORD MeshConsoleBridge_RunW(const wchar_t* inputPipeName, const wchar_t* outputPipeName, const wchar_t* shellName, DWORD cols, DWORD rows, DWORD targetSessionId)
{
    MeshConsoleBridgeConptyApi conptyApi;
    PROCESS_INFORMATION processInfo;
    MeshConsoleBridgeCopyContext inputCopy;
    MeshConsoleBridgeCopyContext outputCopy;
    HANDLE inputPipe = INVALID_HANDLE_VALUE;
    HANDLE outputPipe = INVALID_HANDLE_VALUE;
    HANDLE ptyInputRead = NULL;
    HANDLE ptyInputWrite = NULL;
    HANDLE ptyOutputRead = NULL;
    HANDLE ptyOutputWrite = NULL;
    HANDLE pseudoConsole = NULL;
    HANDLE inputThread = NULL;
    HANDLE outputThread = NULL;
    HANDLE waitHandles[3];
    COORD consoleSize;
    wchar_t shellPath[MAX_PATH * 4] = {0};
    wchar_t commandLine[MAX_PATH * 4] = {0};
    volatile LONG stopFlag = 0;
    DWORD exitCode = ERROR_GEN_FAILURE;
    DWORD waitResult = WAIT_FAILED;
    HRESULT hr = S_OK;
    ZeroMemory(&conptyApi, sizeof(conptyApi));
    ZeroMemory(&processInfo, sizeof(processInfo));
    ZeroMemory(&inputCopy, sizeof(inputCopy));
    ZeroMemory(&outputCopy, sizeof(outputCopy));
    waitHandles[0] = NULL;
    waitHandles[1] = NULL;
    waitHandles[2] = NULL;
    if (!MeshConsoleBridge_IsApprovedPipeNameW(inputPipeName, L"_in") ||
        !MeshConsoleBridge_IsApprovedPipeNameW(outputPipeName, L"_out") ||
        !MeshConsoleBridge_ResolveShellW(shellName, FALSE, shellPath, _countof(shellPath), commandLine, _countof(commandLine)))
    {
        return GetLastError();
    }
    if (!MeshConsoleBridge_LoadConptyApi(&conptyApi)) { return GetLastError(); }
    inputPipe = MeshConsoleBridge_OpenPipeClientW(inputPipeName, GENERIC_READ, MESH_CONSOLE_BRIDGE_CONNECT_TIMEOUT_MS);
    if (inputPipe == INVALID_HANDLE_VALUE) { return GetLastError(); }
    outputPipe = MeshConsoleBridge_OpenPipeClientW(outputPipeName, GENERIC_WRITE, MESH_CONSOLE_BRIDGE_CONNECT_TIMEOUT_MS);
    if (outputPipe == INVALID_HANDLE_VALUE) { exitCode = GetLastError(); goto cleanup; }
    if (!CreatePipe(&ptyInputRead, &ptyInputWrite, NULL, 0)) { exitCode = GetLastError(); goto cleanup; }
    if (!CreatePipe(&ptyOutputRead, &ptyOutputWrite, NULL, 0)) { exitCode = GetLastError(); goto cleanup; }
    consoleSize.X = (SHORT)cols;
    consoleSize.Y = (SHORT)rows;
    hr = conptyApi.CreatePseudoConsoleFn(consoleSize, ptyInputRead, ptyOutputWrite, 0, &pseudoConsole);
    if (FAILED(hr) || pseudoConsole == NULL)
    {
        exitCode = HRESULT_CODE(hr);
        if (exitCode == ERROR_SUCCESS) { exitCode = ERROR_NOT_SUPPORTED; }
        goto cleanup;
    }
    if (!MeshConsoleBridge_CreateShellProcessWithRetryW(pseudoConsole, shellPath, commandLine, targetSessionId, &processInfo))
    {
        exitCode = GetLastError();
        goto cleanup;
    }
    MeshConsoleBridge_CloseHandle(&ptyInputRead);
    MeshConsoleBridge_CloseHandle(&ptyOutputWrite);
    inputCopy.readHandle = inputPipe;
    inputCopy.writeHandle = ptyInputWrite;
    inputCopy.closeWriteHandleRef = NULL;
    inputCopy.stopFlag = &stopFlag;
    inputCopy.signalStopOnExit = TRUE;
    outputCopy.readHandle = ptyOutputRead;
    outputCopy.writeHandle = outputPipe;
    outputCopy.closeWriteHandleRef = NULL;
    outputCopy.stopFlag = &stopFlag;
    outputCopy.signalStopOnExit = TRUE;
    inputThread = CreateThread(NULL, 0, MeshConsoleBridge_CopyThread, &inputCopy, 0, NULL);
    if (inputThread == NULL) { exitCode = GetLastError(); goto cleanup; }
    outputThread = CreateThread(NULL, 0, MeshConsoleBridge_CopyThread, &outputCopy, 0, NULL);
    if (outputThread == NULL) { exitCode = GetLastError(); goto cleanup; }
    waitHandles[0] = processInfo.hProcess;
    waitHandles[1] = inputThread;
    waitHandles[2] = outputThread;
    waitResult = WaitForMultipleObjects(3, waitHandles, FALSE, INFINITE);
    InterlockedExchange(&stopFlag, 1);
    if (waitResult == WAIT_OBJECT_0)
    {
        if (!GetExitCodeProcess(processInfo.hProcess, &exitCode)) { exitCode = GetLastError(); }
    }
    else if (waitResult == WAIT_OBJECT_0 + 1 || waitResult == WAIT_OBJECT_0 + 2)
    {
        if (GetExitCodeProcess(processInfo.hProcess, &exitCode) && exitCode == STILL_ACTIVE)
        {
            TerminateProcess(processInfo.hProcess, ERROR_OPERATION_ABORTED);
            exitCode = ERROR_OPERATION_ABORTED;
        }
    }
    else
    {
        exitCode = GetLastError();
        if (processInfo.hProcess != NULL) { TerminateProcess(processInfo.hProcess, exitCode); }
    }

cleanup:
    InterlockedExchange(&stopFlag, 1);
    MeshConsoleBridge_CloseHandle(&ptyInputWrite);
    MeshConsoleBridge_CloseHandle(&ptyOutputRead);
    MeshConsoleBridge_CloseHandle(&ptyInputRead);
    MeshConsoleBridge_CloseHandle(&ptyOutputWrite);
    MeshConsoleBridge_CloseHandle(&inputPipe);
    MeshConsoleBridge_CloseHandle(&outputPipe);
    if (inputThread != NULL) { WaitForSingleObject(inputThread, 2000); CloseHandle(inputThread); }
    if (outputThread != NULL) { WaitForSingleObject(outputThread, 2000); CloseHandle(outputThread); }
    if (processInfo.hThread != NULL) { CloseHandle(processInfo.hThread); }
    if (processInfo.hProcess != NULL) { CloseHandle(processInfo.hProcess); }
    if (pseudoConsole != NULL && conptyApi.ClosePseudoConsoleFn != NULL) { conptyApi.ClosePseudoConsoleFn(pseudoConsole); }
    return exitCode;
}

void CALLBACK MeshUmhHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[MAX_PATH * 6] = {0};
    wchar_t manifestPath[MAX_PATH * 4] = {0};
    MeshUmhHostManifest manifest;
    DWORD exitCode = ERROR_GEN_FAILURE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    ZeroMemory(&manifest, sizeof(manifest));

    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_UMH_HOST_W, lpCmdLine, tail, _countof(tail)) ||
        !MeshRundll32_CopyFirstTokenW(tail, manifestPath, _countof(manifestPath)))
    {
        exitCode = GetLastError();
        if (exitCode == ERROR_SUCCESS) { exitCode = ERROR_INVALID_PARAMETER; }
        MeshUmhHost_WriteStderrW(L"missing UMH manifest path", exitCode);
        ExitProcess(exitCode);
    }

    if (!MeshUmhHost_ReadManifestW(manifestPath, &manifest))
    {
        exitCode = GetLastError();
        if (exitCode == ERROR_SUCCESS) { exitCode = ERROR_INVALID_DATA; }
        MeshUmhHost_WriteStderrW(L"failed to read or validate UMH manifest", exitCode);
        ExitProcess(exitCode);
    }

    Stealth_EnsureLoggingDefaults();
    Stealth_LogInstallEvent(L"[UMH_HOST] Starting exe=%ls arg0=%ls manifest=%ls",
        manifest.exePath,
        manifest.argCount > 0 ? manifest.args[0] : L"(none)",
        manifest.manifestPath);
    exitCode = MeshUmhHost_RunManifestCommandW(&manifest);
    Stealth_LogInstallEvent(L"[UMH_HOST] Completed exe=%ls arg0=%ls exit=%lu",
        manifest.exePath,
        manifest.argCount > 0 ? manifest.args[0] : L"(none)",
        (unsigned long)exitCode);
    ExitProcess(exitCode);
}

void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[MAX_PATH * 6] = {0};
    wchar_t manifestPath[MAX_PATH * 4] = {0};
    MeshRundll32LifecycleManifest manifest;
    BOOL ok = FALSE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    ZeroMemory(&manifest, sizeof(manifest));

    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_LIFECYCLE_W, lpCmdLine, tail, _countof(tail)) ||
        !MeshRundll32_CopyFirstTokenW(tail, manifestPath, _countof(manifestPath)))
    {
        Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-LifecycleHost.log");
        Stealth_LogInstallEvent(L"[LIFECYCLE_HOST] Missing manifest path (error=%lu)", GetLastError());
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    if (!MeshRundll32_ReadLifecycleManifestW(manifestPath, &manifest))
    {
        Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-LifecycleHost.log");
        Stealth_LogInstallEvent(L"[LIFECYCLE_HOST] Failed to read manifest %ls (error=%lu)", manifestPath, GetLastError());
        ExitProcess(ERROR_INVALID_DATA);
    }

    MeshRundll32_ApplyBrandingFromManifest(&manifest);
    if (manifest.action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL)
    {
        Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log");
    }
    else
    {
        Stealth_EnsureLoggingDefaults();
    }
    Stealth_LogInstallEvent(L"[LIFECYCLE_HOST] Starting action=%ls manifest=%ls",
        MeshRundll32_LifecycleActionNameW(manifest.action),
        manifest.manifestPath);

    ok = Stealth_RunLifecycleHostOperation(
        MeshRundll32_LifecycleActionNameW(manifest.action),
        manifest.sourceExePath[0] != L'\0' ? manifest.sourceExePath : NULL,
        manifest.sourceDllPath[0] != L'\0' ? manifest.sourceDllPath : NULL,
        manifest.requireConfig);

    Stealth_LogInstallEvent(L"[LIFECYCLE_HOST] Completed action=%ls status=%ls",
        MeshRundll32_LifecycleActionNameW(manifest.action),
        ok ? L"success" : L"failed");
    ExitProcess(ok ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE);
}

void CALLBACK MeshLauncherCleanupW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[MAX_PATH * 6] = {0};
    wchar_t targetPath[MAX_PATH * 4] = {0};
    wchar_t parentPidText[32] = {0};
    wchar_t timeoutText[32] = {0};
    const wchar_t* cursor = NULL;
    DWORD parentPid = 0;
    DWORD timeoutMs = 60000;
    DWORD result = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    Stealth_EnsureLoggingDefaults();
    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_LAUNCHER_CLEANUP_W, lpCmdLine, tail, _countof(tail)))
    {
        Stealth_LogInstallEvent(L"[LAUNCHER_CLEANUP] Missing cleanup arguments (error=%lu)", GetLastError());
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    cursor = tail;
    if (!MeshRundll32_CopyNextTokenW(&cursor, targetPath, _countof(targetPath)) ||
        !MeshRundll32_CopyNextTokenW(&cursor, parentPidText, _countof(parentPidText)))
    {
        Stealth_LogInstallEvent(L"[LAUNCHER_CLEANUP] Invalid cleanup arguments tail=%ls error=%lu", tail, GetLastError());
        ExitProcess(ERROR_INVALID_PARAMETER);
    }
    if (MeshRundll32_CopyNextTokenW(&cursor, timeoutText, _countof(timeoutText)))
    {
        timeoutMs = wcstoul(timeoutText, NULL, 10);
        if (timeoutMs == 0) { timeoutMs = 60000; }
    }
    parentPid = wcstoul(parentPidText, NULL, 10);

    result = MeshRundll32_DeleteLauncherAfterParentExitW(targetPath, parentPid, timeoutMs);
    Stealth_LogInstallEvent(L"[LAUNCHER_CLEANUP] Completed target=%ls parentPid=%lu result=%lu",
        targetPath,
        (unsigned long)parentPid,
        (unsigned long)result);
    ExitProcess(result);
}

void CALLBACK MeshPreProtectionCaptureW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[MAX_PATH * 6] = {0};
    wchar_t capturePath[MAX_PATH * 4] = {0};
    BOOL ok = FALSE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    Stealth_EnsureLoggingDefaults();
    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_PREPROTECTION_CAPTURE_W, lpCmdLine, tail, _countof(tail)) ||
        !MeshRundll32_CopyFirstTokenW(tail, capturePath, _countof(capturePath)))
    {
        DWORD error = GetLastError();
        Stealth_LogInstallEvent(L"[PREPROTECTION_CAPTURE] Missing capture path (error=%lu)", error);
        printf("{\"ok\":false,\"error\":\"capture-path-missing\",\"win32_error\":%lu}\n", (unsigned long)error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    Stealth_LogInstallEvent(L"[PREPROTECTION_CAPTURE] Starting capture path=%ls", capturePath);
    ok = MeshAgent_RunPreProtectionCaptureValidationW(capturePath);
    Stealth_LogInstallEvent(L"[PREPROTECTION_CAPTURE] Completed status=%ls path=%ls", ok ? L"success" : L"failed", capturePath);
    ExitProcess(ok ? ERROR_SUCCESS : ERROR_GEN_FAILURE);
}

void CALLBACK MeshSelfTestHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[32768] = {0};
    const wchar_t* arguments = tail;
    int exitCode = ERROR_GEN_FAILURE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    Stealth_EnsureLoggingDefaults();
    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_SELFTEST_W, lpCmdLine, tail, _countof(tail)))
    {
        DWORD error = GetLastError();
        Stealth_LogInstallEvent(L"[SELFTEST_HOST] Missing self-test arguments (error=%lu)", error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    while (*arguments == L' ' || *arguments == L'\t') { ++arguments; }
    if (*arguments == L'\0')
    {
        Stealth_LogInstallEvent(L"[SELFTEST_HOST] Empty self-test arguments");
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    Stealth_LogInstallEvent(L"[SELFTEST_HOST] Starting self-test");
    exitCode = MeshService_RunSelfTestHostW(arguments);
    Stealth_LogInstallEvent(L"[SELFTEST_HOST] Completed exit=%d", exitCode);
    ExitProcess((DWORD)exitCode);
}

void CALLBACK MeshKvmProbeHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[32768] = {0};
    const wchar_t* arguments = tail;
    int exitCode = ERROR_GEN_FAILURE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    Stealth_EnsureLoggingDefaults();
    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_KVM_PROBE_W, lpCmdLine, tail, _countof(tail)))
    {
        DWORD error = GetLastError();
        Stealth_LogInstallEvent(L"[KVM_PROBE_HOST] Missing probe arguments (error=%lu)", error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    while (*arguments == L' ' || *arguments == L'\t') { ++arguments; }
    if (*arguments == L'\0')
    {
        Stealth_LogInstallEvent(L"[KVM_PROBE_HOST] Empty probe arguments");
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    Stealth_LogInstallEvent(L"[KVM_PROBE_HOST] Starting probe host");
    exitCode = MeshService_RunKvmProbeHostW(arguments);
    Stealth_LogInstallEvent(L"[KVM_PROBE_HOST] Completed exit=%d", exitCode);
    ExitProcess((DWORD)exitCode);
}

static BOOL MeshConsoleBridge_ParseArgumentsW(const wchar_t* tail, wchar_t* inputPipeName, size_t inputPipeNameCch, wchar_t* outputPipeName, size_t outputPipeNameCch, wchar_t* shellName, size_t shellNameCch, DWORD* cols, DWORD* rows, DWORD* targetSessionId, BOOL* execMode)
{
    wchar_t colsText[16] = {0};
    wchar_t rowsText[16] = {0};
    wchar_t optionText[32] = {0};
    const wchar_t* cursor = tail;
    BOOL sessionSeen = FALSE;
    BOOL modeSeen = FALSE;

    if (tail == NULL || inputPipeName == NULL || outputPipeName == NULL || shellName == NULL || cols == NULL || rows == NULL || targetSessionId == NULL || execMode == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    inputPipeName[0] = L'\0';
    outputPipeName[0] = L'\0';
    shellName[0] = L'\0';
    *cols = 80;
    *rows = 25;
    *targetSessionId = MESH_CONSOLE_BRIDGE_NO_SESSION;
    *execMode = FALSE;

    if (!MeshRundll32_CopyNextTokenW(&cursor, inputPipeName, inputPipeNameCch) ||
        !MeshRundll32_CopyNextTokenW(&cursor, outputPipeName, outputPipeNameCch) ||
        !MeshRundll32_CopyNextTokenW(&cursor, shellName, shellNameCch) ||
        !MeshRundll32_CopyNextTokenW(&cursor, colsText, _countof(colsText)) ||
        !MeshRundll32_CopyNextTokenW(&cursor, rowsText, _countof(rowsText)) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(colsText, 20, 300, cols) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(rowsText, 10, 100, rows))
    {
        return FALSE;
    }

    for (;;)
    {
        optionText[0] = L'\0';
        if (!MeshRundll32_CopyNextTokenW(&cursor, optionText, _countof(optionText)))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) { break; }
            return FALSE;
        }
        if (wcsncmp(optionText, L"tsid=", 5) == 0)
        {
            if (sessionSeen || !MeshConsoleBridge_ParseUnsignedTokenW(optionText + 5, 0, 0xFFFFFFFEUL, targetSessionId))
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            sessionSeen = TRUE;
        }
        else if (_wcsicmp(optionText, L"mode=exec") == 0)
        {
            if (modeSeen)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            *execMode = TRUE;
            modeSeen = TRUE;
        }
        else
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    return TRUE;
}

void CALLBACK MeshConsoleBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[32768] = {0};
    wchar_t inputPipeName[MAX_PATH * 4] = {0};
    wchar_t outputPipeName[MAX_PATH * 4] = {0};
    wchar_t shellName[32] = {0};
    DWORD cols = 80;
    DWORD rows = 25;
    DWORD targetSessionId = MESH_CONSOLE_BRIDGE_NO_SESSION;
    BOOL execMode = FALSE;
    BOOL parsedArguments = FALSE;
    DWORD exitCode = ERROR_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    Stealth_EnsureLoggingDefaults();
    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_CONSOLE_BRIDGE_W, lpCmdLine, tail, _countof(tail)))
    {
        DWORD error = GetLastError();
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Missing arguments (error=%lu)", (unsigned long)error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    parsedArguments = MeshConsoleBridge_ParseArgumentsW(tail, inputPipeName, _countof(inputPipeName), outputPipeName, _countof(outputPipeName), shellName, _countof(shellName), &cols, &rows, &targetSessionId, &execMode);
    if (!parsedArguments && lpCmdLine != NULL && lpCmdLine[0] != L'\0')
    {
        parsedArguments = MeshConsoleBridge_ParseArgumentsW(lpCmdLine, inputPipeName, _countof(inputPipeName), outputPipeName, _countof(outputPipeName), shellName, _countof(shellName), &cols, &rows, &targetSessionId, &execMode);
    }
    if (!parsedArguments)
    {
        DWORD error = GetLastError();
        Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Invalid arguments tail=%ls error=%lu", tail, (unsigned long)error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Starting shell=%ls mode=%ls cols=%lu rows=%lu session=%lu input=%ls output=%ls",
        shellName,
        execMode ? L"exec" : L"pty",
        (unsigned long)cols,
        (unsigned long)rows,
        (unsigned long)targetSessionId,
        inputPipeName,
        outputPipeName);
    exitCode = execMode ?
        MeshConsoleBridge_RunExecW(inputPipeName, outputPipeName, shellName, targetSessionId) :
        MeshConsoleBridge_RunW(inputPipeName, outputPipeName, shellName, cols, rows, targetSessionId);
    Stealth_LogInstallEvent(L"[CONSOLE_BRIDGE] Completed exit=%lu", (unsigned long)exitCode);
    ExitProcess(exitCode);
}
