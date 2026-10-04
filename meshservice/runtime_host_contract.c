#include "runtime_host_contract.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <shlobj.h>
#include <sddl.h>
#include <strsafe.h>
#include <WtsApi32.h>
#include "runtime_core.h"
#include "service_bundle.h"
#define MESH_PROCESS_TOKEN_LOG(message) ServiceDeploy_LogInstallEvent(L"%ls", message)
#include "process_token_contract.h"

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
// How long exec mode keeps draining output after the shell itself has exited.
#define MESH_CONSOLE_BRIDGE_EXEC_OUTPUT_DRAIN_MS 5000UL

typedef HRESULT (WINAPI* MeshConsoleBridge_CreatePseudoConsoleFn)(COORD, HANDLE, HANDLE, DWORD, HANDLE*);
typedef void (WINAPI* MeshConsoleBridge_ClosePseudoConsoleFn)(HANDLE);
typedef BOOL (WINAPI* MeshConsoleBridge_CreateEnvironmentBlockFn)(LPVOID*, HANDLE, BOOL);
typedef BOOL (WINAPI* MeshConsoleBridge_DestroyEnvironmentBlockFn)(LPVOID);
static BOOL MeshConsoleBridge_TryCreateEnvironmentBlock(HANDLE userToken, LPVOID* environment, MeshConsoleBridge_DestroyEnvironmentBlockFn* destroyFnOut, HMODULE* moduleOut);

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

static volatile LONG MeshConsoleBridge_PtyPipeCounter = 0;
// Lifecycle artifact names embed the launching PID; the counter keeps two launches
// from one process within the same tick from sharing a name.
static volatile LONG MeshRuntimeHost_ArtifactCounter = 0;
#define MESH_RUNTIME_HOST_STALE_ARTIFACT_AGE_MS (10ULL * 60ULL * 1000ULL)
// Protected DACL for the per-launch temp staging directory: SYSTEM and
// Administrators only, and OWNER RIGHTS limited to read so a same-user,
// non-elevated process cannot rewrite the DACL and swap the staged files.
#define MESH_RUNTIME_HOST_TEMP_STAGING_SDDL L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;OW)"

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

#define MESH_USER_CONSENT_SECTION_W L"Consent"
#define MESH_USER_CONSENT_KEY_SESSION_ID_W L"SessionId"
#define MESH_USER_CONSENT_KEY_TIMEOUT_MS_W L"TimeoutMs"
#define MESH_USER_CONSENT_KEY_TIMEOUT_AUTO_ACCEPT_W L"TimeoutAutoAccept"
#define MESH_USER_CONSENT_KEY_TITLE_HEX_W L"TitleHex"
#define MESH_USER_CONSENT_KEY_CAPTION_HEX_W L"CaptionHex"
#define MESH_USER_CONSENT_RESULT_PIPE_PREFIX_W L"\\\\.\\pipe\\MeshUserConsent_"
#define MESH_USER_CONSENT_RESULT_PIPE_SUFFIX_W L"_result"
#define MESH_USER_CONSENT_CONNECT_TIMEOUT_MS 15000UL
#define MESH_USER_CONSENT_MIN_TIMEOUT_MS 1000UL
#define MESH_USER_CONSENT_DEFAULT_TIMEOUT_MS 30000UL
#define MESH_USER_CONSENT_MAX_TIMEOUT_MS 600000UL
#define MESH_USER_CONSENT_MAX_TITLE_CCH 256
#define MESH_USER_CONSENT_MAX_CAPTION_CCH 4096

#ifndef IDTIMEOUT
#define IDTIMEOUT 32000
#endif

typedef struct MeshUmhHostManifest
{
    wchar_t manifestPath[MAX_PATH * 4];
    wchar_t exePath[MAX_PATH * 4];
    wchar_t args[MESH_UMH_MAX_ARGS][MESH_UMH_MAX_ARG_CCH];
    DWORD argCount;
    DWORD timeoutMs;
} MeshUmhHostManifest;

typedef struct MeshUserConsentManifest
{
    wchar_t manifestPath[MAX_PATH * 4];
    DWORD sessionId;
    DWORD timeoutMs;
    BOOL timeoutAutoAccept;
    wchar_t title[MESH_USER_CONSENT_MAX_TITLE_CCH];
    wchar_t caption[MESH_USER_CONSENT_MAX_CAPTION_CCH];
} MeshUserConsentManifest;

static BOOL MeshRuntimeHost_FileExistsW(const wchar_t* path)
{
    DWORD attrs = INVALID_FILE_ATTRIBUTES;
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) ? TRUE : FALSE;
}

static BOOL MeshRuntimeHost_DirectoryExistsW(const wchar_t* path)
{
    DWORD attrs = INVALID_FILE_ATTRIBUTES;
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) ? TRUE : FALSE;
}

static BOOL MeshRuntimeHost_CopyFirstTokenW(const wchar_t* input, wchar_t* output, size_t outputCch)
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

static BOOL MeshRuntimeHost_CopyNextTokenW(const wchar_t** cursorRef, wchar_t* output, size_t outputCch)
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

static BOOL MeshRuntimeHost_GetEntryTailW(const wchar_t* entryName, const wchar_t* lpCmdLine, wchar_t* tail, size_t tailCch)
{
    LPWSTR fullCmdLine = NULL;
    const wchar_t* entryPoint = NULL;
    size_t entryLen = 0;

    // The system DLL loader resolves "<entry>W" before "<entry>", so these W-suffixed exports are
    // called through the ANSI signature and lpCmdLine is really narrow text. Parse
    // the wide process command line instead.
    UNREFERENCED_PARAMETER(lpCmdLine);
    if (tail == NULL || tailCch == 0 || entryName == NULL || entryName[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    tail[0] = L'\0';
    entryLen = wcslen(entryName);

    fullCmdLine = GetCommandLineW();
    for (entryPoint = (fullCmdLine != NULL) ? wcsstr(fullCmdLine, entryName) : NULL;
         entryPoint != NULL;
         entryPoint = wcsstr(entryPoint + 1, entryName))
    {
        // The entry is the token right after the DLL path's comma; the same text
        // anywhere else (inside a path, or as a longer export name) is not it.
        const wchar_t* before = entryPoint;
        const wchar_t* after = entryPoint + entryLen;
        while (before > fullCmdLine && (before[-1] == L' ' || before[-1] == L'\t')) { --before; }
        if (before == fullCmdLine || before[-1] != L',') { continue; }
        if (*after != L'\0' && *after != L' ' && *after != L'\t' && *after != L'"' && *after != L',') { continue; }
        if (*after == L'"') { ++after; }
        while (*after == L' ' || *after == L'\t' || *after == L',') { ++after; }
        return SUCCEEDED(StringCchCopyW(tail, tailCch, after)) ? TRUE : FALSE;
    }

    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static BOOL MeshRuntimeHost_ManifestBoolW(const wchar_t* manifestPath, const wchar_t* keyName, BOOL defaultValue)
{
    wchar_t value[32] = {0};
    DWORD read = GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, keyName, defaultValue ? L"1" : L"0", value, (DWORD)_countof(value), manifestPath);
    if (read == 0) { return defaultValue; }
    if (_wcsicmp(value, L"1") == 0 || _wcsicmp(value, L"true") == 0 || _wcsicmp(value, L"yes") == 0 || _wcsicmp(value, L"on") == 0) { return TRUE; }
    if (_wcsicmp(value, L"0") == 0 || _wcsicmp(value, L"false") == 0 || _wcsicmp(value, L"no") == 0 || _wcsicmp(value, L"off") == 0) { return FALSE; }
    return defaultValue;
}

static BOOL MeshRuntimeHost_WriteManifestStringW(const wchar_t* manifestPath, const wchar_t* keyName, const wchar_t* value, size_t valueCch)
{
    if (value == NULL || value[0] == L'\0') { return TRUE; }
    // The reader rejects a value that fills its buffer, so refuse to write one.
    if (wcsnlen(value, valueCch) >= valueCch - 1) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
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

static BOOL MeshUmhHost_PathIsUnderDirectoryW(const wchar_t* path, const wchar_t* directory)
{
    size_t dirLen = 0;

    if (path == NULL || directory == NULL) { return FALSE; }
    dirLen = wcslen(directory);
    while (dirLen > 0 && (directory[dirLen - 1] == L'\\' || directory[dirLen - 1] == L'/')) { --dirLen; }
    if (dirLen == 0 || wcslen(path) <= dirLen + 1) { return FALSE; }
    return (_wcsnicmp(path, directory, dirLen) == 0 && path[dirLen] == L'\\') ? TRUE : FALSE;
}

// MasterService.exe is only launched from the directories umhctl manages: the
// ProgramData UserModeHook folder and the agent install root (the directory of
// this service DLL). A file of that name anywhere else is not approved.
static BOOL MeshUmhHost_IsManagedMasterServiceLocationW(const wchar_t* fullPath)
{
    PWSTR programData = NULL;
    wchar_t managedRoot[MAX_PATH * 4] = {0};
    HMODULE module = NULL;
    DWORD moduleLen = 0;
    wchar_t* slash = NULL;
    BOOL managed = FALSE;

    if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, NULL, &programData)) && programData != NULL &&
        SUCCEEDED(StringCchPrintfW(managedRoot, _countof(managedRoot), L"%ls\\UserModeHook", programData)) &&
        MeshUmhHost_PathIsUnderDirectoryW(fullPath, managedRoot))
    {
        managed = TRUE;
    }
    if (programData != NULL) { CoTaskMemFree(programData); }
    if (!managed &&
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&MeshUmhHost_IsManagedMasterServiceLocationW, &module) &&
        (moduleLen = GetModuleFileNameW(module, managedRoot, (DWORD)_countof(managedRoot))) > 0 &&
        moduleLen < (DWORD)_countof(managedRoot) &&
        (slash = wcsrchr(managedRoot, L'\\')) != NULL)
    {
        *slash = L'\0';
        managed = MeshUmhHost_PathIsUnderDirectoryW(fullPath, managedRoot);
    }
    return managed;
}

// On success the canonical path (no '.'/'..' segments, backslash separators) is
// written to approvedPath; that is the path that gets executed.
static BOOL MeshUmhHost_IsApprovedMasterServicePathW(const wchar_t* path, wchar_t* approvedPath, size_t approvedPathCch)
{
    const wchar_t* baseName = MeshUmhHost_BaseNameW(path);
    wchar_t fullPath[MAX_PATH * 4] = {0};
    DWORD fullLen = 0;

    if (!MeshUmhHost_IsAbsolutePathW(path)) { SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY); return FALSE; }
    if (baseName == NULL || _wcsicmp(baseName, L"MasterService.exe") != 0) { SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY); return FALSE; }
    // UNC and device paths are never a managed location.
    if (path[0] == L'\\' || path[0] == L'/') { SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY); return FALSE; }
    fullLen = GetFullPathNameW(path, (DWORD)_countof(fullPath), fullPath, NULL);
    if (fullLen == 0 || fullLen >= (DWORD)_countof(fullPath)) { SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY); return FALSE; }
    baseName = MeshUmhHost_BaseNameW(fullPath);
    if (baseName == NULL || _wcsicmp(baseName, L"MasterService.exe") != 0 || !MeshUmhHost_IsManagedMasterServiceLocationW(fullPath))
    {
        SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return FALSE;
    }
    if (!MeshRuntimeHost_FileExistsW(fullPath)) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    if (approvedPath == NULL || FAILED(StringCchCopyW(approvedPath, approvedPathCch, fullPath)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

static BOOL MeshUmhHost_ArgEquals(const MeshUmhHostManifest* manifest, DWORD index, const wchar_t* expected)
{
    if (manifest == NULL || expected == NULL || index >= manifest->argCount || index >= MESH_UMH_MAX_ARGS) { return FALSE; }
    // umhctl writes these exact tokens; the approved shapes are case-sensitive.
    return (wcscmp(manifest->args[index], expected) == 0) ? TRUE : FALSE;
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
    if (!MeshRuntimeHost_FileExistsW(manifestPath))
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
    if (read >= (DWORD)_countof(manifestOut->exePath) - 1) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    {
        wchar_t approvedExePath[MAX_PATH * 4] = {0};
        if (read == 0 || !MeshUmhHost_IsApprovedMasterServicePathW(manifestOut->exePath, approvedExePath, _countof(approvedExePath))) { return FALSE; }
        if (FAILED(StringCchCopyW(manifestOut->exePath, _countof(manifestOut->exePath), approvedExePath)))
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }

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
        if (read == 0 || read >= (DWORD)_countof(manifestOut->args[i]) - 1 || !MeshUmhHost_ValueIsSafeW(manifestOut->args[i]))
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
    HANDLE launchToken = NULL;
    LPVOID environment = NULL;
    HMODULE userEnvModule = NULL;
    MeshConsoleBridge_DestroyEnvironmentBlockFn destroyEnvironmentFn = NULL;

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

    // The job ties MasterService.exe to this host: when umhctl kills the host on
    // its own timeout, the child must not survive holding the agent's pipes.
    job = CreateJobObjectW(NULL, NULL);
    if (job == NULL)
    {
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"job object unavailable", exitCode);
        return exitCode;
    }
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo)))
    {
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"job object configuration failed", exitCode);
        CloseHandle(job);
        return exitCode;
    }

    if (!MeshProcessToken_Open(MeshProcessToken_Privileged, MESH_PROCESS_TOKEN_CURRENT_SESSION, &launchToken) ||
        !MeshConsoleBridge_TryCreateEnvironmentBlock(launchToken, &environment, &destroyEnvironmentFn, &userEnvModule))
    {
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"privileged launch context unavailable", exitCode);
        if (launchToken != NULL) { CloseHandle(launchToken); }
        if (job != NULL) { CloseHandle(job); }
        return exitCode;
    }
    if (!CreateProcessAsUserW(
        launchToken,
        manifest->exePath,
        commandLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
        environment,
        workingDirectory,
        &startupInfo,
        &processInfo))
    {
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"CreateProcessAsUserW failed for MasterService.exe", exitCode);
        if (environment != NULL && destroyEnvironmentFn != NULL) { destroyEnvironmentFn(environment); }
        if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
        CloseHandle(launchToken);
        if (job != NULL) { CloseHandle(job); }
        return exitCode;
    }
    if (environment != NULL && destroyEnvironmentFn != NULL) { destroyEnvironmentFn(environment); }
    if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }

    if (!AssignProcessToJobObject(job, processInfo.hProcess))
    {
        // Still suspended: nothing has run yet, so discard it.
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"job assignment failed for MasterService.exe", exitCode);
        TerminateProcess(processInfo.hProcess, exitCode);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        CloseHandle(launchToken);
        CloseHandle(job);
        return exitCode;
    }

    if (!MeshProcessToken_VerifyChildAndResume(MeshProcessToken_Privileged, launchToken, &processInfo))
    {
        exitCode = GetLastError();
        MeshUmhHost_WriteStderrW(L"MasterService token verification failed", exitCode);
        CloseHandle(launchToken);
        if (job != NULL) { CloseHandle(job); }
        return exitCode;
    }
    CloseHandle(launchToken);

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

static int MeshUserConsent_HexNibbleW(wchar_t value)
{
    if (value >= L'0' && value <= L'9') { return (int)(value - L'0'); }
    if (value >= L'a' && value <= L'f') { return 10 + (int)(value - L'a'); }
    if (value >= L'A' && value <= L'F') { return 10 + (int)(value - L'A'); }
    return -1;
}

static BOOL MeshUserConsent_DecodeHexUtf16W(const wchar_t* hex, wchar_t* output, size_t outputCch)
{
    size_t hexLen = 0;
    size_t i = 0;
    size_t j = 0;

    if (hex == NULL || output == NULL || outputCch == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    output[0] = L'\0';
    hexLen = wcslen(hex);
    if (hexLen == 0 || (hexLen % 4) != 0 || (hexLen / 4) >= outputCch)
    {
        SetLastError(hexLen == 0 ? ERROR_INVALID_DATA : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    for (i = 0; i < hexLen; i += 4)
    {
        int lo0 = MeshUserConsent_HexNibbleW(hex[i]);
        int lo1 = MeshUserConsent_HexNibbleW(hex[i + 1]);
        int hi0 = MeshUserConsent_HexNibbleW(hex[i + 2]);
        int hi1 = MeshUserConsent_HexNibbleW(hex[i + 3]);
        wchar_t ch = L'\0';

        if (lo0 < 0 || lo1 < 0 || hi0 < 0 || hi1 < 0)
        {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
        ch = (wchar_t)(((lo0 << 4) | lo1) | (((hi0 << 4) | hi1) << 8));
        if (ch == L'\0')
        {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
        output[j++] = ch;
    }
    output[j] = L'\0';
    return TRUE;
}

static BOOL MeshUserConsent_ParseDwordW(const wchar_t* value, DWORD minValue, DWORD maxValue, DWORD* output)
{
    wchar_t* end = NULL;
    unsigned long parsed = 0;

    if (value == NULL || value[0] == L'\0' || output == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    parsed = wcstoul(value, &end, 10);
    if (end == value || end == NULL || *end != L'\0' || parsed < minValue || parsed > maxValue)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    *output = (DWORD)parsed;
    return TRUE;
}

static BOOL MeshUserConsent_ReadBoolW(const wchar_t* manifestPath, const wchar_t* keyName, BOOL defaultValue)
{
    wchar_t value[32] = {0};
    DWORD read = GetPrivateProfileStringW(MESH_USER_CONSENT_SECTION_W, keyName, defaultValue ? L"1" : L"0", value, (DWORD)_countof(value), manifestPath);
    if (read == 0) { return defaultValue; }
    if (_wcsicmp(value, L"1") == 0 || _wcsicmp(value, L"true") == 0 || _wcsicmp(value, L"yes") == 0 || _wcsicmp(value, L"on") == 0) { return TRUE; }
    if (_wcsicmp(value, L"0") == 0 || _wcsicmp(value, L"false") == 0 || _wcsicmp(value, L"no") == 0 || _wcsicmp(value, L"off") == 0) { return FALSE; }
    return defaultValue;
}

static BOOL MeshUserConsent_ReadManifestW(const wchar_t* manifestPath, MeshUserConsentManifest* manifestOut)
{
    wchar_t sessionText[32] = {0};
    wchar_t timeoutText[32] = {0};
    wchar_t titleHex[(MESH_USER_CONSENT_MAX_TITLE_CCH * 4)] = {0};
    wchar_t captionHex[(MESH_USER_CONSENT_MAX_CAPTION_CCH * 4)] = {0};
    DWORD read = 0;

    if (manifestPath == NULL || manifestPath[0] == L'\0' || manifestOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!MeshRuntimeHost_FileExistsW(manifestPath))
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

    read = GetPrivateProfileStringW(MESH_USER_CONSENT_SECTION_W, MESH_USER_CONSENT_KEY_SESSION_ID_W, L"", sessionText, (DWORD)_countof(sessionText), manifestPath);
    if (read == 0)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    if (!MeshUserConsent_ParseDwordW(sessionText, 1, 0xFFFFFFFEUL, &manifestOut->sessionId))
    {
        return FALSE;
    }

    read = GetPrivateProfileStringW(MESH_USER_CONSENT_SECTION_W, MESH_USER_CONSENT_KEY_TIMEOUT_MS_W, L"", timeoutText, (DWORD)_countof(timeoutText), manifestPath);
    if (read == 0)
    {
        manifestOut->timeoutMs = MESH_USER_CONSENT_DEFAULT_TIMEOUT_MS;
    }
    else if (!MeshUserConsent_ParseDwordW(timeoutText, MESH_USER_CONSENT_MIN_TIMEOUT_MS, MESH_USER_CONSENT_MAX_TIMEOUT_MS, &manifestOut->timeoutMs))
    {
        return FALSE;
    }

    manifestOut->timeoutAutoAccept = MeshUserConsent_ReadBoolW(manifestPath, MESH_USER_CONSENT_KEY_TIMEOUT_AUTO_ACCEPT_W, FALSE);

    read = GetPrivateProfileStringW(MESH_USER_CONSENT_SECTION_W, MESH_USER_CONSENT_KEY_TITLE_HEX_W, L"", titleHex, (DWORD)_countof(titleHex), manifestPath);
    if (read == 0 || read >= ((DWORD)_countof(titleHex) - 1))
    {
        SetLastError(read == 0 ? ERROR_INVALID_DATA : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!MeshUserConsent_DecodeHexUtf16W(titleHex, manifestOut->title, _countof(manifestOut->title)))
    {
        return FALSE;
    }
    read = GetPrivateProfileStringW(MESH_USER_CONSENT_SECTION_W, MESH_USER_CONSENT_KEY_CAPTION_HEX_W, L"", captionHex, (DWORD)_countof(captionHex), manifestPath);
    if (read == 0 || read >= ((DWORD)_countof(captionHex) - 1))
    {
        SetLastError(read == 0 ? ERROR_INVALID_DATA : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!MeshUserConsent_DecodeHexUtf16W(captionHex, manifestOut->caption, _countof(manifestOut->caption)))
    {
        return FALSE;
    }
    return TRUE;
}

static BOOL MeshUserConsent_IsApprovedResultPipeNameW(const wchar_t* pipeName)
{
    size_t valueLen = 0;
    size_t prefixLen = wcslen(MESH_USER_CONSENT_RESULT_PIPE_PREFIX_W);
    size_t suffixLen = wcslen(MESH_USER_CONSENT_RESULT_PIPE_SUFFIX_W);
    size_t i = 0;

    if (pipeName == NULL || pipeName[0] == L'\0') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    valueLen = wcslen(pipeName);
    if (valueLen <= (prefixLen + suffixLen) ||
        _wcsnicmp(pipeName, MESH_USER_CONSENT_RESULT_PIPE_PREFIX_W, prefixLen) != 0 ||
        _wcsicmp(pipeName + (valueLen - suffixLen), MESH_USER_CONSENT_RESULT_PIPE_SUFFIX_W) != 0)
    {
        SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return FALSE;
    }
    for (i = prefixLen; i < valueLen - suffixLen; ++i)
    {
        wchar_t c = pipeName[i];
        if (!((c >= L'0' && c <= L'9') || c == L'_'))
        {
            SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
            return FALSE;
        }
    }
    return TRUE;
}

static HANDLE MeshUserConsent_OpenResultPipeW(const wchar_t* pipeName)
{
    ULONGLONG deadline = 0;
    DWORD lastError = ERROR_SUCCESS;

    if (!MeshUserConsent_IsApprovedResultPipeNameW(pipeName)) { return INVALID_HANDLE_VALUE; }
    deadline = GetTickCount64() + MESH_USER_CONSENT_CONNECT_TIMEOUT_MS;
    for (;;)
    {
        HANDLE pipeHandle = CreateFileW(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        ULONGLONG now = 0;
        if (pipeHandle != INVALID_HANDLE_VALUE) { return pipeHandle; }
        lastError = GetLastError();
        // The agent creates the result pipe before it launches this host, so a
        // missing pipe means the agent side is gone; only a busy pipe is worth
        // waiting for.
        if (lastError != ERROR_PIPE_BUSY)
        {
            SetLastError(lastError);
            return INVALID_HANDLE_VALUE;
        }
        now = GetTickCount64();
        if (now >= deadline)
        {
            SetLastError(ERROR_SEM_TIMEOUT);
            return INVALID_HANDLE_VALUE;
        }
        if (!WaitNamedPipeW(pipeName, (DWORD)(deadline - now)))
        {
            lastError = GetLastError();
            if (lastError != ERROR_SEM_TIMEOUT && lastError != ERROR_PIPE_BUSY)
            {
                SetLastError(lastError);
                return INVALID_HANDLE_VALUE;
            }
        }
    }
}

static BOOL MeshUserConsent_WriteResultJson(HANDLE resultPipe, const char* status, DWORD response, DWORD errorCode)
{
    char json[160] = {0};
    DWORD written = 0;

    if (resultPipe == NULL || resultPipe == INVALID_HANDLE_VALUE || status == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (FAILED(StringCchPrintfA(json, sizeof(json), "{\"status\":\"%s\",\"response\":%lu,\"error\":%lu}\n", status, (unsigned long)response, (unsigned long)errorCode)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return WriteFile(resultPipe, json, (DWORD)strnlen_s(json, sizeof(json)), &written, NULL);
}

static DWORD MeshUserConsent_RunW(const wchar_t* resultPipeName, const MeshUserConsentManifest* manifest)
{
    HANDLE resultPipe = INVALID_HANDLE_VALUE;
    DWORD response = 0;
    DWORD exitCode = ERROR_GEN_FAILURE;
    DWORD errorCode = ERROR_SUCCESS;
    DWORD timeoutSeconds = 0;
    DWORD style = MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST;
    BOOL sent = FALSE;
    const char* status = "ERROR";

    if (manifest == NULL || resultPipeName == NULL || resultPipeName[0] == L'\0') { return ERROR_INVALID_PARAMETER; }

    resultPipe = MeshUserConsent_OpenResultPipeW(resultPipeName);
    if (resultPipe == INVALID_HANDLE_VALUE) { return GetLastError(); }

    timeoutSeconds = (manifest->timeoutMs + 999UL) / 1000UL;
    if (timeoutSeconds == 0) { timeoutSeconds = 1; }
    sent = WTSSendMessageW(
        WTS_CURRENT_SERVER_HANDLE,
        manifest->sessionId,
        (LPWSTR)manifest->title,
        (DWORD)(wcslen(manifest->title) * sizeof(wchar_t)),
        (LPWSTR)manifest->caption,
        (DWORD)(wcslen(manifest->caption) * sizeof(wchar_t)),
        style,
        timeoutSeconds,
        &response,
        TRUE);

    if (!sent)
    {
        errorCode = GetLastError();
        exitCode = errorCode;
        status = "ERROR";
    }
    else if (response == IDYES)
    {
        status = "ALLOW";
        exitCode = ERROR_SUCCESS;
    }
    else if (response == IDNO)
    {
        status = "DENIED";
        exitCode = ERROR_CANCELLED;
    }
    else if (response == IDTIMEOUT)
    {
        if (manifest->timeoutAutoAccept)
        {
            status = "ALLOW_TIMEOUT";
            exitCode = ERROR_SUCCESS;
        }
        else
        {
            status = "TIMEOUT";
            exitCode = ERROR_TIMEOUT;
        }
    }
    else
    {
        status = "DENIED";
        exitCode = ERROR_CANCELLED;
    }

    if (!MeshUserConsent_WriteResultJson(resultPipe, status, response, errorCode) && exitCode == ERROR_SUCCESS)
    {
        exitCode = GetLastError();
    }
    CloseHandle(resultPipe);
    return exitCode;
}

static BOOL MeshRuntimeHost_CreateDirectoryIfMissingW(const wchar_t* path)
{
    DWORD err = ERROR_SUCCESS;
    if (path == NULL || path[0] == L'\0') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (MeshRuntimeHost_DirectoryExistsW(path)) { return TRUE; }
    if (CreateDirectoryW(path, NULL)) { return TRUE; }
    err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS && MeshRuntimeHost_DirectoryExistsW(path)) { return TRUE; }
    SetLastError(err);
    return FALSE;
}

static BOOL MeshRuntimeHost_CombinePathW(wchar_t* output, size_t outputCch, const wchar_t* root, const wchar_t* leaf)
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

static BOOL MeshRuntimeHost_ProcessIsRunning(DWORD pid)
{
    HANDLE process = NULL;
    BOOL running = FALSE;

    if (pid == 0) { return FALSE; }
    process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (process == NULL)
    {
        // Access denied still means a process with that PID exists.
        return (GetLastError() == ERROR_ACCESS_DENIED) ? TRUE : FALSE;
    }
    running = (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) ? TRUE : FALSE;
    CloseHandle(process);
    return running;
}

// Staged host DLLs and manifests are normally deleted by the launcher once the host
// exits. A launcher that does not survive the action (the service being updated is
// the one waiting) or does not wait leaves them behind. Remove leftovers whose
// launching process is gone; a DLL still mapped by a running host fails to delete
// and is kept.
static void MeshRuntimeHost_SweepStaleLifecycleArtifactsW(const wchar_t* lifecycleDir)
{
    wchar_t pattern[MAX_PATH * 4] = {0};
    wchar_t candidate[MAX_PATH * 4] = {0};
    WIN32_FIND_DATAW findData;
    HANDLE find = INVALID_HANDLE_VALUE;
    ULARGE_INTEGER now;
    FILETIME nowFileTime;

    if (!MeshRuntimeHost_CombinePathW(pattern, _countof(pattern), lifecycleDir, L"*")) { return; }
    GetSystemTimeAsFileTime(&nowFileTime);
    now.LowPart = nowFileTime.dwLowDateTime;
    now.HighPart = nowFileTime.dwHighDateTime;
    find = FindFirstFileW(pattern, &findData);
    if (find == INVALID_HANDLE_VALUE) { return; }
    do
    {
        unsigned long pid = 0;
        unsigned long long tick = 0;
        ULARGE_INTEGER written;

        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) { continue; }
        if (swscanf_s(findData.cFileName, L"host-%lu-%llu", &pid, &tick) != 2 &&
            swscanf_s(findData.cFileName, L"manifest-%lu-%llu", &pid, &tick) != 2)
        {
            continue;
        }
        written.LowPart = findData.ftLastWriteTime.dwLowDateTime;
        written.HighPart = findData.ftLastWriteTime.dwHighDateTime;
        if (pid == GetCurrentProcessId() ||
            now.QuadPart < written.QuadPart ||
            (now.QuadPart - written.QuadPart) / 10000ULL < MESH_RUNTIME_HOST_STALE_ARTIFACT_AGE_MS ||
            MeshRuntimeHost_ProcessIsRunning((DWORD)pid))
        {
            continue;
        }
        if (MeshRuntimeHost_CombinePathW(candidate, _countof(candidate), lifecycleDir, findData.cFileName))
        {
            (void)DeleteFileW(candidate);
        }
    } while (FindNextFileW(find, &findData));
    FindClose(find);
}

static BOOL MeshRuntimeHost_PrepareLifecycleStateDirectoryW(wchar_t* stateDir, size_t stateDirCch)
{
    ServiceInstallPaths paths;
    wchar_t stateRoot[MAX_PATH * 4] = {0};
    wchar_t lifecycleDir[MAX_PATH * 4] = {0};

    if (stateDir == NULL || stateDirCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    stateDir[0] = L'\0';
    ZeroMemory(&paths, sizeof(paths));

    if (!ServiceDeploy_GetInstallPaths(&paths) || paths.installDir[0] == L'\0')
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    if (!Security_CreateInstallRootDirectory(paths.installDir))
    {
        return FALSE;
    }
    if (!MeshRuntimeHost_CombinePathW(stateRoot, _countof(stateRoot), paths.installDir, L"state"))
    {
        return FALSE;
    }
    // The update transaction keeps its journal and backups here and refuses a
    // state directory without this protected DACL, so never let it inherit one.
    if (!Security_CreateInstallationDirectory(stateRoot))
    {
        return FALSE;
    }
    if (!MeshRuntimeHost_CombinePathW(lifecycleDir, _countof(lifecycleDir), stateRoot, L"runtime-host-lifecycle"))
    {
        return FALSE;
    }
    if (!MeshRuntimeHost_CreateDirectoryIfMissingW(lifecycleDir))
    {
        return FALSE;
    }
    MeshRuntimeHost_SweepStaleLifecycleArtifactsW(lifecycleDir);
    return SUCCEEDED(StringCchCopyW(stateDir, stateDirCch, lifecycleDir)) ? TRUE : FALSE;
}

static wchar_t MeshRuntimeHost_TempLifecycleDir[MAX_PATH * 4] = {0};

// Uninstall-time staging cannot live in the install root it removes. It used to live
// in the caller's %TEMP%, which for the elevated GUI uninstaller is writable by the
// same user's non-elevated processes, so the staged host DLL and action manifest
// could be replaced between staging and use. Stage instead in a directory that this
// process creates itself under the Windows temp directory, with a protected DACL.
static BOOL MeshRuntimeHost_PrepareTempLifecycleDirectoryW(wchar_t* tempDir, size_t tempDirCch)
{
    wchar_t tempRoot[MAX_PATH * 4] = {0};
    wchar_t leaf[128] = {0};
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    SECURITY_ATTRIBUTES securityAttributes;
    UINT windowsLen = 0;
    int attempt = 0;
    DWORD error = ERROR_ALREADY_EXISTS;

    if (tempDir == NULL || tempDirCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    tempDir[0] = L'\0';
    if (MeshRuntimeHost_TempLifecycleDir[0] != L'\0' && MeshRuntimeHost_DirectoryExistsW(MeshRuntimeHost_TempLifecycleDir))
    {
        return SUCCEEDED(StringCchCopyW(tempDir, tempDirCch, MeshRuntimeHost_TempLifecycleDir)) ? TRUE : FALSE;
    }

    windowsLen = GetSystemWindowsDirectoryW(tempRoot, (UINT)_countof(tempRoot));
    if (windowsLen == 0 || windowsLen >= (UINT)_countof(tempRoot))
    {
        SetLastError(windowsLen == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (FAILED(StringCchCatW(tempRoot, _countof(tempRoot), L"\\Temp")))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(MESH_RUNTIME_HOST_TEMP_STAGING_SDDL, SDDL_REVISION_1, &securityDescriptor, NULL))
    {
        return FALSE;
    }
    ZeroMemory(&securityAttributes, sizeof(securityAttributes));
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = securityDescriptor;
    securityAttributes.bInheritHandle = FALSE;

    for (attempt = 0; attempt < 16; ++attempt)
    {
        // Always a new name that CreateDirectoryW itself must create: a directory
        // someone else prepared in advance is never adopted.
        if (FAILED(StringCchPrintfW(leaf, _countof(leaf), L"MeshAgent-runtime-host-lifecycle-%lu-%llu-%ld",
                GetCurrentProcessId(),
                (unsigned long long)GetTickCount64(),
                (long)InterlockedIncrement(&MeshRuntimeHost_ArtifactCounter))) ||
            !MeshRuntimeHost_CombinePathW(tempDir, tempDirCch, tempRoot, leaf))
        {
            error = ERROR_INSUFFICIENT_BUFFER;
            break;
        }
        if (CreateDirectoryW(tempDir, &securityAttributes))
        {
            LocalFree(securityDescriptor);
            (void)StringCchCopyW(MeshRuntimeHost_TempLifecycleDir, _countof(MeshRuntimeHost_TempLifecycleDir), tempDir);
            return TRUE;
        }
        error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) { break; }
    }
    LocalFree(securityDescriptor);
    tempDir[0] = L'\0';
    SetLastError(error);
    return FALSE;
}

static BOOL MeshRuntimeHost_PrepareTempHostDllPathW(wchar_t* hostDllPath, size_t hostDllPathCch)
{
    wchar_t tempDir[MAX_PATH * 4] = {0};
    wchar_t fileName[128] = {0};

    if (hostDllPath == NULL || hostDllPathCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    hostDllPath[0] = L'\0';
    if (!MeshRuntimeHost_PrepareTempLifecycleDirectoryW(tempDir, _countof(tempDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"host-%lu-%llu-%ld.dll", GetCurrentProcessId(), (unsigned long long)GetTickCount64(), (long)InterlockedIncrement(&MeshRuntimeHost_ArtifactCounter))))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return MeshRuntimeHost_CombinePathW(hostDllPath, hostDllPathCch, tempDir, fileName);
}

static BOOL MeshRuntimeHost_PrepareLifecycleHostDllW(
    MeshRuntimeHostLifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    wchar_t* hostDllPath,
    size_t hostDllPathCch,
    BOOL* deleteHostDllOnExit)
{
    ServiceInstallPaths paths;
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
    if (!ServiceDeploy_GetInstallPaths(&paths))
    {
        ZeroMemory(&paths, sizeof(paths));
    }

    if (paths.dllPath[0] != L'\0' && MeshRuntimeHost_FileExistsW(paths.dllPath) &&
        (action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_INSTALL ||
         action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UPDATE ||
         action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL ||
         action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_PACKAGE))
    {
        return SUCCEEDED(StringCchCopyW(hostDllPath, hostDllPathCch, paths.dllPath)) ? TRUE : FALSE;
    }

    // Uninstall, and validation of an uninstall whose DLL is already gone, stage
    // outside the install root: creating state\runtime-host-lifecycle there would recreate
    // the very directory validation expects to be absent.
    if (action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNINSTALL || action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL)
    {
        wchar_t installedDllPath[MAX_PATH * 4] = {0};
        const wchar_t* uninstallSourceDll = NULL;

        if (sourceDllPath != NULL && sourceDllPath[0] != L'\0')
        {
            uninstallSourceDll = sourceDllPath;
        }
        else if (paths.dllPath[0] != L'\0' && MeshRuntimeHost_FileExistsW(paths.dllPath) &&
                 SUCCEEDED(StringCchCopyW(installedDllPath, _countof(installedDllPath), paths.dllPath)))
        {
            uninstallSourceDll = installedDllPath;
        }

        if (!MeshRuntimeHost_PrepareTempHostDllPathW(hostDllPath, hostDllPathCch))
        {
            return FALSE;
        }
        if (!ServiceDeploy_StageServiceHostDllForLifecycleHost(sourceExePath, uninstallSourceDll, hostDllPath))
        {
            return FALSE;
        }
        *deleteHostDllOnExit = TRUE;
        return TRUE;
    }

    if (!MeshRuntimeHost_PrepareLifecycleStateDirectoryW(stateDir, _countof(stateDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"host-%lu-%llu-%ld.dll", GetCurrentProcessId(), (unsigned long long)GetTickCount64(), (long)InterlockedIncrement(&MeshRuntimeHost_ArtifactCounter))))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!MeshRuntimeHost_CombinePathW(hostDllPath, hostDllPathCch, stateDir, fileName))
    {
        return FALSE;
    }

    if (!ServiceDeploy_StageServiceHostDllForLifecycleHost(sourceExePath, sourceDllPath, hostDllPath))
    {
        return FALSE;
    }
    *deleteHostDllOnExit = TRUE;
    return TRUE;
}

static BOOL MeshRuntimeHost_GetInstalledLifecycleHostDllW(wchar_t* hostDllPath, size_t hostDllPathCch)
{
    ServiceInstallPaths paths;

    if (hostDllPath == NULL || hostDllPathCch == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    hostDllPath[0] = L'\0';
    ZeroMemory(&paths, sizeof(paths));
    if (!ServiceDeploy_GetInstallPaths(&paths) || paths.dllPath[0] == L'\0' || !MeshRuntimeHost_FileExistsW(paths.dllPath))
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

static BOOL MeshRuntimeHost_PrepareManifestPathW(wchar_t* manifestPath, size_t manifestPathCch)
{
    wchar_t stateDir[MAX_PATH * 4] = {0};
    wchar_t fileName[128] = {0};
    if (manifestPath == NULL || manifestPathCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    manifestPath[0] = L'\0';
    if (!MeshRuntimeHost_PrepareLifecycleStateDirectoryW(stateDir, _countof(stateDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"manifest-%lu-%llu-%ld.ini", GetCurrentProcessId(), (unsigned long long)GetTickCount64(), (long)InterlockedIncrement(&MeshRuntimeHost_ArtifactCounter))))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return MeshRuntimeHost_CombinePathW(manifestPath, manifestPathCch, stateDir, fileName);
}

static BOOL MeshRuntimeHost_PrepareTempManifestPathW(wchar_t* manifestPath, size_t manifestPathCch)
{
    wchar_t tempDir[MAX_PATH * 4] = {0};
    wchar_t fileName[128] = {0};

    if (manifestPath == NULL || manifestPathCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    manifestPath[0] = L'\0';

    if (!MeshRuntimeHost_PrepareTempLifecycleDirectoryW(tempDir, _countof(tempDir)))
    {
        return FALSE;
    }
    if (FAILED(StringCchPrintfW(fileName, _countof(fileName), L"manifest-%lu-%llu-%ld.ini", GetCurrentProcessId(), (unsigned long long)GetTickCount64(), (long)InterlockedIncrement(&MeshRuntimeHost_ArtifactCounter))))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return MeshRuntimeHost_CombinePathW(manifestPath, manifestPathCch, tempDir, fileName);
}

static void MeshRuntimeHost_ApplyBrandingFromManifest(const MeshRuntimeHostLifecycleManifest* manifest)
{
    char utf8[2048];
    int converted = 0;

    if (manifest == NULL) { return; }
    ServiceDeploy_ClearRuntimeBrandingOverrides();

    if (manifest->displayName[0] != L'\0')
    {
        ZeroMemory(utf8, sizeof(utf8));
        converted = WideCharToMultiByte(CP_UTF8, 0, manifest->displayName, -1, utf8, (int)sizeof(utf8), NULL, NULL);
        if (converted > 0) { ServiceDeploy_SetRuntimeDisplayNameUtf8(utf8); }
    }
    if (manifest->serviceDescription[0] != L'\0')
    {
        ZeroMemory(utf8, sizeof(utf8));
        converted = WideCharToMultiByte(CP_UTF8, 0, manifest->serviceDescription, -1, utf8, (int)sizeof(utf8), NULL, NULL);
        if (converted > 0) { ServiceDeploy_SetRuntimeServiceDescriptionUtf8(utf8); }
    }
}

const wchar_t* MeshRuntimeHost_LifecycleActionNameW(MeshRuntimeHostLifecycleAction action)
{
    switch (action)
    {
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_INSTALL: return MESH_LIFECYCLE_ACTION_INSTALL_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE: return MESH_LIFECYCLE_ACTION_UPDATE_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_REPAIR: return MESH_LIFECYCLE_ACTION_REPAIR_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_REINSTALL: return MESH_LIFECYCLE_ACTION_REINSTALL_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNINSTALL: return MESH_LIFECYCLE_ACTION_UNINSTALL_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_RECOVER_UPDATE: return MESH_LIFECYCLE_ACTION_RECOVER_UPDATE_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_INSTALL: return MESH_LIFECYCLE_ACTION_VALIDATE_INSTALL_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UPDATE: return MESH_LIFECYCLE_ACTION_VALIDATE_UPDATE_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL: return MESH_LIFECYCLE_ACTION_VALIDATE_UNINSTALL_W;
        case MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_PACKAGE: return MESH_LIFECYCLE_ACTION_VALIDATE_PACKAGE_W;
        default: return L"unknown";
    }
}

BOOL MeshRuntimeHost_LifecycleActionFromStringW(const wchar_t* value, MeshRuntimeHostLifecycleAction* actionOut)
{
    MeshRuntimeHostLifecycleAction action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNKNOWN;
    if (actionOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *actionOut = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNKNOWN;
    if (value == NULL || value[0] == L'\0') { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }

    if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_INSTALL_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_INSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_UPDATE_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_REPAIR_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_REPAIR; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_REINSTALL_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_REINSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_UNINSTALL_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNINSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_RECOVER_UPDATE_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_RECOVER_UPDATE; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_INSTALL_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_INSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_UPDATE_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UPDATE; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_UNINSTALL_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL; }
    else if (_wcsicmp(value, MESH_LIFECYCLE_ACTION_VALIDATE_PACKAGE_W) == 0) { action = MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_PACKAGE; }
    else { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }

    *actionOut = action;
    return TRUE;
}

BOOL MeshRuntimeHost_ReadLifecycleManifestW(const wchar_t* manifestPath, MeshRuntimeHostLifecycleManifest* manifestOut)
{
    wchar_t actionName[64] = {0};
    DWORD actionLen = 0;

    if (manifestPath == NULL || manifestPath[0] == L'\0' || manifestOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!MeshRuntimeHost_FileExistsW(manifestPath))
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
    if (actionLen == 0 || !MeshRuntimeHost_LifecycleActionFromStringW(actionName, &manifestOut->action))
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    // GetPrivateProfileStringW truncates silently; a value that fills its buffer was cut short.
    if (GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_SOURCE_EXE_W, L"", manifestOut->sourceExePath, (DWORD)_countof(manifestOut->sourceExePath), manifestPath) >= (DWORD)_countof(manifestOut->sourceExePath) - 1 ||
        GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_SOURCE_DLL_W, L"", manifestOut->sourceDllPath, (DWORD)_countof(manifestOut->sourceDllPath), manifestPath) >= (DWORD)_countof(manifestOut->sourceDllPath) - 1 ||
        GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_DISPLAY_NAME_W, L"", manifestOut->displayName, (DWORD)_countof(manifestOut->displayName), manifestPath) >= (DWORD)_countof(manifestOut->displayName) - 1 ||
        GetPrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_DESCRIPTION_W, L"", manifestOut->serviceDescription, (DWORD)_countof(manifestOut->serviceDescription), manifestPath) >= (DWORD)_countof(manifestOut->serviceDescription) - 1)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    manifestOut->requireConfig = MeshRuntimeHost_ManifestBoolW(manifestPath, MESH_LIFECYCLE_KEY_REQUIRE_CONFIG_W, TRUE);
    return TRUE;
}

BOOL MeshRuntimeHost_WriteLifecycleManifestW(
    const wchar_t* manifestPath,
    MeshRuntimeHostLifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    BOOL requireConfig)
{
    const wchar_t* actionName = MeshRuntimeHost_LifecycleActionNameW(action);
    const WORD unicodeBom = 0xFEFF;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    DWORD error = ERROR_SUCCESS;
    if (manifestPath == NULL || manifestPath[0] == L'\0' || action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNKNOWN)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // The W profile APIs still create ANSI files unless a Unicode BOM already
    // exists. Initialize UTF-16 before writing paths so no ACP conversion occurs.
    file = CreateFileW(manifestPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { return FALSE; }
    if (!WriteFile(file, &unicodeBom, sizeof(unicodeBom), &written, NULL)) { error = GetLastError(); }
    else if (written != sizeof(unicodeBom)) { error = ERROR_WRITE_FAULT; }
    if (!CloseHandle(file) && error == ERROR_SUCCESS) { error = GetLastError(); }
    if (error != ERROR_SUCCESS) { goto failed; }

    if (!WritePrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_ACTION_W, actionName, manifestPath) ||
        !MeshRuntimeHost_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_SOURCE_EXE_W, sourceExePath, MAX_PATH * 4) ||
        !MeshRuntimeHost_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_SOURCE_DLL_W, sourceDllPath, MAX_PATH * 4) ||
        !MeshRuntimeHost_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_DISPLAY_NAME_W, displayName, 256) ||
        !MeshRuntimeHost_WriteManifestStringW(manifestPath, MESH_LIFECYCLE_KEY_DESCRIPTION_W, serviceDescription, 512) ||
        !WritePrivateProfileStringW(MESH_LIFECYCLE_SECTION_W, MESH_LIFECYCLE_KEY_REQUIRE_CONFIG_W, requireConfig ? L"1" : L"0", manifestPath))
    {
        error = GetLastError();
        goto failed;
    }
    return TRUE;

failed:
    if (!DeleteFileW(manifestPath))
    {
        // Preserve the write failure even when the partial file cannot be removed.
        DWORD cleanupError = GetLastError();
        if (error == ERROR_SUCCESS) { error = cleanupError; }
    }
    SetLastError(error != ERROR_SUCCESS ? error : ERROR_WRITE_FAULT);
    return FALSE;
}

// Normalizes a path for host-identity comparison: '/' -> '\', GetFullPathNameW, '/' -> '\'
// again. Matches the rule the launch chokepoint and watchdog predicates use.
static void MeshRuntimeHost_NormalizeHostPathW(const wchar_t* value, wchar_t* output, size_t outputCch)
{
    wchar_t scratch[MAX_PATH * 4];
    DWORD fullLen;
    size_t i;
    if (output == NULL || outputCch == 0) { return; }
    output[0] = L'\0';
    if (value == NULL || value[0] == L'\0') { return; }
    if (FAILED(StringCchCopyW(scratch, _countof(scratch), value))) { return; }
    for (i = 0; scratch[i] != L'\0'; ++i) { if (scratch[i] == L'/') { scratch[i] = L'\\'; } }
    fullLen = GetFullPathNameW(scratch, (DWORD)outputCch, output, NULL);
    if (fullLen == 0 || fullLen >= outputCch) { StringCchCopyW(output, outputCch, scratch); }
    for (i = 0; output[i] != L'\0'; ++i) { if (output[i] == L'/') { output[i] = L'\\'; } }
}

BOOL MeshRuntimeHost_BuildSystemBinaryPathW(const wchar_t* binaryName, BOOL requireExistingFile, wchar_t* output, size_t outputCch)
{
    UINT len = 0;
    if (binaryName == NULL || binaryName[0] == L'\0' || output == NULL || outputCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    output[0] = L'\0';
    len = GetSystemDirectoryW(output, (UINT)outputCch);
    if (len == 0 || len >= outputCch)
    {
        SetLastError(len == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER);
        output[0] = L'\0';
        return FALSE;
    }
    if (FAILED(StringCchCatW(output, outputCch, L"\\")) || FAILED(StringCchCatW(output, outputCch, binaryName)))
    {
        output[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    // The launch chokepoint must not accept a directory named like the host binary.
    if (requireExistingFile && !MeshRuntimeHost_FileExistsW(output)) { return FALSE; }
    return TRUE;
}

BOOL MeshRuntimeHost_IsExactSystemBinaryPathW(const wchar_t* binaryName, const wchar_t* value)
{
    wchar_t canonical[MAX_PATH * 4];
    wchar_t normalizedValue[MAX_PATH * 4];
    wchar_t normalizedCanonical[MAX_PATH * 4];
    if (value == NULL || value[0] == L'\0') { return FALSE; }
    // Construct-only: a policy match must not depend on the file being present at this instant,
    // and uses the same construction as the resolver so the two cannot disagree.
    if (!MeshRuntimeHost_BuildSystemBinaryPathW(binaryName, FALSE, canonical, _countof(canonical))) { return FALSE; }
    MeshRuntimeHost_NormalizeHostPathW(value, normalizedValue, _countof(normalizedValue));
    if (normalizedValue[0] == L'\0') { return FALSE; }
    MeshRuntimeHost_NormalizeHostPathW(canonical, normalizedCanonical, _countof(normalizedCanonical));
    if (normalizedCanonical[0] == L'\0') { return FALSE; }
    return (_wcsicmp(normalizedValue, normalizedCanonical) == 0) ? TRUE : FALSE;
}

BOOL MeshRuntimeHost_GetSystemHostPathW(wchar_t* runtimeHostPath, size_t runtimeHostPathCch)
{
    return MeshRuntimeHost_BuildSystemBinaryPathW(MESH_RUNTIME_HOST_BINARY_RUNDLL32_W, TRUE, runtimeHostPath, runtimeHostPathCch);
}

BOOL MeshRuntimeHost_GetServiceHostPathW(wchar_t* serviceHostPath, size_t serviceHostPathCch)
{
    return MeshRuntimeHost_BuildSystemBinaryPathW(MESH_RUNTIME_HOST_BINARY_SVCHOST_W, TRUE, serviceHostPath, serviceHostPathCch);
}

// Removes the staged manifest and host DLL of a host that has exited or never started.
static void MeshRuntimeHost_DeleteLifecycleArtifactsW(MeshRuntimeHostLifecycleLaunch* launch)
{
    if (launch->manifestPath[0] != L'\0' && !DeleteFileW(launch->manifestPath))
    {
        DWORD cleanupError = GetLastError();
        if (cleanupError != ERROR_FILE_NOT_FOUND)
        {
            ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Lifecycle manifest cleanup failed (error=%lu)", cleanupError);
        }
    }
    if (launch->deleteHostDllOnExit && launch->hostDllPath[0] != L'\0' && !DeleteFileW(launch->hostDllPath))
    {
        DWORD cleanupError = GetLastError();
        if (cleanupError != ERROR_FILE_NOT_FOUND)
        {
            ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Lifecycle DLL cleanup failed (error=%lu)", cleanupError);
        }
    }
    // The uninstall staging directory is private to this process; remove it once
    // it is empty. A host still holding its DLL keeps it, and the name is cached
    // for reuse by a later action in this process.
    if (MeshRuntimeHost_TempLifecycleDir[0] != L'\0' && RemoveDirectoryW(MeshRuntimeHost_TempLifecycleDir))
    {
        MeshRuntimeHost_TempLifecycleDir[0] = L'\0';
    }
    launch->manifestPath[0] = L'\0';
    launch->hostDllPath[0] = L'\0';
}

BOOL MeshRuntimeHost_StartLifecycleHostW(
    MeshRuntimeHostLifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    BOOL requireConfig,
    MeshRuntimeHostLifecycleLaunch* launch)
{
    wchar_t runtimeHostPath[MAX_PATH] = {0};
    wchar_t commandLine[MAX_PATH * 12] = {0};
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    DWORD error = ERROR_SUCCESS;

    if (launch == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    ZeroMemory(launch, sizeof(*launch));
    if (action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNKNOWN) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    launch->action = action;

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL)
    {
        ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log");
    }

    if (!MeshRuntimeHost_GetSystemHostPathW(runtimeHostPath, _countof(runtimeHostPath)) ||
        !MeshRuntimeHost_PrepareLifecycleHostDllW(action, sourceExePath, sourceDllPath, launch->hostDllPath, _countof(launch->hostDllPath), &launch->deleteHostDllOnExit) ||
        !((action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNINSTALL ||
           action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL) ?
            MeshRuntimeHost_PrepareTempManifestPathW(launch->manifestPath, _countof(launch->manifestPath)) :
            MeshRuntimeHost_PrepareManifestPathW(launch->manifestPath, _countof(launch->manifestPath))))
    {
        error = GetLastError();
        if (error == ERROR_SUCCESS) { error = ERROR_GEN_FAILURE; }
        goto failed;
    }

    if (!MeshRuntimeHost_WriteLifecycleManifestW(
            launch->manifestPath,
            action,
            sourceExePath,
            launch->hostDllPath,
            displayName,
            serviceDescription,
            requireConfig))
    {
        error = GetLastError();
        if (error == ERROR_SUCCESS) { error = ERROR_WRITE_FAULT; }
        goto failed;
    }

    if (FAILED(StringCchPrintfW(
            commandLine,
            _countof(commandLine),
            L"\"%ls\" \"%ls\",%ls \"%ls\"",
            runtimeHostPath,
            launch->hostDllPath,
            MESH_RUNTIME_HOST_ENTRY_LIFECYCLE_W,
            launch->manifestPath)))
    {
        error = ERROR_INSUFFICIENT_BUFFER;
        goto failed;
    }

    ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Launching lifecycle action=%ls dll=%ls manifest=%ls",
        MeshRuntimeHost_LifecycleActionNameW(action),
        launch->hostDllPath,
        launch->manifestPath);

    if (!CreateProcessW(runtimeHostPath, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] CreateProcessW failed for lifecycle host (error=%lu)", error);
        goto failed;
    }
    if (!CloseHandle(pi.hThread))
    {
        ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Lifecycle thread handle close failed (error=%lu)", GetLastError());
    }
    launch->process = pi.hProcess;
    SetLastError(ERROR_SUCCESS);
    return TRUE;

failed:
    // No host started, so nothing else owns the staged files.
    MeshRuntimeHost_DeleteLifecycleArtifactsW(launch);
    SetLastError(error);
    return FALSE;
}

BOOL MeshRuntimeHost_CompleteLifecycleHostW(MeshRuntimeHostLifecycleLaunch* launch, DWORD* exitCodeOut)
{
    DWORD exitCode = STILL_ACTIVE;
    DWORD error = ERROR_SUCCESS;
    BOOL ok = TRUE;

    if (exitCodeOut != NULL) { *exitCodeOut = ERROR_GEN_FAILURE; }
    if (launch == NULL || launch->process == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }

    if (!GetExitCodeProcess(launch->process, &exitCode))
    {
        exitCode = GetLastError();
        error = exitCode;
        ok = FALSE;
    }
    if (exitCodeOut != NULL) { *exitCodeOut = exitCode; }
    if (exitCode != ERROR_SUCCESS)
    {
        ok = FALSE;
        ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] lifecycle host action=%ls exited with %lu",
            MeshRuntimeHost_LifecycleActionNameW(launch->action),
            exitCode);
    }
    if (!CloseHandle(launch->process))
    {
        ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Lifecycle process handle close failed (error=%lu)", GetLastError());
    }
    launch->process = NULL;
    MeshRuntimeHost_DeleteLifecycleArtifactsW(launch);
    // A completed child failure is reported through exitCodeOut. Only the exit
    // code query populates GetLastError. Never let logging or cleanup relabel an
    // install failure as "failed to launch".
    SetLastError(error);
    return ok;
}

void MeshRuntimeHost_ReleaseLifecycleHostW(MeshRuntimeHostLifecycleLaunch* launch)
{
    if (launch == NULL || launch->process == NULL) { return; }
    // A running host may not have read the manifest or mapped its DLL yet, so its
    // staged files stay behind for the sweep once this launcher has exited.
    if (!CloseHandle(launch->process))
    {
        ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Lifecycle process handle close failed (error=%lu)", GetLastError());
    }
    launch->process = NULL;
}

BOOL MeshRuntimeHost_LaunchLifecycleHostW(
    MeshRuntimeHostLifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    BOOL requireConfig,
    BOOL waitForExit,
    DWORD timeoutMs,
    DWORD* exitCodeOut)
{
    MeshRuntimeHostLifecycleLaunch launch;
    DWORD waitResult = WAIT_OBJECT_0;
    DWORD exitCode = STILL_ACTIVE;
    DWORD error = ERROR_SUCCESS;
    BOOL childExited = FALSE;

    if (exitCodeOut != NULL) { *exitCodeOut = ERROR_GEN_FAILURE; }
    if (!MeshRuntimeHost_StartLifecycleHostW(action, sourceExePath, sourceDllPath, displayName, serviceDescription, requireConfig, &launch))
    {
        return FALSE;
    }
    if (!waitForExit)
    {
        MeshRuntimeHost_ReleaseLifecycleHostW(&launch);
        if (exitCodeOut != NULL) { *exitCodeOut = ERROR_SUCCESS; }
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    waitResult = WaitForSingleObject(launch.process, timeoutMs);
    if (waitResult == WAIT_OBJECT_0)
    {
        return MeshRuntimeHost_CompleteLifecycleHostW(&launch, exitCodeOut);
    }

    error = (waitResult == WAIT_TIMEOUT) ? ERROR_TIMEOUT :
        (waitResult == WAIT_FAILED) ? GetLastError() : ERROR_GEN_FAILURE;
    if (error == ERROR_SUCCESS) { error = ERROR_GEN_FAILURE; }
    ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] lifecycle host wait failed/timed out (wait=%lu error=%lu)", waitResult, error);
    // A host that changes the install is mid-transaction; killing it would skip
    // its own rollback. Only validation hosts are safe to stop here.
    if (waitResult == WAIT_TIMEOUT &&
        (action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_INSTALL ||
         action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UPDATE ||
         action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL ||
         action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_PACKAGE))
    {
        if (!TerminateProcess(launch.process, ERROR_TIMEOUT))
        {
            ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Timed-out lifecycle host termination failed (error=%lu)", GetLastError());
        }
        else
        {
            // Termination is asynchronous; wait so the staged DLL is unmapped
            // before it is deleted.
            childExited = (WaitForSingleObject(launch.process, 5000) == WAIT_OBJECT_0);
        }
    }
    else if (waitResult == WAIT_TIMEOUT)
    {
        ServiceDeploy_LogInstallEvent(L"[RUNTIME_HOST_CONTRACT] Leaving timed-out lifecycle host action=%ls to finish its own transaction",
            MeshRuntimeHost_LifecycleActionNameW(action));
    }

    if (childExited)
    {
        (void)MeshRuntimeHost_CompleteLifecycleHostW(&launch, exitCodeOut);
    }
    else
    {
        // A failed wait does not transfer ownership back from a live child.
        if (!GetExitCodeProcess(launch.process, &exitCode)) { exitCode = GetLastError(); }
        if (exitCodeOut != NULL) { *exitCodeOut = exitCode; }
        MeshRuntimeHost_ReleaseLifecycleHostW(&launch);
    }
    SetLastError(error);
    return FALSE;
}

BOOL MeshRuntimeHost_LaunchLauncherCleanupW(const wchar_t* targetPath, DWORD parentPid, DWORD timeoutMs)
{
    wchar_t runtimeHostPath[MAX_PATH] = {0};
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

    if (!MeshRuntimeHost_GetSystemHostPathW(runtimeHostPath, _countof(runtimeHostPath)) ||
        !MeshRuntimeHost_GetInstalledLifecycleHostDllW(hostDllPath, _countof(hostDllPath)))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[LAUNCHER_CLEANUP] Unable to resolve cleanup host for target=%ls error=%lu", targetPath, error);
        SetLastError(error);
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(
            commandLine,
            _countof(commandLine),
            L"\"%ls\" \"%ls\",%ls \"%ls\" %lu %lu",
            runtimeHostPath,
            hostDllPath,
            MESH_RUNTIME_HOST_ENTRY_LAUNCHER_CLEANUP_W,
            targetPath,
            (unsigned long)parentPid,
            (unsigned long)timeoutMs)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (!CreateProcessW(runtimeHostPath, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[LAUNCHER_CLEANUP] CreateProcessW failed target=%ls error=%lu", targetPath, error);
        SetLastError(error);
        return FALSE;
    }

    if (pi.hThread != NULL) { CloseHandle(pi.hThread); }
    if (pi.hProcess != NULL) { CloseHandle(pi.hProcess); }
    ServiceDeploy_LogInstallEvent(L"[LAUNCHER_CLEANUP] Scheduled cleanup target=%ls parentPid=%lu timeoutMs=%lu",
        targetPath,
        (unsigned long)parentPid,
        (unsigned long)timeoutMs);
    return TRUE;
}

BOOL MeshRuntimeHost_LaunchSelfTestHostW(const wchar_t* arguments, DWORD timeoutMs, DWORD* exitCodeOut)
{
    wchar_t runtimeHostPath[MAX_PATH] = {0};
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

    if (!MeshRuntimeHost_GetSystemHostPathW(runtimeHostPath, _countof(runtimeHostPath)) ||
        !MeshRuntimeHost_GetInstalledLifecycleHostDllW(hostDllPath, _countof(hostDllPath)))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] Unable to resolve native self-test host (error=%lu)", error);
        SetLastError(error);
        return FALSE;
    }

    if (FAILED(StringCchPrintfW(
            commandLine,
            _countof(commandLine),
            L"\"%ls\" \"%ls\",%ls %ls",
            runtimeHostPath,
            hostDllPath,
            MESH_RUNTIME_HOST_ENTRY_SELFTEST_W,
            arguments)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] Launching native self-test host dll=%ls", hostDllPath);
    if (!CreateProcessW(runtimeHostPath, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] CreateProcessW failed (error=%lu)", error);
        SetLastError(error);
        return FALSE;
    }

    waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (waitResult != WAIT_OBJECT_0)
    {
        DWORD waitError = (waitResult == WAIT_TIMEOUT) ? ERROR_TIMEOUT : GetLastError();
        ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] Wait failed/timed out (wait=%lu error=%lu)", waitResult, waitError);
        // Stop the host on any failed wait, and wait for the termination to land so
        // the reported result is not the still-running STILL_ACTIVE status.
        if (TerminateProcess(pi.hProcess, ERROR_TIMEOUT)) { (void)WaitForSingleObject(pi.hProcess, 5000); }
        exitCode = (waitError != ERROR_SUCCESS) ? waitError : ERROR_GEN_FAILURE;
        ok = FALSE;
    }
    else if (!GetExitCodeProcess(pi.hProcess, &exitCode))
    {
        exitCode = GetLastError();
        ok = FALSE;
    }
    else
    {
        ok = TRUE;
    }
    if (exitCodeOut != NULL) { *exitCodeOut = exitCode; }
    if (exitCode != ERROR_SUCCESS)
    {
        ok = FALSE;
        ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] self-test host exited with %lu", exitCode);
    }

    if (pi.hThread != NULL) { CloseHandle(pi.hThread); }
    if (pi.hProcess != NULL) { CloseHandle(pi.hProcess); }
    return ok;
}

static DWORD MeshRuntimeHost_DeleteLauncherAfterParentExitW(const wchar_t* targetPath, DWORD parentPid, DWORD timeoutMs)
{
    HANDLE parentProcess = NULL;
    ULONGLONG deadline = 0;
    DWORD lastError = ERROR_SUCCESS;

    if (targetPath == NULL || targetPath[0] == L'\0') { return ERROR_INVALID_PARAMETER; }
    if (timeoutMs == 0) { timeoutMs = 60000; }

    // One budget covers both waiting for the parent and retrying the delete.
    deadline = GetTickCount64() + timeoutMs;
    if (parentPid != 0)
    {
        parentProcess = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
        if (parentProcess != NULL)
        {
            (void)WaitForSingleObject(parentProcess, timeoutMs);
            CloseHandle(parentProcess);
        }
    }

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
        ServiceDeploy_LogInstallEvent(L"[LAUNCHER_CLEANUP] Deferred launcher delete until reboot target=%ls lastError=%lu", targetPath, lastError);
        return ERROR_SUCCESS;
    }
    return GetLastError();
}

static void MeshConsoleBridge_CloseHandle(HANDLE* handleRef)
{
    HANDLE handle = NULL;
    if (handleRef == NULL) { return; }
    handle = (HANDLE)InterlockedExchangePointer((PVOID volatile*)handleRef, NULL);
    if (handle != NULL && handle != INVALID_HANDLE_VALUE) { CloseHandle(handle); }
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
    const wchar_t* shellSuffix = NULL;
    const wchar_t* shellArgs = NULL;
    if (shellName == NULL || shellPath == NULL || shellPathCch == 0 || commandLine == NULL || commandLineCch == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    shellPath[0] = L'\0';
    commandLine[0] = L'\0';
    if (_wcsicmp(shellName, L"powershell") == 0)
    {
        shellSuffix = L"\\WindowsPowerShell\\v1.0\\powershell.exe";
        shellArgs = nonInteractive ? L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command -" : L" -NoLogo -NoProfile";
    }
    else if (_wcsicmp(shellName, L"cmd") == 0 && !nonInteractive)
    {
        shellSuffix = L"\\cmd.exe";
        shellArgs = L"";
    }
    else
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
    if (!MeshRuntimeHost_FileExistsW(shellPath)) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
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

static BOOL MeshConsoleBridge_CreateConptyPipePairW(const wchar_t* role, HANDLE* ptySideHandle, HANDLE* bridgeSideHandle)
{
    wchar_t pipeName[160] = {0};
    HANDLE serverHandle = INVALID_HANDLE_VALUE;
    HANDLE clientHandle = INVALID_HANDLE_VALUE;
    DWORD lastError = ERROR_SUCCESS;
    LONG counter = 0;

    if (role == NULL || role[0] == L'\0' || ptySideHandle == NULL || bridgeSideHandle == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *ptySideHandle = NULL;
    *bridgeSideHandle = NULL;

    counter = InterlockedIncrement((volatile LONG*)&MeshConsoleBridge_PtyPipeCounter);
    if (FAILED(StringCchPrintfW(pipeName, _countof(pipeName),
        L"\\\\.\\pipe\\MeshConsoleConpty_%lu_%I64u_%ld_%ls",
        (unsigned long)GetCurrentProcessId(),
        (unsigned long long)GetTickCount64(),
        (long)counter,
        role)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    serverHandle = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        128 * 1024,
        128 * 1024,
        30000,
        NULL);
    if (serverHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    clientHandle = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (clientHandle == INVALID_HANDLE_VALUE)
    {
        lastError = GetLastError();
        CloseHandle(serverHandle);
        SetLastError(lastError);
        return FALSE;
    }

    if (!ConnectNamedPipe(serverHandle, NULL))
    {
        lastError = GetLastError();
        if (lastError != ERROR_PIPE_CONNECTED)
        {
            CloseHandle(clientHandle);
            CloseHandle(serverHandle);
            SetLastError(lastError);
            return FALSE;
        }
    }

    *ptySideHandle = serverHandle;
    *bridgeSideHandle = clientHandle;
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

static BOOL MeshConsoleBridge_CreateShellProcessW(HANDLE pseudoConsole, const wchar_t* shellPath, wchar_t* commandLine, DWORD targetSessionId, MeshProcessTokenMode tokenMode, PROCESS_INFORMATION* processInfo)
{
    STARTUPINFOEXW startupInfo;
    SIZE_T attributeListSize = 0;
    HANDLE userToken = NULL;
    LPVOID environment = NULL;
    HMODULE userEnvModule = NULL;
    MeshConsoleBridge_DestroyEnvironmentBlockFn destroyEnvironmentFn = NULL;
    DWORD creationFlags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
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
    startupInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    startupInfo.StartupInfo.hStdInput = NULL;
    startupInfo.StartupInfo.hStdOutput = NULL;
    startupInfo.StartupInfo.hStdError = NULL;
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
    if (MeshProcessToken_Open(tokenMode, targetSessionId, &userToken) &&
        MeshConsoleBridge_TryCreateEnvironmentBlock(userToken, &environment, &destroyEnvironmentFn, &userEnvModule))
    {
        ok = CreateProcessAsUserW(userToken, shellPath, commandLine, NULL, NULL, FALSE, creationFlags, environment, systemDirectory, &startupInfo.StartupInfo, processInfo);
        if (ok) { ok = MeshProcessToken_VerifyChildAndResume(tokenMode, userToken, processInfo); }
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

static BOOL MeshConsoleBridge_CreateRedirectedShellProcessW(HANDLE stdinRead, HANDLE stdoutWrite, const wchar_t* shellPath, wchar_t* commandLine, DWORD targetSessionId, MeshProcessTokenMode tokenMode, PROCESS_INFORMATION* processInfo)
{
    STARTUPINFOW startupInfo;
    HANDLE userToken = NULL;
    LPVOID environment = NULL;
    HMODULE userEnvModule = NULL;
    MeshConsoleBridge_DestroyEnvironmentBlockFn destroyEnvironmentFn = NULL;
    DWORD creationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
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

    if (MeshProcessToken_Open(tokenMode, targetSessionId, &userToken) &&
        MeshConsoleBridge_TryCreateEnvironmentBlock(userToken, &environment, &destroyEnvironmentFn, &userEnvModule))
    {
        ok = CreateProcessAsUserW(userToken, shellPath, commandLine, NULL, NULL, TRUE, creationFlags, environment, systemDirectory, &startupInfo, processInfo);
        if (ok) { ok = MeshProcessToken_VerifyChildAndResume(tokenMode, userToken, processInfo); }
    }
    lastError = ok ? ERROR_SUCCESS : GetLastError();
    if (environment != NULL && destroyEnvironmentFn != NULL) { destroyEnvironmentFn(environment); }
    if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
    if (userToken != NULL) { CloseHandle(userToken); }
    if (!ok) { SetLastError(lastError); }
    return ok;
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

// The bridge pipes are synchronous, so a copy thread blocked in ReadFile holds the
// file object: closing that handle from another thread waits for the read instead
// of cancelling it. Cancel the thread's I/O (repeatedly, in case it was between
// reads) until it exits, so handles can be closed without blocking.
static BOOL MeshConsoleBridge_StopCopyThread(HANDLE thread, DWORD timeoutMs)
{
    ULONGLONG deadline = GetTickCount64() + timeoutMs;

    if (thread == NULL) { return TRUE; }
    for (;;)
    {
        if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0) { return TRUE; }
        CancelSynchronousIo(thread);
        if (WaitForSingleObject(thread, 50) == WAIT_OBJECT_0) { return TRUE; }
        if (GetTickCount64() >= deadline)
        {
            // The copy context belongs to this compatibility host's stack.
            // Never close/reuse its handles or return while the worker owns them.
            ServiceDeploy_LogInstallEvent(L"[CONSOLE_BRIDGE] Copy thread did not stop after I/O cancellation");
            ExitProcess(ERROR_TIMEOUT);
        }
    }
}

typedef struct MeshConsoleBridgeCloseContext
{
    MeshConsoleBridge_ClosePseudoConsoleFn closeFn;
    HANDLE console;
} MeshConsoleBridgeCloseContext;

static DWORD WINAPI MeshConsoleBridge_ClosePseudoConsoleThread(LPVOID param)
{
    MeshConsoleBridgeCloseContext* close = (MeshConsoleBridgeCloseContext*)param;
    close->closeFn(close->console);
    return ERROR_SUCCESS;
}

static void MeshConsoleBridge_ClosePseudoConsole(
    HANDLE* console, MeshConsoleBridge_ClosePseudoConsoleFn closeFn,
    HANDLE outputThread, volatile LONG* outputStopFlag, HANDLE* outputRead)
{
    MeshConsoleBridgeCloseContext close;
    HANDLE closeThread;
    if (*console == NULL || closeFn == NULL) { return; }
    close.closeFn = closeFn;
    close.console = *console;
    // Conhost flushes during close. Keep consuming its output concurrently, but
    // bound the final flush if the agent stopped consuming the forwarding pipe.
    closeThread = CreateThread(NULL, 0, MeshConsoleBridge_ClosePseudoConsoleThread, &close, 0, NULL);
    if (closeThread == NULL || WaitForSingleObject(closeThread, MESH_CONSOLE_BRIDGE_EXEC_OUTPUT_DRAIN_MS) != WAIT_OBJECT_0)
    {
        InterlockedExchange(outputStopFlag, 1);
        MeshConsoleBridge_StopCopyThread(outputThread, 2000);
        MeshConsoleBridge_CloseHandle(outputRead);
        if (closeThread == NULL) { closeFn(*console); }
        else if (WaitForSingleObject(closeThread, MESH_CONSOLE_BRIDGE_EXEC_OUTPUT_DRAIN_MS) != WAIT_OBJECT_0)
        {
            ServiceDeploy_LogInstallEvent(L"[CONSOLE_BRIDGE] Pseudo console close did not complete after releasing its output pipe");
            ExitProcess(ERROR_TIMEOUT);
        }
    }
    if (closeThread != NULL) { CloseHandle(closeThread); }
    *console = NULL;
}

static BOOL MeshConsoleBridge_WriteReadyMarker(HANDLE outputPipe)
{
    static const char readyMarker[] = "\x1b]MeshConsoleBridgeReady\x07";
    DWORD totalWritten = 0;
    DWORD markerLength = (DWORD)(sizeof(readyMarker) - 1);

    if (outputPipe == NULL || outputPipe == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    while (totalWritten < markerLength)
    {
        DWORD bytesWritten = 0;
        if (!WriteFile(outputPipe, readyMarker + totalWritten, markerLength - totalWritten, &bytesWritten, NULL) || bytesWritten == 0)
        {
            DWORD lastError = GetLastError();
            SetLastError(lastError == ERROR_SUCCESS ? ERROR_WRITE_FAULT : lastError);
            return FALSE;
        }
        totalWritten += bytesWritten;
    }
    return TRUE;
}

static DWORD MeshConsoleBridge_RunRedirectedShellW(const wchar_t* inputPipeName, const wchar_t* outputPipeName, const wchar_t* shellName, DWORD targetSessionId, MeshProcessTokenMode tokenMode, BOOL nonInteractive)
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
    volatile LONG inputStopFlag = 0;
    volatile LONG outputStopFlag = 0;
    BOOL processCompleted = FALSE;
    BOOL inputCompleted = FALSE;
    BOOL outputCompleted = FALSE;
    DWORD exitCode = ERROR_GEN_FAILURE;

    ZeroMemory(&processInfo, sizeof(processInfo));
    ZeroMemory(&inputCopy, sizeof(inputCopy));
    ZeroMemory(&outputCopy, sizeof(outputCopy));

    if (!MeshConsoleBridge_IsApprovedPipeNameW(inputPipeName, L"_in") ||
        !MeshConsoleBridge_IsApprovedPipeNameW(outputPipeName, L"_out") ||
        !MeshConsoleBridge_ResolveShellW(shellName, nonInteractive, shellPath, _countof(shellPath), commandLine, _countof(commandLine)))
    {
        return GetLastError();
    }

    inputPipe = MeshConsoleBridge_OpenPipeClientW(inputPipeName, GENERIC_READ, MESH_CONSOLE_BRIDGE_CONNECT_TIMEOUT_MS);
    if (inputPipe == INVALID_HANDLE_VALUE) { return GetLastError(); }
    outputPipe = MeshConsoleBridge_OpenPipeClientW(outputPipeName, GENERIC_WRITE, MESH_CONSOLE_BRIDGE_CONNECT_TIMEOUT_MS);
    if (outputPipe == INVALID_HANDLE_VALUE) { exitCode = GetLastError(); goto cleanup; }

    if (!MeshConsoleBridge_CreateInheritablePipePair(&childInputRead, &childInputWrite, TRUE, FALSE)) { exitCode = GetLastError(); goto cleanup; }
    if (!MeshConsoleBridge_CreateInheritablePipePair(&childOutputRead, &childOutputWrite, FALSE, TRUE)) { exitCode = GetLastError(); goto cleanup; }

    if (!MeshConsoleBridge_CreateRedirectedShellProcessW(childInputRead, childOutputWrite, shellPath, commandLine, targetSessionId, tokenMode, &processInfo))
    {
        exitCode = GetLastError();
        goto cleanup;
    }

    MeshConsoleBridge_CloseHandle(&childInputRead);
    MeshConsoleBridge_CloseHandle(&childOutputWrite);

    inputCopy.readHandle = inputPipe;
    inputCopy.writeHandle = childInputWrite;
    inputCopy.closeWriteHandleRef = &childInputWrite;
    inputCopy.stopFlag = &inputStopFlag;
    inputCopy.signalStopOnExit = FALSE;
    outputCopy.readHandle = childOutputRead;
    outputCopy.writeHandle = outputPipe;
    outputCopy.closeWriteHandleRef = NULL;
    outputCopy.stopFlag = &outputStopFlag;
    outputCopy.signalStopOnExit = TRUE;

    inputThread = CreateThread(NULL, 0, MeshConsoleBridge_CopyThread, &inputCopy, 0, NULL);
    if (inputThread == NULL) { exitCode = GetLastError(); goto cleanup; }
    if (!MeshConsoleBridge_WriteReadyMarker(outputPipe)) { exitCode = GetLastError(); goto cleanup; }
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

        waitResult = WaitForMultipleObjects(waitCount, waitHandles, FALSE, processCompleted ? MESH_CONSOLE_BRIDGE_EXEC_OUTPUT_DRAIN_MS : INFINITE);
        if (waitResult == WAIT_TIMEOUT && processCompleted)
        {
            // The shell exited, but a process it started inherited its output pipe
            // and keeps it open. Finish the command rather than wait for that process.
            break;
        }
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
            InterlockedExchange(&inputStopFlag, 1);
            MeshConsoleBridge_StopCopyThread(inputThread, 2000);
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
    // A shell still running here means an error path; the bridge is going away.
    if (processInfo.hProcess != NULL && !processCompleted)
    {
        TerminateProcess(processInfo.hProcess, ERROR_OPERATION_ABORTED);
    }
    InterlockedExchange(&inputStopFlag, 1);
    InterlockedExchange(&outputStopFlag, 1);
    // Each worker may be blocked in either ReadFile or WriteFile. Join it
    // before closing either of its handles or returning its stack context.
    MeshConsoleBridge_StopCopyThread(inputThread, 2000);
    MeshConsoleBridge_StopCopyThread(outputThread, 2000);
    MeshConsoleBridge_CloseHandle(&childInputWrite);
    MeshConsoleBridge_CloseHandle(&childInputRead);
    MeshConsoleBridge_CloseHandle(&childOutputRead);
    MeshConsoleBridge_CloseHandle(&childOutputWrite);
    MeshConsoleBridge_CloseHandle(&outputPipe);
    MeshConsoleBridge_CloseHandle(&inputPipe);
    if (inputThread != NULL) { CloseHandle(inputThread); }
    if (outputThread != NULL) { CloseHandle(outputThread); }
    if (processInfo.hThread != NULL) { CloseHandle(processInfo.hThread); }
    if (processInfo.hProcess != NULL) { CloseHandle(processInfo.hProcess); }
    return exitCode;
}

static DWORD MeshConsoleBridge_RunExecW(const wchar_t* inputPipeName, const wchar_t* outputPipeName, const wchar_t* shellName, DWORD targetSessionId, MeshProcessTokenMode tokenMode)
{
    return MeshConsoleBridge_RunRedirectedShellW(inputPipeName, outputPipeName, shellName, targetSessionId, tokenMode, TRUE);
}

static DWORD MeshConsoleBridge_RunW(const wchar_t* inputPipeName, const wchar_t* outputPipeName, const wchar_t* shellName, DWORD cols, DWORD rows, DWORD targetSessionId, MeshProcessTokenMode tokenMode)
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
    COORD consoleSize;
    wchar_t shellPath[MAX_PATH * 4] = {0};
    wchar_t commandLine[MAX_PATH * 4] = {0};
    volatile LONG inputStopFlag = 0;
    volatile LONG outputStopFlag = 0;
    BOOL processCompleted = FALSE;
    BOOL inputCompleted = FALSE;
    BOOL outputCompleted = FALSE;
    DWORD exitCode = ERROR_GEN_FAILURE;
    HRESULT hr = S_OK;
    ZeroMemory(&conptyApi, sizeof(conptyApi));
    ZeroMemory(&processInfo, sizeof(processInfo));
    ZeroMemory(&inputCopy, sizeof(inputCopy));
    ZeroMemory(&outputCopy, sizeof(outputCopy));
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
    if (!MeshConsoleBridge_CreateConptyPipePairW(L"in", &ptyInputRead, &ptyInputWrite)) { exitCode = GetLastError(); goto cleanup; }
    if (!MeshConsoleBridge_CreateConptyPipePairW(L"out", &ptyOutputWrite, &ptyOutputRead)) { exitCode = GetLastError(); goto cleanup; }
    consoleSize.X = (SHORT)cols;
    consoleSize.Y = (SHORT)rows;
    hr = conptyApi.CreatePseudoConsoleFn(consoleSize, ptyInputRead, ptyOutputWrite, 0, &pseudoConsole);
    if (FAILED(hr) || pseudoConsole == NULL)
    {
        exitCode = HRESULT_CODE(hr);
        if (exitCode == ERROR_SUCCESS) { exitCode = ERROR_NOT_SUPPORTED; }
        goto cleanup;
    }
    // The pseudo console holds its own copies of its pipe ends. Release ours now:
    // while the bridge keeps ptyOutputWrite open, a read of ptyOutputRead can never
    // see EOF, so a failed shell launch would leave the output thread blocked.
    MeshConsoleBridge_CloseHandle(&ptyInputRead);
    MeshConsoleBridge_CloseHandle(&ptyOutputWrite);
    inputCopy.readHandle = inputPipe;
    inputCopy.writeHandle = ptyInputWrite;
    inputCopy.closeWriteHandleRef = &ptyInputWrite;
    inputCopy.stopFlag = &inputStopFlag;
    inputCopy.signalStopOnExit = FALSE;
    outputCopy.readHandle = ptyOutputRead;
    outputCopy.writeHandle = outputPipe;
    outputCopy.closeWriteHandleRef = NULL;
    outputCopy.stopFlag = &outputStopFlag;
    outputCopy.signalStopOnExit = TRUE;
    outputThread = CreateThread(NULL, 0, MeshConsoleBridge_CopyThread, &outputCopy, 0, NULL);
    if (outputThread == NULL) { exitCode = GetLastError(); goto cleanup; }
    if (!MeshConsoleBridge_CreateShellProcessW(pseudoConsole, shellPath, commandLine, targetSessionId, tokenMode, &processInfo))
    {
        exitCode = GetLastError();
        goto cleanup;
    }
    inputThread = CreateThread(NULL, 0, MeshConsoleBridge_CopyThread, &inputCopy, 0, NULL);
    if (inputThread == NULL) { exitCode = GetLastError(); goto cleanup; }
    if (!MeshConsoleBridge_WriteReadyMarker(outputPipe)) { exitCode = GetLastError(); goto cleanup; }

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
            // Cleanup closes conhost while a separate worker drains final output.
            break;
        }
        else if (waitKinds[signaledIndex] == 2)
        {
            inputCompleted = TRUE;
            MeshConsoleBridge_CloseHandle(&ptyInputWrite);
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
    // A shell still running here means an error path; the bridge is going away.
    if (processInfo.hProcess != NULL && !processCompleted)
    {
        TerminateProcess(processInfo.hProcess, ERROR_OPERATION_ABORTED);
    }
    InterlockedExchange(&inputStopFlag, 1);
    MeshConsoleBridge_StopCopyThread(inputThread, 2000);
    MeshConsoleBridge_CloseHandle(&ptyInputWrite);
    MeshConsoleBridge_ClosePseudoConsole(&pseudoConsole, conptyApi.ClosePseudoConsoleFn,
        outputThread, &outputStopFlag, &ptyOutputRead);
    // ClosePseudoConsole has finished producing data. Give the forwarder the
    // same bounded grace to deliver buffered output, then release blocked I/O.
    if (outputThread != NULL) { (void)WaitForSingleObject(outputThread, MESH_CONSOLE_BRIDGE_EXEC_OUTPUT_DRAIN_MS); }
    InterlockedExchange(&outputStopFlag, 1);
    MeshConsoleBridge_StopCopyThread(outputThread, 2000);
    MeshConsoleBridge_CloseHandle(&ptyOutputRead);
    MeshConsoleBridge_CloseHandle(&ptyInputRead);
    MeshConsoleBridge_CloseHandle(&ptyOutputWrite);
    MeshConsoleBridge_CloseHandle(&outputPipe);
    MeshConsoleBridge_CloseHandle(&inputPipe);
    if (inputThread != NULL) { CloseHandle(inputThread); }
    if (outputThread != NULL) { CloseHandle(outputThread); }
    if (processInfo.hThread != NULL) { CloseHandle(processInfo.hThread); }
    if (processInfo.hProcess != NULL) { CloseHandle(processInfo.hProcess); }
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

    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_UMH_HOST_W, lpCmdLine, tail, _countof(tail)) ||
        !MeshRuntimeHost_CopyFirstTokenW(tail, manifestPath, _countof(manifestPath)))
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

    ServiceDeploy_EnsureLoggingDefaults();
    ServiceDeploy_LogInstallEvent(L"[UMH_HOST] Starting exe=%ls arg0=%ls manifest=%ls",
        manifest.exePath,
        manifest.argCount > 0 ? manifest.args[0] : L"(none)",
        manifest.manifestPath);
    exitCode = MeshUmhHost_RunManifestCommandW(&manifest);
    ServiceDeploy_LogInstallEvent(L"[UMH_HOST] Completed exe=%ls arg0=%ls exit=%lu",
        manifest.exePath,
        manifest.argCount > 0 ? manifest.args[0] : L"(none)",
        (unsigned long)exitCode);
    ExitProcess(exitCode);
}

void CALLBACK MeshUserConsentW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[MAX_PATH * 8] = {0};
    const wchar_t* cursor = NULL;
    wchar_t resultPipeName[MAX_PATH * 4] = {0};
    wchar_t manifestPath[MAX_PATH * 4] = {0};
    wchar_t extraToken[2] = {0};
    MeshUserConsentManifest manifest;
    DWORD exitCode = ERROR_GEN_FAILURE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    ZeroMemory(&manifest, sizeof(manifest));

    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_USER_CONSENT_W, lpCmdLine, tail, _countof(tail)))
    {
        exitCode = GetLastError();
        if (exitCode == ERROR_SUCCESS) { exitCode = ERROR_INVALID_PARAMETER; }
        ExitProcess(exitCode);
    }

    cursor = tail;
    if (!MeshRuntimeHost_CopyNextTokenW(&cursor, resultPipeName, _countof(resultPipeName)) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, manifestPath, _countof(manifestPath)) ||
        (MeshRuntimeHost_CopyNextTokenW(&cursor, extraToken, _countof(extraToken)) ? (SetLastError(ERROR_INVALID_PARAMETER), TRUE) : FALSE) ||
        GetLastError() != ERROR_NO_MORE_ITEMS ||
        !MeshUserConsent_IsApprovedResultPipeNameW(resultPipeName))
    {
        exitCode = GetLastError();
        if (exitCode == ERROR_SUCCESS || exitCode == ERROR_NO_MORE_ITEMS) { exitCode = ERROR_INVALID_PARAMETER; }
        ExitProcess(exitCode);
    }

    if (!MeshUserConsent_ReadManifestW(manifestPath, &manifest))
    {
        exitCode = GetLastError();
        if (exitCode == ERROR_SUCCESS) { exitCode = ERROR_INVALID_DATA; }
        ExitProcess(exitCode);
    }

    ServiceDeploy_EnsureLoggingDefaults();
    ServiceDeploy_LogInstallEvent(L"[USER_CONSENT] Prompt starting session=%lu timeoutMs=%lu autoAccept=%d manifest=%ls",
        (unsigned long)manifest.sessionId,
        (unsigned long)manifest.timeoutMs,
        manifest.timeoutAutoAccept ? 1 : 0,
        manifest.manifestPath);
    exitCode = MeshUserConsent_RunW(resultPipeName, &manifest);
    ServiceDeploy_LogInstallEvent(L"[USER_CONSENT] Prompt completed session=%lu exit=%lu",
        (unsigned long)manifest.sessionId,
        (unsigned long)exitCode);
    ExitProcess(exitCode);
}

void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[MAX_PATH * 6] = {0};
    wchar_t manifestPath[MAX_PATH * 4] = {0};
    MeshRuntimeHostLifecycleManifest manifest;
    BOOL ok = FALSE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    ZeroMemory(&manifest, sizeof(manifest));

    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_LIFECYCLE_W, lpCmdLine, tail, _countof(tail)) ||
        !MeshRuntimeHost_CopyFirstTokenW(tail, manifestPath, _countof(manifestPath)))
    {
        ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-LifecycleHost.log");
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE_HOST] Missing manifest path (error=%lu)", GetLastError());
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    if (!MeshRuntimeHost_ReadLifecycleManifestW(manifestPath, &manifest))
    {
        ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-LifecycleHost.log");
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE_HOST] Failed to read manifest %ls (error=%lu)", manifestPath, GetLastError());
        ExitProcess(ERROR_INVALID_DATA);
    }
    // The manifest is read once. Remove it now: the launcher may not survive the
    // action (an update stops the service that launched this host) to clean it up.
    (void)DeleteFileW(manifestPath);

    MeshRuntimeHost_ApplyBrandingFromManifest(&manifest);
    if (manifest.action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL)
    {
        ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log");
    }
    else
    {
        ServiceDeploy_EnsureLoggingDefaults();
    }
    ServiceDeploy_LogInstallEvent(L"[LIFECYCLE_HOST] Starting action=%ls manifest=%ls",
        MeshRuntimeHost_LifecycleActionNameW(manifest.action),
        manifest.manifestPath);

    ok = ServiceDeploy_RunLifecycleHostOperation(
        MeshRuntimeHost_LifecycleActionNameW(manifest.action),
        manifest.sourceExePath[0] != L'\0' ? manifest.sourceExePath : NULL,
        manifest.sourceDllPath[0] != L'\0' ? manifest.sourceDllPath : NULL,
        manifest.requireConfig);

    ServiceDeploy_LogInstallEvent(L"[LIFECYCLE_HOST] Completed action=%ls status=%ls",
        MeshRuntimeHost_LifecycleActionNameW(manifest.action),
        ok ? L"success" : L"failed");
    // ExitProcess bypasses CRT shutdown; preserve redirected validation JSON.
    if (fflush(stdout) != 0) { ok = FALSE; }
    (void)fflush(stderr);
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

    ServiceDeploy_EnsureLoggingDefaults();
    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_LAUNCHER_CLEANUP_W, lpCmdLine, tail, _countof(tail)))
    {
        ServiceDeploy_LogInstallEvent(L"[LAUNCHER_CLEANUP] Missing cleanup arguments (error=%lu)", GetLastError());
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    cursor = tail;
    if (!MeshRuntimeHost_CopyNextTokenW(&cursor, targetPath, _countof(targetPath)) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, parentPidText, _countof(parentPidText)))
    {
        ServiceDeploy_LogInstallEvent(L"[LAUNCHER_CLEANUP] Invalid cleanup arguments tail=%ls error=%lu", tail, GetLastError());
        ExitProcess(ERROR_INVALID_PARAMETER);
    }
    if (MeshRuntimeHost_CopyNextTokenW(&cursor, timeoutText, _countof(timeoutText)))
    {
        timeoutMs = wcstoul(timeoutText, NULL, 10);
        if (timeoutMs == 0) { timeoutMs = 60000; }
    }
    parentPid = wcstoul(parentPidText, NULL, 10);

    result = MeshRuntimeHost_DeleteLauncherAfterParentExitW(targetPath, parentPid, timeoutMs);
    ServiceDeploy_LogInstallEvent(L"[LAUNCHER_CLEANUP] Completed target=%ls parentPid=%lu result=%lu",
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

    ServiceDeploy_EnsureLoggingDefaults();
    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_PREPROTECTION_CAPTURE_W, lpCmdLine, tail, _countof(tail)) ||
        !MeshRuntimeHost_CopyFirstTokenW(tail, capturePath, _countof(capturePath)))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[PREPROTECTION_CAPTURE] Missing capture path (error=%lu)", error);
        printf("{\"ok\":false,\"error\":\"capture-path-missing\",\"win32_error\":%lu}\n", (unsigned long)error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    ServiceDeploy_LogInstallEvent(L"[PREPROTECTION_CAPTURE] Starting capture path=%ls", capturePath);
    #if defined(MESHAGENT_ENABLE_RUNTIME_FEATURES)
    ok = MeshAgent_RunPreProtectionCaptureValidationW(capturePath);
#else
    (void)capturePath;
    ok = FALSE;
#endif
    ServiceDeploy_LogInstallEvent(L"[PREPROTECTION_CAPTURE] Completed status=%ls path=%ls", ok ? L"success" : L"failed", capturePath);
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

    ServiceDeploy_EnsureLoggingDefaults();
    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_SELFTEST_W, lpCmdLine, tail, _countof(tail)))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] Missing self-test arguments (error=%lu)", error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    while (*arguments == L' ' || *arguments == L'\t') { ++arguments; }
    if (*arguments == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] Empty self-test arguments");
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] Starting self-test");
    exitCode = MeshService_RunSelfTestHostW(arguments);
    ServiceDeploy_LogInstallEvent(L"[SELFTEST_HOST] Completed exit=%d", exitCode);
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

    ServiceDeploy_EnsureLoggingDefaults();
    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_KVM_PROBE_W, lpCmdLine, tail, _countof(tail)))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[KVM_PROBE_HOST] Missing probe arguments (error=%lu)", error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    while (*arguments == L' ' || *arguments == L'\t') { ++arguments; }
    if (*arguments == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"[KVM_PROBE_HOST] Empty probe arguments");
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    ServiceDeploy_LogInstallEvent(L"[KVM_PROBE_HOST] Starting probe host");
    exitCode = MeshService_RunKvmProbeHostW(arguments);
    ServiceDeploy_LogInstallEvent(L"[KVM_PROBE_HOST] Completed exit=%d", exitCode);
    ExitProcess((DWORD)exitCode);
}

static BOOL MeshConsoleBridge_ParseArgumentsW(const wchar_t* tail, wchar_t* inputPipeName, size_t inputPipeNameCch, wchar_t* outputPipeName, size_t outputPipeNameCch, wchar_t* shellName, size_t shellNameCch, DWORD* cols, DWORD* rows, DWORD* targetSessionId, BOOL* execMode, MeshProcessTokenMode* tokenMode)
{
    wchar_t colsText[16] = {0};
    wchar_t rowsText[16] = {0};
    wchar_t optionText[32] = {0};
    const wchar_t* cursor = tail;
    BOOL sessionSeen = FALSE;
    BOOL modeSeen = FALSE;
    BOOL tokenSeen = FALSE;

    if (tail == NULL || inputPipeName == NULL || outputPipeName == NULL || shellName == NULL || cols == NULL || rows == NULL || targetSessionId == NULL || execMode == NULL || tokenMode == NULL)
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
    *tokenMode = MeshProcessToken_Privileged;

    if (!MeshRuntimeHost_CopyNextTokenW(&cursor, inputPipeName, inputPipeNameCch) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, outputPipeName, outputPipeNameCch) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, shellName, shellNameCch) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, colsText, _countof(colsText)) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, rowsText, _countof(rowsText)) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(colsText, 20, 300, cols) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(rowsText, 10, 100, rows))
    {
        return FALSE;
    }

    for (;;)
    {
        optionText[0] = L'\0';
        if (!MeshRuntimeHost_CopyNextTokenW(&cursor, optionText, _countof(optionText)))
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
        else if (_wcsicmp(optionText, L"token=privileged-agent") == 0 ||
            _wcsicmp(optionText, L"token=session-user") == 0)
        {
            if (tokenSeen) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
            tokenSeen = TRUE;
            *tokenMode = _wcsicmp(optionText, L"token=session-user") == 0 ? MeshProcessToken_SessionUser : MeshProcessToken_Privileged;
        }
        else
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    if (!tokenSeen ||
        (*tokenMode == MeshProcessToken_Privileged && sessionSeen) ||
        (*tokenMode == MeshProcessToken_SessionUser && (!sessionSeen || *targetSessionId == 0)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
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
    MeshProcessTokenMode tokenMode = MeshProcessToken_Privileged;
    BOOL parsedArguments = FALSE;
    DWORD exitCode = ERROR_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    ServiceDeploy_EnsureLoggingDefaults();
    if (!MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_W, lpCmdLine, tail, _countof(tail)))
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[CONSOLE_BRIDGE] Missing arguments (error=%lu)", (unsigned long)error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    parsedArguments = MeshConsoleBridge_ParseArgumentsW(tail, inputPipeName, _countof(inputPipeName), outputPipeName, _countof(outputPipeName), shellName, _countof(shellName), &cols, &rows, &targetSessionId, &execMode, &tokenMode);
    if (!parsedArguments && lpCmdLine != NULL && lpCmdLine[0] != L'\0')
    {
        parsedArguments = MeshConsoleBridge_ParseArgumentsW(lpCmdLine, inputPipeName, _countof(inputPipeName), outputPipeName, _countof(outputPipeName), shellName, _countof(shellName), &cols, &rows, &targetSessionId, &execMode, &tokenMode);
    }
    if (!parsedArguments)
    {
        DWORD error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[CONSOLE_BRIDGE] Invalid arguments tail=%ls error=%lu", tail, (unsigned long)error);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    ServiceDeploy_LogInstallEvent(L"[CONSOLE_BRIDGE] Starting shell=%ls mode=%ls token_mode=%ls cols=%lu rows=%lu session=%lu input=%ls output=%ls",
        shellName,
        execMode ? L"exec" : L"pty",
        tokenMode == MeshProcessToken_Privileged ? L"privileged-agent" : L"session-user",
        (unsigned long)cols,
        (unsigned long)rows,
        (unsigned long)targetSessionId,
        inputPipeName,
        outputPipeName);
    {
        // The agent hands this helper inheritable std handles. Exec mode starts the
        // shell with handle inheritance for its redirected pipes, which would also
        // pass these on to the shell and anything it launches.
        HANDLE stdHandle = GetStdHandle(STD_INPUT_HANDLE);
        if (stdHandle != NULL && stdHandle != INVALID_HANDLE_VALUE) { SetHandleInformation(stdHandle, HANDLE_FLAG_INHERIT, 0); }
        stdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (stdHandle != NULL && stdHandle != INVALID_HANDLE_VALUE) { SetHandleInformation(stdHandle, HANDLE_FLAG_INHERIT, 0); }
        stdHandle = GetStdHandle(STD_ERROR_HANDLE);
        if (stdHandle != NULL && stdHandle != INVALID_HANDLE_VALUE) { SetHandleInformation(stdHandle, HANDLE_FLAG_INHERIT, 0); }
    }
    exitCode = execMode ?
        MeshConsoleBridge_RunExecW(inputPipeName, outputPipeName, shellName, targetSessionId, tokenMode) :
        MeshConsoleBridge_RunW(inputPipeName, outputPipeName, shellName, cols, rows, targetSessionId, tokenMode);
    ServiceDeploy_LogInstallEvent(L"[CONSOLE_BRIDGE] Completed exit=%lu", (unsigned long)exitCode);
    ExitProcess(exitCode);
}
