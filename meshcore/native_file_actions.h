#ifndef MESH_NATIVE_FILE_ACTIONS_H
#define MESH_NATIVE_FILE_ACTIONS_H

#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <stdlib.h>
#include <wctype.h>
#include "../meshservice/process_token_contract.h"
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wtsapi32.lib")

#define MESH_FILE_PATH_CHARS 32768

// File paths are literal data. Device paths, relative paths and command text are
// not part of this API. In particular, no shell interprets the selected name.
static BOOL MeshFileAction_Path(const wchar_t* path, wchar_t* full)
{
    size_t i, length;
    DWORD count;
    if (path == NULL || full == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    length = wcsnlen_s(path, MESH_FILE_PATH_CHARS);
    if (length == 0 || length >= MESH_FILE_PATH_CHARS ||
        !((iswalpha(path[0]) && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) ||
          (length > 4 && path[0] == L'\\' && path[1] == L'\\' && path[2] != L'?' && path[2] != L'.')))
    { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    for (i = 0; i < length; ++i)
    {
        if (path[i] < 32 || wcschr(L"\"<>|?*", path[i]) != NULL || (path[i] == L':' && i != 1))
        { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    }
    count = GetFullPathNameW(path, MESH_FILE_PATH_CHARS, full, NULL);
    if (count == 0 || count >= MESH_FILE_PATH_CHARS) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    return TRUE;
}

// Expand only the association's single literal file placeholder. Unknown shell
// placeholders fail closed; this never supplies shell command text or arguments
// from the remote request. Windows file names cannot contain a double quote.
static BOOL MeshFileAction_AssociationCommand(const wchar_t* format, const wchar_t* path, wchar_t* command)
{
    size_t i, used = 0, length = wcslen(path), j, trailing = 0;
    BOOL quoted = FALSE, substituted = FALSE;
    for (j = length; j > 0 && path[j - 1] == L'\\'; --j) { ++trailing; }
    for (i = 0; format[i] != 0; ++i)
    {
        if (format[i] == L'%')
        {
            wchar_t code = format[++i];
            if (code == L'*') { continue; }
            if (code != L'1' && code != L'l' && code != L'L') { SetLastError(ERROR_NO_ASSOCIATION); return FALSE; }
            if (used + length + trailing + 4 >= MESH_FILE_PATH_CHARS) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
            if (!quoted) { command[used++] = L'"'; }
            for (j = 0; j < length; ++j) { command[used++] = path[j]; }
            // Escape trailing backslashes before the closing argument quote.
            for (j = length; j > 0 && path[j - 1] == L'\\'; --j) { command[used++] = L'\\'; }
            if (!quoted) { command[used++] = L'"'; }
            substituted = TRUE;
        }
        else
        {
            if (used + 1 >= MESH_FILE_PATH_CHARS) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
            if (format[i] == L'"') { quoted = !quoted; }
            command[used++] = format[i];
        }
    }
    command[used] = 0;
    if (!substituted || quoted) { SetLastError(ERROR_NO_ASSOCIATION); return FALSE; }
    return TRUE;
}

// Hold each enumerated directory against replacement. Junctions and symbolic
// links are leaves: deleting a tree must never walk into their targets.
static BOOL MeshFileAction_DeleteTree(const wchar_t* path, BOOL recursive, unsigned depth, DWORD* count)
{
    DWORD attributes = GetFileAttributesW(path), error;
    HANDLE directory = INVALID_HANDLE_VALUE, search = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW entry;
    BY_HANDLE_FILE_INFORMATION info;
    wchar_t* child = NULL;
    BOOL ok = FALSE;
    if (attributes == INVALID_FILE_ATTRIBUTES) { return FALSE; }
    if (depth >= 128 || *count >= 100000) { SetLastError(ERROR_BUFFER_OVERFLOW); return FALSE; }
    if (recursive && (attributes & FILE_ATTRIBUTE_DIRECTORY) && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        directory = CreateFileW(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (directory == INVALID_HANDLE_VALUE) { goto cleanup; }
        if (!GetFileInformationByHandle(directory, &info)) { goto cleanup; }
        attributes = info.dwFileAttributes;
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) { SetLastError(ERROR_DIRECTORY); goto cleanup; }
        if (!(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            child = (wchar_t*)calloc(MESH_FILE_PATH_CHARS, sizeof(wchar_t));
            if (!child) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto cleanup; }
            if (FAILED(StringCchPrintfW(child, MESH_FILE_PATH_CHARS, L"%ls\\*", path))) { SetLastError(ERROR_INSUFFICIENT_BUFFER); goto cleanup; }
            search = FindFirstFileW(child, &entry);
            if (search == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND) { goto cleanup; }
            if (search != INVALID_HANDLE_VALUE)
            {
                do
                {
                    if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0) { continue; }
                    if (FAILED(StringCchPrintfW(child, MESH_FILE_PATH_CHARS, L"%ls\\%ls", path, entry.cFileName)))
                    { SetLastError(ERROR_INSUFFICIENT_BUFFER); goto cleanup; }
                    if (!MeshFileAction_DeleteTree(child, TRUE, depth + 1, count)) { goto cleanup; }
                } while (FindNextFileW(search, &entry));
                if (GetLastError() != ERROR_NO_MORE_FILES) { goto cleanup; }
                FindClose(search); search = INVALID_HANDLE_VALUE;
            }
        }
        CloseHandle(directory); directory = INVALID_HANDLE_VALUE;
    }
    ok = (attributes & FILE_ATTRIBUTE_DIRECTORY) ? RemoveDirectoryW(path) : DeleteFileW(path);
    if (ok) { ++*count; }
cleanup:
    error = ok ? ERROR_SUCCESS : GetLastError();
    if (search != INVALID_HANDLE_VALUE) { FindClose(search); }
    if (directory != INVALID_HANDLE_VALUE) { CloseHandle(directory); }
    free(child);
    SetLastError(error);
    return ok;
}

static BOOL MeshFileAction_Delete(const wchar_t* path, BOOL recursive, DWORD* count)
{
    wchar_t* full = (wchar_t*)calloc(MESH_FILE_PATH_CHARS, sizeof(wchar_t));
    DWORD error;
    BOOL ok = FALSE;
    if (!full) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    *count = 0;
    if (MeshFileAction_Path(path, full))
    {
        if (PathIsRootW(full)) { SetLastError(ERROR_ACCESS_DENIED); }
        else { ok = MeshFileAction_DeleteTree(full, recursive, 0, count); }
    }
    error = ok ? ERROR_SUCCESS : GetLastError();
    free(full); SetLastError(error); return ok;
}

static BOOL MeshFileAction_Launch(const wchar_t* requestedPath, BOOL openAssociation, BOOL privileged, DWORD* pid)
{
    HANDLE token = NULL, impersonation = NULL, previous = NULL;
    LPVOID environment = NULL;
    wchar_t *full = NULL, *application = NULL, *command = NULL, *format = NULL, *expanded = NULL, *directory = NULL;
    DWORD attributes, size, error = ERROR_SUCCESS, session = WTSGetActiveConsoleSessionId(), ownSession;
    BOOL ok = FALSE, currentUser = FALSE, impersonating = FALSE;
    MeshProcessTokenMode mode = privileged ? MeshProcessToken_Privileged : MeshProcessToken_SessionUser;
    MeshProcessTokenSnapshot snapshot;
    STARTUPINFOW startup;
    PROCESS_INFORMATION child;
    ZeroMemory(&child, sizeof(child));
    if (pid == NULL || (openAssociation && privileged)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *pid = 0;
    full = (wchar_t*)calloc(6 * MESH_FILE_PATH_CHARS, sizeof(wchar_t));
    if (full == NULL) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    application = full + MESH_FILE_PATH_CHARS; command = application + MESH_FILE_PATH_CHARS;
    format = command + MESH_FILE_PATH_CHARS; expanded = format + MESH_FILE_PATH_CHARS; directory = expanded + MESH_FILE_PATH_CHARS;
    if (!MeshFileAction_Path(requestedPath, full)) { goto cleanup; }
    if (!MeshProcessToken_Open(mode, privileged ? MESH_PROCESS_TOKEN_CURRENT_SESSION : session, &token))
    {
        // A console-mode agent can use its own unelevated interactive identity.
        // A service never substitutes its SYSTEM identity for an absent user.
        if (privileged || session == MAXDWORD || session == 0 ||
            !ProcessIdToSessionId(GetCurrentProcessId(), &ownSession) || ownSession != session ||
            !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token) ||
            !MeshProcessToken_Read(token, &snapshot) || snapshot.system || snapshot.elevated || snapshot.sessionId != session)
        { goto cleanup; }
        currentUser = TRUE;
    }
    if (!privileged)
    {
        if (!DuplicateTokenEx(token, TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &impersonation)) { goto cleanup; }
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, TRUE, &previous) && GetLastError() != ERROR_NO_TOKEN) { goto cleanup; }
        if (!SetThreadToken(NULL, impersonation)) { goto cleanup; }
        impersonating = TRUE;
    }
    attributes = GetFileAttributesW(full);
    if (attributes == INVALID_FILE_ATTRIBUTES) { goto cleanup; }
    if (!openAssociation || (!(attributes & FILE_ATTRIBUTE_DIRECTORY) && _wcsicmp(PathFindExtensionW(full), L".exe") == 0))
    {
        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) || _wcsicmp(PathFindExtensionW(full), L".exe") != 0)
        { SetLastError(ERROR_BAD_EXE_FORMAT); goto cleanup; }
        wcscpy_s(application, MESH_FILE_PATH_CHARS, full);
        if (FAILED(StringCchPrintfW(command, MESH_FILE_PATH_CHARS, L"\"%ls\"", full))) { SetLastError(ERROR_INSUFFICIENT_BUFFER); goto cleanup; }
    }
    else if (attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        size = GetWindowsDirectoryW(application, MESH_FILE_PATH_CHARS);
        if (!size || size + 14 >= MESH_FILE_PATH_CHARS) { SetLastError(ERROR_INSUFFICIENT_BUFFER); goto cleanup; }
        wcscat_s(application, MESH_FILE_PATH_CHARS, L"\\explorer.exe");
        if (!MeshFileAction_AssociationCommand(L"explorer.exe \"%1\"", full, command)) { goto cleanup; }
    }
    else
    {
        size = MESH_FILE_PATH_CHARS;
        if (FAILED(AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE, PathFindExtensionW(full), L"open", application, &size)))
        { SetLastError(ERROR_NO_ASSOCIATION); goto cleanup; }
        size = MESH_FILE_PATH_CHARS;
        if (FAILED(AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_COMMAND, PathFindExtensionW(full), L"open", format, &size)) ||
            !ExpandEnvironmentStringsForUserW(token, format, expanded, MESH_FILE_PATH_CHARS) ||
            !MeshFileAction_AssociationCommand(expanded, full, command)) { SetLastError(ERROR_NO_ASSOCIATION); goto cleanup; }
    }
    if (!MeshFileAction_Path(application, format)) { goto cleanup; }
    wcscpy_s(application, MESH_FILE_PATH_CHARS, format);
    wcscpy_s(directory, MESH_FILE_PATH_CHARS, full);
    if (!PathRemoveFileSpecW(directory)) { SetLastError(ERROR_INVALID_NAME); goto cleanup; }
    if (impersonating)
    {
        if (!SetThreadToken(NULL, previous)) { goto cleanup; }
        impersonating = FALSE;
    }
    if (!CreateEnvironmentBlock(&environment, token, FALSE)) { goto cleanup; }
    ZeroMemory(&startup, sizeof(startup)); startup.cb = sizeof(startup);
    startup.lpDesktop = privileged ? NULL : L"winsta0\\default";
    if (currentUser)
        ok = CreateProcessW(application, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment, directory, &startup, &child);
    else
        ok = CreateProcessAsUserW(token, application, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment, directory, &startup, &child);
    if (ok) { ok = MeshProcessToken_VerifyChildAndResume(mode, token, &child); }
    if (ok) { *pid = child.dwProcessId; }
cleanup:
    error = ok ? ERROR_SUCCESS : GetLastError();
    if (impersonating && !SetThreadToken(NULL, previous))
    {
        // Never return to the JavaScript loop under a borrowed identity.
        if (!RevertToSelf()) { TerminateProcess(GetCurrentProcess(), ERROR_CANNOT_IMPERSONATE); }
        error = ERROR_CANNOT_IMPERSONATE; ok = FALSE;
    }
    if (child.hThread) { CloseHandle(child.hThread); }
    if (child.hProcess) { CloseHandle(child.hProcess); }
    if (environment) { DestroyEnvironmentBlock(environment); }
    if (previous) { CloseHandle(previous); }
    if (impersonation) { CloseHandle(impersonation); }
    if (token) { CloseHandle(token); }
    free(full);
    SetLastError(error);
    return ok;
}
#endif
