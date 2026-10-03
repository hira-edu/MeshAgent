#ifndef MESH_DIAGNOSTIC_LOG_H
#define MESH_DIAGNOSTIC_LOG_H

#ifdef WIN32
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <strsafe.h>
#include <sddl.h>
#include "config/active_profile.h"
#include "../meshservice/service_defaults.h"
#pragma comment(lib, "advapi32.lib")

#define MESH_DIAGNOSTIC_LOG_MAX_BYTES (2 * 1024 * 1024)
#define MESH_DIAGNOSTIC_LOG_KEEP_BYTES (1024 * 1024)
#ifdef __cplusplus
extern "C" {
#endif
extern volatile LONG g_MeshDiagnosticLogDisabled;
#ifdef __cplusplus
}
#endif

static __inline BOOL MeshDiagnosticLog_GetPathW(wchar_t* path, size_t count)
{
    wchar_t directory[MAX_PATH * 4] = {0}, name[MAX_PATH] = {0}, expanded[MAX_PATH * 4];
    const mesh_branding_definition_t* branding = MeshConfig_GetBranding();
    DWORD length;
#if defined(UNICODE) || defined(_UNICODE)
    if (FAILED(StringCchCopyW(directory, _countof(directory), branding->logDirectory)) ||
        FAILED(StringCchCopyW(name, _countof(name), branding->logFileName))) { return FALSE; }
#else
    if (!MultiByteToWideChar(CP_UTF8, 0, branding->logDirectory, -1, directory, _countof(directory)) ||
        !MultiByteToWideChar(CP_UTF8, 0, branding->logFileName, -1, name, _countof(name))) { return FALSE; }
#endif
    length = ExpandEnvironmentStringsW(directory, expanded, _countof(expanded));
    if (!length || length > _countof(expanded) || !name[0]) { return FALSE; }
    for (wchar_t* p = expanded; *p; ++p) { if (*p == L'/') { *p = L'\\'; } }
    return SUCCEEDED(StringCchPrintfW(path, count, L"%ls\\%ls", expanded, name));
}

static __inline BOOL MeshDiagnosticLog_Seek(HANDLE file, LONGLONG offset)
{
    LARGE_INTEGER position;
    position.QuadPart = offset;
    return SetFilePointerEx(file, position, NULL, FILE_BEGIN);
}

/* One file lock covers conversion, pruning, and the complete append across processes. */
static __inline BOOL MeshDiagnosticLog_AppendPathW(const wchar_t* path, const char* entry, DWORD length)
{
    HANDLE file;
    OVERLAPPED lock = {0};
    LARGE_INTEGER size;
    DWORD read = 0, written = 0, error = ERROR_SUCCESS;
    BYTE buffer[4096];
    BOOL result = FALSE, locked = FALSE;
    wchar_t directory[MAX_PATH * 4];
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!path || !entry || !length || length > 32768 || FAILED(StringCchCopyW(directory, _countof(directory), path)))
    { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (wchar_t* p = directory + 3; *p; ++p)
    {
        if (*p == L'\\')
        {
            DWORD attributes;
            *p = 0;
            attributes = GetFileAttributesW(directory);
            if (attributes == INVALID_FILE_ATTRIBUTES)
            {
                SECURITY_ATTRIBUTES security = {sizeof(security), NULL, FALSE};
                if (!descriptor && (!ConvertStringSecurityDescriptorToSecurityDescriptorW(SERVICE_SECURE_DIR_DACL_SDDL, SDDL_REVISION_1, &descriptor, NULL) ||
                    !SetSecurityDescriptorControl(descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)))
                { error = GetLastError(); if (descriptor) { LocalFree(descriptor); } SetLastError(error); return FALSE; }
                security.lpSecurityDescriptor = descriptor;
                if (!CreateDirectoryW(directory, &security) && GetLastError() != ERROR_ALREADY_EXISTS)
                { error = GetLastError(); LocalFree(descriptor); SetLastError(error); return FALSE; }
                attributes = GetFileAttributesW(directory);
            }
            if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            { if (descriptor) { LocalFree(descriptor); } SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
            *p = L'\\';
        }
    }
    if (descriptor) { LocalFree(descriptor); }
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) { return FALSE; }
    {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(file, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        { error = ERROR_ACCESS_DENIED; goto done; }
    }
    for (int attempt = 0; attempt < 50; ++attempt)
    {
        if (LockFileEx(file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD, &lock))
        { locked = TRUE; break; }
        error = GetLastError();
        if (error != ERROR_LOCK_VIOLATION) { goto done; }
        Sleep(10);
    }
    if (!locked) { goto done; }
    if (!GetFileSizeEx(file, &size)) { error = GetLastError(); goto done; }

    /* Old installer logs used UTF-16. Convert the bounded tail in place, without a side file or CRT heap. */
    if (size.QuadPart >= 2 && ReadFile(file, buffer, 2, &read, NULL) && read == 2 && buffer[0] == 0xff && buffer[1] == 0xfe)
    {
        LONGLONG start = size.QuadPart > MESH_DIAGNOSTIC_LOG_KEEP_BYTES ? size.QuadPart - MESH_DIAGNOSTIC_LOG_KEEP_BYTES : 2;
        DWORD bytes;
        wchar_t* wide;
        char* utf8;
        int converted;
        start += start & 1;
        bytes = (DWORD)(size.QuadPart - start) & ~1U;
        wide = (wchar_t*)VirtualAlloc(NULL, bytes + 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        utf8 = (char*)VirtualAlloc(NULL, bytes * 2 + 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!wide || !utf8) { error = ERROR_NOT_ENOUGH_MEMORY; }
        else if (!MeshDiagnosticLog_Seek(file, start) || !ReadFile(file, wide, bytes, &read, NULL) || read != bytes)
        { error = ERROR_READ_FAULT; }
        else
        {
            DWORD skip = 0;
            if (start != 2) { while (skip < bytes / 2 && wide[skip++] != L'\n') {} }
            converted = bytes / 2 == skip ? 0 : WideCharToMultiByte(CP_UTF8, 0, wide + skip, bytes / 2 - skip, utf8, bytes * 2 + 4, NULL, NULL);
            if ((bytes / 2 != skip && !converted) || !MeshDiagnosticLog_Seek(file, 0) ||
                (converted && (!WriteFile(file, utf8, converted, &written, NULL) || written != (DWORD)converted)) || !SetEndOfFile(file))
            { error = ERROR_WRITE_FAULT; }
            else { size.QuadPart = converted; error = ERROR_SUCCESS; }
        }
        if (wide) { VirtualFree(wide, 0, MEM_RELEASE); }
        if (utf8) { VirtualFree(utf8, 0, MEM_RELEASE); }
        if (error != ERROR_SUCCESS) { goto done; }
    }
    if (size.QuadPart + length > MESH_DIAGNOSTIC_LOG_MAX_BYTES)
    {
        LONGLONG source = size.QuadPart - MESH_DIAGNOSTIC_LOG_KEEP_BYTES, dest = 0;
        BOOL boundary = FALSE;
        if (source < 0) { source = 0; }
        while (source < size.QuadPart)
        {
            DWORD chunk = (DWORD)((size.QuadPart - source) > sizeof(buffer) ? sizeof(buffer) : size.QuadPart - source), skip = 0;
            if (!MeshDiagnosticLog_Seek(file, source) || !ReadFile(file, buffer, chunk, &read, NULL) || read != chunk)
            { error = ERROR_READ_FAULT; goto done; }
            source += read;
            if (!boundary) { while (skip < read && buffer[skip++] != '\n') {} if (skip && buffer[skip - 1] == '\n') { boundary = TRUE; } }
            if (boundary && read > skip)
            {
                if (!MeshDiagnosticLog_Seek(file, dest) || !WriteFile(file, buffer + skip, read - skip, &written, NULL) || written != read - skip)
                { error = ERROR_WRITE_FAULT; goto done; }
                dest += written;
            }
        }
        size.QuadPart = dest;
        if (!MeshDiagnosticLog_Seek(file, dest) || !SetEndOfFile(file)) { error = GetLastError(); goto done; }
    }
    if (!MeshDiagnosticLog_Seek(file, size.QuadPart) || !WriteFile(file, entry, length, &written, NULL) || written != length || !FlushFileBuffers(file))
    { error = GetLastError(); if (!error) { error = ERROR_WRITE_FAULT; } goto done; }
    result = TRUE;
done:
    if (locked) { UnlockFileEx(file, 0, MAXDWORD, MAXDWORD, &lock); }
    CloseHandle(file);
    SetLastError(result ? ERROR_SUCCESS : error);
    return result;
}

static __inline BOOL MeshDiagnosticLog_Write(const char* component, const char* message)
{
    DWORD savedError = GetLastError();
    wchar_t path[MAX_PATH * 4];
    char entry[16384];
    SYSTEMTIME now;
    int length;
    BOOL result = FALSE;
    if (InterlockedCompareExchange(&g_MeshDiagnosticLogDisabled, 0, 0)) { return FALSE; }
    GetLocalTime(&now);
    length = _snprintf_s(entry, sizeof(entry), _TRUNCATE,
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u] [pid=%lu tid=%lu] [%s] %s\r\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds,
        GetCurrentProcessId(), GetCurrentThreadId(), component, message ? message : "");
    if (length < 0) { length = (int)strlen(entry); }
    if (MeshDiagnosticLog_GetPathW(path, _countof(path))) { result = MeshDiagnosticLog_AppendPathW(path, entry, length); }
    if (!result) { OutputDebugStringA("[MeshAgent LOG_WRITE_FAILURE] Unable to append unified diagnostics log\n"); }
    SetLastError(savedError);
    return result;
}

static __inline BOOL MeshDiagnosticLog_VPrintfW(const char* component, const wchar_t* format, va_list args)
{
    DWORD savedError = GetLastError();
    wchar_t message[4096];
    char utf8[16384];
    BOOL result = FALSE;
    _vsnwprintf_s(message, _countof(message), _TRUNCATE, format, args);
    if (WideCharToMultiByte(CP_UTF8, 0, message, -1, utf8, sizeof(utf8), NULL, NULL)) { result = MeshDiagnosticLog_Write(component, utf8); }
    SetLastError(savedError);
    return result;
}

static __inline BOOL MeshDiagnosticLog_PrintfW(const char* component, const wchar_t* format, ...)
{
    BOOL result;
    va_list args;
    va_start(args, format);
    result = MeshDiagnosticLog_VPrintfW(component, format, args);
    va_end(args);
    return result;
}
static __inline BOOL MeshDiagnosticLog_Printf(const char* component, const char* format, ...)
{
    DWORD savedError = GetLastError();
    char message[4096];
    BOOL result;
    va_list args;
    va_start(args, format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    va_end(args);
    result = MeshDiagnosticLog_Write(component, message);
    SetLastError(savedError);
    return result;
}
#endif
#endif
