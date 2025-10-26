#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
#include <strsafe.h>
#include "stealth_utils.h"

static void WriteDebugStringA(const char* message)
{
    if (message == NULL) { return; }
    OutputDebugStringA(message);
#if defined(_DEBUG)
    fputs(message, stdout);
#endif
}

static void WriteDebugStringW(const wchar_t* message)
{
    if (message == NULL) { return; }
    OutputDebugStringW(message);
#if defined(_DEBUG)
    fputws(message, stdout);
#endif
}

void Stealth_DebugPrintfA(const char* format, ...)
{
    if (format == NULL) { return; }

    char buffer[1024];
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);

    WriteDebugStringA(buffer);
    if (buffer[0] != 0 && buffer[strlen(buffer) - 1] != '\n')
    {
        WriteDebugStringA("\n");
    }
}

void Stealth_DebugPrintfW(const wchar_t* format, ...)
{
    if (format == NULL) { return; }

    wchar_t buffer[1024];
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), _TRUNCATE, format, args);
    va_end(args);

    WriteDebugStringW(buffer);
    size_t len = wcslen(buffer);
    if (len > 0 && buffer[len - 1] != L'\n')
    {
        WriteDebugStringW(L"\n");
    }
}

static void DebugLastErrorInternalA(const char* context)
{
    DWORD errorCode = GetLastError();
    if (errorCode == 0) { return; }

    char message[512];
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD length = FormatMessageA(flags, NULL, errorCode, 0, message, (DWORD)sizeof(message), NULL);
    if (length == 0)
    {
        _snprintf_s(message, sizeof(message), _TRUNCATE, "Unknown error 0x%08lX", errorCode);
    }

    if (context != NULL)
    {
        Stealth_DebugPrintfA("%s failed with error %lu (%s)", context, errorCode, message);
    }
    else
    {
        Stealth_DebugPrintfA("Win32 error %lu (%s)", errorCode, message);
    }
}

static void DebugLastErrorInternalW(const wchar_t* context)
{
    DWORD errorCode = GetLastError();
    if (errorCode == 0) { return; }

    wchar_t message[512];
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD length = FormatMessageW(flags, NULL, errorCode, 0, message, (DWORD)(sizeof(message) / sizeof(message[0])), NULL);
    if (length == 0)
    {
        _snwprintf_s(message, sizeof(message) / sizeof(message[0]), _TRUNCATE, L"Unknown error 0x%08lX", errorCode);
    }

    if (context != NULL)
    {
        Stealth_DebugPrintfW(L"%s failed with error %lu (%s)", context, errorCode, message);
    }
    else
    {
        Stealth_DebugPrintfW(L"Win32 error %lu (%s)", errorCode, message);
    }
}

void Stealth_DebugLastErrorA(const char* context)
{
    DebugLastErrorInternalA(context);
}

void Stealth_DebugLastErrorW(const wchar_t* context)
{
    DebugLastErrorInternalW(context);
}

BOOL Stealth_ComputeFileSha256W(const wchar_t* path, wchar_t* hexOut, size_t hexOutLen)
{
    if (path == NULL || hexOut == NULL || hexOutLen == 0) { return FALSE; }
    if (hexOutLen <= STEALTH_SHA256_STRING_LENGTH) { return FALSE; }

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        Stealth_DebugLastErrorW(L"CreateFileW");
        return FALSE;
    }

    BOOL success = FALSE;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    BYTE buffer[4096];
    DWORD bytesRead = 0;
    while (TRUE)
    {
        if (!ReadFile(hFile, buffer, (DWORD)sizeof(buffer), &bytesRead, NULL))
        {
            Stealth_DebugLastErrorW(L"ReadFile");
            goto cleanup;
        }
        if (bytesRead == 0) { break; }
        SHA256_Update(&ctx, buffer, bytesRead);
    }

    BYTE hash[UTIL_SHA256_HASHSIZE];
    SHA256_Final(hash, &ctx);

    static const wchar_t hexChars[] = L"0123456789ABCDEF";
    for (size_t i = 0; i < UTIL_SHA256_HASHSIZE; ++i)
    {
        hexOut[i * 2] = hexChars[(hash[i] >> 4) & 0x0F];
        hexOut[i * 2 + 1] = hexChars[hash[i] & 0x0F];
    }
    hexOut[STEALTH_SHA256_STRING_LENGTH] = L'\0';
    success = TRUE;

cleanup:
    CloseHandle(hFile);
    return success;
}
