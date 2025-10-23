#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
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
