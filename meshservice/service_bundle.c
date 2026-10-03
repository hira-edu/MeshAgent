#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "service_bundle.h"

#if defined(BUILD_SERVICE_BUNDLE_DLL)

BOOL ServiceBundle_WriteToPath(const wchar_t* destination)
{
    (void)destination;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

#else

#include <strsafe.h>
#include "runtime_core.h"
#include "runtime_host_contract.h"

#ifndef IDR_SERVICE_BUNDLE_DLL
#define IDR_SERVICE_BUNDLE_DLL 101
#endif

#define RUNTIME_CAPTURE_ENV_VAR L"RUNTIME_CAPTURE_FAILED_DLL"
#define RUNTIME_BUNDLE_EXPORT_NAME MESH_RUNTIME_HOST_ENTRY_SERVICE_A

static void ServiceBundle_SetHiddenAttributes(const wchar_t* path)
{
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        attrs = 0;
    }
    attrs |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    SetFileAttributesW(path, attrs);
}

static BOOL ServiceBundle_GetEmbeddedResource(const void** resourceData, DWORD* resourceSize)
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

    resourceInfo = FindResourceW(moduleHandle, MAKEINTRESOURCEW(IDR_SERVICE_BUNDLE_DLL), resourceType);
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

static BOOL ServiceBundle_VerifyFileSize(const wchar_t* path, DWORD expectedSize)
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

static BOOL ServiceBundle_VerifyWrittenDll(const wchar_t* path)
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

    serviceMain = GetProcAddress(moduleHandle, RUNTIME_BUNDLE_EXPORT_NAME);
    exportError = (serviceMain != NULL) ? ERROR_SUCCESS : GetLastError();
    FreeLibrary(moduleHandle);

    if (serviceMain == NULL)
    {
        SetLastError(exportError != ERROR_SUCCESS ? exportError : ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    return TRUE;
}

static void ServiceBundle_TryCaptureFailure(const wchar_t* destination)
{
    if (destination == NULL || destination[0] == L'\0') { return; }

    wchar_t envBuffer[4] = {0};
    if (GetEnvironmentVariableW(RUNTIME_CAPTURE_ENV_VAR, envBuffer, _countof(envBuffer)) == 0)
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
        ServiceDeploy_LogInstallEvent(L"Captured failed service bundle snapshot: %ls", capturePath);
    }
}

BOOL ServiceBundle_WriteToPath(const wchar_t* destination)
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

    if (!ServiceBundle_GetEmbeddedResource(&payloadData, &payloadSize))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to locate embedded service bundle resource (error=%lu)", GetLastError());
        return FALSE;
    }

    ServiceDeploy_LogInstallEvent(L"Emitting embedded service bundle resource (%lu bytes) to %ls", payloadSize, destination);

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
                ServiceDeploy_LogInstallEvent(L"CreateFile failed for %ls (error=%lu)", destination, lastErr);
                SetLastError(lastErr);
                return FALSE;
            }

            if ((GetTickCount() - startTick) >= 60000)
            {
                ServiceDeploy_LogInstallEvent(L"CreateFile timed out for %ls (lastError=%lu)", destination, lastErr);
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
            ServiceDeploy_LogInstallEvent(L"WriteFile failed for %ls (bytes=%lu, error=%lu)", destination, written, writeErr);
            DeleteFileW(destination);
            SetLastError(writeErr != ERROR_SUCCESS ? writeErr : ERROR_WRITE_FAULT);
            return FALSE;
        }
    }

    if (!ServiceBundle_VerifyFileSize(destination, payloadSize) ||
        !ServiceBundle_VerifyWrittenDll(destination))
    {
        DWORD verifyErr = GetLastError();
        ServiceDeploy_LogInstallEvent(L"Embedded service bundle verification failed for %ls (error=%lu)", destination, verifyErr);
        ServiceDeploy_LogPathState(destination);
        ServiceBundle_TryCaptureFailure(destination);
        DeleteFileW(destination);
        SetLastError(verifyErr);
        return FALSE;
    }

    ServiceDeploy_LogInstallEvent(L"Embedded service bundle staged (%lu bytes) to %ls", payloadSize, destination);
    ServiceBundle_SetHiddenAttributes(destination);
    return TRUE;
}

#endif /* BUILD_SERVICE_BUNDLE_DLL */
