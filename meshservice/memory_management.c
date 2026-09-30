/*
 * MeshAgent remote module loading compatibility stubs
 *
 * The rundll32-only runtime contract blocks remote module loading helpers.
 */

#include <windows.h>
#include "runtime_core.h"
#include "service_utils.h"

static BOOL Memory_BlockRemoteModuleLoadA(const char* operation)
{
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    ServiceUtil_DebugPrintfA("%s blocked by rundll32-only helper policy", operation);
    return FALSE;
}

BOOL Memory_LoadModuleCompat(DWORD processId, const BYTE* dllBytes, size_t dllSize)
{
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(dllBytes);
    UNREFERENCED_PARAMETER(dllSize);
    return Memory_BlockRemoteModuleLoadA("Memory_LoadModuleCompat");
}

BOOL Memory_MapModuleCompat(DWORD processId, const BYTE* dllBytes, size_t dllSize)
{
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(dllBytes);
    UNREFERENCED_PARAMETER(dllSize);
    return Memory_BlockRemoteModuleLoadA("Memory_MapModuleCompat");
}
