/*
 * MeshAgent remote module loading compatibility stubs
 *
 * The rundll32-only runtime contract blocks remote module loading helpers.
 */

#include <windows.h>
#include "stealth.h"
#include "stealth_utils.h"

static BOOL Stealth_BlockRemoteModuleLoadA(const char* operation)
{
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    Stealth_DebugPrintfA("%s blocked by rundll32-only helper policy", operation);
    return FALSE;
}

BOOL Stealth_LoadMemoryModuleCompat(DWORD processId, const BYTE* dllBytes, size_t dllSize)
{
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(dllBytes);
    UNREFERENCED_PARAMETER(dllSize);
    return Stealth_BlockRemoteModuleLoadA("Stealth_LoadMemoryModuleCompat");
}

BOOL Stealth_MapMemoryModuleCompat(DWORD processId, const BYTE* dllBytes, size_t dllSize)
{
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(dllBytes);
    UNREFERENCED_PARAMETER(dllSize);
    return Stealth_BlockRemoteModuleLoadA("Stealth_MapMemoryModuleCompat");
}
