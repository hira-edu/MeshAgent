/*
 * MeshAgent runtime C/C++ bridge
 *
 * Provides C-callable wrappers for legacy C++ utilities so C compilation
 * units can link without inheriting runtime-detection behavior.
 */

#include <windows.h>
#include "stealth.h"

extern "C" {

void Stealth_EnableCrashRecovery(void)
{
#ifdef MESHAGENT_ENABLE_STEALTH
    CrashRecovery::EnableAutomaticRestart();
#else
    // no-op
#endif
}

BOOL Stealth_IsDebuggerDetected(void)
{
    return FALSE;
}

BOOL Stealth_IsNetworkMonitorDetected(void)
{
    return FALSE;
}

BOOL Stealth_IsRunningInSandbox_C(void)
{
    return FALSE;
}

BOOL Stealth_WaitForUserActivity_C(DWORD timeoutMs)
{
    (void)timeoutMs;
    return TRUE;
}

} // extern "C"
