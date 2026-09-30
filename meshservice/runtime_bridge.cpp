/*
 * MeshAgent runtime C/C++ bridge
 *
 * Provides C-callable wrappers for C++ utilities so C compilation
 * units can link without inheriting runtime-detection behavior.
 */

#include <windows.h>
#include "runtime_core.h"

extern "C" {

void Runtime_EnableCrashRecovery(void)
{
#ifdef MESHAGENT_ENABLE_RUNTIME_FEATURES
    CrashRecovery::EnableAutomaticRestart();
#else
    // no-op
#endif
}

BOOL Runtime_IsDebuggerDetected(void)
{
    return FALSE;
}

BOOL Runtime_IsNetworkMonitorDetected(void)
{
    return FALSE;
}

BOOL Runtime_IsRunningInSandbox(void)
{
    return FALSE;
}

BOOL Runtime_WaitForUserActivity(DWORD timeoutMs)
{
    (void)timeoutMs;
    return TRUE;
}

} // extern "C"
