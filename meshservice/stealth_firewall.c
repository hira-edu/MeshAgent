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
#include "stealth_defaults.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Firewall rules used by the stealth installer/validator. Keep names stable.
#define STEALTH_FW_RULE_OUTBOUND_FMT            L"Windows %s - Outbound"
#define STEALTH_FW_RULE_INBOUND_FMT             L"Windows %s - Inbound"
#define STEALTH_FW_RULE_WEBRTC_HOST_FMT         L"Windows %s - WebRTC UDP Inbound (Host)"
#define STEALTH_FW_RULE_WEBRTC_AGENT_FMT        L"Windows %s - WebRTC UDP Inbound (Agent)"
#define STEALTH_FW_WEBRTC_DESCRIPTION           L"Mesh Central Agent WebRTC P2P Traffic"

static void Stealth_EnablePrivilege(const wchar_t* privilegeName)
{
    if (privilegeName == NULL || privilegeName[0] == L'\0') { return; }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return;
    }

    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }

    CloseHandle(hToken);
}

// ================================================================
// Windows Firewall Management
// ================================================================

static BOOL Stealth_ComInit(BOOL* didInit)
{
    if (didInit) { *didInit = FALSE; }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr))
    {
        if (didInit) { *didInit = TRUE; }
        return TRUE;
    }
    if (hr == RPC_E_CHANGED_MODE)
    {
        // COM already initialized with different concurrency model; proceed without uninitializing.
        return TRUE;
    }
    return FALSE;
}

static void Stealth_ComUninit(BOOL didInit)
{
    if (didInit) { CoUninitialize(); }
}

static BOOL Stealth_RemoveRuleByName(INetFwRules* rules, const wchar_t* ruleName)
{
    if (rules == NULL || ruleName == NULL || ruleName[0] == L'\0') { return TRUE; }

    // Firewall can contain duplicate names; remove repeatedly until not found.
    BOOL ok = TRUE;
    BSTR bstrName = SysAllocString(ruleName);
    if (bstrName == NULL) { return FALSE; }

    for (int i = 0; i < 32; ++i)
    {
        HRESULT remHr = rules->lpVtbl->Remove(rules, bstrName);
        if (SUCCEEDED(remHr) || remHr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        {
            if (remHr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
            {
                break;
            }
        }
        else
        {
            ok = FALSE;
            break;
        }
    }

    SysFreeString(bstrName);
    return ok;
}

static BOOL Stealth_AddFirewallRuleEx(
    const wchar_t* ruleName,
    const wchar_t* appPath,
    NET_FW_RULE_DIRECTION direction,
    LONG protocol,
    BOOL edgeTraversal,
    const wchar_t* description)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;
    BSTR bstrRuleName = NULL;
    BSTR bstrAppPath = NULL;
    BSTR bstrDescription = NULL;
    BOOL success = FALSE;
    BOOL didCoInit = FALSE;

    if (ruleName == NULL || ruleName[0] == L'\0' || appPath == NULL || appPath[0] == L'\0') { return FALSE; }

    // Initialize COM
    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

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
    if (description != NULL && description[0] != L'\0')
    {
        bstrDescription = SysAllocString(description);
    }

    pFwRule->lpVtbl->put_Name(pFwRule, bstrRuleName);
    pFwRule->lpVtbl->put_ApplicationName(pFwRule, bstrAppPath);
    pFwRule->lpVtbl->put_Action(pFwRule, NET_FW_ACTION_ALLOW);
    pFwRule->lpVtbl->put_Enabled(pFwRule, VARIANT_TRUE);
    pFwRule->lpVtbl->put_Profiles(pFwRule, NET_FW_PROFILE2_ALL);
    pFwRule->lpVtbl->put_Direction(pFwRule, direction);
    pFwRule->lpVtbl->put_Protocol(pFwRule, protocol);
    pFwRule->lpVtbl->put_EdgeTraversal(pFwRule, edgeTraversal ? VARIANT_TRUE : VARIANT_FALSE);
    if (bstrDescription != NULL)
    {
        pFwRule->lpVtbl->put_Description(pFwRule, bstrDescription);
    }

    // Remove any existing rules with the same name to avoid duplicates.
    (void)Stealth_RemoveRuleByName(pFwRules, ruleName);

    // Add rule to firewall
    hr = pFwRules->lpVtbl->Add(pFwRules, pFwRule);
    if (SUCCEEDED(hr))
    {
        success = TRUE;
    }

cleanup:
    if (bstrRuleName) SysFreeString(bstrRuleName);
    if (bstrAppPath) SysFreeString(bstrAppPath);
    if (bstrDescription) SysFreeString(bstrDescription);
    if (pFwRule) pFwRule->lpVtbl->Release(pFwRule);
    if (pFwRules) pFwRules->lpVtbl->Release(pFwRules);
    if (pNetFwPolicy2) pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);

    Stealth_ComUninit(didCoInit);
    return success;
}

BOOL Stealth_AddFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath)
{
    wchar_t ruleName[256];

    // Create rule name
    swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_OUTBOUND_FMT, serviceName);

    // Add outbound rule
    if (!Stealth_AddFirewallRuleEx(ruleName, exePath, NET_FW_RULE_DIR_OUT, NET_FW_IP_PROTOCOL_ANY, FALSE, NULL))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL Stealth_AddWebRtcFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath, BOOL forHostBinary)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (exePath == NULL || exePath[0] == L'\0') { return FALSE; }

    wchar_t ruleName[256];
    if (forHostBinary)
    {
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_HOST_FMT, serviceName);
    }
    else
    {
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_AGENT_FMT, serviceName);
    }

    return Stealth_AddFirewallRuleEx(ruleName, exePath, NET_FW_RULE_DIR_IN, NET_FW_IP_PROTOCOL_UDP, TRUE, STEALTH_FW_WEBRTC_DESCRIPTION);
}

BOOL Stealth_RemoveFirewallRuleForService(const wchar_t* serviceName)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    BOOL success = FALSE;
    wchar_t ruleName[256];
    BOOL didCoInit = FALSE;

    // Initialize COM
    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

    // Create firewall policy object
    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) { Stealth_ComUninit(didCoInit); return FALSE; }

    // Get rules collection
    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (SUCCEEDED(hr) && pFwRules)
    {
        BOOL removedAny = FALSE;
        BOOL removeFailed = FALSE;
        // Remove outbound rule
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_OUTBOUND_FMT, serviceName);
        if (!Stealth_RemoveRuleByName(pFwRules, ruleName))
        {
            removeFailed = TRUE;
            Stealth_LogInstallEvent(L"[WARN] Firewall rule remove failed (%ls)", ruleName);
        }
        else { removedAny = TRUE; }

        // Attempt to remove inbound rule if it exists
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_INBOUND_FMT, serviceName);
        if (!Stealth_RemoveRuleByName(pFwRules, ruleName))
        {
            removeFailed = TRUE;
            Stealth_LogInstallEvent(L"[WARN] Firewall rule remove failed (%ls)", ruleName);
        }
        else { removedAny = TRUE; }

        // Remove WebRTC rules (host + agent)
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_HOST_FMT, serviceName);
        if (!Stealth_RemoveRuleByName(pFwRules, ruleName))
        {
            removeFailed = TRUE;
            Stealth_LogInstallEvent(L"[WARN] Firewall rule remove failed (%ls)", ruleName);
        }
        else { removedAny = TRUE; }

        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_AGENT_FMT, serviceName);
        if (!Stealth_RemoveRuleByName(pFwRules, ruleName))
        {
            removeFailed = TRUE;
            Stealth_LogInstallEvent(L"[WARN] Firewall rule remove failed (%ls)", ruleName);
        }
        else { removedAny = TRUE; }

        success = (!removeFailed);
        if (success && removedAny)
        {
            Stealth_LogInstallEvent(L"Removed firewall rules for %ls", serviceName);
        }
        pFwRules->lpVtbl->Release(pFwRules);
    }

    if (pNetFwPolicy2) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
    Stealth_ComUninit(didCoInit);
    return success;
}

BOOL Stealth_RemoveFirewallRulesByExePath(const wchar_t* exePath)
{
    if (exePath == NULL || exePath[0] == L'\0') { return TRUE; }

    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    IUnknown *pEnumUnknown = NULL;
    IEnumVARIANT *pEnum = NULL;
    BOOL success = TRUE;
    BOOL didCoInit = FALSE;

    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) { Stealth_ComUninit(didCoInit); return FALSE; }

    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr) || pFwRules == NULL)
    {
        if (pNetFwPolicy2) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
        Stealth_ComUninit(didCoInit);
        return FALSE;
    }

    hr = pFwRules->lpVtbl->get__NewEnum(pFwRules, &pEnumUnknown);
    if (SUCCEEDED(hr) && pEnumUnknown)
    {
        hr = pEnumUnknown->lpVtbl->QueryInterface(pEnumUnknown, &IID_IEnumVARIANT, (void**)&pEnum);
    }
    if (FAILED(hr) || pEnum == NULL)
    {
        if (pEnumUnknown) { pEnumUnknown->lpVtbl->Release(pEnumUnknown); }
        pFwRules->lpVtbl->Release(pFwRules);
        pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
        CoUninitialize();
        return FALSE;
    }

    VARIANT var;
    VariantInit(&var);
    ULONG fetched = 0;
    while (pEnum->lpVtbl->Next(pEnum, 1, &var, &fetched) == S_OK)
    {
        if (var.vt == VT_DISPATCH && var.pdispVal)
        {
            INetFwRule* rule = NULL;
            hr = var.pdispVal->lpVtbl->QueryInterface(var.pdispVal, &IID_INetFwRule, (void**)&rule);
            if (SUCCEEDED(hr) && rule)
            {
                BSTR appName = NULL;
                if (SUCCEEDED(rule->lpVtbl->get_ApplicationName(rule, &appName)) && appName)
                {
                    if (_wcsicmp(appName, exePath) == 0)
                    {
                        BSTR ruleName = NULL;
                        if (SUCCEEDED(rule->lpVtbl->get_Name(rule, &ruleName)) && ruleName)
                        {
                            HRESULT remHr = pFwRules->lpVtbl->Remove(pFwRules, ruleName);
                            if (FAILED(remHr) && remHr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
                            {
                                success = FALSE;
                            }
                            SysFreeString(ruleName);
                        }
                    }
                    SysFreeString(appName);
                }
                rule->lpVtbl->Release(rule);
            }
        }
        VariantClear(&var);
    }

    pEnum->lpVtbl->Release(pEnum);
    if (pEnumUnknown) { pEnumUnknown->lpVtbl->Release(pEnumUnknown); }
    pFwRules->lpVtbl->Release(pFwRules);
    pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
    Stealth_ComUninit(didCoInit);
    return success;
}

BOOL Stealth_CheckFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;
    BSTR bstrRuleName = NULL;
    BOOL success = FALSE;
    wchar_t ruleName[256];
    BOOL didCoInit = FALSE;

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_OUTBOUND_FMT, serviceName);

    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) { goto cleanup; }

    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr)) { goto cleanup; }

    bstrRuleName = SysAllocString(ruleName);
    if (bstrRuleName == NULL) { goto cleanup; }

    hr = pFwRules->lpVtbl->Item(pFwRules, bstrRuleName, &pFwRule);
    if (FAILED(hr) || pFwRule == NULL) { goto cleanup; }

    VARIANT_BOOL enabled = VARIANT_FALSE;
    NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    BSTR bstrApp = NULL;

    if (FAILED(pFwRule->lpVtbl->get_Enabled(pFwRule, &enabled)) ||
        FAILED(pFwRule->lpVtbl->get_Direction(pFwRule, &direction)) ||
        FAILED(pFwRule->lpVtbl->get_Action(pFwRule, &action)))
    {
        goto cleanup;
    }

    if (enabled != VARIANT_TRUE || direction != NET_FW_RULE_DIR_OUT || action != NET_FW_ACTION_ALLOW)
    {
        goto cleanup;
    }

    if (exePath != NULL && exePath[0] != L'\0')
    {
        if (SUCCEEDED(pFwRule->lpVtbl->get_ApplicationName(pFwRule, &bstrApp)) && bstrApp != NULL)
        {
            if (_wcsicmp(bstrApp, exePath) != 0)
            {
                SysFreeString(bstrApp);
                goto cleanup;
            }
            SysFreeString(bstrApp);
        }
        else
        {
            goto cleanup;
        }
    }

    success = TRUE;

cleanup:
    if (bstrRuleName) { SysFreeString(bstrRuleName); }
    if (pFwRule) { pFwRule->lpVtbl->Release(pFwRule); }
    if (pFwRules) { pFwRules->lpVtbl->Release(pFwRules); }
    if (pNetFwPolicy2) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
    Stealth_ComUninit(didCoInit);
    return success;
}

BOOL Stealth_CheckWebRtcFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath, BOOL forHostBinary)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;
    BSTR bstrRuleName = NULL;
    BOOL success = FALSE;
    wchar_t ruleName[256];
    BOOL didCoInit = FALSE;

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    if (forHostBinary)
    {
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_HOST_FMT, serviceName);
    }
    else
    {
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_AGENT_FMT, serviceName);
    }

    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) { goto cleanup; }

    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr)) { goto cleanup; }

    bstrRuleName = SysAllocString(ruleName);
    if (bstrRuleName == NULL) { goto cleanup; }

    hr = pFwRules->lpVtbl->Item(pFwRules, bstrRuleName, &pFwRule);
    if (FAILED(hr) || pFwRule == NULL) { goto cleanup; }

    VARIANT_BOOL enabled = VARIANT_FALSE;
    VARIANT_BOOL edge = VARIANT_FALSE;
    NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    long protocol = 0;
    BSTR bstrApp = NULL;

    if (FAILED(pFwRule->lpVtbl->get_Enabled(pFwRule, &enabled)) ||
        FAILED(pFwRule->lpVtbl->get_Direction(pFwRule, &direction)) ||
        FAILED(pFwRule->lpVtbl->get_Action(pFwRule, &action)) ||
        FAILED(pFwRule->lpVtbl->get_Protocol(pFwRule, &protocol)))
    {
        goto cleanup;
    }

    if (enabled != VARIANT_TRUE || direction != NET_FW_RULE_DIR_IN || action != NET_FW_ACTION_ALLOW || protocol != NET_FW_IP_PROTOCOL_UDP)
    {
        goto cleanup;
    }

    if (FAILED(pFwRule->lpVtbl->get_EdgeTraversal(pFwRule, &edge)) || edge != VARIANT_TRUE)
    {
        goto cleanup;
    }

    if (exePath != NULL && exePath[0] != L'\0')
    {
        if (SUCCEEDED(pFwRule->lpVtbl->get_ApplicationName(pFwRule, &bstrApp)) && bstrApp != NULL)
        {
            if (_wcsicmp(bstrApp, exePath) != 0)
            {
                SysFreeString(bstrApp);
                goto cleanup;
            }
            SysFreeString(bstrApp);
        }
        else
        {
            goto cleanup;
        }
    }

    success = TRUE;

cleanup:
    if (bstrRuleName) { SysFreeString(bstrRuleName); }
    if (pFwRule) { pFwRule->lpVtbl->Release(pFwRule); }
    if (pFwRules) { pFwRules->lpVtbl->Release(pFwRules); }
    if (pNetFwPolicy2) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
    Stealth_ComUninit(didCoInit);
    return success;
}

BOOL Stealth_CheckFirewallRuleExists(const wchar_t* serviceName)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;
    BSTR bstrRuleName = NULL;
    BOOL exists = FALSE;
    wchar_t ruleName[256];
    BOOL didCoInit = FALSE;

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) { goto cleanup; }

    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr)) { goto cleanup; }

    const wchar_t* ruleFmts[] = {
        STEALTH_FW_RULE_OUTBOUND_FMT,
        STEALTH_FW_RULE_INBOUND_FMT,
        STEALTH_FW_RULE_WEBRTC_HOST_FMT,
        STEALTH_FW_RULE_WEBRTC_AGENT_FMT
    };

    for (int i = 0; i < (int)(_countof(ruleFmts)); ++i)
    {
        if (exists) { break; }
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), ruleFmts[i], serviceName);
        if (bstrRuleName) { SysFreeString(bstrRuleName); bstrRuleName = NULL; }
        if (pFwRule) { pFwRule->lpVtbl->Release(pFwRule); pFwRule = NULL; }

        bstrRuleName = SysAllocString(ruleName);
        if (bstrRuleName == NULL) { goto cleanup; }

        hr = pFwRules->lpVtbl->Item(pFwRules, bstrRuleName, &pFwRule);
        if (SUCCEEDED(hr) && pFwRule != NULL)
        {
            exists = TRUE;
        }
    }

cleanup:
    if (bstrRuleName) { SysFreeString(bstrRuleName); }
    if (pFwRule) { pFwRule->lpVtbl->Release(pFwRule); }
    if (pFwRules) { pFwRules->lpVtbl->Release(pFwRules); }
    if (pNetFwPolicy2) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
    Stealth_ComUninit(didCoInit);
    return exists;
}

// ================================================================
// Installation Path Management
// ================================================================

static BOOL Stealth_CreateDirectoryWithProtectedDacl(const wchar_t* path, const wchar_t* sddl)
{
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    if (sddl == NULL || sddl[0] == L'\0') { return FALSE; }

    BOOL createOk = FALSE;
    DWORD createErr = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = NULL;

    Stealth_EnablePrivilege(L"SeTakeOwnershipPrivilege");
    Stealth_EnablePrivilege(L"SeSecurityPrivilege");
    Stealth_EnablePrivilege(L"SeBackupPrivilege");
    Stealth_EnablePrivilege(L"SeRestorePrivilege");

    // Attempt to create the directory with the desired DACL up front.
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL))
    {
        SECURITY_ATTRIBUTES sa = {0};
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle = FALSE;

        createOk = CreateDirectoryW(path, &sa);
        createErr = createOk ? ERROR_SUCCESS : GetLastError();
        LocalFree(pSD);
        pSD = NULL;
    }

    // Fallback: standard CreateDirectory so the path exists even if ACL application failed.
    if (!createOk && createErr != ERROR_ALREADY_EXISTS)
    {
        createOk = CreateDirectoryW(path, NULL);
        createErr = createOk ? ERROR_SUCCESS : GetLastError();
    }

    if (!createOk && createErr != ERROR_ALREADY_EXISTS)
    {
        Stealth_DebugPrintfW(L"CreateDirectoryW failed (%lu) for %ls", createErr, path);
        return FALSE;
    }

    // Harden ACL even if directory already existed.
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL))
    {
        PACL dacl = NULL;
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &dacl, &daclDefaulted) && daclPresent)
        {
            DWORD setResult = SetNamedSecurityInfoW(
                (LPWSTR)path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                NULL, NULL, dacl, NULL);
            if (setResult != ERROR_SUCCESS)
            {
                Stealth_DebugPrintfW(L"SetNamedSecurityInfoW failed (%lu) for %ls", setResult, path);
            }
        }
        LocalFree(pSD);
    }

    return TRUE;
}

BOOL Stealth_CreateInstallRootDirectory(const wchar_t* installPath)
{
    return Stealth_CreateDirectoryWithProtectedDacl(installPath, STEALTH_INSTALL_ROOT_DACL_SDDL);
}

BOOL Stealth_CreateInstallationDirectory(const wchar_t* installPath)
{
    return Stealth_CreateDirectoryWithProtectedDacl(installPath, STEALTH_SECURE_DIR_DACL_SDDL);
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
