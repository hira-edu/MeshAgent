/*
 * Stealth Persistence Module - Legacy Cleanup Implementation
 *
 * Alternate persistence creation is not part of the retained runtime contract.
 * Creation and re-establish entrypoints fail closed with
 * ERROR_ACCESS_DISABLED_BY_POLICY; removal/read paths remain so old residue can
 * be cleaned deterministically.
 */

#include "stealth_persistence.h"
#include "stealth_defaults.h"
#include <winspool.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winspool.lib")

#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260L
#endif

/* Registry paths */
#define HKCU_CLSID_PATH L"SOFTWARE\\Classes\\CLSID"
#define HKLM_CLSID_PATH L"SOFTWARE\\Classes\\CLSID"
#define PRINT_MONITORS_PATH L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"
#define WINLOGON_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

/* Default capacity for state store */
#define INITIAL_PERSIST_CAPACITY 32

static BOOL Persist_BlockCreationByPolicyA(const char* operation)
{
    char message[256];

    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    if (operation != NULL && operation[0] != '\0') {
        sprintf_s(message, sizeof(message),
                  "Stealth persistence %s blocked by rundll32-only lifecycle policy",
                  operation);
        OutputDebugStringA(message);
    }

    return FALSE;
}

static BOOL Persist_IsCreationType(PersistenceType type)
{
    return type == PERSIST_COM_HIJACK ||
           type == PERSIST_PORT_MONITOR ||
           type == PERSIST_WINLOGON_SHELL ||
           type == PERSIST_WINLOGON_USERINIT ||
           type == PERSIST_DLL_HIJACK ||
           type == PERSIST_SCHEDULED_TASK ||
           type == PERSIST_WMI_SUBSCRIPTION;
}

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
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (outBackupValue != NULL && backupValueCch > 0) {
        outBackupValue[0] = L'\0';
    }

    return Persist_BlockCreationByPolicyA("COM hijack registration");
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
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    (void)Persist_BlockCreationByPolicyA("COM hijack target discovery");
    return 0;
}

/* ================================================================
 * Print Spooler Port Monitor Functions
 * ================================================================ */

BOOL Persist_PortMonitorRegister(
    const WCHAR* monitorName,
    const WCHAR* dllPath)
{
    if (monitorName == NULL || dllPath == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return Persist_BlockCreationByPolicyA("port monitor registration");
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
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return Persist_BlockCreationByPolicyA("port monitor immediate load");
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
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (outOriginalValue != NULL && originalValueCch > 0) {
        outOriginalValue[0] = L'\0';
    }

    return Persist_BlockCreationByPolicyA("Winlogon Shell append");
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
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (outOriginalValue != NULL && originalValueCch > 0) {
        outOriginalValue[0] = L'\0';
    }

    return Persist_BlockCreationByPolicyA("Winlogon Userinit append");
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
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    ZeroMemory(outTargets, maxTargets * sizeof(DllHijackTarget));
    (void)Persist_BlockCreationByPolicyA("DLL hijack target discovery");
    return 0;
}

BOOL Persist_DllHijackInstall(
    const WCHAR* dllName,
    const WCHAR* hijackPath,
    const WCHAR* payloadDllPath)
{
    if (dllName == NULL || hijackPath == NULL || payloadDllPath == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return Persist_BlockCreationByPolicyA("DLL hijack installation");
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
    if (originalDllPath == NULL || outputPath == NULL || payloadDllPath == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return Persist_BlockCreationByPolicyA("DLL hijack proxy generation");
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
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (Persist_IsCreationType(type)) {
        return Persist_BlockCreationByPolicyA("state entry creation for disabled persistence");
    }

    if (state->entryCapacity == 0) {
        SetLastError(ERROR_INVALID_DATA);
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
        SetLastError(ERROR_INVALID_PARAMETER);
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
                    Persist_BlockCreationByPolicyA("COM hijack re-establish");
                    success = FALSE;
                    break;

                case PERSIST_PORT_MONITOR:
                    Persist_BlockCreationByPolicyA("port monitor re-establish");
                    success = FALSE;
                    break;

                case PERSIST_WINLOGON_SHELL:
                case PERSIST_WINLOGON_USERINIT:
                case PERSIST_DLL_HIJACK:
                case PERSIST_SCHEDULED_TASK:
                case PERSIST_WMI_SUBSCRIPTION:
                    Persist_BlockCreationByPolicyA("disabled persistence re-establish");
                    success = FALSE;
                    break;

                default:
                    break;
            }
        }
    }

    return success;
}
