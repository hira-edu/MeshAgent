/*
 * Stealth Registry Module - Implementation
 *
 * Registry wrapper with state persistence for backup/restore during
 * SecureEnter/SecureExit lockdown transitions.
 *
 * Ported from:
 * - GiovanniDicanio/WinReg (MIT) - High-level C++ wrapper for Windows Registry
 * - Windows API: RegSaveKeyEx / RegRestoreKey
 */

#include "stealth_registry.h"
#include "stealth_defaults.h"
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

/* Default state file path — uses generic fallback from stealth_defaults.h */
#define DEFAULT_STATE_PATH L"C:\\ProgramData\\" STEALTH_FALLBACK_SERVICE_NAME L"\\state.json"

/* Initial capacity for state store */
#define INITIAL_ENTRY_CAPACITY 64

/* Winlogon registry path */
#define WINLOGON_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

/* Explorer policies path */
#define EXPLORER_POLICIES_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"

/* Forward declarations */
static BOOL ReadRegistryValue(HKEY hRootKey, const WCHAR* subKey, const WCHAR* valueName, RegEntry* entry);
static BOOL WriteRegistryValue(HKEY hRootKey, const WCHAR* subKey, const WCHAR* valueName, const RegEntry* entry);
static const WCHAR* GetRootKeyName(HKEY hKey);
static HKEY ParseRootKeyName(const WCHAR* name);

/* ================================================================
 * State Store Functions
 * ================================================================ */

BOOL RegState_Init(RegStateStore* store, const WCHAR* stateFilePath)
{
    if (store == NULL) {
        return FALSE;
    }

    ZeroMemory(store, sizeof(RegStateStore));

    if (stateFilePath != NULL) {
        StringCchCopyW(store->stateFilePath, MAX_PATH, stateFilePath);
    } else {
        StringCchCopyW(store->stateFilePath, MAX_PATH, DEFAULT_STATE_PATH);
    }

    /* Allocate initial entry array */
    store->entryCapacity = INITIAL_ENTRY_CAPACITY;
    store->entries = (RegEntry*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          store->entryCapacity * sizeof(RegEntry));
    if (store->entries == NULL) {
        return FALSE;
    }

    store->entryCount = 0;
    store->modified = FALSE;

    return TRUE;
}

void RegState_Free(RegStateStore* store)
{
    if (store == NULL) {
        return;
    }

    if (store->entries != NULL) {
        HeapFree(GetProcessHeap(), 0, store->entries);
        store->entries = NULL;
    }

    store->entryCount = 0;
    store->entryCapacity = 0;
}

/* JSON parsing helpers for RegState_Load */
static const char* RegJson_FindStringValue(const char* json, const char* key, char* outValue, size_t outSize)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\"", key);

    const char* keyPos = strstr(json, searchKey);
    if (!keyPos) return NULL;

    const char* colon = strchr(keyPos + strlen(searchKey), ':');
    if (!colon) return NULL;

    const char* ptr = colon + 1;
    while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;

    if (*ptr != '"') return NULL;
    ptr++;

    size_t i = 0;
    while (*ptr && *ptr != '"' && i < outSize - 1) {
        if (*ptr == '\\' && *(ptr + 1)) {
            ptr++;
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

static const char* RegJson_FindIntValue(const char* json, const char* key, int* outValue)
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
    while (*ptr == '-' || (*ptr >= '0' && *ptr <= '9')) ptr++;
    return ptr;
}

static const char* RegJson_FindBoolValue(const char* json, const char* key, BOOL* outValue)
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

/* Base64 decode helper for binary data */
static int RegJson_Base64Decode(const char* input, BYTE* output, DWORD maxOutput)
{
    static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DWORD outLen = 0;
    int val = 0, valb = -8;

    for (const char* p = input; *p && *p != '"'; p++) {
        const char* pos = strchr(b64chars, *p);
        if (pos == NULL) {
            if (*p == '=') break;
            continue;
        }
        val = (val << 6) + (int)(pos - b64chars);
        valb += 6;
        if (valb >= 0) {
            if (outLen >= maxOutput) break;
            output[outLen++] = (BYTE)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return (int)outLen;
}

BOOL RegState_Load(RegStateStore* store)
{
    if (store == NULL || store->stateFilePath[0] == L'\0') {
        return FALSE;
    }

    HANDLE hFile = CreateFileW(store->stateFilePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE; /* File doesn't exist - not an error for first run */
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE || fileSize > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        return (fileSize == 0);
    }

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
        return TRUE;
    }

    const char* arrayStart = strchr(entriesStart, '[');
    if (arrayStart == NULL) {
        HeapFree(GetProcessHeap(), 0, content);
        return TRUE;
    }

    /* Parse each entry object */
    const char* ptr = arrayStart + 1;
    while (ptr && *ptr) {
        const char* objStart = strchr(ptr, '{');
        if (objStart == NULL) break;

        const char* objEnd = strchr(objStart, '}');
        if (objEnd == NULL) break;

        size_t objLen = objEnd - objStart + 1;
        char* objJson = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objLen + 1);
        if (objJson == NULL) break;
        memcpy(objJson, objStart, objLen);
        objJson[objLen] = '\0';

        /* Parse entry fields */
        char keyPathUtf8[1024] = {0};
        char valueNameUtf8[512] = {0};
        char dataBase64[8192] = {0};
        int typeVal = 0;
        int dataSizeVal = 0;
        BOOL existed = FALSE;

        RegJson_FindStringValue(objJson, "keyPath", keyPathUtf8, sizeof(keyPathUtf8));
        RegJson_FindStringValue(objJson, "valueName", valueNameUtf8, sizeof(valueNameUtf8));
        RegJson_FindIntValue(objJson, "type", &typeVal);
        RegJson_FindIntValue(objJson, "dataSize", &dataSizeVal);
        RegJson_FindBoolValue(objJson, "existed", &existed);
        RegJson_FindStringValue(objJson, "data", dataBase64, sizeof(dataBase64));

        HeapFree(GetProcessHeap(), 0, objJson);

        if (keyPathUtf8[0] != '\0') {
            /* Expand array if needed */
            if (store->entryCount >= store->entryCapacity) {
                DWORD newCapacity = store->entryCapacity * 2;
                if (newCapacity == 0) newCapacity = INITIAL_ENTRY_CAPACITY;
                RegEntry* newEntries = (RegEntry*)HeapReAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY,
                    store->entries, newCapacity * sizeof(RegEntry));
                if (newEntries == NULL) break;
                store->entries = newEntries;
                store->entryCapacity = newCapacity;
            }

            RegEntry* entry = &store->entries[store->entryCount];
            ZeroMemory(entry, sizeof(RegEntry));

            /* Convert UTF8 to wide strings */
            MultiByteToWideChar(CP_UTF8, 0, keyPathUtf8, -1, entry->keyPath, 512);
            MultiByteToWideChar(CP_UTF8, 0, valueNameUtf8, -1, entry->valueName, 256);

            entry->type = (RegValueType)typeVal;
            entry->existed = existed;

            /* Decode base64 data if present */
            if (dataBase64[0] != '\0') {
                entry->dataSize = RegJson_Base64Decode(dataBase64, entry->data, sizeof(entry->data));
            } else {
                entry->dataSize = (DWORD)dataSizeVal;
            }

            store->entryCount++;
        }

        ptr = objEnd + 1;
    }

    store->modified = FALSE;
    HeapFree(GetProcessHeap(), 0, content);
    return TRUE;
}

/* Base64 encode helper for binary data */
static void RegJson_Base64Encode(const BYTE* input, DWORD inputLen, char* output, size_t outputSize)
{
    static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t outIdx = 0;
    DWORD i;

    for (i = 0; i < inputLen && outIdx < outputSize - 4; i += 3) {
        DWORD n = ((DWORD)input[i]) << 16;
        if (i + 1 < inputLen) n |= ((DWORD)input[i + 1]) << 8;
        if (i + 2 < inputLen) n |= input[i + 2];

        output[outIdx++] = b64chars[(n >> 18) & 0x3F];
        output[outIdx++] = b64chars[(n >> 12) & 0x3F];
        output[outIdx++] = (i + 1 < inputLen) ? b64chars[(n >> 6) & 0x3F] : '=';
        output[outIdx++] = (i + 2 < inputLen) ? b64chars[n & 0x3F] : '=';
    }
    output[outIdx] = '\0';
}

BOOL RegState_Save(const RegStateStore* store)
{
    if (store == NULL || store->stateFilePath[0] == L'\0') {
        return FALSE;
    }

    /* Ensure directory exists */
    WCHAR dirPath[MAX_PATH];
    StringCchCopyW(dirPath, MAX_PATH, store->stateFilePath);
    WCHAR* lastSlash = wcsrchr(dirPath, L'\\');
    if (lastSlash != NULL) {
        *lastSlash = L'\0';
        CreateDirectoryW(dirPath, NULL);
    }

    HANDLE hFile = CreateFileW(store->stateFilePath, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    /* Write JSON format */
    char header[] = "{\"version\":1,\"entries\":[\n";
    DWORD written = 0;
    WriteFile(hFile, header, (DWORD)strlen(header), &written, NULL);

    for (DWORD i = 0; i < store->entryCount; i++) {
        const RegEntry* entry = &store->entries[i];
        char buffer[16384];
        char keyPathUtf8[1024];
        char valueNameUtf8[512];

        /* Convert wide strings to UTF-8 */
        WideCharToMultiByte(CP_UTF8, 0, entry->keyPath, -1, keyPathUtf8, sizeof(keyPathUtf8), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, entry->valueName, -1, valueNameUtf8, sizeof(valueNameUtf8), NULL, NULL);

        /* Escape backslashes and quotes in keyPath */
        char escapedPath[2048];
        char* dst = escapedPath;
        for (const char* src = keyPathUtf8; *src && dst < escapedPath + sizeof(escapedPath) - 2; src++) {
            if (*src == '\\' || *src == '"') {
                *dst++ = '\\';
            }
            *dst++ = *src;
        }
        *dst = '\0';

        /* Escape valueName */
        char escapedValueName[1024];
        dst = escapedValueName;
        for (const char* src = valueNameUtf8; *src && dst < escapedValueName + sizeof(escapedValueName) - 2; src++) {
            if (*src == '\\' || *src == '"') {
                *dst++ = '\\';
            }
            *dst++ = *src;
        }
        *dst = '\0';

        /* Base64 encode the binary data */
        char dataBase64[8192] = {0};
        if (entry->dataSize > 0 && entry->dataSize < sizeof(entry->data)) {
            RegJson_Base64Encode(entry->data, entry->dataSize, dataBase64, sizeof(dataBase64));
        }

        /* Build JSON entry with data */
        int len = sprintf_s(buffer, sizeof(buffer),
            "%s{\"keyPath\":\"%s\",\"valueName\":\"%s\",\"type\":%d,\"dataSize\":%lu,\"data\":\"%s\",\"existed\":%s}",
            i > 0 ? ",\n" : "",
            escapedPath,
            escapedValueName,
            (int)entry->type,
            entry->dataSize,
            dataBase64,
            entry->existed ? "true" : "false");

        if (len > 0) {
            WriteFile(hFile, buffer, len, &written, NULL);
        }
    }

    char footer[] = "\n]}\n";
    WriteFile(hFile, footer, (DWORD)strlen(footer), &written, NULL);

    CloseHandle(hFile);
    return TRUE;
}

BOOL RegState_AddEntry(
    RegStateStore* store,
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName)
{
    if (store == NULL || subKey == NULL) {
        return FALSE;
    }

    /* Check if already tracking */
    for (DWORD i = 0; i < store->entryCount; i++) {
        if (_wcsicmp(store->entries[i].keyPath, subKey) == 0 &&
            _wcsicmp(store->entries[i].valueName, valueName ? valueName : L"") == 0) {
            return TRUE; /* Already tracking */
        }
    }

    /* Expand array if needed */
    if (store->entryCount >= store->entryCapacity) {
        DWORD newCapacity = store->entryCapacity * 2;
        RegEntry* newEntries = (RegEntry*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                       store->entries, newCapacity * sizeof(RegEntry));
        if (newEntries == NULL) {
            return FALSE;
        }
        store->entries = newEntries;
        store->entryCapacity = newCapacity;
    }

    /* Read current value and add to store */
    RegEntry* entry = &store->entries[store->entryCount];
    ZeroMemory(entry, sizeof(RegEntry));

    /* Build full key path */
    StringCchPrintfW(entry->keyPath, 512, L"%s\\%s", GetRootKeyName(hRootKey), subKey);
    if (valueName != NULL) {
        StringCchCopyW(entry->valueName, 256, valueName);
    }

    /* Read current value */
    entry->existed = ReadRegistryValue(hRootKey, subKey, valueName, entry);

    store->entryCount++;
    store->modified = TRUE;

    return TRUE;
}

BOOL RegState_RestoreAll(RegStateStore* store)
{
    if (store == NULL) {
        return FALSE;
    }

    BOOL success = TRUE;

    for (DWORD i = 0; i < store->entryCount; i++) {
        RegEntry* entry = &store->entries[i];

        /* Parse root key from path */
        WCHAR rootKeyName[32];
        const WCHAR* subKey = wcschr(entry->keyPath, L'\\');
        if (subKey == NULL) {
            continue;
        }

        size_t rootLen = subKey - entry->keyPath;
        if (rootLen >= 32) continue;
        wcsncpy_s(rootKeyName, 32, entry->keyPath, rootLen);
        rootKeyName[rootLen] = L'\0';
        subKey++; /* Skip backslash */

        HKEY hRootKey = ParseRootKeyName(rootKeyName);
        if (hRootKey == NULL) {
            continue;
        }

        if (entry->existed) {
            /* Restore original value */
            if (!WriteRegistryValue(hRootKey, subKey,
                                    entry->valueName[0] ? entry->valueName : NULL, entry)) {
                success = FALSE;
            }
        } else {
            /* Delete value that didn't exist before */
            HKEY hKey;
            if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                RegDeleteValueW(hKey, entry->valueName[0] ? entry->valueName : NULL);
                RegCloseKey(hKey);
            }
        }
    }

    return success;
}

BOOL RegState_Clear(RegStateStore* store)
{
    if (store == NULL) {
        return FALSE;
    }

    /* Delete state file */
    DeleteFileW(store->stateFilePath);

    /* Clear entries */
    store->entryCount = 0;
    store->modified = FALSE;

    return TRUE;
}

/* ================================================================
 * Registry Read Functions
 * ================================================================ */

BOOL Reg_ReadDword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    DWORD* outValue)
{
    if (subKey == NULL || outValue == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD type = 0;
    DWORD size = sizeof(DWORD);
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)outValue, &size);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS && type == REG_DWORD);
}

BOOL Reg_ReadQword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    ULONGLONG* outValue)
{
    if (subKey == NULL || outValue == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD type = 0;
    DWORD size = sizeof(ULONGLONG);
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)outValue, &size);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS && type == REG_QWORD);
}

BOOL Reg_ReadString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    WCHAR* outValue,
    DWORD outValueCch)
{
    if (subKey == NULL || outValue == NULL || outValueCch == 0) {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD type = 0;
    DWORD size = outValueCch * sizeof(WCHAR);
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)outValue, &size);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ));
}

BOOL Reg_ReadExpandString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    WCHAR* outValue,
    DWORD outValueCch)
{
    WCHAR unexpanded[4096];
    if (!Reg_ReadString(hRootKey, subKey, valueName, unexpanded, 4096)) {
        return FALSE;
    }

    DWORD result = ExpandEnvironmentStringsW(unexpanded, outValue, outValueCch);
    return (result > 0 && result < outValueCch);
}

BOOL Reg_ReadBinary(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    BYTE* outData,
    DWORD* inOutSize)
{
    if (subKey == NULL || outData == NULL || inOutSize == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD type = 0;
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &type, outData, inOutSize);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

BOOL Reg_ValueExists(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName)
{
    if (subKey == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    LONG result = RegQueryValueExW(hKey, valueName, NULL, NULL, NULL, NULL);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

BOOL Reg_KeyExists(
    HKEY hRootKey,
    const WCHAR* subKey)
{
    if (subKey == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    RegCloseKey(hKey);
    return TRUE;
}

/* ================================================================
 * Registry Write Functions
 * ================================================================ */

BOOL Reg_WriteDword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    DWORD value,
    RegStateStore* stateStore)
{
    if (subKey == NULL) {
        return FALSE;
    }

    /* Track original value if state store provided */
    if (stateStore != NULL) {
        RegState_AddEntry(stateStore, hRootKey, subKey, valueName);
    }

    HKEY hKey;
    if (RegCreateKeyExW(hRootKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    LONG result = RegSetValueExW(hKey, valueName, 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

BOOL Reg_WriteQword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    ULONGLONG value,
    RegStateStore* stateStore)
{
    if (subKey == NULL) {
        return FALSE;
    }

    if (stateStore != NULL) {
        RegState_AddEntry(stateStore, hRootKey, subKey, valueName);
    }

    HKEY hKey;
    if (RegCreateKeyExW(hRootKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    LONG result = RegSetValueExW(hKey, valueName, 0, REG_QWORD, (LPBYTE)&value, sizeof(ULONGLONG));
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

BOOL Reg_WriteString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const WCHAR* value,
    RegStateStore* stateStore)
{
    if (subKey == NULL || value == NULL) {
        return FALSE;
    }

    if (stateStore != NULL) {
        RegState_AddEntry(stateStore, hRootKey, subKey, valueName);
    }

    HKEY hKey;
    if (RegCreateKeyExW(hRootKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD size = (DWORD)((wcslen(value) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, valueName, 0, REG_SZ, (LPBYTE)value, size);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

BOOL Reg_WriteExpandString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const WCHAR* value,
    RegStateStore* stateStore)
{
    if (subKey == NULL || value == NULL) {
        return FALSE;
    }

    if (stateStore != NULL) {
        RegState_AddEntry(stateStore, hRootKey, subKey, valueName);
    }

    HKEY hKey;
    if (RegCreateKeyExW(hRootKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD size = (DWORD)((wcslen(value) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, valueName, 0, REG_EXPAND_SZ, (LPBYTE)value, size);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

BOOL Reg_WriteBinary(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const BYTE* data,
    DWORD dataSize,
    RegStateStore* stateStore)
{
    if (subKey == NULL || data == NULL) {
        return FALSE;
    }

    if (stateStore != NULL) {
        RegState_AddEntry(stateStore, hRootKey, subKey, valueName);
    }

    HKEY hKey;
    if (RegCreateKeyExW(hRootKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    LONG result = RegSetValueExW(hKey, valueName, 0, REG_BINARY, data, dataSize);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

BOOL Reg_DeleteValue(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    RegStateStore* stateStore)
{
    if (subKey == NULL) {
        return FALSE;
    }

    if (stateStore != NULL) {
        RegState_AddEntry(stateStore, hRootKey, subKey, valueName);
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    LONG result = RegDeleteValueW(hKey, valueName);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
}

BOOL Reg_CreateKey(
    HKEY hRootKey,
    const WCHAR* subKey)
{
    if (subKey == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegCreateKeyExW(hRootKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_READ, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    RegCloseKey(hKey);
    return TRUE;
}

BOOL Reg_DeleteKeyRecursive(
    HKEY hRootKey,
    const WCHAR* subKey)
{
    if (subKey == NULL) {
        return FALSE;
    }

    /* Use RegDeleteTreeW if available (Vista+) */
    return (RegDeleteTreeW(hRootKey, subKey) == ERROR_SUCCESS);
}

/* ================================================================
 * Policy-Specific Functions
 * ================================================================ */

BOOL Reg_SetWinlogonShell(
    const WCHAR* shellValue,
    RegStateStore* stateStore)
{
    return Reg_WriteString(HKEY_LOCAL_MACHINE, WINLOGON_KEY, L"Shell", shellValue, stateStore);
}

BOOL Reg_RestoreWinlogonShell(void)
{
    return Reg_WriteString(HKEY_LOCAL_MACHINE, WINLOGON_KEY, L"Shell", L"explorer.exe", NULL);
}

BOOL Reg_SetWinlogonUserinit(
    const WCHAR* userinitValue,
    RegStateStore* stateStore)
{
    return Reg_WriteString(HKEY_LOCAL_MACHINE, WINLOGON_KEY, L"Userinit", userinitValue, stateStore);
}

BOOL Reg_RestoreWinlogonUserinit(void)
{
    return Reg_WriteString(HKEY_LOCAL_MACHINE, WINLOGON_KEY, L"Userinit",
                          L"C:\\Windows\\system32\\userinit.exe,", NULL);
}

BOOL Reg_SetExplorerRestriction(
    const WCHAR* policyName,
    DWORD value,
    RegStateStore* stateStore)
{
    return Reg_WriteDword(HKEY_CURRENT_USER, EXPLORER_POLICIES_KEY, policyName, value, stateStore);
}

BOOL Reg_ClearExplorerRestrictions(void)
{
    return Reg_DeleteKeyRecursive(HKEY_CURRENT_USER, EXPLORER_POLICIES_KEY);
}

BOOL Reg_SetGpoPolicy(
    BOOL machinePolicy,
    const WCHAR* policyPath,
    const WCHAR* valueName,
    DWORD value,
    RegStateStore* stateStore)
{
    HKEY hRoot = machinePolicy ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    return Reg_WriteDword(hRoot, policyPath, valueName, value, stateStore);
}

/* ================================================================
 * Tamper Detection
 * ================================================================ */

HANDLE Reg_MonitorKeyStart(
    HKEY hRootKey,
    const WCHAR* subKey,
    BOOL watchSubtree)
{
    if (subKey == NULL) {
        return NULL;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_NOTIFY, &hKey) != ERROR_SUCCESS) {
        return NULL;
    }

    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL) {
        RegCloseKey(hKey);
        return NULL;
    }

    LONG result = RegNotifyChangeKeyValue(
        hKey,
        watchSubtree,
        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        hEvent,
        TRUE);

    if (result != ERROR_SUCCESS) {
        CloseHandle(hEvent);
        RegCloseKey(hKey);
        return NULL;
    }

    /* Note: hKey must remain open for monitoring to work */
    /* In production, store hKey alongside hEvent */
    return hEvent;
}

BOOL Reg_MonitorKeyChanged(HANDLE hEvent, DWORD timeoutMs)
{
    if (hEvent == NULL) {
        return FALSE;
    }

    DWORD result = WaitForSingleObject(hEvent, timeoutMs);
    return (result == WAIT_OBJECT_0);
}

void Reg_MonitorKeyStop(HANDLE hEvent)
{
    if (hEvent != NULL) {
        CloseHandle(hEvent);
    }
}

BOOL Reg_VerifyStateIntegrity(
    RegStateStore* store,
    DWORD* outMismatchCount)
{
    if (store == NULL) {
        return FALSE;
    }

    DWORD mismatches = 0;

    for (DWORD i = 0; i < store->entryCount; i++) {
        RegEntry* entry = &store->entries[i];

        /* Parse root key from path */
        WCHAR rootKeyName[32];
        const WCHAR* subKey = wcschr(entry->keyPath, L'\\');
        if (subKey == NULL) {
            continue;
        }

        size_t rootLen = subKey - entry->keyPath;
        if (rootLen >= 32) continue;
        wcsncpy_s(rootKeyName, 32, entry->keyPath, rootLen);
        rootKeyName[rootLen] = L'\0';
        subKey++; /* Skip backslash */

        HKEY hRootKey = ParseRootKeyName(rootKeyName);
        if (hRootKey == NULL) {
            mismatches++;
            continue;
        }

        /* Read current value from registry */
        RegEntry currentEntry;
        ZeroMemory(&currentEntry, sizeof(currentEntry));

        BOOL currentExists = ReadRegistryValue(hRootKey, subKey,
            entry->valueName[0] ? entry->valueName : NULL, &currentEntry);

        /* Compare with stored state */
        if (entry->existed) {
            if (!currentExists) {
                /* Value was deleted - mismatch */
                mismatches++;
            } else if (entry->type != currentEntry.type ||
                       entry->dataSize != currentEntry.dataSize ||
                       memcmp(entry->data, currentEntry.data, entry->dataSize) != 0) {
                /* Value was modified - mismatch */
                mismatches++;
            }
        } else {
            /* Entry didn't exist when we started */
            if (currentExists) {
                /* Value was added - this might be expected if we wrote it */
                /* Don't count as mismatch unless we want strict verification */
            }
        }
    }

    if (outMismatchCount != NULL) {
        *outMismatchCount = mismatches;
    }

    return (mismatches == 0);
}

BOOL Reg_ReapplyState(RegStateStore* store)
{
    if (store == NULL) {
        return FALSE;
    }

    BOOL success = TRUE;

    for (DWORD i = 0; i < store->entryCount; i++) {
        RegEntry* entry = &store->entries[i];

        /* Parse root key from path */
        WCHAR rootKeyName[32];
        const WCHAR* subKey = wcschr(entry->keyPath, L'\\');
        if (subKey == NULL) {
            continue;
        }

        size_t rootLen = subKey - entry->keyPath;
        if (rootLen >= 32) continue;
        wcsncpy_s(rootKeyName, 32, entry->keyPath, rootLen);
        rootKeyName[rootLen] = L'\0';
        subKey++; /* Skip backslash */

        HKEY hRootKey = ParseRootKeyName(rootKeyName);
        if (hRootKey == NULL) {
            success = FALSE;
            continue;
        }

        /* Check if current value matches what we expect */
        RegEntry currentEntry;
        ZeroMemory(&currentEntry, sizeof(currentEntry));
        BOOL currentExists = ReadRegistryValue(hRootKey, subKey,
            entry->valueName[0] ? entry->valueName : NULL, &currentEntry);

        /* If the value was tampered (doesn't match our stored original),
         * we need to re-apply whatever modification we made.
         * This function tracks "modified" values, not originals.
         * For now, we just re-write the stored value. */

        if (entry->existed && entry->dataSize > 0) {
            /* Re-write the stored value */
            if (!WriteRegistryValue(hRootKey, subKey,
                                    entry->valueName[0] ? entry->valueName : NULL, entry)) {
                success = FALSE;
            }
        }
    }

    return success;
}

/* ================================================================
 * Internal Functions
 * ================================================================ */

static BOOL ReadRegistryValue(HKEY hRootKey, const WCHAR* subKey, const WCHAR* valueName, RegEntry* entry)
{
    if (entry == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD type = 0;
    DWORD size = sizeof(entry->data);
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &type, entry->data, &size);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    entry->dataSize = size;
    switch (type) {
        case REG_DWORD: entry->type = REG_VAL_DWORD; break;
        case REG_QWORD: entry->type = REG_VAL_QWORD; break;
        case REG_SZ: entry->type = REG_VAL_STRING; break;
        case REG_EXPAND_SZ: entry->type = REG_VAL_EXPAND_STRING; break;
        case REG_MULTI_SZ: entry->type = REG_VAL_MULTI_STRING; break;
        default: entry->type = REG_VAL_BINARY; break;
    }

    return TRUE;
}

static BOOL WriteRegistryValue(HKEY hRootKey, const WCHAR* subKey, const WCHAR* valueName, const RegEntry* entry)
{
    if (entry == NULL) {
        return FALSE;
    }

    HKEY hKey;
    if (RegCreateKeyExW(hRootKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD type;
    switch (entry->type) {
        case REG_VAL_DWORD: type = REG_DWORD; break;
        case REG_VAL_QWORD: type = REG_QWORD; break;
        case REG_VAL_STRING: type = REG_SZ; break;
        case REG_VAL_EXPAND_STRING: type = REG_EXPAND_SZ; break;
        case REG_VAL_MULTI_STRING: type = REG_MULTI_SZ; break;
        default: type = REG_BINARY; break;
    }

    LONG result = RegSetValueExW(hKey, valueName, 0, type, entry->data, entry->dataSize);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

static const WCHAR* GetRootKeyName(HKEY hKey)
{
    if (hKey == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (hKey == HKEY_CURRENT_USER) return L"HKCU";
    if (hKey == HKEY_CLASSES_ROOT) return L"HKCR";
    if (hKey == HKEY_USERS) return L"HKU";
    if (hKey == HKEY_CURRENT_CONFIG) return L"HKCC";
    return L"UNKNOWN";
}

static HKEY ParseRootKeyName(const WCHAR* name)
{
    if (_wcsicmp(name, L"HKLM") == 0 || _wcsicmp(name, L"HKEY_LOCAL_MACHINE") == 0) return HKEY_LOCAL_MACHINE;
    if (_wcsicmp(name, L"HKCU") == 0 || _wcsicmp(name, L"HKEY_CURRENT_USER") == 0) return HKEY_CURRENT_USER;
    if (_wcsicmp(name, L"HKCR") == 0 || _wcsicmp(name, L"HKEY_CLASSES_ROOT") == 0) return HKEY_CLASSES_ROOT;
    if (_wcsicmp(name, L"HKU") == 0 || _wcsicmp(name, L"HKEY_USERS") == 0) return HKEY_USERS;
    if (_wcsicmp(name, L"HKCC") == 0 || _wcsicmp(name, L"HKEY_CURRENT_CONFIG") == 0) return HKEY_CURRENT_CONFIG;
    return NULL;
}
