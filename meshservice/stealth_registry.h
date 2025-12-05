/*
 * Stealth Registry Module
 *
 * Registry wrapper with state persistence for backup/restore during
 * SecureEnter/SecureExit lockdown transitions.
 *
 * Ported from:
 * - GiovanniDicanio/WinReg (MIT) - High-level C++ wrapper for Windows Registry
 * - Windows API: RegSaveKeyEx / RegRestoreKey
 */

#ifndef STEALTH_REGISTRY_H
#define STEALTH_REGISTRY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Registry value types we track */
typedef enum RegValueType {
    REG_VAL_DWORD = 0,
    REG_VAL_QWORD = 1,
    REG_VAL_STRING = 2,
    REG_VAL_EXPAND_STRING = 3,
    REG_VAL_MULTI_STRING = 4,
    REG_VAL_BINARY = 5
} RegValueType;

/* Single registry entry for state tracking */
typedef struct RegEntry {
    WCHAR keyPath[512];         /* Full registry key path */
    WCHAR valueName[256];       /* Value name (empty for default) */
    RegValueType type;          /* Value type */
    DWORD dataSize;             /* Size of data */
    BYTE data[4096];            /* Value data */
    BOOL existed;               /* Whether value existed before modification */
} RegEntry;

/* State store for tracking modified registry entries */
typedef struct RegStateStore {
    WCHAR stateFilePath[MAX_PATH];
    RegEntry* entries;
    DWORD entryCount;
    DWORD entryCapacity;
    BOOL modified;
} RegStateStore;

/* ================================================================
 * State Store Functions
 * ================================================================ */

/* Initialize state store */
BOOL RegState_Init(RegStateStore* store, const WCHAR* stateFilePath);

/* Free state store resources */
void RegState_Free(RegStateStore* store);

/* Load state from JSON file */
BOOL RegState_Load(RegStateStore* store);

/* Save state to JSON file */
BOOL RegState_Save(const RegStateStore* store);

/* Add entry to state store (records original value) */
BOOL RegState_AddEntry(
    RegStateStore* store,
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName);

/* Restore all entries to original state */
BOOL RegState_RestoreAll(RegStateStore* store);

/* Clear state store (removes file too) */
BOOL RegState_Clear(RegStateStore* store);

/* ================================================================
 * Registry Read Functions
 * ================================================================ */

/* Read DWORD value */
BOOL Reg_ReadDword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    DWORD* outValue);

/* Read QWORD value */
BOOL Reg_ReadQword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    ULONGLONG* outValue);

/* Read string value */
BOOL Reg_ReadString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    WCHAR* outValue,
    DWORD outValueCch);

/* Read expand string value (resolves environment variables) */
BOOL Reg_ReadExpandString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    WCHAR* outValue,
    DWORD outValueCch);

/* Read binary value */
BOOL Reg_ReadBinary(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    BYTE* outData,
    DWORD* inOutSize);

/* Check if value exists */
BOOL Reg_ValueExists(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName);

/* Check if key exists */
BOOL Reg_KeyExists(
    HKEY hRootKey,
    const WCHAR* subKey);

/* ================================================================
 * Registry Write Functions (with state tracking)
 * ================================================================ */

/* Write DWORD value (optionally track original) */
BOOL Reg_WriteDword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    DWORD value,
    RegStateStore* stateStore);

/* Write QWORD value */
BOOL Reg_WriteQword(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    ULONGLONG value,
    RegStateStore* stateStore);

/* Write string value */
BOOL Reg_WriteString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const WCHAR* value,
    RegStateStore* stateStore);

/* Write expand string value */
BOOL Reg_WriteExpandString(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const WCHAR* value,
    RegStateStore* stateStore);

/* Write binary value */
BOOL Reg_WriteBinary(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    const BYTE* data,
    DWORD dataSize,
    RegStateStore* stateStore);

/* Delete value (track original for restore) */
BOOL Reg_DeleteValue(
    HKEY hRootKey,
    const WCHAR* subKey,
    const WCHAR* valueName,
    RegStateStore* stateStore);

/* Create key if not exists */
BOOL Reg_CreateKey(
    HKEY hRootKey,
    const WCHAR* subKey);

/* Delete key recursively */
BOOL Reg_DeleteKeyRecursive(
    HKEY hRootKey,
    const WCHAR* subKey);

/* ================================================================
 * Policy-Specific Functions
 * ================================================================ */

/* Set Winlogon Shell value (with backup) */
BOOL Reg_SetWinlogonShell(
    const WCHAR* shellValue,
    RegStateStore* stateStore);

/* Restore Winlogon Shell to default */
BOOL Reg_RestoreWinlogonShell(void);

/* Set Winlogon Userinit value (with backup) */
BOOL Reg_SetWinlogonUserinit(
    const WCHAR* userinitValue,
    RegStateStore* stateStore);

/* Restore Winlogon Userinit to default */
BOOL Reg_RestoreWinlogonUserinit(void);

/* Set Explorer restriction policy */
BOOL Reg_SetExplorerRestriction(
    const WCHAR* policyName,
    DWORD value,
    RegStateStore* stateStore);

/* Clear all Explorer restrictions */
BOOL Reg_ClearExplorerRestrictions(void);

/* Set GPO-style registry policy */
BOOL Reg_SetGpoPolicy(
    BOOL machinePolicy,  /* TRUE for HKLM, FALSE for HKCU */
    const WCHAR* policyPath,
    const WCHAR* valueName,
    DWORD value,
    RegStateStore* stateStore);

/* ================================================================
 * Tamper Detection
 * ================================================================ */

/* Monitor registry key for changes */
HANDLE Reg_MonitorKeyStart(
    HKEY hRootKey,
    const WCHAR* subKey,
    BOOL watchSubtree);

/* Check if monitored key changed */
BOOL Reg_MonitorKeyChanged(HANDLE hEvent, DWORD timeoutMs);

/* Stop monitoring */
void Reg_MonitorKeyStop(HANDLE hEvent);

/* Verify state store entries match current registry */
BOOL Reg_VerifyStateIntegrity(
    RegStateStore* store,
    DWORD* outMismatchCount);

/* Re-apply all state store entries (tamper recovery) */
BOOL Reg_ReapplyState(RegStateStore* store);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_REGISTRY_H */
