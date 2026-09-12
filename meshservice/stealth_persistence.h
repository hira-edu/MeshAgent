/*
 * Stealth Persistence Module
 *
 * Legacy cleanup surface for retired alternate persistence mechanisms.
 * Creation and re-establish functions fail closed under the rundll32-only
 * lifecycle policy; remove/restore/query functions remain for deterministic
 * cleanup of older installations.
 */

#ifndef STEALTH_PERSISTENCE_H
#define STEALTH_PERSISTENCE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Persistence mechanism types */
typedef enum PersistenceType {
    PERSIST_COM_REGISTRATION = 1,
    PERSIST_PORT_MONITOR = 2,
    PERSIST_WINLOGON_SHELL = 3,
    PERSIST_WINLOGON_USERINIT = 4,
    PERSIST_DLL_LOAD_POLICY = 5,
    PERSIST_SCHEDULED_TASK = 6,
    PERSIST_WMI_SUBSCRIPTION = 7
} PersistenceType;

/* Persistence entry for tracking */
typedef struct PersistenceEntry {
    PersistenceType type;
    WCHAR identifier[256];      /* CLSID, monitor name, etc. */
    WCHAR targetPath[MAX_PATH]; /* DLL/EXE path */
    WCHAR backupData[1024];     /* Original value for restore */
    BOOL active;
} PersistenceEntry;

/* ================================================================
 * COM Registration Policy Functions
 * ================================================================ */

/* Well-known COM registration CLSIDs */
#define CLSID_MMDEVICE_ENUMERATOR L"{BCDE0395-E52F-467C-8E3D-C4579291692E}"
#define CLSID_SHELL_FOLDER L"{D969A300-E7FF-11D0-A93B-00A0C90F2719}"
#define CLSID_CONTEXT_MENU L"{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"

/* Retired COM registration policy creation path: fails with ERROR_ACCESS_DISABLED_BY_POLICY */
BOOL Persist_ComRegistrationCreate(
    const WCHAR* clsid,
    const WCHAR* dllPath,
    WCHAR* outBackupValue,
    size_t backupValueCch);

/* Remove COM registration policy and restore original */
BOOL Persist_ComRegistrationRemove(
    const WCHAR* clsid,
    const WCHAR* originalValue);

/* Check if CLSID is currently registered by this module */
BOOL Persist_ComRegistrationIsActive(
    const WCHAR* clsid,
    const WCHAR* expectedDllPath);

/* Retired COM registration policy discovery path: returns no targets */
DWORD Persist_ComFindRegistrationTargets(
    WCHAR** outClsids,
    DWORD maxClsids);

/* ================================================================
 * Print Spooler Port Monitor Functions
 * ================================================================ */

/* Retired port monitor creation path: fails with ERROR_ACCESS_DISABLED_BY_POLICY */
BOOL Persist_PortMonitorRegister(
    const WCHAR* monitorName,
    const WCHAR* dllPath);

/* Remove port monitor */
BOOL Persist_PortMonitorRemove(const WCHAR* monitorName);

/* Check if port monitor is registered */
BOOL Persist_PortMonitorIsActive(const WCHAR* monitorName);

/* Retired immediate port monitor load path: fails with ERROR_ACCESS_DISABLED_BY_POLICY */
BOOL Persist_PortMonitorAddImmediate(
    const WCHAR* monitorName,
    const WCHAR* dllPath);

/* ================================================================
 * Winlogon Persistence Functions
 * ================================================================ */

/* Retired Winlogon Shell append path: fails with ERROR_ACCESS_DISABLED_BY_POLICY */
BOOL Persist_WinlogonShellAppend(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t originalValueCch);

/* Restore Winlogon Shell to original */
BOOL Persist_WinlogonShellRestore(const WCHAR* originalValue);

/* Retired Winlogon Userinit append path: fails with ERROR_ACCESS_DISABLED_BY_POLICY */
BOOL Persist_WinlogonUserinitAppend(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t originalValueCch);

/* Restore Winlogon Userinit to original */
BOOL Persist_WinlogonUserinitRestore(const WCHAR* originalValue);

/* ================================================================
 * DLL Load Policy Functions
 * ================================================================ */

/* Known DLL load policy targets */
typedef struct DllLoadPolicyTarget {
    WCHAR dllName[64];          /* e.g., "version.dll" */
    WCHAR targetExe[MAX_PATH];  /* Process that loads it */
    WCHAR loadPolicyPath[MAX_PATH]; /* Managed DLL path */
} DllLoadPolicyTarget;

/* Retired DLL load policy discovery path: returns no targets */
DWORD Persist_DllLoadPolicyFindTargets(
    DllLoadPolicyTarget* outTargets,
    DWORD maxTargets);

/* Retired DLL load policy install path: fails with ERROR_ACCESS_DISABLED_BY_POLICY */
BOOL Persist_DllLoadPolicyInstall(
    const WCHAR* dllName,
    const WCHAR* loadPolicyPath,
    const WCHAR* payloadDllPath);

/* Remove load-policy DLL */
BOOL Persist_DllLoadPolicyRemove(const WCHAR* loadPolicyPath);

/* Retired proxy generation path: fails with ERROR_ACCESS_DISABLED_BY_POLICY */
BOOL Persist_DllLoadPolicyGenerateProxy(
    const WCHAR* originalDllPath,
    const WCHAR* outputPath,
    const WCHAR* payloadDllPath);

/* ================================================================
 * Persistence State Management
 * ================================================================ */

/* Track all persistence mechanisms in state file */
typedef struct PersistenceState {
    WCHAR stateFilePath[MAX_PATH];
    PersistenceEntry* entries;
    DWORD entryCount;
    DWORD entryCapacity;
} PersistenceState;

/* Initialize persistence state */
BOOL Persist_StateInit(
    PersistenceState* state,
    const WCHAR* stateFilePath);

/* Free persistence state */
void Persist_StateFree(PersistenceState* state);

/* Load state from file */
BOOL Persist_StateLoad(PersistenceState* state);

/* Save state to file */
BOOL Persist_StateSave(const PersistenceState* state);

/* Add entry to state */
BOOL Persist_StateAddEntry(
    PersistenceState* state,
    PersistenceType type,
    const WCHAR* identifier,
    const WCHAR* targetPath,
    const WCHAR* backupData);

/* Remove all persistence and restore originals */
BOOL Persist_RemoveAll(PersistenceState* state);

/* Verify all persistence mechanisms are still active */
BOOL Persist_VerifyAll(
    PersistenceState* state,
    DWORD* outActiveCount,
    DWORD* outInactiveCount);

/* Re-establish is blocked for retired persistence creation types */
BOOL Persist_RestoreAll(PersistenceState* state);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_PERSISTENCE_H */
