/*
 * stealth_state.h - State persistence module for tracking lockdown artifacts
 *
 * Implements W5: "Track every artifact touched during lockdown (services stopped,
 * tasks disabled, registry entries) in a state-store module so SecureExit/uninstall
 * restores cleanly."
 *
 * References:
 * - nlohmann/json (MIT) - JSON serialization patterns
 * - GiovanniDicanio/WinReg (MIT) - Registry backup/restore
 * - SQLite (Public Domain) - Alternative persistence
 * - Windows API: RegSaveKeyEx / RegRestoreKey
 */

#ifndef STEALTH_STATE_H
#define STEALTH_STATE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* State file format version for migrations */
#define STATE_VERSION_CURRENT 1

/* Maximum artifacts per category */
#define STATE_MAX_SERVICES 32
#define STATE_MAX_TASKS 64
#define STATE_MAX_REGISTRY 256
#define STATE_MAX_FILES 128
#define STATE_MAX_PROCESSES 32

/* Artifact types */
typedef enum StateArtifactType {
    STATE_ARTIFACT_SERVICE = 0,
    STATE_ARTIFACT_TASK = 1,
    STATE_ARTIFACT_REGISTRY = 2,
    STATE_ARTIFACT_FILE = 3,
    STATE_ARTIFACT_PROCESS = 4,
    STATE_ARTIFACT_WMI = 5,
    STATE_ARTIFACT_COM = 6,
    STATE_ARTIFACT_POLICY = 7
} StateArtifactType;

/* Service state record */
typedef struct StateService {
    WCHAR serviceName[64];
    WCHAR displayName[128];
    DWORD originalStartType;     /* SERVICE_AUTO_START, etc. */
    DWORD originalState;         /* SERVICE_RUNNING, etc. */
    DWORD appliedStartType;
    DWORD appliedState;
    BOOL modified;
    BOOL restored;
} StateService;

/* Task state record */
typedef struct StateTask {
    WCHAR taskPath[256];
    WCHAR taskName[128];
    BOOL originalEnabled;
    BOOL appliedEnabled;
    WCHAR originalXml[4096];     /* Full task XML for recreation */
    BOOL created;                /* TRUE if we created it, FALSE if modified */
    BOOL restored;
} StateTask;

/* Registry state record */
typedef struct StateRegistry {
    WCHAR keyPath[512];          /* Full path including root (HKLM\...) */
    WCHAR valueName[128];
    DWORD originalType;
    BYTE originalData[1024];
    DWORD originalDataSize;
    DWORD appliedType;
    BYTE appliedData[1024];
    DWORD appliedDataSize;
    BOOL existed;                /* TRUE if value existed before */
    BOOL restored;
} StateRegistry;

/* File state record */
typedef struct StateFile {
    WCHAR filePath[MAX_PATH];
    WCHAR backupPath[MAX_PATH];  /* Where we stored the backup */
    BOOL existed;                /* TRUE if file existed before */
    BOOL created;                /* TRUE if we created it */
    BOOL restored;
} StateFile;

/* Process state record */
typedef struct StateProcess {
    WCHAR processName[128];
    WCHAR exePath[MAX_PATH];
    DWORD originalPid;
    BOOL wasRunning;
    BOOL stopped;
    BOOL restored;
} StateProcess;

/* WMI subscription state */
typedef struct StateWmi {
    WCHAR filterName[128];
    WCHAR consumerName[128];
    WCHAR bindingName[128];
    WCHAR query[512];
    BOOL created;
    BOOL removed;
} StateWmi;

/* COM registration state */
typedef struct StateCom {
    WCHAR clsid[64];
    WCHAR originalValue[MAX_PATH];
    WCHAR appliedValue[MAX_PATH];
    BOOL hijacked;
    BOOL restored;
} StateCom;

/* Complete state store */
typedef struct StateStore {
    /* Header */
    DWORD version;
    DWORD flags;
    FILETIME createTime;
    FILETIME modifyTime;

    /* Service artifacts */
    StateService services[STATE_MAX_SERVICES];
    DWORD serviceCount;

    /* Task artifacts */
    StateTask tasks[STATE_MAX_TASKS];
    DWORD taskCount;

    /* Registry artifacts */
    StateRegistry registry[STATE_MAX_REGISTRY];
    DWORD registryCount;

    /* File artifacts */
    StateFile files[STATE_MAX_FILES];
    DWORD fileCount;

    /* Process artifacts */
    StateProcess processes[STATE_MAX_PROCESSES];
    DWORD processCount;

    /* WMI artifacts */
    StateWmi wmiSubscriptions[16];
    DWORD wmiCount;

    /* COM artifacts */
    StateCom comRegistrations[16];
    DWORD comCount;

    /* Checksums for integrity */
    DWORD checksum;
} StateStore;

/* State store handle */
typedef struct StateHandle {
    StateStore* store;
    WCHAR filePath[MAX_PATH];
    HANDLE hFile;
    HANDLE hMapping;
    BOOL readOnly;
    CRITICAL_SECTION lock;
} StateHandle;

/*
 * Initialize state store
 * Creates or opens existing state file
 */
BOOL State_Init(StateHandle* handle, const WCHAR* filePath, BOOL readOnly);

/*
 * Create new empty state store
 */
BOOL State_Create(StateHandle* handle, const WCHAR* filePath);

/*
 * Load existing state from file
 */
BOOL State_Load(StateHandle* handle, const WCHAR* filePath);

/*
 * Save current state to file
 */
BOOL State_Save(StateHandle* handle);

/*
 * Close and cleanup state handle
 */
void State_Close(StateHandle* handle);

/*
 * Add a service artifact to track
 */
BOOL State_AddService(StateHandle* handle, const StateService* service);

/*
 * Add a task artifact to track
 */
BOOL State_AddTask(StateHandle* handle, const StateTask* task);

/*
 * Add a registry artifact to track
 */
BOOL State_AddRegistry(StateHandle* handle, const StateRegistry* registry);

/*
 * Add a file artifact to track
 */
BOOL State_AddFile(StateHandle* handle, const StateFile* file);

/*
 * Add a process artifact to track
 */
BOOL State_AddProcess(StateHandle* handle, const StateProcess* process);

/*
 * Add a WMI subscription artifact
 */
BOOL State_AddWmi(StateHandle* handle, const StateWmi* wmi);

/*
 * Add a COM registration artifact
 */
BOOL State_AddCom(StateHandle* handle, const StateCom* com);

/*
 * Find a service by name
 */
StateService* State_FindService(StateHandle* handle, const WCHAR* serviceName);

/*
 * Find a task by path
 */
StateTask* State_FindTask(StateHandle* handle, const WCHAR* taskPath);

/*
 * Find a registry entry by key path and value name
 */
StateRegistry* State_FindRegistry(StateHandle* handle, const WCHAR* keyPath, const WCHAR* valueName);

/*
 * Mark a service as restored
 */
BOOL State_MarkServiceRestored(StateHandle* handle, const WCHAR* serviceName);

/*
 * Mark a task as restored
 */
BOOL State_MarkTaskRestored(StateHandle* handle, const WCHAR* taskPath);

/*
 * Mark a registry entry as restored
 */
BOOL State_MarkRegistryRestored(StateHandle* handle, const WCHAR* keyPath, const WCHAR* valueName);

/*
 * Restore all services to original state
 */
DWORD State_RestoreAllServices(StateHandle* handle);

/*
 * Restore all tasks to original state
 */
DWORD State_RestoreAllTasks(StateHandle* handle);

/*
 * Restore all registry entries to original state
 */
DWORD State_RestoreAllRegistry(StateHandle* handle);

/*
 * Restore all files to original state
 */
DWORD State_RestoreAllFiles(StateHandle* handle);

/*
 * Restore everything
 */
DWORD State_RestoreAll(StateHandle* handle);

/*
 * Get count of unrestored items
 */
DWORD State_GetUnrestoredCount(StateHandle* handle);

/*
 * Export state to JSON string
 */
BOOL State_ExportJson(StateHandle* handle, WCHAR* buffer, DWORD bufferSize);

/*
 * Import state from JSON string
 */
BOOL State_ImportJson(StateHandle* handle, const WCHAR* json);

/*
 * Verify state file integrity
 */
BOOL State_VerifyIntegrity(StateHandle* handle);

/*
 * Backup registry key using RegSaveKeyEx
 */
BOOL State_BackupRegistryKey(HKEY hKey, const WCHAR* subKey, const WCHAR* backupPath);

/*
 * Restore registry key using RegRestoreKey
 */
BOOL State_RestoreRegistryKey(HKEY hKey, const WCHAR* subKey, const WCHAR* backupPath);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_STATE_H */
