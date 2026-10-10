/*
 * MeshAgent Service Deployment Module
 *
 * Handles full deployment process including:
 * - File deployment to System32
 * - Service registration (scoped service group)
 * - Firewall exception rules
 * - Registry configuration
 * - Local logging
 * - Lifecycle maintenance
 */

#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <stdarg.h>
#include <wctype.h>
#include <tlhelp32.h>
#include "runtime_core.h"
#include "runtime_host_contract.h"
#include "service_utils.h"
#include "branding_util.h"
#include "../meshcore/diagnostic_log.h"
#include "service_security.h"
#include "service_bundle.h"
#include "service_defaults.h"
#include "fault_recovery.h"
void ServiceDeploy_LogInstallEvent(const wchar_t* format, ...);
#include "service_legacy_host.h"
#include "service_legacy_process.h"
static BOOL ServiceDeploy_ValidateCopiedLegacyHost(const wchar_t* host, const wchar_t* dll);
#include "service_binding_transaction.h"
#include "service_transaction_journal.h"
#include "../meshcore/agentcore.h"
#include "../meshcore/config/update_defines.h"
#include "../microstack/ILibSimpleDataStore.h"

#ifndef IDR_SERVICE_BUNDLE_DLL
#define IDR_SERVICE_BUNDLE_DLL 101
#endif

#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260L
#endif

static void MeshInstaller_NormalizePathSeparators(wchar_t* path)
{
    if (path == NULL) { return; }
    for (size_t i = 0; path[i] != L'\0'; ++i)
    {
        if (path[i] == L'/')
        {
            path[i] = L'\\';
        }
    }
}

static BOOL MeshInstaller_GetDefaultInstallRoot(wchar_t* buffer, size_t count)
{
    if (buffer == NULL || count == 0) { return FALSE; }
    PWSTR programData = NULL;
    HRESULT hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, NULL, &programData);
    if (FAILED(hr) || programData == NULL)
    {
        return FALSE;
    }

    hr = StringCchCopyW(buffer, count, programData);
    CoTaskMemFree(programData);
    if (FAILED(hr)) { return FALSE; }

    MeshInstaller_NormalizePathSeparators(buffer);
    size_t len = wcslen(buffer);
    if (len > 0 && buffer[len - 1] != L'\\')
    {
        if (FAILED(StringCchCatW(buffer, count, L"\\"))) { return FALSE; }
    }
    if (FAILED(StringCchCatW(buffer, count, SERVICE_FALLBACK_SERVICE_NAME))) { return FALSE; }
    return TRUE;
}

static BOOL MeshInstaller_CombinePath(wchar_t* dest, size_t destLen, const wchar_t* root, const wchar_t* leaf)
{
    if (dest == NULL || destLen == 0) { return FALSE; }
    dest[0] = L'\0';
    if (root == NULL || root[0] == L'\0') { return FALSE; }

    if (FAILED(StringCchCopyW(dest, destLen, root))) { return FALSE; }
    MeshInstaller_NormalizePathSeparators(dest);

    if (leaf != NULL && leaf[0] != L'\0')
    {
        WCHAR leafCopy[MAX_PATH] = {0};
        if (FAILED(StringCchCopyW(leafCopy, _countof(leafCopy), leaf))) { return FALSE; }
        MeshInstaller_NormalizePathSeparators(leafCopy);
        size_t len = wcslen(dest);
        if (len > 0 && dest[len - 1] != L'\\')
        {
            if (FAILED(StringCchCatW(dest, destLen, L"\\"))) { return FALSE; }
        }
        if (FAILED(StringCchCatW(dest, destLen, leafCopy))) { return FALSE; }
    }

    return TRUE;
}

// Forward declaration - implementation after global variables
static void ServiceDeploy_UpdateServiceRecoveryStatePath(const wchar_t* installRoot);

// Forward declarations for service lifecycle helpers
struct ServiceUpdateTransaction;
struct ServiceIdentitySnapshot;
static BOOL ServiceDeploy_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void ServiceDeploy_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting);
static BOOL ServiceDeploy_ApplyServiceRecoveryTask(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, const wchar_t* serviceEventName, ServiceRecoveryState* state);
static BOOL ServiceDeploy_ApplyServiceRecoveryMonitor(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, ServiceRecoveryState* state);
static BOOL ServiceDeploy_ConfigureServiceRecoveryIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);

static SC_ACTION* ServiceDeploy_CreateRestartPlan(size_t actionCount, DWORD delayMs, DWORD* actionCountOut);
static SC_ACTION* ServiceDeploy_BuildRecoveryActionsFromCsv(const wchar_t* csv, DWORD delayMs, DWORD* actionCountOut);
static void ServiceDeploy_TrimWhitespaceInplace(wchar_t* value);
static SC_ACTION_TYPE ServiceDeploy_MapRecoveryActionToken(const wchar_t* token);
static void ServiceDeploy_EnablePrivilege(const wchar_t* privilegeName);
void ServiceDeploy_LogInstallEvent(const wchar_t* format, ...);
static void ServiceDeploy_ImportWinHttpProxyFromIeBestEffort(void);
static void ServiceDeploy_LogAnsiMessage(const char* message);
void ServiceDeploy_SetInstallerLogPathToTemp(const wchar_t* fileName);
void ServiceDeploy_EnsureLoggingDefaults(void);
static BOOL ServiceDeploy_StopServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs, BOOL forceTerminate);
static BOOL ServiceDeploy_QueryServiceStartType(const wchar_t* serviceName, DWORD* startTypeOut);
static BOOL ServiceDeploy_SetServiceStartType(const wchar_t* serviceName, DWORD startType);
static BOOL ServiceDeploy_SetServiceAllowStop(const wchar_t* serviceName, BOOL allow);
static void ServiceDeploy_TerminateProcessesByPath(const wchar_t* exePath);
static void ServiceDeploy_TerminateProcessesByLoadedModulePath(const wchar_t* modulePath);
static BOOL ServiceDeploy_RemoveFileIfExists(const wchar_t* path, BOOL logOnFailure);
static BOOL ServiceDeploy_RemoveFileIfExistsWithTimeout(const wchar_t* path, DWORD timeoutMs, BOOL logOnFailure);
static BOOL ServiceDeploy_RemoveDirectoryTree(const wchar_t* path, BOOL logOnFailure);
void ServiceDeploy_LogPathState(const wchar_t* path);
static void ServiceDeploy_RemoveRunKeyEntry(const wchar_t* serviceName);
static BOOL ServiceDeploy_NormalizeTaskNameInplace(wchar_t* taskName, size_t capacity);
static BOOL ServiceDeploy_CopyTaskNameFromUtf8(const char* source, wchar_t* dest, size_t destLen);
static BOOL ServiceDeploy_FormatDefaultTaskName(const wchar_t* base, const wchar_t* suffix, wchar_t* dest, size_t destLen);
static void ServiceDeploy_SanitizeTaskHint(const wchar_t* input, wchar_t* output, size_t outputSize);
static void ServiceDeploy_BuildTaskPrefixFromHint(const wchar_t* hint, const wchar_t* fallback, wchar_t* output, size_t outputSize);
static BOOL ServiceDeploy_AddTaskCandidate(wchar_t candidates[][SERVICE_TASK_NAME_MAX], size_t* count, size_t capacity, const wchar_t* name);
static size_t ServiceDeploy_BuildTaskPrefixCandidates(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName, wchar_t candidates[][SERVICE_TASK_NAME_MAX], size_t capacity);
static BOOL ServiceDeploy_FindTaskByPrefixCandidates(wchar_t candidates[][SERVICE_TASK_NAME_MAX], size_t count, const wchar_t* token, wchar_t* outTaskPath, size_t outTaskPathCch);
static BOOL ServiceDeploy_FindServiceRecoveryMonitorByPrefixCandidates(wchar_t candidates[][SERVICE_TASK_NAME_MAX], size_t count, wchar_t* outFilterName, size_t outFilterNameCch, wchar_t* outHandlerName, size_t outHandlerNameCch);
static BOOL ServiceDeploy_RemoveScheduledTaskByName(const wchar_t* taskName, const wchar_t* context);
static void ServiceDeploy_RemoveScheduledTasks(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName);
static BOOL ServiceDeploy_EnsureConfigFile(const wchar_t* sourceExePath, const wchar_t* destPath);
static BOOL ServiceDeploy_EnsureMshFile(const wchar_t* sourceExePath, const wchar_t* destPath);
static BOOL ServiceDeploy_EnsureServiceHostDllFile(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, const wchar_t* destPath);
static BOOL ServiceDeploy_ConfigHasRequiredKeys(const wchar_t* configPath);
static BOOL ServiceDeploy_HasEmbeddedProvisioningManifest(const wchar_t* exePath);
static BOOL ServiceDeploy_BuildSiblingPathWithExtension(const wchar_t* sourcePath, const wchar_t* extension, wchar_t* outPath, size_t outPathCch);
static BOOL ServiceDeploy_BuildSiblingPathWithFileName(const wchar_t* sourcePath, const wchar_t* fileName, wchar_t* outPath, size_t outPathCch);
static BOOL ServiceDeploy_TryStageAndValidateServiceHostDll(const wchar_t* candidatePath, const wchar_t* destPath, const wchar_t* sourceLabel);
static BOOL ServiceDeploy_ExtractExecutableFromCommand(const wchar_t* command, wchar_t* exeOut, size_t exeOutCch);
static BOOL ServiceDeploy_ShouldEnableDebugConsole(void);
static void ServiceDeploy_AppendConfigOverride(const wchar_t* path, const char* key, const char* value);
static BOOL ServiceDeploy_ClearServiceRecovery(const wchar_t* serviceName);
static BOOL ServiceDeploy_DoFirewallRulesMatch(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath);
static BOOL ServiceDeploy_WaitForFirewallRuleConvergence(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath, DWORD timeoutMs);
static BOOL ServiceDeploy_RefreshFirewallRulesWithRetry(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath);
static BOOL ServiceDeploy_WaitForServiceAbsence(const wchar_t* serviceName, DWORD timeoutMs);
static BOOL ServiceDeploy_ServiceIsRunning(const wchar_t* serviceName);
static BOOL ServiceDeploy_SendMasterServiceControlRequest(const char* requestJson, char* response, size_t responseLen);
static BOOL ServiceDeploy_BuildInstalledMshPath(const wchar_t* exePath, wchar_t* mshPath, size_t mshPathCch);
static BOOL ServiceDeploy_InstalledProvisioningHealthy(const ServiceInstallPaths* paths, wchar_t* liveMshPath, size_t liveMshPathCch);
static BOOL ServiceDeploy_DataStoreIdentityPresent(const wchar_t* dbPath);
static BOOL ServiceDeploy_CopyFileOverwrite(const wchar_t* sourcePath, const wchar_t* destPath);
static BOOL ServiceDeploy_ExtractEmbeddedServiceHostDllFromExe(const wchar_t* exePath, const wchar_t* destPath);
static void ServiceDeploy_DeleteFileIfPresent(const wchar_t* path);
static const wchar_t* MeshInstaller_GetPathLeaf(const wchar_t* path);
static BOOL ServiceDeploy_DeleteUpdateTransactionArtifacts(const struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_TransactionPathsSafe(const ServiceInstallPaths* paths, const struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_FinalizeUpdateTransaction(const ServiceInstallPaths* paths, struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_PrepareUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL allowInstalledProvisioning, struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_BackupUpdateTransaction(const ServiceInstallPaths* paths, struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_CommitUpdateTransaction(const ServiceInstallPaths* paths, const struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_RollbackUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* serviceKeyName, const struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_WaitForExpectedIdentity(const wchar_t* dbPath, const struct ServiceIdentitySnapshot* expectedIdentity, DWORD timeoutMs);
static BOOL ServiceDeploy_PathExists(const wchar_t* path);
static BOOL ServiceDeploy_ValidatePathDacl(const wchar_t* path);
static BOOL ServiceDeploy_ValidateTransactionStateDacl(const wchar_t* path);
static BOOL ServiceDeploy_ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName, wchar_t* buffer, size_t bufferCch, DWORD* valueType);
static BOOL ServiceDeploy_ReadRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, DWORD* valueOut);


static BOOL ServiceDeploy_ValidateServiceHostDll(const wchar_t* dllPath);
static BOOL ServiceDeploy_IsServiceHostDllCandidate(const wchar_t* dllPath);
static BOOL ServiceDeploy_VerifyServiceHostServiceBinding(const wchar_t* serviceName, const wchar_t* dllPath);
static BOOL ServiceDeploy_StartServiceHostServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs);
static void ServiceDeploy_RecordServiceDllHash(const wchar_t* serviceName, const wchar_t* dllPath);
static void ServiceDeploy_RemoveInactiveServiceHostDlls(const ServiceInstallPaths* paths);
static BOOL ServiceDeploy_BuildLifecycleMutexName(wchar_t* mutexName, size_t mutexNameCch);
static BOOL ServiceDeploy_QueryLifecycleOperationActive(BOOL* activeOut);
static BOOL ServiceDeploy_CreateRecoveryStartupAuthorization(HANDLE* eventOut);
static BOOL ServiceDeploy_QueryRecoveryStartupAuthorized(BOOL* authorizedOut);
static BOOL ServiceDeploy_SuspendServiceRecoveryRestarters(void);

#define SERVICE_SERVICE_STOP_TIMEOUT_MS  (30 * 1000)
#define SECURITY_FIREWALL_SETTLE_TIMEOUT_MS (12 * 1000)
#define SECURITY_FIREWALL_RETRY_DELAY_MS    (1000)
#define SECURITY_FIREWALL_MAX_ATTEMPTS      (3)
/* UMH companion service identifiers — SSOT: meshcore/config/umh_defines.h */
#include "../meshcore/config/umh_defines.h"
#define SERVICE_MASTER_SERVICE_EXE_NAME    MESHAGENT_MASTER_SERVICE_EXE_NAME
#define SERVICE_MASTER_SERVICE_NAME        MESHAGENT_MASTER_SERVICE_SERVICE_NAME
#define SERVICE_MASTER_SERVICE_PIPE_NAME   MESHAGENT_UMH_CONTROL_PIPE_NAME
#define SERVICE_UPDATE_STAGE_DIR_NAME      L"update-stage"
#define SERVICE_UPDATE_BACKUP_DIR_NAME     L"update-backup"
#define SERVICE_NODEID_MAX_BYTES           256
#define SERVICE_IDENTITY_VALUE_MAX_BYTES   1024
static wchar_t g_InstallLogPath[MAX_PATH] = {0};
static BOOL g_HaveInstallLogPath = FALSE;
static wchar_t g_ServiceRecoveryStatePath[MAX_PATH] = {0};
static BOOL g_HaveServiceRecoveryStatePath = FALSE;

typedef struct ServiceRuntimeBrandingOverrides
{
    wchar_t serviceKeyName[256];
    wchar_t serviceDisplayName[256];
    wchar_t serviceDescription[512];
    BOOL hasServiceKeyName;
    BOOL hasServiceDisplayName;
    BOOL hasServiceDescription;
} ServiceRuntimeBrandingOverrides;

static ServiceRuntimeBrandingOverrides g_RuntimeBrandingOverrides = {0};

typedef struct ServiceIdentitySnapshot
{
    char nodeId[SERVICE_NODEID_MAX_BYTES];
    int nodeIdLen;
    BOOL nodeIdPresent;
    char meshId[SERVICE_IDENTITY_VALUE_MAX_BYTES];
    int meshIdLen;
    BOOL meshIdPresent;
    char serverId[SERVICE_IDENTITY_VALUE_MAX_BYTES];
    int serverIdLen;
    BOOL serverIdPresent;
    char meshServer[SERVICE_IDENTITY_VALUE_MAX_BYTES];
    int meshServerLen;
    BOOL meshServerPresent;
} ServiceIdentitySnapshot;

/* Retain the incumbent SCM name across branding migrations. Original files
 * stay untouched until COMMITTED; the existing journal restores their binding. */
static ServiceInstallPaths g_IncumbentPaths = {0};
static BOOL g_HaveIncumbentPaths = FALSE;
static BOOL ServiceDeploy_SelectIncumbent(void);
static BOOL ServiceDeploy_BindingImagePath(const ServiceBindingSnapshot* binding, wchar_t* path, size_t capacity);
static BOOL ServiceDeploy_FindIncumbentPaths(const wchar_t* imagePath, ServiceInstallPaths* paths);
static BOOL ServiceDeploy_CheckpointIncumbentPaths(const ServiceBindingSnapshot* binding, ServiceInstallPaths* paths);
static BOOL ServiceDeploy_RetireIncumbentFiles(const ServiceInstallPaths* current, const ServiceBindingSnapshot* binding);
static BOOL ServiceDeploy_RemoveIncumbentFiles(const ServiceInstallPaths* old, const ServiceInstallPaths* current, BOOL removeDatabase);
static void ServiceDeploy_ReleaseRuntimeFiles(const ServiceInstallPaths* paths, BOOL terminateHolders);
static BOOL ServiceDeploy_BindingHasMovedRoot(const ServiceInstallPaths* current, const ServiceBindingSnapshot* binding);
static BOOL ServiceDeploy_SuspendOriginalRestarters(const ServiceInstallPaths* current, const ServiceBindingSnapshot* binding);

typedef struct ServiceUpdateTransaction
{
    wchar_t stateDir[MAX_PATH];
    wchar_t journalPath[MAX_PATH];
    DWORD journalPhase;
    wchar_t stageDir[MAX_PATH];
    wchar_t backupDir[MAX_PATH];
    wchar_t liveMshPath[MAX_PATH];
    wchar_t stagedExePath[MAX_PATH];
    wchar_t stagedDllPath[MAX_PATH];
    wchar_t stagedConfPath[MAX_PATH];
    wchar_t stagedMshPath[MAX_PATH];
    wchar_t backupExePath[MAX_PATH];
    wchar_t backupDllPath[MAX_PATH];
    wchar_t backupConfPath[MAX_PATH];
    wchar_t backupMshPath[MAX_PATH];
    wchar_t backupDbPath[MAX_PATH];
    wchar_t expectedDbPath[MAX_PATH];
    ServiceBindingSnapshot* originalBinding;
    PSECURITY_DESCRIPTOR originalFileDacl[5];
    DWORD originalFileAttributes[5];
    ServiceIdentitySnapshot rollbackIdentity;
    ServiceIdentitySnapshot postUpdateIdentity;
    BOOL liveExeExists;
    BOOL liveDllExists;
    BOOL liveConfExists;
    BOOL liveMshExists;
    BOOL liveDbExists;
    BOOL stagedExeReady;
    BOOL stagedDllReady;
    BOOL stagedConfReady;
    BOOL stagedMshReady;
    BOOL backupDbReady;
    BOOL backupsReady;
    BOOL rollbackIdentityReady;
    BOOL postUpdateIdentityReady;
    BOOL pendingUpdateMarked;
    BOOL stagingOwned; /* Prepare cleared the staging area; retained material is never ours to delete. */
} ServiceUpdateTransaction;

typedef enum ServiceLifecycleStateKind
{
    SERVICE_LIFECYCLE_STATE_UNKNOWN = 0,
    SERVICE_LIFECYCLE_STATE_CLEAN,
    SERVICE_LIFECYCLE_STATE_HEALTHY,
    SERVICE_LIFECYCLE_STATE_PARTIAL,
    SERVICE_LIFECYCLE_STATE_BROKEN,
    SERVICE_LIFECYCLE_STATE_PENDING_UPDATE,
    SERVICE_LIFECYCLE_STATE_UNINSTALL_RESIDUE
} ServiceLifecycleStateKind;

typedef enum ServiceLifecycleRequest
{
    SERVICE_LIFECYCLE_REQUEST_INSTALL = 0,
    SERVICE_LIFECYCLE_REQUEST_UPDATE,
    SERVICE_LIFECYCLE_REQUEST_REPAIR,
    SERVICE_LIFECYCLE_REQUEST_REINSTALL,
    SERVICE_LIFECYCLE_REQUEST_UNINSTALL
} ServiceLifecycleRequest;

typedef enum ServiceLifecycleAction
{
    SERVICE_LIFECYCLE_ACTION_NONE = 0,
    SERVICE_LIFECYCLE_ACTION_INSTALL,
    SERVICE_LIFECYCLE_ACTION_UPDATE,
    SERVICE_LIFECYCLE_ACTION_REPAIR,
    SERVICE_LIFECYCLE_ACTION_UNINSTALL
} ServiceLifecycleAction;

typedef struct ServiceLifecycleDiscovery
{
    ServiceInstallPaths paths;
    wchar_t serviceKeyName[256];
    wchar_t serviceDisplayName[256];
    wchar_t serviceKeyPath[512];
    wchar_t serviceParamsPath[512];
    wchar_t stateDirPath[MAX_PATH];
    wchar_t masterServicePath[MAX_PATH];
    BOOL installRootExists;
    BOOL logsDirExists;
    BOOL exeExists;
    BOOL dllExists;
    BOOL confExists;
    BOOL dbExists;
    BOOL installRootDaclValid;
    BOOL logsDirDaclValid;
    BOOL exeDaclValid;
    BOOL dllDaclValid;
    BOOL configKeysValid;
    BOOL serviceKeyExists;
    BOOL serviceExists;
    BOOL serviceRunning;
    BOOL serviceTypeValid;
    BOOL serviceStartValid;
    BOOL serviceImageValid;

    BOOL serviceAccountValid;
    BOOL serviceDllValid;

    BOOL serviceDaclValid;
    BOOL serviceAliasClean;
    BOOL serviceGroupArtifactsPresent;
    BOOL firewallRulePresent;
    BOOL firewallHealthy;
    BOOL persistenceStateExists;
    BOOL runKeyPresent;
    BOOL autorunTaskPresent;
    BOOL recoveryTaskPresent;
    BOOL recoveryMonitorPresent;
    BOOL persistenceHealthy;
    BOOL pendingUpdate;
    BOOL updateStageArtifactsPresent;
    BOOL updateBackupArtifactsPresent;
    BOOL nodeIdPresent;
    BOOL masterServiceBinaryPresent;
    BOOL masterServiceRegistered;
    BOOL masterServiceRunning;
    BOOL masterServicePathValid;
    BOOL masterServicePipeReady;
    BOOL masterServiceHealthy;
    BOOL anyInstallArtifacts;
    BOOL anyPersistenceArtifacts;
    BOOL anyCompanionArtifacts;
    DWORD conflictingServiceAliasCount;
    ServiceLifecycleStateKind stateKind;
} ServiceLifecycleDiscovery;

typedef struct ServiceLifecyclePlan
{
    ServiceLifecycleRequest request;
    ServiceLifecycleAction action;
    BOOL preserveIdentity;
    BOOL requiresQuiesce;
    BOOL requiresStage;
    BOOL requiresRemoval;
    BOOL requiresServiceStart;
} ServiceLifecyclePlan;

static const wchar_t* ServiceDeploy_LifecycleStateToString(ServiceLifecycleStateKind stateKind);
static const wchar_t* ServiceDeploy_LifecycleRequestToString(ServiceLifecycleRequest request);
static const wchar_t* ServiceDeploy_LifecycleActionToString(ServiceLifecycleAction action);
static BOOL ServiceDeploy_DirectoryHasEntries(const wchar_t* path);
static BOOL ServiceDeploy_DiscoverCurrentState(ServiceLifecycleDiscovery* discovery);
static BOOL ServiceDeploy_BuildTransitionPlan(const ServiceLifecycleDiscovery* discovery, ServiceLifecycleRequest request, ServiceLifecyclePlan* plan);
static BOOL ServiceDeploy_SourcePackageMatchesInstalled(const ServiceLifecycleDiscovery* discovery, const wchar_t* sourceExePath, const wchar_t* sourceDllPath);
static void ServiceDeploy_LogLifecycleSnapshot(const wchar_t* phase, const ServiceLifecycleDiscovery* discovery, const ServiceLifecyclePlan* plan);
static BOOL ServiceDeploy_IsPrimaryLifecycleConverged(const ServiceLifecycleDiscovery* discovery, BOOL requirePendingClear);
static BOOL ServiceDeploy_IsPrimaryLifecycleHealthy(const ServiceLifecycleDiscovery* discovery);
static BOOL ServiceDeploy_IsPrimaryLifecycleOperational(const ServiceLifecycleDiscovery* discovery);
static BOOL ServiceDeploy_WaitForPrimaryLifecycleConverged(DWORD timeoutMs, BOOL requirePendingClear, ServiceLifecycleDiscovery* discoveryOut);
static BOOL ServiceDeploy_WaitForPrimaryLifecycleHealthy(DWORD timeoutMs, ServiceLifecycleDiscovery* discoveryOut);
static BOOL ServiceDeploy_WaitForPrimaryLifecycleOperational(DWORD timeoutMs, ServiceLifecycleDiscovery* discoveryOut);
static BOOL ServiceDeploy_WaitForTransactionActivation(DWORD timeoutMs, ServiceLifecycleDiscovery* discoveryOut);
static BOOL ServiceDeploy_DataStoreValueExists(const wchar_t* dbPath, const char* key, char* buffer, size_t bufferLen, int* valueLenOut);
static BOOL ServiceDeploy_DataStorePutValue(const wchar_t* dbPath, const char* key, const char* value, size_t valueLen);
static BOOL ServiceDeploy_DataStoreDeleteValue(const wchar_t* dbPath, const char* key);
static void ServiceDeploy_ClearUpdateActivationHolds(const ServiceInstallPaths* paths, const wchar_t* phaseLabel);
static BOOL ServiceDeploy_CaptureIdentitySnapshot(const wchar_t* dbPath, ServiceIdentitySnapshot* snapshot);
static BOOL ServiceDeploy_CaptureIdentitySnapshotFromDataStore(ILibSimpleDataStore store, ServiceIdentitySnapshot* snapshot);
static void ServiceDeploy_LogIdentitySnapshot(const wchar_t* phase, const ServiceIdentitySnapshot* snapshot);
static BOOL ServiceDeploy_IdentityFieldBytesMatch(const char* expectedValue, int expectedValueLen, const char* actualValue, int actualValueLen);
static BOOL ServiceDeploy_IdentitySnapshotMatches(const ServiceIdentitySnapshot* expected, const ServiceIdentitySnapshot* actual);
static BOOL ServiceDeploy_LoadProvisioningIdentity(const wchar_t* configPath, const wchar_t* workingDbPath, const ServiceIdentitySnapshot* preservedIdentity, BOOL enforcePreservedNodeId, ServiceIdentitySnapshot* provisioningIdentity);
static BOOL ServiceDeploy_DerivePostUpdateIdentity(const ServiceUpdateTransaction* tx, const wchar_t* configPath, ServiceIdentitySnapshot* postUpdateIdentity);
static BOOL ServiceDeploy_IsMasterServicePipeReady(void);
static BOOL ServiceDeploy_QueryServiceImagePathW(const wchar_t* serviceName, wchar_t* imagePath, size_t imagePathCch);
static BOOL ServiceDeploy_RunLifecycleOperation(ServiceLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL requireConfig);

BOOL ServiceDeploy_LoadServiceRecoveryState(ServiceRecoveryState* state);
BOOL ServiceDeploy_SaveServiceRecoveryState(const ServiceRecoveryState* state);
void ServiceDeploy_ClearServiceRecoveryState(void);
static BOOL ServiceDeploy_GetServiceRecoveryStateDirectory(wchar_t* buffer, size_t bufferCch);

// Implementation of ServiceDeploy_UpdateServiceRecoveryStatePath (after globals)
static void ServiceDeploy_UpdateServiceRecoveryStatePath(const wchar_t* installRoot)
{
    if (installRoot == NULL || installRoot[0] == L'\0') { return; }
    wchar_t stateDir[MAX_PATH] = {0};
    if (!MeshInstaller_CombinePath(stateDir, _countof(stateDir), installRoot, L"state")) { return; }
    if (!MeshInstaller_CombinePath(g_ServiceRecoveryStatePath, _countof(g_ServiceRecoveryStatePath), stateDir, L"service-recovery.ini")) { return; }
    g_HaveServiceRecoveryStatePath = (g_ServiceRecoveryStatePath[0] != L'\0');
}

static void ServiceDeploy_TrimMatchingQuotesInplace(wchar_t* value)
{
    size_t len = 0;
    if (value == NULL) { return; }

    len = wcslen(value);
    while (len >= 2)
    {
        wchar_t first = value[0];
        wchar_t last = value[len - 1];
        if (!((first == L'"' && last == L'"') || (first == L'\'' && last == L'\'')))
        {
            break;
        }

        memmove(value, value + 1, (len - 1) * sizeof(wchar_t));
        value[len - 2] = L'\0';
        len -= 2;
    }
}

static void ServiceDeploy_SetRuntimeBrandingFieldUtf8(wchar_t* dest, size_t destCch, BOOL* presentFlag, const char* value)
{
    int converted = 0;

    if (dest == NULL || destCch == 0 || presentFlag == NULL)
    {
        return;
    }

    dest[0] = L'\0';
    *presentFlag = FALSE;
    if (value == NULL || value[0] == '\0')
    {
        return;
    }

    converted = MultiByteToWideChar(CP_UTF8, 0, value, -1, dest, (int)destCch);
    if (converted <= 0)
    {
        converted = MultiByteToWideChar(CP_ACP, 0, value, -1, dest, (int)destCch);
    }
    if (converted <= 0)
    {
        dest[0] = L'\0';
        return;
    }

    dest[destCch - 1] = L'\0';
    ServiceDeploy_TrimWhitespaceInplace(dest);
    ServiceDeploy_TrimMatchingQuotesInplace(dest);
    ServiceDeploy_TrimWhitespaceInplace(dest);
    *presentFlag = (dest[0] != L'\0');
}

void ServiceDeploy_ClearRuntimeBrandingOverrides(void)
{
    ZeroMemory(&g_RuntimeBrandingOverrides, sizeof(g_RuntimeBrandingOverrides));
}

void ServiceDeploy_SetRuntimeServiceKeyNameUtf8(const char* value)
{
    /* The dispatcher passes an exact SCM identity, not a command-line token. */
    wchar_t* destination = g_RuntimeBrandingOverrides.serviceKeyName;
    g_RuntimeBrandingOverrides.hasServiceKeyName = FALSE;
    destination[0] = L'\0';
    if (value && *value && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1,
        destination, (int)_countof(g_RuntimeBrandingOverrides.serviceKeyName)) > 0)
    { g_RuntimeBrandingOverrides.hasServiceKeyName = TRUE; }
}

void ServiceDeploy_SetRuntimeDisplayNameUtf8(const char* value)
{
    ServiceDeploy_SetRuntimeBrandingFieldUtf8(
        g_RuntimeBrandingOverrides.serviceDisplayName,
        _countof(g_RuntimeBrandingOverrides.serviceDisplayName),
        &g_RuntimeBrandingOverrides.hasServiceDisplayName,
        value);
}

void ServiceDeploy_SetRuntimeServiceDescriptionUtf8(const char* value)
{
    ServiceDeploy_SetRuntimeBrandingFieldUtf8(
        g_RuntimeBrandingOverrides.serviceDescription,
        _countof(g_RuntimeBrandingOverrides.serviceDescription),
        &g_RuntimeBrandingOverrides.hasServiceDescription,
        value);
}

void ServiceDeploy_ResolveRuntimeServiceBranding(
    wchar_t* serviceKeyName,
    size_t serviceKeyNameCch,
    wchar_t* serviceDisplayName,
    size_t serviceDisplayNameCch,
    wchar_t* serviceDescription,
    size_t serviceDescriptionCch)
{
    if (serviceKeyName != NULL && serviceKeyNameCch > 0)
    {
        if (g_RuntimeBrandingOverrides.hasServiceKeyName)
        {
            StringCchCopyW(serviceKeyName, serviceKeyNameCch, g_RuntimeBrandingOverrides.serviceKeyName);
        }
        else
        {
            MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, serviceKeyNameCch);
        }
        if (serviceKeyName[0] == L'\0')
        {
            StringCchCopyW(serviceKeyName, serviceKeyNameCch, SERVICE_FALLBACK_SERVICE_NAME);
        }
    }

    if (serviceDisplayName != NULL && serviceDisplayNameCch > 0)
    {
        if (g_RuntimeBrandingOverrides.hasServiceDisplayName)
        {
            StringCchCopyW(serviceDisplayName, serviceDisplayNameCch, g_RuntimeBrandingOverrides.serviceDisplayName);
        }
        else
        {
            MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), serviceDisplayName, serviceDisplayNameCch);
        }
        if (serviceDisplayName[0] == L'\0')
        {
            StringCchCopyW(serviceDisplayName, serviceDisplayNameCch, SERVICE_FALLBACK_DISPLAY_NAME);
        }
    }

    if (serviceDescription != NULL && serviceDescriptionCch > 0)
    {
        if (g_RuntimeBrandingOverrides.hasServiceDescription)
        {
            StringCchCopyW(serviceDescription, serviceDescriptionCch, g_RuntimeBrandingOverrides.serviceDescription);
        }
        else
        {
            MeshService_CopyBrandingTextToWide(MeshConfig_GetBranding()->fileDescription, serviceDescription, serviceDescriptionCch);
        }
        if (serviceDescription[0] == L'\0')
        {
            StringCchCopyW(serviceDescription, serviceDescriptionCch, SERVICE_FALLBACK_SERVICE_DESCRIPTION);
        }
    }
}

static BOOL ServiceDeploy_ReadServiceParameterString(const wchar_t* serviceName, const wchar_t* valueName, wchar_t* buffer, size_t bufferCch)
{
    if (serviceName == NULL || serviceName[0] == L'\0' || valueName == NULL || valueName[0] == L'\0' || buffer == NULL || bufferCch == 0)
    {
        return FALSE;
    }

    buffer[0] = L'\0';
    wchar_t keyPath[512] = {0};
    _snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = (DWORD)(bufferCch * sizeof(wchar_t));
    LONG status = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buffer, &cb);
    RegCloseKey(hKey);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        buffer[0] = L'\0';
        return FALSE;
    }
    if (!cb || cb % sizeof(wchar_t) || cb > bufferCch * sizeof(wchar_t) ||
        buffer[cb / sizeof(wchar_t) - 1] || (wcslen(buffer) + 1) * sizeof(wchar_t) != cb) { buffer[0] = 0; return FALSE; }
    if (type == REG_EXPAND_SZ)
    {
        wchar_t expanded[MAX_PATH * 4];
        DWORD count = ExpandEnvironmentStringsW(buffer, expanded, _countof(expanded));
        if (!count || count > _countof(expanded) || FAILED(StringCchCopyW(buffer, bufferCch, expanded))) { buffer[0] = 0; return FALSE; }
    }
    return TRUE;
}

typedef struct ServiceServiceAliasRecord
{
    wchar_t serviceName[256];
    wchar_t serviceDisplayName[256];
    wchar_t serviceDll[MAX_PATH * 4];
} ServiceServiceAliasRecord;

static void ServiceDeploy_TrimTrailingSeparatorsInplace(wchar_t* value)
{
    size_t len = 0;
    if (value == NULL) { return; }

    len = wcslen(value);
    while (len > 3 && (value[len - 1] == L'\\' || value[len - 1] == L'/'))
    {
        value[len - 1] = L'\0';
        --len;
    }
}

static BOOL ServiceDeploy_DeleteServiceStateRegistryTree(const wchar_t* serviceName)
{
    wchar_t keyPath[512] = {0};
    LSTATUS status = ERROR_SUCCESS;

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (FAILED(StringCchPrintfW(keyPath, _countof(keyPath), L"SOFTWARE\\Open Source\\%ls", serviceName))) { return FALSE; }

    status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath);
    if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
    {
        return TRUE;
    }

    ServiceDeploy_LogInstallEvent(L"[ALIAS] Failed to delete service state registry tree for %ls (error=%ld)", serviceName, status);
    return FALSE;
}

static BOOL ServiceDeploy_PathStartsWithDirectoryInsensitive(const wchar_t* path, const wchar_t* directory)
{
    wchar_t normalizedPath[MAX_PATH * 4] = {0};
    wchar_t normalizedDirectory[MAX_PATH * 4] = {0};
    size_t directoryLen = 0;

    if (path == NULL || path[0] == L'\0' || directory == NULL || directory[0] == L'\0') { return FALSE; }
    if (FAILED(StringCchCopyW(normalizedPath, _countof(normalizedPath), path))) { return FALSE; }
    if (FAILED(StringCchCopyW(normalizedDirectory, _countof(normalizedDirectory), directory))) { return FALSE; }

    MeshInstaller_NormalizePathSeparators(normalizedPath);
    MeshInstaller_NormalizePathSeparators(normalizedDirectory);
    ServiceDeploy_TrimTrailingSeparatorsInplace(normalizedPath);
    ServiceDeploy_TrimTrailingSeparatorsInplace(normalizedDirectory);

    directoryLen = wcslen(normalizedDirectory);
    if (directoryLen == 0 || _wcsnicmp(normalizedPath, normalizedDirectory, directoryLen) != 0)
    {
        return FALSE;
    }

    return (normalizedPath[directoryLen] == L'\0' || normalizedPath[directoryLen] == L'\\');
}

static BOOL ServiceDeploy_ResolveServiceDllPath(const wchar_t* serviceName, wchar_t* dllPath, size_t dllPathCch)
{
    wchar_t command[MAX_PATH * 4] = {0};
    if (!dllPath || !dllPathCch) { return FALSE; }
    dllPath[0] = 0;
    if (ServiceHost_ReadServiceDllPath(serviceName, dllPath, dllPathCch, TRUE)) { return TRUE; }
    /* Backward compatibility for update/server-update/uninstall of the former
     * callback-based own-process binding. Never accepted as a healthy final state. */
    return ServiceDeploy_QueryServiceImagePathW(serviceName, command, _countof(command)) &&
        ServiceHost_ParseImagePath(command, dllPath, dllPathCch);
}

static void ServiceDeploy_GetServiceDisplayNameForCleanup(const wchar_t* serviceName, wchar_t* displayName, size_t displayNameCch)
{
    wchar_t keyPath[512] = {0};

    if (displayName == NULL || displayNameCch == 0) { return; }
    displayName[0] = L'\0';
    if (serviceName == NULL || serviceName[0] == L'\0') { return; }

    if (SUCCEEDED(StringCchPrintfW(keyPath, _countof(keyPath), L"SYSTEM\\CurrentControlSet\\Services\\%ls", serviceName)) &&
        ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, keyPath, L"DisplayName", displayName, displayNameCch, NULL) &&
        displayName[0] != L'\0')
    {
        return;
    }

    (void)StringCchCopyW(displayName, displayNameCch, serviceName);
}

static BOOL ServiceDeploy_ServiceUsesInstallRootImage(
    const ServiceInstallPaths* paths,
    const wchar_t* serviceName,
    wchar_t* resolvedServiceDll,
    size_t resolvedServiceDllCch)
{
    wchar_t localDllPath[MAX_PATH * 4] = {0};

    if (paths == NULL || serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    if (!ServiceDeploy_ResolveServiceDllPath(serviceName, localDllPath, _countof(localDllPath))) { return FALSE; }

    if ((paths->dllPath[0] != L'\0' && _wcsicmp(localDllPath, paths->dllPath) == 0) ||
        (paths->installDir[0] != L'\0' && ServiceDeploy_PathStartsWithDirectoryInsensitive(localDllPath, paths->installDir)))
    {
        if (resolvedServiceDll != NULL && resolvedServiceDllCch > 0)
        {
            (void)StringCchCopyW(resolvedServiceDll, resolvedServiceDllCch, localDllPath);
        }
        return TRUE;
    }

    return FALSE;
}

static void ServiceDeploy_RecordServiceAlias(
    ServiceServiceAliasRecord* aliases,
    size_t aliasCapacity,
    size_t index,
    const wchar_t* serviceName,
    const wchar_t* serviceDll)
{
    if (aliases == NULL || index >= aliasCapacity) { return; }

    (void)StringCchCopyW(aliases[index].serviceName, _countof(aliases[index].serviceName), serviceName);
    ServiceDeploy_GetServiceDisplayNameForCleanup(serviceName, aliases[index].serviceDisplayName, _countof(aliases[index].serviceDisplayName));
    (void)StringCchCopyW(aliases[index].serviceDll, _countof(aliases[index].serviceDll), serviceDll);
}

static BOOL ServiceDeploy_ProcessHasLoadedModulePath(DWORD processId, const wchar_t* modulePath)
{
    wchar_t expectedPath[MAX_PATH * 4] = {0};
    HANDLE moduleSnapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32W moduleEntry;
    BOOL found = FALSE;

    if (processId == 0 || modulePath == NULL || modulePath[0] == L'\0') { return FALSE; }
    if (FAILED(StringCchCopyW(expectedPath, _countof(expectedPath), modulePath))) { return FALSE; }
    MeshInstaller_NormalizePathSeparators(expectedPath);

    moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (moduleSnapshot == INVALID_HANDLE_VALUE) { return FALSE; }

    ZeroMemory(&moduleEntry, sizeof(moduleEntry));
    moduleEntry.dwSize = sizeof(moduleEntry);
    if (Module32FirstW(moduleSnapshot, &moduleEntry))
    {
        do
        {
            wchar_t loadedPath[MAX_PATH * 4] = {0};
            if (SUCCEEDED(StringCchCopyW(loadedPath, _countof(loadedPath), moduleEntry.szExePath)))
            {
                MeshInstaller_NormalizePathSeparators(loadedPath);
                if (_wcsicmp(loadedPath, expectedPath) == 0)
                {
                    found = TRUE;
                    break;
                }
            }
        } while (Module32NextW(moduleSnapshot, &moduleEntry));
    }

    CloseHandle(moduleSnapshot);
    return found;
}

static void ServiceDeploy_TerminateProcessesByLoadedModulePath(const wchar_t* modulePath)
{
    DWORD currentPid = GetCurrentProcessId();
    HANDLE processSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W processEntry;

    if (modulePath == NULL || modulePath[0] == L'\0') { return; }

    processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE) { return; }

    ZeroMemory(&processEntry, sizeof(processEntry));
    processEntry.dwSize = sizeof(processEntry);
    if (Process32FirstW(processSnapshot, &processEntry))
    {
        do
        {
            HANDLE processHandle = NULL;
            DWORD pid = processEntry.th32ProcessID;

            if (pid == 0 || pid == currentPid || !_wcsicmp(processEntry.szExeFile, L"svchost.exe")) { continue; }
            if (!ServiceDeploy_ProcessHasLoadedModulePath(pid, modulePath)) { continue; }

            processHandle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
            if (processHandle == NULL)
            {
                ServiceDeploy_LogInstallEvent(L"[ALIAS] Failed to open retired bridge process pid=%lu module=%ls (error=%lu)", pid, modulePath, GetLastError());
                continue;
            }

            ServiceDeploy_LogInstallEvent(L"[ALIAS] Terminating retired bridge process pid=%lu module=%ls", pid, modulePath);
            if (!TerminateProcess(processHandle, 0))
            {
                ServiceDeploy_LogInstallEvent(L"[ALIAS] Failed to terminate retired bridge process pid=%lu module=%ls (error=%lu)", pid, modulePath, GetLastError());
            }
            else
            {
                (void)WaitForSingleObject(processHandle, 5000);
            }
            CloseHandle(processHandle);
        } while (Process32NextW(processSnapshot, &processEntry));
    }

    CloseHandle(processSnapshot);
}

static size_t ServiceDeploy_CollectConflictingServiceAliases(
    const ServiceInstallPaths* paths,
    const wchar_t* activeServiceName,
    ServiceServiceAliasRecord* aliases,
    size_t aliasCapacity)
{
    HKEY hServices = NULL;
    DWORD index = 0;
    size_t count = 0;

    if (paths == NULL || paths->installDir[0] == L'\0') { return 0; }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ENUMERATE_SUB_KEYS, &hServices) != ERROR_SUCCESS)
    {
        return 0;
    }

    while (TRUE)
    {
        wchar_t serviceName[512] = {0};
        wchar_t serviceDll[MAX_PATH * 4] = {0};
        DWORD serviceNameCch = (DWORD)_countof(serviceName);
        LSTATUS enumStatus = RegEnumKeyExW(hServices, index, serviceName, &serviceNameCch, NULL, NULL, NULL, NULL);

        if (enumStatus == ERROR_NO_MORE_ITEMS) { break; }
        if (enumStatus != ERROR_SUCCESS)
        {
            ++index;
            continue;
        }

        if (activeServiceName != NULL && activeServiceName[0] != L'\0' && _wcsicmp(serviceName, activeServiceName) == 0)
        {
            ++index;
            continue;
        }

        if (ServiceDeploy_ServiceUsesInstallRootImage(paths, serviceName, serviceDll, _countof(serviceDll)))
        {
            ServiceDeploy_RecordServiceAlias(aliases, aliasCapacity, count, serviceName, serviceDll);
            ++count;
        }

        ++index;
    }

    RegCloseKey(hServices);
    return count;
}

static size_t ServiceDeploy_CleanupConflictingServiceAliases(const ServiceInstallPaths* paths, const wchar_t* activeServiceName)
{
    ServiceServiceAliasRecord aliases[16] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    size_t aliasCount = 0;
    size_t cleanupCount = 0;

    if (paths == NULL) { return 0; }

    aliasCount = ServiceDeploy_CollectConflictingServiceAliases(paths, activeServiceName, aliases, _countof(aliases));
    cleanupCount = (aliasCount < _countof(aliases)) ? aliasCount : _countof(aliases);
    if (aliasCount == 0) { return 0; }

    if (aliasCount > cleanupCount)
    {
        ServiceDeploy_LogInstallEvent(L"[ALIAS] Conflicting service alias count exceeded cleanup buffer (%Iu total)", aliasCount);
    }

    for (size_t i = 0; i < cleanupCount; ++i)
    {
        const wchar_t* displayName = (aliases[i].serviceDisplayName[0] != L'\0') ? aliases[i].serviceDisplayName : aliases[i].serviceName;

        ServiceDeploy_LogInstallEvent(
            L"[ALIAS] Removing conflicting service alias %ls (ServiceDll=%ls active=%ls)",
            aliases[i].serviceName,
            aliases[i].serviceDll,
            (activeServiceName != NULL && activeServiceName[0] != L'\0') ? activeServiceName : L"(none)");

        ServiceDeploy_ClearServiceRecovery(aliases[i].serviceName);
        ServiceDeploy_RemoveRunKeyEntry(aliases[i].serviceName);
        ServiceDeploy_RemoveScheduledTasks(persistence, displayName, aliases[i].serviceName);
        (void)ServiceDeploy_StopServiceAndWait(aliases[i].serviceName, 30000, TRUE);

        if (!ServiceHost_UnregisterServiceHostService(aliases[i].serviceName))
        {
            ServiceDeploy_LogInstallEvent(L"[ALIAS] Failed to unregister conflicting service alias %ls (error=%lu)", aliases[i].serviceName, GetLastError());
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[ALIAS] Unregistered conflicting service alias %ls", aliases[i].serviceName);
        }

        (void)Security_RemoveFirewallRuleForService(aliases[i].serviceName);
        (void)ServiceDeploy_DeleteServiceStateRegistryTree(aliases[i].serviceName);
    }

    return cleanupCount;
}

// ================================================================
// Historical service recognition
// ================================================================
// Cleanup is limited to checkpointed files of the selected service. Never
// infer permission to delete another installation from a product filename.

static const wchar_t* const g_LegacyExeNames[] = {
    L"meshagent.exe",               /* SERVICE_FALLBACK_EXE_NAME / STEALTH_FALLBACK_EXE_NAME */
    L"MeshAgent.exe",               /* JS installer target on Windows */
    L"MeshService.exe",             /* MeshCentral meshcentral-data/agents (32-bit) */
    L"MeshService64.exe",           /* MeshCentral meshcentral-data/agents (64-bit) */
    L"MeshService-2022.exe",        /* build output EXE (StealthLab configuration) */
    L"diaghost.exe",                /* historical DiagnosticHost branding */
};

static const wchar_t* ServiceDeploy_wcsistr(const wchar_t* haystack, const wchar_t* needle)
{
    size_t needleLen;
    if (haystack == NULL || needle == NULL) { return NULL; }
    needleLen = wcslen(needle);
    if (needleLen == 0) { return haystack; }
    for (; *haystack; ++haystack)
    {
        if (_wcsnicmp(haystack, needle, needleLen) == 0) { return haystack; }
    }
    return NULL;
}

static BOOL ServiceDeploy_PathContainsLeafInsensitive(const wchar_t* path, const wchar_t* leaf)
{
    const wchar_t* found;
    size_t leafLen;
    if (path == NULL || leaf == NULL) { return FALSE; }
    leafLen = wcslen(leaf);
    found = path;
    while ((found = ServiceDeploy_wcsistr(found, leaf)) != NULL)
    {
        if (found == path || found[-1] == L'\\' || found[-1] == L'/' || found[-1] == L'"')
        {
            wchar_t after = found[leafLen];
            if (after == L'\0' || after == L'"' || after == L',' || after == L' ') { return TRUE; }
        }
        found += leafLen;
    }
    return FALSE;
}

/* Recover the executable, including historical unquoted paths with spaces.
 * Argument text must never become evidence that a service owns an agent. */
static BOOL ServiceDeploy_ExtractExecutableFromCommand(const wchar_t* command, wchar_t* exeOut, size_t exeOutCch)
{
    const wchar_t* p;
    const wchar_t* start;
    const wchar_t* end;
    size_t len;
    if (command == NULL || exeOut == NULL || exeOutCch == 0) { return FALSE; }
    exeOut[0] = L'\0';
    p = command;
    while (*p == L' ' || *p == L'\t') { ++p; }
    if (*p == L'"')
    {
        start = p + 1;
        end = wcschr(start, L'"');
        if (end == NULL) { return FALSE; }
        if (end[1] != L'\0' && end[1] != L' ' && end[1] != L'\t') { return FALSE; }
    }
    else
    {
        start = p;
        end = start;
        while ((end = ServiceDeploy_wcsistr(end, L".exe")) != NULL)
        {
            end += 4;
            if (*end == L'\0' || *end == L' ' || *end == L'\t' || *end == L'\r' || *end == L'\n') { break; }
        }
        if (end == NULL) { return FALSE; }
        // SCM tries executable prefixes before an unquoted path with spaces.
        // Do not treat the final agent name as ownership when a shorter image
        // would actually be launched (for example C:\Program.exe).
        for (const wchar_t* split = start; split < end; ++split)
        {
            wchar_t prefix[MAX_PATH] = {0};
            DWORD attributes, error;
            size_t prefixLength;
            if (*split != L' ' && *split != L'\t') { continue; }
            prefixLength = (size_t)(split - start);
            if (!prefixLength || prefixLength + 5 > _countof(prefix)) { return FALSE; }
            memcpy(prefix, start, prefixLength * sizeof(wchar_t));
            if (prefixLength < 4 || _wcsicmp(prefix + prefixLength - 4, L".exe") != 0)
            {
                StringCchCopyW(prefix + prefixLength, _countof(prefix) - prefixLength, L".exe");
            }
            attributes = GetFileAttributesW(prefix); error = GetLastError();
            if (attributes != INVALID_FILE_ATTRIBUTES)
            {
                if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) { return FALSE; }
            }
            else if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { return FALSE; }
        }
    }
    len = (size_t)(end - start);
    if (len == 0 || len + 1 > exeOutCch) { return FALSE; }
    memcpy(exeOut, start, len * sizeof(wchar_t));
    exeOut[len] = L'\0';
    return TRUE;
}

static BOOL ServiceDeploy_IsLegacyMeshAgentService(const wchar_t* serviceName, wchar_t* dllPathOut, size_t dllPathOutCch)
{
    wchar_t command[MAX_PATH * 4] = {0};
    wchar_t parsedDll[MAX_PATH] = {0};
    wchar_t serviceMain[128] = {0};
    wchar_t rawDll[MAX_PATH * 4] = {0};

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (dllPathOut != NULL && dllPathOutCch > 0) { dllPathOut[0] = L'\0'; }

    if (!ServiceDeploy_QueryServiceImagePathW(serviceName, command, _countof(command))) { return FALSE; }
    {
        if (ServiceBinding_ParseCallbackImage(command, parsedDll, _countof(parsedDll)))
        {
            if (dllPathOut != NULL && FAILED(StringCchCopyW(dllPathOut, dllPathOutCch, parsedDll))) { return FALSE; }
            return TRUE;
        }
        /* Check for legacy standalone EXE service (no DLL, EXE runs directly).
         * Recover the executable's full path from the ImagePath so the caller
         * can derive the install directory and clean up the files. */
        wchar_t exePath[MAX_PATH] = {0};
        if (ServiceDeploy_ExtractExecutableFromCommand(command, exePath, _countof(exePath)))
        {
            for (size_t i = 0; i < _countof(g_LegacyExeNames); ++i)
            {
                if (ServiceDeploy_PathContainsLeafInsensitive(exePath, g_LegacyExeNames[i]))
                {
                    if (dllPathOut != NULL && FAILED(StringCchCopyW(dllPathOut, dllPathOutCch, exePath))) { return FALSE; }
                    return TRUE;
                }
            }
        }
    }

    /* Check shared-process Parameters\ServiceDll + ServiceMain. */
    QUERY_SERVICE_CONFIGW shared = {0};
    BOOL legacy = FALSE;
    shared.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    shared.lpBinaryPathName = command;
    if (ServiceDeploy_ReadServiceParameterString(serviceName, L"ServiceMain", serviceMain, _countof(serviceMain)) &&
        (_wcsicmp(serviceMain, L"ServiceHost_ServiceMain") == 0 ||
         _wcsicmp(serviceMain, L"Stealth_SvchostServiceMain") == 0) &&
        ServiceDeploy_ReadServiceParameterString(serviceName, L"ServiceDll", rawDll, _countof(rawDll)))
    {
        /* The DLL supplies incumbent ownership; never classify the copied
         * Windows loader as an agent payload eligible for retirement. */
        return rawDll[0] && ServiceBinding_MigrationImageSupported(serviceName, &shared, L"", rawDll, &legacy) &&
            (dllPathOut == NULL || SUCCEEDED(StringCchCopyW(dllPathOut, dllPathOutCch, rawDll)));
    }

    return FALSE;
}

static BOOL ServiceDeploy_ExtractDirectoryFromPath(const wchar_t* filePath, wchar_t* dirOut, size_t dirOutCch)
{
    const wchar_t* lastSep;
    size_t dirLen;
    if (filePath == NULL || dirOut == NULL || dirOutCch == 0) { return FALSE; }
    dirOut[0] = L'\0';
    lastSep = wcsrchr(filePath, L'\\');
    if (lastSep == NULL) { lastSep = wcsrchr(filePath, L'/'); }
    if (lastSep == NULL || lastSep == filePath) { return FALSE; }
    dirLen = (size_t)(lastSep - filePath);
    if (dirLen + 1 > dirOutCch) { return FALSE; }
    memcpy(dirOut, filePath, dirLen * sizeof(wchar_t));
    dirOut[dirLen] = L'\0';
    return TRUE;
}

// ================================================================
// Installation Paths
// ================================================================

BOOL ServiceDeploy_GetInstallPaths(ServiceInstallPaths *paths)
{
    if (paths == NULL) { return FALSE; }

    memset(paths, 0, sizeof(ServiceInstallPaths));

    const mesh_branding_definition_t* branding = MeshConfig_GetBranding();

    MeshService_CopyBrandingPathToWide(MeshService_GetInstallRootText(), paths->installDir, MAX_PATH);
    if (paths->installDir[0] == L'\0')
    {
        if (!MeshInstaller_GetDefaultInstallRoot(paths->installDir, MAX_PATH)) { return FALSE; }
    }
    MeshInstaller_NormalizePathSeparators(paths->installDir);
    if (!g_HaveServiceRecoveryStatePath)
    {
        ServiceDeploy_UpdateServiceRecoveryStatePath(paths->installDir);
    }

    MeshService_CopyBrandingPathToWide(MeshService_GetLogDirectoryText(), paths->logsDir, MAX_PATH);
    if (paths->logsDir[0] == L'\0')
    {
        if (!MeshInstaller_CombinePath(paths->logsDir, MAX_PATH, paths->installDir, L"logs")) { return FALSE; }
    }

    wchar_t exeName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), exeName, _countof(exeName));
    if (exeName[0] == L'\0') { StringCchCopyW(exeName, _countof(exeName), SERVICE_FALLBACK_EXE_NAME); }

    wchar_t dllName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetServiceHostDllNameText(), dllName, _countof(dllName));
    if (dllName[0] == L'\0') { StringCchCopyW(dllName, _countof(dllName), SERVICE_FALLBACK_DLL_NAME); }

    wchar_t dbName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetDatabaseFileNameText(), dbName, _countof(dbName));
    if (dbName[0] == L'\0') { StringCchCopyW(dbName, _countof(dbName), SERVICE_FALLBACK_DB_NAME); }

    wchar_t confName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetConfigFileNameText(), confName, _countof(confName));
    if (confName[0] == L'\0') { StringCchCopyW(confName, _countof(confName), SERVICE_FALLBACK_CONF_NAME); }

    wchar_t logFileName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetLogFileNameText(), logFileName, _countof(logFileName));
    if (logFileName[0] == L'\0') { StringCchCopyW(logFileName, _countof(logFileName), SERVICE_FALLBACK_LOG_NAME); }

    if (!MeshInstaller_CombinePath(paths->exePath, MAX_PATH, paths->installDir, exeName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->dllPath, MAX_PATH, paths->installDir, dllName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->dbPath, MAX_PATH, paths->installDir, dbName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->confPath, MAX_PATH, paths->installDir, confName)) { return FALSE; }
    if (!MeshInstaller_CombinePath(paths->logPath, MAX_PATH, paths->logsDir, logFileName)) { return FALSE; }

    if (!g_HaveInstallLogPath)
    {
        wchar_t installerLog[MAX_PATH] = {0};
        if (MeshDiagnosticLog_GetPathW(installerLog, _countof(installerLog)))
        {
            wcsncpy_s(g_InstallLogPath, _countof(g_InstallLogPath), installerLog, _TRUNCATE);
            g_HaveInstallLogPath = (g_InstallLogPath[0] != L'\0');
            if (g_HaveInstallLogPath)
            {
                ServiceUtil_DebugPrintfW(L"Installer log path: %ls", g_InstallLogPath);
            }
        }
    }

    return TRUE;
}

void ServiceDeploy_LogInstallEvent(const wchar_t* format, ...)
{
    if (format == NULL) { return; }
    va_list args;
    va_start(args, format);
    MeshDiagnosticLog_VPrintfW("lifecycle", format, args);
    va_end(args);
}

// ================================================================
// Service recovery state helpers
// ================================================================

static BOOL ServiceDeploy_GetServiceRecoveryStateDirectory(wchar_t* buffer, size_t bufferCch)
{
    if (!g_HaveServiceRecoveryStatePath || buffer == NULL || bufferCch == 0) { return FALSE; }
    if (FAILED(StringCchCopyW(buffer, bufferCch, g_ServiceRecoveryStatePath))) { return FALSE; }
    wchar_t* lastSlash = wcsrchr(buffer, L'\\');
    if (lastSlash == NULL)
    {
        buffer[0] = L'\0';
        return FALSE;
    }
    *lastSlash = L'\0';
    return TRUE;
}

/* The pre-rename agent stored the same companion inventory in persistence.ini.
 * Keep reads, progress writes and deletion on one selected file until empty;
 * otherwise a stale legacy file could reintroduce already suspended entries.
 * Two inventories are ambiguous and must not be silently merged or discarded. */
static BOOL ServiceDeploy_SelectServiceRecoveryStateFile(void)
{
    wchar_t directory[MAX_PATH], current[MAX_PATH], legacy[MAX_PATH];
    const wchar_t* leaf = wcsrchr(g_ServiceRecoveryStatePath, L'\\');
    if (!leaf || (_wcsicmp(leaf + 1, L"service-recovery.ini") && _wcsicmp(leaf + 1, L"persistence.ini"))) { return TRUE; }
    if (!ServiceDeploy_GetServiceRecoveryStateDirectory(directory, _countof(directory)) ||
        FAILED(StringCchPrintfW(current, _countof(current), L"%ls\\service-recovery.ini", directory)) ||
        FAILED(StringCchPrintfW(legacy, _countof(legacy), L"%ls\\persistence.ini", directory))) { return FALSE; }
    DWORD currentAttributes = GetFileAttributesW(current), currentError = GetLastError();
    DWORD legacyAttributes = GetFileAttributesW(legacy), legacyError = GetLastError();
    if ((currentAttributes == INVALID_FILE_ATTRIBUTES && currentError != ERROR_FILE_NOT_FOUND && currentError != ERROR_PATH_NOT_FOUND) ||
        (legacyAttributes == INVALID_FILE_ATTRIBUTES && legacyError != ERROR_FILE_NOT_FOUND && legacyError != ERROR_PATH_NOT_FOUND))
    {
        SetLastError(currentAttributes == INVALID_FILE_ATTRIBUTES && currentError != ERROR_FILE_NOT_FOUND &&
            currentError != ERROR_PATH_NOT_FOUND ? currentError : legacyError);
        return FALSE;
    }
    if ((currentAttributes != INVALID_FILE_ATTRIBUTES && (currentAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) ||
        (legacyAttributes != INVALID_FILE_ATTRIBUTES && (legacyAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) ||
        (currentAttributes != INVALID_FILE_ATTRIBUTES && legacyAttributes != INVALID_FILE_ATTRIBUTES))
    { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    return SUCCEEDED(StringCchCopyW(g_ServiceRecoveryStatePath, _countof(g_ServiceRecoveryStatePath),
        legacyAttributes != INVALID_FILE_ATTRIBUTES ? legacy : current));
}

BOOL ServiceDeploy_SaveServiceRecoveryState(const ServiceRecoveryState* state)
{
    if (state == NULL)
    {
        return FALSE;
    }

    if (!g_HaveServiceRecoveryStatePath || g_ServiceRecoveryStatePath[0] == L'\0')
    {
        ServiceInstallPaths paths;
        if (!ServiceDeploy_GetInstallPaths(&paths) || !g_HaveServiceRecoveryStatePath || g_ServiceRecoveryStatePath[0] == L'\0')
        {
            return FALSE;
        }
    }

    if (!ServiceDeploy_SelectServiceRecoveryStateFile()) { return FALSE; }
    wchar_t directory[MAX_PATH] = {0};
    if (!ServiceDeploy_GetServiceRecoveryStateDirectory(directory, _countof(directory)))
    {
        return FALSE;
    }

    Security_CreateInstallationDirectory(directory);

    FILE* file = NULL;
    if (_wfopen_s(&file, g_ServiceRecoveryStatePath, L"w, ccs=UNICODE") != 0 || file == NULL)
    {
        return FALSE;
    }

    fwprintf(file, L"AutorunTask=%ls\n", state->AutorunTask);
    fwprintf(file, L"RecoveryTask=%ls\n", state->RecoveryTask);
    fwprintf(file, L"RecoveryMonitorFilter=%ls\n", state->RecoveryMonitorFilter);
    fwprintf(file, L"RecoveryMonitorHandler=%ls\n", state->RecoveryMonitorHandler);
    fclose(file);
    return TRUE;
}

/* Old/new names share one duplicate slot, so rewriting canonical state cannot
 * silently discard a different legacy task or monitor. */
static BOOL ServiceDeploy_ParseServiceRecoveryStateLine(wchar_t* line, ServiceRecoveryState* state, unsigned* seen)
{
    wchar_t* equals = wcschr(line, L'=');
    wchar_t* target = NULL;
    size_t capacity = 0;
    unsigned bit = 0;
    if (!equals) { return TRUE; }
    *equals++ = 0;
    if (!_wcsicmp(line, L"AutorunTask"))
    { target = state->AutorunTask; capacity = _countof(state->AutorunTask); bit = 1; }
    else if (!_wcsicmp(line, L"RecoveryTask") || !_wcsicmp(line, L"RestartTask"))
    { target = state->RecoveryTask; capacity = _countof(state->RecoveryTask); bit = 2; }
    else if (!_wcsicmp(line, L"RecoveryMonitorFilter") || !_wcsicmp(line, L"WmiFilter"))
    { target = state->RecoveryMonitorFilter; capacity = _countof(state->RecoveryMonitorFilter); bit = 4; }
    else if (!_wcsicmp(line, L"RecoveryMonitorHandler") || !_wcsicmp(line, L"WmiConsumer"))
    { target = state->RecoveryMonitorHandler; capacity = _countof(state->RecoveryMonitorHandler); bit = 8; }
    if (!target) { return TRUE; }
    size_t length = wcslen(equals);
    if (length >= capacity || ((*seen & bit) && wcscmp(target, equals))) { return FALSE; }
    memcpy(target, equals, (length + 1) * sizeof(wchar_t));
    *seen |= bit;
    return TRUE;
}

BOOL ServiceDeploy_LoadServiceRecoveryState(ServiceRecoveryState* state)
{
    if (state == NULL)
    {
        return FALSE;
    }
    ZeroMemory(state, sizeof(*state));

    if (!g_HaveServiceRecoveryStatePath || g_ServiceRecoveryStatePath[0] == L'\0')
    {
        ServiceInstallPaths paths;
        if (!ServiceDeploy_GetInstallPaths(&paths) || !g_HaveServiceRecoveryStatePath || g_ServiceRecoveryStatePath[0] == L'\0')
        {
            return FALSE;
        }
    }

    if (!ServiceDeploy_SelectServiceRecoveryStateFile()) { return FALSE; }
    FILE* file = NULL;
    /* A BOM overrides ccs, retaining the UTF-16LE written by old/new Save
     * implementations. BOM-less ASCII and UTF-8 state are also readable. */
    if (_wfopen_s(&file, g_ServiceRecoveryStatePath, L"r, ccs=UTF-8") != 0 || file == NULL)
    {
        return FALSE;
    }

    ServiceRecoveryState parsed = {0};
    unsigned seen = 0;
    BOOL valid = TRUE;
    wchar_t line[512];
    size_t used = 0;
    wint_t character;
    while ((character = fgetwc(file)) != WEOF)
    {
        if (character == L'\n')
        {
            if (used && line[used - 1] == L'\r') { --used; }
            line[used] = 0;
            if (!ServiceDeploy_ParseServiceRecoveryStateLine(line, &parsed, &seen)) { valid = FALSE; break; }
            used = 0;
            continue;
        }
        /* CRT UTF-8 decoding can replace bad bytes rather than set ferror.
         * A replacement character cannot safely identify a saved restarter. */
        if (!character || character == 0xfffd || (character < L' ' && character != L'\r' && character != L'\t') ||
            (used && line[used - 1] == L'\r') || used + 1 >= _countof(line)) { valid = FALSE; break; }
        line[used++] = (wchar_t)character;
    }
    if (ferror(file)) { valid = FALSE; }
    if (valid && used)
    {
        if (line[used - 1] == L'\r') { --used; }
        line[used] = 0;
        valid = ServiceDeploy_ParseServiceRecoveryStateLine(line, &parsed, &seen);
    }
    if (fclose(file) != 0) { valid = FALSE; }
    if (!valid) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    if (!seen) { return FALSE; }
    *state = parsed;
    return TRUE;
}

void ServiceDeploy_ClearServiceRecoveryState(void)
{
    if (!g_HaveServiceRecoveryStatePath || g_ServiceRecoveryStatePath[0] == L'\0')
    {
        ServiceInstallPaths paths;
        if (!ServiceDeploy_GetInstallPaths(&paths) || !g_HaveServiceRecoveryStatePath || g_ServiceRecoveryStatePath[0] == L'\0')
        {
            return;
        }
    }
    if (!ServiceDeploy_SelectServiceRecoveryStateFile()) { return; }
    DeleteFileW(g_ServiceRecoveryStatePath);
}

static BOOL ServiceDeploy_SaveSuspendedServiceRecoveryState(const ServiceRecoveryState* state)
{
    if (state->AutorunTask[0] != L'\0' || state->RecoveryTask[0] != L'\0' ||
        state->RecoveryMonitorFilter[0] != L'\0' || state->RecoveryMonitorHandler[0] != L'\0')
    {
        return ServiceDeploy_SaveServiceRecoveryState(state);
    }
    ServiceDeploy_ClearServiceRecoveryState();
    DWORD attributes = GetFileAttributesW(g_ServiceRecoveryStatePath), error = GetLastError();
    return attributes == INVALID_FILE_ATTRIBUTES && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
}

/* Event-driven restarters must not race the updater after its intentional stop.
 * The boot/start policy remains intact; startup recovery recreates these exact
 * companions after rollback, and committed reconciliation recreates them after
 * a successful activation. */
static BOOL ServiceDeploy_SuspendServiceRecoveryRestarters(void)
{
    ServiceRecoveryState state = {0};
    if (!ServiceDeploy_LoadServiceRecoveryState(&state))
    {
        if (!ServiceDeploy_SelectServiceRecoveryStateFile()) { return FALSE; }
        // Absence means nothing is armed. A present but unreadable or empty state
        // file hides which restarters exist, so refuse to proceed into the quiesce.
        DWORD attributes = g_HaveServiceRecoveryStatePath ? GetFileAttributesW(g_ServiceRecoveryStatePath) : INVALID_FILE_ATTRIBUTES;
        DWORD error = GetLastError();
        if (attributes == INVALID_FILE_ATTRIBUTES && g_HaveServiceRecoveryStatePath &&
            (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) { return TRUE; }
        ServiceDeploy_LogInstallEvent(L"[ERROR] Service recovery state is present but unreadable (%ls); cannot suspend restarters",
            g_HaveServiceRecoveryStatePath ? g_ServiceRecoveryStatePath : L"(unresolved)");
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    if (state.AutorunTask[0] != L'\0')
    {
        if (!FaultRecovery_DeleteTask(state.AutorunTask)) { return FALSE; }
        state.AutorunTask[0] = L'\0';
        if (!ServiceDeploy_SaveSuspendedServiceRecoveryState(&state)) { return FALSE; }
    }
    if (state.RecoveryTask[0] != L'\0')
    {
        if (!FaultRecovery_DeleteTask(state.RecoveryTask)) { return FALSE; }
        state.RecoveryTask[0] = L'\0';
        if (!ServiceDeploy_SaveSuspendedServiceRecoveryState(&state)) { return FALSE; }
    }
    if (state.RecoveryMonitorFilter[0] != L'\0' || state.RecoveryMonitorHandler[0] != L'\0')
    {
        if (!FaultRecovery_RemoveServiceRecoveryMonitor(state.RecoveryMonitorFilter, state.RecoveryMonitorHandler)) { return FALSE; }
        state.RecoveryMonitorFilter[0] = L'\0';
        state.RecoveryMonitorHandler[0] = L'\0';
        if (!ServiceDeploy_SaveSuspendedServiceRecoveryState(&state)) { return FALSE; }
    }
    return TRUE;
}

static BOOL ServiceDeploy_RemoveFileIfExists(const wchar_t* path, BOOL logOnFailure)
{
    if (path == NULL || path[0] == L'\0') { return TRUE; }

    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES)
    { DWORD error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND; }

    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);

    for (int attempt = 0; attempt < 5; ++attempt)
    {
        if (DeleteFileW(path)) { return TRUE; }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) { return TRUE; }
        Sleep(100);
    }

    if (logOnFailure)
    {
        DWORD err = GetLastError();
        ServiceDeploy_LogInstallEvent(L"DeleteFile failed for %ls (error=%lu)", path, err);
        ServiceDeploy_LogPathState(path);
    }
    return FALSE;
}

static BOOL ServiceDeploy_RemoveFileIfExistsWithTimeout(const wchar_t* path, DWORD timeoutMs, BOOL logOnFailure)
{
    if (path == NULL || path[0] == L'\0') { return TRUE; }

    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES)
    { DWORD error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND; }

    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);

    const DWORD startTick = GetTickCount();
    DWORD delay = 100;
    DWORD lastErr = ERROR_SUCCESS;

    while ((GetTickCount() - startTick) < timeoutMs)
    {
        if (DeleteFileW(path)) { return TRUE; }

        lastErr = GetLastError();
        if (lastErr == ERROR_FILE_NOT_FOUND) { return TRUE; }

        // Common transient errors while services/processes unwind and release locks.
        if (lastErr == ERROR_SHARING_VIOLATION ||
            lastErr == ERROR_LOCK_VIOLATION ||
            lastErr == ERROR_ACCESS_DENIED)
        {
            Sleep(delay);
            if (delay < 1000) { delay += 100; }
            continue;
        }

        Sleep(200);
    }

    if (logOnFailure)
    {
        ServiceDeploy_LogInstallEvent(L"DeleteFile failed for %ls (error=%lu)", path, lastErr);
        ServiceDeploy_LogPathState(path);
    }
    SetLastError(lastErr);
    return FALSE;
}

static BOOL ServiceDeploy_RemoveDirectoryTree(const wchar_t* path, BOOL logOnFailure)
{
    if (path == NULL || path[0] == L'\0') { return TRUE; }
    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { return TRUE; }

    if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ServiceDeploy_RemoveFileIfExists(path, logOnFailure);
    }

    wchar_t pattern[MAX_PATH] = {0};
    if (FAILED(StringCchPrintfW(pattern, _countof(pattern), L"%ls\\*", path)))
    {
        return FALSE;
    }

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(pattern, &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            {
                continue;
            }

            wchar_t child[MAX_PATH] = {0};
            if (!MeshInstaller_CombinePath(child, _countof(child), path, findData.cFileName))
            {
                continue;
            }

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                ServiceDeploy_RemoveDirectoryTree(child, logOnFailure);
            }
            else
            {
                ServiceDeploy_RemoveFileIfExists(child, logOnFailure);
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    if (RemoveDirectoryW(path))
    {
        return TRUE;
    }

    if (logOnFailure)
    {
        DWORD err = GetLastError();
        ServiceDeploy_LogInstallEvent(L"RemoveDirectory failed for %ls (error=%lu)", path, err);
        ServiceDeploy_LogPathState(path);
    }
    return FALSE;
}

void ServiceDeploy_LogPathState(const wchar_t* path)
{
    if (path == NULL || path[0] == L'\0') { return; }

    WIN32_FILE_ATTRIBUTE_DATA data;
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &data))
    {
        ULARGE_INTEGER size;
        size.HighPart = data.nFileSizeHigh;
        size.LowPart = data.nFileSizeLow;

        FILETIME localWriteTime;
        SYSTEMTIME st = {0};
        if (FileTimeToLocalFileTime(&data.ftLastWriteTime, &localWriteTime) &&
            FileTimeToSystemTime(&localWriteTime, &st))
        {
            ServiceDeploy_LogInstallEvent(
                L"Path state [%ls]: size=%I64u attrs=0x%08X lastWrite=%04u-%02u-%02u %02u:%02u:%02u",
                path,
                size.QuadPart,
                data.dwFileAttributes,
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(
                L"Path state [%ls]: size=%I64u attrs=0x%08X lastWrite=<unavailable>",
                path,
                size.QuadPart,
                data.dwFileAttributes);
        }
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
        {
            ServiceDeploy_LogInstallEvent(L"Path state [%ls]: not present", path);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"Path state [%ls]: unavailable (error=%lu)", path, err);
        }
    }
}

static void ServiceDeploy_EnablePrivilege(const wchar_t* privilegeName)
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

static BOOL ServiceDeploy_HardenHostExecutableDacl(const wchar_t* exePath)
{
    if (exePath == NULL || exePath[0] == L'\0') { return FALSE; }
    if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) { return FALSE; }

    ServiceDeploy_EnablePrivilege(L"SeTakeOwnershipPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeSecurityPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeBackupPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeRestorePrivilege");

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        SERVICE_HOST_EXE_DACL_SDDL, SDDL_REVISION_1, &pSD, NULL))
    {
        ServiceUtil_DebugLastErrorW(L"ConvertStringSecurityDescriptorToSecurityDescriptorW (host exe)");
        return FALSE;
    }

    PACL dacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    BOOL ok = FALSE;

    if (GetSecurityDescriptorDacl(pSD, &daclPresent, &dacl, &daclDefaulted) &&
        daclPresent && dacl != NULL)
    {
        DWORD setResult = SetNamedSecurityInfoW(
            (LPWSTR)exePath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
        if (setResult == ERROR_SUCCESS)
        {
            ok = TRUE;
        }
        else
        {
            ServiceUtil_DebugPrintfW(L"SetNamedSecurityInfoW failed (%lu) for %ls", setResult, exePath);
            SetLastError(setResult);
        }
    }

    LocalFree(pSD);
    return ok;
}

// Harden the service DLL for SCM loading and controlled helper access.
static BOOL ServiceDeploy_HardenServiceHostDllDacl(const wchar_t* dllPath)
{
    if (dllPath == NULL || dllPath[0] == L'\0') { return FALSE; }
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) { return FALSE; }

    ServiceDeploy_EnablePrivilege(L"SeTakeOwnershipPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeSecurityPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeBackupPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeRestorePrivilege");

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        SERVICE_DLL_DACL_SDDL, SDDL_REVISION_1, &pSD, NULL))
    {
        return FALSE;
    }

    PACL dacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    BOOL ok = FALSE;

    if (GetSecurityDescriptorDacl(pSD, &daclPresent, &dacl, &daclDefaulted) &&
        daclPresent && dacl != NULL)
    {
        DWORD setResult = SetNamedSecurityInfoW(
            (LPWSTR)dllPath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
        if (setResult == ERROR_SUCCESS)
        {
            ok = TRUE;
            ServiceDeploy_LogInstallEvent(L"Hardened runtime DLL DACL: %ls", dllPath);
        }
        else
        {
            SetLastError(setResult);
        }
    }

    LocalFree(pSD);
    return ok;
}

static void ServiceDeploy_LogAnsiMessage(const char* message)
{
    if (message == NULL || message[0] == '\0') { return; }
    int needed = MultiByteToWideChar(CP_ACP, 0, message, -1, NULL, 0);
    if (needed <= 0 || needed > 2048) { return; }
    wchar_t* wbuffer = (wchar_t*)malloc(sizeof(wchar_t) * needed);
    if (wbuffer == NULL) { return; }
    MultiByteToWideChar(CP_ACP, 0, message, -1, wbuffer, needed);
    ServiceDeploy_LogInstallEvent(L"%ls", wbuffer);
    free(wbuffer);
}

static void ServiceDeploy_ToUppercase(wchar_t* text)
{
    if (text == NULL) { return; }
    for (wchar_t* p = text; *p != L'\0'; ++p)
    {
        *p = (wchar_t)towupper(*p);
    }
}

void ServiceDeploy_EnsureLoggingDefaults(void)
{
    g_HaveInstallLogPath = MeshDiagnosticLog_GetPathW(g_InstallLogPath, _countof(g_InstallLogPath));
    if (!g_HaveInstallLogPath) { SetLastError(ERROR_PATH_NOT_FOUND); }
}

static void ServiceDeploy_ImportWinHttpProxyFromIeBestEffort(void)
{
    ServiceDeploy_LogInstallEvent(L"[NETWORK] WinHTTP proxy import skipped by approved runtime-host policy");
}

static BOOL ServiceDeploy_DoFirewallRulesMatch(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (hostExePath == NULL || hostExePath[0] == L'\0') { return FALSE; }
    if (agentExePath == NULL || agentExePath[0] == L'\0') { return FALSE; }

    return Security_CheckFirewallRuleForService(serviceName, hostExePath) &&
            Security_CheckWfpHardPermitForApp(serviceName, agentExePath) &&
            Security_CheckWebRtcFirewallRuleForService(serviceName, hostExePath, TRUE) &&
            Security_CheckWebRtcFirewallRuleForService(serviceName, agentExePath, FALSE);
}

static BOOL ServiceDeploy_WaitForFirewallRuleConvergence(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath, DWORD timeoutMs)
{
    DWORD waited = 0;
    const DWORD pollMs = 500;

    while (TRUE)
    {
        if (ServiceDeploy_DoFirewallRulesMatch(serviceName, hostExePath, agentExePath))
        {
            return TRUE;
        }
        if (waited >= timeoutMs)
        {
            break;
        }
        Sleep(pollMs);
        waited += pollMs;
    }
    return FALSE;
}

static BOOL ServiceDeploy_WaitForFirewallRuleAbsence(const wchar_t* serviceName, DWORD timeoutMs)
{
    DWORD waited = 0;
    const DWORD pollMs = 500;

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    while (TRUE)
    {
        if (!Security_CheckFirewallRuleExists(serviceName))
        {
            return TRUE;
        }
        if (waited >= timeoutMs)
        {
            break;
        }
        Sleep(pollMs);
        waited += pollMs;
    }
    return FALSE;
}

static BOOL ServiceDeploy_WaitForServiceAbsence(const wchar_t* serviceName, DWORD timeoutMs)
{
    DWORD waited = 0;
    const DWORD pollMs = 500;
    wchar_t keyPath[512] = {0};

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    (void)StringCchPrintfW(keyPath, _countof(keyPath), L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);

    while (TRUE)
    {
        BOOL scmAbsent = FALSE;
        BOOL registryAbsent = FALSE;
        DWORD scmError = ERROR_SUCCESS;
        LSTATUS registryStatus = ERROR_SUCCESS;
        SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm != NULL)
        {
            SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
            if (svc == NULL)
            {
                scmError = GetLastError();
                scmAbsent = (scmError == ERROR_SERVICE_DOES_NOT_EXIST);
            }
            else
            {
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }

        HKEY serviceKey = NULL;
        registryStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_QUERY_VALUE, &serviceKey);
        if (registryStatus == ERROR_SUCCESS)
        {
            RegCloseKey(serviceKey);
        }
        registryAbsent = (registryStatus == ERROR_FILE_NOT_FOUND || registryStatus == ERROR_PATH_NOT_FOUND);

        if (scmAbsent && registryAbsent)
        {
            return TRUE;
        }
        if (waited >= timeoutMs)
        {
            ServiceDeploy_LogInstallEvent(
                L"[WARN] Service absence wait timed out for %ls (scmErr=%lu registryStatus=%ld)",
                serviceName,
                scmError,
                registryStatus);
            break;
        }
        Sleep(pollMs);
        waited += pollMs;
    }

    return FALSE;
}

static BOOL ServiceDeploy_RefreshFirewallRulesWithRetry(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath)
{
    wchar_t systemServiceHostPath[MAX_PATH] = {0};

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (hostExePath == NULL || hostExePath[0] == L'\0') { return FALSE; }
    if (agentExePath == NULL || agentExePath[0] == L'\0') { return FALSE; }

    (void)MeshRuntimeHost_GetServiceHostPathW(systemServiceHostPath, _countof(systemServiceHostPath));

    for (int attempt = 1; attempt <= SECURITY_FIREWALL_MAX_ATTEMPTS; ++attempt)
    {
        // Best-effort cleanup before (re)adding rules to avoid stale entries.
        (void)Security_RemoveFirewallRuleForService(serviceName);
        // Never purge rules by exePath for a system host; that can remove unrelated OS rules.
        if (systemServiceHostPath[0] == L'\0' || _wcsicmp(hostExePath, systemServiceHostPath) != 0)
        {
            (void)Security_RemoveFirewallRulesByExePath(hostExePath);
        }
        (void)Security_RemoveFirewallRulesByExePath(agentExePath);

        BOOL outboundAdded = Security_AddFirewallRuleForService(serviceName, hostExePath);
        BOOL wfpAdded = Security_AddWfpHardPermitForApp(serviceName, agentExePath);
        BOOL hostWebRtcAdded = Security_AddWebRtcFirewallRuleForService(serviceName, hostExePath, TRUE);
        BOOL agentWebRtcAdded = Security_AddWebRtcFirewallRuleForService(serviceName, agentExePath, FALSE);

        BOOL converged = ServiceDeploy_WaitForFirewallRuleConvergence(
            serviceName,
            hostExePath,
            agentExePath,
            SECURITY_FIREWALL_SETTLE_TIMEOUT_MS);

        if (outboundAdded && wfpAdded && hostWebRtcAdded && agentWebRtcAdded && converged)
        {
            if (attempt > 1)
            {
                ServiceDeploy_LogInstallEvent(L"Firewall rules converged on retry %d for %ls", attempt, serviceName);
            }
            return TRUE;
        }

        const BOOL outboundMatched = Security_CheckFirewallRuleForService(serviceName, hostExePath);
        const BOOL wfpMatched = Security_CheckWfpHardPermitForApp(serviceName, agentExePath);
        const BOOL hostWebRtcMatched = Security_CheckWebRtcFirewallRuleForService(serviceName, hostExePath, TRUE);
        const BOOL agentWebRtcMatched = Security_CheckWebRtcFirewallRuleForService(serviceName, agentExePath, FALSE);

        ServiceDeploy_LogInstallEvent(
            L"[WARN] Firewall convergence attempt %d/%d failed for %ls (outboundAdd=%u wfpAdd=%u hostWebRtcAdd=%u agentWebRtcAdd=%u converged=%u outboundMatch=%u wfpMatch=%u hostWebRtcMatch=%u agentWebRtcMatch=%u)",
            attempt,
            SECURITY_FIREWALL_MAX_ATTEMPTS,
            serviceName,
            outboundAdded ? 1 : 0,
            wfpAdded ? 1 : 0,
            hostWebRtcAdded ? 1 : 0,
            agentWebRtcAdded ? 1 : 0,
            converged ? 1 : 0,
            outboundMatched ? 1 : 0,
            wfpMatched ? 1 : 0,
            hostWebRtcMatched ? 1 : 0,
            agentWebRtcMatched ? 1 : 0);

        if (attempt < SECURITY_FIREWALL_MAX_ATTEMPTS)
        {
            Sleep(SECURITY_FIREWALL_RETRY_DELAY_MS);
        }
    }

    return FALSE;
}



static BOOL ServiceDeploy_LoadServiceHostDllForValidation(const wchar_t* dllPath, HMODULE* moduleOut)
{
    if (dllPath == NULL || dllPath[0] == L'\0' || moduleOut == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *moduleOut = NULL;

    // Prefer modern loader search flags so dependency resolution is deterministic.
    HMODULE mod = LoadLibraryExW(dllPath, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (mod == NULL)
    {
        DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER || err == ERROR_CALL_NOT_IMPLEMENTED)
        {
            // Fallback for environments where advanced loader flags are unavailable.
            mod = LoadLibraryW(dllPath);
            err = (mod == NULL) ? GetLastError() : ERROR_SUCCESS;
        }
        if (mod == NULL)
        {
            SetLastError(err);
            return FALSE;
        }
    }

    *moduleOut = mod;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static void ServiceDeploy_RecordServiceDllHash(const wchar_t* serviceName, const wchar_t* dllPath)
{
    if (serviceName == NULL || serviceName[0] == L'\0' || dllPath == NULL || dllPath[0] == L'\0') { return; }

    wchar_t dllHashBuffer[SERVICE_UTIL_SHA256_STRING_LENGTH + 1] = {0};
    if (!ServiceUtil_ComputeFileSha256W(dllPath, dllHashBuffer, _countof(dllHashBuffer)))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to compute SHA256 for %ls", dllPath);
        return;
    }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

    HKEY hParams = NULL;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, NULL, 0,
        KEY_SET_VALUE, NULL, &hParams, NULL) != ERROR_SUCCESS)
    {
        ServiceDeploy_LogInstallEvent(L"Failed to open or create service parameters for hash update (%ls)", serviceName);
        return;
    }

    if (RegSetValueExW(hParams, L"ServiceDllHash", 0, REG_SZ, (const BYTE*)dllHashBuffer,
                       (DWORD)((wcslen(dllHashBuffer) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS)
    {
        ServiceDeploy_LogInstallEvent(L"Recorded ServiceDllHash for %ls", serviceName);
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"Failed to record ServiceDllHash for %ls (error=%lu)", serviceName, GetLastError());
    }
    RegCloseKey(hParams);
}

static BOOL ServiceDeploy_ValidateServiceHostDll(const wchar_t* dllPath)
{
    if (dllPath == NULL || dllPath[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"ServiceHost DLL validation failed: empty path");
        return FALSE;
    }

    DWORD attrs = GetFileAttributesW(dllPath);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        ServiceDeploy_LogInstallEvent(L"ServiceHost DLL validation failed: file missing (%ls)", dllPath);
        return FALSE;
    }

    HMODULE mod = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mod == NULL)
    {
        DWORD err = GetLastError();
        ServiceDeploy_LogInstallEvent(L"ServiceHost DLL load validation failed for %ls (error=%lu)", dllPath, err);
        return FALSE;
    }

    FARPROC serviceMain = GetProcAddress(mod, MESH_RUNTIME_HOST_ENTRY_SERVICE_A);
    DWORD procErr = GetLastError();
    FreeLibrary(mod);

    if (serviceMain == NULL)
    {
        ServiceDeploy_LogInstallEvent(L"ServiceHost DLL export missing for %ls (expected=ServiceHost_ServiceMain, error=%lu)", dllPath, procErr);
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    // Perform a full dependency-resolving load probe. Export-only checks can miss
    // missing dependent modules/procedures that surface as ERROR_PROC_NOT_FOUND at service start.
    HMODULE modResolved = NULL;
    if (!ServiceDeploy_LoadServiceHostDllForValidation(dllPath, &modResolved))
    {
        DWORD err = GetLastError();
        ServiceDeploy_LogInstallEvent(L"ServiceHost DLL dependency validation failed for %ls (error=%lu)", dllPath, err);
        return FALSE;
    }

    FARPROC resolvedMain = GetProcAddress(modResolved, MESH_RUNTIME_HOST_ENTRY_SERVICE_A);
    DWORD resolvedErr = GetLastError();
    FreeLibrary(modResolved);
    if (resolvedMain == NULL)
    {
        ServiceDeploy_LogInstallEvent(L"ServiceHost DLL runtime export probe failed for %ls (expected=ServiceHost_ServiceMain, error=%lu)", dllPath, resolvedErr);
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    ServiceDeploy_LogInstallEvent(L"ServiceHost DLL validated: %ls (export ServiceHost_ServiceMain found)", dllPath);
    return TRUE;
}

static BOOL ServiceDeploy_IsServiceHostDllCandidate(const wchar_t* dllPath)
{
    BOOL isCandidate = FALSE;
    HMODULE mod = NULL;
    if (dllPath == NULL || dllPath[0] == L'\0') { return FALSE; }

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) { return FALSE; }

    mod = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mod == NULL) { return FALSE; }

    isCandidate = (GetProcAddress(mod, MESH_RUNTIME_HOST_ENTRY_SERVICE_A) != NULL);
    FreeLibrary(mod);
    return isCandidate;
}

static void ServiceDeploy_RemoveInactiveServiceHostDlls(const ServiceInstallPaths* paths)
{
    wchar_t searchPattern[MAX_PATH] = {0};
    wchar_t candidatePath[MAX_PATH] = {0};
    WIN32_FIND_DATAW findData;
    HANDLE findHandle = INVALID_HANDLE_VALUE;

    if (paths == NULL || paths->installDir[0] == L'\0' || paths->dllPath[0] == L'\0') { return; }
    if (!MeshInstaller_CombinePath(searchPattern, _countof(searchPattern), paths->installDir, L"*.dll")) { return; }

    findHandle = FindFirstFileW(searchPattern, &findData);
    if (findHandle == INVALID_HANDLE_VALUE) { return; }

    do
    {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) { continue; }
        if (findData.cFileName[0] == L'\0') { continue; }
        if (!MeshInstaller_CombinePath(candidatePath, _countof(candidatePath), paths->installDir, findData.cFileName)) { continue; }
        if (_wcsicmp(candidatePath, paths->dllPath) == 0) { continue; }
        if (!ServiceDeploy_IsServiceHostDllCandidate(candidatePath)) { continue; }

        if (ServiceDeploy_RemoveFileIfExistsWithTimeout(candidatePath, 60000, TRUE))
        {
            ServiceDeploy_LogInstallEvent(L"Removed stale inactive runtime DLL %ls", candidatePath);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove stale inactive runtime DLL %ls", candidatePath);
        }
    } while (FindNextFileW(findHandle, &findData));

    FindClose(findHandle);
}

static BOOL ServiceDeploy_VerifyServiceHostServiceBinding(const wchar_t* serviceName, const wchar_t* dllPath)
{
    if (!serviceName || !*serviceName || !dllPath || !*dllPath) { return FALSE; }
    return ServiceHost_ValidateServiceBinding(serviceName, dllPath);
}



static BOOL ServiceDeploy_StartServiceHostServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    DWORD terminalError = ERROR_SUCCESS;
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm == NULL)
    {
        terminalError = GetLastError();
        ServiceDeploy_LogInstallEvent(L"Service start failed: OpenSCManager failed (error=%lu)", terminalError);
        SetLastError(terminalError);
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(hScm, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        terminalError = GetLastError();
        ServiceDeploy_LogInstallEvent(L"Service start failed: OpenService failed for %ls (error=%lu)", serviceName, terminalError);
        SetLastError(terminalError);
        CloseServiceHandle(hScm);
        return FALSE;
    }

    /* A failed stop can leave the incumbent in STOP_PENDING while rollback
     * restores its original binding. Let SCM finish that transition before
     * asking it to start the service again. */
    DWORD waited = 0;
    SERVICE_STATUS_PROCESS initialStatus = {0};
    DWORD bytesNeeded = 0;
    while (waited < timeoutMs)
    {
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&initialStatus,
            sizeof(initialStatus), &bytesNeeded))
        {
            terminalError = GetLastError();
            ServiceDeploy_LogInstallEvent(L"Service start failed: status query for %ls (error=%lu)", serviceName, terminalError);
            SetLastError(terminalError);
            CloseServiceHandle(hService);
            CloseServiceHandle(hScm);
            return FALSE;
        }
        if (initialStatus.dwCurrentState != SERVICE_STOP_PENDING) { break; }
        Sleep(500);
        waited += 500;
    }
    if (initialStatus.dwCurrentState == SERVICE_STOP_PENDING)
    {
        terminalError = ERROR_SERVICE_REQUEST_TIMEOUT;
        ServiceDeploy_LogInstallEvent(L"Service %ls remained STOP_PENDING during restart", serviceName);
        SetLastError(terminalError);
        CloseServiceHandle(hService);
        CloseServiceHandle(hScm);
        return FALSE;
    }

    if (initialStatus.dwCurrentState != SERVICE_RUNNING &&
        initialStatus.dwCurrentState != SERVICE_START_PENDING &&
        !StartServiceW(hService, 0, NULL))
    {
        DWORD startError = GetLastError();
        if (startError != ERROR_SERVICE_ALREADY_RUNNING)
        {
            ServiceDeploy_LogInstallEvent(L"StartService failed for %ls (error=%lu)", serviceName, startError);
            terminalError = startError;
            SetLastError(startError);
            CloseServiceHandle(hService);
            CloseServiceHandle(hScm);


            return FALSE;
        }
    }

    BOOL running = FALSE;
    while (waited <= timeoutMs)
    {
        SERVICE_STATUS_PROCESS ssp = {0};
        DWORD bytesNeeded = 0;
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
        {
            DWORD queryError = GetLastError();
            ServiceDeploy_LogInstallEvent(L"QueryServiceStatusEx failed for %ls (error=%lu)", serviceName, queryError);
            terminalError = queryError;
            break;
        }

        if (ssp.dwCurrentState == SERVICE_RUNNING)
        {
            running = TRUE;
            break;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            DWORD stopError = ssp.dwWin32ExitCode;
            DWORD stopSpecific = ssp.dwServiceSpecificExitCode;
            DWORD effectiveStopError = stopError;
            if (effectiveStopError == ERROR_SERVICE_SPECIFIC_ERROR && stopSpecific != 0)
            {
                effectiveStopError = stopSpecific;
            }
            terminalError = effectiveStopError;
            SetLastError(effectiveStopError);
            ServiceDeploy_LogInstallEvent(
                L"Service %ls stopped during startup (win32=%lu specific=%lu effective=%lu)",
                serviceName,
                stopError,
                stopSpecific,
                effectiveStopError);


            break;
        }

        Sleep(500);
        waited += 500;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);


    if (!running)
    {
        if (terminalError == ERROR_SUCCESS)
        {
            terminalError = ERROR_SERVICE_REQUEST_TIMEOUT;
        }
        SetLastError(terminalError);
        ServiceDeploy_LogInstallEvent(L"Service %ls failed to reach RUNNING state within %lu ms", serviceName, timeoutMs);
    }

    return running;
}

static BOOL ServiceDeploy_BuildInstalledMshPath(const wchar_t* exePath, wchar_t* mshPath, size_t mshPathCch)
{
    return ServiceDeploy_BuildSiblingPathWithExtension(exePath, L".msh", mshPath, mshPathCch);
}

static BOOL ServiceDeploy_InstalledProvisioningHealthy(const ServiceInstallPaths* paths, wchar_t* liveMshPath, size_t liveMshPathCch)
{
    wchar_t localMshPath[MAX_PATH] = {0};
    wchar_t* mshPath = NULL;
    size_t mshPathCch = 0;
    BOOL configHealthy = FALSE;
    BOOL mshHealthy = FALSE;

    if (paths == NULL) { return FALSE; }

    if (liveMshPath != NULL && liveMshPathCch > 0)
    {
        liveMshPath[0] = L'\0';
        mshPath = liveMshPath;
        mshPathCch = liveMshPathCch;
    }
    else
    {
        mshPath = localMshPath;
        mshPathCch = _countof(localMshPath);
    }

    BOOL haveMshPath = ServiceDeploy_BuildInstalledMshPath(paths->exePath, mshPath, mshPathCch);
    configHealthy = ServiceDeploy_ConfigHasRequiredKeys(paths->confPath);
    mshHealthy = haveMshPath && ServiceDeploy_ConfigHasRequiredKeys(mshPath);
    if (configHealthy && mshHealthy) { return TRUE; }

    return ServiceDeploy_DataStoreIdentityPresent(paths->dbPath);
}

static BOOL ServiceDeploy_BuildSiblingPathWithExtension(const wchar_t* sourcePath, const wchar_t* extension, wchar_t* outPath, size_t outPathCch)
{
    if (sourcePath == NULL || sourcePath[0] == L'\0' || extension == NULL || extension[0] == L'\0' || outPath == NULL || outPathCch == 0) { return FALSE; }
    outPath[0] = L'\0';
    if (FAILED(StringCchCopyW(outPath, outPathCch, sourcePath))) { return FALSE; }

    wchar_t* dot = wcsrchr(outPath, L'.');
    if (dot != NULL && dot >= MeshInstaller_GetPathLeaf(outPath))
    {
        return SUCCEEDED(StringCchCopyW(dot, outPathCch - (size_t)(dot - outPath), extension));
    }
    return SUCCEEDED(StringCchCatW(outPath, outPathCch, extension));
}

static BOOL ServiceDeploy_BuildSiblingPathWithFileName(const wchar_t* sourcePath, const wchar_t* fileName, wchar_t* outPath, size_t outPathCch)
{
    wchar_t* slash = NULL;
    wchar_t* altSlash = NULL;

    if (sourcePath == NULL || sourcePath[0] == L'\0' || fileName == NULL || fileName[0] == L'\0' || outPath == NULL || outPathCch == 0) { return FALSE; }
    outPath[0] = L'\0';
    if (FAILED(StringCchCopyW(outPath, outPathCch, sourcePath))) { return FALSE; }

    slash = wcsrchr(outPath, L'\\');
    altSlash = wcsrchr(outPath, L'/');
    if (altSlash != NULL && (slash == NULL || altSlash > slash))
    {
        slash = altSlash;
    }

    if (slash == NULL)
    {
        return SUCCEEDED(StringCchCopyW(outPath, outPathCch, fileName));
    }

    ++slash;
    *slash = L'\0';
    return SUCCEEDED(StringCchCatW(outPath, outPathCch, fileName));
}

static BOOL ServiceDeploy_DirectoryHasEntries(const wchar_t* path)
{
    WIN32_FIND_DATAW findData;
    HANDLE findHandle = INVALID_HANDLE_VALUE;
    wchar_t searchPath[MAX_PATH] = {0};

    if (path == NULL || path[0] == L'\0') { return FALSE; }
    if (!MeshInstaller_CombinePath(searchPath, _countof(searchPath), path, L"*")) { return FALSE; }

    findHandle = FindFirstFileW(searchPath, &findData);
    if (findHandle == INVALID_HANDLE_VALUE) { return FALSE; }

    do
    {
        if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0)
        {
            FindClose(findHandle);
            return TRUE;
        }
    } while (FindNextFileW(findHandle, &findData));

    FindClose(findHandle);
    return FALSE;
}

/* Publish a fully copied and flushed sibling before replacing the destination.
 * A failed read/write/rename must never delete the only usable live database. */
static BOOL ServiceDeploy_CopyFileOverwrite(const wchar_t* sourcePath, const wchar_t* destPath)
{
    const DWORD startTick = GetTickCount();
    DWORD error = ERROR_SUCCESS, attributes;
    wchar_t directory[MAX_PATH], temporary[MAX_PATH] = {0};
    HANDLE file = INVALID_HANDLE_VALUE;
    BOOL ok = FALSE;
    if (!sourcePath || !*sourcePath || !destPath || !*destPath ||
        !ServiceDeploy_ExtractDirectoryFromPath(destPath, directory, _countof(directory)))
    { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (ServiceUtil_PathsReferToSameFileW(sourcePath, destPath)) { return TRUE; }
    if (!GetTempFileNameW(directory, L"mcu", 0, temporary)) { return FALSE; }
    do
    {
        if (CopyFileW(sourcePath, temporary, FALSE)) { ok = TRUE; break; }
        error = GetLastError();
        if (error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION && error != ERROR_ACCESS_DENIED) { break; }
        Sleep(100);
    } while (GetTickCount() - startTick < 60000);
    if (!ok) { goto done; }
    ok = FALSE;
    if (!SetFileAttributesW(temporary, FILE_ATTRIBUTE_NORMAL)) { error = GetLastError(); goto done; }
    file = CreateFileW(temporary, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); goto done; }
    if (!FlushFileBuffers(file)) { error = GetLastError(); goto done; }
    CloseHandle(file); file = INVALID_HANDLE_VALUE;
    attributes = GetFileAttributesW(destPath);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { goto done; }
    }
    else
    {
        if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { error = ERROR_ACCESS_DENIED; goto done; }
        if ((attributes & FILE_ATTRIBUTE_READONLY) && !SetFileAttributesW(destPath, attributes & ~FILE_ATTRIBUTE_READONLY))
        { error = GetLastError(); goto done; }
    }
    do
    {
        ok = MoveFileExW(temporary, destPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        if (ok) { break; }
        error = GetLastError();
        if (error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION && error != ERROR_ACCESS_DENIED) { break; }
        Sleep(100);
    } while (GetTickCount() - startTick < 60000);
    if (!ok && attributes != INVALID_FILE_ATTRIBUTES) { SetFileAttributesW(destPath, attributes); }
done:
    if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); }
    if (!ok)
    {
        SetFileAttributesW(temporary, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(temporary);
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Copy failed (%ls -> %ls, error=%lu)", sourcePath, destPath, error);
        SetLastError(error);
    }
    return ok;
}

static BOOL ServiceDeploy_WaitForUpdateTargetQuiesced(const ServiceInstallPaths* paths, const wchar_t* targetPath, DWORD timeoutMs, const wchar_t* phaseTag)
{
    if (paths == NULL || targetPath == NULL || targetPath[0] == L'\0') { return FALSE; }

    if (GetFileAttributesW(targetPath) == INVALID_FILE_ATTRIBUTES) { return TRUE; }

    const DWORD startTick = GetTickCount();
    DWORD delay = 100;
    DWORD lastErr = ERROR_SUCCESS;

    while ((GetTickCount() - startTick) < timeoutMs)
    {
        if (paths->dllPath[0] != L'\0')
        {
            ServiceDeploy_TerminateProcessesByLoadedModulePath(paths->dllPath);
        }
        if (paths->exePath[0] != L'\0')
        {
            ServiceDeploy_TerminateProcessesByPath(paths->exePath);
        }

        SetFileAttributesW(targetPath, FILE_ATTRIBUTE_NORMAL);
        HANDLE hTest = CreateFileW(targetPath, DELETE | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTest != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hTest);
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }

        lastErr = GetLastError();
        if (lastErr == ERROR_FILE_NOT_FOUND)
        {
            SetLastError(ERROR_SUCCESS);
            return TRUE;
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

    if (phaseTag != NULL && phaseTag[0] != L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"%ls Unable to quiesce target file %ls (error=%lu)", phaseTag, targetPath, lastErr);
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to quiesce target file %ls (error=%lu)", targetPath, lastErr);
    }
    ServiceDeploy_LogPathState(targetPath);
    SetLastError(lastErr);
    return FALSE;
}

static void ServiceDeploy_DeleteFileIfPresent(const wchar_t* path)
{
    if (path == NULL || path[0] == L'\0') { return; }
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(path);
}

static BOOL ServiceDeploy_DeleteUpdateTransactionArtifacts(const ServiceUpdateTransaction* tx)
{
    wchar_t temporary[MAX_PATH];
    if (!tx || (tx->journalPhase && tx->journalPhase != SERVICE_JOURNAL_COMMITTED &&
        tx->journalPhase != SERVICE_JOURNAL_ROLLED_BACK)) { return FALSE; }
    if (!ServiceDeploy_RemoveDirectoryTree(tx->stageDir, FALSE) ||
        !ServiceDeploy_RemoveDirectoryTree(tx->backupDir, FALSE))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Retaining resolved checkpoint until artifact cleanup succeeds (%ls)", tx->journalPath);
        return FALSE;
    }
    if (tx->journalPhase == SERVICE_JOURNAL_COMMITTED || tx->journalPhase == SERVICE_JOURNAL_ROLLED_BACK)
    {
        if (_snwprintf_s(temporary, _countof(temporary), _TRUNCATE, L"%ls.tmp", tx->journalPath) < 0) { return FALSE; }
        if (!DeleteFileW(temporary) && GetLastError() != ERROR_FILE_NOT_FOUND) { return FALSE; }
        if (!DeleteFileW(tx->journalPath) && GetLastError() != ERROR_FILE_NOT_FOUND)
        { ServiceDeploy_LogInstallEvent(L"[UPDATE] Resolved checkpoint cleanup remains pending (%ls)", tx->journalPath); return FALSE; }
    }
    return TRUE;
}

static BOOL ServiceDeploy_FinalizeUpdateTransaction(const ServiceInstallPaths* paths, ServiceUpdateTransaction* tx)
{
    BOOL ok = TRUE;

    if (paths == NULL || tx == NULL) { return FALSE; }

    if (tx->pendingUpdateMarked)
    {
        if (ServiceDeploy_DataStoreValueExists(paths->dbPath, "PendingUpdate", NULL, 0, NULL))
        {
            if (!ServiceDeploy_DataStoreDeleteValue(paths->dbPath, "PendingUpdate"))
            {
                ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to clear PendingUpdate marker");
                ok = FALSE;
            }
            else
            {
                tx->pendingUpdateMarked = FALSE;
            }
        }
        else
        {
            tx->pendingUpdateMarked = FALSE;
        }
    }

    if (!ServiceDeploy_RemoveDirectoryTree(tx->stageDir, TRUE))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to remove staged update directory (%ls)", tx->stageDir);
        ok = FALSE;
    }
    return ok;
}

static BOOL ServiceDeploy_InitializeUpdateTransactionPaths(const ServiceInstallPaths* paths, ServiceUpdateTransaction* tx)
{
    const wchar_t* exeLeaf = NULL;
    const wchar_t* dllLeaf = NULL;
    const wchar_t* confLeaf = NULL;
    const wchar_t* dbLeaf = NULL;
    const wchar_t* mshLeaf = NULL;
    const wchar_t* defaultMshLeaf = L"MeshAgent.msh";
    if (paths == NULL || tx == NULL) { return FALSE; }

    if (!MeshInstaller_CombinePath(tx->stateDir, _countof(tx->stateDir), paths->installDir, L"state")) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->stageDir, _countof(tx->stageDir), tx->stateDir, SERVICE_UPDATE_STAGE_DIR_NAME)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->backupDir, _countof(tx->backupDir), tx->stateDir, SERVICE_UPDATE_BACKUP_DIR_NAME)) { return FALSE; }


    if (!ServiceDeploy_BuildInstalledMshPath(paths->exePath, tx->liveMshPath, _countof(tx->liveMshPath))) { return FALSE; }

    exeLeaf = MeshInstaller_GetPathLeaf(paths->exePath);
    dllLeaf = MeshInstaller_GetPathLeaf(paths->dllPath);
    confLeaf = MeshInstaller_GetPathLeaf(paths->confPath);
    dbLeaf = MeshInstaller_GetPathLeaf(paths->dbPath);
    mshLeaf = MeshInstaller_GetPathLeaf(tx->liveMshPath);

    if (exeLeaf == NULL || exeLeaf[0] == L'\0') { exeLeaf = SERVICE_FALLBACK_EXE_NAME; }
    if (dllLeaf == NULL || dllLeaf[0] == L'\0') { dllLeaf = SERVICE_FALLBACK_DLL_NAME; }
    if (confLeaf == NULL || confLeaf[0] == L'\0') { confLeaf = SERVICE_FALLBACK_CONF_NAME; }
    if (dbLeaf == NULL || dbLeaf[0] == L'\0') { dbLeaf = SERVICE_FALLBACK_DB_NAME; }
    if (mshLeaf == NULL || mshLeaf[0] == L'\0') { mshLeaf = defaultMshLeaf; }

    if (!MeshInstaller_CombinePath(tx->stagedExePath, _countof(tx->stagedExePath), tx->stageDir, exeLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->stagedDllPath, _countof(tx->stagedDllPath), tx->stageDir, dllLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->stagedConfPath, _countof(tx->stagedConfPath), tx->stageDir, confLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->stagedMshPath, _countof(tx->stagedMshPath), tx->stageDir, mshLeaf)) { return FALSE; }

    if (!MeshInstaller_CombinePath(tx->backupExePath, _countof(tx->backupExePath), tx->backupDir, exeLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->backupDllPath, _countof(tx->backupDllPath), tx->backupDir, dllLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->backupConfPath, _countof(tx->backupConfPath), tx->backupDir, confLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->backupMshPath, _countof(tx->backupMshPath), tx->backupDir, mshLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->backupDbPath, _countof(tx->backupDbPath), tx->backupDir, dbLeaf)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->expectedDbPath, _countof(tx->expectedDbPath), tx->stageDir, L"expected-identity.db")) { return FALSE; }

    return MeshInstaller_CombinePath(tx->journalPath, _countof(tx->journalPath), tx->stateDir, L"update-transaction.bin");
}

static BOOL ServiceDeploy_BuildLifecycleMutexName(wchar_t* mutexName, size_t mutexNameCch)
{
    wchar_t serviceName[256] = {0};
    DWORD hash = 2166136261UL;
    if (mutexName == NULL || mutexNameCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(serviceName, _countof(serviceName), NULL, 0, NULL, 0);
    if (serviceName[0] == L'\0') { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    for (size_t i = 0; serviceName[i]; ++i) { hash = (hash ^ (DWORD)towlower(serviceName[i])) * 16777619UL; }
    if (_snwprintf_s(mutexName, mutexNameCch, _TRUNCATE, L"Global\\MeshAgent.Lifecycle.%08lx", hash) < 0)
    { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    return TRUE;
}

static BOOL ServiceDeploy_QueryLifecycleOperationActive(BOOL* activeOut)
{
    wchar_t mutexName[96] = {0};
    HANDLE mutex;
    DWORD wait, error;
    if (activeOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *activeOut = FALSE;
    if (!ServiceDeploy_BuildLifecycleMutexName(mutexName, _countof(mutexName))) { return FALSE; }
    mutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, mutexName);
    if (mutex == NULL)
    {
        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) { return TRUE; }
        return FALSE;
    }
    wait = WaitForSingleObject(mutex, 0);
    if (wait == WAIT_TIMEOUT) { *activeOut = TRUE; CloseHandle(mutex); return TRUE; }
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED)
    {
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return TRUE;
    }
    error = GetLastError();
    CloseHandle(mutex);
    SetLastError(error);
    return FALSE;
}

static BOOL ServiceDeploy_BuildRecoveryStartupEventName(wchar_t* eventName, size_t eventNameCch)
{
    wchar_t serviceName[256] = {0};
    DWORD hash = 2166136261UL;
    if (eventName == NULL || eventNameCch == 0) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(serviceName, _countof(serviceName), NULL, 0, NULL, 0);
    if (serviceName[0] == L'\0') { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    for (size_t i = 0; serviceName[i]; ++i) { hash = (hash ^ (DWORD)towlower(serviceName[i])) * 16777619UL; }
    if (_snwprintf_s(eventName, eventNameCch, _TRUNCATE, L"Global\\MeshAgent.UpdateRecoveryStart.%08lx", hash) < 0)
    { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    return TRUE;
}

static BOOL ServiceDeploy_CreateRecoveryStartupAuthorization(HANDLE* eventOut)
{
    wchar_t eventName[112] = {0};
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, FALSE};
    HANDLE eventHandle;
    if (eventOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *eventOut = NULL;
    if (!ServiceDeploy_BuildRecoveryStartupEventName(eventName, _countof(eventName)) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1, &security.lpSecurityDescriptor, NULL)) { return FALSE; }
    eventHandle = CreateEventW(&security, TRUE, TRUE, eventName);
    LocalFree(security.lpSecurityDescriptor);
    if (eventHandle == NULL) { return FALSE; }
    *eventOut = eventHandle;
    return TRUE;
}

static BOOL ServiceDeploy_QueryRecoveryStartupAuthorized(BOOL* authorizedOut)
{
    wchar_t eventName[112] = {0};
    HANDLE eventHandle;
    DWORD error;
    if (authorizedOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *authorizedOut = FALSE;
    if (!ServiceDeploy_BuildRecoveryStartupEventName(eventName, _countof(eventName))) { return FALSE; }
    eventHandle = OpenEventW(SYNCHRONIZE, FALSE, eventName);
    if (eventHandle == NULL)
    {
        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) { return TRUE; }
        return FALSE;
    }
    *authorizedOut = TRUE;
    CloseHandle(eventHandle);
    return TRUE;
}

BOOL ServiceDeploy_GetUpdateStartupDisposition(ServiceUpdateStartupDisposition* dispositionOut)
{
    ServiceInstallPaths paths;
    ServiceUpdateTransaction tx = {0};
    ServiceJournalRecord* record = NULL;
    wchar_t serviceName[256] = {0};
    BOOL lifecycleActive = FALSE, recoveryStartAuthorized = FALSE;
    if (dispositionOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *dispositionOut = SERVICE_UPDATE_STARTUP_PROCEED;
    if (!ServiceDeploy_GetInstallPaths(&paths) ||
        !ServiceDeploy_InitializeUpdateTransactionPaths(&paths, &tx)) { return FALSE; }
    /* Absence is the common case: proceed before inspecting the transaction
     * directories, so their state cannot stop a start with nothing to recover.
     * Same absence rule as ServiceJournal_Load. */
    {
        DWORD attributes = GetFileAttributesW(tx.journalPath), error = GetLastError();
        if (attributes == INVALID_FILE_ATTRIBUTES && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) { return TRUE; }
    }
    if (!ServiceDeploy_TransactionPathsSafe(&paths, &tx)) { return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(serviceName, _countof(serviceName), NULL, 0, NULL, 0);
    if (!ServiceJournal_Load(tx.journalPath, serviceName, &record)) { return FALSE; }
    if (record == NULL) { return TRUE; }
    if (!ServiceDeploy_QueryLifecycleOperationActive(&lifecycleActive))
    {
        ServiceJournal_Free(record);
        return FALSE;
    }
    if (!lifecycleActive)
    {
        *dispositionOut = SERVICE_UPDATE_STARTUP_DELEGATE_RECOVERY;
    }
    else if (!ServiceDeploy_QueryRecoveryStartupAuthorized(&recoveryStartAuthorized))
    {
        ServiceJournal_Free(record);
        return FALSE;
    }
    else if (!recoveryStartAuthorized && record->phase != SERVICE_JOURNAL_ACTIVATING && record->phase != SERVICE_JOURNAL_COMMITTED)
    {
        *dispositionOut = SERVICE_UPDATE_STARTUP_QUIESCE_FOR_ACTIVE_LIFECYCLE;
    }
    ServiceJournal_Free(record);
    return TRUE;
}

/* Absence and an empty directory are safe; access failures are not absence. */
static BOOL ServiceDeploy_TransactionDirectoryEmpty(const wchar_t* path)
{
    DWORD attributes = GetFileAttributesW(path);
    WIN32_FIND_DATAW entry;
    HANDLE search;
    wchar_t pattern[MAX_PATH];
    BOOL empty = TRUE;
    DWORD error;
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !MeshInstaller_CombinePath(pattern, _countof(pattern), path, L"*")) { return FALSE; }
    search = FindFirstFileW(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE) { return GetLastError() == ERROR_FILE_NOT_FOUND; }
    do
    {
        if (wcscmp(entry.cFileName, L".") && wcscmp(entry.cFileName, L"..")) { empty = FALSE; break; }
    } while (FindNextFileW(search, &entry));
    error = GetLastError();
    FindClose(search);
    return empty && error == ERROR_NO_MORE_FILES;
}

static BOOL ServiceDeploy_TransactionPathsSafe(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx)
{
    const wchar_t* dirs[] = {paths->installDir, tx->stateDir, tx->stageDir, tx->backupDir};
    for (size_t i = 0; i < _countof(dirs); ++i)
    {
        DWORD attributes = GetFileAttributesW(dirs[i]), error = GetLastError();
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { return FALSE; }
        }
        else if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) { return FALSE; }
        else if (i == 1 && !ServiceDeploy_ValidateTransactionStateDacl(tx->stateDir))
        {
            error = GetLastError();
            if (error == ERROR_SUCCESS) { error = ERROR_ACCESS_DENIED; }
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Transaction state directory failed trust validation (%ls, error=%lu)", tx->stateDir, error);
            SetLastError(error);
            return FALSE;
        }
    }
    return TRUE;
}

static DWORD ServiceDeploy_UpdateFileMask(const ServiceUpdateTransaction* tx)
{
    return (tx->liveExeExists ? 1 : 0) | (tx->liveDllExists ? 2 : 0) |
        (tx->liveConfExists ? 4 : 0) | (tx->liveMshExists ? 8 : 0) | (tx->liveDbExists ? 16 : 0);
}

static BOOL ServiceDeploy_WriteTransactionPhase(ServiceUpdateTransaction* tx, const wchar_t* name, DWORD phase)
{
    if (!ServiceJournal_Save(tx->journalPath, name, phase, ServiceDeploy_UpdateFileMask(tx),
        tx->originalBinding, tx->originalFileDacl, tx->originalFileAttributes))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Cannot publish transaction checkpoint phase=%lu (%ls)", phase, tx->journalPath);
        return FALSE;
    }
    tx->journalPhase = phase;
    return TRUE;
}

static BOOL ServiceDeploy_ResolveUpdateTransaction(ServiceUpdateTransaction* tx, const wchar_t* name)
{
    /* Persist rollback completion before removing any recovery material. */
    if (!ServiceDeploy_WriteTransactionPhase(tx, name, SERVICE_JOURNAL_ROLLED_BACK)) { return FALSE; }
    return ServiceDeploy_DeleteUpdateTransactionArtifacts(tx);
}

/* COMMITTED is irreversible. Retry companion reconciliation before deleting
 * its journal, and report failure without restoring obsolete runtime bytes. */
static BOOL ServiceDeploy_ReconcileCommittedTransaction(const ServiceInstallPaths* paths,
    const wchar_t* name, ServiceUpdateTransaction* tx)
{
    wchar_t hostPath[MAX_PATH] = {0};
    ServiceLifecycleDiscovery state;
    BOOL ok;
    // Nothing can roll back a COMMITTED update, so a failed check must not leave the
    // service stopped: still restore its recovery policy and start it, then report failure.
    ok = ServiceDeploy_VerifyServiceHostServiceBinding(name, paths->dllPath);
    if (!ServiceDeploy_ConfigureServiceRecoveryIfEnabled(MeshConfig_GetPersistence(), name)) { ok = FALSE; }
    if (!ServiceDeploy_ReconcileServiceRecovery()) { ok = FALSE; }
    MeshService_HardenServiceDaclByName(name);
    ServiceUtil_ProtectServiceFromTermination(name);
    Security_CreateInstallRootDirectory(paths->installDir);
    Security_CreateInstallationDirectory(paths->logsDir);
    // This returns the number of aliases removed; zero is the healthy case.
    // The final lifecycle health check verifies that no aliases remain.
    (void)ServiceDeploy_CleanupConflictingServiceAliases(paths, name);
    if (!MeshRuntimeHost_GetServiceHostPathW(hostPath, _countof(hostPath)) ||
        !ServiceDeploy_RefreshFirewallRulesWithRetry(name, hostPath, paths->exePath)) { ok = FALSE; }
    // A committed backup remains until this function removes it, so the
    // pre-cleanup gate must allow that one pending artifact.
    if (!ServiceDeploy_StartServiceHostServiceAndWait(name, 30000) ||
        !ServiceDeploy_WaitForPrimaryLifecycleOperational(30000, &state)) { ok = FALSE; }
    if (ok && (state.updateStageArtifactsPresent ||
        ServiceDeploy_DataStoreValueExists(paths->dbPath, "PendingUpdate", NULL, 0, NULL)))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Committed transaction still has staged files or PendingUpdate marker");
        ok = FALSE;
    }
    if (!ok) { ServiceDeploy_LogInstallEvent(L"[UPDATE] Committed transaction retained for reconciliation (%ls)", tx->journalPath); return FALSE; }
    if (!ServiceDeploy_RetireIncumbentFiles(paths, tx->originalBinding)) { return FALSE; }
    return ServiceDeploy_DeleteUpdateTransactionArtifacts(tx);
}

static BOOL ServiceDeploy_PrepareUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL allowInstalledProvisioning, ServiceUpdateTransaction* tx)
{
    BOOL installedDbIdentityPresent = FALSE;
    DWORD attributes, error;
    if (!paths || !tx) { return FALSE; }
    if (!ServiceDeploy_InitializeUpdateTransactionPaths(paths, tx) || !ServiceDeploy_TransactionPathsSafe(paths, tx)) { return FALSE; }
    attributes = GetFileAttributesW(tx->journalPath); error = GetLastError();
    if (attributes != INVALID_FILE_ATTRIBUTES || (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) ||
        !ServiceDeploy_TransactionDirectoryEmpty(tx->backupDir))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Retained transaction requires recovery before staging (%ls)", tx->journalPath);
        return FALSE;
    }
    if (!Security_CreateInstallationDirectory(tx->stateDir) || !ServiceDeploy_ValidatePathDacl(tx->stateDir)) { return FALSE; }
    if (!ServiceDeploy_DeleteUpdateTransactionArtifacts(tx) ||
        !Security_CreateInstallationDirectory(tx->stageDir) ||
        !Security_CreateInstallationDirectory(tx->backupDir)) { return FALSE; }
    tx->stagingOwned = TRUE;

    tx->liveExeExists = ServiceDeploy_PathExists(paths->exePath);
    tx->liveDllExists = ServiceDeploy_PathExists(paths->dllPath);
    tx->liveConfExists = ServiceDeploy_PathExists(paths->confPath);
    tx->liveMshExists = ServiceDeploy_PathExists(tx->liveMshPath);
    tx->liveDbExists = ServiceDeploy_PathExists(paths->dbPath);
    installedDbIdentityPresent = ServiceDeploy_DataStoreIdentityPresent(
        g_HaveIncumbentPaths ? g_IncumbentPaths.dbPath : paths->dbPath);

    if (sourceExePath != NULL && sourceExePath[0] != L'\0')
    {
        if (!ServiceDeploy_CopyFileOverwrite(sourceExePath, tx->stagedExePath)) { return FALSE; }
        tx->stagedExeReady = TRUE;
    }

    if (sourceExePath != NULL && sourceExePath[0] != L'\0' &&
        ServiceDeploy_EnsureConfigFile(sourceExePath, tx->stagedConfPath))
    {
        tx->stagedConfReady = TRUE;
    }
    if (!tx->stagedConfReady)
    {
        if (!allowInstalledProvisioning)
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to stage a valid provisioning .conf file from package data");
            return FALSE;
        }
        if (!tx->liveConfExists || !ServiceDeploy_ConfigHasRequiredKeys(paths->confPath))
        {
            if (!installedDbIdentityPresent)
            {
                ServiceDeploy_LogInstallEvent(L"[UPDATE] Binary-only update rejected because installed provisioning .conf is unavailable or invalid (%ls)", paths->confPath);
                return FALSE;
            }
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Binary-only update retaining datastore identity without installed provisioning .conf (%ls)", paths->confPath);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Binary-only update retaining installed provisioning .conf (%ls)", paths->confPath);
        }
    }

    if (sourceExePath != NULL && sourceExePath[0] != L'\0' &&
        ServiceDeploy_EnsureMshFile(sourceExePath, tx->stagedMshPath))
    {
        tx->stagedMshReady = TRUE;
    }
    if (!tx->stagedMshReady)
    {
        if (!allowInstalledProvisioning)
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to stage a valid provisioning .msh file from package data");
            return FALSE;
        }
        if (!tx->liveMshExists || !ServiceDeploy_ConfigHasRequiredKeys(tx->liveMshPath))
        {
            if (!installedDbIdentityPresent)
            {
                ServiceDeploy_LogInstallEvent(L"[UPDATE] Binary-only update rejected because installed provisioning .msh is unavailable or invalid (%ls)", tx->liveMshPath);
                return FALSE;
            }
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Binary-only update retaining datastore identity without installed provisioning .msh (%ls)", tx->liveMshPath);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Binary-only update retaining installed provisioning .msh (%ls)", tx->liveMshPath);
        }
    }

    if (!ServiceDeploy_EnsureServiceHostDllFile(sourceExePath, sourceDllPath, tx->stagedDllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to stage a valid runtime DLL");
        return FALSE;
    }
    tx->stagedDllReady = TRUE;

    return TRUE;
}

// Keep the incumbent file DACLs/attributes even when install helpers recreate
// their destinations. Checkpoints live only in the protected state directory.
static BOOL ServiceDeploy_CaptureUpdateFileSecurity(const ServiceInstallPaths* paths, ServiceUpdateTransaction* tx)
{
    const wchar_t* files[] = {paths->exePath, paths->dllPath, paths->confPath, tx->liveMshPath, paths->dbPath};
    size_t i;
    for (i = 0; i < _countof(files); ++i)
    {
        DWORD size = 0;
        tx->originalFileAttributes[i] = GetFileAttributesW(files[i]);
        if (tx->originalFileAttributes[i] == INVALID_FILE_ATTRIBUTES)
        {
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { return FALSE; }
            continue;
        }
        if (tx->originalFileAttributes[i] & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { return FALSE; }
        GetFileSecurityW(files[i], DACL_SECURITY_INFORMATION, NULL, 0, &size);
        if (!size || size > 65536) { return FALSE; }
        tx->originalFileDacl[i] = (PSECURITY_DESCRIPTOR)malloc(size);
        if (!tx->originalFileDacl[i] || !GetFileSecurityW(files[i], DACL_SECURITY_INFORMATION, tx->originalFileDacl[i], size, &size)) { return FALSE; }
    }
    tx->liveExeExists = tx->originalFileAttributes[0] != INVALID_FILE_ATTRIBUTES;
    tx->liveDllExists = tx->originalFileAttributes[1] != INVALID_FILE_ATTRIBUTES;
    tx->liveConfExists = tx->originalFileAttributes[2] != INVALID_FILE_ATTRIBUTES;
    tx->liveMshExists = tx->originalFileAttributes[3] != INVALID_FILE_ATTRIBUTES;
    tx->liveDbExists = tx->originalFileAttributes[4] != INVALID_FILE_ATTRIBUTES;
    return TRUE;
}

static BOOL ServiceDeploy_RefreshQuiescedFileCheckpoint(const ServiceInstallPaths* paths,
    const wchar_t* name, ServiceUpdateTransaction* tx)
{
    ServiceUpdateTransaction refreshed = *tx;
    size_t i;
    ZeroMemory(refreshed.originalFileDacl, sizeof(refreshed.originalFileDacl));
    if (!ServiceDeploy_CaptureUpdateFileSecurity(paths, &refreshed) ||
        !ServiceDeploy_WriteTransactionPhase(&refreshed, name, SERVICE_JOURNAL_PREPARED))
    {
        for (i = 0; i < _countof(refreshed.originalFileDacl); ++i) { free(refreshed.originalFileDacl[i]); }
        return FALSE;
    }
    for (i = 0; i < _countof(tx->originalFileDacl); ++i) { free(tx->originalFileDacl[i]); }
    *tx = refreshed;
    return TRUE;
}

static BOOL ServiceDeploy_RestoreUpdateFileSecurity(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx)
{
    const wchar_t* files[] = {paths->exePath, paths->dllPath, paths->confPath, tx->liveMshPath, paths->dbPath};
    BOOL ok = TRUE;
    size_t i;
    for (i = 0; i < _countof(files); ++i)
    {
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        if (!tx->originalFileDacl[i]) { continue; }
        if (tx->journalPhase == SERVICE_JOURNAL_PREPARED && GetFileAttributesW(files[i]) == INVALID_FILE_ATTRIBUTES)
        {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) { continue; }
            ok = FALSE; continue;
        }
        if (!GetSecurityDescriptorControl(tx->originalFileDacl[i], &control, &revision) ||
            !SetFileSecurityW(files[i], DACL_SECURITY_INFORMATION |
                ((control & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION), tx->originalFileDacl[i]) ||
            !SetFileAttributesW(files[i], tx->originalFileAttributes[i])) { ok = FALSE; }
    }
    return ok;
}

static BOOL ServiceDeploy_ValidateQuiescedFilePresence(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx)
{
    const wchar_t* files[] = {paths->exePath, paths->dllPath, paths->confPath, tx->liveMshPath, paths->dbPath};
    DWORD originalMask = ServiceDeploy_UpdateFileMask(tx);
    for (size_t i = 0; i < _countof(files); ++i)
    {
        DWORD attributes = GetFileAttributesW(files[i]);
        BOOL exists = attributes != INVALID_FILE_ATTRIBUTES;
        if (!exists && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) { return FALSE; }
        if (exists != ((originalMask & (1UL << i)) != 0) ||
            (exists && (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] File presence changed during quiesce; preserving live files and checkpoint (%ls)", files[i]);
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL ServiceDeploy_BackupUpdateTransaction(const ServiceInstallPaths* paths, ServiceUpdateTransaction* tx)
{
    if (paths == NULL || tx == NULL) { return FALSE; }

    if (!ServiceDeploy_ValidateQuiescedFilePresence(paths, tx)) { return FALSE; }
    tx->backupDbReady = FALSE;
    tx->backupsReady = FALSE;
    tx->rollbackIdentityReady = FALSE;
    tx->postUpdateIdentityReady = FALSE;
    ZeroMemory(&tx->rollbackIdentity, sizeof(tx->rollbackIdentity));
    ZeroMemory(&tx->postUpdateIdentity, sizeof(tx->postUpdateIdentity));

    if (tx->liveExeExists && !ServiceDeploy_CopyFileOverwrite(paths->exePath, tx->backupExePath)) { return FALSE; }
    if (tx->liveDllExists && !ServiceDeploy_CopyFileOverwrite(paths->dllPath, tx->backupDllPath)) { return FALSE; }
    if (tx->liveConfExists && !ServiceDeploy_CopyFileOverwrite(paths->confPath, tx->backupConfPath)) { return FALSE; }
    if (tx->liveMshExists && !ServiceDeploy_CopyFileOverwrite(tx->liveMshPath, tx->backupMshPath)) { return FALSE; }
    if (tx->liveDbExists)
    {
        if (!ServiceDeploy_CopyFileOverwrite(paths->dbPath, tx->backupDbPath)) { return FALSE; }
        tx->backupDbReady = TRUE;
        tx->rollbackIdentityReady = ServiceDeploy_CaptureIdentitySnapshot(paths->dbPath, &tx->rollbackIdentity);
        if (tx->rollbackIdentityReady)
        {
            ServiceDeploy_LogIdentitySnapshot(L"before-update", &tx->rollbackIdentity);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[IDENTITY] before-update datastore present but no retained identity keys were available");
        }
    }
    tx->postUpdateIdentity = tx->rollbackIdentity;
    tx->postUpdateIdentityReady = tx->rollbackIdentityReady;

    {
        const wchar_t* files[] = {tx->backupExePath, tx->backupDllPath, tx->backupConfPath, tx->backupMshPath, tx->backupDbPath};
        DWORD mask = ServiceDeploy_UpdateFileMask(tx);
        for (size_t i = 0; i < _countof(files); ++i)
        {
            HANDLE file;
            BOOL flushed;
            if (!(mask & (1UL << i))) { continue; }
            if (!SetFileAttributesW(files[i], FILE_ATTRIBUTE_NORMAL)) { return FALSE; }
            file = CreateFileW(files[i], GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (file == INVALID_HANDLE_VALUE) { return FALSE; }
            flushed = FlushFileBuffers(file); CloseHandle(file);
            if (!flushed) { return FALSE; }
        }
    }
    tx->backupsReady = TRUE;
    return TRUE;
}

static BOOL ServiceDeploy_CommitUpdateTransaction(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx)
{
    if (paths == NULL || tx == NULL) { return FALSE; }

    if (tx->stagedDllReady)
    {
        if (!ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->dllPath, 60000, L"[UPDATE]") ||
            !ServiceDeploy_RemoveFileIfExistsWithTimeout(paths->dllPath, 60000, TRUE))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to remove existing runtime DLL (%ls)", paths->dllPath);
            return FALSE;
        }
        if (!Security_InstallFiles(tx->stagedDllPath, paths->dllPath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to commit staged runtime DLL to %ls", paths->dllPath);
            return FALSE;
        }
        if (!ServiceDeploy_HardenServiceHostDllDacl(paths->dllPath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to apply runtime DLL DACL to %ls", paths->dllPath);
            return FALSE;
        }
        if (!ServiceDeploy_ValidateServiceHostDll(paths->dllPath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Committed runtime DLL failed validation (%ls)", paths->dllPath);
            return FALSE;
        }
    }

    if (tx->stagedExeReady &&
        (!ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->exePath, 60000, L"[UPDATE]") ||
         !Security_InstallFiles(tx->stagedExePath, paths->exePath)))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to commit staged executable to %ls", paths->exePath);
        return FALSE;
    }

    if (paths->exePath[0] != L'\0' && GetFileAttributesW(paths->exePath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!ServiceDeploy_HardenHostExecutableDacl(paths->exePath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to apply host executable DACL to %ls", paths->exePath);
            return FALSE;
        }
    }

    if (tx->stagedConfReady && !ServiceDeploy_CopyFileOverwrite(tx->stagedConfPath, paths->confPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to commit staged config to %ls", paths->confPath);
        return FALSE;
    }

    if (tx->stagedMshReady && !ServiceDeploy_CopyFileOverwrite(tx->stagedMshPath, tx->liveMshPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to commit staged msh to %ls", tx->liveMshPath);
        return FALSE;
    }

    return TRUE;
}

/* Terminal journal phases may outlive backups. Flush every live destination
 * while the service is stopped before allowing a terminal phase to publish. */
static BOOL ServiceDeploy_FlushUpdateFiles(const ServiceInstallPaths* paths, const ServiceUpdateTransaction* tx)
{
    const wchar_t* files[] = {paths->exePath, paths->dllPath, paths->confPath, tx->liveMshPath, paths->dbPath};
    size_t i;
    for (i = 0; i < _countof(files); ++i)
    {
        DWORD attributes = GetFileAttributesW(files[i]);
        HANDLE file;
        BOOL ok;
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) { continue; }
            return FALSE;
        }
        if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { return FALSE; }
        if ((attributes & FILE_ATTRIBUTE_READONLY) && !SetFileAttributesW(files[i], attributes & ~FILE_ATTRIBUTE_READONLY)) { return FALSE; }
        file = CreateFileW(files[i], GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        ok = file != INVALID_HANDLE_VALUE && FlushFileBuffers(file);
        if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); }
        if ((attributes & FILE_ATTRIBUTE_READONLY) && !SetFileAttributesW(files[i], attributes)) { ok = FALSE; }
        if (!ok) { return FALSE; }
    }
    return TRUE;
}

static BOOL ServiceDeploy_RollbackUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* serviceKeyName, const ServiceUpdateTransaction* tx)
{
    if (paths == NULL || serviceKeyName == NULL || serviceKeyName[0] == L'\0' || tx == NULL) { return FALSE; }
    BOOL ok = TRUE;

    if (tx->liveDllExists)
    {
        ok = (ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->dllPath, 60000, L"[UPDATE][ROLLBACK]") &&
            ServiceDeploy_CopyFileOverwrite(tx->backupDllPath, paths->dllPath) && ok);
    }
    else
    {
        ok = (ServiceDeploy_RemoveFileIfExistsWithTimeout(paths->dllPath, 60000, TRUE) && ok);
    }
    if (tx->liveExeExists)
    {
        ok = (ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->exePath, 60000, L"[UPDATE][ROLLBACK]") &&
            ServiceDeploy_CopyFileOverwrite(tx->backupExePath, paths->exePath) && ok);
    }
    else
    {
        ok = (ServiceDeploy_RemoveFileIfExistsWithTimeout(paths->exePath, 60000, TRUE) && ok);
    }
    if (tx->liveConfExists)
    {
        ok = (ServiceDeploy_CopyFileOverwrite(tx->backupConfPath, paths->confPath) && ok);
    }
    else
    {
        ok = (ServiceDeploy_RemoveFileIfExistsWithTimeout(paths->confPath, 60000, TRUE) && ok);
    }
    if (tx->liveMshExists)
    {
        ok = (ServiceDeploy_CopyFileOverwrite(tx->backupMshPath, tx->liveMshPath) && ok);
    }
    else
    {
        ok = (ServiceDeploy_RemoveFileIfExistsWithTimeout(tx->liveMshPath, 60000, TRUE) && ok);
    }
    if (tx->backupDbReady)
    {
        ok = (ServiceDeploy_CopyFileOverwrite(tx->backupDbPath, paths->dbPath) && ok);
    }
    else if (!tx->liveDbExists)
    {
        ok = (ServiceDeploy_RemoveFileIfExistsWithTimeout(paths->dbPath, 60000, TRUE) && ok);
    }
    if (ok) { ok = ServiceDeploy_FlushUpdateFiles(paths, tx); }
    if (ok) { ok = ServiceDeploy_RestoreUpdateFileSecurity(paths, tx); }
    if (ok && tx->originalBinding)
    {
        ok = ServiceBinding_Restore(serviceKeyName, tx->originalBinding);
    }
    else if (ok)
    {
        ok = ServiceHost_UnregisterServiceHostService(serviceKeyName);
    }
    return ok;
}

static BOOL ServiceDeploy_WaitForExpectedIdentity(const wchar_t* dbPath, const ServiceIdentitySnapshot* expectedIdentity, DWORD timeoutMs)
{
    if (expectedIdentity == NULL) { return TRUE; }
    if (!expectedIdentity->nodeIdPresent &&
        !expectedIdentity->meshIdPresent &&
        !expectedIdentity->serverIdPresent &&
        !expectedIdentity->meshServerPresent)
    {
        return TRUE;
    }

    DWORD waited = 0;
    while (waited <= timeoutMs)
    {
        ServiceIdentitySnapshot currentIdentity;
        ZeroMemory(&currentIdentity, sizeof(currentIdentity));
        if (ServiceDeploy_CaptureIdentitySnapshot(dbPath, &currentIdentity) &&
            ServiceDeploy_IdentitySnapshotMatches(expectedIdentity, &currentIdentity))
        {
            return TRUE;
        }

        Sleep(500);
        waited += 500;
    }

    ServiceIdentitySnapshot finalIdentity;
    ZeroMemory(&finalIdentity, sizeof(finalIdentity));
    if (ServiceDeploy_CaptureIdentitySnapshot(dbPath, &finalIdentity))
    {
        ServiceDeploy_LogIdentitySnapshot(L"mismatch", &finalIdentity);
    }
    return FALSE;
}



// ================================================================
// Complete Installation Function
// ================================================================

/* The host-operation mutex covers recovery, discovery, staging and cleanup. */
static BOOL ServiceDeploy_RecoverInterruptedTransaction(void)
{
    ServiceInstallPaths paths;
    ServiceInstallPaths originalPaths;
    const ServiceInstallPaths* rollbackPaths = &paths;
    ServiceUpdateTransaction tx = {0};
    ServiceJournalRecord* record = NULL;
    wchar_t serviceName[256];
    BOOL ok = FALSE, currentExists = FALSE, legacy = FALSE;
    HANDLE recoveryStartupAuthorization = NULL;
    if (!ServiceDeploy_GetInstallPaths(&paths) || !ServiceDeploy_InitializeUpdateTransactionPaths(&paths, &tx) || !ServiceDeploy_TransactionPathsSafe(&paths, &tx)) { return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(serviceName, _countof(serviceName), NULL, 0, NULL, 0);
    if (!ServiceJournal_Load(tx.journalPath, serviceName, &record))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Unreadable or invalid retained checkpoint; preserving transaction (%ls)", tx.journalPath);
        return FALSE;
    }
    if (!record)
    {
        ok = ServiceDeploy_TransactionDirectoryEmpty(tx.backupDir);
        if (!ok) { ServiceDeploy_LogInstallEvent(L"[UPDATE] Unowned backup material requires operator recovery (%ls)", tx.backupDir); }
        return ok;
    }
    tx.journalPhase = record->phase;
    tx.originalBinding = record->binding;
    tx.liveExeExists = (record->fileMask & 1) != 0;
    tx.liveDllExists = (record->fileMask & 2) != 0;
    tx.liveConfExists = (record->fileMask & 4) != 0;
    tx.liveMshExists = (record->fileMask & 8) != 0;
    tx.liveDbExists = (record->fileMask & 16) != 0;
    for (size_t i = 0; i < 5; ++i)
    {
        tx.originalFileDacl[i] = record->dacl[i];
        tx.originalFileAttributes[i] = record->attributes[i];
        if ((record->phase == SERVICE_JOURNAL_PREPARED || ServiceJournal_PhaseRequiresBackups(record->phase)) && (record->fileMask & (1UL << i)) &&
            (!record->dacl[i] || record->attributes[i] == INVALID_FILE_ATTRIBUTES)) { goto done; }
    }
    if (record->binding && (!ServiceBinding_MigrationImageSupported(serviceName, record->binding->config, paths.exePath, paths.dllPath, &legacy) ||
        legacy != record->binding->legacy || !ServiceBinding_SharedImageSupported(record->binding, paths.dllPath)))
    {
        wchar_t originalImage[MAX_PATH];
        if (!ServiceDeploy_BindingImagePath(record->binding, originalImage, _countof(originalImage)) ||
            !ServiceBinding_MigrationImageSupported(serviceName, record->binding->config, originalImage, originalImage, &legacy) ||
            legacy != record->binding->legacy || !ServiceBinding_SharedImageSupported(record->binding, originalImage)) { goto done; }
    }
    if (tx.journalPhase == SERVICE_JOURNAL_COMMITTED)
    {
        ok = ServiceDeploy_ReconcileCommittedTransaction(&paths, serviceName, &tx);
        goto verifyCleanup;
    }
    if (tx.journalPhase == SERVICE_JOURNAL_ROLLED_BACK)
    {
        ok = ServiceDeploy_DeleteUpdateTransactionArtifacts(&tx);
        goto verifyCleanup;
    }
    if (tx.originalBinding && (tx.originalBinding->incumbentDbPath[0] || ServiceDeploy_BindingHasMovedRoot(&paths, tx.originalBinding)))
    {
        if (!ServiceDeploy_CheckpointIncumbentPaths(tx.originalBinding, &originalPaths)) { goto done; }
        if (_wcsicmp(originalPaths.dbPath, paths.dbPath))
        {
            if (!ServiceDeploy_CaptureIdentitySnapshot(originalPaths.dbPath, &tx.rollbackIdentity) || !tx.rollbackIdentity.nodeIdPresent) { goto done; }
            rollbackPaths = &originalPaths;
            tx.rollbackIdentityReady = TRUE;
        }
    }
    if (ServiceJournal_PhaseRequiresBackups(tx.journalPhase))
    {
        const wchar_t* backups[] = {tx.backupExePath, tx.backupDllPath, tx.backupConfPath, tx.backupMshPath, tx.backupDbPath};
        for (size_t i = 0; i < _countof(backups); ++i)
        {
            DWORD attributes;
            if (!(record->fileMask & (1UL << i))) { continue; }
            attributes = GetFileAttributesW(backups[i]);
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) { goto done; }
        }
        tx.backupsReady = TRUE;
        tx.backupDbReady = tx.liveDbExists;
        if (tx.backupDbReady && rollbackPaths == &paths)
        { tx.rollbackIdentityReady = ServiceDeploy_CaptureIdentitySnapshot(tx.backupDbPath, &tx.rollbackIdentity); }
    }
    if (!ServiceBinding_QueryExists(serviceName, &currentExists)) { goto done; }
    if (currentExists)
    {
        ServiceBindingSnapshot* current = ServiceBinding_Capture(serviceName, paths.exePath, paths.dllPath);
        if (!current && tx.originalBinding)
        {
            wchar_t originalImage[MAX_PATH];
            if (ServiceDeploy_BindingImagePath(tx.originalBinding, originalImage, _countof(originalImage)))
            { current = ServiceBinding_Capture(serviceName, originalImage, originalImage); }
        }
        if (!current) { goto done; }
        ServiceBinding_Free(current);
    }
    if (currentExists && (!ServiceDeploy_SuspendOriginalRestarters(&paths, tx.originalBinding) ||
        !ServiceDeploy_SuspendServiceRecoveryRestarters() ||
        !ServiceDeploy_ClearServiceRecovery(serviceName) ||
        /* PREPARED has not replaced live bytes. Match in-process rollback:
         * restore the incumbent's policy without requiring another stop. */
        ((tx.journalPhase != SERVICE_JOURNAL_PREPARED || !tx.originalBinding) &&
         !ServiceDeploy_StopServiceAndWait(serviceName, 30000, TRUE)))) { goto done; }
    if (tx.backupsReady) { ok = ServiceDeploy_RollbackUpdateTransaction(&paths, serviceName, &tx); }
    else
    {
        ok = ServiceDeploy_RestoreUpdateFileSecurity(&paths, &tx);
        if (ok && tx.originalBinding) { ok = ServiceBinding_Restore(serviceName, tx.originalBinding); }
        else if (ok && currentExists) { ok = ServiceHost_UnregisterServiceHostService(serviceName); }
    }
    if (ok && tx.originalBinding) { ok = ServiceDeploy_SetServiceStartType(serviceName, tx.originalBinding->config->dwStartType); }
    if (ok && tx.originalBinding && !ServiceDeploy_BindingHasMovedRoot(&paths, tx.originalBinding) && !ServiceDeploy_ReconcileServiceRecovery())
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Restored recovery companions require later reconciliation");
    }
    if (ok && tx.originalBinding && tx.originalBinding->running)
    {
        ok = ServiceDeploy_CreateRecoveryStartupAuthorization(&recoveryStartupAuthorization) &&
            ServiceDeploy_StartServiceHostServiceAndWait(serviceName, 30000);
        if (recoveryStartupAuthorization != NULL)
        {
            CloseHandle(recoveryStartupAuthorization);
            recoveryStartupAuthorization = NULL;
        }
    }
    if (ok && tx.rollbackIdentityReady && !ServiceDeploy_WaitForExpectedIdentity(rollbackPaths->dbPath, &tx.rollbackIdentity, 30000))
    { ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Restored service did not report its original identity in time"); }
    if (ok) { ok = ServiceDeploy_ResolveUpdateTransaction(&tx, serviceName); }
verifyCleanup:
    if (ok)
    {
        DWORD attributes = GetFileAttributesW(tx.journalPath), error = GetLastError();
        ok = attributes == INVALID_FILE_ATTRIBUTES && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
    }
done:
    if (recoveryStartupAuthorization != NULL) { CloseHandle(recoveryStartupAuthorization); }
    ServiceDeploy_LogInstallEvent(L"[UPDATE] Interrupted transaction recovery %ls (phase=%lu)", ok ? L"completed" : L"retained for retry", record->phase);
    ServiceJournal_Free(record);
    return ok;
}

static BOOL ServiceDeploy_ApplyUpdateFlow(
    const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL requireConfig);

static BOOL ServiceDeploy_ApplyInstallFlow(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath)
{
    /* Installation and repair use the same staged transaction as updates.
     * A complete package is required; no alternate EXE-service repair path exists. */
    return ServiceDeploy_ApplyUpdateFlow(sourceExePath, sourceDllPath, TRUE);
}

static BOOL ServiceDeploy_ApplyRepairFlow(const wchar_t* sourceExePath, const wchar_t* sourceDllPath)
{
    ServiceInstallPaths paths;
    ServiceLifecycleDiscovery finalState;

    if (!ServiceDeploy_ApplyInstallFlow(sourceExePath, sourceDllPath))
    {
        return FALSE;
    }

    if (!ServiceDeploy_GetInstallPaths(&paths))
    {
        ServiceDeploy_LogInstallEvent(L"[REPAIR] Failed to resolve install paths after repair install");
        return FALSE;
    }

    if (!ServiceDeploy_WaitForPrimaryLifecycleHealthy(30000, &finalState))
    {
        ServiceDeploy_LogInstallEvent(
            L"[REPAIR] Post-repair discovery did not converge to healthy state (state=%ls pending=%u stageArtifacts=%u backupArtifacts=%u firewall=%u persistence=%u)",
            ServiceDeploy_LifecycleStateToString(finalState.stateKind),
            finalState.pendingUpdate,
            finalState.updateStageArtifactsPresent,
            finalState.updateBackupArtifactsPresent,
            finalState.firewallHealthy,
            finalState.persistenceHealthy);
        return FALSE;
    }

    return TRUE;
}

static const wchar_t* MeshInstaller_GetPathLeaf(const wchar_t* path)
{
    const wchar_t* leaf = NULL;
    if (path == NULL || path[0] == L'\0') { return NULL; }

    leaf = wcsrchr(path, L'\\');
    if (leaf == NULL)
    {
        leaf = wcsrchr(path, L'/');
    }

    return (leaf != NULL && leaf[1] != L'\0') ? (leaf + 1) : path;
}

// ================================================================
// Uninstallation
// ================================================================

static BOOL ServiceDeploy_ApplyUninstallFlow(void)
{
    ServiceInstallPaths paths;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    BOOL success = TRUE;
    wchar_t legacyServiceHostPath[MAX_PATH] = {0};
    wchar_t stateDatPath[MAX_PATH] = {0};
    wchar_t stateDirPath[MAX_PATH] = {0};
    wchar_t controlLogPath[MAX_PATH] = {0};
    wchar_t legacyServiceHostDebugPath[MAX_PATH] = {0};

    ServiceDeploy_ResolveRuntimeServiceBranding(
        serviceKeyName,
        _countof(serviceKeyName),
        serviceDisplayName,
        _countof(serviceDisplayName),
        NULL,
        0);

    ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-Uninstall.log");
    ServiceDeploy_LogInstallEvent(L"Beginning complete uninstallation for %ls", serviceKeyName);

    // Get paths
    ServiceDeploy_GetInstallPaths(&paths);
    if (g_IncumbentPaths.dbPath[0])
    {
        ServiceBindingSnapshot* original = ServiceBinding_Capture(serviceKeyName,
            g_IncumbentPaths.exePath[0] ? g_IncumbentPaths.exePath : paths.exePath,
            g_IncumbentPaths.dllPath[0] ? g_IncumbentPaths.dllPath : paths.dllPath);
        if (!original) { return FALSE; }
        BOOL suspended = ServiceDeploy_SuspendOriginalRestarters(&paths, original);
        ServiceBinding_Free(original);
        if (!suspended) { return FALSE; }
    }
    {
        size_t removedAliases = ServiceDeploy_CleanupConflictingServiceAliases(&paths, serviceKeyName);
        if (removedAliases > 0)
        {
            ServiceDeploy_LogInstallEvent(L"[ALIAS] Removed %Iu conflicting service alias(es) before uninstall", removedAliases);
        }
    }
    // Disable recovery and remove restart triggers before stopping
    ServiceDeploy_ClearServiceRecovery(serviceKeyName);
    ServiceDeploy_RemoveRunKeyEntry(serviceKeyName);
    ServiceDeploy_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);

    // Stop and terminate service/host processes
    ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, TRUE);
    ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);
    ServiceDeploy_TerminateProcessesByPath(paths.exePath);

    if (g_IncumbentPaths.dbPath[0])
    {
        if (!ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, TRUE)) { return FALSE; }
        ServiceDeploy_ReleaseRuntimeFiles(&g_IncumbentPaths, TRUE);
        /* Keep the database as ownership evidence until SCM deletion succeeds. */
        if (!ServiceDeploy_RemoveIncumbentFiles(&g_IncumbentPaths, &paths, FALSE)) { return FALSE; }
    }

    // Clean up any persistence artifacts that may have been recreated during shutdown
    ServiceDeploy_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);
    ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, TRUE);
    ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);
    ServiceDeploy_TerminateProcessesByPath(paths.exePath);

    if (!ServiceHost_UnregisterServiceHostService(serviceKeyName))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to unregister service %ls", serviceKeyName);
        success = FALSE;
    }
    else if (!ServiceDeploy_WaitForServiceAbsence(serviceKeyName, 30000))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Service removal did not converge within timeout for %ls", serviceKeyName);
        success = FALSE;
    }
    if (g_IncumbentPaths.dbPath[0] &&
        (!success || !ServiceDeploy_RemoveIncumbentFiles(&g_IncumbentPaths, &paths, TRUE))) { return FALSE; }

    // Remove firewall rules
    if (!Security_RemoveFirewallRuleForService(serviceKeyName))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove firewall rules for %ls", serviceKeyName);
        success = FALSE;
    }
    if (!ServiceDeploy_DeleteServiceStateRegistryTree(serviceKeyName))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove service state registry tree for %ls", serviceKeyName);
        success = FALSE;
    }
    if (!Security_RemoveFirewallRulesByExePath(paths.exePath))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove firewall rules for %ls", paths.exePath);
        success = FALSE;
    }

    // Delete files (best-effort)
    if (!ServiceDeploy_RemoveFileIfExists(paths.dbPath, TRUE)) { success = FALSE; }
    // Do not recreate the installation directory while uninstall deletes its audit log.
    InterlockedExchange(&g_MeshDiagnosticLogDisabled, 1);
    if (!ServiceDeploy_RemoveFileIfExists(paths.logPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(paths.confPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(paths.exePath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(paths.dllPath, TRUE)) { success = FALSE; }

    MeshInstaller_CombinePath(legacyServiceHostPath, _countof(legacyServiceHostPath), paths.installDir, L"svchost.exe");
    MeshInstaller_CombinePath(stateDatPath, _countof(stateDatPath), paths.installDir, L"state.dat");
    MeshInstaller_CombinePath(stateDirPath, _countof(stateDirPath), paths.installDir, L"state");
    MeshInstaller_CombinePath(controlLogPath, _countof(controlLogPath), paths.installDir, L"controlchannel-debug.log");
    MeshInstaller_CombinePath(legacyServiceHostDebugPath, _countof(legacyServiceHostDebugPath), paths.installDir, L"svchost-debug.log");

    if (!Security_RemoveFirewallRulesByExePath(legacyServiceHostPath))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove firewall rules for %ls", legacyServiceHostPath);
        success = FALSE;
    }

    if (!ServiceDeploy_RemoveFileIfExists(controlLogPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(legacyServiceHostDebugPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(stateDatPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(legacyServiceHostPath, TRUE)) { success = FALSE; }

    if (!ServiceDeploy_RemoveDirectoryTree(stateDirPath, TRUE)) { success = FALSE; }

    /* Other installations have their own identities. The selected SCM binding
     * supplies the only historical files this uninstall may remove. */

    ServiceDeploy_LogInstallEvent(L"Complete uninstallation finished for %ls", serviceKeyName);

    ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-Uninstall.log");
    if (!ServiceDeploy_RemoveDirectoryTree(paths.logsDir, TRUE))
    {
        success = FALSE;
    }
    if (!ServiceDeploy_RemoveDirectoryTree(paths.installDir, TRUE))
    {
        Sleep(500);
        if (!ServiceDeploy_RemoveDirectoryTree(paths.installDir, TRUE))
        {
            success = FALSE;
        }
    }

    {
        ServiceLifecycleDiscovery finalState;
        ZeroMemory(&finalState, sizeof(finalState));
        if (ServiceDeploy_DiscoverCurrentState(&finalState) &&
            finalState.stateKind == SERVICE_LIFECYCLE_STATE_CLEAN)
        {
            if (!success)
            {
                ServiceDeploy_LogInstallEvent(L"Uninstall cleanup warnings were resolved by final clean-state discovery for %ls", serviceKeyName);
            }
            success = TRUE;
        }
        else
        {
            ServiceDeploy_LogInstallEvent(
                L"[WARN] Uninstall did not converge to clean state for %ls (state=%ls service=%u exe=%u dll=%u conf=%u db=%u firewall=%u persistence=%u)",
                serviceKeyName,
                ServiceDeploy_LifecycleStateToString(finalState.stateKind),
                finalState.serviceExists,
                finalState.exeExists,
                finalState.dllExists,
                finalState.confExists,
                finalState.dbExists,
                finalState.firewallRulePresent,
                finalState.anyPersistenceArtifacts);
            success = FALSE;
        }
    }

    return success;
}

// ================================================================
// Update (in-place repair/update without full uninstall)
// ================================================================

// SCM reports STOPPED before the service process has unmapped the runtime DLL, and
// helpers started from that DLL can outlive the service. Stop them (unless they share
// a host process with other services), then wait until the DLL can be written.
static void ServiceDeploy_ReleaseRuntimeFiles(const ServiceInstallPaths* paths, BOOL terminateHolders)
{
    if (terminateHolders)
    {
        ServiceDeploy_TerminateProcessesByLoadedModulePath(paths->dllPath);
        ServiceDeploy_TerminateProcessesByPath(paths->exePath);
    }
    if (paths->dllPath[0] != L'\0' && GetFileAttributesW(paths->dllPath) != INVALID_FILE_ATTRIBUTES)
    {
        DWORD lockWaitStart = GetTickCount();
        while ((GetTickCount() - lockWaitStart) < 10000)
        {
            HANDLE hTest = CreateFileW(paths->dllPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hTest != INVALID_HANDLE_VALUE)
            {
                CloseHandle(hTest);
                break;
            }
            DWORD lockErr = GetLastError();
            if (lockErr != ERROR_SHARING_VIOLATION && lockErr != ERROR_LOCK_VIOLATION) { break; }
            Sleep(250);
        }
    }
}

static BOOL ServiceDeploy_ApplyUpdateFlow(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL requireConfig)
{
    InterlockedExchange(&g_MeshDiagnosticLogDisabled, 0);
    ServiceInstallPaths paths;
    BOOL success = TRUE;
    BOOL restartService = TRUE;
    BOOL serviceExists = FALSE;
    BOOL serviceWasRunning = FALSE;
    BOOL rollbackCompleted = FALSE;
    DWORD operationError = ERROR_SUCCESS;
    HANDLE rollbackStartupAuthorization = NULL;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    wchar_t liveMshPath[MAX_PATH] = {0};
    ServiceUpdateTransaction tx;
    ServicePackagePreflight preflight;
    wchar_t preflightReason[512] = {0};
    BOOL allowInstalledProvisioning = FALSE;
    ZeroMemory(&tx, sizeof(tx));

    ServiceDeploy_ResolveRuntimeServiceBranding(
        serviceKeyName,
        _countof(serviceKeyName),
        serviceDisplayName,
        _countof(serviceDisplayName),
        NULL,
        0);

    ServiceDeploy_LogInstallEvent(L"[UPDATE] Starting update for %ls", serviceKeyName);

    if (!ServiceDeploy_GetInstallPaths(&paths))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to resolve install paths");
        return FALSE;
    }

    if (!ServiceBinding_QueryExists(serviceKeyName, &serviceExists))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to inspect incumbent service; aborting before mutation");
        return FALSE;
    }
    serviceWasRunning = serviceExists && ServiceDeploy_ServiceIsRunning(serviceKeyName);

    ZeroMemory(&preflight, sizeof(preflight));
    if (!ServiceDeploy_PreflightPackageSource(sourceExePath, requireConfig || !serviceExists, &preflight, preflightReason, _countof(preflightReason)))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Package preflight failed: %ls", preflightReason);
        return FALSE;
    }
    allowInstalledProvisioning = !preflight.configAvailable;
    ServiceDeploy_LogInstallEvent(
        L"[UPDATE] Package preflight passed (embeddedProvisioning=%u sidecarProvisioning=%u manifestRequireConfig=%u allowInstalledProvisioning=%u)",
        preflight.sourceEmbeddedConfigPresent,
        preflight.sourceSidecarConfigPresent,
        requireConfig,
        allowInstalledProvisioning);
    if (allowInstalledProvisioning)
    {
        if (!ServiceDeploy_InstalledProvisioningHealthy(g_HaveIncumbentPaths ? &g_IncumbentPaths : &paths, liveMshPath, _countof(liveMshPath)))
        {
            ServiceDeploy_LogInstallEvent(
                L"[UPDATE] Binary-only update rejected because installed provisioning identity is not healthy (conf=%ls msh=%ls)",
                paths.confPath,
                liveMshPath);
            return FALSE;
        }
        ServiceDeploy_LogInstallEvent(
            L"[UPDATE] Binary-only update retaining installed provisioning identity (conf=%ls msh=%ls)",
            paths.confPath,
            liveMshPath);
    }
    if (sourceDllPath != NULL && sourceDllPath[0] != L'\0' && !ServiceDeploy_ValidateServiceHostDll(sourceDllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Package preflight failed: invalid runtime DLL source (%ls)", sourceDllPath);
        return FALSE;
    }

    if (serviceExists)
    {
        tx.originalBinding = ServiceBinding_Capture(serviceKeyName,
            g_IncumbentPaths.exePath[0] ? g_IncumbentPaths.exePath : paths.exePath,
            g_IncumbentPaths.dllPath[0] ? g_IncumbentPaths.dllPath : paths.dllPath);
        if (!tx.originalBinding)
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Cannot preserve incumbent configuration; requires LocalSystem, a stable Win32 service and managed legacy EXE path. Aborting before quiesce");
            return FALSE;
        }
        StringCchCopyW(tx.originalBinding->incumbentExePath, _countof(tx.originalBinding->incumbentExePath), g_IncumbentPaths.exePath);
        StringCchCopyW(tx.originalBinding->incumbentDllPath, _countof(tx.originalBinding->incumbentDllPath), g_IncumbentPaths.dllPath);
        StringCchCopyW(tx.originalBinding->incumbentDbPath, _countof(tx.originalBinding->incumbentDbPath), g_IncumbentPaths.dbPath);
        serviceWasRunning = tx.originalBinding->running;
    }

    ServiceDeploy_ImportWinHttpProxyFromIeBestEffort();

    if (!ServiceDeploy_PathExists(paths.installDir)) { Security_CreateInstallRootDirectory(paths.installDir); }
    if (!ServiceDeploy_PathExists(paths.logsDir)) { Security_CreateInstallationDirectory(paths.logsDir); }

    if (!ServiceDeploy_PrepareUpdateTransaction(&paths, sourceExePath, sourceDllPath, allowInstalledProvisioning, &tx))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to prepare staged update transaction");
        // Only material this call staged may be removed: a refusal over a retained
        // journal or backup set must leave that rollback material for recovery.
        if (tx.stagingOwned && !ServiceDeploy_DeleteUpdateTransactionArtifacts(&tx))
        { ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Failed to remove incomplete staged update material"); }
        ServiceBinding_Free(tx.originalBinding);
        return FALSE;
    }


    if (!ServiceDeploy_CaptureUpdateFileSecurity(&paths, &tx) ||
        !ServiceDeploy_WriteTransactionPhase(&tx, serviceKeyName, SERVICE_JOURNAL_PREPARED))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Cannot checkpoint original file security; aborting before quiesce");
        ServiceDeploy_DeleteUpdateTransactionArtifacts(&tx);
        ServiceBinding_Free(tx.originalBinding);
        for (size_t i = 0; i < _countof(tx.originalFileDacl); ++i) { free(tx.originalFileDacl[i]); }
        return FALSE;
    }

    // Keep the original start type intact so a reboot can invoke startup repair.
    // Recovery actions are suspended while the checkpointed files are in flight;
    // any task/monitor start is rejected by the service startup disposition gate.
    DWORD originalStartType = serviceExists ? tx.originalBinding->config->dwStartType : SERVICE_AUTO_START;
    if (serviceExists && (!ServiceDeploy_SuspendOriginalRestarters(&paths, tx.originalBinding) ||
        !ServiceDeploy_SuspendServiceRecoveryRestarters() ||
        !ServiceDeploy_ClearServiceRecovery(serviceKeyName)))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to suspend incumbent launches before quiesce");
        success = FALSE;
        goto CLEANUP;
    }

    /* Recheck copied-host ownership after suspending restarters, immediately
     * before control. No registry normalization or shared-host kill is allowed. */
    wchar_t copiedHost[MAX_PATH];
    if (serviceExists && ServiceLegacyHost_ParseImage(tx.originalBinding->config->lpBinaryPathName,
        g_IncumbentPaths.dllPath[0] ? g_IncumbentPaths.dllPath : paths.dllPath, copiedHost, _countof(copiedHost)) &&
        !ServiceLegacyHost_ProcessSafe(serviceKeyName, copiedHost))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Copied legacy host process ownership changed; aborting before stop");
        success = FALSE;
        goto CLEANUP;
    }
    if (serviceExists && !ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, TRUE))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Service did not stop; retaining original checkpoint");
        success = FALSE;
        goto CLEANUP;
    }
    ServiceDeploy_ReleaseRuntimeFiles(&paths, TRUE);
    if (g_HaveIncumbentPaths) { ServiceDeploy_ReleaseRuntimeFiles(&g_IncumbentPaths, TRUE); }

    if (!ServiceDeploy_RefreshQuiescedFileCheckpoint(&paths, serviceKeyName, &tx) ||
        !ServiceDeploy_BackupUpdateTransaction(&paths, &tx))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to capture quiesced rollback set");
        success = FALSE;
        goto CLEANUP;
    }
    if (!ServiceDeploy_WriteTransactionPhase(&tx, serviceKeyName, SERVICE_JOURNAL_BACKED_UP))
    {
        tx.backupsReady = FALSE; /* Published PREPARED still guarantees unchanged live bytes. */
        success = FALSE;
        goto CLEANUP;
    }
    if (g_HaveIncumbentPaths)
    {
        /* BACKED_UP records whether the destination DB originally existed.
         * A crash during this copy rolls the destination back or removes it;
         * the stopped incumbent's database remains entirely unchanged. */
        if (!ServiceDeploy_CaptureIdentitySnapshot(g_IncumbentPaths.dbPath, &tx.rollbackIdentity) ||
            !tx.rollbackIdentity.nodeIdPresent ||
            !ServiceDeploy_CopyFileOverwrite(g_IncumbentPaths.dbPath, paths.dbPath) ||
            !ServiceDeploy_WaitForExpectedIdentity(paths.dbPath, &tx.rollbackIdentity, 0))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to preserve historical database; restoring incumbent binding");
            success = FALSE;
            goto CLEANUP;
        }
        tx.rollbackIdentityReady = TRUE;
        tx.postUpdateIdentity = tx.rollbackIdentity;
        tx.postUpdateIdentityReady = TRUE;
    }
    /* A registration without an identity DB stays repairable; an existing DB
     * must carry a NodeID so activation never replaces it with a fresh one. */
    if (serviceExists && (tx.liveDbExists || g_HaveIncumbentPaths) &&
        (!tx.rollbackIdentityReady || !tx.rollbackIdentity.nodeIdPresent))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Existing service has no verified NodeID; refusing fresh identity activation");
        success = FALSE;
        goto CLEANUP;
    }
    if (!allowInstalledProvisioning)
    {
        const wchar_t* expectedProvisioningPath = tx.stagedMshReady ? tx.stagedMshPath : tx.stagedConfPath;
        if (!ServiceDeploy_DerivePostUpdateIdentity(&tx, expectedProvisioningPath, &tx.postUpdateIdentity))
        {
            ServiceDeploy_LogInstallEvent(
                L"[UPDATE] Failed to derive expected post-update package identity from staged provisioning (%ls, error=%lu)",
                expectedProvisioningPath != NULL ? expectedProvisioningPath : L"(missing)",
                GetLastError());
            success = FALSE;
            goto CLEANUP;
        }
        tx.postUpdateIdentityReady = TRUE;
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Package-driven update preserving NodeID while adopting staged provisioning identity");
        ServiceDeploy_LogIdentitySnapshot(L"expected-after-package-update", &tx.postUpdateIdentity);
    }
    if (tx.liveDbExists)
    {
        if (!ServiceDeploy_DataStorePutValue(paths.dbPath, "PendingUpdate", "1", 1))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to mark PendingUpdate before commit");
            success = FALSE;
            goto CLEANUP;
        }
        tx.pendingUpdateMarked = TRUE;
        ServiceDeploy_LogInstallEvent(L"[UPDATE] PendingUpdate marker written prior to commit");
    }

    if (!ServiceDeploy_CommitUpdateTransaction(&paths, &tx))
    {
        success = FALSE;
        goto CLEANUP;
    }

    if (!ServiceHost_RegisterServiceHostService(serviceKeyName, paths.dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] ServiceHost registration failed for %ls (error=%lu)", serviceKeyName, GetLastError());
        success = FALSE;
        goto CLEANUP;
    }
    if (!ServiceDeploy_VerifyServiceHostServiceBinding(serviceKeyName, paths.dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] ServiceHost binding verification failed for %ls", serviceKeyName);
        success = FALSE;
        goto CLEANUP;
    }
    ServiceDeploy_RecordServiceDllHash(serviceKeyName, paths.dllPath);

CLEANUP:
    if (success && !ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_AUTO_START))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Failed to restore service auto-start during cleanup (%ls, error=%lu)", serviceKeyName, GetLastError());
        success = FALSE;
    }
    // The service owns the datastore with a non-shareable writer once started.
    // Clear successful-activation markers while the service is still stopped.
    if (success)
    {
        ServiceDeploy_ClearUpdateActivationHolds(&paths, L"[UPDATE]");
        if (!ServiceDeploy_FinalizeUpdateTransaction(&paths, &tx))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Transaction cleanup incomplete before service restart; retaining rollback capability");
            success = FALSE;
        }
    }

    if (success && !ServiceDeploy_WriteTransactionPhase(&tx, serviceKeyName, SERVICE_JOURNAL_ACTIVATING))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to publish activation-ready checkpoint");
        success = FALSE;
    }

    // Never start a partially committed package; the failure path restores the incumbent first.
    if (success && restartService)
    {
        if (!ServiceDeploy_StartServiceHostServiceAndWait(serviceKeyName, 30000))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Service failed to reach RUNNING state after update for %ls", serviceKeyName);
            success = FALSE;
        }
    }

    if (success)
    {
        ServiceLifecycleDiscovery finalState;
        if (!ServiceDeploy_WaitForTransactionActivation(30000, &finalState))
        {
            ServiceDeploy_LogInstallEvent(
                L"[UPDATE] Post-update primary lifecycle did not converge before transaction cleanup (state=%ls pending=%u stageArtifacts=%u backupArtifacts=%u firewall=%u persistence=%u)",
                ServiceDeploy_LifecycleStateToString(finalState.stateKind),
                finalState.pendingUpdate,
                finalState.updateStageArtifactsPresent,
                finalState.updateBackupArtifactsPresent,
                finalState.firewallHealthy,
                finalState.persistenceHealthy);
            success = FALSE;
        }
        else if (!tx.postUpdateIdentityReady ||
                 !ServiceDeploy_WaitForExpectedIdentity(paths.dbPath, &tx.postUpdateIdentity, 30000))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Identity preservation check failed after update");
            success = FALSE;
        }
        else if (!ServiceDeploy_WaitForTransactionActivation(30000, &finalState))
        {
            ServiceDeploy_LogInstallEvent(
                L"[UPDATE] Post-update primary lifecycle stopped being operational after transaction cleanup (state=%ls pending=%u stageArtifacts=%u backupArtifacts=%u firewall=%u persistence=%u)",
                ServiceDeploy_LifecycleStateToString(finalState.stateKind),
                finalState.pendingUpdate,
                finalState.updateStageArtifactsPresent,
                finalState.updateBackupArtifactsPresent,
                finalState.firewallHealthy,
                finalState.persistenceHealthy);
            success = FALSE;
        }
        else
        {
            // The activated service re-created its event-driven restarters at startup.
            // This stop is intentional, so suspend them first; committed reconciliation
            // restores them (and the SCM failure actions) after the flush.
            BOOL activatedServiceStopped = ServiceDeploy_SuspendServiceRecoveryRestarters() &&
                ServiceDeploy_ClearServiceRecovery(serviceKeyName) &&
                ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, FALSE);
            if (activatedServiceStopped) { ServiceDeploy_ReleaseRuntimeFiles(&paths, TRUE); }
            if (!activatedServiceStopped ||
                !ServiceDeploy_FlushUpdateFiles(&paths, &tx) ||
                !ServiceDeploy_WriteTransactionPhase(&tx, serviceKeyName, SERVICE_JOURNAL_COMMITTED))
            {
                success = FALSE;
                goto ROLLBACK;
            }
            success = ServiceDeploy_ReconcileCommittedTransaction(&paths, serviceKeyName, &tx);
        }
    }

ROLLBACK:
    /* Keep the activation error (for example SCM error 193), not a registry
     * or filesystem result produced while restoring the original package. */
    if (!success) { operationError = GetLastError(); }
    if (!success && tx.journalPhase != SERVICE_JOURNAL_COMMITTED)
    {
        BOOL rollbackOk = TRUE;
        BOOL currentExists = FALSE;
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Restoring original transaction state for %ls", serviceKeyName);
        rollbackOk = ServiceBinding_QueryExists(serviceKeyName, &currentExists);
        /* PREPARED has not replaced any live bytes. A first stop failure may
         * leave the incumbent running, so do not make recovery depend on a
         * second stop before restoring its original SCM policy. */
        if (rollbackOk && currentExists && tx.journalPhase != SERVICE_JOURNAL_PREPARED)
        {
            rollbackOk = ServiceDeploy_ClearServiceRecovery(serviceKeyName) &&
                ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, TRUE);
        }
        if (rollbackOk && tx.backupsReady)
        {
            rollbackOk = ServiceDeploy_RollbackUpdateTransaction(&paths, serviceKeyName, &tx);
        }
        else if (rollbackOk)
        {
            rollbackOk = ServiceDeploy_RestoreUpdateFileSecurity(&paths, &tx);
            if (rollbackOk && tx.originalBinding) { rollbackOk = ServiceBinding_Restore(serviceKeyName, tx.originalBinding); }
            else if (rollbackOk && currentExists) { rollbackOk = ServiceHost_UnregisterServiceHostService(serviceKeyName); }
        }
        if (rollbackOk && tx.backupsReady)
        {
            rollbackOk = ServiceDeploy_FlushUpdateFiles(&paths, &tx);
        }
        if (rollbackOk && tx.originalBinding && !ServiceDeploy_BindingHasMovedRoot(&paths, tx.originalBinding) && !ServiceDeploy_ReconcileServiceRecovery())
        { ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Restored recovery companions require later reconciliation"); }
        // The checkpoint is still in flight and this operation holds the lifecycle
        // mutex, so the restored service's startup gate would quiesce it. Authorize
        // this one start the same way interrupted-transaction recovery does.
        if (rollbackOk && serviceWasRunning)
        {
            rollbackOk = ServiceDeploy_CreateRecoveryStartupAuthorization(&rollbackStartupAuthorization) &&
                ServiceDeploy_StartServiceHostServiceAndWait(serviceKeyName, 30000);
            if (rollbackStartupAuthorization != NULL)
            {
                CloseHandle(rollbackStartupAuthorization);
                rollbackStartupAuthorization = NULL;
            }
        }
        if (rollbackOk && serviceExists) { rollbackOk = ServiceDeploy_SetServiceStartType(serviceKeyName, originalStartType); }
        // The restored files are flushed and the service runs them. Keeping the checkpoint
        // because the identity check timed out would let a later operation restore this
        // backup again, over whatever the agent has written since.
        if (rollbackOk && tx.rollbackIdentityReady && !ServiceDeploy_WaitForExpectedIdentity(
            g_HaveIncumbentPaths ? g_IncumbentPaths.dbPath : paths.dbPath, &tx.rollbackIdentity, 30000))
        { ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Restored service did not report its original identity in time"); }
        if (rollbackOk) { rollbackOk = ServiceDeploy_ResolveUpdateTransaction(&tx, serviceKeyName); }
        rollbackCompleted = rollbackOk;
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Rollback %ls for %ls", rollbackOk ? L"completed" : L"failed", serviceKeyName);
    }

    if (success)
    {
        // Safe after the commit point; this is a best-effort sweep only.
        ServiceDeploy_DeleteUpdateTransactionArtifacts(&tx);
        ServiceDeploy_RemoveInactiveServiceHostDlls(&paths);
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Update completed for %ls", serviceKeyName);
    }
    else
    {
        if (rollbackCompleted)
        {
            ServiceDeploy_DeleteUpdateTransactionArtifacts(&tx);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Preserving transaction artifacts after failed rollback (%ls)", tx.backupDir);
        }
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Update failed for %ls", serviceKeyName);
    }
    ServiceBinding_Free(tx.originalBinding);
    for (size_t i = 0; i < _countof(tx.originalFileDacl); ++i) { free(tx.originalFileDacl[i]); }
    if (!success) { SetLastError(operationError); }
    return success;
}

// ================================================================
// Silent Installation Check
// ================================================================

BOOL ServiceDeploy_IsAlreadyInstalled(void)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL installed = FALSE;
    wchar_t serviceKeyName[256] = {0};

    ServiceDeploy_ResolveRuntimeServiceBranding(
        serviceKeyName,
        _countof(serviceKeyName),
        NULL,
        0,
        NULL,
        0);

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        hService = OpenServiceW(hSCM, serviceKeyName, SERVICE_QUERY_STATUS);
        if (hService)
        {
            installed = TRUE;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    return installed;
}

typedef struct ServiceValidationSummary
{
    wchar_t serviceName[256], installedExePath[MAX_PATH], installedDllPath[MAX_PATH];
    const char* phase;
    BOOL success;
    BOOL installRoot;
    BOOL logsRoot;
    BOOL installRootDacl;
    BOOL logsRootDacl;
    BOOL installerLog;
    BOOL exePresent;
    BOOL exeDacl;
    BOOL dllPresent;
    BOOL dllDacl;
    BOOL configPresent;
    BOOL configKeys;
    BOOL serviceExists;
    BOOL serviceType;
    BOOL serviceStart;
    BOOL serviceImagePath;

    BOOL serviceAccount;
    BOOL serviceDll;

    BOOL serviceDllHash;
    BOOL serviceDacl;
    BOOL serviceAliasClean;
    BOOL serviceRunning;
    BOOL firewallRule;
    BOOL serviceRecoveryState;
    BOOL autorunTask;
    BOOL recoveryTask;
    BOOL recoveryMonitor;
    BOOL runKey;
    BOOL pendingUpdateClear;
} ServiceValidationSummary;

static BOOL ServiceDeploy_PathExists(const wchar_t* path)
{
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES);
}

static BOOL ServiceDeploy_ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName,
                                       wchar_t* buffer, size_t bufferCch, DWORD* valueType)
{
    if (buffer == NULL || bufferCch == 0) { return FALSE; }
    buffer[0] = L'\0';

    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = (DWORD)(bufferCch * sizeof(wchar_t));
    LONG status = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buffer, &cb);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
    {
        buffer[0] = L'\0';
        return FALSE;
    }

    if (valueType) { *valueType = type; }
    buffer[bufferCch - 1] = L'\0';
    return TRUE;
}

static BOOL ServiceDeploy_ReadRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, DWORD* valueOut)
{
    if (valueOut == NULL) { return FALSE; }
    *valueOut = 0;

    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = sizeof(DWORD);
    LONG status = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)valueOut, &cb);
    RegCloseKey(hKey);

    return (status == ERROR_SUCCESS && type == REG_DWORD);
}

static BOOL ServiceDeploy_ServiceIsRunning(const wchar_t* serviceName)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    BOOL running = FALSE;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) { return FALSE; }
    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
    if (svc != NULL)
    {
        SERVICE_STATUS_PROCESS ssp = {0};
        DWORD bytes = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes))
        {
            running = (ssp.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

static BOOL ServiceDeploy_RunKeyValueExists(const wchar_t* valueName, wchar_t* valueOut, size_t valueOutCch)
{
    if (valueOut && valueOutCch > 0) { valueOut[0] = L'\0'; }
    if (valueName == NULL || valueName[0] == L'\0') { return FALSE; }
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD type = 0;
    DWORD cb = (DWORD)(valueOut && valueOutCch > 0 ? valueOutCch * sizeof(wchar_t) : 0);
    LONG status = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)valueOut, &cb);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        if (valueOut && valueOutCch > 0) { valueOut[0] = L'\0'; }
        return FALSE;
    }
    if (valueOut && valueOutCch > 0) { valueOut[valueOutCch - 1] = L'\0'; }
    return TRUE;
}

// Mirrors IsSafeServiceName in fault_recovery.cpp: a name embedded in a quoted
// command line must not carry quotes or line breaks and must fit SCM's limit.
static BOOL ServiceDeploy_IsSafeServiceName(const wchar_t* serviceName)
{
    return serviceName != NULL && serviceName[0] != L'\0' && wcslen(serviceName) <= 255 &&
        wcspbrk(serviceName, L"\"\r\n") == NULL;
}

static BOOL ServiceDeploy_RunKeyMatchesService(const wchar_t* serviceName)
{
    if (!ServiceDeploy_IsSafeServiceName(serviceName)) { return FALSE; }
    wchar_t systemDirectory[MAX_PATH] = {0};
    const UINT systemDirectoryLength = GetSystemDirectoryW(systemDirectory, _countof(systemDirectory));
    wchar_t expected[512] = {0};
    wchar_t actual[512] = {0};
    if (systemDirectoryLength == 0 || systemDirectoryLength >= _countof(systemDirectory) ||
        FAILED(StringCchPrintfW(expected, _countof(expected),
            L"\"%ls\\sc.exe\" start \"%ls\"", systemDirectory, serviceName)))
    {
        return FALSE;
    }
    return ServiceDeploy_RunKeyValueExists(serviceName, actual, _countof(actual)) &&
        wcscmp(actual, expected) == 0;
}

static BOOL ServiceDeploy_AclMatchesExpected(PACL actualDacl, PACL expectedDacl)
{
    if (actualDacl == NULL || expectedDacl == NULL) { return FALSE; }

    ACL_SIZE_INFORMATION actualInfo = {0};
    ACL_SIZE_INFORMATION expectedInfo = {0};
    if (!GetAclInformation(actualDacl, &actualInfo, sizeof(actualInfo), AclSizeInformation)) { return FALSE; }
    if (!GetAclInformation(expectedDacl, &expectedInfo, sizeof(expectedInfo), AclSizeInformation)) { return FALSE; }
    if (actualInfo.AceCount != expectedInfo.AceCount) { return FALSE; }

    for (DWORD i = 0; i < expectedInfo.AceCount; ++i)
    {
        void* expectedAce = NULL;
        if (!GetAce(expectedDacl, i, &expectedAce) || expectedAce == NULL) { return FALSE; }

        BOOL found = FALSE;
        for (DWORD j = 0; j < actualInfo.AceCount; ++j)
        {
            void* actualAce = NULL;
            if (!GetAce(actualDacl, j, &actualAce) || actualAce == NULL) { continue; }

            ACE_HEADER* expHdr = (ACE_HEADER*)expectedAce;
            ACE_HEADER* actHdr = (ACE_HEADER*)actualAce;
            if (expHdr->AceType != actHdr->AceType || expHdr->AceFlags != actHdr->AceFlags) { continue; }

            if (expHdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
            {
                ACCESS_ALLOWED_ACE* expAce = (ACCESS_ALLOWED_ACE*)expectedAce;
                ACCESS_ALLOWED_ACE* actAce = (ACCESS_ALLOWED_ACE*)actualAce;
                if (expAce->Mask != actAce->Mask) { continue; }
                PSID expSid = (PSID)&expAce->SidStart;
                PSID actSid = (PSID)&actAce->SidStart;
                if (EqualSid(expSid, actSid))
                {
                    found = TRUE;
                    break;
                }
            }
        }
        if (!found) { return FALSE; }
    }

    return TRUE;
}

static BOOL ServiceDeploy_ValidatePathDaclWithExpected(const wchar_t* path, const wchar_t* expectedSddl)
{
    if (path == NULL || path[0] == L'\0') { return FALSE; }
    if (expectedSddl == NULL || expectedSddl[0] == L'\0') { return FALSE; }

    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    DWORD result = GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    if (result != ERROR_SUCCESS || sd == NULL) { return FALSE; }

    BOOL ok = FALSE;
    if (GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) && daclPresent && dacl != NULL)
    {
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        if (GetSecurityDescriptorControl(sd, &control, &revision))
        {
            if ((control & SE_DACL_PROTECTED) != 0)
            {
                PSECURITY_DESCRIPTOR expectedSd = NULL;
                if (ConvertStringSecurityDescriptorToSecurityDescriptorW(expectedSddl,
                                                                         SDDL_REVISION_1, &expectedSd, NULL))
                {
                    PACL expectedDacl = NULL;
                    BOOL expectedPresent = FALSE;
                    BOOL expectedDefaulted = FALSE;
                    if (GetSecurityDescriptorDacl(expectedSd, &expectedPresent, &expectedDacl, &expectedDefaulted) &&
                        expectedPresent && expectedDacl != NULL)
                    {
                        ok = ServiceDeploy_AclMatchesExpected(dacl, expectedDacl);
                    }
                    LocalFree(expectedSd);
                }
            }
        }
    }

    if (sd != NULL) { LocalFree(sd); }
    return ok;
}

static BOOL ServiceDeploy_ValidatePathDacl(const wchar_t* path)
{
    return ServiceDeploy_ValidatePathDaclWithExpected(path, SERVICE_SECURE_DIR_DACL_SDDL);
}

/* Only transaction admission accepts the older, stricter state layout. The
 * normal directory creator later applies the current protected template. */
static BOOL ServiceDeploy_ValidateTransactionStateDacl(const wchar_t* path)
{
    if (ServiceDeploy_ValidatePathDacl(path)) { return TRUE; }
    /* Require a trusted owner as well as the exact historical two grants;
     * the broader migration permission predicate alone is not sufficient. */
    if (!ServiceLegacyHost_ValidatePermissions(path, TRUE)) { return FALSE; }
    if (!ServiceDeploy_ValidatePathDaclWithExpected(path, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return TRUE;
}

static BOOL ServiceDeploy_ValidateInstallRootDacl(const wchar_t* path)
{
    return ServiceDeploy_ValidatePathDaclWithExpected(path, SERVICE_INSTALL_ROOT_DACL_SDDL);
}

static BOOL ServiceDeploy_ValidateHostExecutableDacl(const wchar_t* exePath)
{
    return ServiceDeploy_ValidatePathDaclWithExpected(exePath, SERVICE_HOST_EXE_DACL_SDDL);
}

static BOOL ServiceDeploy_ValidateServiceHostDllDacl(const wchar_t* dllPath)
{
    return ServiceDeploy_ValidatePathDaclWithExpected(dllPath, SERVICE_DLL_DACL_SDDL);
}


static BOOL ServiceDeploy_ValidateCopiedLegacyHost(const wchar_t* host, const wchar_t* dll)
{
    wchar_t root[MAX_PATH], normalizedDll[MAX_PATH];
    if (!ServiceLegacyHost_NormalizePath(dll, normalizedDll, _countof(normalizedDll)) ||
        !ServiceDeploy_ExtractDirectoryFromPath(normalizedDll, root, _countof(root)) ||
        !ServiceLegacyHost_ValidatePermissions(root, TRUE) ||
        !ServiceLegacyHost_ValidatePermissions(host, FALSE) || !ServiceLegacyHost_ValidateFile(host))
    {
        SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Copied legacy Windows host failed provenance or path protection checks (%ls)", host);
        return FALSE;
    }
    return TRUE;
}

static const wchar_t* ServiceDeploy_LifecycleStateToString(ServiceLifecycleStateKind stateKind)
{
    switch (stateKind)
    {
        case SERVICE_LIFECYCLE_STATE_CLEAN: return L"clean";
        case SERVICE_LIFECYCLE_STATE_HEALTHY: return L"healthy";
        case SERVICE_LIFECYCLE_STATE_PARTIAL: return L"partial";
        case SERVICE_LIFECYCLE_STATE_BROKEN: return L"broken";
        case SERVICE_LIFECYCLE_STATE_PENDING_UPDATE: return L"pending-update";
        case SERVICE_LIFECYCLE_STATE_UNINSTALL_RESIDUE: return L"uninstall-residue";
        default: return L"unknown";
    }
}

static void MeshInstaller_UppercaseInplace(wchar_t* value)
{
    if (value == NULL || value[0] == L'\0') { return; }
    CharUpperBuffW(value, (DWORD)wcslen(value));
}

static const wchar_t* ServiceDeploy_LifecycleRequestToString(ServiceLifecycleRequest request)
{
    switch (request)
    {
        case SERVICE_LIFECYCLE_REQUEST_INSTALL: return L"install";
        case SERVICE_LIFECYCLE_REQUEST_UPDATE: return L"update";
        case SERVICE_LIFECYCLE_REQUEST_REPAIR: return L"repair";
        case SERVICE_LIFECYCLE_REQUEST_REINSTALL: return L"reinstall";
        case SERVICE_LIFECYCLE_REQUEST_UNINSTALL: return L"uninstall";
        default: return L"unknown";
    }
}

static const wchar_t* ServiceDeploy_LifecycleActionToString(ServiceLifecycleAction action)
{
    switch (action)
    {
        case SERVICE_LIFECYCLE_ACTION_INSTALL: return L"install";
        case SERVICE_LIFECYCLE_ACTION_UPDATE: return L"update";
        case SERVICE_LIFECYCLE_ACTION_REPAIR: return L"repair";
        case SERVICE_LIFECYCLE_ACTION_UNINSTALL: return L"uninstall";
        default: return L"noop";
    }
}

static BOOL ServiceDeploy_DataStoreValueExists(const wchar_t* dbPath, const char* key, char* buffer, size_t bufferLen, int* valueLenOut)
{
    if (valueLenOut != NULL) { *valueLenOut = 0; }
    if (buffer != NULL && bufferLen > 0) { buffer[0] = 0; }
    if (dbPath == NULL || dbPath[0] == L'\0' || key == NULL || key[0] == '\0') { return FALSE; }
    if (!ServiceDeploy_PathExists(dbPath)) { return FALSE; }

    char dbPathUtf8[ILibSimpleDataStore_MaxFilePath] = {0};
    if (WideCharToMultiByte(CP_UTF8, 0, dbPath, -1, dbPathUtf8, (int)sizeof(dbPathUtf8), NULL, NULL) <= 0)
    {
        return FALSE;
    }
    if (ILibSimpleDataStore_Exists(dbPathUtf8) == 0) { return FALSE; }

    ILibSimpleDataStore store = ILibSimpleDataStore_CreateEx2(dbPathUtf8, 0, 1);
    if (store == NULL) { return FALSE; }

    int valueLen = ILibSimpleDataStore_Get(store, (char*)key, buffer, bufferLen);
    ILibSimpleDataStore_Close(store);

    if (valueLenOut != NULL) { *valueLenOut = valueLen; }
    if (buffer != NULL && bufferLen > 0)
    {
        size_t terminator = (valueLen >= 0 && (size_t)valueLen < bufferLen) ? (size_t)valueLen : (bufferLen - 1);
        buffer[terminator] = 0;
    }

    return (valueLen > 0);
}

static BOOL ServiceDeploy_DataStorePutValue(const wchar_t* dbPath, const char* key, const char* value, size_t valueLen)
{
    if (dbPath == NULL || dbPath[0] == L'\0' || key == NULL || key[0] == '\0' || value == NULL || valueLen == 0) { return FALSE; }

    char dbPathUtf8[ILibSimpleDataStore_MaxFilePath] = {0};
    if (WideCharToMultiByte(CP_UTF8, 0, dbPath, -1, dbPathUtf8, (int)sizeof(dbPathUtf8), NULL, NULL) <= 0)
    {
        return FALSE;
    }

    ILibSimpleDataStore store = ILibSimpleDataStore_CreateEx2(dbPathUtf8, 0, 0);
    if (store == NULL) { return FALSE; }

    const int putStatus = ILibSimpleDataStore_PutEx(store, (char*)key, (size_t)strnlen_s(key, 255), (char*)value, valueLen);
    const int flushStatus = ILibSimpleDataStore_Flush(store);
    ILibSimpleDataStore_Close(store);
    return (putStatus == 0 && flushStatus == 0);
}

static BOOL ServiceDeploy_DataStoreDeleteValue(const wchar_t* dbPath, const char* key)
{
    if (dbPath == NULL || dbPath[0] == L'\0' || key == NULL || key[0] == '\0') { return FALSE; }
    if (!ServiceDeploy_PathExists(dbPath)) { return FALSE; }

    char dbPathUtf8[ILibSimpleDataStore_MaxFilePath] = {0};
    if (WideCharToMultiByte(CP_UTF8, 0, dbPath, -1, dbPathUtf8, (int)sizeof(dbPathUtf8), NULL, NULL) <= 0)
    {
        return FALSE;
    }
    if (ILibSimpleDataStore_Exists(dbPathUtf8) == 0) { return FALSE; }

    ILibSimpleDataStore store = ILibSimpleDataStore_CreateEx2(dbPathUtf8, 0, 0);
    if (store == NULL) { return FALSE; }

    const int deleteStatus = ILibSimpleDataStore_DeleteEx(store, (char*)key, (size_t)strnlen_s(key, 255));
    const int flushStatus = ILibSimpleDataStore_Flush(store);
    ILibSimpleDataStore_Close(store);
    return (deleteStatus != 0 && flushStatus == 0);
}

static BOOL ServiceDeploy_LoadProvisioningIdentity(const wchar_t* configPath, const wchar_t* workingDbPath, const ServiceIdentitySnapshot* preservedIdentity, BOOL enforcePreservedNodeId, ServiceIdentitySnapshot* provisioningIdentity)
{
    ILibSimpleDataStore store = NULL;
    char workingDbPathUtf8[ILibSimpleDataStore_MaxFilePath] = {0};
    char configPathUtf8[ILibSimpleDataStore_MaxFilePath] = {0};
    char normalizedMeshId[UTIL_SHA384_HASHSIZE] = {0};
    int importedBytes = 0;
    DWORD error = ERROR_SUCCESS;
    BOOL ok = FALSE;

    if (configPath == NULL || configPath[0] == L'\0' ||
        workingDbPath == NULL || workingDbPath[0] == L'\0' ||
        provisioningIdentity == NULL ||
        (enforcePreservedNodeId && preservedIdentity == NULL))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(provisioningIdentity, sizeof(*provisioningIdentity));
    if (!ServiceDeploy_RemoveFileIfExists(workingDbPath, FALSE))
    {
        return FALSE;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, workingDbPath, -1, workingDbPathUtf8, (int)sizeof(workingDbPathUtf8), NULL, NULL) <= 0 ||
        WideCharToMultiByte(CP_UTF8, 0, configPath, -1, configPathUtf8, (int)sizeof(configPathUtf8), NULL, NULL) <= 0)
    {
        error = GetLastError();
        goto CLEANUP;
    }

    store = ILibSimpleDataStore_CreateEx2(workingDbPathUtf8, 0, 0);
    if (store == NULL)
    {
        error = ERROR_OPEN_FAILED;
        goto CLEANUP;
    }
    if (preservedIdentity != NULL && preservedIdentity->nodeIdPresent &&
        ILibSimpleDataStore_PutEx(
            store,
            "NodeID",
            6,
            (char*)preservedIdentity->nodeId,
            (size_t)preservedIdentity->nodeIdLen) != 0)
    {
        error = ERROR_WRITE_FAULT;
        goto CLEANUP;
    }
    importedBytes = MeshAgent_ImportSettingsToDataStore(store, configPathUtf8);
    if (importedBytes <= 0)
    {
        error = ERROR_INVALID_DATA;
        goto CLEANUP;
    }
    if (MeshAgent_NormalizeMeshIdDataStoreValue(store, normalizedMeshId, sizeof(normalizedMeshId), NULL) == 0)
    {
        error = ERROR_INVALID_DATA;
        goto CLEANUP;
    }
    if (!ServiceDeploy_CaptureIdentitySnapshotFromDataStore(store, provisioningIdentity) ||
        !provisioningIdentity->meshIdPresent ||
        !provisioningIdentity->serverIdPresent ||
        !provisioningIdentity->meshServerPresent)
    {
        error = ERROR_INVALID_DATA;
        goto CLEANUP;
    }
    if (enforcePreservedNodeId &&
        (preservedIdentity->nodeIdPresent != provisioningIdentity->nodeIdPresent ||
         (preservedIdentity->nodeIdPresent &&
          !ServiceDeploy_IdentityFieldBytesMatch(
              preservedIdentity->nodeId,
              preservedIdentity->nodeIdLen,
              provisioningIdentity->nodeId,
              provisioningIdentity->nodeIdLen))))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Staged provisioning rejected because it changes the installed NodeID");
        error = ERROR_INVALID_DATA;
        goto CLEANUP;
    }

    ok = TRUE;

CLEANUP:
    if (store != NULL) { ILibSimpleDataStore_Close(store); }
    if (!ServiceDeploy_RemoveFileIfExists(workingDbPath, FALSE))
    {
        if (error == ERROR_SUCCESS) { error = ERROR_ACCESS_DENIED; }
        ok = FALSE;
    }
    if (!ok) { SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA); }
    return ok;
}

static BOOL ServiceDeploy_DerivePostUpdateIdentity(const ServiceUpdateTransaction* tx, const wchar_t* configPath, ServiceIdentitySnapshot* postUpdateIdentity)
{
    if (tx == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return ServiceDeploy_LoadProvisioningIdentity(
        configPath,
        tx->expectedDbPath,
        &tx->rollbackIdentity,
        TRUE,
        postUpdateIdentity);
}

/* Update holds were removed. Delete keys written by earlier builds so a
 * rollback to one of them does not act on a stale hold. A key that cannot be
 * deleted is logged and never fails the transaction. */
static void ServiceDeploy_ClearUpdateActivationHolds(const ServiceInstallPaths* paths, const wchar_t* phaseLabel)
{
    static const char* const staleKeys[] = {
        MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY, MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY,
        "UpdateActivationFailureCompressed", "UpdateForceAttempt", "forceUpdateHold", "forceUpdatePending",
    };
    const wchar_t* safePhase = (phaseLabel != NULL && phaseLabel[0] != L'\0') ? phaseLabel : L"[UPDATE]";
    if (paths == NULL || paths->dbPath[0] == L'\0') { return; }

    for (size_t i = 0; i < _countof(staleKeys); ++i)
    {
        if (!ServiceDeploy_DataStoreValueExists(paths->dbPath, staleKeys[i], NULL, 0, NULL)) { continue; }
        if (ServiceDeploy_DataStoreDeleteValue(paths->dbPath, staleKeys[i]))
        {
            ServiceDeploy_LogInstallEvent(L"%ls Cleared stale update key %hs", safePhase, staleKeys[i]);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] %ls Failed to clear stale update key %hs", safePhase, staleKeys[i]);
        }
    }
}

static BOOL ServiceDeploy_IsPrintableIdentityValue(const char* value, int valueLen)
{
    if (value == NULL || valueLen <= 0) { return FALSE; }

    int printableLen = valueLen;
    if (printableLen > 0 && value[printableLen - 1] == '\0')
    {
        --printableLen;
    }

    if (printableLen <= 0) { return FALSE; }
    for (int i = 0; i < printableLen; ++i)
    {
        const unsigned char ch = (unsigned char)value[i];
        if (ch < 32 || ch > 126)
        {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL ServiceDeploy_IdentityFieldBytesMatch(const char* expectedValue, int expectedValueLen, const char* actualValue, int actualValueLen)
{
    int normalizedExpectedLen = expectedValueLen;
    int normalizedActualLen = actualValueLen;

    if (expectedValue == NULL || actualValue == NULL || expectedValueLen <= 0 || actualValueLen <= 0) { return FALSE; }
    if (expectedValueLen == actualValueLen && memcmp(expectedValue, actualValue, (size_t)expectedValueLen) == 0) { return TRUE; }

    if (!ServiceDeploy_IsPrintableIdentityValue(expectedValue, expectedValueLen) ||
        !ServiceDeploy_IsPrintableIdentityValue(actualValue, actualValueLen))
    {
        return FALSE;
    }

    if (normalizedExpectedLen > 0 && expectedValue[normalizedExpectedLen - 1] == '\0') { --normalizedExpectedLen; }
    if (normalizedActualLen > 0 && actualValue[normalizedActualLen - 1] == '\0') { --normalizedActualLen; }

    return (normalizedExpectedLen == normalizedActualLen &&
        memcmp(expectedValue, actualValue, (size_t)normalizedExpectedLen) == 0) ? TRUE : FALSE;
}

static void ServiceDeploy_LogIdentityField(const wchar_t* phase, const char* keyName, const char* value, int valueLen, BOOL present)
{
    if (keyName == NULL || keyName[0] == '\0') { return; }

    if (!present)
    {
        ServiceDeploy_LogInstallEvent(L"[IDENTITY] %ls %S=absent", (phase != NULL ? phase : L"snapshot"), keyName);
        return;
    }

    if (ServiceDeploy_IsPrintableIdentityValue(value, valueLen))
    {
        ServiceDeploy_LogInstallEvent(L"[IDENTITY] %ls %S len=%d value=%hs",
            (phase != NULL ? phase : L"snapshot"),
            keyName,
            valueLen,
            value);
        return;
    }

    int renderLen = valueLen;
    if (renderLen > 64) { renderLen = 64; }
    char hex[(64 * 2) + 1] = {0};
    util_tohex((char*)value, (size_t)renderLen, hex);
    ServiceDeploy_LogInstallEvent(L"[IDENTITY] %ls %S len=%d hex=%hs%ls",
        (phase != NULL ? phase : L"snapshot"),
        keyName,
        valueLen,
        hex,
        valueLen > renderLen ? L"..." : L"");
}

static BOOL ServiceDeploy_CaptureIdentitySnapshotFromDataStore(ILibSimpleDataStore store, ServiceIdentitySnapshot* snapshot)
{
    if (snapshot == NULL) { return FALSE; }
    ZeroMemory(snapshot, sizeof(*snapshot));
    if (store == NULL) { return FALSE; }

    snapshot->nodeIdLen = ILibSimpleDataStore_Get(store, "NodeID", snapshot->nodeId, sizeof(snapshot->nodeId));
    snapshot->meshIdLen = ILibSimpleDataStore_Get(store, "MeshID", snapshot->meshId, sizeof(snapshot->meshId));
    snapshot->serverIdLen = ILibSimpleDataStore_Get(store, "ServerID", snapshot->serverId, sizeof(snapshot->serverId));
    snapshot->meshServerLen = ILibSimpleDataStore_Get(store, "MeshServer", snapshot->meshServer, sizeof(snapshot->meshServer));
    if (snapshot->nodeIdLen < 0 || (snapshot->nodeIdLen != 0 && snapshot->nodeIdLen != UTIL_SHA384_HASHSIZE) ||
        snapshot->meshIdLen < 0 || snapshot->meshIdLen > sizeof(snapshot->meshId) ||
        snapshot->serverIdLen < 0 || snapshot->serverIdLen > sizeof(snapshot->serverId) ||
        snapshot->meshServerLen < 0 || snapshot->meshServerLen > sizeof(snapshot->meshServer)) { return FALSE; }
#if !defined(MICROSTACK_NOTLS)
    if (snapshot->nodeIdLen == 0)
    {
        int certificateLength = ILibSimpleDataStore_Get(store, "SelfNodeCert", NULL, 0);
        if (certificateLength < 0 || certificateLength > 65536) { return FALSE; }
        if (certificateLength > 0)
        {
            char* encoded = (char*)malloc(certificateLength);
            struct util_cert certificate = {0};
            BOOL loaded;
            if (!encoded) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
            loaded = ILibSimpleDataStore_Get(store, "SelfNodeCert", encoded, certificateLength) == certificateLength &&
                util_from_p12(encoded, certificateLength, "hidden", &certificate) != 0 && certificate.pkey != NULL &&
                util_keyhash(certificate, snapshot->nodeId) == 0;
            util_freecert(&certificate); free(encoded);
            if (!loaded) { return FALSE; }
            snapshot->nodeIdLen = UTIL_SHA384_HASHSIZE;
        }
    }
#endif
    snapshot->nodeIdPresent = snapshot->nodeIdLen > 0;
    snapshot->meshIdPresent = snapshot->meshIdLen > 0;
    snapshot->serverIdPresent = snapshot->serverIdLen > 0;
    snapshot->meshServerPresent = snapshot->meshServerLen > 0;

    return (snapshot->nodeIdPresent ||
            snapshot->meshIdPresent ||
            snapshot->serverIdPresent ||
            snapshot->meshServerPresent);
}

static BOOL ServiceDeploy_CaptureIdentitySnapshot(const wchar_t* dbPath, ServiceIdentitySnapshot* snapshot)
{
    char dbPathUtf8[ILibSimpleDataStore_MaxFilePath] = {0};
    ILibSimpleDataStore store = NULL;
    BOOL captured = FALSE;

    if (snapshot == NULL) { return FALSE; }
    ZeroMemory(snapshot, sizeof(*snapshot));
    if (dbPath == NULL || dbPath[0] == L'\0' || !ServiceDeploy_PathExists(dbPath)) { return FALSE; }
    if (WideCharToMultiByte(CP_UTF8, 0, dbPath, -1, dbPathUtf8, (int)sizeof(dbPathUtf8), NULL, NULL) <= 0) { return FALSE; }
    if (ILibSimpleDataStore_Exists(dbPathUtf8) == 0) { return FALSE; }

    store = ILibSimpleDataStore_CreateEx2(dbPathUtf8, 0, 1);
    if (store == NULL) { return FALSE; }
    captured = ServiceDeploy_CaptureIdentitySnapshotFromDataStore(store, snapshot);
    ILibSimpleDataStore_Close(store);
    return captured;
}

static BOOL ServiceDeploy_DataStoreIdentityPresent(const wchar_t* dbPath)
{
    ServiceIdentitySnapshot snapshot;
    return ServiceDeploy_CaptureIdentitySnapshot(dbPath, &snapshot) && snapshot.nodeIdPresent;
}

static BOOL ServiceDeploy_BindingImagePath(const ServiceBindingSnapshot* binding, wchar_t* path, size_t capacity)
{
    wchar_t expanded[MAX_PATH * 4];
    if (!binding || !binding->config || !path || !capacity) { return FALSE; }
    path[0] = 0;
    if (binding->config->dwServiceType == SERVICE_WIN32_SHARE_PROCESS)
    {
        const ServiceBindingValue* value = &binding->values[9];
        if (!value->present || !value->data || !value->size || value->size % sizeof(wchar_t) ||
            (value->type != REG_SZ && value->type != REG_EXPAND_SZ) ||
            ((wchar_t*)value->data)[value->size / sizeof(wchar_t) - 1]) { return FALSE; }
        if (value->type == REG_SZ)
        { if (FAILED(StringCchCopyW(path, capacity, (wchar_t*)value->data))) { return FALSE; } }
        else
        {
            DWORD count = ExpandEnvironmentStringsW((wchar_t*)value->data, path, (DWORD)capacity);
            if (!count || count > capacity) { return FALSE; }
        }
        return ServiceBinding_SharedImageSupported(binding, path);
    }
    if (!binding->config->lpBinaryPathName) { return FALSE; }
    DWORD count = ExpandEnvironmentStringsW(binding->config->lpBinaryPathName, expanded, _countof(expanded));
    if (!count || count > _countof(expanded)) { return FALSE; }
    if (ServiceBinding_ParseCallbackImage(expanded, path, capacity)) { return TRUE; }
    return binding->legacy && ServiceDeploy_ExtractExecutableFromCommand(expanded, path, capacity);
}

static BOOL ServiceDeploy_EmbeddedServiceBundleMatchesDll(const wchar_t* executable, const wchar_t* dll)
{
    HMODULE module = LoadLibraryExW(executable, NULL, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    HANDLE file = INVALID_HANDLE_VALUE;
    BOOL matches = FALSE;
    if (!module) { return FALSE; }
    HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(IDR_SERVICE_BUNDLE_DLL), MAKEINTRESOURCEW(10));
    DWORD size = resource ? SizeofResource(module, resource) : 0, offset = 0;
    HGLOBAL loaded = resource ? LoadResource(module, resource) : NULL;
    const BYTE* data = loaded ? (const BYTE*)LockResource(loaded) : NULL;
    LARGE_INTEGER length;
    BY_HANDLE_FILE_INFORMATION info;
    BYTE block[16384];
    if (!data || !size) { goto done; }
    file = CreateFileW(dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(file, &length) || length.QuadPart != size) { goto done; }
    while (offset < size)
    {
        DWORD read = 0, count = size - offset;
        if (count > sizeof(block)) { count = sizeof(block); }
        if (!ReadFile(file, block, count, &read, NULL) || read != count || memcmp(block, data + offset, count)) { goto done; }
        offset += count;
    }
    matches = TRUE;
done:
    if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); }
    FreeLibrary(module);
    return matches;
}

static BOOL ServiceDeploy_BindingHasMovedRoot(const ServiceInstallPaths* current, const ServiceBindingSnapshot* binding)
{
    wchar_t imagePath[MAX_PATH], root[MAX_PATH];
    return binding && ServiceDeploy_BindingImagePath(binding, imagePath, _countof(imagePath)) &&
        ServiceDeploy_ExtractDirectoryFromPath(imagePath, root, _countof(root)) && _wcsicmp(root, current->installDir);
}

static BOOL ServiceDeploy_SuspendOriginalRestarters(const ServiceInstallPaths* current, const ServiceBindingSnapshot* binding)
{
    wchar_t imagePath[MAX_PATH], root[MAX_PATH];
    BOOL ok;
    if (!ServiceDeploy_BindingHasMovedRoot(current, binding)) { return TRUE; }
    if (!ServiceDeploy_BindingImagePath(binding, imagePath, _countof(imagePath)) ||
        !ServiceDeploy_ExtractDirectoryFromPath(imagePath, root, _countof(root))) { return FALSE; }
    ServiceDeploy_UpdateServiceRecoveryStatePath(root);
    ok = ServiceDeploy_SuspendServiceRecoveryRestarters();
    ServiceDeploy_UpdateServiceRecoveryStatePath(current->installDir);
    return ok;
}

/* A conventional backup copy is not a second live datastore. Only exclude
 * byte-identical .bak/.backup siblings of an existing file; never pick between
 * unrelated stores or different revisions based on NodeID alone. */
static BOOL ServiceDeploy_IsDuplicateDatabaseBackup(const wchar_t* path)
{
    wchar_t original[MAX_PATH];
    const wchar_t* suffix = wcsrchr(path, L'.');
    HANDLE left = INVALID_HANDLE_VALUE, right = INVALID_HANDLE_VALUE;
    BOOL equal = FALSE;
    LARGE_INTEGER a, b;
    BYTE x[16384], y[16384];
    BY_HANDLE_FILE_INFORMATION info;
    if (!suffix || (_wcsicmp(suffix, L".bak") && _wcsicmp(suffix, L".backup")) ||
        FAILED(StringCchCopyW(original, _countof(original), path))) { return FALSE; }
    original[suffix - path] = 0;
    left = CreateFileW(original, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    right = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (left == INVALID_HANDLE_VALUE || right == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(left, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileInformationByHandle(right, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(left, &a) || !GetFileSizeEx(right, &b) || a.QuadPart != b.QuadPart) { goto done; }
    do
    {
        DWORD n, m;
        if (!ReadFile(left, x, sizeof(x), &n, NULL) || !ReadFile(right, y, sizeof(y), &m, NULL) ||
            n != m || memcmp(x, y, n)) { goto done; }
        if (!n) { equal = TRUE; break; }
    } while (TRUE);
done:
    if (left != INVALID_HANDLE_VALUE) { CloseHandle(left); }
    if (right != INVALID_HANDLE_VALUE) { CloseHandle(right); }
    return equal;
}

/* Recovery must not rediscover ownership from a directory activation changed.
 * Older v1 journals have no paths and retain the conservative discovery path. */
static BOOL ServiceDeploy_CheckpointIncumbentPaths(const ServiceBindingSnapshot* binding, ServiceInstallPaths* paths)
{
    wchar_t imagePath[MAX_PATH], root[MAX_PATH], canonical[MAX_PATH], directory[MAX_PATH];
    if (!binding || !ServiceDeploy_BindingImagePath(binding, imagePath, _countof(imagePath))) { return FALSE; }
    if (!binding->incumbentDbPath[0]) { return ServiceDeploy_FindIncumbentPaths(imagePath, paths); }
    if (wcslen(imagePath) < 4 || imagePath[1] != L':' || (imagePath[2] != L'\\' && imagePath[2] != L'/')) { return FALSE; }
    ZeroMemory(paths, sizeof(*paths));
    DWORD count = GetFullPathNameW(imagePath, _countof(canonical), canonical, NULL);
    if (!count || count >= _countof(canonical) ||
        !ServiceDeploy_ExtractDirectoryFromPath(canonical, root, _countof(root)) || wcslen(root) < 4 ||
        (_wcsicmp(canonical, binding->incumbentExePath) && _wcsicmp(canonical, binding->incumbentDllPath))) { return FALSE; }
    const wchar_t* saved[] = {binding->incumbentExePath, binding->incumbentDllPath, binding->incumbentDbPath};
    wchar_t* destinations[] = {paths->exePath, paths->dllPath, paths->dbPath};
    for (size_t i = 0; i < _countof(saved); ++i)
    {
        if (!saved[i][0]) { continue; }
        count = GetFullPathNameW(saved[i], _countof(canonical), canonical, NULL);
        if (!count || count >= _countof(canonical) || _wcsicmp(canonical, saved[i]) ||
            !ServiceDeploy_ExtractDirectoryFromPath(canonical, directory, _countof(directory)) || _wcsicmp(directory, root)) { return FALSE; }
        DWORD attributes = GetFileAttributesW(canonical), error = GetLastError();
        if (attributes == INVALID_FILE_ATTRIBUTES)
        { if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { return FALSE; } }
        else if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { return FALSE; }
        StringCchCopyW(destinations[i], MAX_PATH, canonical);
    }
    StringCchCopyW(paths->installDir, _countof(paths->installDir), root);
    /* Refuse reparse traversal even if a previously owned root was replaced. */
    StringCchCopyW(directory, _countof(directory), root);
    while (wcslen(directory) >= 3)
    {
        DWORD attributes = GetFileAttributesW(directory), error = GetLastError();
        if (attributes == INVALID_FILE_ATTRIBUTES)
        { if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { return FALSE; } }
        else if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) { return FALSE; }
        if (wcslen(directory) == 3) { break; }
        wchar_t* separator = wcsrchr(directory, L'\\');
        if (!separator || separator < directory + 2) { return FALSE; }
        if (separator == directory + 2) { separator[1] = 0; } else { *separator = 0; }
    }
    return ServiceDeploy_BuildSiblingPathWithExtension(paths->dbPath, L".conf", paths->confPath, _countof(paths->confPath));
}

/* A valid datastore beside a managed service supplies ownership independently
 * of product spelling. Refuse multiple identities rather than picking one. */
static BOOL ServiceDeploy_FindIncumbentPaths(const wchar_t* imagePath, ServiceInstallPaths* paths)
{
    wchar_t pattern[MAX_PATH], candidate[MAX_PATH], systemDir[MAX_PATH], windowsDir[MAX_PATH];
    wchar_t canonical[MAX_PATH], ancestor[MAX_PATH];
    WIN32_FIND_DATAW entry;
    HANDLE search;
    DWORD attributes, error;
    unsigned found = 0, companions = 0;
    ServiceIdentitySnapshot identity;
    ZeroMemory(paths, sizeof(*paths));
    if (!imagePath || wcslen(imagePath) < 4 || imagePath[1] != L':' ||
        (imagePath[2] != L'\\' && imagePath[2] != L'/')) { return FALSE; }
    DWORD count = GetFullPathNameW(imagePath, _countof(canonical), canonical, NULL);
    if (!count || count >= _countof(canonical)) { return FALSE; }
    if (!ServiceDeploy_ExtractDirectoryFromPath(canonical, paths->installDir, _countof(paths->installDir)) ||
        wcslen(paths->installDir) < 4) { return FALSE; }
    if (!GetSystemDirectoryW(systemDir, _countof(systemDir)) || !GetWindowsDirectoryW(windowsDir, _countof(windowsDir)) ||
        !_wcsicmp(paths->installDir, systemDir) || !_wcsicmp(paths->installDir, windowsDir)) { return FALSE; }
    StringCchCopyW(ancestor, _countof(ancestor), paths->installDir);
    while (TRUE)
    {
        attributes = GetFileAttributesW(ancestor);
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) { return FALSE; }
        if (wcslen(ancestor) == 3) { break; }
        wchar_t* separator = wcsrchr(ancestor, L'\\');
        if (!separator || separator < ancestor + 2) { return FALSE; }
        if (separator == ancestor + 2) { separator[1] = 0; } else { *separator = 0; }
    }
    /* Older packaging could rename the datastore as well as the executable.
     * Its parsed identity records, rather than an extension, establish it. */
    if (!MeshInstaller_CombinePath(pattern, _countof(pattern), paths->installDir, L"*")) { return FALSE; }
    search = FindFirstFileW(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE) { return FALSE; }
    do
    {
        if (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { continue; }
        if (!MeshInstaller_CombinePath(candidate, _countof(candidate), paths->installDir, entry.cFileName)) { found = 2; break; }
        if (ServiceDeploy_IsDuplicateDatabaseBackup(candidate)) { continue; }
        /* An interrupted copy (mcu*.tmp) or datastore compaction (*.db.tmp) holds a
         * duplicate identity but is never a live store. Leave it in place. */
        size_t nameLength = wcslen(entry.cFileName);
        if (nameLength > 4 && !_wcsicmp(entry.cFileName + nameLength - 4, L".tmp") &&
            (!_wcsnicmp(entry.cFileName, L"mcu", 3) ||
             (nameLength > 7 && !_wcsicmp(entry.cFileName + nameLength - 7, L".db.tmp")))) { continue; }
        if (ServiceDeploy_CaptureIdentitySnapshot(candidate, &identity) && identity.nodeIdPresent &&
            identity.meshIdPresent && identity.serverIdPresent && identity.meshServerPresent)
        {
            if (++found > 1 || FAILED(StringCchCopyW(paths->dbPath, _countof(paths->dbPath), candidate))) { found = 2; break; }
        }
    } while (FindNextFileW(search, &entry));
    error = GetLastError(); FindClose(search);
    if (found != 1 || error != ERROR_NO_MORE_FILES) { return FALSE; }
    const wchar_t* leaf = MeshInstaller_GetPathLeaf(canonical);
    if (!leaf || !*leaf) { return FALSE; }
    if (ServiceDeploy_PathContainsLeafInsensitive(canonical, L"meshagent.exe") ||
        (wcslen(leaf) >= 4 && !_wcsicmp(leaf + wcslen(leaf) - 4, L".exe")))
    { if (FAILED(StringCchCopyW(paths->exePath, _countof(paths->exePath), canonical))) { return FALSE; } }
    else
    {
        if (FAILED(StringCchCopyW(paths->dllPath, _countof(paths->dllPath), canonical)) ||
            !MeshInstaller_CombinePath(pattern, _countof(pattern), paths->installDir, L"*.exe")) { return FALSE; }
        search = FindFirstFileW(pattern, &entry);
        if (search == INVALID_HANDLE_VALUE)
        {
            error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND) { return FALSE; }
        }
        else
        {
            do
            {
                if (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { continue; }
                if (!MeshInstaller_CombinePath(candidate, _countof(candidate), paths->installDir, entry.cFileName)) { FindClose(search); return FALSE; }
                if (ServiceDeploy_EmbeddedServiceBundleMatchesDll(candidate, canonical))
                {
                    if (++companions == 1) { StringCchCopyW(paths->exePath, _countof(paths->exePath), candidate); }
                    else { paths->exePath[0] = 0; } /* Retain ambiguous companions; the DLL binding is sufficient. */
                }
            } while (FindNextFileW(search, &entry));
            error = GetLastError(); FindClose(search);
            if (error != ERROR_NO_MORE_FILES) { return FALSE; }
        }
    }
    return ServiceDeploy_BuildSiblingPathWithExtension(paths->dbPath, L".conf", paths->confPath, _countof(paths->confPath));
}

static BOOL ServiceDeploy_SelectJournalService(const ServiceInstallPaths* paths, BOOL* found)
{
    ServiceUpdateTransaction tx = {0};
    ServiceJournalRecord* record = NULL;
    *found = FALSE;
    if (!ServiceDeploy_InitializeUpdateTransactionPaths(paths, &tx) || !ServiceDeploy_TransactionPathsSafe(paths, &tx) ||
        !ServiceJournal_Load(tx.journalPath, NULL, &record)) { return FALSE; }
    if (!record) { return TRUE; }
    StringCchCopyW(g_RuntimeBrandingOverrides.serviceKeyName, _countof(g_RuntimeBrandingOverrides.serviceKeyName), record->serviceName);
    g_RuntimeBrandingOverrides.hasServiceKeyName = TRUE;
    *found = TRUE;
    ServiceJournal_Free(record);
    return TRUE;
}

static BOOL ServiceDeploy_SelectIncumbent(void)
{
    ServiceInstallPaths current, selected;
    wchar_t active[256], chosen[256] = {0}, imagePath[MAX_PATH], command[MAX_PATH * 4];
    BOOL exists;
    HKEY services = NULL;
    DWORD index = 0;
    LSTATUS status;
    g_HaveIncumbentPaths = FALSE;
    ZeroMemory(&g_IncumbentPaths, sizeof(g_IncumbentPaths));
    if (!ServiceDeploy_GetInstallPaths(&current)) { return FALSE; }
    BOOL checkpointFound = FALSE;
    if (!ServiceDeploy_SelectJournalService(&current, &checkpointFound)) { return FALSE; }
    if (checkpointFound) { return TRUE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(active, _countof(active), NULL, 0, NULL, 0);
    if (!ServiceBinding_QueryExists(active, &exists)) { return FALSE; }
    /* The ordinary installed path needs no historical scan; it keeps no
     * incumbent paths, so its lifecycle does not depend on identity discovery. */
    if (exists && ServiceDeploy_IsLegacyMeshAgentService(active, imagePath, _countof(imagePath)) &&
        (!_wcsicmp(imagePath, current.dllPath) || !_wcsicmp(imagePath, current.exePath))) { return TRUE; }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ENUMERATE_SUB_KEYS, &services) != ERROR_SUCCESS) { return FALSE; }
    while (TRUE)
    {
        wchar_t name[256]; DWORD count = _countof(name);
        status = RegEnumKeyExW(services, index++, name, &count, NULL, NULL, NULL, NULL);
        if (status != ERROR_SUCCESS) { break; }
        if (exists && _wcsicmp(name, active)) { continue; }
        BOOL knownImage = ServiceDeploy_IsLegacyMeshAgentService(name, imagePath, _countof(imagePath));
        if (!knownImage)
        {
            /* Custom standalone branding is admitted only with an owned DB and
             * the complete LocalSystem SCM checkpoint below. */
            if (!ServiceDeploy_QueryServiceImagePathW(name, command, _countof(command)) ||
                !ServiceDeploy_ExtractExecutableFromCommand(command, imagePath, _countof(imagePath))) { continue; }
        }
        if (!ServiceDeploy_FindIncumbentPaths(imagePath, &selected))
        {
            if (knownImage)
            {
                RegCloseKey(services);
                ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Historical service %ls has missing, ambiguous or unreadable identity; refusing a fresh install", name);
                return FALSE;
            }
            continue;
        }
        ServiceBindingSnapshot* binding = ServiceBinding_Capture(name,
            selected.exePath[0] ? selected.exePath : current.exePath,
            selected.dllPath[0] ? selected.dllPath : current.dllPath);
        if (!binding)
        {
            RegCloseKey(services);
            ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Cannot preserve historical service %ls configuration", name);
            return FALSE;
        }
        ServiceBinding_Free(binding);
        if (chosen[0])
        {
            RegCloseKey(services);
            ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Multiple historical identities require explicit operator selection; no files changed");
            return FALSE;
        }
        StringCchCopyW(chosen, _countof(chosen), name);
        g_IncumbentPaths = selected;
    }
    RegCloseKey(services);
    if (status != ERROR_NO_MORE_ITEMS) { return FALSE; }
    if (!chosen[0]) { return !exists; }
    g_HaveIncumbentPaths = _wcsicmp(g_IncumbentPaths.dbPath, current.dbPath) != 0;
    if (g_HaveIncumbentPaths && ServiceDeploy_PathExists(current.dbPath))
    {
        ServiceIdentitySnapshot oldIdentity, newIdentity;
        if (!ServiceDeploy_CaptureIdentitySnapshot(g_IncumbentPaths.dbPath, &oldIdentity) ||
            !ServiceDeploy_CaptureIdentitySnapshot(current.dbPath, &newIdentity) ||
            oldIdentity.nodeIdLen != newIdentity.nodeIdLen || !oldIdentity.nodeIdPresent || !newIdentity.nodeIdPresent ||
            memcmp(oldIdentity.nodeId, newIdentity.nodeId, oldIdentity.nodeIdLen)) { return FALSE; }
    }
    StringCchCopyW(g_RuntimeBrandingOverrides.serviceKeyName, _countof(g_RuntimeBrandingOverrides.serviceKeyName), chosen);
    g_RuntimeBrandingOverrides.hasServiceKeyName = TRUE;
    return TRUE;
}

static BOOL ServiceDeploy_RemoveIncumbentFiles(const ServiceInstallPaths* old, const ServiceInstallPaths* current, BOOL removeDatabase)
{
    wchar_t sidecar[MAX_PATH], currentMsh[MAX_PATH];
    const wchar_t* imagePath = old->exePath[0] ? old->exePath : old->dllPath;
    if (!ServiceDeploy_BuildInstalledMshPath(current->exePath, currentMsh, _countof(currentMsh))) { return FALSE; }
    const wchar_t* stems[] = {imagePath, old->dbPath, old->dllPath};
    const wchar_t* extensions[] = {L".msh", L".conf", L".mshx"};
    for (size_t i = 0; i < _countof(stems); ++i)
    {
        if (!stems[i][0]) { continue; }
        for (size_t j = 0; j < _countof(extensions); ++j)
        {
            if (!ServiceDeploy_BuildSiblingPathWithExtension(stems[i], extensions[j], sidecar, _countof(sidecar))) { return FALSE; }
            if (_wcsicmp(sidecar, current->confPath) && _wcsicmp(sidecar, currentMsh) &&
                _wcsicmp(sidecar, current->dbPath) && _wcsicmp(sidecar, old->dbPath) &&
                _wcsicmp(sidecar, current->exePath) && _wcsicmp(sidecar, current->dllPath) &&
                !ServiceDeploy_RemoveFileIfExists(sidecar, FALSE)) { return FALSE; }
        }
    }
    if (_wcsicmp(imagePath, current->exePath) && _wcsicmp(imagePath, current->dllPath) &&
        !ServiceDeploy_RemoveFileIfExists(imagePath, FALSE)) { return FALSE; }
    if (old->dllPath[0] && _wcsicmp(old->dllPath, current->dllPath) &&
        _wcsicmp(old->dllPath, current->exePath) && _wcsicmp(old->dllPath, current->dbPath) &&
        !ServiceDeploy_RemoveFileIfExists(old->dllPath, FALSE)) { return FALSE; }
    if (_wcsicmp(old->installDir, current->installDir))
    {
        wchar_t stateDir[MAX_PATH], stateFile[MAX_PATH];
        if (!MeshInstaller_CombinePath(stateDir, _countof(stateDir), old->installDir, L"state") ||
            !MeshInstaller_CombinePath(stateFile, _countof(stateFile), stateDir, L"service-recovery.ini") ||
            !ServiceDeploy_RemoveFileIfExists(stateFile, FALSE)) { return FALSE; }
        (void)RemoveDirectoryW(stateDir);
    }
    /* Retain the identity proof until every other managed file is gone. */
    if (removeDatabase && _wcsicmp(old->dbPath, current->dbPath) &&
        !ServiceDeploy_RemoveFileIfExists(old->dbPath, FALSE)) { return FALSE; }
    (void)RemoveDirectoryW(old->installDir); /* Never recursively remove unrelated files. */
    return TRUE;
}

static BOOL ServiceDeploy_RetireIncumbentFiles(const ServiceInstallPaths* current, const ServiceBindingSnapshot* binding)
{
    wchar_t imagePath[MAX_PATH];
    ServiceInstallPaths old;
    ServiceIdentitySnapshot original, activated;
    if (!binding || !ServiceDeploy_BindingImagePath(binding, imagePath, _countof(imagePath))) { return binding == NULL; }
    if (!binding->incumbentDbPath[0] && (!_wcsicmp(imagePath, current->exePath) || !_wcsicmp(imagePath, current->dllPath))) { return TRUE; }
    if (!ServiceDeploy_CheckpointIncumbentPaths(binding, &old))
    {
        if (binding->incumbentDbPath[0]) { return FALSE; }
        DWORD attributes = GetFileAttributesW(imagePath), error = GetLastError();
        return attributes == INVALID_FILE_ATTRIBUTES && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
    }
    if (!_wcsicmp(old.dbPath, current->dbPath))
    {
        if (!_wcsicmp(imagePath, current->exePath) || !_wcsicmp(imagePath, current->dllPath)) { return TRUE; }
        return ServiceDeploy_RemoveIncumbentFiles(&old, current, FALSE);
    }
    if (!ServiceDeploy_PathExists(old.dbPath))
    {
        DWORD error = GetLastError();
        /* The journal remains until retirement completes; removal is idempotent. */
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) { return ServiceDeploy_RemoveIncumbentFiles(&old, current, TRUE); }
        return FALSE;
    }
    if (!ServiceDeploy_CaptureIdentitySnapshot(old.dbPath, &original) ||
        !ServiceDeploy_CaptureIdentitySnapshot(current->dbPath, &activated) || !activated.nodeIdPresent ||
        original.nodeIdLen != activated.nodeIdLen || memcmp(original.nodeId, activated.nodeId, original.nodeIdLen)) { return FALSE; }
    return ServiceDeploy_RemoveIncumbentFiles(&old, current, TRUE);
}

static void ServiceDeploy_LogIdentitySnapshot(const wchar_t* phase, const ServiceIdentitySnapshot* snapshot)
{
    if (snapshot == NULL) { return; }
    ServiceDeploy_LogIdentityField(phase, "NodeID", snapshot->nodeId, snapshot->nodeIdLen, snapshot->nodeIdPresent);
    ServiceDeploy_LogIdentityField(phase, "MeshID", snapshot->meshId, snapshot->meshIdLen, snapshot->meshIdPresent);
    ServiceDeploy_LogIdentityField(phase, "ServerID", snapshot->serverId, snapshot->serverIdLen, snapshot->serverIdPresent);
    ServiceDeploy_LogIdentityField(phase, "MeshServer", snapshot->meshServer, snapshot->meshServerLen, snapshot->meshServerPresent);
}

static BOOL ServiceDeploy_IdentityFieldMatches(const char* keyName, BOOL expectedPresent, const char* expectedValue, int expectedValueLen, BOOL actualPresent, const char* actualValue, int actualValueLen)
{
    if (!expectedPresent) { return TRUE; }
    if (!actualPresent)
    {
        ServiceDeploy_LogInstallEvent(L"[IDENTITY] Missing expected %S in current datastore snapshot", keyName);
        return FALSE;
    }
    if (!ServiceDeploy_IdentityFieldBytesMatch(expectedValue, expectedValueLen, actualValue, actualValueLen))
    {
        ServiceDeploy_LogInstallEvent(L"[IDENTITY] Value mismatch for %S (expectedLen=%d, actualLen=%d)", keyName, expectedValueLen, actualValueLen);
        return FALSE;
    }
    return TRUE;
}

static BOOL ServiceDeploy_IdentitySnapshotMatches(const ServiceIdentitySnapshot* expected, const ServiceIdentitySnapshot* actual)
{
    if (expected == NULL || actual == NULL) { return FALSE; }

    return (ServiceDeploy_IdentityFieldMatches("NodeID", expected->nodeIdPresent, expected->nodeId, expected->nodeIdLen, actual->nodeIdPresent, actual->nodeId, actual->nodeIdLen) &&
            ServiceDeploy_IdentityFieldMatches("MeshID", expected->meshIdPresent, expected->meshId, expected->meshIdLen, actual->meshIdPresent, actual->meshId, actual->meshIdLen) &&
            ServiceDeploy_IdentityFieldMatches("ServerID", expected->serverIdPresent, expected->serverId, expected->serverIdLen, actual->serverIdPresent, actual->serverId, actual->serverIdLen) &&
            ServiceDeploy_IdentityFieldMatches("MeshServer", expected->meshServerPresent, expected->meshServer, expected->meshServerLen, actual->meshServerPresent, actual->meshServer, actual->meshServerLen));
}

static BOOL ServiceDeploy_IsMasterServicePipeReady(void)
{
    char response[4096] = {0};
    if (!ServiceDeploy_SendMasterServiceControlRequest("{\"op\":\"status\"}\n", response, sizeof(response)))
    {
        return FALSE;
    }
    if (strstr(response, "\"ok\":true") != NULL)
    {
        return TRUE;
    }
    if (strstr(response, "unknown op") != NULL)
    {
        ZeroMemory(response, sizeof(response));
        if (!ServiceDeploy_SendMasterServiceControlRequest("{\"op\":\"listProcesses\"}\n", response, sizeof(response)))
        {
            return FALSE;
        }
        return (strstr(response, "\"ok\":true") != NULL);
    }

    return FALSE;
}

static BOOL ServiceDeploy_SendMasterServiceControlRequest(const char* requestJson, char* response, size_t responseLen)
{
    if (requestJson == NULL || requestJson[0] == '\0' || response == NULL || responseLen < 2) { return FALSE; }
    response[0] = '\0';

    if (!WaitNamedPipeW(SERVICE_MASTER_SERVICE_PIPE_NAME, 1500))
    {
        return FALSE;
    }

    HANDLE pipe = CreateFileW(
        SERVICE_MASTER_SERVICE_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(pipe, requestJson, (DWORD)strlen(requestJson), &written, NULL);
    DWORD read = 0;
    if (ok)
    {
        ok = ReadFile(pipe, response, (DWORD)(responseLen - 1), &read, NULL);
    }
    CloseHandle(pipe);

    if (!ok) { return FALSE; }
    if (read >= responseLen) { read = (DWORD)(responseLen - 1); }
    response[read] = '\0';
    return TRUE;
}

static BOOL ServiceDeploy_QueryServiceImagePathW(const wchar_t* serviceName, wchar_t* imagePath, size_t imagePathCch)
{
    if (imagePath == NULL || imagePathCch == 0) { return FALSE; }
    imagePath[0] = L'\0';
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    BOOL ok = FALSE;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) { return FALSE; }

    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_CONFIG);
    if (svc != NULL)
    {
        DWORD bytesNeeded = 0;
        QueryServiceConfigW(svc, NULL, 0, &bytesNeeded);
        if (bytesNeeded > 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            QUERY_SERVICE_CONFIGW* config = (QUERY_SERVICE_CONFIGW*)LocalAlloc(LPTR, bytesNeeded);
            if (config != NULL)
            {
                if (QueryServiceConfigW(svc, config, bytesNeeded, &bytesNeeded) &&
                    config->lpBinaryPathName != NULL &&
                    SUCCEEDED(StringCchCopyW(imagePath, imagePathCch, config->lpBinaryPathName)))
                {
                    wchar_t expanded[MAX_PATH * 4];
                    DWORD count = ExpandEnvironmentStringsW(imagePath, expanded, _countof(expanded));
                    ok = count && count <= _countof(expanded) && SUCCEEDED(StringCchCopyW(imagePath, imagePathCch, expanded));
                }
                LocalFree(config);
            }
        }
        CloseServiceHandle(svc);
    }

    CloseServiceHandle(scm);
    return ok;
}

static void ServiceDeploy_LogLifecycleSnapshot(const wchar_t* phase, const ServiceLifecycleDiscovery* discovery, const ServiceLifecyclePlan* plan)
{
    if (discovery == NULL) { return; }

    ServiceDeploy_LogInstallEvent(
        L"[LIFECYCLE] phase=%ls request=%ls action=%ls state=%ls service=%u running=%u exe=%u dll=%u conf=%u db=%u firewall=%u persistence=%u umh=%u pendingUpdate=%u stageArtifacts=%u backupArtifacts=%u nodeId=%u aliasCount=%lu",
        (phase != NULL ? phase : L"snapshot"),
        (plan != NULL ? ServiceDeploy_LifecycleRequestToString(plan->request) : L"(none)"),
        (plan != NULL ? ServiceDeploy_LifecycleActionToString(plan->action) : L"(none)"),
        ServiceDeploy_LifecycleStateToString(discovery->stateKind),
        discovery->serviceExists,
        discovery->serviceRunning,
        discovery->exeExists,
        discovery->dllExists,
        discovery->confExists,
        discovery->dbExists,
        discovery->firewallHealthy,
        discovery->persistenceHealthy,
        discovery->masterServiceHealthy,
        discovery->pendingUpdate,
        discovery->updateStageArtifactsPresent,
        discovery->updateBackupArtifactsPresent,
        discovery->nodeIdPresent,
        discovery->conflictingServiceAliasCount);
}

// Commit is based on the target runtime/binding and retained identity. Companion
// policy (DACLs, aliases, persistence and firewall) is reconciled after commit so
// it cannot destroy unrelated incumbent state during a failed migration.
static BOOL ServiceDeploy_WaitForTransactionActivation(DWORD timeoutMs, ServiceLifecycleDiscovery* discoveryOut)
{
    DWORD start = GetTickCount();
    ServiceLifecycleDiscovery state;
    ZeroMemory(&state, sizeof(state));
    do
    {
        if (ServiceDeploy_DiscoverCurrentState(&state) && state.serviceExists && state.serviceRunning &&
            state.exeExists && state.dllExists && state.serviceTypeValid && state.serviceStartValid &&
            state.serviceImageValid && state.serviceAccountValid &&
            state.serviceDllValid &&
            (state.configKeysValid || (state.dbExists && state.nodeIdPresent)))
        {
            if (discoveryOut) { *discoveryOut = state; }
            return TRUE;
        }
        Sleep(500);
    } while (GetTickCount() - start < timeoutMs);
    if (discoveryOut) { *discoveryOut = state; }
    return FALSE;
}

static BOOL ServiceDeploy_IsPrimaryLifecycleConverged(const ServiceLifecycleDiscovery* discovery, BOOL requirePendingClear)
{
    if (discovery == NULL) { return FALSE; }

    const BOOL identityHealthy = (discovery->configKeysValid ||
                                  (discovery->dbExists && discovery->nodeIdPresent));
    /* Path DACLs are applied when files and directories are written and are
     * logged by discovery; drift alone must not fail an install or update. */
    const BOOL filesystemHealthy = (discovery->installRootExists &&
                                    discovery->logsDirExists &&
                                    discovery->exeExists &&
                                    discovery->dllExists &&
                                    identityHealthy);
    const BOOL serviceHealthy = (discovery->serviceExists &&
                                 discovery->serviceRunning &&
                                 discovery->serviceKeyExists &&
                                 discovery->serviceTypeValid &&
                                 discovery->serviceStartValid &&
                                 discovery->serviceImageValid &&

                                 discovery->serviceAccountValid &&
                                 discovery->serviceDllValid &&


                                 discovery->serviceDaclValid &&
                                 discovery->serviceAliasClean);

    return ((!requirePendingClear || !discovery->pendingUpdate) &&
            filesystemHealthy &&
            serviceHealthy &&
            discovery->firewallHealthy &&
            discovery->persistenceHealthy);
}

static BOOL ServiceDeploy_IsPrimaryLifecycleHealthy(const ServiceLifecycleDiscovery* discovery)
{
    return ServiceDeploy_IsPrimaryLifecycleConverged(discovery, TRUE);
}

static BOOL ServiceDeploy_IsPrimaryLifecycleOperational(const ServiceLifecycleDiscovery* discovery)
{
    return ServiceDeploy_IsPrimaryLifecycleConverged(discovery, FALSE);
}

static BOOL ServiceDeploy_WaitForPrimaryLifecycleConverged(DWORD timeoutMs, BOOL requirePendingClear, ServiceLifecycleDiscovery* discoveryOut)
{
    const DWORD startTick = GetTickCount();
    ServiceLifecycleDiscovery currentState;

    if (discoveryOut != NULL)
    {
        ZeroMemory(discoveryOut, sizeof(*discoveryOut));
    }

    do
    {
        if (ServiceDeploy_DiscoverCurrentState(&currentState))
        {
            if (ServiceDeploy_IsPrimaryLifecycleConverged(&currentState, requirePendingClear))
            {
                if (discoveryOut != NULL)
                {
                    *discoveryOut = currentState;
                }
                return TRUE;
            }
            if (discoveryOut != NULL)
            {
                *discoveryOut = currentState;
            }
        }
        Sleep(500);
    } while ((GetTickCount() - startTick) < timeoutMs);

    return FALSE;
}

static BOOL ServiceDeploy_WaitForPrimaryLifecycleHealthy(DWORD timeoutMs, ServiceLifecycleDiscovery* discoveryOut)
{
    return ServiceDeploy_WaitForPrimaryLifecycleConverged(timeoutMs, TRUE, discoveryOut);
}

static BOOL ServiceDeploy_WaitForPrimaryLifecycleOperational(DWORD timeoutMs, ServiceLifecycleDiscovery* discoveryOut)
{
    return ServiceDeploy_WaitForPrimaryLifecycleConverged(timeoutMs, FALSE, discoveryOut);
}

static BOOL ServiceDeploy_BuildTransitionPlan(const ServiceLifecycleDiscovery* discovery, ServiceLifecycleRequest request, ServiceLifecyclePlan* plan)
{
    if (discovery == NULL || plan == NULL) { return FALSE; }
    ZeroMemory(plan, sizeof(*plan));
    plan->request = request;

    switch (request)
    {
        case SERVICE_LIFECYCLE_REQUEST_INSTALL:
            plan->action = (discovery->stateKind == SERVICE_LIFECYCLE_STATE_CLEAN) ?
                SERVICE_LIFECYCLE_ACTION_INSTALL : SERVICE_LIFECYCLE_ACTION_REPAIR;
            break;
        case SERVICE_LIFECYCLE_REQUEST_UPDATE:
            if (discovery->stateKind == SERVICE_LIFECYCLE_STATE_CLEAN)
            {
                plan->action = SERVICE_LIFECYCLE_ACTION_INSTALL;
            }
            else if (discovery->stateKind == SERVICE_LIFECYCLE_STATE_HEALTHY)
            {
                plan->action = SERVICE_LIFECYCLE_ACTION_UPDATE;
            }
            else
            {
                plan->action = SERVICE_LIFECYCLE_ACTION_REPAIR;
            }
            break;
        case SERVICE_LIFECYCLE_REQUEST_REPAIR:
        case SERVICE_LIFECYCLE_REQUEST_REINSTALL:
            plan->action = (discovery->stateKind == SERVICE_LIFECYCLE_STATE_CLEAN) ?
                SERVICE_LIFECYCLE_ACTION_INSTALL : SERVICE_LIFECYCLE_ACTION_REPAIR;
            break;
        case SERVICE_LIFECYCLE_REQUEST_UNINSTALL:
            plan->action = (discovery->stateKind == SERVICE_LIFECYCLE_STATE_CLEAN &&
                            !discovery->installRootExists &&
                            !discovery->logsDirExists) ?
                SERVICE_LIFECYCLE_ACTION_NONE : SERVICE_LIFECYCLE_ACTION_UNINSTALL;
            break;
        default:
            return FALSE;
    }

    plan->preserveIdentity = (request != SERVICE_LIFECYCLE_REQUEST_UNINSTALL && discovery->dbExists && discovery->nodeIdPresent);
    plan->requiresQuiesce = (plan->action == SERVICE_LIFECYCLE_ACTION_UPDATE ||
                             plan->action == SERVICE_LIFECYCLE_ACTION_REPAIR ||
                             plan->action == SERVICE_LIFECYCLE_ACTION_UNINSTALL);
    plan->requiresStage = (plan->action == SERVICE_LIFECYCLE_ACTION_INSTALL ||
                           plan->action == SERVICE_LIFECYCLE_ACTION_UPDATE ||
                           plan->action == SERVICE_LIFECYCLE_ACTION_REPAIR);
    plan->requiresRemoval = (plan->action == SERVICE_LIFECYCLE_ACTION_UNINSTALL);
    plan->requiresServiceStart = (plan->action == SERVICE_LIFECYCLE_ACTION_INSTALL ||
                                  plan->action == SERVICE_LIFECYCLE_ACTION_UPDATE ||
                                  plan->action == SERVICE_LIFECYCLE_ACTION_REPAIR);
    return TRUE;
}

static BOOL ServiceDeploy_FileSha256MatchesW(const wchar_t* leftPath, const wchar_t* rightPath)
{
    wchar_t leftHash[SERVICE_UTIL_SHA256_STRING_LENGTH + 1] = {0};
    wchar_t rightHash[SERVICE_UTIL_SHA256_STRING_LENGTH + 1] = {0};

    if (leftPath == NULL || leftPath[0] == L'\0' || rightPath == NULL || rightPath[0] == L'\0') { return FALSE; }
    if (!ServiceUtil_ComputeFileSha256W(leftPath, leftHash, _countof(leftHash))) { return FALSE; }
    if (!ServiceUtil_ComputeFileSha256W(rightPath, rightHash, _countof(rightHash))) { return FALSE; }
    return (_wcsicmp(leftHash, rightHash) == 0) ? TRUE : FALSE;
}

static BOOL ServiceDeploy_SourcePackageMatchesInstalled(const ServiceLifecycleDiscovery* discovery, const wchar_t* sourceExePath, const wchar_t* sourceDllPath)
{
    BOOL compared = FALSE;

    if (discovery == NULL || discovery->stateKind != SERVICE_LIFECYCLE_STATE_HEALTHY) { return FALSE; }
    if (sourceExePath != NULL && sourceExePath[0] != L'\0')
    {
        compared = TRUE;
        if (!ServiceDeploy_FileSha256MatchesW(sourceExePath, discovery->paths.exePath)) { return FALSE; }
    }
    if (sourceDllPath != NULL && sourceDllPath[0] != L'\0')
    {
        compared = TRUE;
        if (!ServiceDeploy_FileSha256MatchesW(sourceDllPath, discovery->paths.dllPath)) { return FALSE; }
    }
    return compared;
}

static BOOL ServiceDeploy_ServiceGroupsAbsent(const wchar_t* serviceName)
{
    wchar_t groupName[64] = {0};
    BOOL scopedMember = FALSE, legacyMember = FALSE;
    return ServiceHost_BuildGroupName(serviceName, groupName, _countof(groupName)) &&
        ServiceBinding_Group(groupName, serviceName, FALSE, &scopedMember, TRUE) &&
        ServiceBinding_Group(L"netsvcs", serviceName, FALSE, &legacyMember, FALSE) &&
        !scopedMember && !legacyMember;
}

static BOOL ServiceDeploy_DiscoverCurrentState(ServiceLifecycleDiscovery* discovery)
{
    if (discovery == NULL) { return FALSE; }
    ZeroMemory(discovery, sizeof(*discovery));

    if (!ServiceDeploy_GetInstallPaths(&discovery->paths))
    {
        return FALSE;
    }

    ServiceDeploy_ResolveRuntimeServiceBranding(
        discovery->serviceKeyName,
        _countof(discovery->serviceKeyName),
        discovery->serviceDisplayName,
        _countof(discovery->serviceDisplayName),
        NULL,
        0);

    StringCchPrintfW(discovery->serviceKeyPath, _countof(discovery->serviceKeyPath),
        L"SYSTEM\\CurrentControlSet\\Services\\%s", discovery->serviceKeyName);
    StringCchPrintfW(discovery->serviceParamsPath, _countof(discovery->serviceParamsPath),
        L"%s\\Parameters", discovery->serviceKeyPath);
    MeshInstaller_CombinePath(discovery->stateDirPath, _countof(discovery->stateDirPath), discovery->paths.installDir, L"state");
    MeshInstaller_CombinePath(discovery->masterServicePath, _countof(discovery->masterServicePath), discovery->paths.installDir, SERVICE_MASTER_SERVICE_EXE_NAME);

    discovery->installRootExists = ServiceDeploy_PathExists(discovery->paths.installDir);
    discovery->logsDirExists = ServiceDeploy_PathExists(discovery->paths.logsDir);
    discovery->exeExists = ServiceDeploy_PathExists(discovery->paths.exePath);
    discovery->dllExists = ServiceDeploy_PathExists(discovery->paths.dllPath);
    discovery->confExists = ServiceDeploy_PathExists(discovery->paths.confPath);
    discovery->dbExists = ServiceDeploy_PathExists(discovery->paths.dbPath);
    discovery->installRootDaclValid = (discovery->installRootExists ? ServiceDeploy_ValidateInstallRootDacl(discovery->paths.installDir) : FALSE);
    discovery->logsDirDaclValid = (discovery->logsDirExists ? ServiceDeploy_ValidatePathDacl(discovery->paths.logsDir) : FALSE);
    discovery->exeDaclValid = (discovery->exeExists ? ServiceDeploy_ValidateHostExecutableDacl(discovery->paths.exePath) : FALSE);
    discovery->dllDaclValid = (discovery->dllExists ? ServiceDeploy_ValidateServiceHostDllDacl(discovery->paths.dllPath) : FALSE);
    discovery->configKeysValid = (discovery->confExists ? ServiceDeploy_ConfigHasRequiredKeys(discovery->paths.confPath) : FALSE);

    HKEY serviceKey = NULL;
    discovery->serviceKeyExists = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, 0, KEY_QUERY_VALUE, &serviceKey) == ERROR_SUCCESS);
    if (serviceKey != NULL) { RegCloseKey(serviceKey); }

    discovery->serviceExists = ServiceDeploy_IsAlreadyInstalled();
    discovery->serviceRunning = (discovery->serviceExists ? ServiceDeploy_ServiceIsRunning(discovery->serviceKeyName) : FALSE);
    if (discovery->serviceKeyExists)
    {
        DWORD typeValue = 0, startValue = 0;
        wchar_t command[MAX_PATH * 4] = {0};
        wchar_t objectName[256] = {0};
        wchar_t serviceDll[MAX_PATH * 4] = {0};
        discovery->serviceTypeValid = (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, L"Type", &typeValue) &&
                                       typeValue == SERVICE_WIN32_SHARE_PROCESS);
        discovery->serviceStartValid = (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, L"Start", &startValue) &&
                                        startValue == SERVICE_AUTO_START);
        discovery->serviceImageValid = ServiceDeploy_QueryServiceImagePathW(discovery->serviceKeyName, command, _countof(command)) &&
            ServiceHost_IsServiceImagePath(discovery->serviceKeyName, command);
        discovery->serviceDllValid = discovery->serviceImageValid &&
            ServiceHost_ReadServiceDllPath(discovery->serviceKeyName, serviceDll, _countof(serviceDll), FALSE) &&
            _wcsicmp(serviceDll, discovery->paths.dllPath) == 0 &&
            ServiceHost_ValidateServiceBinding(discovery->serviceKeyName, discovery->paths.dllPath);
        discovery->serviceAccountValid = (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, L"ObjectName", objectName, _countof(objectName), NULL) &&
                                          _wcsicmp(objectName, L"LocalSystem") == 0);
    }
    discovery->serviceDaclValid = (discovery->serviceExists ? MeshService_ValidateServiceDaclByName(discovery->serviceKeyName, NULL, 0) : FALSE);
    discovery->conflictingServiceAliasCount = (DWORD)ServiceDeploy_CollectConflictingServiceAliases(&discovery->paths, discovery->serviceKeyName, NULL, 0);
    discovery->serviceAliasClean = (discovery->conflictingServiceAliasCount == 0);
    discovery->serviceGroupArtifactsPresent = !ServiceDeploy_ServiceGroupsAbsent(discovery->serviceKeyName);

    wchar_t systemServiceHostPath[MAX_PATH] = {0};
    const wchar_t* hostToValidate = NULL;
    if (MeshRuntimeHost_GetServiceHostPathW(systemServiceHostPath, _countof(systemServiceHostPath)))
    {
        hostToValidate = systemServiceHostPath;
    }
    discovery->firewallRulePresent = Security_CheckFirewallRuleExists(discovery->serviceKeyName);
    discovery->firewallHealthy = (hostToValidate != NULL &&
                                  discovery->firewallRulePresent &&
                                  ServiceDeploy_DoFirewallRulesMatch(discovery->serviceKeyName, hostToValidate, discovery->paths.exePath));

    ServiceRecoveryState persisted = {0};
    discovery->persistenceStateExists = ServiceDeploy_LoadServiceRecoveryState(&persisted);
    discovery->runKeyPresent = ServiceDeploy_RunKeyMatchesService(discovery->serviceKeyName);

    wchar_t prefixCandidates[10][SERVICE_TASK_NAME_MAX] = {0};
    size_t prefixCount = ServiceDeploy_BuildTaskPrefixCandidates(
        MeshConfig_GetPersistence(),
        discovery->serviceDisplayName,
        discovery->serviceKeyName,
        prefixCandidates,
        _countof(prefixCandidates));
    wchar_t existingTask[SERVICE_TASK_NAME_MAX] = {0};
    discovery->autorunTaskPresent = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-Autorun-", existingTask, _countof(existingTask));
    wchar_t recoveryEventXPath[1024] = {0};
    const BOOL recoveryEventValid = FaultRecovery_FormatServiceStopEventXPath(
        discovery->serviceDisplayName,
        recoveryEventXPath,
        _countof(recoveryEventXPath));
    discovery->recoveryTaskPresent = (discovery->persistenceStateExists && recoveryEventValid &&
        persisted.RecoveryTask[0] != L'\0' &&
        FaultRecovery_ServiceRecoveryTaskMatches(
            persisted.RecoveryTask,
            discovery->serviceKeyName,
            recoveryEventXPath));

    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    wchar_t monitorNamespace[128] = {0};
    if (persistence != NULL)
    {
        MeshService_CopyBrandingTextToWide(persistence->serviceRecoveryMonitor.namespacePath, monitorNamespace, _countof(monitorNamespace));
    }
    discovery->recoveryMonitorPresent = (discovery->persistenceStateExists &&
        persisted.RecoveryMonitorFilter[0] != L'\0' && persisted.RecoveryMonitorHandler[0] != L'\0' &&
        FaultRecovery_ServiceRecoveryMonitorMatches(
            persisted.RecoveryMonitorFilter,
            persisted.RecoveryMonitorHandler,
            discovery->serviceKeyName,
            monitorNamespace));

    {
        const BOOL wantRunKey = (persistence != NULL && persistence->runKey != 0);
        const BOOL wantRecoveryTask = (persistence != NULL && persistence->serviceRecoveryTask.enabled != 0);
        const BOOL wantRecoveryMonitor = (persistence != NULL && persistence->serviceRecoveryMonitor.enabled != 0);
        const BOOL wantState = (wantRecoveryTask || wantRecoveryMonitor);
        discovery->persistenceHealthy =
            (discovery->runKeyPresent == wantRunKey) &&
            (!discovery->autorunTaskPresent) &&
            (discovery->recoveryTaskPresent == wantRecoveryTask) &&
            (discovery->recoveryMonitorPresent == wantRecoveryMonitor) &&
            (discovery->persistenceStateExists == wantState);
    }

    {
        wchar_t updateStageDir[MAX_PATH] = {0};
        wchar_t updateBackupDir[MAX_PATH] = {0};
        if (MeshInstaller_CombinePath(updateStageDir, _countof(updateStageDir), discovery->stateDirPath, SERVICE_UPDATE_STAGE_DIR_NAME))
        {
            discovery->updateStageArtifactsPresent = ServiceDeploy_DirectoryHasEntries(updateStageDir);
        }
        if (MeshInstaller_CombinePath(updateBackupDir, _countof(updateBackupDir), discovery->stateDirPath, SERVICE_UPDATE_BACKUP_DIR_NAME))
        {
            discovery->updateBackupArtifactsPresent = ServiceDeploy_DirectoryHasEntries(updateBackupDir);
        }
    }
    discovery->pendingUpdate = (ServiceDeploy_DataStoreValueExists(discovery->paths.dbPath, "PendingUpdate", NULL, 0, NULL) ||
                                discovery->updateStageArtifactsPresent ||
                                discovery->updateBackupArtifactsPresent);
    discovery->nodeIdPresent = ServiceDeploy_DataStoreIdentityPresent(discovery->paths.dbPath);

    discovery->masterServiceBinaryPresent = ServiceDeploy_PathExists(discovery->masterServicePath);
    BOOL masterServiceManagedByAgent = discovery->masterServiceBinaryPresent;
    wchar_t masterServiceImage[MAX_PATH * 4] = {0};
    if (ServiceDeploy_QueryServiceImagePathW(SERVICE_MASTER_SERVICE_NAME, masterServiceImage, _countof(masterServiceImage)))
    {
        discovery->masterServiceRegistered = TRUE;
        MeshInstaller_NormalizePathSeparators(masterServiceImage);
        if (masterServiceImage[0] == L'"')
        {
            size_t imageLen = wcslen(masterServiceImage);
            if (imageLen > 1)
            {
                memmove(masterServiceImage, masterServiceImage + 1, imageLen * sizeof(wchar_t));
                wchar_t* closingQuote = wcschr(masterServiceImage, L'"');
                if (closingQuote != NULL) { *closingQuote = L'\0'; }
            }
        }
        discovery->masterServicePathValid = (_wcsicmp(masterServiceImage, discovery->masterServicePath) == 0);
        if (discovery->masterServicePathValid)
        {
            masterServiceManagedByAgent = TRUE;
        }
    }
    discovery->masterServiceRunning = (discovery->masterServiceRegistered ? ServiceDeploy_ServiceIsRunning(SERVICE_MASTER_SERVICE_NAME) : FALSE);
    discovery->masterServicePipeReady = (discovery->masterServiceRunning ? ServiceDeploy_IsMasterServicePipeReady() : FALSE);

    discovery->anyPersistenceArtifacts = (discovery->persistenceStateExists ||
                                          discovery->runKeyPresent ||
                                          discovery->autorunTaskPresent ||
                                          discovery->recoveryTaskPresent ||
                                          discovery->recoveryMonitorPresent);
    discovery->anyCompanionArtifacts = (discovery->masterServiceBinaryPresent ||
                                        (discovery->masterServiceRegistered && discovery->masterServicePathValid) ||
                                        (masterServiceManagedByAgent && discovery->masterServicePipeReady));
    discovery->masterServiceHealthy = (!discovery->anyCompanionArtifacts ||
                                       (discovery->masterServiceBinaryPresent &&
                                        discovery->masterServiceRegistered &&
                                        discovery->masterServicePathValid &&
                                        (!discovery->masterServiceRunning || discovery->masterServicePipeReady)));

    discovery->anyInstallArtifacts = (discovery->exeExists ||
                                      discovery->dllExists ||
                                      discovery->confExists ||
                                      discovery->dbExists ||
                                      discovery->serviceKeyExists ||
                                      discovery->serviceExists ||
                                      discovery->firewallRulePresent ||
                                      discovery->serviceGroupArtifactsPresent);

    const BOOL identityHealthy = (discovery->configKeysValid ||
                                  (discovery->dbExists && discovery->nodeIdPresent));
    const BOOL filesystemHealthy = (discovery->installRootExists &&
                                    discovery->logsDirExists &&
                                    discovery->exeExists &&
                                    discovery->dllExists &&
                                    identityHealthy);
    const BOOL serviceHealthy = (discovery->serviceExists &&
                                 discovery->serviceKeyExists &&
                                 discovery->serviceTypeValid &&
                                 discovery->serviceStartValid &&
                                 discovery->serviceImageValid &&
                                 discovery->serviceAccountValid &&
                                 discovery->serviceDllValid &&
                                 discovery->serviceDaclValid &&
                                 discovery->serviceAliasClean);
    const BOOL uninstallResidue = (!discovery->serviceExists &&
                                   (discovery->serviceKeyExists ||
                                    discovery->exeExists ||
                                    discovery->dllExists ||
                                    discovery->confExists ||
                                    discovery->dbExists ||
                                    discovery->firewallRulePresent ||
                                    discovery->anyPersistenceArtifacts ||
                                    discovery->serviceGroupArtifactsPresent));

    if (!discovery->anyInstallArtifacts && !discovery->anyPersistenceArtifacts)
    {
        discovery->stateKind = SERVICE_LIFECYCLE_STATE_CLEAN;
    }
    else if (discovery->pendingUpdate)
    {
        discovery->stateKind = SERVICE_LIFECYCLE_STATE_PENDING_UPDATE;
    }
    else if (uninstallResidue)
    {
        discovery->stateKind = SERVICE_LIFECYCLE_STATE_UNINSTALL_RESIDUE;
    }
    else if (filesystemHealthy && serviceHealthy && discovery->firewallHealthy && discovery->persistenceHealthy)
    {
        discovery->stateKind = SERVICE_LIFECYCLE_STATE_HEALTHY;
    }
    else if (discovery->serviceExists || discovery->serviceKeyExists)
    {
        discovery->stateKind = SERVICE_LIFECYCLE_STATE_BROKEN;
    }
    else
    {
        discovery->stateKind = SERVICE_LIFECYCLE_STATE_PARTIAL;
    }

    return TRUE;
}

static BOOL ServiceDeploy_RunLifecycleOperation(ServiceLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL requireConfig)
{
    ServiceLifecycleDiscovery discovery;
    ServiceLifecyclePlan plan;
    if (!ServiceDeploy_RecoverInterruptedTransaction() || !ServiceDeploy_SelectIncumbent()) { return FALSE; }
    if (!ServiceDeploy_DiscoverCurrentState(&discovery))
    {
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Failed to discover current lifecycle state");
        return FALSE;
    }
    if (!ServiceDeploy_BuildTransitionPlan(&discovery, request, &plan))
    {
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Failed to build lifecycle transition plan");
        return FALSE;
    }
    if (g_HaveIncumbentPaths && (request == SERVICE_LIFECYCLE_REQUEST_INSTALL ||
        request == SERVICE_LIFECYCLE_REQUEST_UPDATE || request == SERVICE_LIFECYCLE_REQUEST_REPAIR))
    {
        /* A renamed incumbent is an update even when the new root is empty. */
        plan.action = SERVICE_LIFECYCLE_ACTION_UPDATE;
    }
    if (request == SERVICE_LIFECYCLE_REQUEST_INSTALL &&
        plan.action == SERVICE_LIFECYCLE_ACTION_REPAIR &&
        ServiceDeploy_SourcePackageMatchesInstalled(&discovery, sourceExePath, sourceDllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Install request already matches healthy installed package; using noop action");
        plan.action = SERVICE_LIFECYCLE_ACTION_NONE;
        plan.requiresQuiesce = FALSE;
        plan.requiresStage = FALSE;
        plan.requiresRemoval = FALSE;
        plan.requiresServiceStart = FALSE;
    }
    if (request == SERVICE_LIFECYCLE_REQUEST_UPDATE &&
        !requireConfig &&
        plan.action == SERVICE_LIFECYCLE_ACTION_REPAIR &&
        discovery.dbExists &&
        discovery.nodeIdPresent)
    {
        ServiceDeploy_LogInstallEvent(
            L"[LIFECYCLE] Binary-only update preserving datastore identity on %ls state; using update action",
            ServiceDeploy_LifecycleStateToString(discovery.stateKind));
        plan.action = SERVICE_LIFECYCLE_ACTION_UPDATE;
    }

    ServiceDeploy_LogLifecycleSnapshot(L"before", &discovery, &plan);

    BOOL ok = FALSE;
    switch (plan.action)
    {
        case SERVICE_LIFECYCLE_ACTION_NONE:
            ok = TRUE;
            break;
        case SERVICE_LIFECYCLE_ACTION_INSTALL:
            ok = ServiceDeploy_ApplyInstallFlow(sourceExePath, sourceDllPath);
            break;
        case SERVICE_LIFECYCLE_ACTION_UPDATE:
            ok = ServiceDeploy_ApplyUpdateFlow(sourceExePath, sourceDllPath, requireConfig);
            break;
        case SERVICE_LIFECYCLE_ACTION_REPAIR:
            ok = ServiceDeploy_ApplyRepairFlow(sourceExePath, sourceDllPath);
            break;
        case SERVICE_LIFECYCLE_ACTION_UNINSTALL:
            ok = ServiceDeploy_ApplyUninstallFlow();
            break;
        default:
            ok = FALSE;
            break;
    }

    DWORD operationError = GetLastError();
    ServiceLifecycleDiscovery postState;
    if (ServiceDeploy_DiscoverCurrentState(&postState))
    {
        ServiceDeploy_LogLifecycleSnapshot(ok ? L"after" : L"after-failed", &postState, &plan);
    }

    if (!ok) { SetLastError(operationError); }

    return ok;
}







/* ServiceMain delegates here after stopping for an abandoned checkpoint, so a
 * start was requested. Recovery is idempotent: retry transient failures (file
 * locks, slow SCM transitions), then start the service once the checkpoint is
 * gone. Recovery itself starts it only when it was running before the update,
 * and a clean ServiceMain exit triggers no SCM retry, so without this start
 * the agent stays offline until the next boot. A retained checkpoint is never
 * started over: the startup gate would only delegate again. */
static BOOL ServiceDeploy_RunDelegatedUpdateRecovery(void)
{
    wchar_t serviceName[256] = {0};
    BOOL recovered = FALSE, exists = FALSE;
    DWORD error = ERROR_GEN_FAILURE;
    ServiceDeploy_ResolveRuntimeServiceBranding(serviceName, _countof(serviceName), NULL, 0, NULL, 0);
    for (int attempt = 1; attempt <= 3; ++attempt)
    {
        if (attempt > 1)
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Retrying interrupted update recovery or service start in 10s (attempt %d of 3)", attempt);
            Sleep(10000);
        }
        if (!recovered)
        {
            recovered = ServiceDeploy_RecoverInterruptedTransaction();
            if (!recovered) { error = GetLastError(); continue; }
        }
        /* Once resolved, retry only the start: the old checkpoint must not be
         * replayed while a restored service is starting. */
        if (!ServiceBinding_QueryExists(serviceName, &exists))
        {
            error = GetLastError();
            ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Recovered service %ls could not be queried (error=%lu)", serviceName, error);
            continue;
        }
        /* Rolling back an originally absent service legitimately removes it. */
        if (!exists || ServiceDeploy_StartServiceHostServiceAndWait(serviceName, 30000)) { return TRUE; }
        error = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Recovered service %ls did not start (error=%lu)", serviceName, error);
    }
    SetLastError(error != ERROR_SUCCESS ? error : ERROR_GEN_FAILURE);
    return FALSE;
}

static BOOL ServiceDeploy_RunLifecycleHostOperationLocked(
    const wchar_t* actionName,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL requireConfig)
{
    if (actionName == NULL || actionName[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE_HOST] Missing lifecycle action");
        return FALSE;
    }

    if (_wcsicmp(actionName, L"install") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_INSTALL, sourceExePath, sourceDllPath, TRUE);
    }
    if (_wcsicmp(actionName, L"update") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_UPDATE, sourceExePath, sourceDllPath, requireConfig);
    }
    if (_wcsicmp(actionName, L"repair") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_REPAIR, sourceExePath, sourceDllPath, TRUE);
    }
    if (_wcsicmp(actionName, L"reinstall") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_REINSTALL, sourceExePath, sourceDllPath, TRUE);
    }
    if (_wcsicmp(actionName, L"uninstall") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_UNINSTALL, NULL, NULL, TRUE);
    }
    if (_wcsicmp(actionName, MESH_LIFECYCLE_ACTION_RECOVER_UPDATE_W) == 0)
    {
        return ServiceDeploy_RunDelegatedUpdateRecovery();
    }
    if (_wcsicmp(actionName, L"validate-install") == 0)
    {
        return ServiceDeploy_RunInstallValidation();
    }
    if (_wcsicmp(actionName, L"validate-update") == 0)
    {
        return ServiceDeploy_RunUpdateValidation();
    }
    if (_wcsicmp(actionName, L"validate-uninstall") == 0)
    {
        return ServiceDeploy_RunUninstallValidation();
    }
    if (_wcsicmp(actionName, L"validate-package") == 0)
    {
        return ServiceDeploy_RunPackageValidation(sourceExePath, requireConfig);
    }

    ServiceDeploy_LogInstallEvent(L"[LIFECYCLE_HOST] Unsupported lifecycle action: %ls", actionName);
    return FALSE;
}

static HANDLE ServiceDeploy_AcquireLifecycleMutex(void)
{
    wchar_t mutexName[96];
    DWORD wait;
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, FALSE};
    HANDLE mutex;
    if (!ServiceDeploy_BuildLifecycleMutexName(mutexName, _countof(mutexName))) { return NULL; }
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1, &security.lpSecurityDescriptor, NULL)) { return NULL; }
    mutex = CreateMutexW(&security, FALSE, mutexName);
    LocalFree(security.lpSecurityDescriptor);
    if (!mutex) { return NULL; }
    wait = WaitForSingleObject(mutex, 30000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED)
    {
        CloseHandle(mutex);
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Another lifecycle operation is still active");
        return NULL;
    }
    return mutex;
}

BOOL ServiceDeploy_RunLifecycleHostOperation(
    const wchar_t* actionName, const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath, BOOL requireConfig)
{
    HANDLE mutex;
    BOOL ok;
    wchar_t lockedName[256], selectedName[256];
    if (!ServiceDeploy_SelectIncumbent()) { return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(lockedName, _countof(lockedName), NULL, 0, NULL, 0);
    mutex = ServiceDeploy_AcquireLifecycleMutex();
    if (mutex == NULL) { return FALSE; }
    /* Revalidate after serialization: another lifecycle operation may have
     * changed SCM or datastore ownership while this caller waited. */
    if (!ServiceDeploy_SelectIncumbent()) { ReleaseMutex(mutex); CloseHandle(mutex); return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(selectedName, _countof(selectedName), NULL, 0, NULL, 0);
    if (_wcsicmp(lockedName, selectedName)) { ReleaseMutex(mutex); CloseHandle(mutex); return FALSE; }
    ok = ServiceDeploy_RunLifecycleHostOperationLocked(actionName, sourceExePath, sourceDllPath, requireConfig);
    DWORD operationError = GetLastError();
    ReleaseMutex(mutex); CloseHandle(mutex);
    if (!ok) { SetLastError(operationError); }
    return ok;
}

// An uninstall started from the installed image cannot delete its own running binary. When
// that binary is the only remaining artifact, move it off the canonical path (a running image
// can be renamed, not deleted) and schedule the retired copy and the then-empty install
// directory for removal at reboot. Retiring it first keeps the pending delete from removing a
// binary that is reinstalled before the reboot.
static BOOL ServiceDeploy_RetireRunningInstalledImage(const wchar_t* runningExePath, const ServiceInstallPaths* paths, WCHAR* retiredPath, size_t retiredPathCch, BOOL* removalScheduled)
{
	*removalScheduled = FALSE;
	if (!ServiceUtil_PathsReferToSameFileW(runningExePath, paths->exePath) ||
		!ServiceDeploy_IsUninstallCleanExceptInstalledExe())
	{
		ServiceDeploy_LogInstallEvent(L"[TERMINAL] Uninstall left artifacts beyond the running installed image; not treating as complete");
		return FALSE;
	}
	if (FAILED(StringCchPrintfW(retiredPath, retiredPathCch, L"%ls.%lu.pending-delete", paths->exePath, (unsigned long)GetCurrentProcessId())))
	{
		ServiceDeploy_LogInstallEvent(L"[TERMINAL] Retired image path too long for %ls", paths->exePath);
		return FALSE;
	}
	if (!MoveFileExW(paths->exePath, retiredPath, 0))
	{
		ServiceDeploy_LogInstallEvent(L"[TERMINAL] Unable to retire running installed image %ls (error=%lu)", paths->exePath, GetLastError());
		retiredPath[0] = L'\0';
		return FALSE;
	}
	ServiceDeploy_LogInstallEvent(L"[TERMINAL] Retired running installed image to %ls", retiredPath);

	if (!MoveFileExW(retiredPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
	{
		ServiceDeploy_LogInstallEvent(L"[TERMINAL] Unable to schedule reboot removal of %ls (error=%lu)", retiredPath, GetLastError());
		return FALSE;
	}
	*removalScheduled = TRUE;
	// Removed at restart only if the directory is empty by then.
	if (paths->installDir[0] != L'\0' && !MoveFileExW(paths->installDir, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
	{
		ServiceDeploy_LogInstallEvent(L"[TERMINAL] Unable to schedule reboot removal of %ls (error=%lu)", paths->installDir, GetLastError());
	}
	ServiceDeploy_LogInstallEvent(L"[TERMINAL] Scheduled reboot removal of %ls", retiredPath);
	return TRUE;
}

// The uninstall and running-image retirement share the same lifecycle mutex.
// Another install cannot replace the canonical image between cleanup and rename.
BOOL ServiceDeploy_RunTerminalUninstall(const wchar_t* runningExePath,
    wchar_t* retiredPath, size_t retiredPathCch, BOOL* removalScheduled)
{
    ServiceInstallPaths paths;
    HANDLE mutex;
    BOOL ok;
    wchar_t lockedName[256], selectedName[256];
    if (runningExePath == NULL || retiredPath == NULL || retiredPathCch == 0 || removalScheduled == NULL)
    { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    retiredPath[0] = L'\0';
    *removalScheduled = FALSE;
    if (!ServiceDeploy_SelectIncumbent()) { return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(lockedName, _countof(lockedName), NULL, 0, NULL, 0);
    mutex = ServiceDeploy_AcquireLifecycleMutex();
    if (mutex == NULL) { return FALSE; }
    if (!ServiceDeploy_SelectIncumbent()) { ReleaseMutex(mutex); CloseHandle(mutex); return FALSE; }
    ServiceDeploy_ResolveRuntimeServiceBranding(selectedName, _countof(selectedName), NULL, 0, NULL, 0);
    if (_wcsicmp(lockedName, selectedName)) { ReleaseMutex(mutex); CloseHandle(mutex); return FALSE; }
    ZeroMemory(&paths, sizeof(paths));
    ok = ServiceDeploy_GetInstallPaths(&paths);
    DWORD operationError = GetLastError();
    if (ok)
    {
        ok = ServiceDeploy_RunLifecycleHostOperationLocked(MESH_LIFECYCLE_ACTION_UNINSTALL_W, NULL, NULL, FALSE);
        operationError = GetLastError();
        if (!ok)
        {
            ok = ServiceDeploy_RetireRunningInstalledImage(runningExePath, &paths,
                retiredPath, retiredPathCch, removalScheduled);
        }
    }
    ReleaseMutex(mutex); CloseHandle(mutex);
    if (!ok) { SetLastError(operationError); }
    return ok;
}


BOOL ServiceDeploy_StageServiceHostDllForLifecycleHost(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* destPath)
{
    HMODULE mod = NULL;
    BOOL hasLifecycleEntry = FALSE;

    if (!ServiceDeploy_EnsureServiceHostDllFile(sourceExePath, sourceDllPath, destPath)) { return FALSE; }

    // The SCM host cannot load a service DLL without the exported ServiceMain.
    mod = LoadLibraryExW(destPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mod != NULL)
    {
        hasLifecycleEntry = (GetProcAddress(mod, MESH_RUNTIME_HOST_ENTRY_LIFECYCLE_A) != NULL);
        FreeLibrary(mod);
    }
    if (!hasLifecycleEntry)
    {
        ServiceDeploy_LogInstallEvent(L"Lifecycle host DLL export missing for %ls (expected=MeshLifecycleHostW)", destPath);
        ServiceDeploy_DeleteFileIfPresent(destPath);
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return TRUE;
}

static BOOL ServiceDeploy_ExtractEmbeddedMshFromExe(const wchar_t* exePath, const wchar_t* destPath)
{
    if (exePath == NULL || exePath[0] == L'\0' || destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    static const unsigned char kMshGuid[16] = {
        0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19,
        0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x19
    };

    FILE* src = NULL;
    if (_wfopen_s(&src, exePath, L"rb") != 0 || src == NULL) { return FALSE; }

    if (fseek(src, 0, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }
    long fileLen = ftell(src);
    if (fileLen < 20)
    {
        fclose(src);
        return FALSE;
    }

    if (fseek(src, -16, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }

    unsigned char guid[16] = {0};
    if (fread(guid, 1, sizeof(guid), src) != sizeof(guid) || memcmp(guid, kMshGuid, sizeof(guid)) != 0)
    {
        fclose(src);
        return FALSE;
    }

    if (fseek(src, -20, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }

    unsigned char lenBuf[4] = {0};
    if (fread(lenBuf, 1, sizeof(lenBuf), src) != sizeof(lenBuf))
    {
        fclose(src);
        return FALSE;
    }

    unsigned int mshLen = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
    if (mshLen == 0 || ((unsigned long)mshLen + 20UL) > (unsigned long)fileLen)
    {
        fclose(src);
        return FALSE;
    }

    long dataOffset = fileLen - 20 - (long)mshLen;
    if (dataOffset < 0 || fseek(src, dataOffset, SEEK_SET) != 0)
    {
        fclose(src);
        return FALSE;
    }

    char* buffer = (char*)malloc(mshLen);
    if (buffer == NULL)
    {
        fclose(src);
        return FALSE;
    }

    BOOL ok = FALSE;
    if (fread(buffer, 1, mshLen, src) == mshLen)
    {
        FILE* dst = NULL;
        if (_wfopen_s(&dst, destPath, L"wb") == 0 && dst != NULL)
        {
            if (fwrite(buffer, 1, mshLen, dst) == mshLen)
            {
                ok = TRUE;
            }
            fclose(dst);
        }
    }

    free(buffer);
    fclose(src);
    return ok;
}

static BOOL ServiceDeploy_HasEmbeddedProvisioningManifest(const wchar_t* exePath)
{
    if (exePath == NULL || exePath[0] == L'\0') { return FALSE; }

    static const unsigned char kMshGuid[16] = {
        0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19,
        0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x19
    };

    FILE* src = NULL;
    if (_wfopen_s(&src, exePath, L"rb") != 0 || src == NULL) { return FALSE; }

    if (fseek(src, 0, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }
    long fileLen = ftell(src);
    if (fileLen < 20)
    {
        fclose(src);
        return FALSE;
    }

    if (fseek(src, -16, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }

    unsigned char guid[16] = {0};
    if (fread(guid, 1, sizeof(guid), src) != sizeof(guid) || memcmp(guid, kMshGuid, sizeof(guid)) != 0)
    {
        fclose(src);
        return FALSE;
    }

    if (fseek(src, -20, SEEK_END) != 0)
    {
        fclose(src);
        return FALSE;
    }

    unsigned char lenBuf[4] = {0};
    if (fread(lenBuf, 1, sizeof(lenBuf), src) != sizeof(lenBuf))
    {
        fclose(src);
        return FALSE;
    }

    unsigned int mshLen = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
    fclose(src);
    return (mshLen != 0 && ((unsigned long)mshLen + 20UL) <= (unsigned long)fileLen);
}

static BOOL ServiceDeploy_CopyFileIfPresent(const wchar_t* sourcePath, const wchar_t* destPath)
{
    if (sourcePath == NULL || destPath == NULL) { return FALSE; }
    DWORD attr = GetFileAttributesW(sourcePath);
    if (attr == INVALID_FILE_ATTRIBUTES) { return FALSE; }
    SetFileAttributesW(destPath, FILE_ATTRIBUTE_NORMAL);
    CopyFileW(sourcePath, destPath, FALSE);
    return (GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES);
}

static BOOL ServiceDeploy_TryStageAndValidateServiceHostDll(const wchar_t* candidatePath, const wchar_t* destPath, const wchar_t* sourceLabel)
{
    if (candidatePath == NULL || candidatePath[0] == L'\0' || destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    DWORD attrs = GetFileAttributesW(candidatePath);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        return FALSE;
    }

    if (_wcsicmp(candidatePath, destPath) == 0)
    {
        if (ServiceDeploy_ValidateServiceHostDll(destPath))
        {
            if (!ServiceDeploy_HardenServiceHostDllDacl(destPath))
            {
                ServiceDeploy_LogInstallEvent(L"Failed to harden runtime DLL DACL in place (%ls, error=%lu)", destPath, GetLastError());
                return FALSE;
            }
            return TRUE;
        }
        ServiceDeploy_LogInstallEvent(L"ServiceHost DLL candidate failed validation in place (%ls)", candidatePath);
        return FALSE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (!ServiceDeploy_CopyFileOverwrite(candidatePath, destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to stage runtime DLL from %ls (%ls -> %ls)", sourceLabel != NULL ? sourceLabel : L"candidate", candidatePath, destPath);
        return FALSE;
    }

    if (!ServiceDeploy_HardenServiceHostDllDacl(destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to harden staged runtime DLL DACL from %ls (%ls, error=%lu)", sourceLabel != NULL ? sourceLabel : L"candidate", destPath, GetLastError());
        ServiceDeploy_DeleteFileIfPresent(destPath);
        return FALSE;
    }

    if (ServiceDeploy_ValidateServiceHostDll(destPath))
    {
        return TRUE;
    }

    ServiceDeploy_LogInstallEvent(L"ServiceHost DLL candidate from %ls failed validation (%ls)", sourceLabel != NULL ? sourceLabel : L"candidate", candidatePath);
    ServiceDeploy_DeleteFileIfPresent(destPath);
    return FALSE;
}

static BOOL ServiceDeploy_ExtractEmbeddedServiceHostDllFromExe(const wchar_t* exePath, const wchar_t* destPath)
{
    BOOL ok = FALSE;
    HMODULE moduleHandle = NULL;
    HRSRC resourceInfo = NULL;
    HGLOBAL resourceHandle = NULL;
    const void* resourceData = NULL;
    DWORD resourceSize = 0;
    FILE* dst = NULL;
    LPCWSTR rcDataType = MAKEINTRESOURCEW(10);

    if (exePath == NULL || exePath[0] == L'\0' || destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    moduleHandle = LoadLibraryExW(exePath, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (moduleHandle == NULL) { return FALSE; }

    resourceInfo = FindResourceW(moduleHandle, MAKEINTRESOURCEW(IDR_SERVICE_BUNDLE_DLL), rcDataType);
    if (resourceInfo == NULL) { goto cleanup; }

    resourceHandle = LoadResource(moduleHandle, resourceInfo);
    if (resourceHandle == NULL) { goto cleanup; }

    resourceData = LockResource(resourceHandle);
    resourceSize = SizeofResource(moduleHandle, resourceInfo);
    if (resourceData == NULL || resourceSize == 0) { goto cleanup; }

    SetFileAttributesW(destPath, FILE_ATTRIBUTE_NORMAL);
    if (_wfopen_s(&dst, destPath, L"wb") != 0 || dst == NULL) { goto cleanup; }
    if (fwrite(resourceData, 1, resourceSize, dst) != resourceSize) { goto cleanup; }

    ok = TRUE;

cleanup:
    if (dst != NULL)
    {
        fclose(dst);
        dst = NULL;
    }
    if (!ok)
    {
        ServiceDeploy_DeleteFileIfPresent(destPath);
    }
    if (moduleHandle != NULL)
    {
        FreeLibrary(moduleHandle);
    }
    return ok;
}

static BOOL ServiceDeploy_EnsureServiceHostDllFile(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, const wchar_t* destPath)
{
    BOOL packageProvided = (sourceExePath != NULL && sourceExePath[0] != L'\0');

    if (destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    if (sourceDllPath != NULL && sourceDllPath[0] != L'\0')
    {
        if (ServiceDeploy_TryStageAndValidateServiceHostDll(sourceDllPath, destPath, L"explicit package DLL"))
        {
            return TRUE;
        }
    }

    if (packageProvided)
    {
        ServiceDeploy_DeleteFileIfPresent(destPath);
        if (ServiceDeploy_ExtractEmbeddedServiceHostDllFromExe(sourceExePath, destPath))
        {
            if (!ServiceDeploy_HardenServiceHostDllDacl(destPath))
            {
                ServiceDeploy_LogInstallEvent(L"Failed to harden extracted runtime DLL DACL (%ls, error=%lu)", destPath, GetLastError());
                ServiceDeploy_DeleteFileIfPresent(destPath);
                return FALSE;
            }
            if (ServiceDeploy_ValidateServiceHostDll(destPath))
            {
                return TRUE;
            }
            ServiceDeploy_DeleteFileIfPresent(destPath);
        }

        /* Historical binaries do not embed resource 101. Fall back to current process embedded bundle. */
        if (ServiceBundle_WriteToPath(destPath))
        {
            if (!ServiceDeploy_HardenServiceHostDllDacl(destPath))
            {
                ServiceDeploy_LogInstallEvent(L"Warning: DLL DACL hardening failed for %ls (error=%lu)", destPath, GetLastError());
            }
            if (ServiceDeploy_ValidateServiceHostDll(destPath))
            {
                ServiceDeploy_LogInstallEvent(L"Provided package (%ls) lacks an embedded service DLL; successfully staged from current running bundle", sourceExePath);
                return TRUE;
            }
            ServiceDeploy_DeleteFileIfPresent(destPath);
        }

        /* Fallback: if destPath is already present and valid (e.g. existing installation), preserve it. */
        if (ServiceDeploy_PathExists(destPath) && ServiceDeploy_ValidateServiceHostDll(destPath))
        {
            ServiceDeploy_LogInstallEvent(L"Reusing existing valid runtime DLL at %ls", destPath);
            return TRUE;
        }

        ServiceDeploy_DeleteFileIfPresent(destPath);
        ServiceDeploy_LogInstallEvent(L"Package did not provide a valid explicit or embedded runtime DLL (%ls)", sourceExePath);
        return FALSE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (!ServiceBundle_WriteToPath(destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to stage embedded runtime DLL to %ls (error=%lu)", destPath, GetLastError());
        return FALSE;
    }

    // BUGFIX: Harden DLL DACL immediately after creation
    if (!ServiceDeploy_HardenServiceHostDllDacl(destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Warning: DLL DACL hardening failed for %ls (error=%lu)", destPath, GetLastError());
    }

    if (!ServiceDeploy_ValidateServiceHostDll(destPath))
    {
        ServiceDeploy_DeleteFileIfPresent(destPath);
        return FALSE;
    }
    return TRUE;
}

static BOOL ServiceDeploy_EnsureConfigFile(const wchar_t* sourceExePath, const wchar_t* destPath)
{
    wchar_t sidecarPath[MAX_PATH * 4] = {0};

    if (destPath == NULL || destPath[0] == L'\0') { return FALSE; }
    if (sourceExePath == NULL || sourceExePath[0] == L'\0')
    {
        return FALSE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (ServiceDeploy_ExtractEmbeddedMshFromExe(sourceExePath, destPath) && ServiceDeploy_ConfigHasRequiredKeys(destPath))
    {
        return TRUE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (ServiceDeploy_BuildSiblingPathWithExtension(sourceExePath, L".msh", sidecarPath, _countof(sidecarPath)) &&
        ServiceDeploy_ConfigHasRequiredKeys(sidecarPath) &&
        ServiceDeploy_CopyFileOverwrite(sidecarPath, destPath) &&
        ServiceDeploy_ConfigHasRequiredKeys(destPath))
    {
        return TRUE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    return FALSE;
}

static BOOL ServiceDeploy_EnsureMshFile(const wchar_t* sourceExePath, const wchar_t* destPath)
{
    wchar_t sidecarPath[MAX_PATH * 4] = {0};

    if (destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    if (sourceExePath == NULL || sourceExePath[0] == L'\0')
    {
        return FALSE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (ServiceDeploy_ExtractEmbeddedMshFromExe(sourceExePath, destPath) && ServiceDeploy_ConfigHasRequiredKeys(destPath))
    {
        return TRUE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (ServiceDeploy_BuildSiblingPathWithExtension(sourceExePath, L".msh", sidecarPath, _countof(sidecarPath)) &&
        ServiceDeploy_ConfigHasRequiredKeys(sidecarPath) &&
        ServiceDeploy_CopyFileOverwrite(sidecarPath, destPath) &&
        ServiceDeploy_ConfigHasRequiredKeys(destPath))
    {
        return TRUE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    return FALSE;
}

BOOL ServiceDeploy_PreflightPackageSource(
    const wchar_t* sourceExePath,
    BOOL requireConfig,
    ServicePackagePreflight* summary,
    wchar_t* failureReason,
    size_t failureReasonCch)
{
    ServicePackagePreflight localSummary;
    ServicePackagePreflight* target = (summary != NULL) ? summary : &localSummary;
    ZeroMemory(target, sizeof(*target));
    if (failureReason != NULL && failureReasonCch > 0) { failureReason[0] = L'\0'; }

    if (sourceExePath == NULL || sourceExePath[0] == L'\0')
    {
        if (failureReason != NULL && failureReasonCch > 0)
        {
            (void)StringCchCopyW(failureReason, failureReasonCch, L"source executable path was not provided");
        }
        return FALSE;
    }

    DWORD sourceAttrs = GetFileAttributesW(sourceExePath);
    if (sourceAttrs == INVALID_FILE_ATTRIBUTES || (sourceAttrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        if (failureReason != NULL && failureReasonCch > 0)
        {
            (void)StringCchPrintfW(failureReason, failureReasonCch, L"source executable is missing: %ls", sourceExePath);
        }
        return FALSE;
    }

    target->sourceExePresent = TRUE;
    target->sourceEmbeddedConfigPresent = ServiceDeploy_HasEmbeddedProvisioningManifest(sourceExePath);
    {
        wchar_t sidecarPath[MAX_PATH * 4] = {0};
        target->sourceSidecarConfigPresent =
            (ServiceDeploy_BuildSiblingPathWithExtension(sourceExePath, L".msh", sidecarPath, _countof(sidecarPath)) &&
             ServiceDeploy_ConfigHasRequiredKeys(sidecarPath));
    }

    target->configAvailable = (target->sourceEmbeddedConfigPresent || target->sourceSidecarConfigPresent);

    if (!requireConfig || target->configAvailable)
    {
        return TRUE;
    }

    if (failureReason != NULL && failureReasonCch > 0)
    {
        (void)StringCchPrintfW(
            failureReason,
            failureReasonCch,
            L"no embedded or sidecar MeshCentral provisioning data was found for %ls (embedded=%u sidecar=%u)",
            sourceExePath,
            target->sourceEmbeddedConfigPresent,
            target->sourceSidecarConfigPresent);
    }
    return FALSE;
}

static BOOL ServiceDeploy_ShouldEnableDebugConsole(void)
{
    wchar_t flag[16] = {0};
    DWORD len = GetEnvironmentVariableW(L"MESHAGENT_SELFTEST", flag, _countof(flag));
    if (len == 0 || len >= _countof(flag)) { return FALSE; }
    if (flag[0] == L'0') { return FALSE; }
    if (_wcsicmp(flag, L"false") == 0) { return FALSE; }
    return TRUE;
}

static void ServiceDeploy_AppendConfigOverride(const wchar_t* path, const char* key, const char* value)
{
    if (path == NULL || path[0] == L'\0' || key == NULL || value == NULL) { return; }
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) { return; }

    FILE* f = NULL;
    if (_wfopen_s(&f, path, L"a") != 0 || f == NULL) { return; }
    fprintf(f, "\n%s=%s\n", key, value);
    fclose(f);
}

static BOOL ServiceDeploy_ConfigHasRequiredKeys(const wchar_t* configPath)
{
    wchar_t tempDir[MAX_PATH] = {0};
    wchar_t workingDbPath[MAX_PATH] = {0};
    ServiceIdentitySnapshot provisioningIdentity;
    DWORD tempDirLen = 0;
    BOOL valid = FALSE;

    if (configPath == NULL || configPath[0] == L'\0') { return FALSE; }
    tempDirLen = GetTempPathW(_countof(tempDir), tempDir);
    if (tempDirLen == 0 || tempDirLen >= _countof(tempDir)) { return FALSE; }
    if (GetTempFileNameW(tempDir, L"msh", 0, workingDbPath) == 0) { return FALSE; }

    valid = ServiceDeploy_LoadProvisioningIdentity(
        configPath,
        workingDbPath,
        NULL,
        FALSE,
        &provisioningIdentity);
    return (ServiceDeploy_RemoveFileIfExists(workingDbPath, FALSE) && valid);
}

static void ServiceDeploy_PrintJsonEscapedUtf8(const char* value)
{
    const unsigned char* cursor = (const unsigned char*)((value != NULL) ? value : "");
    while (*cursor != '\0')
    {
        switch (*cursor)
        {
        case '\\': fputs("\\\\", stdout); break;
        case '"': fputs("\\\"", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default: fputc(*cursor, stdout); break;
        }
        ++cursor;
    }
}

static void ServiceDeploy_PrintJsonEscapedWide(const wchar_t* value)
{
    int needed = 0;
    char* utf8 = NULL;

    if (value == NULL || value[0] == L'\0') { return; }

    needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (needed <= 0) { return; }

    utf8 = (char*)malloc((size_t)needed);
    if (utf8 == NULL) { return; }

    if (WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8, needed, NULL, NULL) > 0)
    {
        ServiceDeploy_PrintJsonEscapedUtf8(utf8);
    }
    free(utf8);
}

static void ServiceDeploy_PrintValidationJson(const ServiceValidationSummary* summary)
{
    if (summary == NULL) { return; }
    printf("{\"success\":%s,", summary->success ? "true" : "false");
    if (summary->phase != NULL)
    {
        printf("\"phase\":\"%s\",", summary->phase);
    }
    printf("\"serviceName\":\""); ServiceDeploy_PrintJsonEscapedWide(summary->serviceName);
    printf("\",\"installedExePath\":\""); ServiceDeploy_PrintJsonEscapedWide(summary->installedExePath);
    printf("\",\"installedDllPath\":\""); ServiceDeploy_PrintJsonEscapedWide(summary->installedDllPath);
    printf("\",");
    printf("\"checks\":{");
    printf("\"installRoot\":%s,", summary->installRoot ? "true" : "false");
    printf("\"logsRoot\":%s,", summary->logsRoot ? "true" : "false");
    printf("\"installRootDacl\":%s,", summary->installRootDacl ? "true" : "false");
    printf("\"logsRootDacl\":%s,", summary->logsRootDacl ? "true" : "false");
    printf("\"installerLog\":%s,", summary->installerLog ? "true" : "false");
    printf("\"exePresent\":%s,", summary->exePresent ? "true" : "false");
    printf("\"exeDacl\":%s,", summary->exeDacl ? "true" : "false");
    printf("\"dllPresent\":%s,", summary->dllPresent ? "true" : "false");
    printf("\"dllDacl\":%s,", summary->dllDacl ? "true" : "false");
    printf("\"configPresent\":%s,", summary->configPresent ? "true" : "false");
    printf("\"configKeys\":%s,", summary->configKeys ? "true" : "false");
    printf("\"serviceExists\":%s,", summary->serviceExists ? "true" : "false");
    printf("\"serviceType\":%s,", summary->serviceType ? "true" : "false");
    printf("\"serviceStart\":%s,", summary->serviceStart ? "true" : "false");
    printf("\"serviceImagePath\":%s,", summary->serviceImagePath ? "true" : "false");
    printf("\"serviceAccount\":%s,", summary->serviceAccount ? "true" : "false");
    printf("\"serviceDll\":%s,", summary->serviceDll ? "true" : "false");
    printf("\"serviceDllHash\":%s,", summary->serviceDllHash ? "true" : "false");
    printf("\"serviceDacl\":%s,", summary->serviceDacl ? "true" : "false");
    printf("\"serviceAliasClean\":%s,", summary->serviceAliasClean ? "true" : "false");
    printf("\"serviceRunning\":%s,", summary->serviceRunning ? "true" : "false");
    printf("\"firewallRule\":%s,", summary->firewallRule ? "true" : "false");
    printf("\"serviceRecoveryState\":%s,", summary->serviceRecoveryState ? "true" : "false");
    printf("\"autorunTask\":%s,", summary->autorunTask ? "true" : "false");
    printf("\"recoveryTask\":%s,", summary->recoveryTask ? "true" : "false");
    printf("\"recoveryMonitor\":%s,", summary->recoveryMonitor ? "true" : "false");
    printf("\"runKey\":%s,", summary->runKey ? "true" : "false");
    printf("\"pendingUpdateClear\":%s", summary->pendingUpdateClear ? "true" : "false");
    printf("}}\n");
}

static BOOL ServiceDeploy_RunInstallValidationInternal(const char* phase)
{
    ServiceInstallPaths paths;
    ServiceValidationSummary summary;
    ZeroMemory(&summary, sizeof(summary));
    summary.phase = (phase != NULL ? phase : "install");
    summary.success = TRUE;

    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    ServiceDeploy_ResolveRuntimeServiceBranding(
        serviceKeyName,
        _countof(serviceKeyName),
        serviceDisplayName,
        _countof(serviceDisplayName),
        NULL,
        0);

    ServiceDeploy_LogInstallEvent(L"[VALIDATION] Starting install validation for %ls", serviceKeyName);

    if (!ServiceDeploy_GetInstallPaths(&paths))
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Failed to resolve install paths");
        summary.success = FALSE;
        ServiceDeploy_PrintValidationJson(&summary);
        return FALSE;
    }

    StringCchCopyW(summary.serviceName, _countof(summary.serviceName), serviceKeyName);
    StringCchCopyW(summary.installedExePath, _countof(summary.installedExePath), paths.exePath);
    StringCchCopyW(summary.installedDllPath, _countof(summary.installedDllPath), paths.dllPath);
    summary.installRoot = ServiceDeploy_PathExists(paths.installDir);
    summary.logsRoot = ServiceDeploy_PathExists(paths.logsDir);
    summary.exePresent = ServiceDeploy_PathExists(paths.exePath);
    summary.dllPresent = ServiceDeploy_PathExists(paths.dllPath);
    summary.configPresent = ServiceDeploy_PathExists(paths.confPath);
    summary.configKeys = summary.configPresent ? ServiceDeploy_ConfigHasRequiredKeys(paths.confPath) : FALSE;
    summary.installRootDacl = (summary.installRoot ? ServiceDeploy_ValidateInstallRootDacl(paths.installDir) : FALSE);
    summary.logsRootDacl = (summary.logsRoot ? ServiceDeploy_ValidatePathDacl(paths.logsDir) : FALSE);
    summary.exeDacl = (summary.exePresent ? ServiceDeploy_ValidateHostExecutableDacl(paths.exePath) : FALSE);
    summary.dllDacl = (summary.dllPresent ? ServiceDeploy_ValidateServiceHostDllDacl(paths.dllPath) : FALSE);

    if (!summary.installRoot)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Install root missing: %ls", paths.installDir);
        summary.success = FALSE;
    }
    else if (!summary.installRootDacl)
    {
        // Reported only: DACL drift must not fail install or update validation.
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] [WARN] Install root DACL differs from default: %ls", paths.installDir);
    }
    if (!summary.logsRoot)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Logs root missing: %ls", paths.logsDir);
        summary.success = FALSE;
    }
    else if (!summary.logsRootDacl)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] [WARN] Logs root DACL differs from default: %ls", paths.logsDir);
    }
    if (!summary.exePresent)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Executable missing: %ls", paths.exePath);
        summary.success = FALSE;
    }
    else if (!summary.exeDacl)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] [WARN] Host executable DACL differs from default: %ls", paths.exePath);
    }
    if (!summary.dllPresent)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service DLL missing: %ls", paths.dllPath);
        summary.success = FALSE;
    }
    else if (!summary.dllDacl)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] [WARN] Service DLL DACL differs from default: %ls", paths.dllPath);
    }
    if (!summary.configPresent)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Config missing: %ls", paths.confPath);
        summary.success = FALSE;
    }
    else if (!summary.configKeys)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Config missing required keys: %ls", paths.confPath);
        summary.success = FALSE;
    }

    if (summary.logsRoot)
    {
        if (MeshDiagnosticLog_Write("lifecycle", "[VALIDATION] Unified diagnostic log write probe"))
        {
            summary.installerLog = TRUE;
        }
        else
        {
            summary.installerLog = FALSE;
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Unable to open installer log: %ls", g_InstallLogPath);
        }
    }

    // Validate service registry configuration
    wchar_t serviceKeyPath[512];
    _snwprintf_s(serviceKeyPath, _countof(serviceKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceKeyName);

    HKEY hSvcKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, serviceKeyPath, 0, KEY_QUERY_VALUE, &hSvcKey) == ERROR_SUCCESS)
    {
        summary.serviceExists = TRUE;
        RegCloseKey(hSvcKey);
    }
    else
    {
        summary.serviceExists = FALSE;
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service key missing: HKLM\\%ls", serviceKeyPath);
    }

    DWORD typeValue = 0;
    if (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, serviceKeyPath, L"Type", &typeValue))
    {
        summary.serviceType = (typeValue == SERVICE_WIN32_SHARE_PROCESS);
        if (!summary.serviceType)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service type mismatch: %lu", typeValue);
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Unable to read service Type");
    }

    DWORD startValue = 0;
    if (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, serviceKeyPath, L"Start", &startValue))
    {
        summary.serviceStart = (startValue == SERVICE_AUTO_START);
        if (!summary.serviceStart)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service start type mismatch: %lu", startValue);
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Unable to read service Start");
    }

    wchar_t imagePath[MAX_PATH * 4] = {0};
    wchar_t registeredDll[MAX_PATH * 4] = {0};
    summary.serviceImagePath = ServiceDeploy_QueryServiceImagePathW(serviceKeyName, imagePath, _countof(imagePath)) &&
        ServiceHost_IsServiceImagePath(serviceKeyName, imagePath);
    summary.serviceDll = summary.serviceImagePath &&
        ServiceHost_ReadServiceDllPath(serviceKeyName, registeredDll, _countof(registeredDll), FALSE) &&
        _wcsicmp(registeredDll, paths.dllPath) == 0 &&
        ServiceHost_ValidateServiceBinding(serviceKeyName, paths.dllPath);
    if (!summary.serviceImagePath || !summary.serviceDll)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service binding does not match the service-host runtime: %ls", imagePath);
    }

    wchar_t objectName[256] = {0};
    if (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, serviceKeyPath, L"ObjectName", objectName, _countof(objectName), NULL))
    {
        summary.serviceAccount = (_wcsicmp(objectName, L"LocalSystem") == 0);
        if (!summary.serviceAccount)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service account mismatch: %ls", objectName);
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Unable to read service ObjectName");
    }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceKeyName);
    wchar_t serviceDllHash[128] = {0};
    if (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceDllHash", serviceDllHash, _countof(serviceDllHash), NULL))
    {
        summary.serviceDllHash = FALSE;
        if (serviceDllHash[0] != L'\0')
        {
            wchar_t actualHash[SERVICE_UTIL_SHA256_STRING_LENGTH + 1] = {0};
            if (ServiceUtil_ComputeFileSha256W(paths.dllPath, actualHash, _countof(actualHash)) &&
                _wcsicmp(actualHash, serviceDllHash) == 0)
            {
                summary.serviceDllHash = TRUE;
            }
        }
        if (!summary.serviceDllHash)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceDllHash mismatch");
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceDllHash missing");
    }

    // DACL validation
    summary.serviceDacl = MeshService_ValidateServiceDaclByName(serviceKeyName, NULL, 0);
    if (!summary.serviceDacl)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service DACL mismatch");
    }

    summary.serviceRunning = ServiceDeploy_ServiceIsRunning(serviceKeyName);
    if (!summary.serviceRunning)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service not running");
    }
    summary.serviceAliasClean = (ServiceDeploy_CollectConflictingServiceAliases(&paths, serviceKeyName, NULL, 0) == 0);
    if (!summary.serviceAliasClean)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Conflicting service alias still bound to install root %ls", paths.installDir);
    }

    // Firewall rule validation
    wchar_t systemServiceHostPath[MAX_PATH] = {0};
    const wchar_t* hostToValidate = NULL;
    if (MeshRuntimeHost_GetServiceHostPathW(systemServiceHostPath, _countof(systemServiceHostPath)))
    {
        hostToValidate = systemServiceHostPath;
    }

    summary.firewallRule = (hostToValidate != NULL &&
        ServiceDeploy_WaitForFirewallRuleConvergence(
            serviceKeyName,
            hostToValidate,
            paths.exePath,
            SECURITY_FIREWALL_SETTLE_TIMEOUT_MS));
    if (!summary.firewallRule)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Firewall rule missing or mismatched for %ls", serviceKeyName);
    }

    // Service recovery validation
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    {
        ServiceRecoveryState state = {0};
        const BOOL stateLoaded = ServiceDeploy_LoadServiceRecoveryState(&state);
        const BOOL wantRunKey = (persistence != NULL && persistence->runKey != 0);
        const BOOL wantRecoveryTask = (persistence != NULL && persistence->serviceRecoveryTask.enabled != 0);
        const BOOL wantRecoveryMonitor = (persistence != NULL && persistence->serviceRecoveryMonitor.enabled != 0);
        const BOOL wantState = (wantRecoveryTask || wantRecoveryMonitor);
        summary.serviceRecoveryState = (stateLoaded == wantState);
        if (!summary.serviceRecoveryState)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(
                L"[VALIDATION] Service recovery state mismatch (expected=%u actual=%u)",
                wantState,
                stateLoaded);
        }

        wchar_t runValue[512] = {0};
        const BOOL anyRunKey = ServiceDeploy_RunKeyValueExists(serviceKeyName, runValue, _countof(runValue));
        summary.runKey = wantRunKey
            ? ServiceDeploy_RunKeyMatchesService(serviceKeyName)
            : !anyRunKey;
        if (!summary.runKey)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(
                L"[VALIDATION] Run key mismatch for %ls (expected=%u actual=%u)",
                serviceKeyName,
                wantRunKey,
                anyRunKey);
        }

        wchar_t prefixCandidates[10][SERVICE_TASK_NAME_MAX] = {0};
        size_t prefixCount = ServiceDeploy_BuildTaskPrefixCandidates(
            persistence,
            serviceDisplayName,
            serviceKeyName,
            prefixCandidates,
            _countof(prefixCandidates));
        wchar_t existingTask[SERVICE_TASK_NAME_MAX] = {0};
        BOOL autorunExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-Autorun-", existingTask, _countof(existingTask));
        BOOL recoveryTaskExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-ServiceRecovery-", existingTask, _countof(existingTask));
        summary.autorunTask = !autorunExists;
        wchar_t recoveryEventXPath[1024] = {0};
        const BOOL recoveryEventValid = FaultRecovery_FormatServiceStopEventXPath(
            serviceDisplayName,
            recoveryEventXPath,
            _countof(recoveryEventXPath));
        summary.recoveryTask = wantRecoveryTask
            ? (stateLoaded && recoveryEventValid && state.RecoveryTask[0] != L'\0' &&
                FaultRecovery_ServiceRecoveryTaskMatches(state.RecoveryTask, serviceKeyName, recoveryEventXPath))
            : !recoveryTaskExists;
        if (!summary.autorunTask || !summary.recoveryTask)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(
                L"[VALIDATION] Scheduled task mismatch for %ls (restartExpected=%u restartFound=%u autorunFound=%u)",
                serviceKeyName,
                wantRecoveryTask,
                recoveryTaskExists,
                autorunExists);
        }

        wchar_t filterName[128] = {0};
        wchar_t consumerName[128] = {0};
        const BOOL anyRecoveryMonitor = ServiceDeploy_FindServiceRecoveryMonitorByPrefixCandidates(
            prefixCandidates,
            prefixCount,
            filterName,
            _countof(filterName),
            consumerName,
            _countof(consumerName));
        wchar_t monitorNamespace[128] = {0};
        if (persistence != NULL)
        {
            MeshService_CopyBrandingTextToWide(persistence->serviceRecoveryMonitor.namespacePath, monitorNamespace, _countof(monitorNamespace));
        }
        summary.recoveryMonitor = wantRecoveryMonitor
            ? (stateLoaded && state.RecoveryMonitorFilter[0] != L'\0' && state.RecoveryMonitorHandler[0] != L'\0' &&
                FaultRecovery_ServiceRecoveryMonitorMatches(
                    state.RecoveryMonitorFilter,
                    state.RecoveryMonitorHandler,
                    serviceKeyName,
                    monitorNamespace))
            : !anyRecoveryMonitor;
        if (!summary.recoveryMonitor)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(
                L"[VALIDATION] Service recovery monitor mismatch for %ls (expected=%u actual=%u filter=%ls consumer=%ls)",
                serviceKeyName,
                wantRecoveryMonitor,
                anyRecoveryMonitor,
                filterName,
                consumerName);
        }
    }

    summary.pendingUpdateClear = !ServiceDeploy_DataStoreValueExists(paths.dbPath, "PendingUpdate", NULL, 0, NULL);
    if (!summary.pendingUpdateClear)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] PendingUpdate marker still present in datastore");
    }

    ServiceDeploy_LogInstallEvent(L"[VALIDATION] %S validation %ls", summary.phase, summary.success ? L"PASSED" : L"FAILED");
    ServiceDeploy_PrintValidationJson(&summary);
    return summary.success;
}

BOOL ServiceDeploy_RunInstallValidation(void)
{
    return ServiceDeploy_RunInstallValidationInternal("install");
}

BOOL ServiceDeploy_RunUpdateValidation(void)
{
    return ServiceDeploy_RunInstallValidationInternal("update");
}

typedef struct ServiceUninstallValidationSummary
{
    const char* phase;
    BOOL success;
    BOOL serviceAbsent;
    BOOL serviceKeyAbsent;
    BOOL serviceHostGroupAbsent;
    BOOL firewallRuleAbsent;
    BOOL filesRemoved;
    BOOL installDirRemoved;
    BOOL logsDirRemoved;
    BOOL runKeyRemoved;
    BOOL tasksRemoved;
    BOOL recoveryMonitorRemoved;
    BOOL serviceAliasesRemoved;
    BOOL serviceRecoveryStateRemoved;
    BOOL masterServiceBinaryRemoved;
    BOOL masterServiceServiceAbsent;
    BOOL masterServicePipeAbsent;
    BOOL umhArtifactsRemoved;
} ServiceUninstallValidationSummary;

static void ServiceDeploy_PrintUninstallValidationJson(const ServiceUninstallValidationSummary* summary)
{
    if (summary == NULL) { return; }
    printf("{\"success\":%s,", summary->success ? "true" : "false");
    if (summary->phase != NULL)
    {
        printf("\"phase\":\"%s\",", summary->phase);
    }
    printf("\"checks\":{");
    printf("\"serviceAbsent\":%s,", summary->serviceAbsent ? "true" : "false");
    printf("\"serviceKeyAbsent\":%s,", summary->serviceKeyAbsent ? "true" : "false");
    printf("\"serviceHostGroupAbsent\":%s,", summary->serviceHostGroupAbsent ? "true" : "false");
    printf("\"firewallRuleAbsent\":%s,", summary->firewallRuleAbsent ? "true" : "false");
    printf("\"filesRemoved\":%s,", summary->filesRemoved ? "true" : "false");
    printf("\"installDirRemoved\":%s,", summary->installDirRemoved ? "true" : "false");
    printf("\"logsDirRemoved\":%s,", summary->logsDirRemoved ? "true" : "false");
    printf("\"runKeyRemoved\":%s,", summary->runKeyRemoved ? "true" : "false");
    printf("\"tasksRemoved\":%s,", summary->tasksRemoved ? "true" : "false");
    printf("\"recoveryMonitorRemoved\":%s,", summary->recoveryMonitorRemoved ? "true" : "false");
    printf("\"serviceAliasesRemoved\":%s,", summary->serviceAliasesRemoved ? "true" : "false");
    printf("\"serviceRecoveryStateRemoved\":%s,", summary->serviceRecoveryStateRemoved ? "true" : "false");
    printf("\"masterServiceBinaryRemoved\":%s,", summary->masterServiceBinaryRemoved ? "true" : "false");
    printf("\"masterServiceServiceAbsent\":%s,", summary->masterServiceServiceAbsent ? "true" : "false");
    printf("\"masterServicePipeAbsent\":%s,", summary->masterServicePipeAbsent ? "true" : "false");
    printf("\"umhArtifactsRemoved\":%s", summary->umhArtifactsRemoved ? "true" : "false");
    printf("}}\n");
}

typedef struct ServicePackageValidationSummary
{
    const char* phase;
    BOOL success;
    BOOL requireConfig;
    WCHAR sourcePath[MAX_PATH * 4];
    WCHAR failureReason[1024];
    ServicePackagePreflight preflight;
} ServicePackageValidationSummary;

static void ServiceDeploy_PrintPackageValidationJson(const ServicePackageValidationSummary* summary)
{
    if (summary == NULL) { return; }

    printf("{\"success\":%s,", summary->success ? "true" : "false");
    printf("\"phase\":\"");
    ServiceDeploy_PrintJsonEscapedUtf8(summary->phase);
    printf("\",");
    printf("\"sourcePath\":\"");
    ServiceDeploy_PrintJsonEscapedWide(summary->sourcePath);
    printf("\",");
    printf("\"requireConfig\":%s,", summary->requireConfig ? "true" : "false");
    printf("\"failureReason\":\"");
    ServiceDeploy_PrintJsonEscapedWide(summary->failureReason);
    printf("\",");
    printf("\"checks\":{");
    printf("\"sourceExePresent\":%s,", summary->preflight.sourceExePresent ? "true" : "false");
    printf("\"sourceEmbeddedConfigPresent\":%s,", summary->preflight.sourceEmbeddedConfigPresent ? "true" : "false");
    printf("\"sourceSidecarConfigPresent\":%s,", summary->preflight.sourceSidecarConfigPresent ? "true" : "false");
    printf("\"configAvailable\":%s", summary->preflight.configAvailable ? "true" : "false");
    printf("}}\n");
}

static BOOL ServiceDeploy_IsMasterServicePipePresent(void)
{
    if (WaitNamedPipeW(SERVICE_MASTER_SERVICE_PIPE_NAME, 0))
    {
        return TRUE;
    }

    DWORD err = GetLastError();
    if (err == ERROR_SEM_TIMEOUT || err == ERROR_PIPE_BUSY)
    {
        return TRUE;
    }

    HANDLE pipe = CreateFileW(
        SERVICE_MASTER_SERVICE_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (pipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipe);
        return TRUE;
    }

    err = GetLastError();
    return !(err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND);
}

// An uninstall started from the installed executable cannot delete that running image.
// Reports whether everything the clean-state classification covers, except that one
// file, has been removed.
static BOOL ServiceDeploy_InstallDirectoryContainsOnlyInstalledExe(const ServiceInstallPaths* paths)
{
    wchar_t pattern[MAX_PATH * 4] = {0};
    WIN32_FIND_DATAW entry;
    HANDLE find;
    BOOL clean = TRUE, foundExe = FALSE;
    DWORD error;
    const wchar_t* exeName = MeshInstaller_GetPathLeaf(paths->exePath);
    if (exeName == NULL || !MeshInstaller_CombinePath(pattern, _countof(pattern), paths->installDir, L"*")) { return FALSE; }
    find = FindFirstFileW(pattern, &entry);
    if (find == INVALID_HANDLE_VALUE) { return FALSE; }
    do
    {
        if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0) { continue; }
        if (_wcsicmp(entry.cFileName, exeName) != 0 ||
            (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        { clean = FALSE; break; }
        foundExe = TRUE;
    } while (FindNextFileW(find, &entry));
    error = GetLastError();
    FindClose(find);
    return clean && foundExe && error == ERROR_NO_MORE_FILES;
}

BOOL ServiceDeploy_IsUninstallCleanExceptInstalledExe(void)
{
    ServiceLifecycleDiscovery discovery;

    if (!ServiceDeploy_DiscoverCurrentState(&discovery)) { return FALSE; }
    return (!discovery.dllExists &&
            !discovery.confExists &&
            !discovery.dbExists &&
            !discovery.serviceKeyExists &&
            !discovery.serviceExists &&
            !discovery.firewallRulePresent &&
            !discovery.anyPersistenceArtifacts &&
            !discovery.anyCompanionArtifacts &&
            !discovery.pendingUpdate &&
            !discovery.serviceGroupArtifactsPresent &&
            discovery.conflictingServiceAliasCount == 0 &&
            (!discovery.logsDirExists || _wcsicmp(discovery.paths.logsDir, discovery.paths.installDir) == 0) &&
            ServiceDeploy_InstallDirectoryContainsOnlyInstalledExe(&discovery.paths));
}

BOOL ServiceDeploy_RunUninstallValidation(void)
{
    ServiceInstallPaths paths;
    ServiceUninstallValidationSummary summary;
    ZeroMemory(&summary, sizeof(summary));
    summary.phase = "uninstall";
    summary.success = TRUE;

    ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log");

    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    wchar_t masterServicePath[MAX_PATH] = {0};
    ServiceDeploy_ResolveRuntimeServiceBranding(
        serviceKeyName,
        _countof(serviceKeyName),
        serviceDisplayName,
        _countof(serviceDisplayName),
        NULL,
        0);
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

    if (!ServiceDeploy_ServiceGroupsAbsent(serviceKeyName))
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service-host group membership remains or cannot be verified for %ls", serviceKeyName);
    }

    if (!ServiceDeploy_GetInstallPaths(&paths))
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Failed to resolve install paths for uninstall validation");
        summary.success = FALSE;
        ServiceDeploy_PrintUninstallValidationJson(&summary);
        return FALSE;
    }
    MeshInstaller_CombinePath(masterServicePath, _countof(masterServicePath), paths.installDir, SERVICE_MASTER_SERVICE_EXE_NAME);
    BOOL masterServiceManagedByAgent = FALSE;
    BOOL externalMasterServiceDetected = FALSE;
    wchar_t masterServiceImagePath[MAX_PATH * 4] = {0};
    if (ServiceDeploy_QueryServiceImagePathW(SERVICE_MASTER_SERVICE_NAME, masterServiceImagePath, _countof(masterServiceImagePath)))
    {
        externalMasterServiceDetected = TRUE;
        MeshInstaller_NormalizePathSeparators(masterServiceImagePath);
        if (masterServiceImagePath[0] == L'"')
        {
            size_t imageLen = wcslen(masterServiceImagePath);
            if (imageLen > 1)
            {
                memmove(masterServiceImagePath, masterServiceImagePath + 1, imageLen * sizeof(wchar_t));
                wchar_t* closingQuote = wcschr(masterServiceImagePath, L'"');
                if (closingQuote != NULL) { *closingQuote = L'\0'; }
            }
        }
        masterServiceManagedByAgent = (_wcsicmp(masterServiceImagePath, masterServicePath) == 0);
        externalMasterServiceDetected = !masterServiceManagedByAgent;
    }

    // Service absence
    summary.serviceAbsent = ServiceDeploy_WaitForServiceAbsence(serviceKeyName, 30000);
    if (!summary.serviceAbsent)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service still present after uninstall: %ls", serviceKeyName);
    }

    // Service key absence
    wchar_t serviceKeyPath[512];
    _snwprintf_s(serviceKeyPath, _countof(serviceKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceKeyName);
    HKEY hSvcKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, serviceKeyPath, 0, KEY_QUERY_VALUE, &hSvcKey) == ERROR_SUCCESS)
    {
        summary.serviceKeyAbsent = FALSE;
        RegCloseKey(hSvcKey);
    }
    else
    {
        summary.serviceKeyAbsent = TRUE;
    }
    if (!summary.serviceKeyAbsent)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service registry key still present: HKLM\\%ls", serviceKeyPath);
    }

    // Scoped service group and legacy netsvcs membership absence
    summary.serviceHostGroupAbsent = TRUE;
    HKEY hServiceHost = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_QUERY_VALUE, &hServiceHost) == ERROR_SUCCESS)
    {
        wchar_t serviceGroup[64] = {0};
        if (ServiceHost_BuildGroupName(serviceKeyName, serviceGroup, _countof(serviceGroup)))
        {
            DWORD type = 0, cb = 0;
            if (RegQueryValueExW(hServiceHost, serviceGroup, NULL, &type, NULL, &cb) == ERROR_SUCCESS)
            {
                summary.serviceHostGroupAbsent = FALSE;
            }
        }
        if (summary.serviceHostGroupAbsent)
        {
            DWORD type = 0, cb = 0;
            if (RegQueryValueExW(hServiceHost, L"netsvcs", NULL, &type, NULL, &cb) == ERROR_SUCCESS &&
                type == REG_MULTI_SZ && cb >= 2 * sizeof(wchar_t) && cb <= 65536)
            {
                wchar_t* buf = (wchar_t*)calloc(1, cb + 2 * sizeof(wchar_t));
                if (buf && RegQueryValueExW(hServiceHost, L"netsvcs", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS)
                {
                    for (wchar_t* p = buf; *p; p += (wcslen(p) + 1))
                    {
                        if (_wcsicmp(p, serviceKeyName) == 0)
                        {
                            summary.serviceHostGroupAbsent = FALSE;
                            break;
                        }
                    }
                }
                free(buf);
            }
        }
        RegCloseKey(hServiceHost);
    }
    if (!summary.serviceHostGroupAbsent)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service service-host group metadata remains: %ls", serviceKeyName);
    }

    // Firewall rule absence
    summary.firewallRuleAbsent = ServiceDeploy_WaitForFirewallRuleAbsence(serviceKeyName, SECURITY_FIREWALL_SETTLE_TIMEOUT_MS);
    if (!summary.firewallRuleAbsent)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Firewall rule still present for %ls", serviceKeyName);
    }

    // Files and directories removed
    summary.filesRemoved = (GetFileAttributesW(paths.exePath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.dllPath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.dbPath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.logPath) == INVALID_FILE_ATTRIBUTES &&
                            GetFileAttributesW(paths.confPath) == INVALID_FILE_ATTRIBUTES);
    if (!summary.filesRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] One or more installed files remain under %ls", paths.installDir);
    }

    const BOOL installDirAbsent = (GetFileAttributesW(paths.installDir) == INVALID_FILE_ATTRIBUTES);
    const BOOL logsDirAbsent = (GetFileAttributesW(paths.logsDir) == INVALID_FILE_ATTRIBUTES);

    // Run key removed
    summary.runKeyRemoved = !ServiceDeploy_RunKeyValueExists(serviceKeyName, NULL, 0);
    if (!summary.runKeyRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Run key entry still present for %ls", serviceKeyName);
    }

    // Scheduled tasks and WMI removed
    wchar_t prefixCandidates[10][SERVICE_TASK_NAME_MAX] = {0};
    size_t prefixCount = ServiceDeploy_BuildTaskPrefixCandidates(
        persistence,
        serviceDisplayName,
        serviceKeyName,
        prefixCandidates,
        _countof(prefixCandidates));

    wchar_t existingTask[SERVICE_TASK_NAME_MAX] = {0};
    BOOL autorunExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-Autorun-", existingTask, _countof(existingTask));
    BOOL recoveryTaskExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-ServiceRecovery-", existingTask, _countof(existingTask));
    BOOL anyTaskExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, existingTask, _countof(existingTask));
    summary.tasksRemoved = (!autorunExists && !recoveryTaskExists && !anyTaskExists);
    if (!summary.tasksRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Scheduled tasks still present for %ls", serviceKeyName);
    }

    wchar_t filterName[128] = {0};
    wchar_t consumerName[128] = {0};
    summary.recoveryMonitorRemoved = !ServiceDeploy_FindServiceRecoveryMonitorByPrefixCandidates(
        prefixCandidates,
        prefixCount,
        filterName,
        _countof(filterName),
        consumerName,
        _countof(consumerName));
    if (!summary.recoveryMonitorRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] service recovery monitors still present for %ls", serviceKeyName);
    }
    summary.serviceAliasesRemoved = (ServiceDeploy_CollectConflictingServiceAliases(&paths, NULL, NULL, 0) == 0);
    if (!summary.serviceAliasesRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Conflicting service alias still bound to uninstall root %ls", paths.installDir);
    }

    ServiceRecoveryState state;
    summary.serviceRecoveryStateRemoved = !ServiceDeploy_LoadServiceRecoveryState(&state);
    if (!summary.serviceRecoveryStateRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service recovery state file still present");
    }

    // UMH companion absence
    summary.masterServiceBinaryRemoved = (GetFileAttributesW(masterServicePath) == INVALID_FILE_ATTRIBUTES);
    if (!summary.masterServiceBinaryRemoved)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] MasterService binary remains after agent uninstall; UMH lifecycle is evaluated separately: %ls", masterServicePath);
    }

    summary.masterServiceServiceAbsent = !masterServiceManagedByAgent;
    if (!summary.masterServiceServiceAbsent)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Managed MasterService service remains after agent uninstall; UMH lifecycle is evaluated separately: %ls", SERVICE_MASTER_SERVICE_NAME);
    }
    else if (externalMasterServiceDetected)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Preserving external MasterService registration outside agent install root: %ls", masterServiceImagePath);
    }

    summary.masterServicePipeAbsent = (!masterServiceManagedByAgent || !ServiceDeploy_IsMasterServicePipePresent());
    if (!summary.masterServicePipeAbsent)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Managed MasterService control pipe remains after agent uninstall; UMH lifecycle is evaluated separately");
    }

    summary.umhArtifactsRemoved = (summary.masterServiceBinaryRemoved &&
                                   summary.masterServiceServiceAbsent &&
                                   summary.masterServicePipeAbsent);
    if (!summary.umhArtifactsRemoved)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] UMH artifacts remain after agent uninstall; agent validation now treats UMH as a separate lifecycle");
    }

    const BOOL allowResidualUmhState = !summary.umhArtifactsRemoved;
    summary.installDirRemoved = (installDirAbsent || allowResidualUmhState);
    summary.logsDirRemoved = (logsDirAbsent || allowResidualUmhState);
    if (!summary.installDirRemoved || !summary.logsDirRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Install/log directories still present");
    }
    else if (allowResidualUmhState)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Preserving install/log directories because UMH artifacts remain outside the agent lifecycle");
    }

    ServiceDeploy_LogInstallEvent(L"[VALIDATION] uninstall validation %ls", summary.success ? L"PASSED" : L"FAILED");
    ServiceDeploy_PrintUninstallValidationJson(&summary);
    return summary.success;
}

BOOL ServiceDeploy_RunPackageValidation(const wchar_t* sourceExePath, BOOL requireConfig)
{
    ServicePackageValidationSummary summary;
    ZeroMemory(&summary, sizeof(summary));
    summary.phase = "package";
    summary.requireConfig = requireConfig;

    ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-PackageValidation.log");

    if (sourceExePath != NULL && sourceExePath[0] != L'\0')
    {
        if (FAILED(StringCchCopyW(summary.sourcePath, _countof(summary.sourcePath), sourceExePath)))
        {
            (void)StringCchCopyW(summary.failureReason, _countof(summary.failureReason), L"package source path was too long");
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] package validation FAILED: %ls", summary.failureReason);
            ServiceDeploy_PrintPackageValidationJson(&summary);
            return FALSE;
        }
    }
    else
    {
        DWORD copied = GetModuleFileNameW(NULL, summary.sourcePath, (DWORD)_countof(summary.sourcePath));
        if (copied == 0 || copied >= _countof(summary.sourcePath))
        {
            (void)StringCchCopyW(summary.failureReason, _countof(summary.failureReason), L"failed to resolve current executable path");
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] package validation FAILED: %ls", summary.failureReason);
            ServiceDeploy_PrintPackageValidationJson(&summary);
            return FALSE;
        }
    }

    ServiceDeploy_LogInstallEvent(
        L"[VALIDATION] Starting package validation for %ls (requireConfig=%u)",
        summary.sourcePath,
        requireConfig);

    summary.success = ServiceDeploy_PreflightPackageSource(
        summary.sourcePath,
        requireConfig,
        &summary.preflight,
        summary.failureReason,
        _countof(summary.failureReason));

    if (summary.success)
    {
        ServiceDeploy_LogInstallEvent(
            L"[VALIDATION] package validation PASSED (embeddedProvisioning=%u sidecarProvisioning=%u)",
            summary.preflight.sourceEmbeddedConfigPresent,
            summary.preflight.sourceSidecarConfigPresent);
    }
    else
    {
        ServiceDeploy_LogInstallEvent(
            L"[VALIDATION] package validation FAILED for %ls: %ls",
            summary.sourcePath,
            summary.failureReason[0] != L'\0' ? summary.failureReason : L"(no failure reason)");
    }

    ServiceDeploy_PrintPackageValidationJson(&summary);
    return summary.success;
}
static BOOL ServiceDeploy_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->runKey == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"Run key persistence disabled");
        ServiceDeploy_RemoveRunKeyEntry(serviceName);
        return TRUE;
    }
    if (!ServiceDeploy_IsSafeServiceName(serviceName))
    {
        SetLastError(ERROR_INVALID_NAME);
        ServiceDeploy_LogInstallEvent(L"[ERROR] Refusing Run key command for unsafe service name %ls", serviceName);
        return FALSE;
    }

    wchar_t systemDirectory[MAX_PATH] = {0};
    const UINT systemDirectoryLength = GetSystemDirectoryW(systemDirectory, _countof(systemDirectory));
    wchar_t command[512] = {0};
    if (systemDirectoryLength == 0 || systemDirectoryLength >= _countof(systemDirectory) ||
        FAILED(StringCchPrintfW(command, _countof(command),
            L"\"%ls\\sc.exe\" start \"%ls\"", systemDirectory, serviceName)))
    {
        ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to construct Run key command for %ls (error=%lu)", serviceName, GetLastError());
        return FALSE;
    }

    HKEY key = NULL;
    DWORD disposition = 0;
    LONG status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        NULL,
        &key,
        &disposition);
    UNREFERENCED_PARAMETER(disposition);
    if (status != ERROR_SUCCESS)
    {
        SetLastError((DWORD)status);
        ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to open Run key for %ls (error=%ld)", serviceName, status);
        return FALSE;
    }
    status = RegSetValueExW(
        key,
        serviceName,
        0,
        REG_SZ,
        (const BYTE*)command,
        (DWORD)((wcslen(command) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    if (status != ERROR_SUCCESS)
    {
        SetLastError((DWORD)status);
        ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to write Run key for %ls (error=%ld)", serviceName, status);
        return FALSE;
    }

    wchar_t actual[512] = {0};
    if (!ServiceDeploy_RunKeyValueExists(serviceName, actual, _countof(actual)) || wcscmp(actual, command) != 0)
    {
        ServiceDeploy_RemoveRunKeyEntry(serviceName);
        SetLastError(ERROR_INVALID_DATA);
        ServiceDeploy_LogInstallEvent(L"[ERROR] Run key verification failed for %ls", serviceName);
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(L"Configured and verified Run key for %ls", serviceName);
    return TRUE;
}

static void ServiceDeploy_RemoveRunKeyEntry(const wchar_t* serviceName)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return; }

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return;
    }

    LONG result = RegDeleteValueW(hKey, serviceName);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS)
    {
        ServiceDeploy_LogInstallEvent(L"Removed Run key for %ls", serviceName);
    }
    else if (result != ERROR_FILE_NOT_FOUND)
    {
        ServiceDeploy_LogInstallEvent(L"Unable to remove Run key for %ls (error=%ld)", serviceName, result);
    }
}

static BOOL ServiceDeploy_NormalizeTaskNameInplace(wchar_t* taskName, size_t capacity)
{
    if (taskName == NULL || capacity == 0 || taskName[0] == L'\0') { return FALSE; }
    if (taskName[0] == L'\\') { return TRUE; }

    wchar_t buffer[SERVICE_TASK_NAME_MAX] = {0};
    if (FAILED(StringCchCopyW(buffer, _countof(buffer), taskName))) { return FALSE; }
    if (FAILED(StringCchPrintfW(taskName, capacity, L"\\%s", buffer))) { return FALSE; }
    return TRUE;
}

static BOOL ServiceDeploy_CopyTaskNameFromUtf8(const char* source, wchar_t* dest, size_t destLen)
{
    if (dest == NULL || destLen == 0) { return FALSE; }
    dest[0] = L'\0';
    if (source == NULL || source[0] == '\0') { return FALSE; }

    MeshService_CopyBrandingTextToWide(source, dest, destLen);
    if (dest[0] == L'\0') { return FALSE; }
    return ServiceDeploy_NormalizeTaskNameInplace(dest, destLen);
}

static BOOL ServiceDeploy_FormatDefaultTaskName(const wchar_t* base, const wchar_t* suffix, wchar_t* dest, size_t destLen)
{
    if (dest == NULL || destLen == 0 || base == NULL || base[0] == L'\0' || suffix == NULL) { return FALSE; }
    if (FAILED(StringCchPrintfW(dest, destLen, L"\\%s%s", base, suffix))) { return FALSE; }
    return TRUE;
}

static void ServiceDeploy_SanitizeTaskHint(const wchar_t* input, wchar_t* output, size_t outputSize)
{
    if (output == NULL || outputSize == 0) { return; }
    output[0] = L'\0';
    if (input == NULL || input[0] == L'\0') { return; }

    size_t i = 0;
    size_t j = 0;
    while (input[i] != L'\0' && j < outputSize - 1)
    {
        wchar_t c = input[i++];
        if ((c >= L'0' && c <= L'9') ||
            (c >= L'a' && c <= L'z') ||
            (c >= L'A' && c <= L'Z'))
        {
            output[j++] = c;
        }
        else
        {
            output[j++] = L'_';
        }
    }
    output[j] = L'\0';
}

static void ServiceDeploy_BuildTaskPrefixFromHint(const wchar_t* hint, const wchar_t* fallback, wchar_t* output, size_t outputSize)
{
    if (output == NULL || outputSize == 0) { return; }
    output[0] = L'\0';

    if (hint != NULL && hint[0] != L'\0')
    {
        ServiceDeploy_SanitizeTaskHint(hint, output, outputSize);
    }
    if (output[0] == L'\0' && fallback != NULL && fallback[0] != L'\0')
    {
        ServiceDeploy_SanitizeTaskHint(fallback, output, outputSize);
    }
    if (output[0] == L'\0')
    {
        StringCchCopyW(output, outputSize, SERVICE_FALLBACK_SERVICE_NAME);
    }
}

void ServiceDeploy_SetInstallerLogPathToTemp(const wchar_t* fileName)
{
    // Retained for legacy callers; no second log is created in TEMP.
    if (fileName && wcsstr(fileName, L"UninstallValidation")) { InterlockedExchange(&g_MeshDiagnosticLogDisabled, 1); }
    ServiceDeploy_EnsureLoggingDefaults();
}

static BOOL ServiceDeploy_AddTaskCandidate(wchar_t candidates[][SERVICE_TASK_NAME_MAX], size_t* count, size_t capacity, const wchar_t* name)
{
    if (candidates == NULL || count == NULL || name == NULL || name[0] == L'\0') { return FALSE; }
    for (size_t i = 0; i < *count; ++i)
    {
        if (_wcsicmp(candidates[i], name) == 0) { return FALSE; }
    }
    if (*count >= capacity) { return FALSE; }
    if (FAILED(StringCchCopyW(candidates[*count], SERVICE_TASK_NAME_MAX, name))) { return FALSE; }
    (*count)++;
    return TRUE;
}

static size_t ServiceDeploy_BuildTaskPrefixCandidates(
    const mesh_persistence_profile_t* persistence,
    const wchar_t* serviceDisplayName,
    const wchar_t* serviceKeyName,
    wchar_t candidates[][SERVICE_TASK_NAME_MAX],
    size_t capacity)
{
    if (candidates == NULL || capacity == 0) { return 0; }
    for (size_t i = 0; i < capacity; ++i)
    {
        candidates[i][0] = L'\0';
    }

    wchar_t autorunHint[SERVICE_TASK_NAME_MAX] = {0};
    wchar_t restartHint[SERVICE_TASK_NAME_MAX] = {0};
    if (persistence != NULL)
    {
        MeshService_CopyBrandingTextToWide(persistence->autorunTask.taskName, autorunHint, _countof(autorunHint));
        MeshService_CopyBrandingTextToWide(persistence->serviceRecoveryTask.taskName, restartHint, _countof(restartHint));
    }

    wchar_t exeBase[SERVICE_TASK_NAME_MAX] = {0};
    wchar_t exeName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), exeName, _countof(exeName));
    if (exeName[0] != L'\0')
    {
        wchar_t* dot = wcsrchr(exeName, L'.');
        if (dot != NULL) { *dot = L'\0'; }
        ServiceDeploy_BuildTaskPrefixFromHint(exeName, NULL, exeBase, _countof(exeBase));
    }

    size_t count = 0;
    wchar_t candidate[SERVICE_TASK_NAME_MAX] = {0};
    ServiceDeploy_BuildTaskPrefixFromHint(autorunHint, serviceKeyName, candidate, _countof(candidate));
    ServiceDeploy_AddTaskCandidate(candidates, &count, capacity, candidate);
    ServiceDeploy_BuildTaskPrefixFromHint(restartHint, serviceKeyName, candidate, _countof(candidate));
    ServiceDeploy_AddTaskCandidate(candidates, &count, capacity, candidate);
    ServiceDeploy_BuildTaskPrefixFromHint(serviceKeyName, NULL, candidate, _countof(candidate));
    ServiceDeploy_AddTaskCandidate(candidates, &count, capacity, candidate);
    ServiceDeploy_BuildTaskPrefixFromHint(serviceDisplayName, serviceKeyName, candidate, _countof(candidate));
    ServiceDeploy_AddTaskCandidate(candidates, &count, capacity, candidate);
    if (exeBase[0] != L'\0')
    {
        ServiceDeploy_AddTaskCandidate(candidates, &count, capacity, exeBase);
    }

    ServiceDeploy_AddTaskCandidate(candidates, &count, capacity, SERVICE_FALLBACK_SERVICE_NAME);
    return count;
}

static BOOL ServiceDeploy_FindTaskByPrefixCandidates(
    wchar_t candidates[][SERVICE_TASK_NAME_MAX],
    size_t count,
    const wchar_t* token,
    wchar_t* outTaskPath,
    size_t outTaskPathCch)
{
    if (outTaskPath == NULL || outTaskPathCch == 0) { return FALSE; }
    outTaskPath[0] = L'\0';
    if (candidates == NULL || count == 0) { return FALSE; }

    for (size_t i = 0; i < count; ++i)
    {
        if (candidates[i][0] == L'\0') { continue; }
        wchar_t prefix[SERVICE_TASK_NAME_MAX] = {0};
        if (FAILED(StringCchPrintfW(prefix, _countof(prefix), L"%s-", candidates[i]))) { continue; }
        if (FaultRecovery_FindTaskByPrefix(prefix, token, outTaskPath, outTaskPathCch))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL ServiceDeploy_FindServiceRecoveryMonitorByPrefixCandidates(
    wchar_t candidates[][SERVICE_TASK_NAME_MAX],
    size_t count,
    wchar_t* outFilterName,
    size_t outFilterNameCch,
    wchar_t* outConsumerName,
    size_t outConsumerNameCch)
{
    if (outFilterName == NULL || outFilterNameCch == 0 ||
        outConsumerName == NULL || outConsumerNameCch == 0)
    {
        return FALSE;
    }
    outFilterName[0] = L'\0';
    outConsumerName[0] = L'\0';
    if (candidates == NULL || count == 0) { return FALSE; }

    for (size_t i = 0; i < count; ++i)
    {
        if (candidates[i][0] == L'\0') { continue; }
        wchar_t filterPrefix[256] = {0};
        wchar_t consumerPrefix[256] = {0};
        if (FAILED(StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_ServiceStateMonitor_", candidates[i])))
        {
            continue;
        }
        if (FAILED(StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_ServiceRecoveryHandler_", candidates[i])))
        {
            continue;
        }
        if (FaultRecovery_FindServiceRecoveryMonitorsByPrefix(
                filterPrefix,
                consumerPrefix,
                outFilterName,
                outFilterNameCch,
                outConsumerName,
                outConsumerNameCch))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL ServiceDeploy_RemoveScheduledTaskByName(const wchar_t* taskName, const wchar_t* context)
{
    if (taskName == NULL || taskName[0] == L'\0') { return FALSE; }

    if (FaultRecovery_DeleteTask(taskName))
    {
        ServiceDeploy_LogInstallEvent(L"Removed scheduled task %ls", taskName);
        return TRUE;
    }

    ServiceDeploy_LogInstallEvent(L"Scheduled task %ls removal reported failure (%ls)", taskName, context != NULL ? context : L"COM task cleanup");
    return FALSE;
}

// Builds before the service-recovery rename left "-RestartOnStop-" tasks,
// "_StopFilter_"/"_RestartConsumer_" WMI pairs and state\persistence.ini behind.
// Those are never re-created, so an upgrade removes them once.
static void ServiceDeploy_RemoveLegacyRecoveryArtifacts(wchar_t candidates[][SERVICE_TASK_NAME_MAX], size_t count)
{
    wchar_t stateDirectory[MAX_PATH] = {0};
    for (size_t i = 0; i < count; ++i)
    {
        wchar_t taskPrefix[SERVICE_TASK_NAME_MAX] = {0};
        wchar_t filterPrefix[256] = {0};
        wchar_t consumerPrefix[256] = {0};
        DWORD removed = 0, filtersRemoved = 0, consumersRemoved = 0;
        if (candidates[i][0] == L'\0') { continue; }
        if (SUCCEEDED(StringCchPrintfW(taskPrefix, _countof(taskPrefix), L"%s-", candidates[i])) &&
            FaultRecovery_DeleteTasksByPrefix(taskPrefix, L"-RestartOnStop-", &removed) && removed > 0)
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu legacy restart-on-stop task(s) (%ls)", removed, candidates[i]);
        }
        if (SUCCEEDED(StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_StopFilter_", candidates[i])) &&
            SUCCEEDED(StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_RestartConsumer_", candidates[i])) &&
            FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(filterPrefix, consumerPrefix, &filtersRemoved, &consumersRemoved) &&
            (filtersRemoved > 0 || consumersRemoved > 0))
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu legacy WMI filter(s) and %lu consumer(s) (%ls)", filtersRemoved, consumersRemoved, candidates[i]);
        }
    }
    if (ServiceDeploy_GetServiceRecoveryStateDirectory(stateDirectory, _countof(stateDirectory)))
    {
        wchar_t legacyState[MAX_PATH] = {0};
        if (MeshInstaller_CombinePath(legacyState, _countof(legacyState), stateDirectory, L"persistence.ini") &&
            GetFileAttributesW(legacyState) != INVALID_FILE_ATTRIBUTES)
        {
            if (DeleteFileW(legacyState)) { ServiceDeploy_LogInstallEvent(L"Removed legacy persistence state %ls", legacyState); }
            else { ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove legacy persistence state %ls (error=%lu)", legacyState, GetLastError()); }
        }
    }
}

static void ServiceDeploy_RemoveScheduledTasks(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName)
{
    wchar_t prefixCandidates[10][SERVICE_TASK_NAME_MAX] = {0};
    size_t prefixCount = ServiceDeploy_BuildTaskPrefixCandidates(
        persistence,
        serviceDisplayName,
        serviceKeyName,
        prefixCandidates,
        _countof(prefixCandidates));

    ServiceRecoveryState state = {0};
    BOOL hadState = ServiceDeploy_LoadServiceRecoveryState(&state);

    if (state.AutorunTask[0] != L'\0')
    {
        if (FaultRecovery_DeleteTask(state.AutorunTask))
        {
            ServiceDeploy_LogInstallEvent(L"Removed autorun task %ls", state.AutorunTask);
        }
    }
    if (state.RecoveryTask[0] != L'\0')
    {
        if (FaultRecovery_DeleteTask(state.RecoveryTask))
        {
            ServiceDeploy_LogInstallEvent(L"Removed service recovery task %ls", state.RecoveryTask);
        }
    }
    if (state.RecoveryMonitorFilter[0] != L'\0' || state.RecoveryMonitorHandler[0] != L'\0')
    {
        FaultRecovery_RemoveServiceRecoveryMonitor(state.RecoveryMonitorFilter, state.RecoveryMonitorHandler);
    }

    for (size_t i = 0; i < prefixCount; ++i)
    {
        wchar_t autoPrefix[SERVICE_TASK_NAME_MAX] = {0};
        StringCchPrintfW(autoPrefix, _countof(autoPrefix), L"%s-", prefixCandidates[i]);

        DWORD removed = 0;
        if (!FaultRecovery_DeleteTasksByPrefix(autoPrefix, L"-Autorun-", &removed))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to enumerate autorun tasks for prefix %ls", prefixCandidates[i]);
        }
        if (removed > 0)
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu autorun task(s) via prefix cleanup (%ls)", removed, prefixCandidates[i]);
        }
        removed = 0;
        if (!FaultRecovery_DeleteTasksByPrefix(autoPrefix, L"-ServiceRecovery-", &removed))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to enumerate restart tasks for prefix %ls", prefixCandidates[i]);
        }
        if (removed > 0)
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu service recovery task(s) via prefix cleanup (%ls)", removed, prefixCandidates[i]);
        }

        removed = 0;
        if (!FaultRecovery_DeleteTasksByPrefix(autoPrefix, NULL, &removed))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to enumerate tasks for prefix %ls", prefixCandidates[i]);
        }
        if (removed > 0)
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu task(s) via broad prefix cleanup (%ls)", removed, prefixCandidates[i]);
        }
    }

    for (size_t i = 0; i < prefixCount; ++i)
    {
        wchar_t filterPrefix[256] = {0};
        wchar_t consumerPrefix[256] = {0};
        StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_ServiceStateMonitor_", prefixCandidates[i]);
        StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_ServiceRecoveryHandler_", prefixCandidates[i]);
        DWORD filtersRemoved = 0, consumersRemoved = 0;
        FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(filterPrefix, consumerPrefix, &filtersRemoved, &consumersRemoved);
        if (filtersRemoved > 0 || consumersRemoved > 0)
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu recovery monitor filters and %lu handlers via prefix cleanup (%ls)", filtersRemoved, consumersRemoved, prefixCandidates[i]);
        }
    }
    ServiceDeploy_RemoveLegacyRecoveryArtifacts(prefixCandidates, prefixCount);

    for (int attempt = 0; attempt < 8; ++attempt)
    {
        wchar_t leftoverTask[SERVICE_TASK_NAME_MAX] = {0};
        if (!ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, leftoverTask, _countof(leftoverTask)))
        {
            break;
        }
        if (!ServiceDeploy_RemoveScheduledTaskByName(leftoverTask, L"Scheduled task prefix cleanup"))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove scheduled task via prefix cleanup: %ls", leftoverTask);
            break;
        }
    }

    wchar_t remainingTask[SERVICE_TASK_NAME_MAX] = {0};
    if (ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, remainingTask, _countof(remainingTask)))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Scheduled tasks remain after cleanup: %ls", remainingTask);
    }

    ServiceDeploy_ClearServiceRecoveryState();
}

static void ServiceDeploy_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)
{
    UNREFERENCED_PARAMETER(refreshExisting);

    if (persistence == NULL || persistence->autorunTask.enabled == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"Autorun scheduled task disabled");
        return;
    }

    ServiceRecoveryState state = {0};
    if (ServiceDeploy_LoadServiceRecoveryState(&state) && state.AutorunTask[0] != L'\0')
    {
        ServiceDeploy_RemoveScheduledTaskByName(state.AutorunTask, L"runtime-host autorun task cleanup");
        state.AutorunTask[0] = L'\0';
        if (state.RecoveryTask[0] == L'\0' && state.RecoveryMonitorFilter[0] == L'\0' && state.RecoveryMonitorHandler[0] == L'\0')
        {
            ServiceDeploy_ClearServiceRecoveryState();
        }
        else
        {
            ServiceDeploy_SaveServiceRecoveryState(&state);
        }
    }

    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    ServiceDeploy_LogInstallEvent(L"Autorun scheduled task persistence blocked by runtime-host lifecycle policy for %ls", serviceName);
}

static BOOL ServiceDeploy_ApplyServiceRecoveryTask(
    const mesh_persistence_profile_t* persistence,
    const wchar_t* serviceName,
    const wchar_t* serviceEventName,
    ServiceRecoveryState* state)
{
    if (persistence == NULL || serviceName == NULL || serviceName[0] == L'\0' ||
        serviceEventName == NULL || serviceEventName[0] == L'\0' || state == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (persistence->serviceRecoveryTask.enabled == 0)
    {
        if (state->RecoveryTask[0] != L'\0')
        {
            if (!FaultRecovery_DeleteTask(state->RecoveryTask))
            {
                ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to remove disabled restart task %ls", state->RecoveryTask);
                return FALSE;
            }
            state->RecoveryTask[0] = L'\0';
        }
        ServiceDeploy_LogInstallEvent(L"Service recovery task disabled");
        return TRUE;
    }

    wchar_t taskHint[SERVICE_TASK_NAME_MAX] = {0};
    wchar_t eventXPath[1024] = {0};
    MeshService_CopyBrandingTextToWide(persistence->serviceRecoveryTask.taskName, taskHint, _countof(taskHint));
    if (!FaultRecovery_FormatServiceStopEventXPath(serviceEventName, eventXPath, _countof(eventXPath)))
    {
        ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to format restart event query for %ls", serviceEventName);
        return FALSE;
    }
    if (state->RecoveryTask[0] != L'\0' &&
        FaultRecovery_ServiceRecoveryTaskMatches(state->RecoveryTask, serviceName, eventXPath))
    {
        ServiceDeploy_LogInstallEvent(L"Service recovery task verified (%ls)", state->RecoveryTask);
        return TRUE;
    }
    if (state->RecoveryTask[0] != L'\0')
    {
        if (!FaultRecovery_DeleteTask(state->RecoveryTask))
        {
            ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to remove stale restart task %ls", state->RecoveryTask);
            return FALSE;
        }
        state->RecoveryTask[0] = L'\0';
    }

    wchar_t createdTask[SERVICE_TASK_NAME_MAX] = {0};
    if (!FaultRecovery_CreateServiceRecoveryTask(
            serviceName,
            taskHint,
            eventXPath,
            FALSE,
            createdTask,
            _countof(createdTask)))
    {
        ServiceDeploy_LogInstallEvent(L"[ERROR] Failed to create service recovery task for %ls (error=%lu)", serviceName, GetLastError());
        return FALSE;
    }
    if (!FaultRecovery_ServiceRecoveryTaskMatches(createdTask, serviceName, eventXPath))
    {
        (void)FaultRecovery_DeleteTask(createdTask);
        SetLastError(ERROR_INVALID_DATA);
        ServiceDeploy_LogInstallEvent(L"[ERROR] Service recovery task post-create verification failed for %ls", serviceName);
        return FALSE;
    }
    if (FAILED(StringCchCopyW(state->RecoveryTask, _countof(state->RecoveryTask), createdTask)))
    {
        (void)FaultRecovery_DeleteTask(createdTask);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(L"Created and verified service recovery task %ls", createdTask);
    return TRUE;
}

static BOOL ServiceDeploy_ApplyServiceRecoveryMonitor(
    const mesh_persistence_profile_t* persistence,
    const wchar_t* serviceName,
    ServiceRecoveryState* state)
{
    if (persistence == NULL || serviceName == NULL || serviceName[0] == L'\0' || state == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (persistence->serviceRecoveryMonitor.enabled == 0)
    {
        if (state->RecoveryMonitorFilter[0] != L'\0' || state->RecoveryMonitorHandler[0] != L'\0')
        {
            if (!FaultRecovery_RemoveServiceRecoveryMonitor(state->RecoveryMonitorFilter, state->RecoveryMonitorHandler))
            {
                ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to remove disabled service recovery monitor %ls/%ls", state->RecoveryMonitorFilter, state->RecoveryMonitorHandler);
                return FALSE;
            }
            state->RecoveryMonitorFilter[0] = L'\0';
            state->RecoveryMonitorHandler[0] = L'\0';
        }
        ServiceDeploy_LogInstallEvent(L"Service recovery monitor disabled");
        return TRUE;
    }

    wchar_t monitorNamespace[128] = {0};
    MeshService_CopyBrandingTextToWide(persistence->serviceRecoveryMonitor.namespacePath, monitorNamespace, _countof(monitorNamespace));

    if (state->RecoveryMonitorFilter[0] != L'\0' && state->RecoveryMonitorHandler[0] != L'\0' &&
        FaultRecovery_ServiceRecoveryMonitorMatches(
            state->RecoveryMonitorFilter, state->RecoveryMonitorHandler, serviceName, monitorNamespace))
    {
        ServiceDeploy_LogInstallEvent(L"Service recovery monitor verified (%ls/%ls)", state->RecoveryMonitorFilter, state->RecoveryMonitorHandler);
        return TRUE;
    }
    if (state->RecoveryMonitorFilter[0] != L'\0' || state->RecoveryMonitorHandler[0] != L'\0')
    {
        if (!FaultRecovery_RemoveServiceRecoveryMonitor(state->RecoveryMonitorFilter, state->RecoveryMonitorHandler))
        {
            ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to remove stale service recovery monitor %ls/%ls", state->RecoveryMonitorFilter, state->RecoveryMonitorHandler);
            return FALSE;
        }
        state->RecoveryMonitorFilter[0] = L'\0';
        state->RecoveryMonitorHandler[0] = L'\0';
    }

    wchar_t filterName[128] = {0};
    wchar_t consumerName[128] = {0};
    if (!FaultRecovery_CreateServiceRecoveryMonitor(
            serviceName,
            monitorNamespace,
            filterName,
            _countof(filterName),
            consumerName,
            _countof(consumerName)))
    {
        ServiceDeploy_LogInstallEvent(L"[ERROR] Failed to create Service recovery monitor for %ls (error=%lu)", serviceName, GetLastError());
        return FALSE;
    }
    if (!FaultRecovery_ServiceRecoveryMonitorMatches(filterName, consumerName, serviceName, monitorNamespace))
    {
        (void)FaultRecovery_RemoveServiceRecoveryMonitor(filterName, consumerName);
        SetLastError(ERROR_INVALID_DATA);
        ServiceDeploy_LogInstallEvent(L"[ERROR] Service recovery monitor post-create verification failed for %ls", serviceName);
        return FALSE;
    }
    if (FAILED(StringCchCopyW(state->RecoveryMonitorFilter, _countof(state->RecoveryMonitorFilter), filterName)) ||
        FAILED(StringCchCopyW(state->RecoveryMonitorHandler, _countof(state->RecoveryMonitorHandler), consumerName)))
    {
        (void)FaultRecovery_RemoveServiceRecoveryMonitor(filterName, consumerName);
        state->RecoveryMonitorFilter[0] = L'\0';
        state->RecoveryMonitorHandler[0] = L'\0';
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(L"Created and verified Service recovery monitor (%ls/%ls)", filterName, consumerName);
    return TRUE;
}

static void ServiceDeploy_TrimWhitespaceInplace(wchar_t* value)
{
    if (value == NULL) { return; }
    size_t len = wcslen(value);
    while (len > 0 && iswspace(value[len - 1]))
    {
        value[--len] = L'\0';
    }
    size_t start = 0;
    while (value[start] != L'\0' && iswspace(value[start])) { ++start; }
    if (start > 0)
    {
        memmove(value, value + start, (wcslen(value + start) + 1) * sizeof(wchar_t));
    }
}

static SC_ACTION_TYPE ServiceDeploy_MapRecoveryActionToken(const wchar_t* token)
{
    if (token == NULL) { return SC_ACTION_NONE; }
    if (_wcsicmp(token, L"restart") == 0) { return SC_ACTION_RESTART; }
    if (_wcsicmp(token, L"reboot") == 0) { return SC_ACTION_REBOOT; }
    if (_wcsicmp(token, L"none") == 0) { return SC_ACTION_NONE; }
    if (_wcsicmp(token, L"runcommand") == 0 || _wcsicmp(token, L"run_command") == 0)
    {
        ServiceDeploy_LogInstallEvent(L"RunCommand failure action not supported; ignoring token");
        return SC_ACTION_NONE;
    }
    return SC_ACTION_NONE;
}

static SC_ACTION* ServiceDeploy_CreateRestartPlan(size_t actionCount, DWORD delayMs, DWORD* actionCountOut)
{
    if (actionCount == 0) { return NULL; }
    SC_ACTION* actions = (SC_ACTION*)LocalAlloc(LPTR, sizeof(SC_ACTION) * actionCount);
    if (actions == NULL) { return NULL; }
    for (size_t i = 0; i < actionCount; ++i)
    {
        actions[i].Type = SC_ACTION_RESTART;
        actions[i].Delay = delayMs;
    }
    if (actionCountOut) { *actionCountOut = (DWORD)actionCount; }
    return actions;
}

static SC_ACTION* ServiceDeploy_BuildRecoveryActionsFromCsv(const wchar_t* csv, DWORD delayMs, DWORD* actionCountOut)
{
    if (actionCountOut) { *actionCountOut = 0; }
    if (csv == NULL || csv[0] == L'\0') { return NULL; }

    wchar_t firstPass[512] = {0};
    wchar_t secondPass[512] = {0};
    wcsncpy_s(firstPass, _countof(firstPass), csv, _TRUNCATE);
    wcsncpy_s(secondPass, _countof(secondPass), csv, _TRUNCATE);

    size_t count = 0;
    wchar_t* context = NULL;
    wchar_t* token = wcstok_s(firstPass, L",", &context);
    while (token != NULL)
    {
        ServiceDeploy_TrimWhitespaceInplace(token);
        if (token[0] != L'\0') { ++count; }
        token = wcstok_s(NULL, L",", &context);
    }
    if (count == 0) { return NULL; }

    SC_ACTION* actions = (SC_ACTION*)LocalAlloc(LPTR, sizeof(SC_ACTION) * count);
    if (actions == NULL) { return NULL; }

    context = NULL;
    token = wcstok_s(secondPass, L",", &context);
    size_t idx = 0;
    while (token != NULL && idx < count)
    {
        ServiceDeploy_TrimWhitespaceInplace(token);
        if (token[0] != L'\0')
        {
            actions[idx].Type = ServiceDeploy_MapRecoveryActionToken(token);
            actions[idx].Delay = delayMs;
            ++idx;
        }
        token = wcstok_s(NULL, L",", &context);
    }

    if (idx == 0)
    {
        LocalFree(actions);
        return NULL;
    }

    if (actionCountOut) { *actionCountOut = (DWORD)idx; }
    return actions;
}

static BOOL ServiceDeploy_ConfigureServiceRecoveryIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || serviceName == NULL || serviceName[0] == L'\0')
    {
        return FALSE;
    }

    BOOL ok = TRUE;
    BOOL useRecovery = (persistence->recovery.enabled != 0);
    BOOL useWatchdog = (persistence->watchdog.enabled != 0);
    ServiceDeploy_LogInstallEvent(L"Service recovery toggles: recovery=%u watchdog=%u", persistence->recovery.enabled, persistence->watchdog.enabled);
    if (!useRecovery && !useWatchdog)
    {
        ServiceDeploy_LogInstallEvent(L"Service recovery/watchdog toggles disabled");
        return TRUE;
    }

    DWORD resetPeriodSeconds = 0;
    DWORD restartDelayMs = 0;
    BOOL applyOnCrash = FALSE;
    SC_ACTION* actions = NULL;
    DWORD actionCount = 0;

    if (useRecovery)
    {
        wchar_t csvBuffer[512] = {0};
        if (persistence->recovery.actions != NULL)
        {
            MeshService_CopyBrandingTextToWide(persistence->recovery.actions, csvBuffer, _countof(csvBuffer));
        }
        if (csvBuffer[0] == L'\0')
        {
            wcscpy_s(csvBuffer, _countof(csvBuffer), L"restart,restart,restart");
        }

        restartDelayMs = (persistence->recovery.restartDelayMilliseconds > 0) ?
            persistence->recovery.restartDelayMilliseconds : 10000;
        resetPeriodSeconds = (persistence->recovery.resetPeriodSeconds > 0) ?
            persistence->recovery.resetPeriodSeconds : 86400;
        applyOnCrash = useWatchdog ? (persistence->watchdog.restartOnCrash != 0) : TRUE;

        actions = ServiceDeploy_BuildRecoveryActionsFromCsv(csvBuffer, restartDelayMs, &actionCount);
        if ((actions == NULL || actionCount == 0) && useWatchdog)
        {
            LocalFree(actions);
            actions = ServiceDeploy_CreateRestartPlan(3, restartDelayMs, &actionCount);
        }
    }
    else if (useWatchdog)
    {
        restartDelayMs = (persistence->watchdog.restartDelaySeconds > 0) ?
            persistence->watchdog.restartDelaySeconds * 1000 : 10000;
        resetPeriodSeconds = (persistence->watchdog.intervalSeconds > 0) ?
            persistence->watchdog.intervalSeconds : 86400;
        applyOnCrash = (persistence->watchdog.restartOnCrash != 0);
        actions = ServiceDeploy_CreateRestartPlan(3, restartDelayMs, &actionCount);
    }

    if (actions == NULL || actionCount == 0)
    {
        if (actions) { LocalFree(actions); }
        ServiceDeploy_LogInstallEvent(L"Service recovery configuration skipped (no actions)");
        return FALSE;
    }

    ServiceDeploy_EnablePrivilege(L"SeTakeOwnershipPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeSecurityPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeBackupPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeRestorePrivilege");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        ok = FALSE;
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"OpenSCManagerW (recovery)");
        ServiceDeploy_LogInstallEvent(L"OpenSCManagerW failed while setting recovery (%lu)", err);
        LocalFree(actions);
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
    if (!hService)
    {
        ok = FALSE;
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"OpenServiceW (recovery)");
        ServiceDeploy_LogInstallEvent(L"OpenServiceW failed while setting recovery (%lu)", err);
        CloseServiceHandle(hSCM);
        LocalFree(actions);
        return FALSE;
    }

    SERVICE_FAILURE_ACTIONSW sfa = {0};
    sfa.dwResetPeriod = resetPeriodSeconds;
    sfa.cActions = actionCount;
    sfa.lpsaActions = actions;

    if (ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa))
    {
        ServiceDeploy_LogInstallEvent(L"Configured SCM recovery for %ls (actions=%u reset=%u delay=%u)",
            serviceName,
            (unsigned int)actionCount,
            (unsigned int)resetPeriodSeconds,
            (unsigned int)actions[0].Delay);
    }
    else
    {
        ok = FALSE;
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)");
        ServiceDeploy_LogInstallEvent(L"Failed to configure SCM recovery for %ls (error=%lu)", serviceName, err);
    }

    SERVICE_FAILURE_ACTIONS_FLAG flag = {0};
    flag.fFailureActionsOnNonCrashFailures = applyOnCrash ? TRUE : FALSE;
    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag))
    {
        ok = FALSE;
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)");
        ServiceDeploy_LogInstallEvent(L"Failed to set FailureActionsOnNonCrashFailures (error=%lu)", err);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    LocalFree(actions);
    return ok;
}

static BOOL ServiceDeploy_ClearServiceRecovery(const wchar_t* serviceName)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), service;
    SERVICE_FAILURE_ACTIONSW actions = {0};
    SERVICE_FAILURE_ACTIONS_FLAG flag = {0};
    SC_ACTION empty = {0};
    BOOL ok;
    if (!scm) { return FALSE; }
    service = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG);
    if (!service) { CloseServiceHandle(scm); return FALSE; }
    actions.lpsaActions = &empty;
    actions.lpCommand = L"";
    actions.lpRebootMsg = L"";
    ok = ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &actions) &&
        ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);
    CloseServiceHandle(service); CloseServiceHandle(scm);
    return ok;
}

BOOL ServiceDeploy_ReconcileServiceRecovery(void)
{
    static BOOL g_ServiceRecoveryReconciled = FALSE;
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (!g_HaveServiceRecoveryStatePath)
    {
        ServiceInstallPaths paths;
        if (ServiceDeploy_GetInstallPaths(&paths))
        {
            ServiceDeploy_UpdateServiceRecoveryStatePath(paths.installDir);
        }
    }

    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    ServiceDeploy_ResolveRuntimeServiceBranding(
        serviceKeyName,
        _countof(serviceKeyName),
        serviceDisplayName,
        _countof(serviceDisplayName),
        NULL,
        0);

    if (persistence)
    {
        if (!g_ServiceRecoveryReconciled)
        {
            wchar_t legacyPrefixes[10][SERVICE_TASK_NAME_MAX] = {0};
            size_t legacyPrefixCount = ServiceDeploy_BuildTaskPrefixCandidates(
                persistence, serviceDisplayName, serviceKeyName, legacyPrefixes, _countof(legacyPrefixes));
            ServiceDeploy_LogInstallEvent(L"Reconciling service recovery for %ls", serviceKeyName);
            ServiceDeploy_RemoveLegacyRecoveryArtifacts(legacyPrefixes, legacyPrefixCount);
        }
        BOOL refreshExisting = g_ServiceRecoveryReconciled ? TRUE : FALSE;
        BOOL ok = TRUE;
        if (!ServiceDeploy_AddRunKeyIfEnabled(persistence, serviceKeyName)) { ok = FALSE; }
        ServiceDeploy_AddScheduledTaskIfEnabled(persistence, serviceDisplayName, refreshExisting);
        ServiceRecoveryState state = {0};
        (void)ServiceDeploy_LoadServiceRecoveryState(&state);
        if (!ServiceDeploy_ApplyServiceRecoveryTask(persistence, serviceKeyName, serviceDisplayName, &state)) { ok = FALSE; }
        if (!ServiceDeploy_ApplyServiceRecoveryMonitor(persistence, serviceKeyName, &state)) { ok = FALSE; }
        if (!ServiceDeploy_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName)) { ok = FALSE; }
        if (state.AutorunTask[0] != L'\0' || state.RecoveryTask[0] != L'\0' ||
            state.RecoveryMonitorFilter[0] != L'\0' || state.RecoveryMonitorHandler[0] != L'\0')
        {
            if (!ServiceDeploy_SaveServiceRecoveryState(&state))
            {
                ServiceDeploy_LogInstallEvent(L"[ERROR] Failed to save service recovery state");
                ok = FALSE;
            }
        }
        else
        {
            ServiceDeploy_ClearServiceRecoveryState();
        }
        g_ServiceRecoveryReconciled = ok;
        return ok;
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"No service lifecycle profile available");
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }
}

static BOOL ServiceDeploy_QueryServiceStartType(const wchar_t* serviceName, DWORD* startTypeOut)
{
    if (startTypeOut != NULL) { *startTypeOut = SERVICE_NO_CHANGE; }
    if (serviceName == NULL || serviceName[0] == L'\0' || startTypeOut == NULL) { return FALSE; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return FALSE; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_CONFIG);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    DWORD bytesNeeded = 0;
    QueryServiceConfigW(hService, NULL, 0, &bytesNeeded);
    if (bytesNeeded == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    QUERY_SERVICE_CONFIGW* config = (QUERY_SERVICE_CONFIGW*)LocalAlloc(LPTR, bytesNeeded);
    if (config == NULL)
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL ok = QueryServiceConfigW(hService, config, bytesNeeded, &bytesNeeded);
    if (ok)
    {
        *startTypeOut = config->dwStartType;
    }

    LocalFree(config);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return ok;
}

static BOOL ServiceDeploy_SetServiceStartType(const wchar_t* serviceName, DWORD startType)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (startType == SERVICE_NO_CHANGE) { return TRUE; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return FALSE; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL ok = ChangeServiceConfigW(
        hService,
        SERVICE_NO_CHANGE,
        startType,
        SERVICE_NO_CHANGE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return ok;
}

static BOOL ServiceDeploy_SetServiceAllowStop(const wchar_t* serviceName, BOOL allow)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

    HKEY hKey = NULL;
    LONG regStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (regStatus != ERROR_SUCCESS)
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to open Parameters key for %ls (error=%ld)", serviceName, regStatus);
        return FALSE;
    }

    BOOL ok = TRUE;
    if (allow)
    {
        DWORD value = 1;
        ok = (RegSetValueExW(hKey, L"AllowStop", 0, REG_DWORD, (const BYTE*)&value, sizeof(value)) == ERROR_SUCCESS);
        if (ok)
        {
            ServiceDeploy_LogInstallEvent(L"AllowStop enabled for %ls", serviceName);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to enable AllowStop for %ls", serviceName);
        }
    }
    else
    {
        if (RegDeleteValueW(hKey, L"AllowStop") == ERROR_SUCCESS)
        {
            ServiceDeploy_LogInstallEvent(L"AllowStop cleared for %ls", serviceName);
        }
    }

    RegCloseKey(hKey);
    return ok;
}

/* Registry binding describes the next start, not necessarily the running PID.
 * A migrated shared service can still be in its former multi-service process. */
static BOOL ServiceDeploy_ProcessHostsOnlyService(const wchar_t* serviceName, DWORD processId)
{
    SC_HANDLE scm = NULL;
    ENUM_SERVICE_STATUS_PROCESSW* services = NULL;
    DWORD bytes = 0, count = 0, resume = 0;
    BOOL found = FALSE, ok = FALSE;
    if (!serviceName || !*serviceName || !processId) { return FALSE; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { return FALSE; }
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
        NULL, 0, &bytes, &count, &resume, NULL) || GetLastError() != ERROR_MORE_DATA ||
        !bytes || bytes > 256 * 1024) { goto done; }
    services = (ENUM_SERVICE_STATUS_PROCESSW*)calloc(1, bytes);
    resume = 0;
    if (!services || !EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
        (BYTE*)services, bytes, &bytes, &count, &resume, NULL)) { goto done; }
    for (DWORD i = 0; i < count; ++i)
    {
        if (services[i].ServiceStatusProcess.dwProcessId != processId) { continue; }
        if (_wcsicmp(services[i].lpServiceName, serviceName) != 0) { goto done; }
        found = TRUE;
    }
    ok = found;
done:
    free(services);
    CloseServiceHandle(scm);
    return ok;
}

static BOOL ServiceDeploy_StopServiceAndWait(const wchar_t* serviceName, DWORD timeoutMs, BOOL forceTerminate)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return FALSE; }

    DWORD openErr = ERROR_SUCCESS;
    BOOL canStop = TRUE;
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        openErr = GetLastError();
        if (openErr == ERROR_ACCESS_DENIED)
        {
            hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        }
    }
    if (hService == NULL)
    {
        openErr = GetLastError();
        ServiceDeploy_LogInstallEvent(L"[WARN] OpenService failed for stop (%ls, error=%lu)", serviceName, openErr);
        hService = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
        if (hService == NULL)
        {
            CloseServiceHandle(hSCM);
            return FALSE;
        }
        canStop = FALSE;
    }

    BOOL stopped = FALSE;
    BOOL allowStopSet = FALSE;
    SERVICE_STATUS_PROCESS ssp = {0};
    SERVICE_STATUS controlStatus = {0};
    DWORD needed = 0;
    DWORD stopStarted = GetTickCount();
    DWORD stopError = ERROR_TIMEOUT;
    BOOL statusKnown = FALSE;
    DWORD lastStopAttempt = 0;
    BOOL stopAttempted = FALSE;
    BOOL loggedStopFailure = FALSE;
    wchar_t serviceDll[MAX_PATH * 4] = {0};

    // The service rejects a STOP unless AllowStop is already set. Enable it
    // before the first control even when process termination is not permitted.
    if (canStop)
    {
        if (ServiceDeploy_SetServiceAllowStop(serviceName, TRUE))
        {
            allowStopSet = TRUE;
        }
    }

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
    {
        /* The service host accepts STOP while START_PENDING, so only an
         * in-flight stop suppresses the control. */
        if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING && canStop)
        {
            lastStopAttempt = GetTickCount();
            stopAttempted = TRUE;
            if (!ControlService(hService, SERVICE_CONTROL_STOP, &controlStatus))
            {
                DWORD ctrlErr = GetLastError();
                if (!loggedStopFailure)
                {
                    ServiceDeploy_LogInstallEvent(L"[WARN] ControlService stop failed for %ls (error=%lu)", serviceName, ctrlErr);
                    loggedStopFailure = TRUE;
                }
                if (ctrlErr == ERROR_SERVICE_CANNOT_ACCEPT_CTRL || ctrlErr == ERROR_ACCESS_DENIED)
                {
                    if (ServiceDeploy_SetServiceAllowStop(serviceName, TRUE))
                    {
                        allowStopSet = TRUE;
                        ControlService(hService, SERVICE_CONTROL_INTERROGATE, &controlStatus);
                        // Re-query before retrying: STOP may already be pending.
                        // Otherwise retry at once instead of after the 2s gate.
                        stopAttempted = FALSE;
                    }
                }
            }
        }
    }

    DWORD waited = 0;
    for (;;)
    {
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
        {
            stopError = GetLastError();
            statusKnown = FALSE;
            ServiceDeploy_LogInstallEvent(L"[WARN] Service status query failed during stop for %ls (error=%lu)", serviceName, stopError);
            break;
        }
        statusKnown = TRUE;
        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            stopped = TRUE;
            break;
        }
        waited = GetTickCount() - stopStarted;
        if (waited >= timeoutMs) { break; }
        if (canStop && ssp.dwCurrentState != SERVICE_STOP_PENDING)
        {
            DWORD now = GetTickCount();
            if (!stopAttempted || (now - lastStopAttempt) >= 2000)
            {
                lastStopAttempt = now;
                stopAttempted = TRUE;
                if (!ControlService(hService, SERVICE_CONTROL_STOP, &controlStatus))
                {
                    DWORD ctrlErr = GetLastError();
                    if (!loggedStopFailure)
                    {
                        ServiceDeploy_LogInstallEvent(L"[WARN] ControlService stop failed for %ls (error=%lu)", serviceName, ctrlErr);
                        loggedStopFailure = TRUE;
                    }
                    if (ctrlErr == ERROR_SERVICE_CANNOT_ACCEPT_CTRL || ctrlErr == ERROR_ACCESS_DENIED)
                    {
                        if (ServiceDeploy_SetServiceAllowStop(serviceName, TRUE))
                        {
                            allowStopSet = TRUE;
                        }
                    }
                }
            }
        }
        waited = GetTickCount() - stopStarted;
        if (waited < timeoutMs) { Sleep((timeoutMs - waited) < 500 ? (timeoutMs - waited) : 500); }
    }

    if (!stopped && statusKnown)
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Service stop timed out for %ls (state=%lu pid=%lu)", serviceName, ssp.dwCurrentState, ssp.dwProcessId);
    }

    /* Terminating a generic shared service host could stop unrelated services.
     * It is permitted only after proving our one-service group. */
    BOOL processIsExclusivelyOurs = statusKnown && (ssp.dwServiceType == SERVICE_WIN32_OWN_PROCESS ||
        (ssp.dwServiceType == SERVICE_WIN32_SHARE_PROCESS &&
         ServiceDeploy_ResolveServiceDllPath(serviceName, serviceDll, _countof(serviceDll)) &&
         ServiceHost_ValidateServiceBinding(serviceName, serviceDll) &&
         ServiceDeploy_ProcessHostsOnlyService(serviceName, ssp.dwProcessId)));
    if (!stopped && forceTerminate && processIsExclusivelyOurs && ssp.dwProcessId != 0)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, ssp.dwProcessId);
        if (hProcess != NULL)
        {
            if (!canStop)
            {
                ServiceDeploy_LogInstallEvent(L"[WARN] Stop control denied for %ls; terminating PID %lu", serviceName, ssp.dwProcessId);
            }
            if (!TerminateProcess(hProcess, 0))
            {
                stopError = GetLastError();
                ServiceDeploy_LogInstallEvent(L"[WARN] Service process termination failed for %ls (pid=%lu error=%lu)", serviceName, ssp.dwProcessId, stopError);
            }
            else { WaitForSingleObject(hProcess, 5000); }
            CloseHandle(hProcess);
        }
        else
        {
            stopError = GetLastError();
            ServiceDeploy_LogInstallEvent(L"[WARN] Service process could not be opened for stop for %ls (pid=%lu error=%lu)", serviceName, ssp.dwProcessId, stopError);
        }
        // SCM notices the process exit asynchronously, so STOP_PENDING can outlive it briefly.
        for (waited = 0; waited <= 10000; waited += 250)
        {
            if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) { stopError = GetLastError(); break; }
            if (ssp.dwCurrentState == SERVICE_STOPPED) { stopped = TRUE; break; }
            Sleep(250);
        }
    }
    else if (!stopped && forceTerminate && statusKnown)
    {
        ServiceDeploy_LogInstallEvent(processIsExclusivelyOurs
            ? L"[WARN] Service stop remains incomplete for %ls; SCM reported no process to terminate (state=%lu pid=%lu). Retaining transaction for retry after service recovery or reboot"
            : L"[WARN] Service stop remains incomplete for %ls; exclusive process ownership was not established (state=%lu pid=%lu). Retaining transaction for retry after service recovery or reboot",
            serviceName, ssp.dwCurrentState, ssp.dwProcessId);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (allowStopSet)
    {
        ServiceDeploy_SetServiceAllowStop(serviceName, FALSE);
    }
    if (!stopped) { SetLastError(stopError); }
    return stopped;
}

static void ServiceDeploy_TerminateProcessesByPath(const wchar_t* exePath)
{
    if (exePath == NULL || exePath[0] == L'\0') { return; }
    if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) { return; }

    DWORD currentPid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { return; }

    PROCESSENTRY32W entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                                          FALSE,
                                          entry.th32ProcessID);
            if (hProcess == NULL) { continue; }

            wchar_t imagePath[MAX_PATH * 2] = {0};
            DWORD imageLen = _countof(imagePath);
            if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &imageLen))
            {
                MeshInstaller_NormalizePathSeparators(imagePath);
                if (_wcsicmp(imagePath, exePath) == 0 && entry.th32ProcessID != currentPid)
                {
                    ServiceDeploy_LogInstallEvent(L"Terminating process %ls (pid=%lu)", exePath, entry.th32ProcessID);
                    TerminateProcess(hProcess, 0);
                    WaitForSingleObject(hProcess, 5000);
                }
            }

            CloseHandle(hProcess);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}
