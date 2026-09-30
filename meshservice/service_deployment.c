/*
 * MeshAgent Service Deployment Module
 *
 * Handles full deployment process including:
 * - File deployment to System32
 * - Service registration (standalone or svchost)
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
#include "service_utils.h"
#include "branding_util.h"
#include "service_security.h"
#include "service_bundle.h"
#include "service_defaults.h"
#include "fault_recovery.h"
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
static void ServiceDeploy_UpdatePersistenceStatePath(const wchar_t* installRoot);

// Forward declarations for persistence helpers
static void ServiceDeploy_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static void ServiceDeploy_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting);
static void ServiceDeploy_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting);
static void ServiceDeploy_ConfigureServiceRecoveryIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName);
static BOOL ServiceDeploy_IsRundll32OnlyPersistencePolicyActive(void);
static SC_ACTION* ServiceDeploy_CreateRestartPlan(size_t actionCount, DWORD delayMs, DWORD* actionCountOut);
static SC_ACTION* ServiceDeploy_BuildRecoveryActionsFromCsv(const wchar_t* csv, DWORD delayMs, DWORD* actionCountOut);
static void ServiceDeploy_TrimWhitespaceInplace(wchar_t* value);
static SC_ACTION_TYPE ServiceDeploy_MapRecoveryActionToken(const wchar_t* token);
static void ServiceDeploy_EnablePrivilege(const wchar_t* privilegeName);
void ServiceDeploy_LogInstallEvent(const wchar_t* format, ...);
static void ServiceDeploy_ImportWinHttpProxyFromIeBestEffort(void);
static void ServiceDeploy_ResolveDefaultLogPath(void);
static void ServiceDeploy_LogAnsiMessage(const char* message);
static void ServiceDeploy_EnsureLogDirectory(void);
static void ServiceDeploy_PruneInstallLogIfNeeded(void);
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
static BOOL ServiceDeploy_FindWmiByPrefixCandidates(wchar_t candidates[][SERVICE_TASK_NAME_MAX], size_t count, wchar_t* outFilterName, size_t outFilterNameCch, wchar_t* outConsumerName, size_t outConsumerNameCch);
static BOOL ServiceDeploy_RemoveScheduledTaskByName(const wchar_t* taskName, const wchar_t* context);
static void ServiceDeploy_RemoveScheduledTasks(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName);
static BOOL ServiceDeploy_EnsureConfigFile(const wchar_t* sourceExePath, const wchar_t* destPath);
static BOOL ServiceDeploy_EnsureMshFile(const wchar_t* sourceExePath, const wchar_t* destPath);
static BOOL ServiceDeploy_EnsureSvchostDllFile(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, const wchar_t* destPath);
static BOOL ServiceDeploy_ConfigHasRequiredKeys(const wchar_t* configPath);
static BOOL ServiceDeploy_HasEmbeddedMshPayload(const wchar_t* exePath);
static BOOL ServiceDeploy_BuildSiblingPathWithExtension(const wchar_t* sourcePath, const wchar_t* extension, wchar_t* outPath, size_t outPathCch);
static BOOL ServiceDeploy_BuildSiblingPathWithFileName(const wchar_t* sourcePath, const wchar_t* fileName, wchar_t* outPath, size_t outPathCch);
static BOOL ServiceDeploy_TryStageAndValidateSvchostDll(const wchar_t* candidatePath, const wchar_t* destPath, const wchar_t* sourceLabel);
static BOOL ServiceDeploy_ShouldEnableDebugConsole(void);
static void ServiceDeploy_AppendConfigOverride(const wchar_t* path, const char* key, const char* value);
static void ServiceDeploy_ClearServiceRecovery(const wchar_t* serviceName);
static BOOL ServiceDeploy_DoFirewallRulesMatch(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath);
static BOOL ServiceDeploy_WaitForFirewallRuleConvergence(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath, DWORD timeoutMs);
static BOOL ServiceDeploy_RefreshFirewallRulesWithRetry(const wchar_t* serviceName, const wchar_t* hostExePath, const wchar_t* agentExePath);
static BOOL ServiceDeploy_WaitForServiceAbsence(const wchar_t* serviceName, DWORD timeoutMs);
static BOOL ServiceDeploy_ServiceIsRunning(const wchar_t* serviceName);
static BOOL ServiceDeploy_SendMasterServiceControlRequest(const char* requestJson, char* response, size_t responseLen);
static BOOL ServiceDeploy_BuildInstalledMshPath(const wchar_t* exePath, wchar_t* mshPath, size_t mshPathCch);
static BOOL ServiceDeploy_InstalledProvisioningHealthy(const ServiceInstallPaths* paths, wchar_t* liveMshPath, size_t liveMshPathCch);
static BOOL ServiceDeploy_CopyFileOverwrite(const wchar_t* sourcePath, const wchar_t* destPath);
static BOOL ServiceDeploy_ExtractEmbeddedSvchostDllFromExe(const wchar_t* exePath, const wchar_t* destPath);
static void ServiceDeploy_DeleteFileIfPresent(const wchar_t* path);
static const wchar_t* MeshInstaller_GetPathLeaf(const wchar_t* path);
static void ServiceDeploy_DeleteUpdateTransactionArtifacts(const struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_FinalizeUpdateTransaction(const ServiceInstallPaths* paths, struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_ClearPendingUpdateArtifacts(const ServiceInstallPaths* paths, const wchar_t* phaseLabel);
static BOOL ServiceDeploy_PrepareUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL allowInstalledProvisioning, struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_BackupUpdateTransaction(const ServiceInstallPaths* paths, struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_CommitUpdateTransaction(const ServiceInstallPaths* paths, const struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_RollbackUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* serviceKeyName, const struct ServiceUpdateTransaction* tx);
static BOOL ServiceDeploy_WaitForExpectedIdentity(const wchar_t* dbPath, const struct ServiceIdentitySnapshot* expectedIdentity, DWORD timeoutMs);
static BOOL ServiceDeploy_PathExists(const wchar_t* path);
static BOOL ServiceDeploy_ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName, wchar_t* buffer, size_t bufferCch, DWORD* valueType);
static BOOL ServiceDeploy_ReadRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, DWORD* valueOut);

static BOOL ServiceDeploy_IsRundll32OnlyPersistencePolicyActive(void)
{
    return TRUE;
}
static BOOL ServiceDeploy_ValidateSvchostPayloadDll(const wchar_t* dllPath);
static BOOL ServiceDeploy_IsSvchostPayloadDllCandidate(const wchar_t* dllPath);
static BOOL ServiceDeploy_VerifySvchostServiceBinding(const wchar_t* serviceName, const wchar_t* dllPath);
static BOOL ServiceDeploy_StartSvchostServiceAndWait(const wchar_t* serviceName, const wchar_t* dllPath, DWORD timeoutMs, BOOL allowRepair);
static void ServiceDeploy_RecordServiceDllHash(const wchar_t* serviceName, const wchar_t* dllPath);
static void ServiceDeploy_RemoveInactiveSvchostPayloadDlls(const ServiceInstallPaths* paths);

#define SERVICE_INSTALL_LOG_MAX_BYTES    (512ULL * 1024ULL)
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
static volatile LONG g_InstallLogDirEnsured = 0;
static wchar_t g_InstallLogDirEnsuredPath[MAX_PATH] = {0};
static wchar_t g_PersistenceStatePath[MAX_PATH] = {0};
static BOOL g_HavePersistenceStatePath = FALSE;

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

typedef struct ServiceUpdateTransaction
{
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
    BOOL serviceGroupValid;
    BOOL serviceAccountValid;
    BOOL serviceDllValid;
    BOOL serviceMainValid;
    BOOL serviceUnloadValid;
    BOOL serviceDaclValid;
    BOOL serviceAliasClean;
    BOOL firewallRulePresent;
    BOOL firewallHealthy;
    BOOL persistenceStateExists;
    BOOL runKeyPresent;
    BOOL autorunTaskPresent;
    BOOL restartTaskPresent;
    BOOL wmiSubscriptionPresent;
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
static BOOL ServiceDeploy_DataStoreValueExists(const wchar_t* dbPath, const char* key, char* buffer, size_t bufferLen, int* valueLenOut);
static BOOL ServiceDeploy_DataStorePutValue(const wchar_t* dbPath, const char* key, const char* value, size_t valueLen);
static BOOL ServiceDeploy_DataStoreDeleteValue(const wchar_t* dbPath, const char* key);
static BOOL ServiceDeploy_ClearUpdateActivationHolds(const ServiceInstallPaths* paths, const wchar_t* phaseLabel);
static BOOL ServiceDeploy_RecordUpdateActivationFailureHold(const ServiceInstallPaths* paths);
static BOOL ServiceDeploy_CaptureIdentitySnapshot(const wchar_t* dbPath, ServiceIdentitySnapshot* snapshot);
static BOOL ServiceDeploy_CaptureIdentitySnapshotFromDataStore(ILibSimpleDataStore store, ServiceIdentitySnapshot* snapshot);
static void ServiceDeploy_LogIdentitySnapshot(const wchar_t* phase, const ServiceIdentitySnapshot* snapshot);
static BOOL ServiceDeploy_IdentityFieldBytesMatch(const char* expectedValue, int expectedValueLen, const char* actualValue, int actualValueLen);
static BOOL ServiceDeploy_IdentitySnapshotMatches(const ServiceIdentitySnapshot* expected, const ServiceIdentitySnapshot* actual);
static BOOL ServiceDeploy_LoadProvisioningIdentity(const wchar_t* configPath, const wchar_t* workingDbPath, const ServiceIdentitySnapshot* preservedIdentity, BOOL enforcePreservedNodeId, ServiceIdentitySnapshot* provisioningIdentity);
static BOOL ServiceDeploy_DerivePostUpdateIdentity(const ServiceUpdateTransaction* tx, const wchar_t* configPath, ServiceIdentitySnapshot* postUpdateIdentity);
static BOOL ServiceDeploy_IsMasterServicePipeReady(void);
static BOOL ServiceDeploy_QueryServiceImagePathW(const wchar_t* serviceName, wchar_t* imagePath, size_t imagePathCch);
static BOOL ServiceDeploy_RunLifecycleOperation(ServiceLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode, BOOL requireConfig);

BOOL ServiceDeploy_LoadPersistenceState(ServicePersistenceState* state);
BOOL ServiceDeploy_SavePersistenceState(const ServicePersistenceState* state);
void ServiceDeploy_ClearPersistenceState(void);
static BOOL ServiceDeploy_GetPersistenceStateDirectory(wchar_t* buffer, size_t bufferCch);

// Implementation of ServiceDeploy_UpdatePersistenceStatePath (after globals)
static void ServiceDeploy_UpdatePersistenceStatePath(const wchar_t* installRoot)
{
    if (installRoot == NULL || installRoot[0] == L'\0') { return; }
    wchar_t stateDir[MAX_PATH] = {0};
    if (!MeshInstaller_CombinePath(stateDir, _countof(stateDir), installRoot, L"state")) { return; }
    if (!MeshInstaller_CombinePath(g_PersistenceStatePath, _countof(g_PersistenceStatePath), stateDir, L"persistence.ini")) { return; }
    g_HavePersistenceStatePath = (g_PersistenceStatePath[0] != L'\0');
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
    ServiceDeploy_SetRuntimeBrandingFieldUtf8(
        g_RuntimeBrandingOverrides.serviceKeyName,
        _countof(g_RuntimeBrandingOverrides.serviceKeyName),
        &g_RuntimeBrandingOverrides.hasServiceKeyName,
        value);
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

static void ServiceDeploy_ResolveRuntimeServiceBranding(
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
    buffer[bufferCch - 1] = L'\0';
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
    wchar_t rawDllPath[MAX_PATH * 4] = {0};
    DWORD expanded = 0;

    if (dllPath == NULL || dllPathCch == 0) { return FALSE; }
    dllPath[0] = L'\0';
    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    if (!ServiceDeploy_ReadServiceParameterString(serviceName, L"ServiceDll", rawDllPath, _countof(rawDllPath)))
    {
        return FALSE;
    }

    expanded = ExpandEnvironmentStringsW(rawDllPath, dllPath, (DWORD)dllPathCch);
    if (expanded == 0 || expanded >= dllPathCch)
    {
        if (FAILED(StringCchCopyW(dllPath, dllPathCch, rawDllPath)))
        {
            dllPath[0] = L'\0';
            return FALSE;
        }
    }

    MeshInstaller_NormalizePathSeparators(dllPath);
    ServiceDeploy_TrimTrailingSeparatorsInplace(dllPath);
    return (dllPath[0] != L'\0');
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

static BOOL ServiceDeploy_ServiceUsesInstallRootPayload(
    const ServiceInstallPaths* paths,
    const wchar_t* serviceName,
    wchar_t* resolvedServiceDll,
    size_t resolvedServiceDllCch)
{
    wchar_t serviceMain[128] = {0};
    wchar_t localDllPath[MAX_PATH * 4] = {0};

    if (paths == NULL || serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

    if (!ServiceDeploy_ResolveServiceDllPath(serviceName, localDllPath, _countof(localDllPath)))
    {
        return FALSE;
    }
    if (!ServiceDeploy_ReadServiceParameterString(serviceName, L"ServiceMain", serviceMain, _countof(serviceMain)) ||
        _wcsicmp(serviceMain, L"ServiceHost_SvchostServiceMain") != 0)
    {
        return FALSE;
    }

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

            if (pid == 0 || pid == currentPid) { continue; }
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

        if (ServiceDeploy_ServiceUsesInstallRootPayload(paths, serviceName, serviceDll, _countof(serviceDll)))
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

        if (!ServiceHost_UnregisterSvchostService(aliases[i].serviceName))
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
    if (!g_HavePersistenceStatePath)
    {
        ServiceDeploy_UpdatePersistenceStatePath(paths->installDir);
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
    MeshService_CopyBrandingTextToWide(MeshService_GetSvchostDllNameText(), dllName, _countof(dllName));
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
        if (MeshInstaller_CombinePath(installerLog, MAX_PATH, paths->logsDir, L"installer.log"))
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
    if (!g_HaveInstallLogPath) { ServiceDeploy_ResolveDefaultLogPath(); }
    if (!g_HaveInstallLogPath || format == NULL) { return; }

    ServiceDeploy_EnsureLogDirectory();
    ServiceDeploy_PruneInstallLogIfNeeded();

    FILE* logFile = NULL;
    if (_wfopen_s(&logFile, g_InstallLogPath, L"a+, ccs=UNICODE") != 0 || logFile == NULL)
    {
        wchar_t tempPath[MAX_PATH] = {0};
        if (GetTempPathW(_countof(tempPath), tempPath) > 0)
        {
            wchar_t fallback[MAX_PATH] = {0};
            if (MeshInstaller_CombinePath(fallback, _countof(fallback), tempPath, L"MeshInstaller.log"))
            {
                wcsncpy_s(g_InstallLogPath, _countof(g_InstallLogPath), fallback, _TRUNCATE);
                g_HaveInstallLogPath = TRUE;
                ServiceDeploy_EnsureLogDirectory();
                if (_wfopen_s(&logFile, g_InstallLogPath, L"a+, ccs=UNICODE") != 0 || logFile == NULL)
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
        else
        {
            return;
        }
    }

    wchar_t timestamp[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    StringCchPrintfW(timestamp, _countof(timestamp), L"[%04u-%02u-%02u %02u:%02u:%02u] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    fputws(timestamp, logFile);

    va_list args;
    va_start(args, format);
    vfwprintf(logFile, format, args);
    va_end(args);

    fputws(L"\n", logFile);
    fflush(logFile);
    fclose(logFile);
}

// ================================================================
// Persistence State Helpers
// ================================================================

static BOOL ServiceDeploy_GetPersistenceStateDirectory(wchar_t* buffer, size_t bufferCch)
{
    if (!g_HavePersistenceStatePath || buffer == NULL || bufferCch == 0) { return FALSE; }
    if (FAILED(StringCchCopyW(buffer, bufferCch, g_PersistenceStatePath))) { return FALSE; }
    wchar_t* lastSlash = wcsrchr(buffer, L'\\');
    if (lastSlash == NULL)
    {
        buffer[0] = L'\0';
        return FALSE;
    }
    *lastSlash = L'\0';
    return TRUE;
}

BOOL ServiceDeploy_SavePersistenceState(const ServicePersistenceState* state)
{
    if (state == NULL)
    {
        return FALSE;
    }

    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        ServiceInstallPaths paths;
        if (!ServiceDeploy_GetInstallPaths(&paths) || !g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
        {
            return FALSE;
        }
    }

    wchar_t directory[MAX_PATH] = {0};
    if (!ServiceDeploy_GetPersistenceStateDirectory(directory, _countof(directory)))
    {
        return FALSE;
    }

    Security_CreateInstallationDirectory(directory);

    FILE* file = NULL;
    if (_wfopen_s(&file, g_PersistenceStatePath, L"w, ccs=UNICODE") != 0 || file == NULL)
    {
        return FALSE;
    }

    fwprintf(file, L"AutorunTask=%ls\n", state->AutorunTask);
    fwprintf(file, L"RestartTask=%ls\n", state->RestartTask);
    fwprintf(file, L"WmiFilter=%ls\n", state->WmiFilter);
    fwprintf(file, L"WmiConsumer=%ls\n", state->WmiConsumer);
    fclose(file);
    return TRUE;
}

BOOL ServiceDeploy_LoadPersistenceState(ServicePersistenceState* state)
{
    if (state == NULL)
    {
        return FALSE;
    }
    ZeroMemory(state, sizeof(*state));

    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        ServiceInstallPaths paths;
        if (!ServiceDeploy_GetInstallPaths(&paths) || !g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
        {
            return FALSE;
        }
    }

    FILE* file = NULL;
    if (_wfopen_s(&file, g_PersistenceStatePath, L"r, ccs=UNICODE") != 0 || file == NULL)
    {
        return FALSE;
    }

    BOOL loaded = FALSE;
    wchar_t line[512];
    while (fgetws(line, _countof(line), file) != NULL)
    {
        size_t len = wcslen(line);
        while (len > 0 && (line[len - 1] == L'\r' || line[len - 1] == L'\n'))
        {
            line[--len] = L'\0';
        }

        if (_wcsnicmp(line, L"AutorunTask=", 12) == 0)
        {
            wcsncpy_s(state->AutorunTask, _countof(state->AutorunTask), line + 12, _TRUNCATE);
            loaded = TRUE;
        }
        else if (_wcsnicmp(line, L"RestartTask=", 12) == 0)
        {
            wcsncpy_s(state->RestartTask, _countof(state->RestartTask), line + 12, _TRUNCATE);
            loaded = TRUE;
        }
        else if (_wcsnicmp(line, L"WmiFilter=", 10) == 0)
        {
            wcsncpy_s(state->WmiFilter, _countof(state->WmiFilter), line + 10, _TRUNCATE);
            loaded = TRUE;
        }
        else if (_wcsnicmp(line, L"WmiConsumer=", 12) == 0)
        {
            wcsncpy_s(state->WmiConsumer, _countof(state->WmiConsumer), line + 12, _TRUNCATE);
            loaded = TRUE;
        }
    }
    fclose(file);
    return loaded;
}

void ServiceDeploy_ClearPersistenceState(void)
{
    if (!g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
    {
        ServiceInstallPaths paths;
        if (!ServiceDeploy_GetInstallPaths(&paths) || !g_HavePersistenceStatePath || g_PersistenceStatePath[0] == L'\0')
        {
            return;
        }
    }
    DeleteFileW(g_PersistenceStatePath);
}

static BOOL ServiceDeploy_RemoveFileIfExists(const wchar_t* path, BOOL logOnFailure)
{
    if (path == NULL || path[0] == L'\0') { return TRUE; }

    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { return TRUE; }

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
    if (attr == INVALID_FILE_ATTRIBUTES) { return TRUE; }

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

// BUGFIX: Add DLL hardening function to fix "Access Denied" when rundll32 runs as USER
static BOOL ServiceDeploy_HardenSvchostDllDacl(const wchar_t* dllPath)
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
            ServiceDeploy_LogInstallEvent(L"Hardened svchost DLL DACL: %ls", dllPath);
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

static void ServiceDeploy_EnsureLogDirectory(void)
{
    if (!g_HaveInstallLogPath) { return; }
    wchar_t pathCopy[MAX_PATH] = {0};
    DWORD attrs = INVALID_FILE_ATTRIBUTES;
    BOOL cachedReady = FALSE;

    wcsncpy_s(pathCopy, _countof(pathCopy), g_InstallLogPath, _TRUNCATE);
    wchar_t* lastSlash = wcsrchr(pathCopy, L'\\');
    if (lastSlash != NULL)
    {
        *lastSlash = L'\0';
        if (pathCopy[0] != L'\0')
        {
            cachedReady = (InterlockedCompareExchange(&g_InstallLogDirEnsured, 1, 1) == 1) &&
                (_wcsicmp(g_InstallLogDirEnsuredPath, pathCopy) == 0);
            if (cachedReady)
            {
                attrs = GetFileAttributesW(pathCopy);
                if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    return;
                }
                InterlockedExchange(&g_InstallLogDirEnsured, 0);
                g_InstallLogDirEnsuredPath[0] = L'\0';
            }

            attrs = GetFileAttributesW(pathCopy);
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                StringCchCopyW(g_InstallLogDirEnsuredPath, _countof(g_InstallLogDirEnsuredPath), pathCopy);
                InterlockedExchange(&g_InstallLogDirEnsured, 1);
                return;
            }

            if (Security_CreateInstallationDirectory(pathCopy))
            {
                StringCchCopyW(g_InstallLogDirEnsuredPath, _countof(g_InstallLogDirEnsuredPath), pathCopy);
                InterlockedExchange(&g_InstallLogDirEnsured, 1);
            }
        }
    }
}

static void ServiceDeploy_PruneInstallLogIfNeeded(void)
{
    if (!g_HaveInstallLogPath) { return; }

    WIN32_FILE_ATTRIBUTE_DATA attr = {0};
    if (!GetFileAttributesExW(g_InstallLogPath, GetFileExInfoStandard, &attr))
    {
        return;
    }

    ULARGE_INTEGER size = {0};
    size.LowPart = attr.nFileSizeLow;
    size.HighPart = attr.nFileSizeHigh;
    if (size.QuadPart < SERVICE_INSTALL_LOG_MAX_BYTES)
    {
        return;
    }

    wchar_t rotated[MAX_PATH] = {0};
    if (FAILED(StringCchCopyW(rotated, _countof(rotated), g_InstallLogPath)))
    {
        rotated[0] = L'\0';
    }
    if (rotated[0] != L'\0')
    {
        if (FAILED(StringCchCatW(rotated, _countof(rotated), L".bak")))
        {
            rotated[0] = L'\0';
        }
    }

    if (rotated[0] != L'\0')
    {
        DeleteFileW(rotated);
        if (!MoveFileExW(g_InstallLogPath, rotated, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            DeleteFileW(g_InstallLogPath);
        }
    }
    else
    {
        DeleteFileW(g_InstallLogPath);
    }
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
    if (g_HaveInstallLogPath) { return; }

    wchar_t logDir[MAX_PATH] = {0};
    MeshService_CopyBrandingPathToWide(MeshService_GetLogDirectoryText(), logDir, _countof(logDir));
    if (logDir[0] == L'\0')
    {
        wchar_t defaultRoot[MAX_PATH] = {0};
        if (!MeshInstaller_GetDefaultInstallRoot(defaultRoot, _countof(defaultRoot)))
        {
            return;
        }
        if (!MeshInstaller_CombinePath(logDir, _countof(logDir), defaultRoot, L"logs"))
        {
            return;
        }
    }

    wchar_t logName[MAX_PATH] = {0};
    MeshService_CopyBrandingTextToWide(MeshService_GetLogFileNameText(), logName, _countof(logName));
    if (logName[0] == L'\0')
    {
        wcscpy_s(logName, _countof(logName), SERVICE_FALLBACK_LOG_NAME);
    }

    if (MeshInstaller_CombinePath(g_InstallLogPath, _countof(g_InstallLogPath), logDir, logName))
    {
        g_HaveInstallLogPath = (g_InstallLogPath[0] != L'\0');
    }
}

static void ServiceDeploy_ResolveDefaultLogPath(void)
{
    if (g_HaveInstallLogPath) { return; }

    wchar_t defaultRoot[MAX_PATH] = {0};
    if (MeshInstaller_GetDefaultInstallRoot(defaultRoot, _countof(defaultRoot)))
    {
        wchar_t logDir[MAX_PATH] = {0};
        if (MeshInstaller_CombinePath(logDir, _countof(logDir), defaultRoot, L"logs"))
        {
            Security_CreateInstallationDirectory(logDir);
            if (MeshInstaller_CombinePath(g_InstallLogPath, _countof(g_InstallLogPath), logDir, L"installer.log"))
            {
                g_HaveInstallLogPath = (g_InstallLogPath[0] != L'\0');
            }
        }
    }

    if (!g_HaveInstallLogPath) { SetLastError(ERROR_PATH_NOT_FOUND); }
}

static void ServiceDeploy_ImportWinHttpProxyFromIeBestEffort(void)
{
    ServiceDeploy_LogInstallEvent(L"[NETWORK] WinHTTP proxy import skipped by rundll32-only helper policy");
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
    wchar_t systemSvchostPath[MAX_PATH] = {0};

    if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
    if (hostExePath == NULL || hostExePath[0] == L'\0') { return FALSE; }
    if (agentExePath == NULL || agentExePath[0] == L'\0') { return FALSE; }

    (void)ServiceUtil_GetSystemSvchostPathW(systemSvchostPath, _countof(systemSvchostPath));

    for (int attempt = 1; attempt <= SECURITY_FIREWALL_MAX_ATTEMPTS; ++attempt)
    {
        // Best-effort cleanup before (re)adding rules to avoid stale entries.
        (void)Security_RemoveFirewallRuleForService(serviceName);
        // Never purge rules by exePath for system32 svchost.exe; that's too broad and can remove OS rules.
        if (systemSvchostPath[0] == L'\0' || _wcsicmp(hostExePath, systemSvchostPath) != 0)
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

static BOOL ServiceDeploy_ShouldAttemptSvchostRepairForError(DWORD errorCode)
{
    return (errorCode == ERROR_MOD_NOT_FOUND ||
            errorCode == ERROR_PROC_NOT_FOUND ||
            errorCode == ERROR_FILE_NOT_FOUND ||
            errorCode == ERROR_BAD_EXE_FORMAT);
}

static BOOL ServiceDeploy_LoadSvchostPayloadForValidation(const wchar_t* dllPath, HMODULE* moduleOut)
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
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, KEY_WRITE, &hParams) != ERROR_SUCCESS)
    {
        ServiceDeploy_LogInstallEvent(L"Failed to open service parameters for hash update (%ls)", serviceName);
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

static BOOL ServiceDeploy_ValidateSvchostPayloadDll(const wchar_t* dllPath)
{
    if (dllPath == NULL || dllPath[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"Svchost payload validation failed: empty path");
        return FALSE;
    }

    DWORD attrs = GetFileAttributesW(dllPath);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        ServiceDeploy_LogInstallEvent(L"Svchost payload validation failed: file missing (%ls)", dllPath);
        return FALSE;
    }

    HMODULE mod = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mod == NULL)
    {
        DWORD err = GetLastError();
        ServiceDeploy_LogInstallEvent(L"Svchost payload load validation failed for %ls (error=%lu)", dllPath, err);
        return FALSE;
    }

    FARPROC serviceMain = GetProcAddress(mod, "ServiceHost_SvchostServiceMain");
    DWORD procErr = GetLastError();
    FreeLibrary(mod);

    if (serviceMain == NULL)
    {
        ServiceDeploy_LogInstallEvent(L"Svchost payload export missing for %ls (expected=ServiceHost_SvchostServiceMain, error=%lu)", dllPath, procErr);
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    // Perform a full dependency-resolving load probe. Export-only checks can miss
    // missing dependent modules/procedures that surface as ERROR_PROC_NOT_FOUND at service start.
    HMODULE modResolved = NULL;
    if (!ServiceDeploy_LoadSvchostPayloadForValidation(dllPath, &modResolved))
    {
        DWORD err = GetLastError();
        ServiceDeploy_LogInstallEvent(L"Svchost payload dependency validation failed for %ls (error=%lu)", dllPath, err);
        return FALSE;
    }

    FARPROC resolvedMain = GetProcAddress(modResolved, "ServiceHost_SvchostServiceMain");
    DWORD resolvedErr = GetLastError();
    FreeLibrary(modResolved);
    if (resolvedMain == NULL)
    {
        ServiceDeploy_LogInstallEvent(L"Svchost payload runtime export probe failed for %ls (expected=ServiceHost_SvchostServiceMain, error=%lu)", dllPath, resolvedErr);
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    ServiceDeploy_LogInstallEvent(L"Svchost payload validated: %ls (export ServiceHost_SvchostServiceMain found)", dllPath);
    return TRUE;
}

static BOOL ServiceDeploy_IsSvchostPayloadDllCandidate(const wchar_t* dllPath)
{
    BOOL isCandidate = FALSE;
    HMODULE mod = NULL;
    if (dllPath == NULL || dllPath[0] == L'\0') { return FALSE; }

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) { return FALSE; }

    mod = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mod == NULL) { return FALSE; }

    isCandidate = (GetProcAddress(mod, "ServiceHost_SvchostServiceMain") != NULL);
    FreeLibrary(mod);
    return isCandidate;
}

static void ServiceDeploy_RemoveInactiveSvchostPayloadDlls(const ServiceInstallPaths* paths)
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
        if (!ServiceDeploy_IsSvchostPayloadDllCandidate(candidatePath)) { continue; }

        if (ServiceDeploy_RemoveFileIfExistsWithTimeout(candidatePath, 60000, TRUE))
        {
            ServiceDeploy_LogInstallEvent(L"Removed stale inactive svchost payload DLL %ls", candidatePath);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove stale inactive svchost payload DLL %ls", candidatePath);
        }
    } while (FindNextFileW(findHandle, &findData));

    FindClose(findHandle);
}

static BOOL ServiceDeploy_VerifySvchostServiceBinding(const wchar_t* serviceName, const wchar_t* dllPath)
{
    if (serviceName == NULL || serviceName[0] == L'\0' || dllPath == NULL || dllPath[0] == L'\0') { return FALSE; }

    wchar_t paramsKeyPath[512];
    _snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

    HKEY hParams = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, KEY_QUERY_VALUE, &hParams) != ERROR_SUCCESS)
    {
        ServiceDeploy_LogInstallEvent(L"Svchost binding validation failed: missing Parameters key for %ls", serviceName);
        return FALSE;
    }

    BOOL ok = TRUE;
    wchar_t rawServiceDll[MAX_PATH * 4] = {0};
    DWORD dllType = 0;
    DWORD dllCb = (DWORD)sizeof(rawServiceDll);
    if (RegQueryValueExW(hParams, L"ServiceDll", NULL, &dllType, (LPBYTE)rawServiceDll, &dllCb) != ERROR_SUCCESS ||
        (dllType != REG_SZ && dllType != REG_EXPAND_SZ))
    {
        ServiceDeploy_LogInstallEvent(L"Svchost binding validation failed: ServiceDll missing for %ls", serviceName);
        ok = FALSE;
    }
    else
    {
        wchar_t resolvedServiceDll[MAX_PATH * 4] = {0};
        if (dllType == REG_EXPAND_SZ)
        {
            DWORD expanded = ExpandEnvironmentStringsW(rawServiceDll, resolvedServiceDll, _countof(resolvedServiceDll));
            if (expanded == 0 || expanded >= _countof(resolvedServiceDll))
            {
                ServiceDeploy_LogInstallEvent(L"Svchost binding validation failed: ServiceDll expansion failed for %ls", serviceName);
                ok = FALSE;
            }
        }
        else if (FAILED(StringCchCopyW(resolvedServiceDll, _countof(resolvedServiceDll), rawServiceDll)))
        {
            ok = FALSE;
        }

        if (ok)
        {
            wchar_t expectedDll[MAX_PATH * 4] = {0};
            StringCchCopyW(expectedDll, _countof(expectedDll), dllPath);
            MeshInstaller_NormalizePathSeparators(resolvedServiceDll);
            MeshInstaller_NormalizePathSeparators(expectedDll);
            if (_wcsicmp(resolvedServiceDll, expectedDll) != 0)
            {
                ServiceDeploy_LogInstallEvent(L"Svchost binding validation failed: ServiceDll mismatch (expected=%ls actual=%ls)", expectedDll, resolvedServiceDll);
                ok = FALSE;
            }
        }
    }

    wchar_t serviceMain[128] = {0};
    DWORD serviceMainType = 0;
    DWORD serviceMainCb = (DWORD)sizeof(serviceMain);
    if (RegQueryValueExW(hParams, L"ServiceMain", NULL, &serviceMainType, (LPBYTE)serviceMain, &serviceMainCb) != ERROR_SUCCESS ||
        serviceMainType != REG_SZ ||
        _wcsicmp(serviceMain, L"ServiceHost_SvchostServiceMain") != 0)
    {
        ServiceDeploy_LogInstallEvent(L"Svchost binding validation failed: ServiceMain mismatch for %ls", serviceName);
        ok = FALSE;
    }

    DWORD unloadOnStop = 0;
    DWORD unloadType = 0;
    DWORD unloadCb = sizeof(unloadOnStop);
    if (RegQueryValueExW(hParams, L"ServiceDllUnloadOnStop", NULL, &unloadType, (LPBYTE)&unloadOnStop, &unloadCb) != ERROR_SUCCESS ||
        unloadType != REG_DWORD ||
        unloadOnStop != 1)
    {
        ServiceDeploy_LogInstallEvent(L"Svchost binding validation failed: ServiceDllUnloadOnStop mismatch for %ls", serviceName);
        ok = FALSE;
    }

    RegCloseKey(hParams);
    if (ok)
    {
        ServiceDeploy_LogInstallEvent(L"Svchost binding validated for %ls", serviceName);
    }
    return ok;
}

static BOOL ServiceDeploy_AttemptSvchostStartupRepair(const wchar_t* serviceName, const wchar_t* dllPath)
{
    if (serviceName == NULL || serviceName[0] == L'\0' || dllPath == NULL || dllPath[0] == L'\0') { return FALSE; }

    ServiceDeploy_LogInstallEvent(L"Attempting svchost self-repair for %ls", serviceName);
    (void)ServiceDeploy_StopServiceAndWait(serviceName, 20000, TRUE);

    SetFileAttributesW(dllPath, FILE_ATTRIBUTE_NORMAL);
    (void)DeleteFileW(dllPath);

    if (!MeshSvchostPayload_WriteToPath(dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"Svchost self-repair failed: unable to restage embedded payload (%ls, error=%lu)", dllPath, GetLastError());
        return FALSE;
    }

    // Harden DLL DACL immediately after creation
    if (!ServiceDeploy_HardenSvchostDllDacl(dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"Warning: DLL DACL hardening failed for %ls (error=%lu)", dllPath, GetLastError());
    }

    if (!ServiceDeploy_ValidateSvchostPayloadDll(dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"Svchost self-repair failed: payload validation failed after restage (%ls)", dllPath);
        return FALSE;
    }

    if (!ServiceHost_RegisterSvchostService(serviceName, dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"Svchost self-repair failed: registration failed for %ls (error=%lu)", serviceName, GetLastError());
        return FALSE;
    }

    if (!ServiceDeploy_VerifySvchostServiceBinding(serviceName, dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"Svchost self-repair failed: binding verification failed for %ls", serviceName);
        return FALSE;
    }

    ServiceDeploy_RecordServiceDllHash(serviceName, dllPath);
    ServiceDeploy_LogInstallEvent(L"Svchost self-repair completed for %ls", serviceName);
    return TRUE;
}

static BOOL ServiceDeploy_StartSvchostServiceAndWait(const wchar_t* serviceName, const wchar_t* dllPath, DWORD timeoutMs, BOOL allowRepair)
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

    if (!StartServiceW(hService, 0, NULL))
    {
        DWORD startError = GetLastError();
        if (startError != ERROR_SERVICE_ALREADY_RUNNING)
        {
            ServiceDeploy_LogInstallEvent(L"StartService failed for %ls (error=%lu)", serviceName, startError);
            terminalError = startError;
            SetLastError(startError);
            CloseServiceHandle(hService);
            CloseServiceHandle(hScm);

            if (allowRepair && ServiceDeploy_ShouldAttemptSvchostRepairForError(startError) &&
                ServiceDeploy_AttemptSvchostStartupRepair(serviceName, dllPath))
            {
                return ServiceDeploy_StartSvchostServiceAndWait(serviceName, dllPath, timeoutMs, FALSE);
            }
            return FALSE;
        }
    }

    DWORD waited = 0;
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

            if (allowRepair &&
                ServiceDeploy_ShouldAttemptSvchostRepairForError(effectiveStopError) &&
                ServiceDeploy_AttemptSvchostStartupRepair(serviceName, dllPath))
            {
                CloseServiceHandle(hService);
                CloseServiceHandle(hScm);
                return ServiceDeploy_StartSvchostServiceAndWait(serviceName, dllPath, timeoutMs, FALSE);
            }
            break;
        }

        Sleep(500);
        waited += 500;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);

    if (!running && allowRepair && ServiceDeploy_AttemptSvchostStartupRepair(serviceName, dllPath))
    {
        return ServiceDeploy_StartSvchostServiceAndWait(serviceName, dllPath, timeoutMs, FALSE);
    }

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

    if (!ServiceDeploy_BuildInstalledMshPath(paths->exePath, mshPath, mshPathCch)) { return FALSE; }
    configHealthy = ServiceDeploy_ConfigHasRequiredKeys(paths->confPath);
    mshHealthy = ServiceDeploy_ConfigHasRequiredKeys(mshPath);
    if (configHealthy && mshHealthy) { return TRUE; }

    return ServiceDeploy_DataStoreValueExists(paths->dbPath, "NodeID", NULL, 0, NULL);
}

static BOOL ServiceDeploy_BuildSiblingPathWithExtension(const wchar_t* sourcePath, const wchar_t* extension, wchar_t* outPath, size_t outPathCch)
{
    if (sourcePath == NULL || sourcePath[0] == L'\0' || extension == NULL || extension[0] == L'\0' || outPath == NULL || outPathCch == 0) { return FALSE; }
    outPath[0] = L'\0';
    if (FAILED(StringCchCopyW(outPath, outPathCch, sourcePath))) { return FALSE; }

    wchar_t* dot = wcsrchr(outPath, L'.');
    if (dot != NULL)
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

static BOOL ServiceDeploy_CopyFileOverwrite(const wchar_t* sourcePath, const wchar_t* destPath)
{
    const DWORD timeoutMs = 60000;
    const DWORD startTick = GetTickCount();
    DWORD delay = 100;
    DWORD lastErr = ERROR_SUCCESS;

    if (sourcePath == NULL || sourcePath[0] == L'\0' || destPath == NULL || destPath[0] == L'\0') { return FALSE; }
    if (!ServiceDeploy_PathExists(sourcePath)) { return FALSE; }

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
            lastErr == ERROR_ACCESS_DENIED ||
            lastErr == ERROR_ALREADY_EXISTS)
        {
            Sleep(delay);
            if (delay < 1000) { delay += 100; }
            continue;
        }
        break;
    }

    ServiceDeploy_LogInstallEvent(L"[UPDATE] Copy failed (%ls -> %ls, error=%lu)", sourcePath, destPath, lastErr);
    SetLastError(lastErr);
    return FALSE;
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

static void ServiceDeploy_DeleteUpdateTransactionArtifacts(const ServiceUpdateTransaction* tx)
{
    if (tx == NULL) { return; }
    (void)ServiceDeploy_RemoveDirectoryTree(tx->stageDir, FALSE);
    (void)ServiceDeploy_RemoveDirectoryTree(tx->backupDir, FALSE);
    ServiceDeploy_DeleteFileIfPresent(tx->stagedExePath);
    ServiceDeploy_DeleteFileIfPresent(tx->stagedDllPath);
    ServiceDeploy_DeleteFileIfPresent(tx->stagedConfPath);
    ServiceDeploy_DeleteFileIfPresent(tx->stagedMshPath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupExePath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupDllPath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupConfPath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupMshPath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupDbPath);
    ServiceDeploy_DeleteFileIfPresent(tx->expectedDbPath);
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

static BOOL ServiceDeploy_DiscardUpdateBackup(ServiceUpdateTransaction* tx)
{
    if (tx == NULL) { return FALSE; }
    if (!tx->backupsReady)
    {
        return TRUE;
    }
    if (!ServiceDeploy_RemoveDirectoryTree(tx->backupDir, TRUE))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Failed to remove update backup directory (%ls); preserving remaining rollback material", tx->backupDir);
        return FALSE;
    }
    tx->backupsReady = FALSE;
    return TRUE;
}

static BOOL ServiceDeploy_PrepareUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL allowInstalledProvisioning, ServiceUpdateTransaction* tx)
{
    const wchar_t* exeLeaf = NULL;
    const wchar_t* dllLeaf = NULL;
    const wchar_t* confLeaf = NULL;
    const wchar_t* dbLeaf = NULL;
    const wchar_t* mshLeaf = NULL;
    const wchar_t* defaultMshLeaf = L"MeshAgent.msh";
    BOOL installedDbIdentityPresent = FALSE;
    if (paths == NULL || tx == NULL) { return FALSE; }
    ZeroMemory(tx, sizeof(*tx));

    wchar_t stateDir[MAX_PATH] = {0};
    if (!MeshInstaller_CombinePath(stateDir, _countof(stateDir), paths->installDir, L"state")) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->stageDir, _countof(tx->stageDir), stateDir, SERVICE_UPDATE_STAGE_DIR_NAME)) { return FALSE; }
    if (!MeshInstaller_CombinePath(tx->backupDir, _countof(tx->backupDir), stateDir, SERVICE_UPDATE_BACKUP_DIR_NAME)) { return FALSE; }

    Security_CreateInstallationDirectory(stateDir);

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

    ServiceDeploy_DeleteUpdateTransactionArtifacts(tx);
    Security_CreateInstallationDirectory(tx->stageDir);
    Security_CreateInstallationDirectory(tx->backupDir);

    tx->liveExeExists = ServiceDeploy_PathExists(paths->exePath);
    tx->liveDllExists = ServiceDeploy_PathExists(paths->dllPath);
    tx->liveConfExists = ServiceDeploy_PathExists(paths->confPath);
    tx->liveMshExists = ServiceDeploy_PathExists(tx->liveMshPath);
    tx->liveDbExists = ServiceDeploy_PathExists(paths->dbPath);
    installedDbIdentityPresent = ServiceDeploy_DataStoreValueExists(paths->dbPath, "NodeID", NULL, 0, NULL);

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
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to stage a valid provisioning .conf file from package payload");
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
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to stage a valid provisioning .msh file from package payload");
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

    if (!ServiceDeploy_EnsureSvchostDllFile(sourceExePath, sourceDllPath, tx->stagedDllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to stage a valid svchost DLL payload");
        return FALSE;
    }
    tx->stagedDllReady = TRUE;

    return TRUE;
}

static BOOL ServiceDeploy_BackupUpdateTransaction(const ServiceInstallPaths* paths, ServiceUpdateTransaction* tx)
{
    if (paths == NULL || tx == NULL) { return FALSE; }

    tx->backupDbReady = FALSE;
    tx->backupsReady = FALSE;
    tx->rollbackIdentityReady = FALSE;
    tx->postUpdateIdentityReady = FALSE;
    ZeroMemory(&tx->rollbackIdentity, sizeof(tx->rollbackIdentity));
    ZeroMemory(&tx->postUpdateIdentity, sizeof(tx->postUpdateIdentity));

    ServiceDeploy_DeleteFileIfPresent(tx->backupExePath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupDllPath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupConfPath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupMshPath);
    ServiceDeploy_DeleteFileIfPresent(tx->backupDbPath);

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
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to remove existing svchost DLL (%ls)", paths->dllPath);
            return FALSE;
        }
        if (!Security_InstallFiles(tx->stagedDllPath, paths->dllPath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to commit staged svchost DLL to %ls", paths->dllPath);
            return FALSE;
        }
        if (!ServiceDeploy_HardenSvchostDllDacl(paths->dllPath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to apply svchost DLL DACL to %ls", paths->dllPath);
            return FALSE;
        }
        if (!ServiceDeploy_ValidateSvchostPayloadDll(paths->dllPath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Committed svchost DLL failed validation (%ls)", paths->dllPath);
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

static BOOL ServiceDeploy_RollbackUpdateTransaction(const ServiceInstallPaths* paths, const wchar_t* serviceKeyName, const ServiceUpdateTransaction* tx)
{
    if (paths == NULL || serviceKeyName == NULL || serviceKeyName[0] == L'\0' || tx == NULL) { return FALSE; }
    BOOL ok = TRUE;

    if (tx->liveDllExists)
    {
        ok = (ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->dllPath, 60000, L"[UPDATE][ROLLBACK]") &&
            ServiceDeploy_CopyFileOverwrite(tx->backupDllPath, paths->dllPath) && ok);
    }
    if (tx->liveExeExists)
    {
        ok = (ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->exePath, 60000, L"[UPDATE][ROLLBACK]") &&
            ServiceDeploy_CopyFileOverwrite(tx->backupExePath, paths->exePath) && ok);
    }
    if (tx->liveConfExists)
    {
        ok = (ServiceDeploy_CopyFileOverwrite(tx->backupConfPath, paths->confPath) && ok);
    }
    if (tx->liveMshExists)
    {
        ok = (ServiceDeploy_CopyFileOverwrite(tx->backupMshPath, tx->liveMshPath) && ok);
    }
    if (tx->backupDbReady)
    {
        ok = (ServiceDeploy_CopyFileOverwrite(tx->backupDbPath, paths->dbPath) && ok);
    }
    if (ok && paths->exePath[0] != L'\0' && GetFileAttributesW(paths->exePath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!ServiceDeploy_HardenHostExecutableDacl(paths->exePath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to restore host executable DACL during rollback (%ls)", paths->exePath);
            ok = FALSE;
        }
    }
    if (ok && paths->dllPath[0] != L'\0' && GetFileAttributesW(paths->dllPath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!ServiceDeploy_HardenSvchostDllDacl(paths->dllPath))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to restore svchost DLL DACL during rollback (%ls)", paths->dllPath);
            ok = FALSE;
        }
    }

    if (ok)
    {
        ok = ServiceHost_RegisterSvchostService(serviceKeyName, paths->dllPath);
    }
    if (ok)
    {
        ok = ServiceDeploy_VerifySvchostServiceBinding(serviceKeyName, paths->dllPath);
    }
    if (ok)
    {
        ServiceDeploy_RecordServiceDllHash(serviceKeyName, paths->dllPath);
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

static BOOL ServiceDeploy_ClearPendingUpdateArtifacts(const ServiceInstallPaths* paths, const wchar_t* phaseLabel)
{
    BOOL ok = TRUE;
    wchar_t stateDir[MAX_PATH] = {0};
    wchar_t stageDir[MAX_PATH] = {0};
    wchar_t backupDir[MAX_PATH] = {0};
    const wchar_t* safePhase = (phaseLabel != NULL && phaseLabel[0] != L'\0') ? phaseLabel : L"[REPAIR]";

    if (paths == NULL) { return FALSE; }

    if (MeshInstaller_CombinePath(stateDir, _countof(stateDir), paths->installDir, L"state"))
    {
        if (MeshInstaller_CombinePath(stageDir, _countof(stageDir), stateDir, SERVICE_UPDATE_STAGE_DIR_NAME) &&
            ServiceDeploy_PathExists(stageDir) &&
            !ServiceDeploy_RemoveDirectoryTree(stageDir, TRUE))
        {
            ServiceDeploy_LogInstallEvent(L"%ls Failed to remove stale update-stage directory (%ls)", safePhase, stageDir);
            ok = FALSE;
        }
        if (MeshInstaller_CombinePath(backupDir, _countof(backupDir), stateDir, SERVICE_UPDATE_BACKUP_DIR_NAME) &&
            ServiceDeploy_PathExists(backupDir) &&
            !ServiceDeploy_RemoveDirectoryTree(backupDir, TRUE))
        {
            ServiceDeploy_LogInstallEvent(L"%ls Failed to remove stale update-backup directory (%ls)", safePhase, backupDir);
            ok = FALSE;
        }
    }

    if (paths->dbPath[0] != L'\0' && ServiceDeploy_DataStoreValueExists(paths->dbPath, "PendingUpdate", NULL, 0, NULL))
    {
        if (!ServiceDeploy_DataStoreDeleteValue(paths->dbPath, "PendingUpdate"))
        {
            ServiceDeploy_LogInstallEvent(L"%ls Failed to clear PendingUpdate marker from datastore", safePhase);
            ok = FALSE;
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"%ls Cleared stale PendingUpdate marker from datastore", safePhase);
        }
    }

    ServiceDeploy_ClearUpdateActivationHolds(paths, safePhase);

    return ok;
}

// ================================================================
// Complete Installation Function
// ================================================================

static BOOL ServiceDeploy_ApplyInstallFlow(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    BOOL useSvchostMode)
{
    UNREFERENCED_PARAMETER(useSvchostMode);
    ServiceInstallPaths paths;
    BOOL success = FALSE;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    wchar_t serviceDescription[512] = {0};
    ServicePackagePreflight preflight;
    wchar_t preflightReason[512] = {0};
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (persistence)
    {
        ServiceDeploy_LogInstallEvent(L"Persistence profile: runKey=%u task=%u restart=%u watchdog=%u",
            persistence->runKey,
            persistence->autorunTask.enabled,
            persistence->restartTask.enabled,
            persistence->watchdog.enabled);
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"Persistence profile missing; RunKey/Task disabled");
    }

    ServiceDeploy_ResolveRuntimeServiceBranding(
        serviceKeyName,
        _countof(serviceKeyName),
        serviceDisplayName,
        _countof(serviceDisplayName),
        serviceDescription,
        _countof(serviceDescription));

    // Get installation paths
    if (!ServiceDeploy_GetInstallPaths(&paths))
    {
        ServiceUtil_DebugPrintfW(L"ServiceDeploy_GetInstallPaths failed");
        ServiceDeploy_LogInstallEvent(L"Install paths unavailable; aborting install");
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(L"Install paths resolved (root=%ls)", paths.installDir);
    {
        size_t removedAliases = ServiceDeploy_CleanupConflictingServiceAliases(&paths, serviceKeyName);
        if (removedAliases > 0)
        {
            ServiceDeploy_LogInstallEvent(L"[ALIAS] Removed %Iu conflicting service alias(es) before install", removedAliases);
        }
    }
    ZeroMemory(&preflight, sizeof(preflight));
    if (!ServiceDeploy_PreflightPackageSource(sourceExePath, TRUE, &preflight, preflightReason, _countof(preflightReason)))
    {
        ServiceDeploy_LogInstallEvent(L"[INSTALL] Package preflight failed: %ls", preflightReason);
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(
        L"[INSTALL] Package preflight passed (embeddedProvisioning=%u sidecarProvisioning=%u)",
        preflight.sourceEmbeddedConfigPresent,
        preflight.sourceSidecarConfigPresent);
    if (sourceDllPath != NULL && sourceDllPath[0] != L'\0' && !ServiceDeploy_ValidateSvchostPayloadDll(sourceDllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[INSTALL] Package preflight failed: invalid svchost DLL source (%ls)", sourceDllPath);
        return FALSE;
    }

    ServiceDeploy_ImportWinHttpProxyFromIeBestEffort();

    // Pre-clean: stop any running service and remove stale artifacts from prior failed installs
    ServiceDeploy_StopServiceAndWait(serviceKeyName, 20000, TRUE);
    ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);
    ServiceDeploy_TerminateProcessesByPath(paths.exePath);
    {
        wchar_t staleStateDir[MAX_PATH] = {0};
        wchar_t staleStageDir[MAX_PATH] = {0};
        wchar_t staleBackupDir[MAX_PATH] = {0};
        if (MeshInstaller_CombinePath(staleStateDir, _countof(staleStateDir), paths.installDir, L"state"))
        {
            if (MeshInstaller_CombinePath(staleStageDir, _countof(staleStageDir), staleStateDir, SERVICE_UPDATE_STAGE_DIR_NAME))
            {
                ServiceDeploy_RemoveDirectoryTree(staleStageDir, FALSE);
            }
            if (MeshInstaller_CombinePath(staleBackupDir, _countof(staleBackupDir), staleStateDir, SERVICE_UPDATE_BACKUP_DIR_NAME))
            {
                ServiceDeploy_RemoveDirectoryTree(staleBackupDir, FALSE);
            }
        }
    }

    // Step 1: Create installation directories
    if (!Security_CreateInstallRootDirectory(paths.installDir))
    {
        ServiceUtil_DebugPrintfW(L"Failed to create install directory: %ls", paths.installDir);
        ServiceDeploy_LogInstallEvent(L"Failed to create install directory: %ls", paths.installDir);
        return FALSE;
    }

    if (!Security_CreateInstallationDirectory(paths.logsDir))
    {
        // Non-fatal, continue
    }

    // Step 2: Copy executable (for CLI usage) if a source path is provided
    if (sourceExePath && sourceExePath[0] != L'\0')
    {
        if (!Security_InstallFiles(sourceExePath, paths.exePath))
        {
            ServiceUtil_DebugPrintfW(L"Security_InstallFiles failed (EXE) %ls -> %ls", sourceExePath, paths.exePath);
            ServiceDeploy_LogInstallEvent(L"Failed to copy executable to %ls", paths.exePath);
            return FALSE;
        }
        ServiceDeploy_LogInstallEvent(L"Copied executable to %ls", paths.exePath);
    }

    // Host binary must be executable by interactive users so the KVM helper can be launched
    // via CreateProcessAsUser() in the active session.
    if (paths.exePath[0] != L'\0' && GetFileAttributesW(paths.exePath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!ServiceDeploy_HardenHostExecutableDacl(paths.exePath))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to apply host executable DACL to %ls", paths.exePath);
            return FALSE;
        }
    }

    if (sourceExePath && sourceExePath[0] != L'\0')
    {
        if (!ServiceDeploy_EnsureConfigFile(sourceExePath, paths.confPath))
        {
            ServiceDeploy_LogInstallEvent(L"Failed to stage required provisioning config to %ls", paths.confPath);
            return FALSE;
        }
        ServiceDeploy_LogInstallEvent(L"Provisioning config staged to %ls", paths.confPath);
    }

    if (paths.exePath[0] != L'\0')
    {
        wchar_t mshPath[MAX_PATH] = {0};
        StringCchCopyW(mshPath, _countof(mshPath), paths.exePath);
        wchar_t* dot = wcsrchr(mshPath, L'.');
        if (dot != NULL)
        {
            StringCchCopyW(dot, _countof(mshPath) - (dot - mshPath), L".msh");
        }
        else
        {
            StringCchCatW(mshPath, _countof(mshPath), L".msh");
        }

        if (!ServiceDeploy_EnsureMshFile(sourceExePath, mshPath))
        {
            ServiceDeploy_LogInstallEvent(L"Failed to stage required provisioning msh to %ls", mshPath);
            return FALSE;
        }
        ServiceDeploy_LogInstallEvent(L"Provisioning msh staged to %ls", mshPath);

        if (ServiceDeploy_ShouldEnableDebugConsole())
        {
            ServiceDeploy_AppendConfigOverride(paths.confPath, "debugConsole", "1");
            ServiceDeploy_AppendConfigOverride(mshPath, "debugConsole", "1");
        }
    }

    // Always stage the svchost DLL payload
    ServiceDeploy_RemoveFileIfExists(paths.dllPath, TRUE);
    if (!ServiceDeploy_EnsureSvchostDllFile(sourceExePath, sourceDllPath, paths.dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to stage a valid svchost DLL to %ls", paths.dllPath);
        ServiceDeploy_LogPathState(paths.dllPath);
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(L"Svchost payload staged to %ls", paths.dllPath);

    // Register svchost-hosted service only
    if (!ServiceHost_RegisterSvchostService(serviceKeyName, paths.dllPath))
    {
        ServiceUtil_DebugPrintfW(L"ServiceHost_RegisterSvchostService failed for %ls", serviceKeyName);
        ServiceDeploy_LogInstallEvent(L"Svchost registration failed for %ls (error=%lu)", serviceKeyName, GetLastError());
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(L"Svchost registration complete for %ls", serviceKeyName);
    if (!ServiceDeploy_VerifySvchostServiceBinding(serviceKeyName, paths.dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"Svchost registration binding verification failed for %ls", serviceKeyName);
        return FALSE;
    }
    ServiceDeploy_RecordServiceDllHash(serviceKeyName, paths.dllPath);
    ServiceDeploy_RemoveInactiveSvchostPayloadDlls(&paths);
    ServiceDeploy_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName);
    ServiceDeploy_ApplyPersistenceProfile();
    success = TRUE;
    ServiceDeploy_StopServiceAndWait(serviceKeyName, 20000, TRUE);

    if (MeshService_HardenServiceDaclByName(serviceKeyName))
    {
        ServiceDeploy_LogInstallEvent(L"Hardened service DACL for %ls", serviceKeyName);
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to harden service DACL for %ls (see debug output)", serviceKeyName);
    }

    if (ServiceUtil_ProtectServiceFromTermination(serviceKeyName))
    {
        ServiceDeploy_LogInstallEvent(L"Configured service termination protection for %ls", serviceKeyName);
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Service termination protections not applied to %ls", serviceKeyName);
    }

    // Step 4: Add Windows Firewall exceptions
    wchar_t systemSvchostPath[MAX_PATH] = {0};
    const wchar_t* hostToExcept = NULL;
    if (ServiceUtil_GetSystemSvchostPathW(systemSvchostPath, _countof(systemSvchostPath)))
    {
        hostToExcept = systemSvchostPath;
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"[ERROR] Unable to resolve system svchost.exe for firewall provisioning");
        return FALSE;
    }

    if (!ServiceDeploy_RefreshFirewallRulesWithRetry(serviceKeyName, hostToExcept, paths.exePath))
    {
        ServiceDeploy_LogInstallEvent(L"[ERROR] Firewall rule provisioning failed for %ls", serviceKeyName);
        return FALSE;
    }

    // Step 5: Apply service resilience (Task Scheduler / WMI restart subscriptions)
    ServiceDeploy_LogInstallEvent(L"Applying service resilience configuration");

    // Step 6: Hide service registry key (optional, can make debugging harder)

    // Step 7: Start the service and confirm running state
    if (!ServiceDeploy_StartSvchostServiceAndWait(serviceKeyName, paths.dllPath, 20000, TRUE))
    {
        ServiceDeploy_LogInstallEvent(L"Installation failed: service failed to reach RUNNING state for %ls", serviceKeyName);
        return FALSE;
    }
    ServiceDeploy_LogInstallEvent(L"Service reached RUNNING state for %ls", serviceKeyName);

    return success;
}

static BOOL ServiceDeploy_ApplyRepairFlow(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode)
{
    ServiceInstallPaths paths;
    ServiceLifecycleDiscovery finalState;

    if (!ServiceDeploy_ApplyInstallFlow(sourceExePath, sourceDllPath, useSvchostMode))
    {
        return FALSE;
    }

    if (!ServiceDeploy_GetInstallPaths(&paths))
    {
        ServiceDeploy_LogInstallEvent(L"[REPAIR] Failed to resolve install paths after repair install");
        return FALSE;
    }

    if (!ServiceDeploy_ClearPendingUpdateArtifacts(&paths, L"[REPAIR]"))
    {
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
    wchar_t svchostPath[MAX_PATH] = {0};
    wchar_t stateDatPath[MAX_PATH] = {0};
    wchar_t stateDirPath[MAX_PATH] = {0};
    wchar_t controlLogPath[MAX_PATH] = {0};
    wchar_t svchostDebugPath[MAX_PATH] = {0};

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

    // Clean up any persistence artifacts that may have been recreated during shutdown
    ServiceDeploy_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);
    ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, TRUE);
    ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);
    ServiceDeploy_TerminateProcessesByPath(paths.exePath);

    if (!ServiceHost_UnregisterSvchostService(serviceKeyName))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to unregister service %ls", serviceKeyName);
        success = FALSE;
    }
    else if (!ServiceDeploy_WaitForServiceAbsence(serviceKeyName, 30000))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Service removal did not converge within timeout for %ls", serviceKeyName);
        success = FALSE;
    }

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
    if (!ServiceDeploy_RemoveFileIfExists(paths.logPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(paths.confPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(paths.exePath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(paths.dllPath, TRUE)) { success = FALSE; }

    MeshInstaller_CombinePath(svchostPath, _countof(svchostPath), paths.installDir, L"svchost.exe");
    MeshInstaller_CombinePath(stateDatPath, _countof(stateDatPath), paths.installDir, L"state.dat");
    MeshInstaller_CombinePath(stateDirPath, _countof(stateDirPath), paths.installDir, L"state");
    MeshInstaller_CombinePath(controlLogPath, _countof(controlLogPath), paths.installDir, L"controlchannel-debug.log");
    MeshInstaller_CombinePath(svchostDebugPath, _countof(svchostDebugPath), paths.installDir, L"svchost-debug.log");

    if (!Security_RemoveFirewallRulesByExePath(svchostPath))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Failed to remove firewall rules for %ls", svchostPath);
        success = FALSE;
    }

    if (!ServiceDeploy_RemoveFileIfExists(controlLogPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(svchostDebugPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(stateDatPath, TRUE)) { success = FALSE; }
    if (!ServiceDeploy_RemoveFileIfExists(svchostPath, TRUE)) { success = FALSE; }

    if (!ServiceDeploy_RemoveDirectoryTree(stateDirPath, TRUE)) { success = FALSE; }

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

static BOOL ServiceDeploy_ApplyUpdateFlow(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode, BOOL requireConfig)
{
    if (!useSvchostMode)
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Svchost mode required; update aborted");
        return FALSE;
    }

    ServiceInstallPaths paths;
    BOOL success = TRUE;
    BOOL restartService = TRUE;
    BOOL serviceExists = FALSE;
    BOOL rollbackCompleted = FALSE;
    BOOL failureHoldRecorded = FALSE;
    wchar_t serviceKeyName[256] = {0};
    wchar_t serviceDisplayName[256] = {0};
    wchar_t liveMshPath[MAX_PATH] = {0};
    ServiceUpdateTransaction tx;
    ServicePackagePreflight preflight;
    wchar_t preflightReason[512] = {0};
    BOOL allowInstalledProvisioning = FALSE;
    ZeroMemory(&tx, sizeof(tx));
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

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
    {
        size_t removedAliases = ServiceDeploy_CleanupConflictingServiceAliases(&paths, serviceKeyName);
        if (removedAliases > 0)
        {
            ServiceDeploy_LogInstallEvent(L"[ALIAS] Removed %Iu conflicting service alias(es) before update", removedAliases);
        }
    }
    serviceExists = ServiceDeploy_IsAlreadyInstalled();

    ZeroMemory(&preflight, sizeof(preflight));
    if (!ServiceDeploy_PreflightPackageSource(sourceExePath, FALSE, &preflight, preflightReason, _countof(preflightReason)))
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
        if (!ServiceDeploy_InstalledProvisioningHealthy(&paths, liveMshPath, _countof(liveMshPath)))
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
    if (sourceDllPath != NULL && sourceDllPath[0] != L'\0' && !ServiceDeploy_ValidateSvchostPayloadDll(sourceDllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Package preflight failed: invalid svchost DLL source (%ls)", sourceDllPath);
        return FALSE;
    }

    ServiceDeploy_ImportWinHttpProxyFromIeBestEffort();

    Security_CreateInstallRootDirectory(paths.installDir);
    Security_CreateInstallationDirectory(paths.logsDir);

    // Pre-clean stale staging/backup artifacts from prior failed updates
    {
        wchar_t staleStateDir[MAX_PATH] = {0};
        wchar_t staleStageDir[MAX_PATH] = {0};
        wchar_t staleBackupDir[MAX_PATH] = {0};
        if (MeshInstaller_CombinePath(staleStateDir, _countof(staleStateDir), paths.installDir, L"state"))
        {
            if (MeshInstaller_CombinePath(staleStageDir, _countof(staleStageDir), staleStateDir, SERVICE_UPDATE_STAGE_DIR_NAME))
            {
                ServiceDeploy_RemoveDirectoryTree(staleStageDir, FALSE);
            }
            if (MeshInstaller_CombinePath(staleBackupDir, _countof(staleBackupDir), staleStateDir, SERVICE_UPDATE_BACKUP_DIR_NAME))
            {
                ServiceDeploy_RemoveDirectoryTree(staleBackupDir, FALSE);
            }
        }
    }

    if (!ServiceDeploy_PrepareUpdateTransaction(&paths, sourceExePath, sourceDllPath, allowInstalledProvisioning, &tx))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to prepare staged update transaction");
        return FALSE;
    }

    // Disable restart mechanisms before stopping to avoid immediate re-launch.
    // Keep the SCM start type repairable/auto-start: disabling it before old-image
    // teardown can strand the endpoint if svchost terminates unexpectedly.
    ServicePersistenceState persisted = {0};
    BOOL havePersisted = ServiceDeploy_LoadPersistenceState(&persisted);

    DWORD originalStartType = SERVICE_AUTO_START;
    if (serviceExists)
    {
        if (!ServiceDeploy_QueryServiceStartType(serviceKeyName, &originalStartType))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Unable to query service start type before update (%ls, error=%lu)", serviceKeyName, GetLastError());
            originalStartType = SERVICE_AUTO_START;
        }
        if (originalStartType != SERVICE_AUTO_START)
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Repairing service start type before update (%ls, original=%lu target=%lu)", serviceKeyName, originalStartType, (DWORD)SERVICE_AUTO_START);
        }
        if (!ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_AUTO_START))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Failed to ensure service auto-start before update (%ls, error=%lu)", serviceKeyName, GetLastError());
        }
    }

    ServiceDeploy_ClearServiceRecovery(serviceKeyName);
    ServiceDeploy_RemoveRunKeyEntry(serviceKeyName);
    ServiceDeploy_RemoveScheduledTasks(persistence, serviceDisplayName, serviceKeyName);
    if (havePersisted && persisted.WmiFilter[0] != L'\0' && persisted.WmiConsumer[0] != L'\0')
    {
        if (FaultRecovery_RemoveWmiSubscription(persisted.WmiFilter, persisted.WmiConsumer))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] WMI restart subscription removed (%ls/%ls)", persisted.WmiFilter, persisted.WmiConsumer);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Failed to remove WMI restart subscription (%ls/%ls)", persisted.WmiFilter, persisted.WmiConsumer);
        }
    }

    if (serviceExists && !ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000, TRUE))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Service stop timed out; forcing dedicated host teardown");
        ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);
        ServiceDeploy_TerminateProcessesByPath(paths.exePath);
        Sleep(1000);
        if (ServiceDeploy_ServiceIsRunning(serviceKeyName))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Service still running after forced teardown; aborting update");
            success = FALSE;
            goto CLEANUP;
        }
    }
    if (!serviceExists)
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Existing service registration absent; continuing with repair install semantics");
    }

    ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);
    ServiceDeploy_TerminateProcessesByPath(paths.exePath);

    // Wait for file locks to release after process termination (DLL may still be held briefly)
    if (paths.dllPath[0] != L'\0' && GetFileAttributesW(paths.dllPath) != INVALID_FILE_ATTRIBUTES)
    {
        DWORD lockWaitStart = GetTickCount();
        while ((GetTickCount() - lockWaitStart) < 10000)
        {
            HANDLE hTest = CreateFileW(paths.dllPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

    if (!ServiceDeploy_BackupUpdateTransaction(&paths, &tx))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to capture quiesced rollback set");
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

    if (!ServiceHost_RegisterSvchostService(serviceKeyName, paths.dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Svchost registration failed for %ls (error=%lu)", serviceKeyName, GetLastError());
        success = FALSE;
        goto CLEANUP;
    }
    if (!ServiceDeploy_VerifySvchostServiceBinding(serviceKeyName, paths.dllPath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Svchost binding verification failed for %ls", serviceKeyName);
        success = FALSE;
        goto CLEANUP;
    }
    ServiceDeploy_RecordServiceDllHash(serviceKeyName, paths.dllPath);
    ServiceDeploy_RemoveInactiveSvchostPayloadDlls(&paths);

CLEANUP:
    if (serviceExists && !ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_AUTO_START))
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Failed to restore service auto-start during cleanup (%ls, error=%lu)", serviceKeyName, GetLastError());
        success = FALSE;
    }
    ServiceDeploy_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName);
    ServiceDeploy_ApplyPersistenceProfile();

    MeshService_HardenServiceDaclByName(serviceKeyName);
    ServiceUtil_ProtectServiceFromTermination(serviceKeyName);

    // Refresh firewall rules (host svchost + WebRTC inbound UDP)
    wchar_t systemSvchostPath[MAX_PATH] = {0};
    const wchar_t* hostToExcept = NULL;
    if (ServiceUtil_GetSystemSvchostPathW(systemSvchostPath, _countof(systemSvchostPath)))
    {
        hostToExcept = systemSvchostPath;
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Unable to resolve system svchost.exe for firewall provisioning");
        success = FALSE;
    }

    if (hostToExcept != NULL && !ServiceDeploy_RefreshFirewallRulesWithRetry(serviceKeyName, hostToExcept, paths.exePath))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Firewall rule provisioning failed for %ls", serviceKeyName);
        success = FALSE;
    }

    // The service owns the datastore with a non-shareable writer once started.
    // Clear successful-activation markers while the service is still stopped.
    if (success)
    {
        (void)ServiceDeploy_ClearUpdateActivationHolds(&paths, L"[UPDATE]");
        if (!ServiceDeploy_FinalizeUpdateTransaction(&paths, &tx))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Transaction cleanup incomplete before service restart; retaining rollback capability");
        }
    }

    if (restartService)
    {
        if (!ServiceDeploy_StartSvchostServiceAndWait(serviceKeyName, paths.dllPath, 30000, TRUE))
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Service failed to reach RUNNING state after update for %ls", serviceKeyName);
            success = FALSE;
        }
    }

    if (success)
    {
        ServiceLifecycleDiscovery finalState;
        if (!ServiceDeploy_WaitForPrimaryLifecycleOperational(30000, &finalState))
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
        else if (!ServiceDeploy_WaitForPrimaryLifecycleOperational(30000, &finalState))
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
            ServiceIdentitySnapshot finalIdentity;
            // Commit point: primary runtime and identity are valid and transactional
            // cleanup succeeded. From here on, backup/degraded companion cleanup is
            // best effort and must never trigger rollback from deleted material.
            (void)ServiceDeploy_DiscardUpdateBackup(&tx);
            if (!ServiceDeploy_WaitForPrimaryLifecycleHealthy(30000, &finalState))
            {
                ServiceDeploy_LogInstallEvent(
                    L"[WARN] [UPDATE] Primary agent is operational but final companion cleanup remains degraded (state=%ls pending=%u stageArtifacts=%u backupArtifacts=%u firewall=%u persistence=%u)",
                    ServiceDeploy_LifecycleStateToString(finalState.stateKind),
                    finalState.pendingUpdate,
                    finalState.updateStageArtifactsPresent,
                    finalState.updateBackupArtifactsPresent,
                    finalState.firewallHealthy,
                    finalState.persistenceHealthy);
            }
            if (finalState.stateKind != SERVICE_LIFECYCLE_STATE_HEALTHY)
            {
                ServiceDeploy_LogInstallEvent(L"[UPDATE] Primary agent converged but companion state remains degraded (%ls)",
                    ServiceDeploy_LifecycleStateToString(finalState.stateKind));
            }
            if (ServiceDeploy_CaptureIdentitySnapshot(paths.dbPath, &finalIdentity))
            {
                ServiceDeploy_LogIdentitySnapshot(L"after-update", &finalIdentity);
            }
        }
    }

    if (!success)
    {
        BOOL canRollback = tx.backupsReady;
        if (canRollback)
        {
            BOOL rollbackOk = FALSE;
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Attempting rollback for %ls", serviceKeyName);
            (void)ServiceDeploy_StopServiceAndWait(serviceKeyName, 20000, TRUE);
            ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);
            ServiceDeploy_TerminateProcessesByPath(paths.exePath);
            rollbackOk = ServiceDeploy_RollbackUpdateTransaction(&paths, serviceKeyName, &tx);
            if (rollbackOk)
            {
                // Promote the target to a failure hold before restarting the old
                // service, otherwise its writable datastore handle blocks this write.
                failureHoldRecorded = ServiceDeploy_RecordUpdateActivationFailureHold(&paths);
                if (!ServiceDeploy_FinalizeUpdateTransaction(&paths, &tx))
                {
                    ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Rollback cleanup incomplete before service restart");
                }
            }
            if (rollbackOk && restartService)
            {
                rollbackOk = ServiceDeploy_StartSvchostServiceAndWait(serviceKeyName, paths.dllPath, 30000, TRUE);
            }
            if (rollbackOk)
            {
                ServiceLifecycleDiscovery rollbackState;
                rollbackOk = ServiceDeploy_WaitForPrimaryLifecycleOperational(30000, &rollbackState);
                if (!rollbackOk)
                {
                    ServiceDeploy_LogInstallEvent(
                        L"[UPDATE] Rollback primary lifecycle did not converge before transaction cleanup (state=%ls pending=%u stageArtifacts=%u backupArtifacts=%u firewall=%u persistence=%u)",
                        ServiceDeploy_LifecycleStateToString(rollbackState.stateKind),
                        rollbackState.pendingUpdate,
                        rollbackState.updateStageArtifactsPresent,
                        rollbackState.updateBackupArtifactsPresent,
                        rollbackState.firewallHealthy,
                        rollbackState.persistenceHealthy);
                }
                if (rollbackOk)
                {
                    rollbackOk = (!tx.rollbackIdentityReady ||
                        ServiceDeploy_WaitForExpectedIdentity(paths.dbPath, &tx.rollbackIdentity, 30000));
                    if (!rollbackOk)
                    {
                        ServiceDeploy_LogInstallEvent(L"[UPDATE] Identity preservation check failed after rollback");
                    }
                }
                if (rollbackOk)
                {
                    (void)ServiceDeploy_DiscardUpdateBackup(&tx);
                    if (!ServiceDeploy_WaitForPrimaryLifecycleHealthy(30000, &rollbackState))
                    {
                        ServiceDeploy_LogInstallEvent(
                            L"[WARN] [UPDATE] Rollback restored the primary agent but companion cleanup remains degraded (state=%ls pending=%u stageArtifacts=%u backupArtifacts=%u firewall=%u persistence=%u)",
                            ServiceDeploy_LifecycleStateToString(rollbackState.stateKind),
                            rollbackState.pendingUpdate,
                            rollbackState.updateStageArtifactsPresent,
                            rollbackState.updateBackupArtifactsPresent,
                            rollbackState.firewallHealthy,
                            rollbackState.persistenceHealthy);
                    }
                }
                if (rollbackOk)
                {
                    ServiceIdentitySnapshot rollbackIdentity;
                    if (rollbackState.stateKind != SERVICE_LIFECYCLE_STATE_HEALTHY)
                    {
                        ServiceDeploy_LogInstallEvent(L"[UPDATE] Rollback restored primary agent health but companion state remains degraded (%ls)",
                            ServiceDeploy_LifecycleStateToString(rollbackState.stateKind));
                    }
                    if (ServiceDeploy_CaptureIdentitySnapshot(paths.dbPath, &rollbackIdentity))
                    {
                        ServiceDeploy_LogIdentitySnapshot(L"after-rollback", &rollbackIdentity);
                    }
                }
            }
            rollbackCompleted = rollbackOk;
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Rollback %ls for %ls", rollbackOk ? L"completed" : L"failed", serviceKeyName);
        }
    }

    if (success)
    {
        // Safe after the commit point; this is a best-effort sweep only.
        ServiceDeploy_DeleteUpdateTransactionArtifacts(&tx);
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Update completed for %ls", serviceKeyName);
    }
    else
    {
        if (!failureHoldRecorded && !ServiceDeploy_RecordUpdateActivationFailureHold(&paths))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] [UPDATE] Unable to persist failed package hold");
        }
        if (rollbackCompleted || !tx.backupsReady)
        {
            ServiceDeploy_DeleteUpdateTransactionArtifacts(&tx);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"[UPDATE] Preserving transaction artifacts after failed rollback (%ls)", tx.backupDir);
        }
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Update failed for %ls", serviceKeyName);
    }
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
    BOOL serviceGroup;
    BOOL serviceAccount;
    BOOL serviceDll;
    BOOL serviceMain;
    BOOL serviceUnload;
    BOOL serviceDllHash;
    BOOL serviceDacl;
    BOOL serviceAliasClean;
    BOOL serviceRunning;
    BOOL firewallRule;
    BOOL persistenceState;
    BOOL autorunTask;
    BOOL restartTask;
    BOOL wmiSubscription;
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

static BOOL ServiceDeploy_ValidateInstallRootDacl(const wchar_t* path)
{
    return ServiceDeploy_ValidatePathDaclWithExpected(path, SERVICE_INSTALL_ROOT_DACL_SDDL);
}

static BOOL ServiceDeploy_ValidateHostExecutableDacl(const wchar_t* exePath)
{
    return ServiceDeploy_ValidatePathDaclWithExpected(exePath, SERVICE_HOST_EXE_DACL_SDDL);
}

static BOOL ServiceDeploy_ValidateSvchostDllDacl(const wchar_t* dllPath)
{
    return ServiceDeploy_ValidatePathDaclWithExpected(dllPath, SERVICE_DLL_DACL_SDDL);
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
    ILibSimpleDataStore_Close(store);
    return (putStatus == 0);
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
    ILibSimpleDataStore_Close(store);
    return (deleteStatus != 0);
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

static BOOL ServiceDeploy_ReadUpdateActivationTargetHash(const ServiceInstallPaths* paths, char* valueOut, size_t valueOutLen, int* valueLenOut)
{
    char value[MESHAGENT_UPDATE_HASH_HEX_LENGTH + 4] = {0};
    int valueLen = 0;

    if (valueLenOut != NULL) { *valueLenOut = 0; }
    if (valueOut != NULL && valueOutLen > 0) { valueOut[0] = 0; }
    if (paths == NULL || paths->dbPath[0] == L'\0') { return FALSE; }
    if (!ServiceDeploy_DataStoreValueExists(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY, value, sizeof(value), &valueLen)) { return FALSE; }
    valueLen = MeshAgent_NormalizeUpdateHashHex(value, valueLen, sizeof(value));
    if (valueLen == 0)
    {
        (void)ServiceDeploy_DataStoreDeleteValue(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY);
        return FALSE;
    }
    if (valueOut != NULL && valueOutLen > 0)
    {
        if (valueOutLen <= (size_t)valueLen) { return FALSE; }
        memcpy_s(valueOut, valueOutLen, value, (size_t)valueLen + 1);
    }
    if (valueLenOut != NULL) { *valueLenOut = valueLen; }
    return TRUE;
}

static BOOL ServiceDeploy_ClearUpdateActivationHolds(const ServiceInstallPaths* paths, const wchar_t* phaseLabel)
{
    const wchar_t* safePhase = (phaseLabel != NULL && phaseLabel[0] != L'\0') ? phaseLabel : L"[UPDATE]";
    BOOL ok = TRUE;
    if (paths == NULL || paths->dbPath[0] == L'\0') { return FALSE; }

    if (ServiceDeploy_DataStoreValueExists(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY, NULL, 0, NULL))
    {
        if (ServiceDeploy_DataStoreDeleteValue(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY))
        {
            ServiceDeploy_LogInstallEvent(L"%ls Cleared update activation target marker", safePhase);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"%ls Failed to clear update activation target marker", safePhase);
            ok = FALSE;
        }
    }
    if (ServiceDeploy_DataStoreValueExists(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY, NULL, 0, NULL))
    {
        if (ServiceDeploy_DataStoreDeleteValue(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY))
        {
            ServiceDeploy_LogInstallEvent(L"%ls Cleared update activation failure marker", safePhase);
        }
        else
        {
            ServiceDeploy_LogInstallEvent(L"%ls Failed to clear update activation failure marker", safePhase);
            ok = FALSE;
        }
    }
    return ok;
}

static BOOL ServiceDeploy_RecordUpdateActivationFailureHold(const ServiceInstallPaths* paths)
{
    char targetHash[MESHAGENT_UPDATE_HASH_HEX_LENGTH + 1] = {0};
    int targetHashLen = 0;

    if (paths == NULL || paths->dbPath[0] == L'\0') { return FALSE; }
    if (!ServiceDeploy_ReadUpdateActivationTargetHash(paths, targetHash, sizeof(targetHash), &targetHashLen)) { return FALSE; }

    if (ServiceDeploy_DataStorePutValue(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY, targetHash, (size_t)targetHashLen))
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Recorded failed update activation package hash hold");
        (void)ServiceDeploy_DataStoreDeleteValue(paths->dbPath, MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY);
        return TRUE;
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"[UPDATE] Failed to record update activation package hash hold");
    }
    return FALSE;
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
                    ok = TRUE;
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

static BOOL ServiceDeploy_IsPrimaryLifecycleConverged(const ServiceLifecycleDiscovery* discovery, BOOL requirePendingClear)
{
    if (discovery == NULL) { return FALSE; }

    const BOOL identityHealthy = (discovery->configKeysValid ||
                                  (discovery->dbExists && discovery->nodeIdPresent));
    const BOOL filesystemHealthy = (discovery->installRootExists &&
                                    discovery->logsDirExists &&
                                    discovery->exeExists &&
                                    discovery->dllExists &&
                                    discovery->installRootDaclValid &&
                                    discovery->logsDirDaclValid &&
                                    discovery->exeDaclValid &&
                                    discovery->dllDaclValid &&
                                    identityHealthy);
    const BOOL serviceHealthy = (discovery->serviceExists &&
                                 discovery->serviceRunning &&
                                 discovery->serviceKeyExists &&
                                 discovery->serviceTypeValid &&
                                 discovery->serviceStartValid &&
                                 discovery->serviceImageValid &&
                                 discovery->serviceGroupValid &&
                                 discovery->serviceAccountValid &&
                                 discovery->serviceDllValid &&
                                 discovery->serviceMainValid &&
                                 discovery->serviceUnloadValid &&
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
    discovery->dllDaclValid = (discovery->dllExists ? ServiceDeploy_ValidateSvchostDllDacl(discovery->paths.dllPath) : FALSE);
    discovery->configKeysValid = (discovery->confExists ? ServiceDeploy_ConfigHasRequiredKeys(discovery->paths.confPath) : FALSE);

    HKEY serviceKey = NULL;
    discovery->serviceKeyExists = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, 0, KEY_QUERY_VALUE, &serviceKey) == ERROR_SUCCESS);
    if (serviceKey != NULL) { RegCloseKey(serviceKey); }

    discovery->serviceExists = ServiceDeploy_IsAlreadyInstalled();
    discovery->serviceRunning = (discovery->serviceExists ? ServiceDeploy_ServiceIsRunning(discovery->serviceKeyName) : FALSE);
    if (discovery->serviceKeyExists)
    {
        DWORD typeValue = 0;
        DWORD startValue = 0;
        DWORD unloadValue = 0;
        wchar_t imagePath[512] = {0};
        wchar_t objectName[256] = {0};
        wchar_t serviceDll[512] = {0};
        wchar_t serviceMain[128] = {0};

        discovery->serviceTypeValid = (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, L"Type", &typeValue) &&
                                       typeValue == SERVICE_WIN32_SHARE_PROCESS);
        discovery->serviceStartValid = (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, L"Start", &startValue) &&
                                        startValue == SERVICE_AUTO_START);
        if (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, L"ImagePath", imagePath, _countof(imagePath), NULL))
        {
            wchar_t imagePathUpper[512] = {0};
            StringCchCopyW(imagePathUpper, _countof(imagePathUpper), imagePath);
            MeshInstaller_UppercaseInplace(imagePathUpper);
            discovery->serviceImageValid = (wcsstr(imagePathUpper, L"SVCHOST.EXE") != NULL);
            discovery->serviceGroupValid = (wcsstr(imagePathUpper, L"-K NETSVCS") != NULL);
        }
        discovery->serviceAccountValid = (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, discovery->serviceKeyPath, L"ObjectName", objectName, _countof(objectName), NULL) &&
                                          _wcsicmp(objectName, L"LocalSystem") == 0);
        discovery->serviceDllValid = (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, discovery->serviceParamsPath, L"ServiceDll", serviceDll, _countof(serviceDll), NULL) &&
                                      _wcsicmp(serviceDll, discovery->paths.dllPath) == 0);
        discovery->serviceMainValid = (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, discovery->serviceParamsPath, L"ServiceMain", serviceMain, _countof(serviceMain), NULL) &&
                                       _wcsicmp(serviceMain, L"ServiceHost_SvchostServiceMain") == 0);
        discovery->serviceUnloadValid = (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, discovery->serviceParamsPath, L"ServiceDllUnloadOnStop", &unloadValue) &&
                                         unloadValue == 1);
    }
    discovery->serviceDaclValid = (discovery->serviceExists ? MeshService_ValidateServiceDaclByName(discovery->serviceKeyName, NULL, 0) : FALSE);
    discovery->conflictingServiceAliasCount = (DWORD)ServiceDeploy_CollectConflictingServiceAliases(&discovery->paths, discovery->serviceKeyName, NULL, 0);
    discovery->serviceAliasClean = (discovery->conflictingServiceAliasCount == 0);

    wchar_t systemSvchostPath[MAX_PATH] = {0};
    const wchar_t* hostToValidate = NULL;
    if (ServiceUtil_GetSystemSvchostPathW(systemSvchostPath, _countof(systemSvchostPath)))
    {
        hostToValidate = systemSvchostPath;
    }
    discovery->firewallRulePresent = Security_CheckFirewallRuleExists(discovery->serviceKeyName);
    discovery->firewallHealthy = (hostToValidate != NULL &&
                                  discovery->firewallRulePresent &&
                                  ServiceDeploy_DoFirewallRulesMatch(discovery->serviceKeyName, hostToValidate, discovery->paths.exePath));

    ServicePersistenceState persisted = {0};
    discovery->persistenceStateExists = ServiceDeploy_LoadPersistenceState(&persisted);
    discovery->runKeyPresent = ServiceDeploy_RunKeyValueExists(discovery->serviceKeyName, NULL, 0);

    wchar_t prefixCandidates[10][SERVICE_TASK_NAME_MAX] = {0};
    size_t prefixCount = ServiceDeploy_BuildTaskPrefixCandidates(
        MeshConfig_GetPersistence(),
        discovery->serviceDisplayName,
        discovery->serviceKeyName,
        prefixCandidates,
        _countof(prefixCandidates));
    wchar_t existingTask[SERVICE_TASK_NAME_MAX] = {0};
    discovery->autorunTaskPresent = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-Autorun-", existingTask, _countof(existingTask));
    discovery->restartTaskPresent = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-RestartOnStop-", existingTask, _countof(existingTask));
    discovery->wmiSubscriptionPresent = FALSE;
    if (!discovery->restartTaskPresent)
    {
        wchar_t filterName[128] = {0};
        wchar_t consumerName[128] = {0};
        discovery->wmiSubscriptionPresent = ServiceDeploy_FindWmiByPrefixCandidates(
            prefixCandidates,
            prefixCount,
            filterName,
            _countof(filterName),
            consumerName,
            _countof(consumerName));
    }

    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (ServiceDeploy_IsRundll32OnlyPersistencePolicyActive())
    {
        discovery->persistenceHealthy = (!discovery->persistenceStateExists &&
                                         !discovery->runKeyPresent &&
                                         !discovery->autorunTaskPresent &&
                                         !discovery->restartTaskPresent &&
                                         !discovery->wmiSubscriptionPresent);
    }
    else
    {
        discovery->persistenceHealthy = TRUE;
        if (persistence != NULL)
        {
            if (!discovery->persistenceStateExists)
            {
                discovery->persistenceHealthy = FALSE;
            }
            if (persistence->runKey != 0 && !discovery->runKeyPresent)
            {
                discovery->persistenceHealthy = FALSE;
            }
            if (persistence->autorunTask.enabled && !discovery->autorunTaskPresent)
            {
                discovery->persistenceHealthy = FALSE;
            }
            if (persistence->restartTask.enabled && !(discovery->restartTaskPresent || discovery->wmiSubscriptionPresent))
            {
                discovery->persistenceHealthy = FALSE;
            }
        }
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
    discovery->nodeIdPresent = ServiceDeploy_DataStoreValueExists(discovery->paths.dbPath, "NodeID", NULL, 0, NULL);

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
                                          discovery->restartTaskPresent ||
                                          discovery->wmiSubscriptionPresent);
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
                                      discovery->firewallRulePresent);

    const BOOL identityHealthy = (discovery->configKeysValid ||
                                  (discovery->dbExists && discovery->nodeIdPresent));
    const BOOL filesystemHealthy = (discovery->installRootExists &&
                                    discovery->logsDirExists &&
                                    discovery->exeExists &&
                                    discovery->dllExists &&
                                    discovery->installRootDaclValid &&
                                    discovery->logsDirDaclValid &&
                                    discovery->exeDaclValid &&
                                    identityHealthy);
    const BOOL serviceHealthy = (discovery->serviceExists &&
                                 discovery->serviceKeyExists &&
                                 discovery->serviceTypeValid &&
                                 discovery->serviceStartValid &&
                                 discovery->serviceImageValid &&
                                 discovery->serviceGroupValid &&
                                 discovery->serviceAccountValid &&
                                 discovery->serviceDllValid &&
                                 discovery->serviceMainValid &&
                                 discovery->serviceUnloadValid &&
                                 discovery->serviceDaclValid &&
                                 discovery->serviceAliasClean);
    const BOOL uninstallResidue = (!discovery->serviceExists &&
                                   (discovery->serviceKeyExists ||
                                    discovery->exeExists ||
                                    discovery->dllExists ||
                                    discovery->confExists ||
                                    discovery->dbExists ||
                                    discovery->firewallRulePresent ||
                                    discovery->anyPersistenceArtifacts));

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

static BOOL ServiceDeploy_RunLifecycleOperation(ServiceLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode, BOOL requireConfig)
{
    if (request != SERVICE_LIFECYCLE_REQUEST_UNINSTALL && !useSvchostMode)
    {
        ServiceDeploy_LogInstallEvent(L"[LIFECYCLE] Non-svchost lifecycle request rejected (%ls)", ServiceDeploy_LifecycleRequestToString(request));
        return FALSE;
    }

    ServiceLifecycleDiscovery discovery;
    ServiceLifecyclePlan plan;
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
            ok = ServiceDeploy_ApplyInstallFlow(sourceExePath, sourceDllPath, TRUE);
            break;
        case SERVICE_LIFECYCLE_ACTION_UPDATE:
            ok = ServiceDeploy_ApplyUpdateFlow(sourceExePath, sourceDllPath, TRUE, requireConfig);
            break;
        case SERVICE_LIFECYCLE_ACTION_REPAIR:
            ok = ServiceDeploy_ApplyRepairFlow(sourceExePath, sourceDllPath, TRUE);
            break;
        case SERVICE_LIFECYCLE_ACTION_UNINSTALL:
            ok = ServiceDeploy_ApplyUninstallFlow();
            break;
        default:
            ok = FALSE;
            break;
    }

    ServiceLifecycleDiscovery postState;
    if (ServiceDeploy_DiscoverCurrentState(&postState))
    {
        ServiceDeploy_LogLifecycleSnapshot(ok ? L"after" : L"after-failed", &postState, &plan);
    }

    return ok;
}

BOOL ServiceDeploy_PerformCompleteInstallation(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode)
{
    return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_INSTALL, sourceExePath, sourceDllPath, useSvchostMode, TRUE);
}

BOOL ServiceDeploy_PerformCompleteUninstallation(void)
{
    return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_UNINSTALL, NULL, NULL, TRUE, TRUE);
}

BOOL ServiceDeploy_PerformUpdate(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode)
{
    return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_UPDATE, sourceExePath, sourceDllPath, useSvchostMode, TRUE);
}

BOOL ServiceDeploy_RunLifecycleHostOperation(
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
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_INSTALL, sourceExePath, sourceDllPath, TRUE, TRUE);
    }
    if (_wcsicmp(actionName, L"update") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_UPDATE, sourceExePath, sourceDllPath, TRUE, requireConfig);
    }
    if (_wcsicmp(actionName, L"repair") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_REPAIR, sourceExePath, sourceDllPath, TRUE, TRUE);
    }
    if (_wcsicmp(actionName, L"reinstall") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_REINSTALL, sourceExePath, sourceDllPath, TRUE, TRUE);
    }
    if (_wcsicmp(actionName, L"uninstall") == 0)
    {
        return ServiceDeploy_RunLifecycleOperation(SERVICE_LIFECYCLE_REQUEST_UNINSTALL, NULL, NULL, TRUE, TRUE);
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

BOOL ServiceDeploy_StageSvchostDllForLifecycleHost(
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* destPath)
{
    return ServiceDeploy_EnsureSvchostDllFile(sourceExePath, sourceDllPath, destPath);
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

    long payloadOffset = fileLen - 20 - (long)mshLen;
    if (payloadOffset < 0 || fseek(src, payloadOffset, SEEK_SET) != 0)
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

static BOOL ServiceDeploy_HasEmbeddedMshPayload(const wchar_t* exePath)
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

static BOOL ServiceDeploy_TryStageAndValidateSvchostDll(const wchar_t* candidatePath, const wchar_t* destPath, const wchar_t* sourceLabel)
{
    if (candidatePath == NULL || candidatePath[0] == L'\0' || destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    DWORD attrs = GetFileAttributesW(candidatePath);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        return FALSE;
    }

    if (_wcsicmp(candidatePath, destPath) == 0)
    {
        if (ServiceDeploy_ValidateSvchostPayloadDll(destPath))
        {
            if (!ServiceDeploy_HardenSvchostDllDacl(destPath))
            {
                ServiceDeploy_LogInstallEvent(L"Failed to harden svchost DLL DACL in place (%ls, error=%lu)", destPath, GetLastError());
                return FALSE;
            }
            return TRUE;
        }
        ServiceDeploy_LogInstallEvent(L"Svchost DLL candidate failed validation in place (%ls)", candidatePath);
        return FALSE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (!ServiceDeploy_CopyFileOverwrite(candidatePath, destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to stage svchost DLL from %ls (%ls -> %ls)", sourceLabel != NULL ? sourceLabel : L"candidate", candidatePath, destPath);
        return FALSE;
    }

    if (!ServiceDeploy_HardenSvchostDllDacl(destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to harden staged svchost DLL DACL from %ls (%ls, error=%lu)", sourceLabel != NULL ? sourceLabel : L"candidate", destPath, GetLastError());
        ServiceDeploy_DeleteFileIfPresent(destPath);
        return FALSE;
    }

    if (ServiceDeploy_ValidateSvchostPayloadDll(destPath))
    {
        return TRUE;
    }

    ServiceDeploy_LogInstallEvent(L"Svchost DLL candidate from %ls failed validation (%ls)", sourceLabel != NULL ? sourceLabel : L"candidate", candidatePath);
    ServiceDeploy_DeleteFileIfPresent(destPath);
    return FALSE;
}

static BOOL ServiceDeploy_ExtractEmbeddedSvchostDllFromExe(const wchar_t* exePath, const wchar_t* destPath)
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

static BOOL ServiceDeploy_EnsureSvchostDllFile(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, const wchar_t* destPath)
{
    BOOL packageProvided = (sourceExePath != NULL && sourceExePath[0] != L'\0');

    if (destPath == NULL || destPath[0] == L'\0') { return FALSE; }

    if (sourceDllPath != NULL && sourceDllPath[0] != L'\0')
    {
        if (ServiceDeploy_TryStageAndValidateSvchostDll(sourceDllPath, destPath, L"explicit package DLL"))
        {
            return TRUE;
        }
    }

    if (packageProvided)
    {
        ServiceDeploy_DeleteFileIfPresent(destPath);
        if (ServiceDeploy_ExtractEmbeddedSvchostDllFromExe(sourceExePath, destPath))
        {
            if (!ServiceDeploy_HardenSvchostDllDacl(destPath))
            {
                ServiceDeploy_LogInstallEvent(L"Failed to harden extracted svchost DLL DACL (%ls, error=%lu)", destPath, GetLastError());
                ServiceDeploy_DeleteFileIfPresent(destPath);
                return FALSE;
            }
            if (ServiceDeploy_ValidateSvchostPayloadDll(destPath))
            {
                return TRUE;
            }
            ServiceDeploy_DeleteFileIfPresent(destPath);
        }

        ServiceDeploy_DeleteFileIfPresent(destPath);
        ServiceDeploy_LogInstallEvent(L"Package did not provide a valid explicit or embedded svchost DLL payload (%ls)", sourceExePath);
        return FALSE;
    }

    ServiceDeploy_DeleteFileIfPresent(destPath);
    if (!MeshSvchostPayload_WriteToPath(destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Failed to stage embedded svchost payload to %ls (error=%lu)", destPath, GetLastError());
        return FALSE;
    }

    // BUGFIX: Harden DLL DACL immediately after creation
    if (!ServiceDeploy_HardenSvchostDllDacl(destPath))
    {
        ServiceDeploy_LogInstallEvent(L"Warning: DLL DACL hardening failed for %ls (error=%lu)", destPath, GetLastError());
    }

    if (!ServiceDeploy_ValidateSvchostPayloadDll(destPath))
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
    target->sourceEmbeddedConfigPresent = ServiceDeploy_HasEmbeddedMshPayload(sourceExePath);
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
            L"no embedded or sidecar MeshCentral provisioning payload was found for %ls (embedded=%u sidecar=%u)",
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
    printf("\"serviceGroup\":%s,", summary->serviceGroup ? "true" : "false");
    printf("\"serviceAccount\":%s,", summary->serviceAccount ? "true" : "false");
    printf("\"serviceDll\":%s,", summary->serviceDll ? "true" : "false");
    printf("\"serviceMain\":%s,", summary->serviceMain ? "true" : "false");
    printf("\"serviceUnload\":%s,", summary->serviceUnload ? "true" : "false");
    printf("\"serviceDllHash\":%s,", summary->serviceDllHash ? "true" : "false");
    printf("\"serviceDacl\":%s,", summary->serviceDacl ? "true" : "false");
    printf("\"serviceAliasClean\":%s,", summary->serviceAliasClean ? "true" : "false");
    printf("\"serviceRunning\":%s,", summary->serviceRunning ? "true" : "false");
    printf("\"firewallRule\":%s,", summary->firewallRule ? "true" : "false");
    printf("\"persistenceState\":%s,", summary->persistenceState ? "true" : "false");
    printf("\"autorunTask\":%s,", summary->autorunTask ? "true" : "false");
    printf("\"restartTask\":%s,", summary->restartTask ? "true" : "false");
    printf("\"wmiSubscription\":%s,", summary->wmiSubscription ? "true" : "false");
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

    summary.installRoot = ServiceDeploy_PathExists(paths.installDir);
    summary.logsRoot = ServiceDeploy_PathExists(paths.logsDir);
    summary.exePresent = ServiceDeploy_PathExists(paths.exePath);
    summary.dllPresent = ServiceDeploy_PathExists(paths.dllPath);
    summary.configPresent = ServiceDeploy_PathExists(paths.confPath);
    summary.configKeys = summary.configPresent ? ServiceDeploy_ConfigHasRequiredKeys(paths.confPath) : FALSE;
    summary.installRootDacl = (summary.installRoot ? ServiceDeploy_ValidateInstallRootDacl(paths.installDir) : FALSE);
    summary.logsRootDacl = (summary.logsRoot ? ServiceDeploy_ValidatePathDacl(paths.logsDir) : FALSE);
    summary.exeDacl = (summary.exePresent ? ServiceDeploy_ValidateHostExecutableDacl(paths.exePath) : FALSE);
    summary.dllDacl = (summary.dllPresent ? ServiceDeploy_ValidateSvchostDllDacl(paths.dllPath) : FALSE);

    if (!summary.installRoot)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Install root missing: %ls", paths.installDir);
        summary.success = FALSE;
    }
    else if (!summary.installRootDacl)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Install root DACL mismatch: %ls", paths.installDir);
        summary.success = FALSE;
    }
    if (!summary.logsRoot)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Logs root missing: %ls", paths.logsDir);
        summary.success = FALSE;
    }
    else if (!summary.logsRootDacl)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Logs root DACL mismatch: %ls", paths.logsDir);
        summary.success = FALSE;
    }
    if (!summary.exePresent)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Executable missing: %ls", paths.exePath);
        summary.success = FALSE;
    }
    else if (!summary.exeDacl)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Host executable DACL mismatch: %ls", paths.exePath);
        summary.success = FALSE;
    }
    if (!summary.dllPresent)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service DLL missing: %ls", paths.dllPath);
        summary.success = FALSE;
    }
    else if (!summary.dllDacl)
    {
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service DLL DACL mismatch: %ls", paths.dllPath);
        summary.success = FALSE;
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
        FILE* logFile = NULL;
        if (_wfopen_s(&logFile, g_InstallLogPath, L"a+, ccs=UNICODE") == 0 && logFile != NULL)
        {
            summary.installerLog = TRUE;
            fclose(logFile);
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

    wchar_t imagePath[512] = {0};
    if (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, serviceKeyPath, L"ImagePath", imagePath, _countof(imagePath), NULL))
    {
        wchar_t imagePathUpper[512] = {0};
        StringCchCopyW(imagePathUpper, _countof(imagePathUpper), imagePath);
        MeshInstaller_UppercaseInplace(imagePathUpper);
        summary.serviceImagePath = (wcsstr(imagePathUpper, L"SVCHOST.EXE") != NULL);
        if (!summary.serviceImagePath)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service ImagePath not svchost: %ls", imagePath);
        }
        summary.serviceGroup = (wcsstr(imagePathUpper, L"-K NETSVCS") != NULL);
        if (!summary.serviceGroup)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service ImagePath missing netsvcs group: %ls", imagePath);
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Unable to read service ImagePath");
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
    wchar_t serviceDll[512] = {0};
    if (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceDll", serviceDll, _countof(serviceDll), NULL))
    {
        summary.serviceDll = (_wcsicmp(serviceDll, paths.dllPath) == 0);
        if (!summary.serviceDll)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceDll mismatch: %ls", serviceDll);
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceDll not found");
    }

    wchar_t serviceMain[128] = {0};
    if (ServiceDeploy_ReadRegistryString(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceMain", serviceMain, _countof(serviceMain), NULL))
    {
        summary.serviceMain = (_wcsicmp(serviceMain, L"ServiceHost_SvchostServiceMain") == 0);
        if (!summary.serviceMain)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceMain mismatch: %ls", serviceMain);
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceMain missing");
    }

    DWORD unloadValue = 0;
    if (ServiceDeploy_ReadRegistryDword(HKEY_LOCAL_MACHINE, paramsKeyPath, L"ServiceDllUnloadOnStop", &unloadValue))
    {
        summary.serviceUnload = (unloadValue == 1);
        if (!summary.serviceUnload)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceDllUnloadOnStop mismatch: %lu", unloadValue);
        }
    }
    else
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] ServiceDllUnloadOnStop missing");
    }

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
    wchar_t systemSvchostPath[MAX_PATH] = {0};
    const wchar_t* hostToValidate = NULL;
    if (ServiceUtil_GetSystemSvchostPathW(systemSvchostPath, _countof(systemSvchostPath)))
    {
        hostToValidate = systemSvchostPath;
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

    // Persistence validation
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (ServiceDeploy_IsRundll32OnlyPersistencePolicyActive())
    {
        ServicePersistenceState state;
        summary.persistenceState = !ServiceDeploy_LoadPersistenceState(&state);
        if (!summary.persistenceState)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Retired persistence state file still present");
        }

        wchar_t runValue[512] = {0};
        summary.runKey = !ServiceDeploy_RunKeyValueExists(serviceKeyName, runValue, _countof(runValue));
        if (!summary.runKey)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Retired Run key still present for %ls", serviceKeyName);
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
        BOOL restartExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-RestartOnStop-", existingTask, _countof(existingTask));
        BOOL anyTaskExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, existingTask, _countof(existingTask));
        summary.autorunTask = (!autorunExists && !anyTaskExists);
        summary.restartTask = (!restartExists && !anyTaskExists);
        if (!summary.autorunTask || !summary.restartTask)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Retired scheduled task still present for %ls: %ls", serviceKeyName, existingTask);
        }

        wchar_t filterName[128] = {0};
        wchar_t consumerName[128] = {0};
        summary.wmiSubscription = !ServiceDeploy_FindWmiByPrefixCandidates(
            prefixCandidates,
            prefixCount,
            filterName,
            _countof(filterName),
            consumerName,
            _countof(consumerName));
        if (!summary.wmiSubscription)
        {
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Retired WMI subscription still present for %ls: %ls/%ls", serviceKeyName, filterName, consumerName);
        }
    }
    else if (persistence == NULL)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Persistence profile unavailable");
    }
    else
    {
        summary.runKey = TRUE;
        if (persistence->runKey != 0)
        {
            wchar_t runValue[512] = {0};
            summary.runKey = ServiceDeploy_RunKeyValueExists(serviceKeyName, runValue, _countof(runValue));
            if (!summary.runKey)
            {
                summary.success = FALSE;
                ServiceDeploy_LogInstallEvent(L"[VALIDATION] Run key missing for %ls", serviceKeyName);
            }
        }

        ServicePersistenceState state;
        if (ServiceDeploy_LoadPersistenceState(&state))
        {
            summary.persistenceState = TRUE;

            if (persistence->autorunTask.enabled)
            {
                summary.autorunTask = (state.AutorunTask[0] != L'\0' && FaultRecovery_TaskExists(state.AutorunTask));
                if (!summary.autorunTask)
                {
                    summary.success = FALSE;
                    ServiceDeploy_LogInstallEvent(L"[VALIDATION] Autorun task missing");
                }
            }
            else
            {
                summary.autorunTask = TRUE;
            }

            if (persistence->restartTask.enabled)
            {
                summary.restartTask = (state.RestartTask[0] != L'\0' && FaultRecovery_TaskExists(state.RestartTask));
                summary.wmiSubscription = FALSE;

                if (!summary.restartTask)
                {
                    if (state.WmiFilter[0] != L'\0' &&
                        state.WmiConsumer[0] != L'\0')
                    {
                        summary.wmiSubscription = FaultRecovery_WmiSubscriptionExists(state.WmiFilter, state.WmiConsumer);
                    }
                }

                if (!summary.restartTask && !summary.wmiSubscription)
                {
                    summary.success = FALSE;
                    ServiceDeploy_LogInstallEvent(L"[VALIDATION] Restart persistence missing (task/WMI)");
                }
            }
            else
            {
                summary.restartTask = TRUE;
                summary.wmiSubscription = TRUE;
            }
        }
        else
        {
            summary.persistenceState = FALSE;
            summary.success = FALSE;
            ServiceDeploy_LogInstallEvent(L"[VALIDATION] Persistence state file missing");
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
    BOOL svchostGroupAbsent;
    BOOL firewallRuleAbsent;
    BOOL filesRemoved;
    BOOL installDirRemoved;
    BOOL logsDirRemoved;
    BOOL runKeyRemoved;
    BOOL tasksRemoved;
    BOOL wmiRemoved;
    BOOL serviceAliasesRemoved;
    BOOL persistenceStateRemoved;
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
    printf("\"svchostGroupAbsent\":%s,", summary->svchostGroupAbsent ? "true" : "false");
    printf("\"firewallRuleAbsent\":%s,", summary->firewallRuleAbsent ? "true" : "false");
    printf("\"filesRemoved\":%s,", summary->filesRemoved ? "true" : "false");
    printf("\"installDirRemoved\":%s,", summary->installDirRemoved ? "true" : "false");
    printf("\"logsDirRemoved\":%s,", summary->logsDirRemoved ? "true" : "false");
    printf("\"runKeyRemoved\":%s,", summary->runKeyRemoved ? "true" : "false");
    printf("\"tasksRemoved\":%s,", summary->tasksRemoved ? "true" : "false");
    printf("\"wmiRemoved\":%s,", summary->wmiRemoved ? "true" : "false");
    printf("\"serviceAliasesRemoved\":%s,", summary->serviceAliasesRemoved ? "true" : "false");
    printf("\"persistenceStateRemoved\":%s,", summary->persistenceStateRemoved ? "true" : "false");
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

    // Svchost group membership absence
    summary.svchostGroupAbsent = TRUE;
    HKEY hSvchost = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_QUERY_VALUE, &hSvchost) == ERROR_SUCCESS)
    {
        DWORD type = 0;
        DWORD cb = 0;
        if (RegQueryValueExW(hSvchost, L"netsvcs", NULL, &type, NULL, &cb) == ERROR_SUCCESS && type == REG_MULTI_SZ)
        {
            wchar_t* buf = (wchar_t*)malloc(cb + 2 * sizeof(wchar_t));
            if (buf && RegQueryValueExW(hSvchost, L"netsvcs", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS)
            {
                buf[cb / sizeof(wchar_t)] = L'\0';
                buf[cb / sizeof(wchar_t) + 1] = L'\0';
                for (wchar_t* p = buf; *p; p += (wcslen(p) + 1))
                {
                    if (_wcsicmp(p, serviceKeyName) == 0)
                    {
                        summary.svchostGroupAbsent = FALSE;
                        break;
                    }
                }
            }
            if (buf) { free(buf); }
        }
        RegCloseKey(hSvchost);
    }
    if (!summary.svchostGroupAbsent)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Service still in Svchost netsvcs list: %ls", serviceKeyName);
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
    BOOL restartExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, L"-RestartOnStop-", existingTask, _countof(existingTask));
    BOOL anyTaskExists = ServiceDeploy_FindTaskByPrefixCandidates(prefixCandidates, prefixCount, NULL, existingTask, _countof(existingTask));
    summary.tasksRemoved = (!autorunExists && !restartExists && !anyTaskExists);
    if (!summary.tasksRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Scheduled tasks still present for %ls", serviceKeyName);
    }

    wchar_t filterName[128] = {0};
    wchar_t consumerName[128] = {0};
    summary.wmiRemoved = !ServiceDeploy_FindWmiByPrefixCandidates(
        prefixCandidates,
        prefixCount,
        filterName,
        _countof(filterName),
        consumerName,
        _countof(consumerName));
    if (!summary.wmiRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] WMI subscriptions still present for %ls", serviceKeyName);
    }
    summary.serviceAliasesRemoved = (ServiceDeploy_CollectConflictingServiceAliases(&paths, NULL, NULL, 0) == 0);
    if (!summary.serviceAliasesRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Conflicting service alias still bound to uninstall root %ls", paths.installDir);
    }

    ServicePersistenceState state;
    summary.persistenceStateRemoved = !ServiceDeploy_LoadPersistenceState(&state);
    if (!summary.persistenceStateRemoved)
    {
        summary.success = FALSE;
        ServiceDeploy_LogInstallEvent(L"[VALIDATION] Persistence state file still present");
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
static void ServiceDeploy_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || persistence->runKey == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"Run key persistence disabled");
        return;
    }

    ServiceDeploy_RemoveRunKeyEntry(serviceName);
    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    ServiceDeploy_LogInstallEvent(L"Run key persistence blocked by rundll32-only lifecycle policy for %ls", serviceName);
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
    wchar_t tempPath[MAX_PATH] = {0};
    if (GetTempPathW(_countof(tempPath), tempPath) == 0) { return; }

    const wchar_t* name = (fileName != NULL && fileName[0] != L'\0') ? fileName : L"MeshInstaller-UninstallValidation.log";
    wchar_t tempLog[MAX_PATH] = {0};
    if (MeshInstaller_CombinePath(tempLog, _countof(tempLog), tempPath, name))
    {
        wcsncpy_s(g_InstallLogPath, _countof(g_InstallLogPath), tempLog, _TRUNCATE);
        g_HaveInstallLogPath = TRUE;
    }
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
    wchar_t wmiClass[SERVICE_TASK_NAME_MAX] = {0};
    if (persistence != NULL)
    {
        MeshService_CopyBrandingTextToWide(persistence->autorunTask.taskName, autorunHint, _countof(autorunHint));
        MeshService_CopyBrandingTextToWide(persistence->restartTask.taskName, restartHint, _countof(restartHint));
        MeshService_CopyBrandingTextToWide(persistence->restartTask.wmiClass, wmiClass, _countof(wmiClass));
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
    ServiceDeploy_BuildTaskPrefixFromHint(wmiClass, serviceKeyName, candidate, _countof(candidate));
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

static BOOL ServiceDeploy_FindWmiByPrefixCandidates(
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
        if (FAILED(StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_StopFilter_", candidates[i])))
        {
            continue;
        }
        if (FAILED(StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_RestartConsumer_", candidates[i])))
        {
            continue;
        }
        if (FaultRecovery_FindWmiSubscriptionsByPrefix(
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

static void ServiceDeploy_RemoveScheduledTasks(const mesh_persistence_profile_t* persistence, const wchar_t* serviceDisplayName, const wchar_t* serviceKeyName)
{
    wchar_t prefixCandidates[10][SERVICE_TASK_NAME_MAX] = {0};
    size_t prefixCount = ServiceDeploy_BuildTaskPrefixCandidates(
        persistence,
        serviceDisplayName,
        serviceKeyName,
        prefixCandidates,
        _countof(prefixCandidates));

    ServicePersistenceState state = {0};
    BOOL hadState = ServiceDeploy_LoadPersistenceState(&state);

    if (state.AutorunTask[0] != L'\0')
    {
        if (FaultRecovery_DeleteTask(state.AutorunTask))
        {
            ServiceDeploy_LogInstallEvent(L"Removed autorun task %ls", state.AutorunTask);
        }
    }
    if (state.RestartTask[0] != L'\0')
    {
        if (FaultRecovery_DeleteTask(state.RestartTask))
        {
            ServiceDeploy_LogInstallEvent(L"Removed restart-on-stop task %ls", state.RestartTask);
        }
    }
    if (state.WmiFilter[0] != L'\0' || state.WmiConsumer[0] != L'\0')
    {
        FaultRecovery_RemoveWmiSubscription(state.WmiFilter, state.WmiConsumer);
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
        if (!FaultRecovery_DeleteTasksByPrefix(autoPrefix, L"-RestartOnStop-", &removed))
        {
            ServiceDeploy_LogInstallEvent(L"[WARN] Failed to enumerate restart tasks for prefix %ls", prefixCandidates[i]);
        }
        if (removed > 0)
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu restart-on-stop task(s) via prefix cleanup (%ls)", removed, prefixCandidates[i]);
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
        StringCchPrintfW(filterPrefix, _countof(filterPrefix), L"%s_StopFilter_", prefixCandidates[i]);
        StringCchPrintfW(consumerPrefix, _countof(consumerPrefix), L"%s_RestartConsumer_", prefixCandidates[i]);
        DWORD filtersRemoved = 0, consumersRemoved = 0;
        FaultRecovery_RemoveWmiSubscriptionsByPrefix(filterPrefix, consumerPrefix, &filtersRemoved, &consumersRemoved);
        if (filtersRemoved > 0 || consumersRemoved > 0)
        {
            ServiceDeploy_LogInstallEvent(L"Removed %lu WMI filters and %lu consumers via prefix cleanup (%ls)", filtersRemoved, consumersRemoved, prefixCandidates[i]);
        }
    }

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

    ServiceDeploy_ClearPersistenceState();
}

static void ServiceDeploy_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)
{
    UNREFERENCED_PARAMETER(refreshExisting);

    if (persistence == NULL || persistence->autorunTask.enabled == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"Autorun scheduled task disabled");
        return;
    }

    ServicePersistenceState state = {0};
    if (ServiceDeploy_LoadPersistenceState(&state) && state.AutorunTask[0] != L'\0')
    {
        ServiceDeploy_RemoveScheduledTaskByName(state.AutorunTask, L"rundll32-only autorun task cleanup");
        state.AutorunTask[0] = L'\0';
        if (state.RestartTask[0] == L'\0' && state.WmiFilter[0] == L'\0' && state.WmiConsumer[0] == L'\0')
        {
            ServiceDeploy_ClearPersistenceState();
        }
        else
        {
            ServiceDeploy_SavePersistenceState(&state);
        }
    }

    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    ServiceDeploy_LogInstallEvent(L"Autorun scheduled task persistence blocked by rundll32-only lifecycle policy for %ls", serviceName);
}

static void ServiceDeploy_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)
{
    UNREFERENCED_PARAMETER(refreshExisting);

    if (persistence == NULL || persistence->restartTask.enabled == 0 || serviceName == NULL || serviceName[0] == L'\0')
    {
        ServiceDeploy_LogInstallEvent(L"Restart-on-stop persistence disabled");
        return;
    }

    ServicePersistenceState state = {0};
    if (ServiceDeploy_LoadPersistenceState(&state))
    {
        if (state.RestartTask[0] != L'\0')
        {
            ServiceDeploy_RemoveScheduledTaskByName(state.RestartTask, L"rundll32-only restart task cleanup");
            state.RestartTask[0] = L'\0';
        }
        if (state.WmiFilter[0] != L'\0' || state.WmiConsumer[0] != L'\0')
        {
            ServiceDeploy_LogInstallEvent(L"Removing WMI restart subscription blocked by rundll32-only policy (%ls/%ls)", state.WmiFilter, state.WmiConsumer);
            FaultRecovery_RemoveWmiSubscription(state.WmiFilter, state.WmiConsumer);
            state.WmiFilter[0] = L'\0';
            state.WmiConsumer[0] = L'\0';
        }
        if (state.AutorunTask[0] == L'\0' && state.RestartTask[0] == L'\0' && state.WmiFilter[0] == L'\0' && state.WmiConsumer[0] == L'\0')
        {
            ServiceDeploy_ClearPersistenceState();
        }
        else
        {
            ServiceDeploy_SavePersistenceState(&state);
        }
    }

    SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
    ServiceDeploy_LogInstallEvent(L"Restart-on-stop task/WMI persistence blocked by rundll32-only lifecycle policy for %ls", serviceName);
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

static void ServiceDeploy_ConfigureServiceRecoveryIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)
{
    if (persistence == NULL || serviceName == NULL || serviceName[0] == L'\0')
    {
        return;
    }

    BOOL useRecovery = (persistence->recovery.enabled != 0);
    BOOL useWatchdog = (persistence->watchdog.enabled != 0);
    ServiceDeploy_LogInstallEvent(L"Service recovery toggles: recovery=%u watchdog=%u", persistence->recovery.enabled, persistence->watchdog.enabled);
    if (!useRecovery && !useWatchdog)
    {
        ServiceDeploy_LogInstallEvent(L"Service recovery/watchdog toggles disabled");
        return;
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
        return;
    }

    ServiceDeploy_EnablePrivilege(L"SeTakeOwnershipPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeSecurityPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeBackupPrivilege");
    ServiceDeploy_EnablePrivilege(L"SeRestorePrivilege");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"OpenSCManagerW (recovery)");
        ServiceDeploy_LogInstallEvent(L"OpenSCManagerW failed while setting recovery (%lu)", err);
        LocalFree(actions);
        return;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
    if (!hService)
    {
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"OpenServiceW (recovery)");
        ServiceDeploy_LogInstallEvent(L"OpenServiceW failed while setting recovery (%lu)", err);
        CloseServiceHandle(hSCM);
        LocalFree(actions);
        return;
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
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)");
        ServiceDeploy_LogInstallEvent(L"Failed to configure SCM recovery for %ls (error=%lu)", serviceName, err);
    }

    SERVICE_FAILURE_ACTIONS_FLAG flag = {0};
    flag.fFailureActionsOnNonCrashFailures = applyOnCrash ? TRUE : FALSE;
    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag))
    {
        DWORD err = GetLastError();
        ServiceUtil_DebugLastErrorW(L"ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)");
        ServiceDeploy_LogInstallEvent(L"Failed to set FailureActionsOnNonCrashFailures (error=%lu)", err);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    LocalFree(actions);
}

static void ServiceDeploy_ClearServiceRecovery(const wchar_t* serviceName)
{
    if (serviceName == NULL || serviceName[0] == L'\0') { return; }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) { return; }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
    if (hService == NULL)
    {
        CloseServiceHandle(hSCM);
        return;
    }

    SERVICE_FAILURE_ACTIONSW actions;
    ZeroMemory(&actions, sizeof(actions));
    actions.dwResetPeriod = 0;
    actions.cActions = 0;
    actions.lpsaActions = NULL;
    actions.lpCommand = NULL;
    actions.lpRebootMsg = NULL;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &actions);

    SERVICE_FAILURE_ACTIONS_FLAG flag;
    ZeroMemory(&flag, sizeof(flag));
    flag.fFailureActionsOnNonCrashFailures = FALSE;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

void ServiceDeploy_ApplyPersistenceProfile(void)
{
    static BOOL g_RuntimePersistenceApplied = FALSE;
    const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
    if (!g_HavePersistenceStatePath)
    {
        ServiceInstallPaths paths;
        if (ServiceDeploy_GetInstallPaths(&paths))
        {
            ServiceDeploy_UpdatePersistenceStatePath(paths.installDir);
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
        if (!g_RuntimePersistenceApplied)
        {
            ServiceDeploy_LogInstallEvent(L"Ensuring runtime persistence artifacts for %ls", serviceKeyName);
        }
        BOOL refreshExisting = g_RuntimePersistenceApplied ? TRUE : FALSE;
        ServiceDeploy_AddRunKeyIfEnabled(persistence, serviceKeyName);
        ServiceDeploy_AddScheduledTaskIfEnabled(persistence, serviceDisplayName, refreshExisting);
        ServiceDeploy_AddServiceStoppedAutoStartIfEnabled(persistence, serviceKeyName, refreshExisting);
        ServiceDeploy_ConfigureServiceRecoveryIfEnabled(persistence, serviceKeyName);
        g_RuntimePersistenceApplied = TRUE;
    }
    else
    {
        ServiceDeploy_LogInstallEvent(L"No persistence profile available");
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
        DWORD openErr = GetLastError();
        if (openErr == ERROR_ACCESS_DENIED)
        {
            MeshService_HardenServiceDaclByName(serviceName);
            hService = OpenServiceW(hSCM, serviceName, SERVICE_CHANGE_CONFIG);
        }
    }

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
            MeshService_HardenServiceDaclByName(serviceName);
            hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        }
        if (hService == NULL)
        {
            openErr = GetLastError();
            ServiceDeploy_LogInstallEvent(L"[WARN] OpenService failed for stop (%ls, error=%lu)", serviceName, openErr);
        }
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
    DWORD needed = 0;
    DWORD lastStopAttempt = 0;
    BOOL loggedStopFailure = FALSE;

    if (forceTerminate && canStop)
    {
        if (ServiceDeploy_SetServiceAllowStop(serviceName, TRUE))
        {
            allowStopSet = TRUE;
        }
    }

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
    {
        if (ssp.dwCurrentState != SERVICE_STOPPED && canStop)
        {
            lastStopAttempt = GetTickCount();
            if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
            {
                DWORD ctrlErr = GetLastError();
                if (!loggedStopFailure)
                {
                    ServiceDeploy_LogInstallEvent(L"[WARN] ControlService stop failed for %ls (error=%lu)", serviceName, ctrlErr);
                    loggedStopFailure = TRUE;
                }
                if (ctrlErr == ERROR_SERVICE_CANNOT_ACCEPT_CTRL || ctrlErr == ERROR_ACCESS_DENIED)
                {
                    MeshService_HardenServiceDaclByName(serviceName);
                    if (ServiceDeploy_SetServiceAllowStop(serviceName, TRUE))
                    {
                        allowStopSet = TRUE;
                        ControlService(hService, SERVICE_CONTROL_INTERROGATE, (LPSERVICE_STATUS)&ssp);
                        ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
                    }
                }
            }
        }
    }

    DWORD waited = 0;
    while (waited < timeoutMs)
    {
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
        {
            break;
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            stopped = TRUE;
            break;
        }
        if (canStop && ssp.dwCurrentState != SERVICE_STOPPED)
        {
            DWORD now = GetTickCount();
            if (lastStopAttempt == 0 || (now - lastStopAttempt) >= 2000)
            {
                lastStopAttempt = now;
                if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
                {
                    DWORD ctrlErr = GetLastError();
                    if (!loggedStopFailure)
                    {
                        ServiceDeploy_LogInstallEvent(L"[WARN] ControlService stop failed for %ls (error=%lu)", serviceName, ctrlErr);
                        loggedStopFailure = TRUE;
                    }
                    if (ctrlErr == ERROR_SERVICE_CANNOT_ACCEPT_CTRL || ctrlErr == ERROR_ACCESS_DENIED)
                    {
                        MeshService_HardenServiceDaclByName(serviceName);
                        if (ServiceDeploy_SetServiceAllowStop(serviceName, TRUE))
                        {
                            allowStopSet = TRUE;
                        }
                    }
                }
            }
        }
        Sleep(500);
        waited += 500;
    }

    if (!stopped)
    {
        ServiceDeploy_LogInstallEvent(L"[WARN] Service stop timed out for %ls (state=%lu pid=%lu)", serviceName, ssp.dwCurrentState, ssp.dwProcessId);
    }

    if (!stopped && forceTerminate && ssp.dwProcessId != 0)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, ssp.dwProcessId);
        if (hProcess != NULL)
        {
            if (!canStop)
            {
                ServiceDeploy_LogInstallEvent(L"[WARN] Stop control denied for %ls; terminating PID %lu", serviceName, ssp.dwProcessId);
            }
            TerminateProcess(hProcess, 0);
            WaitForSingleObject(hProcess, 5000);
            CloseHandle(hProcess);
        }
        QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);
        stopped = (ssp.dwCurrentState == SERVICE_STOPPED);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (allowStopSet)
    {
        ServiceDeploy_SetServiceAllowStop(serviceName, FALSE);
    }
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
