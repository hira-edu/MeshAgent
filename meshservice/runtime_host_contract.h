#ifndef MESH_RUNTIME_HOST_CONTRACT_H
#define MESH_RUNTIME_HOST_CONTRACT_H

#include <windows.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Single source of truth for the two OS binaries that host this service DLL: svchost hosts
// the SCM service, rundll32 hosts the interactive/helper entry points. Every consumer that
// resolves or validates a host path must use these names and the helpers below, never a
// private "%System32%\<name>" construction (enforced by test/service_host_exports_contract.js).
#define MESH_RUNTIME_HOST_BINARY_RUNDLL32_W      L"rundll32.exe"
#define MESH_RUNTIME_HOST_BINARY_RUNDLL32_A      "rundll32.exe"
#define MESH_RUNTIME_HOST_BINARY_SVCHOST_W       L"svchost.exe"
#define MESH_RUNTIME_HOST_BINARY_SVCHOST_A       "svchost.exe"

#define MESH_RUNTIME_HOST_ENTRY_SERVICE_W        L"ServiceHost_ServiceMain"
#define MESH_RUNTIME_HOST_ENTRY_SERVICE_A        "ServiceHost_ServiceMain"
#define MESH_RUNTIME_HOST_ENTRY_LEGACY_SERVICE_W L"MeshServiceHostW"
#define MESH_RUNTIME_HOST_ENTRY_LIFECYCLE_W      L"MeshLifecycleHostW"
#define MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_W     L"KvmSessionBridgeW"
#define MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_W L"MeshConsoleBridgeW"
#define MESH_RUNTIME_HOST_ENTRY_UMH_HOST_W       L"MeshUmhHostW"
#define MESH_RUNTIME_HOST_ENTRY_USER_CONSENT_W   L"MeshUserConsentW"
#define MESH_RUNTIME_HOST_ENTRY_LAUNCHER_CLEANUP_W L"MeshLauncherCleanupW"
#define MESH_RUNTIME_HOST_ENTRY_PREPROTECTION_CAPTURE_W L"MeshPreProtectionCaptureW"
#define MESH_RUNTIME_HOST_ENTRY_SELFTEST_W    L"MeshSelfTestHostW"
#define MESH_RUNTIME_HOST_ENTRY_KVM_PROBE_W   L"MeshKvmProbeHostW"
#define MESH_RUNTIME_HOST_ENTRY_LIFECYCLE_A      "MeshLifecycleHostW"
#define MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_A     "KvmSessionBridgeW"
#define MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_A "MeshConsoleBridgeW"
#define MESH_RUNTIME_HOST_ENTRY_UMH_HOST_A       "MeshUmhHostW"
#define MESH_RUNTIME_HOST_ENTRY_USER_CONSENT_A   "MeshUserConsentW"
#define MESH_RUNTIME_HOST_ENTRY_LAUNCHER_CLEANUP_A "MeshLauncherCleanupW"
#define MESH_RUNTIME_HOST_ENTRY_PREPROTECTION_CAPTURE_A "MeshPreProtectionCaptureW"
#define MESH_RUNTIME_HOST_ENTRY_SELFTEST_A    "MeshSelfTestHostW"
#define MESH_RUNTIME_HOST_ENTRY_KVM_PROBE_A   "MeshKvmProbeHostW"

#define MESH_LIFECYCLE_ACTION_INSTALL_W      L"install"
#define MESH_LIFECYCLE_ACTION_UPDATE_W       L"update"
#define MESH_LIFECYCLE_ACTION_REPAIR_W       L"repair"
#define MESH_LIFECYCLE_ACTION_REINSTALL_W    L"reinstall"
#define MESH_LIFECYCLE_ACTION_UNINSTALL_W    L"uninstall"
#define MESH_LIFECYCLE_ACTION_RECOVER_UPDATE_W L"recover-update"
#define MESH_LIFECYCLE_ACTION_VALIDATE_INSTALL_W   L"validate-install"
#define MESH_LIFECYCLE_ACTION_VALIDATE_UPDATE_W    L"validate-update"
#define MESH_LIFECYCLE_ACTION_VALIDATE_UNINSTALL_W L"validate-uninstall"
#define MESH_LIFECYCLE_ACTION_VALIDATE_PACKAGE_W   L"validate-package"

typedef enum MeshRuntimeHostLifecycleAction
{
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNKNOWN = 0,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_INSTALL,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_REPAIR,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_REINSTALL,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNINSTALL,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_RECOVER_UPDATE,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_INSTALL,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UPDATE,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UNINSTALL,
    MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_PACKAGE
} MeshRuntimeHostLifecycleAction;

typedef struct MeshRuntimeHostLifecycleManifest
{
    MeshRuntimeHostLifecycleAction action;
    wchar_t manifestPath[MAX_PATH * 4];
    wchar_t sourceExePath[MAX_PATH * 4];
    wchar_t sourceDllPath[MAX_PATH * 4];
    wchar_t displayName[256];
    wchar_t serviceDescription[512];
    // Optional SCM key name ("ServiceName"). Empty means the host resolves the name from
    // branding and incumbent discovery; an incumbent or retained journal still wins.
    wchar_t serviceName[256];
    BOOL requireConfig;
} MeshRuntimeHostLifecycleManifest;

const wchar_t* MeshRuntimeHost_LifecycleActionNameW(MeshRuntimeHostLifecycleAction action);
BOOL MeshRuntimeHost_LifecycleActionFromStringW(const wchar_t* value, MeshRuntimeHostLifecycleAction* actionOut);
BOOL MeshRuntimeHost_ReadLifecycleManifestW(const wchar_t* manifestPath, MeshRuntimeHostLifecycleManifest* manifestOut);
// serviceName may be NULL/empty; it is written only when present and must be a valid SCM key name.
BOOL MeshRuntimeHost_WriteLifecycleManifestW(
    const wchar_t* manifestPath,
    MeshRuntimeHostLifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    const wchar_t* serviceName,
    BOOL requireConfig);
// Builds "%System32%\<binaryName>". When requireExistingFile is TRUE the result must be an
// existing, non-directory file, matching the hardened validation the launch chokepoint relies
// on. binaryName is one of the MESH_RUNTIME_HOST_BINARY_*_W names above.
BOOL MeshRuntimeHost_BuildSystemBinaryPathW(const wchar_t* binaryName, BOOL requireExistingFile, wchar_t* output, size_t outputCch);
// TRUE when value, normalized, is exactly "%System32%\<binaryName>". Derived from the same
// construction as the resolver, so the resolver and this predicate cannot diverge.
BOOL MeshRuntimeHost_IsExactSystemBinaryPathW(const wchar_t* binaryName, const wchar_t* value);
BOOL MeshRuntimeHost_GetSystemHostPathW(wchar_t* runtimeHostPath, size_t runtimeHostPathCch);
BOOL MeshRuntimeHost_GetServiceHostPathW(wchar_t* serviceHostPath, size_t serviceHostPathCch);

// A lifecycle host started by MeshRuntimeHost_StartLifecycleHostW. The caller owns
// `process`: once it is signaled, pass the record to
// MeshRuntimeHost_CompleteLifecycleHostW; to stop watching a host that is still
// running, pass it to MeshRuntimeHost_ReleaseLifecycleHostW instead. A released
// host keeps its staged DLL and manifest; they are swept after the launcher exits.
typedef struct MeshRuntimeHostLifecycleLaunch
{
    MeshRuntimeHostLifecycleAction action;
    HANDLE process;
    BOOL deleteHostDllOnExit;
    wchar_t hostDllPath[MAX_PATH * 4];
    wchar_t manifestPath[MAX_PATH * 4];
} MeshRuntimeHostLifecycleLaunch;

// serviceName is the SCM key the caller already knows (its own SCM identity, or the
// name the operator asked for); NULL lets the host resolve it from branding.
BOOL MeshRuntimeHost_StartLifecycleHostW(
    MeshRuntimeHostLifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    const wchar_t* serviceName,
    BOOL requireConfig,
    MeshRuntimeHostLifecycleLaunch* launch);
// Same result convention as MeshRuntimeHost_LaunchLifecycleHostW.
BOOL MeshRuntimeHost_CompleteLifecycleHostW(MeshRuntimeHostLifecycleLaunch* launch, DWORD* exitCodeOut);
void MeshRuntimeHost_ReleaseLifecycleHostW(MeshRuntimeHostLifecycleLaunch* launch);
// FALSE with GetLastError()==ERROR_SUCCESS means a completed child failed;
// exitCodeOut contains its result. Nonzero GetLastError identifies an API failure.
BOOL MeshRuntimeHost_LaunchLifecycleHostW(
    MeshRuntimeHostLifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    const wchar_t* serviceName,
    BOOL requireConfig,
    BOOL waitForExit,
    DWORD timeoutMs,
    DWORD* exitCodeOut);
BOOL MeshRuntimeHost_LaunchLauncherCleanupW(const wchar_t* targetPath, DWORD parentPid, DWORD timeoutMs);
BOOL MeshRuntimeHost_LaunchSelfTestHostW(const wchar_t* arguments, DWORD timeoutMs, DWORD* exitCodeOut);

BOOL ServiceHost_BuildImagePath(const wchar_t* dllPath, wchar_t* command, size_t commandCch);
BOOL ServiceHost_ParseImagePath(const wchar_t* command, wchar_t* dllPath, size_t dllPathCch);
BOOL ServiceHost_BuildGroupName(const wchar_t* serviceName, wchar_t* groupName, size_t groupNameCch);
BOOL ServiceHost_BuildServiceImagePath(const wchar_t* serviceName, wchar_t* command, size_t commandCch);
BOOL ServiceHost_IsServiceImagePath(const wchar_t* serviceName, const wchar_t* command);
BOOL ServiceHost_ReadServiceDllPath(const wchar_t* serviceName, wchar_t* dllPath, size_t dllPathCch, BOOL allowLegacyEntry);
BOOL ServiceHost_ValidateServiceBinding(const wchar_t* serviceName, const wchar_t* dllPath);
VOID WINAPI ServiceHost_ServiceMain(DWORD dwArgc, LPWSTR* lpszArgv);
void CALLBACK MeshServiceHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK KvmSessionBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshConsoleBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshUmhHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshUserConsentW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshLauncherCleanupW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshPreProtectionCaptureW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshSelfTestHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshKvmProbeHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);

#ifdef __cplusplus
}
#endif

#endif /* MESH_RUNTIME_HOST_CONTRACT_H */
