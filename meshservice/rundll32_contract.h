#ifndef MESH_RUNDLL32_CONTRACT_H
#define MESH_RUNDLL32_CONTRACT_H

#include <windows.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_RUNDLL32_ENTRY_LIFECYCLE_W      L"MeshLifecycleHostW"
#define MESH_RUNDLL32_ENTRY_KVM_BRIDGE_W     L"KvmSessionBridgeW"
#define MESH_RUNDLL32_ENTRY_LAUNCHER_CLEANUP_W L"MeshLauncherCleanupW"
#define MESH_RUNDLL32_ENTRY_PREPROTECTION_CAPTURE_W L"MeshPreProtectionCaptureW"
#define MESH_RUNDLL32_ENTRY_SELFTEST_W    L"MeshSelfTestHostW"
#define MESH_RUNDLL32_ENTRY_KVM_PROBE_W   L"MeshKvmProbeHostW"
#define MESH_RUNDLL32_ENTRY_LIFECYCLE_A      "MeshLifecycleHostW"
#define MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A     "KvmSessionBridgeW"
#define MESH_RUNDLL32_ENTRY_LAUNCHER_CLEANUP_A "MeshLauncherCleanupW"
#define MESH_RUNDLL32_ENTRY_PREPROTECTION_CAPTURE_A "MeshPreProtectionCaptureW"
#define MESH_RUNDLL32_ENTRY_SELFTEST_A    "MeshSelfTestHostW"
#define MESH_RUNDLL32_ENTRY_KVM_PROBE_A   "MeshKvmProbeHostW"

#define MESH_LIFECYCLE_ACTION_INSTALL_W      L"install"
#define MESH_LIFECYCLE_ACTION_UPDATE_W       L"update"
#define MESH_LIFECYCLE_ACTION_REPAIR_W       L"repair"
#define MESH_LIFECYCLE_ACTION_REINSTALL_W    L"reinstall"
#define MESH_LIFECYCLE_ACTION_UNINSTALL_W    L"uninstall"
#define MESH_LIFECYCLE_ACTION_VALIDATE_INSTALL_W   L"validate-install"
#define MESH_LIFECYCLE_ACTION_VALIDATE_UPDATE_W    L"validate-update"
#define MESH_LIFECYCLE_ACTION_VALIDATE_UNINSTALL_W L"validate-uninstall"
#define MESH_LIFECYCLE_ACTION_VALIDATE_PACKAGE_W   L"validate-package"

typedef enum MeshRundll32LifecycleAction
{
    MESH_RUNDLL32_LIFECYCLE_ACTION_UNKNOWN = 0,
    MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL,
    MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE,
    MESH_RUNDLL32_LIFECYCLE_ACTION_REPAIR,
    MESH_RUNDLL32_LIFECYCLE_ACTION_REINSTALL,
    MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL,
    MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL,
    MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE,
    MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL,
    MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_PACKAGE
} MeshRundll32LifecycleAction;

typedef struct MeshRundll32LifecycleManifest
{
    MeshRundll32LifecycleAction action;
    wchar_t manifestPath[MAX_PATH * 4];
    wchar_t sourceExePath[MAX_PATH * 4];
    wchar_t sourceDllPath[MAX_PATH * 4];
    wchar_t displayName[256];
    wchar_t serviceDescription[512];
    BOOL requireConfig;
} MeshRundll32LifecycleManifest;

const wchar_t* MeshRundll32_LifecycleActionNameW(MeshRundll32LifecycleAction action);
BOOL MeshRundll32_LifecycleActionFromStringW(const wchar_t* value, MeshRundll32LifecycleAction* actionOut);
BOOL MeshRundll32_ReadLifecycleManifestW(const wchar_t* manifestPath, MeshRundll32LifecycleManifest* manifestOut);
BOOL MeshRundll32_WriteLifecycleManifestW(
    const wchar_t* manifestPath,
    MeshRundll32LifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    BOOL requireConfig);
BOOL MeshRundll32_GetSystemRundll32PathW(wchar_t* rundll32Path, size_t rundll32PathCch);
BOOL MeshRundll32_LaunchLifecycleHostW(
    MeshRundll32LifecycleAction action,
    const wchar_t* sourceExePath,
    const wchar_t* sourceDllPath,
    const wchar_t* displayName,
    const wchar_t* serviceDescription,
    BOOL requireConfig,
    BOOL waitForExit,
    DWORD timeoutMs,
    DWORD* exitCodeOut);
BOOL MeshRundll32_LaunchLauncherCleanupW(const wchar_t* targetPath, DWORD parentPid, DWORD timeoutMs);
BOOL MeshRundll32_LaunchSelfTestHostW(const wchar_t* arguments, DWORD timeoutMs, DWORD* exitCodeOut);

void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshLauncherCleanupW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshPreProtectionCaptureW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshSelfTestHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);
void CALLBACK MeshKvmProbeHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);

#ifdef __cplusplus
}
#endif

#endif /* MESH_RUNDLL32_CONTRACT_H */
