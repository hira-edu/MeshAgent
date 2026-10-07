"""Exercise locked terminal uninstall and residue checks without SCM mutation.

Production file identity and enumeration run against temporary files. Mutex,
deployment and reboot-deletion APIs are stubbed so no pending deletes are added.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def extract(file, name):
    source = (ROOT / file).read_text()
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'(?:static )?(?:BOOL|const wchar_t\*) ' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]


prelude = r'''
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define MESH_LIFECYCLE_ACTION_UNINSTALL_W L"uninstall"
typedef struct { wchar_t installDir[MAX_PATH], logsDir[MAX_PATH], exePath[MAX_PATH]; } ServiceInstallPaths;
typedef struct {
    ServiceInstallPaths paths;
    BOOL dllExists, confExists, dbExists, serviceKeyExists, serviceExists, firewallRulePresent,
        anyPersistenceArtifacts, anyCompanionArtifacts, pendingUpdate, serviceGroupArtifactsPresent, logsDirExists;
    DWORD conflictingServiceAliasCount;
} ServiceLifecycleDiscovery;
static ServiceLifecycleDiscovery state;
#define ServiceDeploy_SelectIncumbent() TRUE
#define ServiceDeploy_ResolveRuntimeServiceBranding(n,c,...) StringCchCopyW(n,c,L"Agent")
static BOOL locked, lockFault, pathFault, discoveryFault, engineResult, scopedMember, legacyMember, groupFault;
static int calls, moves, moveFault, closes, groupCalls;
static HANDLE acquire(void) {
    assert(!locked); if (lockFault) return NULL; locked = TRUE; return (HANDLE)1;
}
static BOOL release(HANDLE mutex) { assert(mutex == (HANDLE)1 && locked); locked = FALSE; return TRUE; }
static BOOL closeMutex(HANDLE mutex) { assert(mutex == (HANDLE)1 && !locked); ++closes; return TRUE; }
static BOOL fixturePaths(ServiceInstallPaths* out) { assert(locked); *out = state.paths; return !pathFault; }
static BOOL discover(ServiceLifecycleDiscovery* out) { assert(locked); *out = state; return !discoveryFault; }
static BOOL operation(const wchar_t* action, const wchar_t* exe, const wchar_t* dll, BOOL config) {
    assert(locked && !wcscmp(action, L"uninstall") && !exe && !dll && !config); ++calls; return engineResult;
}
static BOOL move(const wchar_t* source, const wchar_t* target, DWORD flags) {
    assert(locked); ++moves;
    if (moves == 1) { assert(!wcscmp(source, state.paths.exePath) && target && !flags); }
    else { assert(!target && flags == MOVEFILE_DELAY_UNTIL_REBOOT); }
    return moves != moveFault;
}
static BOOL combine(wchar_t* out, size_t size, const wchar_t* root, const wchar_t* leaf) {
    return SUCCEEDED(StringCchPrintfW(out, size, L"%ls\\%ls", root, leaf));
}
static BOOL buildGroup(const wchar_t* name, wchar_t* out, size_t size) {
    (void)name; return SUCCEEDED(StringCchCopyW(out, size, L"group"));
}
static BOOL group(const wchar_t* name, const wchar_t* service, BOOL restore, BOOL* member, BOOL deleteEmpty) {
    (void)service; assert(!restore); ++groupCalls;
    assert(deleteEmpty == (wcscmp(name, L"netsvcs") != 0));
    *member = deleteEmpty ? scopedMember : legacyMember;
    return groupCalls != groupFault;
}
static void log_event(const wchar_t* format, ...) { (void)format; }
#define ServiceDeploy_AcquireLifecycleMutex acquire
#define ServiceDeploy_GetInstallPaths fixturePaths
#define ServiceDeploy_DiscoverCurrentState discover
#define ServiceDeploy_RunLifecycleHostOperationLocked operation
#define ServiceDeploy_LogInstallEvent log_event
#define ServiceHost_BuildGroupName buildGroup
#define ServiceBinding_Group group
#define MeshInstaller_CombinePath combine
#define MoveFileExW move
#define ReleaseMutex release
'''

cases = r'''
static void reset(void) {
    assert(!locked);
    ZeroMemory(&state, sizeof(state));
    wcscpy_s(state.paths.installDir, MAX_PATH, L"install-dir");
    wcscpy_s(state.paths.logsDir, MAX_PATH, L"install-dir\\logs");
    wcscpy_s(state.paths.exePath, MAX_PATH, L"install-dir\\agent.exe");
    lockFault = pathFault = discoveryFault = engineResult = FALSE;
    moves = calls = closes = moveFault = 0;
}
static BOOL run(const wchar_t* running, BOOL* scheduled, wchar_t* retired) {
    BOOL result = ServiceDeploy_RunTerminalUninstall(running, retired, MAX_PATH * 4, scheduled);
    assert(!locked && (lockFault || closes == 1)); return result;
}
int main(void) {
    assert(CreateDirectoryW(L"install-dir", NULL));
    HANDLE file = CreateFileW(L"install-dir\\agent.exe", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE); CloseHandle(file);
    assert(CreateHardLinkW(L"alias.exe", L"install-dir\\agent.exe", NULL));
    file = CreateFileW(L"staged.exe", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE); CloseHandle(file);
    assert(ServiceUtil_PathsReferToSameFileW(L"alias.exe", L"install-dir\\agent.exe"));
    assert(!ServiceUtil_PathsReferToSameFileW(L"staged.exe", L"install-dir\\agent.exe"));
    assert(!ServiceUtil_PathsReferToSameFileW(L"missing.exe", L"install-dir\\agent.exe"));
    wchar_t retired[MAX_PATH * 4]; BOOL scheduled;
    reset(); engineResult = TRUE; assert(run(L"staged.exe", &scheduled, retired) && !moves && !scheduled);
    reset(); lockFault = TRUE; assert(!run(L"alias.exe", &scheduled, retired) && !calls && !moves);
    reset(); pathFault = TRUE; assert(!run(L"alias.exe", &scheduled, retired) && !calls && !moves);
    reset(); assert(!run(L"staged.exe", &scheduled, retired) && calls == 1 && !moves);
    reset(); assert(run(L"alias.exe", &scheduled, retired) && scheduled && moves == 3);
    for (int failure = 1; failure <= 3; ++failure) {
        reset(); moveFault = failure;
        BOOL result = run(L"alias.exe", &scheduled, retired);
        assert(result == (failure == 3));
        if (failure == 1) assert(!retired[0] && !scheduled);
        if (failure == 2) assert(retired[0] && !scheduled);
        if (failure == 3) assert(retired[0] && scheduled);
    }
    BOOL* residue[] = {&state.dllExists, &state.confExists, &state.dbExists, &state.serviceKeyExists,
        &state.serviceExists, &state.firewallRulePresent, &state.anyPersistenceArtifacts,
        &state.anyCompanionArtifacts, &state.pendingUpdate, &state.serviceGroupArtifactsPresent, &state.logsDirExists};
    for (size_t i = 0; i < _countof(residue); ++i) {
        reset(); *residue[i] = TRUE;
        assert(!run(L"alias.exe", &scheduled, retired) && !moves);
    }
    reset(); state.conflictingServiceAliasCount = 1; assert(!run(L"alias.exe", &scheduled, retired) && !moves);
    reset(); discoveryFault = TRUE; assert(!run(L"alias.exe", &scheduled, retired) && !moves);
    file = CreateFileW(L"install-dir\\unknown.log", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE); CloseHandle(file);
    reset(); assert(!run(L"alias.exe", &scheduled, retired) && !moves);
    assert(DeleteFileW(L"install-dir\\unknown.log"));
    assert(CreateDirectoryW(L"install-dir\\state", NULL));
    reset(); assert(!run(L"alias.exe", &scheduled, retired) && !moves);
    assert(RemoveDirectoryW(L"install-dir\\state"));
    for (int i = 0; i < 5; ++i) {
        groupCalls = 0; scopedMember = i == 1; legacyMember = i == 2;
        groupFault = i == 3 ? 1 : i == 4 ? 2 : 0;
        assert(ServiceDeploy_ServiceGroupsAbsent(L"Agent") == (i == 0));
    }
    assert(DeleteFileW(L"alias.exe") && DeleteFileW(L"staged.exe") && DeleteFileW(L"install-dir\\agent.exe"));
    assert(RemoveDirectoryW(L"install-dir"));
    puts("Terminal uninstall: locked retirement, 11 residue categories, real hard-link identity, filesystem and group faults passed");
    return 0;
}
'''

if os.name != 'nt':
    raise SystemExit('This harness requires Windows headers')
functions = [extract('meshservice/service_utils.c', 'ServiceUtil_PathsReferToSameFileW')]
# Identity's ordinary file handles use the real API; only the lifecycle mutex is stubbed.
functions.append('#define CloseHandle closeMutex\n')
for name in ['MeshInstaller_GetPathLeaf', 'ServiceDeploy_InstallDirectoryContainsOnlyInstalledExe',
             'ServiceDeploy_IsUninstallCleanExceptInstalledExe', 'ServiceDeploy_RetireRunningInstalledImage',
             'ServiceDeploy_RunTerminalUninstall', 'ServiceDeploy_ServiceGroupsAbsent']:
    functions.append(extract('meshservice/service_deployment.c', name))
functions.append('#undef CloseHandle\n')
with tempfile.TemporaryDirectory(prefix='mesh-terminal-uninstall-') as directory:
    c_path = Path(directory) / 'uninstall.c'
    executable = Path(directory) / 'uninstall.exe'
    c_path.write_text(prelude + '\n'.join(functions) + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c_path), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], cwd=directory, check=True)
