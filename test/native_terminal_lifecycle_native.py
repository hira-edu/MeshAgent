"""Fault-inject the production terminal dispatcher without changing services.

Compile extracted production functions with Windows headers. The lifecycle engine
is stubbed; this verifies command admission and results, not SCM integration.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/ServiceMain.c').read_text()
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                lambda m: ' ' * len(m.group()), source, flags=re.S)


def extract(name):
    match = re.search(r'static (?:BOOL|int) ' + name + r'\s*\([^;{]+\)\s*\{', masked)
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
#include <stdarg.h>
#include <string.h>
#define strcasecmp _stricmp
#define MESH_LIFECYCLE_ACTION_INSTALL_W L"install"
#define MESH_LIFECYCLE_ACTION_UPDATE_W L"update"
#define MESH_LIFECYCLE_ACTION_UNINSTALL_W L"uninstall"
#define MESH_LIFECYCLE_ACTION_VALIDATE_INSTALL_W L"validate-install"
#define MESH_LIFECYCLE_ACTION_VALIDATE_UPDATE_W L"validate-update"
#define MESH_LIFECYCLE_ACTION_VALIDATE_UNINSTALL_W L"validate-uninstall"
typedef struct { WCHAR installDir[MAX_PATH], exePath[MAX_PATH]; } ServiceInstallPaths;
typedef struct { BOOL configAvailable; } ServicePackagePreflight;
static int admin, extraPathFault, moduleFault, sameFile, preflightFault, config,
    engineResult, calls, validationCalls, handlers, handlerFault, quietCalls, quietFault;
static BOOL passedConfig;
static DWORD module(HMODULE mod, WCHAR* out, DWORD size) {
    (void)mod; if (moduleFault) return moduleFault == 1 ? 0 : size;
    wcscpy_s(out, size, L"staged.exe"); return 10;
}
static BOOL fixturePaths(ServiceInstallPaths* out) {
    if (extraPathFault) return FALSE;
    wcscpy_s(out->exePath, MAX_PATH, L"installed.exe"); return TRUE;
}
static BOOL fixturePreflight(const WCHAR* path, BOOL require, ServicePackagePreflight* out, WCHAR* reason, size_t size) {
    (void)path; (void)require; (void)reason; (void)size;
    out->configAvailable = config; return !preflightFault;
}
static BOOL engine(const WCHAR* action, const WCHAR* exe, const WCHAR* dll, BOOL require) {
    (void)exe; (void)dll; passedConfig = require;
    if (!wcsncmp(action, L"validate-", 9)) { ++validationCalls; return TRUE; }
    ++calls; SetLastError(engineResult ? ERROR_SUCCESS : ERROR_BAD_EXE_FORMAT); return engineResult;
}
static BOOL uninstall(const WCHAR* path, WCHAR* retired, size_t capacity, BOOL* scheduled) {
    (void)path; (void)retired; (void)capacity; *scheduled = FALSE;
    ++calls; return engineResult;
}
static BOOL ctrl(PHANDLER_ROUTINE handler, BOOL add) {
    (void)handler; if (add && handlerFault) return FALSE;
    handlers += add ? 1 : -1; return TRUE;
}
static BOOL WINAPI handler(DWORD type) { (void)type; return TRUE; }
static BOOL retire(const ServiceInstallPaths* paths, WCHAR* retired, size_t size, BOOL* scheduled) {
    (void)paths; (void)retired; (void)size; (void)scheduled; return FALSE;
}
static int quiet(void) { ++quietCalls; return quietFault ? ERROR_OPEN_FAILED : 0; }
static void log_event(const WCHAR* format, ...) { (void)format; }
#define IsAdmin() admin
#define GetModuleFileNameW module
#define ServiceDeploy_GetInstallPaths fixturePaths
#define ServiceUtil_PathsReferToSameFileW(a,b) sameFile
#define ServiceDeploy_PreflightPackageSource fixturePreflight
#define ServiceDeploy_RunLifecycleHostOperation engine
#define ServiceDeploy_RunTerminalUninstall uninstall
#define SetConsoleCtrlHandler ctrl
#define MeshService_LifecycleConsoleCtrlHandler handler
#define MeshService_RetireRunningInstalledImage retire
#define MeshService_EnableQuietTerminalLifecycle quiet
#define ServiceDeploy_EnsureLoggingDefaults() ((void)0)
#define ServiceDeploy_SetInstallerLogPathToTemp(p) ((void)0)
#define ServiceDeploy_LogInstallEvent log_event
#define MeshDiagnosticLog_GetPathW(out,size) (wcscpy_s(out,size,L"C:\\Agent\\logs\\diagnostics.log"),TRUE)
'''

cases = r'''
static void reset(void) {
    admin = engineResult = TRUE;
    extraPathFault = moduleFault = sameFile = preflightFault = config = calls =
        validationCalls = handlers = handlerFault = quietCalls = quietFault = 0;
}
static int run(const char* action, const char* option) {
    char* args[] = {"agent.exe", (char*)action, (char*)option};
    int result = MeshService_RunNativeTerminalLifecycle(option ? 3 : 2, args);
    assert(!handlers); return result;
}
int main(void) {
#if defined(_WIN64)
    /* A healthy restored incumbent must not relabel a rejected update. */
    reset(); engineResult = FALSE;
    assert(run("-update", NULL) == ERROR_INSTALL_FAILURE);
    assert(calls == 1 && !validationCalls);
    for (int i = 0; i < 3; ++i) {
        const char* action = i == 0 ? "-install" : i == 1 ? "-update" : "-uninstall";
        reset(); assert(run(action, NULL) == 0 && calls == 1);
        reset(); admin = FALSE; assert(run(action, NULL) == ERROR_ACCESS_DENIED && !calls);
        reset(); assert(run(action, "--unknown") == ERROR_INVALID_PARAMETER && !calls);
        reset(); extraPathFault = TRUE; assert(run(action, NULL) != 0 && !calls);
        reset(); moduleFault = 2; assert(run(action, NULL) == ERROR_INSUFFICIENT_BUFFER && !calls);
        reset(); handlerFault = TRUE; assert(run(action, NULL) != 0 && !calls);
        reset(); assert(run(action, "--quiet") == 0 && quietCalls == 1 && calls == 1);
        reset(); assert(run(action, "-silent") == 0 && quietCalls == 1 && calls == 1);
        reset(); quietFault = TRUE; assert(run(action, "--quiet") == ERROR_OPEN_FAILED && !calls);
        reset(); engineResult = FALSE; assert(run(action, NULL) == ERROR_INSTALL_FAILURE && !validationCalls);
    }
    reset(); sameFile = TRUE; assert(run("-install", NULL) == ERROR_INSTALL_FAILURE && !calls);
    reset(); sameFile = TRUE; assert(run("-update", NULL) == ERROR_INSTALL_FAILURE && !calls);
    reset(); sameFile = TRUE; assert(run("-uninstall", NULL) == 0 && calls == 1);
    reset(); preflightFault = TRUE; assert(run("-update", NULL) == ERROR_INVALID_DATA && !calls);
    reset(); assert(run("-update", NULL) == 0 && !passedConfig);
    reset(); config = TRUE; assert(run("-update", NULL) == 0 && passedConfig);
    puts("Terminal lifecycle: rollback results, admission, interruption guard and quiet cases passed");
#else
    const char* actions[] = {"-install", "-update", "-uninstall"};
    for (int i = 0; i < 3; ++i) {
        reset(); assert(run(actions[i], NULL) == ERROR_NOT_SUPPORTED && !calls && !handlers);
        reset(); assert(run(actions[i], "--quiet") == ERROR_NOT_SUPPORTED && quietCalls == 1 && !calls);
        reset(); assert(run(actions[i], "-silent") == ERROR_NOT_SUPPORTED && quietCalls == 1 && !calls);
    }
    puts("Win32 terminal lifecycle: normal and quiet commands rejected before deployment mutation");
#endif
    return 0;
}
'''

if os.name != 'nt':
    raise SystemExit('This harness requires Windows headers')
with tempfile.TemporaryDirectory(prefix='mesh-terminal-') as directory:
    c_path = Path(directory) / 'terminal.c'
    c_path.write_text(prelude + extract('MeshService_RunNativeTerminalLifecycle') + cases)
    for architecture in [[], ['-m32']]:
        executable = Path(directory) / ('terminal32.exe' if architecture else 'terminal64.exe')
        subprocess.run([os.environ.get('CC', 'clang'), *architecture, '-std=c11', str(c_path), '-o', str(executable)], check=True)
        result = subprocess.run([str(executable)], capture_output=True, check=True)
        if not architecture:
            assert b'exit=1603; Windows error hint=193' in result.stdout
            assert b'Installer diagnostics: C:\\Agent\\logs\\diagnostics.log' in result.stdout
        print(result.stdout.decode(errors='replace'), end='')
    # Use the real CRT and Win32 streams to verify silence with redirected pipes.
    c_path.write_text(r'''
#include <windows.h>
#include <stdio.h>
static void ServiceDeploy_LogInstallEvent(const wchar_t* format, ...) { (void)format; }
''' + extract('MeshService_EnableQuietTerminalLifecycle') + r'''
int main(int argc, char** argv) {
    (void)argv;
    if (argc > 1 && MeshService_EnableQuietTerminalLifecycle() != 0) return 1;
    printf("stdout marker\n"); fprintf(stderr, "stderr marker\n");
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "native output", 13, &written, NULL);
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), "native error", 12, &written, NULL);
    return 0;
}
''')
    executable = Path(directory) / 'quiet.exe'
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c_path), '-o', str(executable)], check=True)
    control = subprocess.run([str(executable)], capture_output=True, check=True)
    assert b'stdout marker' in control.stdout and b'stderr marker' in control.stderr
    quiet = subprocess.run([str(executable), '--quiet'], capture_output=True, check=True)
    assert quiet.stdout == b'' and quiet.stderr == b'', (quiet.stdout, quiet.stderr)
    print('Quiet terminal: real CRT and Win32 redirected streams passed')
