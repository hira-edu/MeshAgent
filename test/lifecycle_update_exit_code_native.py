#!/usr/bin/env python3
"""Lifecycle update results: success, completed-with-warnings and failure stay distinct.

Runs the production MeshRuntimeHost_LifecycleExitCode mapping (lifecycle host exit
code) and MeshAgent_RunNativeServiceFullUpdate (agent side) against a scripted
lifecycle launcher. A failed update must never be reported as success because a
later VALIDATE_UPDATE passes; that validation is a diagnostic only.
"""
import os
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def extract(source, name):
    match = re.search(r"(?m)^[^\n;]*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source)
    if not match:
        raise AssertionError("Missing production function: " + name)
    depth = 1
    for token in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[match.end():]):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():match.end() + token.end()]
    raise AssertionError("Unclosed function: " + name)


PRELUDE = r'''
#define _CRT_SECURE_NO_WARNINGS 1
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifndef _WIN32
#define _wcsicmp wcscasecmp
#endif
typedef int BOOL;
typedef unsigned long DWORD;
typedef wchar_t WCHAR;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define ERROR_SUCCESS 0UL
#define ERROR_INSTALL_FAILURE 1603UL
#define ERROR_ACCESS_DENIED 5UL
#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif
typedef enum { MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE = 2, MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UPDATE = 8 } MeshRuntimeHostLifecycleAction;
struct MeshAgentHostContainer { char *exePath; };
static DWORD lastError;
static DWORD GetLastError(void) { return lastError; }
static void SetLastError(DWORD e) { lastError = e; }
static int ILibUTF8ToWideEx(const char *in, int len, WCHAR *out, int count) { (void)len; return (int)mbstowcs(out, in, (size_t)count); }
static void MeshAgent_GetServiceKeyNameW(WCHAR *buffer, size_t count) { wcsncpy(buffer, L"MeshAgent", count); }
static BOOL MeshAgent_WaitForServiceNotRunning(const WCHAR *name, DWORD timeoutMs) { (void)name; (void)timeoutMs; return TRUE; }
static char logText[4096];
static void MeshAgent_LogNativeInstallerEvent(const char *fmt, ...) {
    va_list args; size_t used = strlen(logText); va_start(args, fmt);
    vsnprintf(logText + used, sizeof(logText) - used, fmt, args); va_end(args);
    strncat(logText, "\n", sizeof(logText) - strlen(logText) - 1);
}
static DWORD updateExit, validateExit, updateLastError; static int updateLaunches, validateLaunches;
static BOOL MeshRuntimeHost_LaunchLifecycleHostW(MeshRuntimeHostLifecycleAction action, const WCHAR *exe, const WCHAR *dll,
    const WCHAR *name, const WCHAR *description, const WCHAR *serviceName, BOOL config, BOOL wait, DWORD timeoutMs, DWORD *exitCode)
{
    (void)exe; (void)dll; (void)name; (void)description; (void)serviceName; (void)config; (void)wait; (void)timeoutMs;
    if (action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE) { ++updateLaunches; *exitCode = updateExit; SetLastError(updateLastError); return updateExit == ERROR_SUCCESS; }
    assert(action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_UPDATE);
    ++validateLaunches; *exitCode = validateExit; SetLastError(ERROR_ACCESS_DENIED); return validateExit == ERROR_SUCCESS;
}
'''

MAIN = r'''
static BOOL runUpdate(DWORD hostExit, DWORD hostError, DWORD validation) {
    struct MeshAgentHostContainer agent = { "C:\\Program Files\\Mesh Agent\\MeshAgent.exe" };
    logText[0] = 0; updateLaunches = validateLaunches = 0; lastError = 0;
    updateExit = hostExit; updateLastError = hostError; validateExit = validation;
    /* Same image as the running agent: the in-process compatibility update path. */
    return MeshAgent_RunNativeServiceFullUpdate(&agent, NULL, NULL, NULL, NULL);
}
int main(void) {
    assert(MESH_LIFECYCLE_EXIT_COMPLETED_WITH_WARNINGS & 0x20000000UL);
    assert(MeshRuntimeHost_LifecycleExitCode(TRUE, ERROR_ACCESS_DENIED) == ERROR_SUCCESS);
    assert(MeshRuntimeHost_LifecycleExitCode(FALSE, MESH_LIFECYCLE_EXIT_COMPLETED_WITH_WARNINGS) == MESH_LIFECYCLE_EXIT_COMPLETED_WITH_WARNINGS);
    assert(MeshRuntimeHost_LifecycleExitCode(FALSE, ERROR_ACCESS_DENIED) == ERROR_INSTALL_FAILURE);
    assert(MeshRuntimeHost_LifecycleExitCode(FALSE, ERROR_SUCCESS) == ERROR_INSTALL_FAILURE);

    assert(runUpdate(ERROR_SUCCESS, 0, ERROR_SUCCESS) == TRUE && updateLaunches == 1 && validateLaunches == 0);

    assert(runUpdate(MESH_LIFECYCLE_EXIT_COMPLETED_WITH_WARNINGS, 0, ERROR_INSTALL_FAILURE) == TRUE);
    assert(validateLaunches == 0 && strstr(logText, "completed with warnings (exit=536870913)"));

    /* The host failed: report failure even though the state probe passes. */
    assert(runUpdate(ERROR_INSTALL_FAILURE, 0, ERROR_SUCCESS) == FALSE && validateLaunches == 1);
    assert(GetLastError() == ERROR_INSTALL_FAILURE);
    assert(strstr(logText, "update failed (exit=1603") && strstr(logText, "Post-failure update validation passed (exit=0)"));
    assert(!strstr(logText, "validation passed\n...RuntimeHost lifecycle update completed"));

    assert(runUpdate(ERROR_INSTALL_FAILURE, ERROR_ACCESS_DENIED, ERROR_INSTALL_FAILURE) == FALSE && validateLaunches == 1);
    assert(GetLastError() == ERROR_ACCESS_DENIED && strstr(logText, "Post-failure update validation failed (exit=1603)"));

    puts("PASS: lifecycle update success, completed-with-warnings and failure stay distinct; validation is diagnostic only");
    return 0;
}
'''


def main():
    header = (ROOT / 'meshservice/runtime_host_contract.h').read_text(encoding='utf-8')
    host = (ROOT / 'meshservice/runtime_host_contract.c').read_text(encoding='utf-8')
    deployment = (ROOT / 'meshservice/service_deployment.c').read_text(encoding='utf-8')
    agentcore = (ROOT / 'meshcore/agentcore.c').read_text(encoding='utf-8')

    warning = re.search(r'(?m)^#define MESH_LIFECYCLE_EXIT_COMPLETED_WITH_WARNINGS .*$', header)
    assert warning, 'lifecycle warning exit code must be defined in runtime_host_contract.h'
    mapping = extract(header, 'MeshRuntimeHost_LifecycleExitCode')
    update = extract(agentcore, 'MeshAgent_RunNativeServiceFullUpdate')

    lifecycle_host = extract(host, 'MeshLifecycleHostW')
    assert 'MeshRuntimeHost_LifecycleExitCode(ok, operationError)' in lifecycle_host and 'ExitProcess(exitCode);' in lifecycle_host, \
        'MeshLifecycleHostW must exit with the mapped lifecycle exit code'
    apply_update = extract(deployment, 'ServiceDeploy_ApplyUpdateFlow')
    tail = apply_update[apply_update.index('if (success && !companionsReconciled)'):]
    assert 'SetLastError(MESH_LIFECYCLE_EXIT_COMPLETED_WITH_WARNINGS);' in tail[:tail.index('return FALSE;')], \
        'a committed update with unreconciled companions must report completed-with-warnings'

    with tempfile.TemporaryDirectory(prefix='mesh-lifecycle-exit-') as folder:
        path = pathlib.Path(folder)
        (path / 'probe.c').write_text(PRELUDE + warning.group(0) + '\n' + mapping.replace('static __inline', 'static') + '\n' + update + MAIN)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                        '-fsanitize=address,undefined', str(path / 'probe.c'), '-o', str(path / 'probe')], check=True)
        subprocess.run([str(path / 'probe')], check=True, timeout=15)


if __name__ == '__main__':
    main()
