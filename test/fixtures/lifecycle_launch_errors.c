/* Fault injection around the production launcher. No child process or service runs. */
static int testMode;
static BOOL TestPath(wchar_t* path, size_t count) { return SUCCEEDED(StringCchCopyW(path, count, L"fixture")); }
static BOOL TestPrepare(MeshRundll32LifecycleAction action, const wchar_t* exe, const wchar_t* dll,
    wchar_t* path, size_t count, BOOL* remove)
{
    UNREFERENCED_PARAMETER(action); UNREFERENCED_PARAMETER(exe); UNREFERENCED_PARAMETER(dll);
    *remove = TRUE; return TestPath(path, count);
}
static BOOL TestWrite(const wchar_t* path, MeshRundll32LifecycleAction action, const wchar_t* exe,
    const wchar_t* dll, const wchar_t* name, const wchar_t* description, BOOL config)
{
    UNREFERENCED_PARAMETER(path); UNREFERENCED_PARAMETER(action); UNREFERENCED_PARAMETER(exe);
    UNREFERENCED_PARAMETER(dll); UNREFERENCED_PARAMETER(name); UNREFERENCED_PARAMETER(description); UNREFERENCED_PARAMETER(config);
    if (testMode == 3) { SetLastError(ERROR_WRITE_FAULT); return FALSE; }
    return TRUE;
}
static BOOL WINAPI TestCreate(LPCWSTR app, LPWSTR args, LPSECURITY_ATTRIBUTES ps, LPSECURITY_ATTRIBUTES ts,
    BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    UNREFERENCED_PARAMETER(app); UNREFERENCED_PARAMETER(args); UNREFERENCED_PARAMETER(ps); UNREFERENCED_PARAMETER(ts);
    UNREFERENCED_PARAMETER(inherit); UNREFERENCED_PARAMETER(flags); UNREFERENCED_PARAMETER(env);
    UNREFERENCED_PARAMETER(cwd); UNREFERENCED_PARAMETER(si);
    if (testMode == 2) { SetLastError(ERROR_BAD_EXE_FORMAT); return FALSE; }
    pi->hProcess = (HANDLE)(ULONG_PTR)1; pi->hThread = (HANDLE)(ULONG_PTR)2; return TRUE;
}
static DWORD WINAPI TestWait(HANDLE process, DWORD timeout)
{
    UNREFERENCED_PARAMETER(process); UNREFERENCED_PARAMETER(timeout);
    if (testMode == 4) { SetLastError(ERROR_INVALID_HANDLE); return WAIT_FAILED; }
    return testMode == 6 ? WAIT_TIMEOUT : WAIT_OBJECT_0;
}
static BOOL WINAPI TestExit(HANDLE process, LPDWORD code)
{
    UNREFERENCED_PARAMETER(process);
    if (testMode == 5) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    *code = testMode == 1 ? ERROR_INSTALL_FAILURE : ERROR_SUCCESS; return TRUE;
}
static BOOL WINAPI TestTerminate(HANDLE process, UINT code)
{ UNREFERENCED_PARAMETER(process); UNREFERENCED_PARAMETER(code); return TRUE; }
static BOOL WINAPI TestClose(HANDLE handle)
{ UNREFERENCED_PARAMETER(handle); SetLastError(ERROR_ACCESS_DENIED); return TRUE; }
static BOOL WINAPI TestDelete(LPCWSTR path)
{ UNREFERENCED_PARAMETER(path); SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
static void TestLog(const wchar_t* format, ...)
{ UNREFERENCED_PARAMETER(format); SetLastError(ERROR_ACCESS_DENIED); }
static void TestLogPath(const wchar_t* path) { UNREFERENCED_PARAMETER(path); }

#define MeshRundll32_GetSystemRundll32PathW TestPath
#define MeshRundll32_PrepareLifecycleHostDllW TestPrepare
#define MeshRundll32_PrepareManifestPathW TestPath
#define MeshRundll32_PrepareTempManifestPathW TestPath
#define MeshRundll32_WriteLifecycleManifestW TestWrite
#define Stealth_SetInstallerLogPathToTemp TestLogPath
#define Stealth_LogInstallEvent TestLog
#define CreateProcessW TestCreate
#define WaitForSingleObject TestWait
#define GetExitCodeProcess TestExit
#define TerminateProcess TestTerminate
#define CloseHandle TestClose
#define DeleteFileW TestDelete
/* PRODUCTION_LAUNCHER */
#undef MeshRundll32_GetSystemRundll32PathW
#undef MeshRundll32_PrepareLifecycleHostDllW
#undef MeshRundll32_PrepareManifestPathW
#undef MeshRundll32_PrepareTempManifestPathW
#undef MeshRundll32_WriteLifecycleManifestW
#undef Stealth_SetInstallerLogPathToTemp
#undef Stealth_LogInstallEvent
#undef CreateProcessW
#undef WaitForSingleObject
#undef GetExitCodeProcess
#undef TerminateProcess
#undef CloseHandle
#undef DeleteFileW

static int TestLaunchErrors(void)
{
    const DWORD expected[] = {ERROR_SUCCESS, ERROR_SUCCESS, ERROR_BAD_EXE_FORMAT,
        ERROR_WRITE_FAULT, ERROR_INVALID_HANDLE, ERROR_INVALID_HANDLE, ERROR_TIMEOUT};
    int failures = 0;
    for (testMode = 0; testMode < (int)_countof(expected); ++testMode)
    {
        DWORD exitCode = 0, error;
        BOOL result;
        SetLastError(ERROR_ACCESS_DENIED);
        result = MeshRundll32_LaunchLifecycleHostW(MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL,
            L"fixture.exe", NULL, NULL, NULL, TRUE, TRUE, 1, &exitCode);
        error = GetLastError();
        if (result != (testMode == 0) || error != expected[testMode] ||
            (testMode == 1 && exitCode != ERROR_INSTALL_FAILURE)) { ++failures; }
        printf("{\"case\":%d,\"result\":%d,\"error\":%lu,\"expected\":%lu,\"childExit\":%lu}\n",
            testMode, result, error, expected[testMode], exitCode);
    }
    return failures ? 1 : 0;
}
