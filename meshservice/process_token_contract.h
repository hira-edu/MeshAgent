#ifndef MESH_PROCESS_TOKEN_CONTRACT_H
#define MESH_PROCESS_TOKEN_CONTRACT_H

#include <windows.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <stdio.h>

// Session placement never implies an identity or an elevation request.
#define MESH_PROCESS_TOKEN_CURRENT_SESSION MAXDWORD
typedef enum MeshProcessTokenMode
{
    MeshProcessToken_Privileged = 0,
    MeshProcessToken_SessionUser = 1
} MeshProcessTokenMode;

typedef struct MeshProcessTokenSnapshot
{
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sessionId;
    DWORD integrityRid;
    TOKEN_ELEVATION_TYPE elevationType;
    BOOL elevated;
    BOOL system;
    BOOL adminEnabled;
    BOOL restricted;
    DWORD appContainer;
} MeshProcessTokenSnapshot;

#ifndef MESH_PROCESS_TOKEN_LOG
#define MESH_PROCESS_TOKEN_LOG(message) OutputDebugStringW(message)
#endif

static void MeshProcessToken_Log(const wchar_t* phase, MeshProcessTokenMode mode, DWORD pid,
    const MeshProcessTokenSnapshot* snapshot, DWORD error)
{
    wchar_t message[768];
    LPWSTR sid = NULL;
    if (snapshot != NULL) { ConvertSidToStringSidW((PSID)snapshot->sid, &sid); }
    swprintf_s(message, _countof(message),
        L"[PROCESS_TOKEN] phase=%ls mode=%ls parent=%lu child=%lu sid=%ls session=%lu integrity=%lu elevated=%d type=%u error=%lu",
        phase, mode == MeshProcessToken_SessionUser ? L"session-user" : L"privileged-agent",
        GetCurrentProcessId(), pid, sid != NULL ? sid : L"unknown",
        snapshot != NULL ? snapshot->sessionId : MAXDWORD,
        snapshot != NULL ? snapshot->integrityRid : 0,
        snapshot != NULL ? snapshot->elevated : FALSE,
        snapshot != NULL ? (unsigned)snapshot->elevationType : 0, error);
    MESH_PROCESS_TOKEN_LOG(message);
    if (sid != NULL) { LocalFree(sid); }
}

static BOOL MeshProcessToken_Read(HANDLE token, MeshProcessTokenSnapshot* snapshot)
{
    union { TOKEN_USER value; BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } user;
    union { TOKEN_MANDATORY_LABEL value; BYTE bytes[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE]; } label;
    TOKEN_ELEVATION elevation;
    TOKEN_TYPE type;
    PTOKEN_GROUPS groups = NULL;
    DWORD length = 0, groupBytes = 0, index;
    BOOL ok = FALSE;
    DWORD error;
    if (token == NULL || snapshot == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    ZeroMemory(snapshot, sizeof(*snapshot));
    if (!GetTokenInformation(token, TokenType, &type, sizeof(type), &length)) { return FALSE; }
    if (type != TokenPrimary) { SetLastError(ERROR_BAD_TOKEN_TYPE); return FALSE; }
    if (!GetTokenInformation(token, TokenUser, &user, sizeof(user), &length) ||
        !GetTokenInformation(token, TokenIntegrityLevel, &label, sizeof(label), &length) ||
        !GetTokenInformation(token, TokenSessionId, &snapshot->sessionId, sizeof(DWORD), &length) ||
        !GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length) ||
        !GetTokenInformation(token, TokenElevationType, &snapshot->elevationType, sizeof(snapshot->elevationType), &length) ||
        !GetTokenInformation(token, TokenIsAppContainer, &snapshot->appContainer, sizeof(DWORD), &length)) { return FALSE; }
    if (!IsValidSid(user.value.User.Sid) || !IsValidSid(label.value.Label.Sid) ||
        *GetSidSubAuthorityCount(label.value.Label.Sid) == 0) { SetLastError(ERROR_INVALID_SID); return FALSE; }
    if (!CopySid(sizeof(snapshot->sid), snapshot->sid, user.value.User.Sid)) { return FALSE; }
    snapshot->system = IsWellKnownSid(user.value.User.Sid, WinLocalSystemSid);
    snapshot->elevated = elevation.TokenIsElevated != 0;
    snapshot->integrityRid = *GetSidSubAuthority(label.value.Label.Sid, *GetSidSubAuthorityCount(label.value.Label.Sid) - 1);
    snapshot->restricted = IsTokenRestricted(token);
    if (GetTokenInformation(token, TokenGroups, NULL, 0, &groupBytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || groupBytes < sizeof(TOKEN_GROUPS))
    { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    groups = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), 0, groupBytes);
    if (groups == NULL) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    if (GetTokenInformation(token, TokenGroups, groups, groupBytes, &length))
    {
        for (index = 0; index < groups->GroupCount; ++index)
        {
            DWORD attributes = groups->Groups[index].Attributes;
            if ((attributes & SE_GROUP_ENABLED) != 0 && (attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0 &&
                IsWellKnownSid(groups->Groups[index].Sid, WinBuiltinAdministratorsSid)) { snapshot->adminEnabled = TRUE; }
        }
        ok = TRUE;
    }
    error = ok ? ERROR_SUCCESS : GetLastError();
    HeapFree(GetProcessHeap(), 0, groups);
    SetLastError(error);
    return ok;
}

static BOOL MeshProcessToken_IsPrivileged(const MeshProcessTokenSnapshot* snapshot)
{
    return !snapshot->restricted && !snapshot->appContainer &&
        ((snapshot->system && snapshot->integrityRid >= SECURITY_MANDATORY_SYSTEM_RID) ||
         (snapshot->adminEnabled && snapshot->elevated && snapshot->integrityRid >= SECURITY_MANDATORY_HIGH_RID));
}

static BOOL MeshProcessToken_Matches(const MeshProcessTokenSnapshot* expected, const MeshProcessTokenSnapshot* actual)
{
    return EqualSid((PSID)expected->sid, (PSID)actual->sid) &&
        expected->sessionId == actual->sessionId && expected->integrityRid == actual->integrityRid &&
        expected->elevated == actual->elevated && expected->elevationType == actual->elevationType &&
        expected->adminEnabled == actual->adminEnabled && expected->restricted == actual->restricted &&
        expected->appContainer == actual->appContainer;
}

// Resolve only the caller's privilege or an explicitly requested WTS user.
// Never borrow another process's token or fall back between these roles.
static BOOL MeshProcessToken_Open(MeshProcessTokenMode mode, DWORD sessionId, HANDLE* tokenOut)
{
    HANDLE source = NULL, primary = NULL;
    MeshProcessTokenSnapshot original, selected, actual;
    DWORD error = ERROR_SUCCESS;
    BOOL ok = FALSE;
    if (tokenOut == NULL) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *tokenOut = NULL;
    if (mode == MeshProcessToken_SessionUser)
    {
        if (sessionId == MESH_PROCESS_TOKEN_CURRENT_SESSION || sessionId == 0)
        { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        if (!WTSQueryUserToken(sessionId, &source)) { goto cleanup; }
    }
    else if (mode == MeshProcessToken_Privileged)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &source)) { goto cleanup; }
    }
    else { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!MeshProcessToken_Read(source, &original)) { goto cleanup; }
    selected = original;
    if (mode == MeshProcessToken_Privileged && !MeshProcessToken_IsPrivileged(&selected))
    {
        // A limited caller must obtain consent through an authorized broker.
        // This helper never activates a linked token or implements self-elevation.
        SetLastError(ERROR_ELEVATION_REQUIRED);
        goto cleanup;
    }
    if (mode == MeshProcessToken_SessionUser && (selected.system || selected.sessionId != sessionId))
    { SetLastError(ERROR_ACCESS_DENIED); goto cleanup; }
    if (!DuplicateTokenEx(source,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
        NULL, SecurityImpersonation, TokenPrimary, &primary)) { goto cleanup; }
    if (sessionId != MESH_PROCESS_TOKEN_CURRENT_SESSION && selected.sessionId != sessionId)
    {
        if (!SetTokenInformation(primary, TokenSessionId, &sessionId, sizeof(sessionId))) { goto cleanup; }
        selected.sessionId = sessionId;
    }
    if (!MeshProcessToken_Read(primary, &actual)) { goto cleanup; }
    if (!MeshProcessToken_Matches(&selected, &actual)) { SetLastError(ERROR_ACCESS_DENIED); goto cleanup; }
    MeshProcessToken_Log(L"selected", mode, 0, &actual, ERROR_SUCCESS);
    *tokenOut = primary;
    primary = NULL;
    ok = TRUE;
cleanup:
    error = ok ? ERROR_SUCCESS : GetLastError();
    if (primary != NULL) { CloseHandle(primary); }
    if (source != NULL) { CloseHandle(source); }
    if (!ok) { MeshProcessToken_Log(L"denied", mode, 0, NULL, error); }
    SetLastError(error);
    return ok;
}

// The caller must create suspended. No command code runs until this check passes.
static BOOL MeshProcessToken_VerifyChildAndResume(MeshProcessTokenMode mode, HANDLE selectedToken, PROCESS_INFORMATION* processInfo)
{
    HANDLE childToken = NULL;
    MeshProcessTokenSnapshot expected, actual;
    DWORD error;
    DWORD cleanupError;
    DWORD waitResult;
    if (processInfo == NULL || processInfo->hProcess == NULL || processInfo->hThread == NULL)
    { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!MeshProcessToken_Read(selectedToken, &expected) ||
        !OpenProcessToken(processInfo->hProcess, TOKEN_QUERY, &childToken) ||
        !MeshProcessToken_Read(childToken, &actual)) { goto fail; }
    CloseHandle(childToken);
    childToken = NULL;
    if (!MeshProcessToken_Matches(&expected, &actual) ||
        (mode == MeshProcessToken_Privileged && !MeshProcessToken_IsPrivileged(&actual)) ||
        (mode == MeshProcessToken_SessionUser && actual.system))
    { SetLastError(ERROR_ACCESS_DENIED); goto fail; }
    if (ResumeThread(processInfo->hThread) == (DWORD)-1) { goto fail; }
    MeshProcessToken_Log(L"started", mode, processInfo->dwProcessId, &actual, ERROR_SUCCESS);
    return TRUE;
fail:
    error = GetLastError();
    if (childToken != NULL) { CloseHandle(childToken); }
    MeshProcessToken_Log(L"child-rejected", mode, processInfo->dwProcessId, NULL, error);
    if (!TerminateProcess(processInfo->hProcess, error))
    {
        cleanupError = GetLastError();
        MeshProcessToken_Log(L"child-termination-failed", mode, processInfo->dwProcessId, NULL, cleanupError);
    }
    else
    {
        waitResult = WaitForSingleObject(processInfo->hProcess, 5000);
        if (waitResult != WAIT_OBJECT_0)
        {
            cleanupError = waitResult == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
            MeshProcessToken_Log(L"child-termination-wait-failed", mode, processInfo->dwProcessId, NULL, cleanupError);
        }
    }
    CloseHandle(processInfo->hThread);
    CloseHandle(processInfo->hProcess);
    ZeroMemory(processInfo, sizeof(*processInfo));
    SetLastError(error);
    return FALSE;
}

#endif
