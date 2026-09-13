// Fault-injected Win32 boundary test. No OS token, process or service is changed.
#include <windows.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct FakeToken
{
    BYTE sid[SECURITY_MAX_SID_SIZE], label[SECURITY_MAX_SID_SIZE], adminSid[SECURITY_MAX_SID_SIZE];
    DWORD session, integrity, appContainer;
    BOOL elevated, admin, restricted;
    TOKEN_ELEVATION_TYPE elevationType;
} FakeToken;
static FakeToken currentToken, sessionToken, duplicateToken, fakeChildToken;
static DWORD infoFailure, setFailure, duplicateFailure, wtsFailure, resumeFailure, terminateFailure, waitFailure;
static BOOL childOpenFailure, corruptDuplicate;
static int openedTokens, wtsCalls, duplicateCalls, setCalls, resumed, terminated, waited, processClosed, threadClosed;
static unsigned checks;
#define PROCESS_HANDLE ((HANDLE)(ULONG_PTR)0x1234)
#define THREAD_HANDLE ((HANDLE)(ULONG_PTR)0x5678)

static BOOL WINAPI FakeOpenProcessToken(HANDLE process, DWORD access, PHANDLE token)
{
    (void)access;
    if (process == PROCESS_HANDLE && childOpenFailure) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    *token = process == PROCESS_HANDLE ? &fakeChildToken : &currentToken;
    ++openedTokens;
    return TRUE;
}
static BOOL WINAPI FakeGetTokenInformation(HANDLE handle, TOKEN_INFORMATION_CLASS kind, LPVOID out, DWORD capacity, PDWORD length)
{
    FakeToken* token = (FakeToken*)handle;
    DWORD size = sizeof(DWORD);
    if ((DWORD)kind == infoFailure) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    if (kind == TokenUser) { size = sizeof(TOKEN_USER); }
    if (kind == TokenIntegrityLevel) { size = sizeof(TOKEN_MANDATORY_LABEL); }
    if (kind == TokenGroups) { size = sizeof(TOKEN_GROUPS); }
    *length = size;
    if (out == NULL || capacity < size) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    ZeroMemory(out, size);
    switch (kind)
    {
    case TokenType: *(TOKEN_TYPE*)out = TokenPrimary; break;
    case TokenUser: ((PTOKEN_USER)out)->User.Sid = token->sid; break;
    case TokenIntegrityLevel: ((PTOKEN_MANDATORY_LABEL)out)->Label.Sid = token->label; break;
    case TokenSessionId: *(PDWORD)out = token->session; break;
    case TokenElevation: ((TOKEN_ELEVATION*)out)->TokenIsElevated = token->elevated; break;
    case TokenElevationType: *(TOKEN_ELEVATION_TYPE*)out = token->elevationType; break;
    case TokenIsAppContainer: *(PDWORD)out = token->appContainer; break;
    case TokenGroups:
        ((PTOKEN_GROUPS)out)->GroupCount = 1;
        ((PTOKEN_GROUPS)out)->Groups[0].Sid = token->adminSid;
        ((PTOKEN_GROUPS)out)->Groups[0].Attributes = token->admin ? SE_GROUP_ENABLED : SE_GROUP_USE_FOR_DENY_ONLY;
        break;
    default: SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    return TRUE;
}
static BOOL WINAPI FakeDuplicateTokenEx(HANDLE source, DWORD access, LPSECURITY_ATTRIBUTES attributes,
    SECURITY_IMPERSONATION_LEVEL level, TOKEN_TYPE type, PHANDLE output)
{
    (void)access; (void)attributes; (void)level; (void)type;
    ++duplicateCalls;
    if (duplicateFailure) { SetLastError(duplicateFailure); return FALSE; }
    duplicateToken = *(FakeToken*)source;
    if (corruptDuplicate) { ++duplicateToken.session; }
    *output = &duplicateToken;
    ++openedTokens;
    return TRUE;
}
static BOOL WINAPI FakeSetTokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS kind, LPVOID value, DWORD length)
{
    (void)kind; (void)length; ++setCalls;
    if (setFailure) { SetLastError(setFailure); return FALSE; }
    ((FakeToken*)token)->session = *(PDWORD)value;
    return TRUE;
}
static BOOL WINAPI FakeWTSQueryUserToken(ULONG session, PHANDLE token)
{
    (void)session; ++wtsCalls;
    if (wtsFailure) { SetLastError(wtsFailure); return FALSE; }
    *token = &sessionToken; ++openedTokens; return TRUE;
}
static BOOL WINAPI FakeIsTokenRestricted(HANDLE token) { return ((FakeToken*)token)->restricted; }
static BOOL WINAPI FakeCloseHandle(HANDLE handle)
{
    if (handle == PROCESS_HANDLE) { ++processClosed; }
    else if (handle == THREAD_HANDLE) { ++threadClosed; }
    else { --openedTokens; }
    return TRUE;
}
static DWORD WINAPI FakeResumeThread(HANDLE thread)
{
    (void)thread;
    if (resumeFailure) { SetLastError(resumeFailure); return MAXDWORD; }
    ++resumed; return 1;
}
static BOOL WINAPI FakeTerminateProcess(HANDLE process, UINT error)
{
    (void)process; (void)error; ++terminated;
    if (terminateFailure) { SetLastError(terminateFailure); return FALSE; }
    return TRUE;
}
static DWORD WINAPI FakeWaitForSingleObject(HANDLE handle, DWORD timeout)
{
    (void)handle; (void)timeout; ++waited;
    if (waitFailure) { SetLastError(waitFailure); return WAIT_FAILED; }
    return WAIT_OBJECT_0;
}

#define OpenProcessToken FakeOpenProcessToken
#define GetTokenInformation FakeGetTokenInformation
#define DuplicateTokenEx FakeDuplicateTokenEx
#define SetTokenInformation FakeSetTokenInformation
#define WTSQueryUserToken FakeWTSQueryUserToken
#define IsTokenRestricted FakeIsTokenRestricted
#define CloseHandle FakeCloseHandle
#define ResumeThread FakeResumeThread
#define TerminateProcess FakeTerminateProcess
#define WaitForSingleObject FakeWaitForSingleObject
#define MESH_PROCESS_TOKEN_LOG(message) ((void)(message))
#include "process_token_contract.h"

static void check(BOOL condition, const char* name)
{
    ++checks;
    if (!condition) { fprintf(stderr, "FAIL %s error=%lu\n", name, GetLastError()); exit(1); }
    printf("PASS %s\n", name);
}
static void initToken(FakeToken* token, BOOL system, DWORD integrity, BOOL elevated)
{
    DWORD size = SECURITY_MAX_SID_SIZE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    ZeroMemory(token, sizeof(*token));
    CreateWellKnownSid(system ? WinLocalSystemSid : WinWorldSid, NULL, token->sid, &size);
    size = SECURITY_MAX_SID_SIZE;
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, token->adminSid, &size);
    InitializeSid(token->label, &authority, 1);
    *GetSidSubAuthority(token->label, 0) = integrity;
    token->integrity = integrity; token->elevated = elevated; token->admin = elevated;
    token->session = system ? 0 : 3;
    token->elevationType = elevated ? TokenElevationTypeFull : TokenElevationTypeLimited;
}
static void reset(void)
{
    check(openedTokens == 0, "previous scenario released all tokens");
    initToken(&currentToken, TRUE, SECURITY_MANDATORY_SYSTEM_RID, TRUE);
    initToken(&sessionToken, FALSE, SECURITY_MANDATORY_MEDIUM_RID, FALSE);
    infoFailure = setFailure = duplicateFailure = wtsFailure = resumeFailure = terminateFailure = waitFailure = 0;
    childOpenFailure = corruptDuplicate = FALSE;
    wtsCalls = duplicateCalls = setCalls = resumed = terminated = waited = processClosed = threadClosed = 0;
}
static void rejectOpen(MeshProcessTokenMode mode, DWORD session, DWORD expected, const char* name)
{
    HANDLE token = (HANDLE)(ULONG_PTR)1;
    BOOL ok = MeshProcessToken_Open(mode, session, &token);
    DWORD error = GetLastError();
    check(!ok && token == NULL && error == expected && openedTokens == 0, name);
}
static void verifyChild(BOOL allow, const char* name)
{
    PROCESS_INFORMATION process = {0};
    process.hProcess = PROCESS_HANDLE; process.hThread = THREAD_HANDLE; process.dwProcessId = 42;
    check(MeshProcessToken_VerifyChildAndResume(MeshProcessToken_Privileged, &duplicateToken, &process) == allow, name);
    check(allow ? (resumed == 1 && terminated == 0 && processClosed == 0) :
        (resumed == 0 && terminated == 1 && processClosed == 1 && threadClosed == 1 && process.hProcess == NULL),
        "child resumes only after verification; rejected child terminated and closed");
}
int main(void)
{
    HANDLE token;
    reset();
    check(MeshProcessToken_Open(MeshProcessToken_Privileged, MAXDWORD, &token), "SYSTEM accepted");
    check(setCalls == 0 && wtsCalls == 0, "current privilege does not borrow WTS token or change session");
    CloseHandle(token);
    reset(); initToken(&currentToken, FALSE, SECURITY_MANDATORY_HIGH_RID, TRUE);
    check(MeshProcessToken_Open(MeshProcessToken_Privileged, MAXDWORD, &token), "already elevated admin accepted"); CloseHandle(token);
    reset(); initToken(&currentToken, FALSE, SECURITY_MANDATORY_MEDIUM_RID, FALSE);
    rejectOpen(MeshProcessToken_Privileged, MAXDWORD, ERROR_ELEVATION_REQUIRED, "filtered admin denied without linked-token activation");
    check(duplicateCalls == 0 && wtsCalls == 0, "medium rejection precedes duplication and WTS calls");
    currentToken.elevationType = TokenElevationTypeDefault;
    rejectOpen(MeshProcessToken_Privileged, MAXDWORD, ERROR_ELEVATION_REQUIRED, "standard user denied");
    reset(); currentToken.restricted = TRUE;
    rejectOpen(MeshProcessToken_Privileged, MAXDWORD, ERROR_ELEVATION_REQUIRED, "restricted SYSTEM denied");
    reset(); currentToken.appContainer = TRUE;
    rejectOpen(MeshProcessToken_Privileged, MAXDWORD, ERROR_ELEVATION_REQUIRED, "AppContainer denied");
    reset(); infoFailure = TokenIntegrityLevel;
    rejectOpen(MeshProcessToken_Privileged, MAXDWORD, ERROR_ACCESS_DENIED, "token query failure fails closed");
    reset(); duplicateFailure = ERROR_ACCESS_DENIED;
    rejectOpen(MeshProcessToken_Privileged, MAXDWORD, ERROR_ACCESS_DENIED, "duplication failure releases source");
    reset(); setFailure = ERROR_PRIVILEGE_NOT_HELD;
    rejectOpen(MeshProcessToken_Privileged, 3, ERROR_PRIVILEGE_NOT_HELD, "session adjustment failure has no fallback");
    reset(); corruptDuplicate = TRUE;
    rejectOpen(MeshProcessToken_Privileged, MAXDWORD, ERROR_ACCESS_DENIED, "duplicate session drift rejected");
    reset();
    check(MeshProcessToken_Open(MeshProcessToken_SessionUser, 3, &token), "session user accepted from WTS");
    check(wtsCalls == 1 && !duplicateToken.elevated && setCalls == 0, "SYSTEM host preserves medium WTS identity"); CloseHandle(token);
    reset(); wtsFailure = ERROR_NO_TOKEN;
    rejectOpen(MeshProcessToken_SessionUser, 3, ERROR_NO_TOKEN, "missing WTS token never falls back to SYSTEM");
    check(duplicateCalls == 0, "no duplication after WTS failure");
    reset(); sessionToken = currentToken; sessionToken.session = 3;
    rejectOpen(MeshProcessToken_SessionUser, 3, ERROR_ACCESS_DENIED, "SYSTEM token rejected for user mode");
    reset();
    rejectOpen(MeshProcessToken_SessionUser, 4, ERROR_ACCESS_DENIED, "WTS session mismatch rejected");
    rejectOpen(MeshProcessToken_SessionUser, MAXDWORD, ERROR_INVALID_PARAMETER, "user mode requires session");
    rejectOpen((MeshProcessTokenMode)9, 3, ERROR_INVALID_PARAMETER, "unknown mode denied");
    reset(); duplicateToken = currentToken; fakeChildToken = duplicateToken;
    verifyChild(TRUE, "matching child accepted");
    reset(); duplicateToken = currentToken; fakeChildToken = duplicateToken; fakeChildToken.session = 3;
    verifyChild(FALSE, "wrong-session child rejected before resume");
    reset(); duplicateToken = currentToken; initToken(&fakeChildToken, FALSE, SECURITY_MANDATORY_MEDIUM_RID, FALSE);
    verifyChild(FALSE, "medium child rejected before resume");
    reset(); duplicateToken = currentToken; fakeChildToken = duplicateToken; childOpenFailure = TRUE;
    verifyChild(FALSE, "uninspectable child rejected before resume");
    reset(); duplicateToken = currentToken; fakeChildToken = duplicateToken; resumeFailure = ERROR_ACCESS_DENIED;
    verifyChild(FALSE, "resume failure terminates suspended child");
    reset(); duplicateToken = currentToken; fakeChildToken = duplicateToken; fakeChildToken.session = 3; terminateFailure = ERROR_NOT_ENOUGH_MEMORY;
    verifyChild(FALSE, "termination failure is reported without resuming rejected child");
    check(waited == 0 && GetLastError() == ERROR_ACCESS_DENIED, "termination failure skips wait and preserves rejection error");
    reset(); duplicateToken = currentToken; fakeChildToken = duplicateToken; fakeChildToken.session = 3; waitFailure = ERROR_INVALID_HANDLE;
    verifyChild(FALSE, "termination wait failure still closes rejected child");
    check(waited == 1 && GetLastError() == ERROR_ACCESS_DENIED, "wait failure preserves rejection error");
    check(openedTokens == 0, "final token handles released");
    printf("checks=%u failures=0\n", checks);
    return 0;
}
