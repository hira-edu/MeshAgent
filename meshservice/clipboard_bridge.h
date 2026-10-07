#ifndef MESH_CLIPBOARD_BRIDGE_H
#define MESH_CLIPBOARD_BRIDGE_H

// Included by runtime_host_contract.c. Wire format: three little-endian DWORDs
// (request ID, operation/status, UTF-8 byte count), followed by at most 1 MiB.
// Operation 1 reads, 2 writes; status is a Win32 error. No clipboard data is logged.
#define MESH_CLIPBOARD_MAX_BYTES (1024UL * 1024UL)
#define MESH_CLIPBOARD_IO_MS 15000UL
// The agent closes idle helpers after 60 seconds; this is only the orphan bound
// and must stay well above it so a request never races the helper's own exit.
#define MESH_CLIPBOARD_IDLE_MS 120000UL

typedef struct MeshClipboardFrame { DWORD id, code, length; } MeshClipboardFrame;

static DWORD MeshClipboard_Io(HANDLE pipe, BOOL write, void* data, DWORD length, BOOL overlapped, DWORD timeout)
{
    BYTE* cursor = (BYTE*)data;
    ULONGLONG deadline = GetTickCount64() + timeout;
    while (length != 0)
    {
        DWORD count = 0, error = ERROR_SUCCESS;
        OVERLAPPED ov = {0};
        BOOL ok;
        if (overlapped)
        {
            ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (ov.hEvent == NULL) { return GetLastError(); }
        }
        ok = write ? WriteFile(pipe, cursor, length, &count, overlapped ? &ov : NULL) :
            ReadFile(pipe, cursor, length, &count, overlapped ? &ov : NULL);
        if (!ok && overlapped && GetLastError() == ERROR_IO_PENDING)
        {
            ULONGLONG now = GetTickCount64();
            DWORD wait = WaitForSingleObject(ov.hEvent, now < deadline ? (DWORD)(deadline - now) : 0);
            if (wait != WAIT_OBJECT_0)
            {
                error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
                CancelIoEx(pipe, &ov);
                // The OVERLAPPED storage must outlive cancellation completion.
                GetOverlappedResult(pipe, &ov, &count, TRUE);
            }
            else if (!GetOverlappedResult(pipe, &ov, &count, FALSE)) { error = GetLastError(); }
        }
        else if (!ok) { error = GetLastError(); }
        if (ov.hEvent != NULL) { CloseHandle(ov.hEvent); }
        if (error != ERROR_SUCCESS) { return error; }
        if (count == 0) { return ERROR_BROKEN_PIPE; }
        if (count > length) { return ERROR_INVALID_DATA; }
        cursor += count;
        length -= count;
        if (length != 0 && GetTickCount64() >= deadline) { return ERROR_TIMEOUT; }
    }
    return ERROR_SUCCESS;
}

static DWORD MeshClipboard_Text(DWORD operation, char** text, DWORD* bytes)
{
    HGLOBAL memory = NULL;
    HWND owner = NULL;
    MSG message;
    wchar_t* wide = NULL;
    DWORD error = ERROR_SUCCESS;
    BOOL opened = FALSE, locked = FALSE;
    unsigned attempt;
    int chars = 0, encoded;
    SIZE_T size, length, limit;
    if (operation != 1 && operation != 2) { return ERROR_INVALID_FUNCTION; }
    // Prepare and validate a write before emptying the user's clipboard.
    if (operation == 2)
    {
        if (*bytes > MESH_CLIPBOARD_MAX_BYTES || (*bytes != 0 && memchr(*text, 0, *bytes) != NULL)) { return ERROR_INVALID_DATA; }
        if (*bytes != 0)
        {
            chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, *text, (int)*bytes, NULL, 0);
            if (chars == 0) { return GetLastError(); }
        }
        memory = GlobalAlloc(GMEM_MOVEABLE, ((SIZE_T)chars + 1) * sizeof(wchar_t));
        if (memory == NULL) { return ERROR_NOT_ENOUGH_MEMORY; }
        wide = (wchar_t*)GlobalLock(memory);
        if (wide == NULL) { error = GetLastError(); if (!error) { error = ERROR_INVALID_DATA; } goto cleanup; }
        locked = TRUE;
        if (chars != 0 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, *text, (int)*bytes, wide, chars) != chars)
        { error = GetLastError(); goto cleanup; }
        wide[chars] = 0;
        GlobalUnlock(memory); locked = FALSE;
        // SetClipboardData needs an owner. A message-only window receives no broadcasts,
        // and destroying it after the write releases ownership while Windows keeps the
        // data, so an idle helper never holds a window that other applications wait on.
        owner = CreateWindowExW(0, L"STATIC", NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandleW(NULL), NULL);
        if (owner == NULL) { error = GetLastError(); if (error == ERROR_SUCCESS) { error = ERROR_INVALID_WINDOW_HANDLE; } goto cleanup; }
    }
    for (attempt = 0; attempt < 5; ++attempt)
    {
        if (OpenClipboard(owner)) { opened = TRUE; break; }
        error = GetLastError();
        Sleep(20);
    }
    if (!opened) { if (error == ERROR_SUCCESS) { error = ERROR_ACCESS_DENIED; } goto cleanup; }
    error = ERROR_SUCCESS;
    if (operation == 2)
    {
        if (!EmptyClipboard() || SetClipboardData(CF_UNICODETEXT, memory) == NULL)
        { error = GetLastError(); if (error == ERROR_SUCCESS) { error = ERROR_ACCESS_DENIED; } goto cleanup; }
        memory = NULL; // Windows owns the allocation only after SetClipboardData succeeds.
        *bytes = 0;
    }
    else
    {
        *bytes = 0;
        *text = NULL;
        // An empty clipboard or non-text content is a successful empty text read.
        if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) { goto cleanup; }
        memory = (HGLOBAL)GetClipboardData(CF_UNICODETEXT);
        if (memory == NULL) { error = GetLastError(); if (!error) { error = ERROR_INVALID_DATA; } goto cleanup; }
        size = GlobalSize(memory);
        if (size < sizeof(wchar_t)) { error = ERROR_INVALID_DATA; goto cleanup; }
        wide = (wchar_t*)GlobalLock(memory);
        if (wide == NULL) { error = GetLastError(); if (!error) { error = ERROR_INVALID_DATA; } goto cleanup; }
        locked = TRUE;
        // Applications may over-allocate, so bound the scan rather than the block. More
        // than MAX_BYTES UTF-16 units always encodes to more than MAX_BYTES of UTF-8.
        limit = size / sizeof(wchar_t);
        if (limit > MESH_CLIPBOARD_MAX_BYTES + 1) { limit = MESH_CLIPBOARD_MAX_BYTES + 1; }
        for (length = 0; length < limit && wide[length] != 0; ++length) { }
        if (length == limit)
        { error = limit == size / sizeof(wchar_t) ? ERROR_INVALID_DATA : ERROR_BUFFER_OVERFLOW; goto cleanup; }
        if (length == 0) { goto cleanup; }
        encoded = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)length, NULL, 0, NULL, NULL);
        if (encoded == 0) { error = GetLastError(); goto cleanup; }
        if ((DWORD)encoded > MESH_CLIPBOARD_MAX_BYTES) { error = ERROR_BUFFER_OVERFLOW; goto cleanup; }
        *text = (char*)malloc((size_t)encoded);
        if (*text == NULL) { error = ERROR_NOT_ENOUGH_MEMORY; goto cleanup; }
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)length, *text, encoded, NULL, NULL) != encoded)
        { error = GetLastError(); free(*text); *text = NULL; goto cleanup; }
        *bytes = (DWORD)encoded;
    }
cleanup:
    if (locked) { GlobalUnlock(memory); }
    if (opened) { CloseClipboard(); }
    if (owner != NULL)
    {
        // Answer anything sent while the window owned the clipboard before releasing it.
        while (PeekMessageW(&message, owner, 0, 0, PM_REMOVE)) { DispatchMessageW(&message); }
        DestroyWindow(owner);
    }
    if (operation == 2 && memory != NULL) { GlobalFree(memory); }
    return error;
}

static DWORD MeshClipboard_Serve(HANDLE input, HANDLE output, BOOL overlapped)
{
    DWORD error;
    for (;;)
    {
        MeshClipboardFrame frame;
        char* text = NULL;
        error = MeshClipboard_Io(input, FALSE, &frame, sizeof(frame), overlapped, MESH_CLIPBOARD_IDLE_MS);
        if (error != ERROR_SUCCESS) { break; }
        if (frame.id == 0 || frame.length > MESH_CLIPBOARD_MAX_BYTES ||
            (frame.code != 1 && frame.code != 2) || (frame.code == 1 && frame.length != 0))
        { error = ERROR_INVALID_DATA; break; }
        if (frame.length != 0)
        {
            text = (char*)malloc(frame.length);
            if (text == NULL) { error = ERROR_NOT_ENOUGH_MEMORY; break; }
            error = MeshClipboard_Io(input, FALSE, text, frame.length, overlapped, MESH_CLIPBOARD_IO_MS);
            if (error != ERROR_SUCCESS) { free(text); break; }
        }
        frame.code = MeshClipboard_Text(frame.code, &text, &frame.length);
        if (frame.code != ERROR_SUCCESS) { frame.length = 0; }
        error = MeshClipboard_Io(output, TRUE, &frame, sizeof(frame), overlapped, MESH_CLIPBOARD_IO_MS);
        if (error == ERROR_SUCCESS && frame.length != 0)
        { error = MeshClipboard_Io(output, TRUE, text, frame.length, overlapped, MESH_CLIPBOARD_IO_MS); }
        free(text);
        if (error != ERROR_SUCCESS) { break; }
    }
    return error;
}

static DWORD MeshClipboard_User(const wchar_t* pipeName, DWORD brokerPid, DWORD sessionId)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    ULONG serverPid = 0;
    DWORD actualSession = 0, error = ERROR_ACCESS_DENIED;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &actualSession) || actualSession != sessionId || sessionId == 0) { return error; }
    if (!WaitNamedPipeW(pipeName, MESH_CLIPBOARD_IO_MS)) { return GetLastError(); }
    pipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE) { return GetLastError(); }
    if (!GetNamedPipeServerProcessId(pipe, &serverPid) || serverPid != brokerPid) { goto cleanup; }
    error = MeshClipboard_Serve(pipe, pipe, TRUE);
cleanup:
    CloseHandle(pipe);
    return error;
}

// A session ID can be reused after logoff. Bind every request to the original
// logon AuthenticationId so a persistent broker never crosses that boundary.
static BOOL MeshClipboard_SessionMatches(HANDLE selected, DWORD sessionId)
{
    HANDLE current = NULL;
    TOKEN_STATISTICS expected, actual;
    DWORD length = 0;
    BOOL ok = FALSE;
    if (!WTSQueryUserToken(sessionId, &current)) { return FALSE; }
    if (GetTokenInformation(selected, TokenStatistics, &expected, sizeof(expected), &length) &&
        GetTokenInformation(current, TokenStatistics, &actual, sizeof(actual), &length))
    {
        ok = expected.AuthenticationId.LowPart == actual.AuthenticationId.LowPart &&
            expected.AuthenticationId.HighPart == actual.AuthenticationId.HighPart;
    }
    CloseHandle(current);
    if (!ok) { SetLastError(ERROR_ACCESS_DENIED); }
    return ok;
}

static DWORD MeshClipboard_Broker(DWORD sessionId, HINSTANCE module)
{
    HANDLE token = NULL, pipe = INVALID_HANDLE_VALUE, job = NULL;
    PROCESS_INFORMATION child = {0};
    STARTUPINFOW startup = {0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    MeshProcessTokenSnapshot snapshot;
    LPWSTR sid = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, FALSE};
    wchar_t pipeName[128], sddl[256], host[MAX_PATH], dll[MAX_PATH * 4], command[4096];
    DWORD error = ERROR_ACCESS_DENIED;
    OVERLAPPED connect = {0};
    ULONG clientPid = 0;
    BOOL connected;
    char* text = NULL;
    if (!MeshProcessToken_Open(MeshProcessToken_SessionUser, sessionId, &token) ||
        !MeshProcessToken_Read(token, &snapshot) || !ConvertSidToStringSidW((PSID)snapshot.sid, &sid))
    { error = GetLastError(); goto cleanup; }
    swprintf_s(pipeName, _countof(pipeName), L"\\\\.\\pipe\\MeshClipboard_%lu", GetCurrentProcessId());
    swprintf_s(sddl, _countof(sddl), L"D:P(A;;GA;;;SY)(A;;GA;;;%ls)", sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL))
    { error = GetLastError(); goto cleanup; }
    attributes.lpSecurityDescriptor = descriptor;
    pipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1, 8192, 8192, 0, &attributes);
    if (pipe == INVALID_HANDLE_VALUE) { error = GetLastError(); goto cleanup; }
    job = CreateJobObjectW(NULL, NULL);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job == NULL || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    { error = GetLastError(); goto cleanup; }
    if (!MeshRuntimeHost_GetSystemHostPathW(host, _countof(host)) ||
        GetModuleFileNameW(module, dll, _countof(dll)) == 0 || wcslen(dll) >= _countof(dll) - 1)
    { error = ERROR_INVALID_NAME; goto cleanup; }
    if (FAILED(StringCchPrintfW(command, _countof(command), L"\"%ls\" \"%ls\",MeshClipboardBridgeW user %ls %lu %lu",
        host, dll, pipeName, GetCurrentProcessId(), sessionId))) { error = ERROR_BUFFER_OVERFLOW; goto cleanup; }
    startup.cb = sizeof(startup);
    startup.lpDesktop = L"winsta0\\default";
    if (!CreateProcessAsUserW(token, host, command, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child))
    { error = GetLastError(); goto cleanup; }
    if (!AssignProcessToJobObject(job, child.hProcess)) { error = GetLastError(); goto cleanup; }
    if (!MeshProcessToken_VerifyChildAndResume(MeshProcessToken_SessionUser, token, &child))
    { error = GetLastError(); goto cleanup; }
    connect.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (connect.hEvent == NULL) { error = GetLastError(); goto cleanup; }
    connected = ConnectNamedPipe(pipe, &connect);
    if (!connected)
    {
        error = GetLastError();
        if (error == ERROR_IO_PENDING)
        {
            HANDLE waits[2] = {connect.hEvent, child.hProcess};
            DWORD wait = WaitForMultipleObjects(2, waits, FALSE, MESH_CLIPBOARD_IO_MS), count;
            if (wait != WAIT_OBJECT_0)
            {
                error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_BROKEN_PIPE;
                CancelIoEx(pipe, &connect); GetOverlappedResult(pipe, &connect, &count, TRUE);
                goto cleanup;
            }
            if (!GetOverlappedResult(pipe, &connect, &count, FALSE)) { error = GetLastError(); goto cleanup; }
        }
        else if (error != ERROR_PIPE_CONNECTED) { goto cleanup; }
    }
    if (!GetNamedPipeClientProcessId(pipe, &clientPid) || clientPid != child.dwProcessId) { error = ERROR_ACCESS_DENIED; goto cleanup; }
    // One relay buffer for the broker's lifetime; every frame length is bounded by it.
    text = (char*)malloc(MESH_CLIPBOARD_MAX_BYTES);
    if (text == NULL) { error = ERROR_NOT_ENOUGH_MEMORY; goto cleanup; }
    for (;;)
    {
        MeshClipboardFrame request, response;
        // Blocking read: the agent bounds idle time by terminating this broker.
        error = MeshClipboard_Io(GetStdHandle(STD_INPUT_HANDLE), FALSE, &request, sizeof(request), FALSE, MESH_CLIPBOARD_IDLE_MS);
        if (error != ERROR_SUCCESS) { break; }
        if (request.id == 0 || request.length > MESH_CLIPBOARD_MAX_BYTES ||
            (request.code != 1 && request.code != 2) || (request.code == 1 && request.length != 0))
        { error = ERROR_INVALID_DATA; break; }
        if (!MeshClipboard_SessionMatches(token, sessionId)) { error = ERROR_ACCESS_DENIED; break; }
        error = MeshClipboard_Io(GetStdHandle(STD_INPUT_HANDLE), FALSE, text, request.length, FALSE, MESH_CLIPBOARD_IO_MS);
        if (error == ERROR_SUCCESS) { error = MeshClipboard_Io(pipe, TRUE, &request, sizeof(request), TRUE, MESH_CLIPBOARD_IO_MS); }
        if (error == ERROR_SUCCESS) { error = MeshClipboard_Io(pipe, TRUE, text, request.length, TRUE, MESH_CLIPBOARD_IO_MS); }
        if (error == ERROR_SUCCESS) { error = MeshClipboard_Io(pipe, FALSE, &response, sizeof(response), TRUE, MESH_CLIPBOARD_IO_MS); }
        if (error == ERROR_SUCCESS && (response.id != request.id || response.length > MESH_CLIPBOARD_MAX_BYTES ||
            (response.code != 0 && response.length != 0) || (request.code == 2 && response.length != 0))) { error = ERROR_INVALID_DATA; }
        if (error == ERROR_SUCCESS) { error = MeshClipboard_Io(pipe, FALSE, text, response.length, TRUE, MESH_CLIPBOARD_IO_MS); }
        if (error == ERROR_SUCCESS) { error = MeshClipboard_Io(GetStdHandle(STD_OUTPUT_HANDLE), TRUE, &response, sizeof(response), FALSE, MESH_CLIPBOARD_IO_MS); }
        if (error == ERROR_SUCCESS) { error = MeshClipboard_Io(GetStdHandle(STD_OUTPUT_HANDLE), TRUE, text, response.length, FALSE, MESH_CLIPBOARD_IO_MS); }
        if (error != ERROR_SUCCESS) { break; }
    }
cleanup:
    // Orderly exits stop the session helper here. If the agent terminates this broker
    // instead, closing the kill-on-close job handle stops the helper.
    if (child.hProcess != NULL)
    {
        if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) { TerminateProcess(child.hProcess, error); }
        WaitForSingleObject(child.hProcess, 5000);
        CloseHandle(child.hProcess);
    }
    if (child.hThread != NULL) { CloseHandle(child.hThread); }
    if (job != NULL) { CloseHandle(job); }
    if (connect.hEvent != NULL) { CloseHandle(connect.hEvent); }
    if (pipe != INVALID_HANDLE_VALUE) { CloseHandle(pipe); }
    if (descriptor != NULL) { LocalFree(descriptor); }
    if (sid != NULL) { LocalFree(sid); }
    if (token != NULL) { CloseHandle(token); }
    free(text);
    return error;
}

static DWORD MeshClipboard_Run(const wchar_t* tail, HINSTANCE module)
{
    const wchar_t* cursor = tail;
    wchar_t mode[32], pipe[128], pidText[16], sessionText[16], extra[2];
    DWORD session, pid;
    if (!MeshRuntimeHost_CopyNextTokenW(&cursor, mode, _countof(mode))) { return ERROR_INVALID_PARAMETER; }
    if (wcscmp(mode, L"local") == 0 || wcsncmp(mode, L"tsid=", 5) == 0)
    {
        if (MeshRuntimeHost_CopyNextTokenW(&cursor, extra, _countof(extra)) || GetLastError() != ERROR_NO_MORE_ITEMS)
        { return ERROR_INVALID_PARAMETER; }
        if (wcscmp(mode, L"local") == 0)
        {
            if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || session == 0) { return ERROR_ACCESS_DENIED; }
            return MeshClipboard_Serve(GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE), FALSE);
        }
        if (!MeshConsoleBridge_ParseUnsignedTokenW(mode + 5, 1, 0xFFFFFFFEUL, &session)) { return ERROR_INVALID_PARAMETER; }
        return MeshClipboard_Broker(session, module);
    }
    if (wcscmp(mode, L"user") != 0 ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, pipe, _countof(pipe)) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, pidText, _countof(pidText)) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, sessionText, _countof(sessionText)) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(pidText, 1, 0xFFFFFFFEUL, &pid) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(sessionText, 1, 0xFFFFFFFEUL, &session)) { return ERROR_INVALID_PARAMETER; }
    swprintf_s(mode, _countof(mode), L"%lu", pid);
    {
        wchar_t expected[128];
        swprintf_s(expected, _countof(expected), L"\\\\.\\pipe\\MeshClipboard_%ls", mode);
        if (wcscmp(pipe, expected) != 0 || MeshRuntimeHost_CopyNextTokenW(&cursor, extra, _countof(extra)) ||
            GetLastError() != ERROR_NO_MORE_ITEMS) { return ERROR_INVALID_PARAMETER; }
    }
    return MeshClipboard_User(pipe, pid, session);
}
#endif
