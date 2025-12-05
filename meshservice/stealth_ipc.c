/*
 * Stealth IPC Module - Implementation
 *
 * Named pipe IPC for SecureEnter/SecureExit commands and inter-process
 * communication between service and client components.
 *
 * Ported from:
 * - goodtrailer/win-pipe (MIT) - Single-file C++ named pipes
 * - blewert/win32-simple-named-pipe-client (MIT) - Header-only pipe client
 * - microsoft/IPC (MIT) - Microsoft's IPC patterns
 */

#include "stealth_ipc.h"
#include <sddl.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

/* Magic number for message validation */
#define IPC_MAGIC 0x4D455348  /* 'MESH' */
#define IPC_VERSION 1
#define IPC_BUFFER_SIZE 8192
#define IPC_PIPE_PREFIX L"\\\\.\\pipe\\MeshAgent_"
#define IPC_MAX_PAYLOAD_SIZE (1024 * 1024)  /* 1MB max payload */
#define IPC_CONNECT_POLL_MS 1000            /* Connection poll interval */

/* Internal server thread */
static DWORD WINAPI IpcServerThread(LPVOID param);

/* ================================================================
 * Server Functions
 * ================================================================ */

BOOL Ipc_ServerCreate(
    IpcServer* server,
    const WCHAR* pipeName,
    void (*onMessage)(IpcServer*, const IpcMessageHeader*, const void*),
    void* userData)
{
    if (server == NULL || pipeName == NULL) {
        return FALSE;
    }

    ZeroMemory(server, sizeof(IpcServer));
    StringCchCopyW(server->pipeName, 256, pipeName);
    server->onMessage = onMessage;
    server->userData = userData;
    server->hPipe = INVALID_HANDLE_VALUE;
    server->hThread = NULL;
    return Ipc_ServerStart(server);
}

void Ipc_ServerDestroy(IpcServer* server)
{
    if (server == NULL) {
        return;
    }

    Ipc_ServerStop(server);
    ZeroMemory(server, sizeof(IpcServer));
}

BOOL Ipc_ServerStart(IpcServer* server)
{
    if (server == NULL) {
        return FALSE;
    }

    if (server->running) {
        return TRUE;
    }

    /* Create security descriptor for pipe
     * SYSTEM: Full access (GA)
     * Administrators: Full access (GA)
     * Authenticated Users: Read/Write for IPC communication (GRGW)
     * Removed world-read (WD) to prevent information disclosure */
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",
            SDDL_REVISION_1, &pSD, NULL)) {
        return FALSE;
    }

    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    server->hPipe = CreateNamedPipeW(
        server->pipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        IPC_BUFFER_SIZE,
        IPC_BUFFER_SIZE,
        0,
        &sa);

    LocalFree(pSD);

    if (server->hPipe == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    server->running = TRUE;
    server->hThread = CreateThread(NULL, 0, IpcServerThread, server, 0, NULL);
    if (server->hThread == NULL) {
        server->running = FALSE;
        CloseHandle(server->hPipe);
        server->hPipe = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

void Ipc_ServerStop(IpcServer* server)
{
    if (server == NULL) {
        return;
    }

    if (!server->running) {
        return;
    }

    server->running = FALSE;

    if (server->hPipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(server->hPipe, NULL);
        DisconnectNamedPipe(server->hPipe);
        CloseHandle(server->hPipe);
        server->hPipe = INVALID_HANDLE_VALUE;
    }

    if (server->hThread != NULL) {
        WaitForSingleObject(server->hThread, 3000);
        CloseHandle(server->hThread);
        server->hThread = NULL;
    }
}

BOOL Ipc_ServerSend(
    IpcServer* server,
    IpcMessageType type,
    const void* payload,
    DWORD payloadSize)
{
    if (server == NULL || server->hPipe == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    /* Build message */
    IpcMessageHeader header;
    header.magic = IPC_MAGIC;
    header.version = IPC_VERSION;
    header.type = (DWORD)type;
    header.payloadSize = payloadSize;
    header.sequence = GetTickCount();
    header.timestamp = GetTickCount();

    /* Write header */
    DWORD written = 0;
    if (!WriteFile(server->hPipe, &header, sizeof(header), &written, NULL) ||
        written != sizeof(header)) {
        return FALSE;
    }

    /* Write payload if present */
    if (payload != NULL && payloadSize > 0) {
        if (!WriteFile(server->hPipe, payload, payloadSize, &written, NULL) ||
            written != payloadSize) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL Ipc_ServerBroadcast(
    IpcServer* server,
    IpcMessageType type,
    const void* payload,
    DWORD payloadSize)
{
    /* For single-instance server, just send */
    return Ipc_ServerSend(server, type, payload, payloadSize);
}

/* ================================================================
 * Client Functions
 * ================================================================ */

BOOL Ipc_ClientConnect(
    IpcClient* client,
    const WCHAR* pipeName,
    DWORD timeoutMs)
{
    if (client == NULL || pipeName == NULL) {
        return FALSE;
    }

    ZeroMemory(client, sizeof(IpcClient));
    StringCchCopyW(client->pipeName, 256, pipeName);
    client->timeoutMs = timeoutMs;

    /* Wait for pipe to become available */
    if (!WaitNamedPipeW(pipeName, timeoutMs)) {
        return FALSE;
    }

    /* Open pipe */
    client->hPipe = CreateFileW(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (client->hPipe == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    /* Set pipe to message mode */
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(client->hPipe, &mode, NULL, NULL)) {
        CloseHandle(client->hPipe);
        client->hPipe = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

void Ipc_ClientDisconnect(IpcClient* client)
{
    if (client == NULL) {
        return;
    }

    if (client->hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(client->hPipe);
        client->hPipe = INVALID_HANDLE_VALUE;
    }
}

BOOL Ipc_ClientSend(
    IpcClient* client,
    IpcMessageType type,
    const void* payload,
    DWORD payloadSize)
{
    if (client == NULL || client->hPipe == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    /* Build message */
    IpcMessageHeader header;
    header.magic = IPC_MAGIC;
    header.version = IPC_VERSION;
    header.type = (DWORD)type;
    header.payloadSize = payloadSize;
    header.sequence = ++client->lastSequence;
    header.timestamp = GetTickCount();

    /* Write header */
    DWORD written = 0;
    if (!WriteFile(client->hPipe, &header, sizeof(header), &written, NULL) ||
        written != sizeof(header)) {
        return FALSE;
    }

    /* Write payload if present */
    if (payload != NULL && payloadSize > 0) {
        if (!WriteFile(client->hPipe, payload, payloadSize, &written, NULL) ||
            written != payloadSize) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL Ipc_ClientReceive(
    IpcClient* client,
    IpcMessageHeader* outHeader,
    void* outPayload,
    DWORD payloadBufferSize,
    DWORD timeoutMs)
{
    if (client == NULL || client->hPipe == INVALID_HANDLE_VALUE || outHeader == NULL) {
        return FALSE;
    }

    /* For named pipes, use overlapped I/O with WaitForSingleObject for timeout.
     * Note: SetCommTimeouts only works for serial ports, not named pipes.
     * Since we opened the pipe without FILE_FLAG_OVERLAPPED, we use a simple
     * peek-based timeout approach. */
    DWORD startTime = GetTickCount();
    DWORD available = 0;

    /* Wait for data with timeout */
    while (TRUE) {
        if (!PeekNamedPipe(client->hPipe, NULL, 0, NULL, &available, NULL)) {
            return FALSE; /* Pipe error */
        }
        if (available >= sizeof(IpcMessageHeader)) {
            break; /* Data available */
        }
        if (GetTickCount() - startTime >= timeoutMs) {
            SetLastError(ERROR_TIMEOUT);
            return FALSE; /* Timeout */
        }
        Sleep(10); /* Brief sleep to avoid busy-wait */
    }

    /* Read header */
    DWORD bytesRead = 0;
    if (!ReadFile(client->hPipe, outHeader, sizeof(IpcMessageHeader), &bytesRead, NULL) ||
        bytesRead != sizeof(IpcMessageHeader)) {
        return FALSE;
    }

    /* Validate header */
    if (!Ipc_ValidateHeader(outHeader)) {
        return FALSE;
    }

    /* Read payload if present */
    if (outHeader->payloadSize > 0) {
        if (outPayload == NULL || payloadBufferSize < outHeader->payloadSize) {
            /* Skip payload */
            BYTE skipBuffer[256];
            DWORD remaining = outHeader->payloadSize;
            while (remaining > 0) {
                DWORD toRead = remaining > sizeof(skipBuffer) ? sizeof(skipBuffer) : remaining;
                if (!ReadFile(client->hPipe, skipBuffer, toRead, &bytesRead, NULL)) {
                    return FALSE;
                }
                remaining -= bytesRead;
            }
        } else {
            if (!ReadFile(client->hPipe, outPayload, outHeader->payloadSize, &bytesRead, NULL) ||
                bytesRead != outHeader->payloadSize) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

BOOL Ipc_ClientRequest(
    IpcClient* client,
    IpcMessageType requestType,
    const void* requestPayload,
    DWORD requestSize,
    IpcMessageHeader* responseHeader,
    void* responsePayload,
    DWORD responseBufferSize,
    DWORD timeoutMs)
{
    /* Send request */
    if (!Ipc_ClientSend(client, requestType, requestPayload, requestSize)) {
        return FALSE;
    }

    /* Wait for response */
    return Ipc_ClientReceive(client, responseHeader, responsePayload,
                             responseBufferSize, timeoutMs);
}

/* ================================================================
 * Utility Functions
 * ================================================================ */

void Ipc_GetDefaultPipeName(
    const WCHAR* serviceName,
    WCHAR* outPipeName,
    size_t outSize)
{
    if (serviceName == NULL || outPipeName == NULL || outSize == 0) {
        return;
    }

    StringCchPrintfW(outPipeName, outSize, L"%s%s", IPC_PIPE_PREFIX, serviceName);
}

BOOL Ipc_ValidateHeader(const IpcMessageHeader* header)
{
    if (header == NULL) {
        return FALSE;
    }

    if (header->magic != IPC_MAGIC) {
        return FALSE;
    }

    if (header->version != IPC_VERSION) {
        return FALSE;
    }

    /* Sanity check payload size */
    if (header->payloadSize > IPC_MAX_PAYLOAD_SIZE) {
        return FALSE;
    }

    return TRUE;
}

void Ipc_BuildLockdownPayload(
    IpcLockdownPayload* payload,
    BOOL shellRestrictions,
    BOOL policyEnforcement,
    BOOL networkLockdown,
    BOOL taskMonitoring)
{
    if (payload == NULL) {
        return;
    }

    ZeroMemory(payload, sizeof(IpcLockdownPayload));
    payload->enableShellRestrictions = shellRestrictions;
    payload->enablePolicyEnforcement = policyEnforcement;
    payload->enableNetworkLockdown = networkLockdown;
    payload->enableTaskMonitoring = taskMonitoring;
}

DWORD Ipc_ParseProcessList(
    const WCHAR* list,
    WCHAR** outProcesses,
    DWORD maxProcesses)
{
    if (list == NULL || outProcesses == NULL || maxProcesses == 0) {
        return 0;
    }

    DWORD count = 0;
    const WCHAR* ptr = list;

    while (*ptr != L'\0' && count < maxProcesses) {
        /* Find end of current string */
        const WCHAR* end = ptr;
        while (*end != L'\0') {
            end++;
        }

        /* Store pointer to this string */
        outProcesses[count++] = (WCHAR*)ptr;

        /* Move to next string */
        ptr = end + 1;
    }

    return count;
}

/* ================================================================
 * Internal Functions
 * ================================================================ */

static DWORD WINAPI IpcServerThread(LPVOID param)
{
    IpcServer* server = (IpcServer*)param;
    HANDLE hEvent = NULL;
    DWORD result = 0;

    if (server == NULL) {
        return 1;
    }

    BYTE buffer[IPC_BUFFER_SIZE];
    OVERLAPPED overlapped = {0};

    /* Use SEH to ensure event handle cleanup on any exit path */
    __try {
        hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (hEvent == NULL) {
            return 1;
        }
        overlapped.hEvent = hEvent;

        while (server->running) {
            /* Reset event for new connection attempt */
            ResetEvent(hEvent);

            /* Wait for client connection */
            BOOL connected = ConnectNamedPipe(server->hPipe, &overlapped);
            DWORD err = GetLastError();

            if (!connected) {
                if (err == ERROR_IO_PENDING) {
                    /* Wait for connection or shutdown with timeout */
                    DWORD waitResult = WaitForSingleObject(hEvent, IPC_CONNECT_POLL_MS);
                    if (waitResult == WAIT_TIMEOUT) {
                        /* Cancel the pending IO before continuing - fixes TOCTOU */
                        CancelIoEx(server->hPipe, &overlapped);
                        /* Wait briefly for cancellation to complete */
                        WaitForSingleObject(hEvent, 100);
                        continue;
                    }
                    if (waitResult != WAIT_OBJECT_0) {
                        break;
                    }
                    /* Get the result of the overlapped operation */
                    DWORD transferred = 0;
                    if (!GetOverlappedResult(server->hPipe, &overlapped, &transferred, FALSE)) {
                        err = GetLastError();
                        if (err == ERROR_OPERATION_ABORTED) {
                            continue; /* Cancelled, try again */
                        }
                        if (err != ERROR_PIPE_CONNECTED) {
                            Sleep(100);
                            continue;
                        }
                    }
                } else if (err != ERROR_PIPE_CONNECTED) {
                    Sleep(100);
                    continue;
                }
            }

            /* Client connected */
            if (server->onConnect != NULL) {
                server->onConnect(server);
            }

            /* Read messages */
            while (server->running) {
                DWORD bytesRead = 0;
                ZeroMemory(buffer, sizeof(buffer));

                if (!ReadFile(server->hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                    err = GetLastError();
                    if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                        break; /* Client disconnected */
                    }
                    continue;
                }

                if (bytesRead < sizeof(IpcMessageHeader)) {
                    continue;
                }

                IpcMessageHeader* header = (IpcMessageHeader*)buffer;
                if (!Ipc_ValidateHeader(header)) {
                    continue;
                }

                /* Dispatch message */
                if (server->onMessage != NULL) {
                    void* payload = NULL;
                    if (header->payloadSize > 0 &&
                        bytesRead >= sizeof(IpcMessageHeader) + header->payloadSize) {
                        payload = buffer + sizeof(IpcMessageHeader);
                    }
                    server->onMessage(server, header, payload);
                }
            }

            /* Client disconnected */
            if (server->onDisconnect != NULL) {
                server->onDisconnect(server);
            }

            DisconnectNamedPipe(server->hPipe);
        }

        result = 0;
    }
    __finally {
        /* Guaranteed cleanup of event handle */
        if (hEvent != NULL) {
            CloseHandle(hEvent);
        }
    }

    return result;
}
