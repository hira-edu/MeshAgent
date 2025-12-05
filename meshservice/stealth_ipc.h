/*
 * Stealth IPC Module
 *
 * Named pipe IPC for SecureEnter/SecureExit commands and inter-process
 * communication between service and client components.
 *
 * Ported from:
 * - goodtrailer/win-pipe (MIT) - Single-file C++ named pipes
 * - blewert/win32-simple-named-pipe-client (MIT) - Header-only pipe client
 * - microsoft/IPC (MIT) - Microsoft's IPC patterns
 */

#ifndef STEALTH_IPC_H
#define STEALTH_IPC_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IPC Message Types */
typedef enum IpcMessageType {
    IPC_MSG_PING = 0,
    IPC_MSG_PONG = 1,
    IPC_MSG_SECURE_ENTER = 10,
    IPC_MSG_SECURE_EXIT = 11,
    IPC_MSG_STATUS_REQUEST = 20,
    IPC_MSG_STATUS_RESPONSE = 21,
    IPC_MSG_LOCKDOWN_POLICY = 30,
    IPC_MSG_TAMPER_ALERT = 40,
    IPC_MSG_HEARTBEAT = 50,
    IPC_MSG_SHUTDOWN = 99,
    IPC_MSG_ACK = 100,
    IPC_MSG_ERROR = 255
} IpcMessageType;

/* IPC Message Header */
typedef struct IpcMessageHeader {
    DWORD magic;            /* Magic number: 0x4D455348 ('MESH') */
    DWORD version;          /* Protocol version: 1 */
    DWORD type;             /* IpcMessageType */
    DWORD payloadSize;      /* Size of payload following header */
    DWORD sequence;         /* Sequence number for tracking */
    DWORD timestamp;        /* GetTickCount() at send time */
} IpcMessageHeader;

/* SecureEnter/Exit payload */
typedef struct IpcLockdownPayload {
    BOOL enableShellRestrictions;
    BOOL enablePolicyEnforcement;
    BOOL enableNetworkLockdown;
    BOOL enableTaskMonitoring;
    WCHAR allowedProcesses[1024];   /* Null-separated list */
    WCHAR blockedProcesses[1024];   /* Null-separated list */
} IpcLockdownPayload;

/* Status response payload */
typedef struct IpcStatusPayload {
    DWORD serviceState;         /* SERVICE_RUNNING, etc. */
    BOOL lockdownActive;
    DWORD watchdogState;
    DWORD uptime;
    DWORD lastTamperTime;
    WCHAR lastTamperSource[256];
} IpcStatusPayload;

/* Server handle */
typedef struct IpcServer {
    HANDLE hPipe;
    HANDLE hThread;
    volatile BOOL running;
    WCHAR pipeName[256];
    void* userData;
    void (*onMessage)(struct IpcServer*, const IpcMessageHeader*, const void* payload);
    void (*onConnect)(struct IpcServer*);
    void (*onDisconnect)(struct IpcServer*);
} IpcServer;

/* Client handle */
typedef struct IpcClient {
    HANDLE hPipe;
    WCHAR pipeName[256];
    DWORD timeoutMs;
    DWORD lastSequence;
} IpcClient;

/* ================================================================
 * Server Functions
 * ================================================================ */

/* Create and start IPC server */
BOOL Ipc_ServerCreate(
    IpcServer* server,
    const WCHAR* pipeName,
    void (*onMessage)(IpcServer*, const IpcMessageHeader*, const void*),
    void* userData);

/* Start server if previously stopped */
BOOL Ipc_ServerStart(IpcServer* server);

/* Stop server without destroying structure */
void Ipc_ServerStop(IpcServer* server);

/* Stop and destroy IPC server */
void Ipc_ServerDestroy(IpcServer* server);

/* Send message to connected client */
BOOL Ipc_ServerSend(
    IpcServer* server,
    IpcMessageType type,
    const void* payload,
    DWORD payloadSize);

/* Broadcast message to all connected clients (multi-instance server) */
BOOL Ipc_ServerBroadcast(
    IpcServer* server,
    IpcMessageType type,
    const void* payload,
    DWORD payloadSize);

/* ================================================================
 * Client Functions
 * ================================================================ */

/* Connect to IPC server */
BOOL Ipc_ClientConnect(
    IpcClient* client,
    const WCHAR* pipeName,
    DWORD timeoutMs);

/* Disconnect from server */
void Ipc_ClientDisconnect(IpcClient* client);

/* Send message to server */
BOOL Ipc_ClientSend(
    IpcClient* client,
    IpcMessageType type,
    const void* payload,
    DWORD payloadSize);

/* Receive message from server (blocking with timeout) */
BOOL Ipc_ClientReceive(
    IpcClient* client,
    IpcMessageHeader* outHeader,
    void* outPayload,
    DWORD payloadBufferSize,
    DWORD timeoutMs);

/* Send request and wait for response */
BOOL Ipc_ClientRequest(
    IpcClient* client,
    IpcMessageType requestType,
    const void* requestPayload,
    DWORD requestSize,
    IpcMessageHeader* responseHeader,
    void* responsePayload,
    DWORD responseBufferSize,
    DWORD timeoutMs);

/* ================================================================
 * Utility Functions
 * ================================================================ */

/* Get default pipe name for service */
void Ipc_GetDefaultPipeName(
    const WCHAR* serviceName,
    WCHAR* outPipeName,
    size_t outSize);

/* Validate message header */
BOOL Ipc_ValidateHeader(const IpcMessageHeader* header);

/* Build SecureEnter lockdown payload */
void Ipc_BuildLockdownPayload(
    IpcLockdownPayload* payload,
    BOOL shellRestrictions,
    BOOL policyEnforcement,
    BOOL networkLockdown,
    BOOL taskMonitoring);

/* Parse null-separated process list */
DWORD Ipc_ParseProcessList(
    const WCHAR* list,
    WCHAR** outProcesses,
    DWORD maxProcesses);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_IPC_H */
