#!/usr/bin/env python3
"""Exercise production receive/error diagnostics with disposable Windows TCP peers.

Runs extracted production functions; TLS failures are injected diagnostic
snapshots, not live TLS handshakes. No installed service is started or changed.
"""
import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path


def extract(source, name):
    match = re.search(r"(?m)^[^\n;]*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source)
    if not match:
        raise AssertionError("Missing production function: " + name)
    start = match.start()
    depth = 1
    for token in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[match.end():]):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[start:match.end() + token.end()]
    raise AssertionError("Unclosed function: " + name)


PRELUDE = r'''
#define WIN32 1
#define WINSOCK2 1
#define MICROSTACK_NOTLS 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define MEMORYCHUNKSIZE 4096
#define ILibAsyncSocket_LastSocketError() WSAGetLastError()
#define ILibAsyncSocket_RecvErrorIsTransient(e) ((e)==WSAEWOULDBLOCK || (e)==WSAENOBUFS || (e)==WSAEINTR)
#define ILibRemoteLogging_printf(...) ((void)0)
#define SEM_TRACK(...) ((void)0);
#define ILIBCRITICALEXIT(e) abort()
#define WEBSOCKET_OPCODE_CLOSE 8
typedef void *ILibAsyncSocket_SocketModule;
typedef void *ILibWebClient_StateObject;
typedef struct ILibAsyncSocket_ConnectionDiagnostics {
    const char *stage;
    int nativeError, tlsError;
    unsigned long opensslError;
} ILibAsyncSocket_ConnectionDiagnostics;
typedef struct ILibAsyncSocketModule ILibAsyncSocketModule;
struct ILibAsyncSocketModule {
    SOCKET internalSocket;
    unsigned int PendingBytesToSend;
    int FinConnect, PAUSE, BeginPointer, EndPointer, MallocSize, MaxBufferSize;
    int timeout_milliSeconds;
    char *buffer;
    void *user, *OnInterrupt, *timeout_handler;
    struct sockaddr_in6 SourceAddress, RemoteAddress;
    ILibAsyncSocket_ConnectionDiagnostics diagnostics;
    void (*OnData)(void *, char *, int *, int, void **, void **, int *);
    void (*OnConnect)(void *, int, void *);
    void (*OnDisconnect)(void *, void *);
    void (*OnBufferReAllocated)(void *, void *, ptrdiff_t);
};
typedef struct ILibWebClientDataObject {
    ILibAsyncSocket_ConnectionDiagnostics diagnostics;
    ILibAsyncSocketModule *SOCK;
    int webSocketCloseCode;
} ILibWebClientDataObject;
typedef struct MeshAgentHostContainer {
    void *chain;
    int controlChannelIntentionalDisconnect, serverConnectionState, serverAuthState, controlChannel_pongGraceUsed;
    long long controlChannel_lastDataTick, controlChannel_pingSentTick;
} MeshAgentHostContainer;
static char ILibAsyncSocket_ScratchPad[4096];
static char logLines[8][4096];
static int logs, disconnects, dataBytes, destroying;
static void ILIBLOGMESSAGEX(char *format, ...) {
    assert(logs < 8);
    va_list args; va_start(args, format);
    vsnprintf(logLines[logs++], 4096, format, args); va_end(args);
    WSASetLastError(777);
}
static void ILibAsyncSocket_ClearPendingSend(void *socket) { ((ILibAsyncSocketModule *)socket)->PendingBytesToSend=0; }
static void ILib6to4(struct sockaddr *address) { (void)address; }
static long long ILibGetUptime(void) { return 10000; }
static int ILibIsChainBeingDestroyed(void *chain) { (void)chain; return destroying; }
static int ILibWebClient_GetDescriptorValue_FromStateObject(void *state) { return state ? 23 : -1; }
static void close_frames(void);
'''


TESTS = r'''
static ILibWebClientDataObject client;
static MeshAgentHostContainer agent;
static void disconnected(void *socket, void *user) {
    (void)user; ++disconnects;
    ILibAsyncSocket_GetConnectionDiagnostics(socket, &client.diagnostics);
    client.SOCK=NULL;
    MeshAgent_ControlChannelFailureLog(&agent,&client,"disconnected",0,101);
}
static void received(void *socket, char *data, int *begin, int end, void **interrupt, void **user, int *pause) {
    (void)socket; (void)data; (void)interrupt; (void)user; (void)pause;
    dataBytes+=end; *begin=end;
}
static SOCKET peer_pair(ILibAsyncSocketModule *reader) {
    SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    struct sockaddr_in address={0}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(listener!=INVALID_SOCKET && bind(listener,(struct sockaddr *)&address,sizeof(address))==0);
    assert(listen(listener,1)==0);
    int len=sizeof(address); assert(getsockname(listener,(struct sockaddr *)&address,&len)==0);
    SOCKET local=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    assert(local!=INVALID_SOCKET && connect(local,(struct sockaddr *)&address,sizeof(address))==0);
    SOCKET peer=accept(listener,NULL,NULL); assert(peer!=INVALID_SOCKET); closesocket(listener);
    memset(reader,0,sizeof(*reader)); reader->internalSocket=local; reader->FinConnect=1;
    reader->RemoteAddress.sin6_family=AF_INET; reader->MallocSize=4096; reader->buffer=malloc(4096);
    assert(reader->buffer); reader->OnDisconnect=disconnected; reader->OnData=received;
    u_long nonblocking=1; assert(ioctlsocket(local,FIONBIO,&nonblocking)==0);
    memset(&client,0,sizeof(client)); client.SOCK=reader;
    memset(&agent,0,sizeof(agent)); agent.serverConnectionState=2; agent.serverAuthState=3;
    logs=disconnects=dataBytes=destroying=0; return peer;
}
static void await_read(SOCKET socket) {
    fd_set readset; FD_ZERO(&readset); FD_SET(socket,&readset);
    struct timeval timeout={2,0}; assert(select(0,&readset,NULL,NULL,&timeout)>0);
}
static void quiet_cases(void) {
    ILibAsyncSocketModule reader; SOCKET peer=peer_pair(&reader);
    ILibProcessAsyncSocket(&reader,1);
    assert(logs==0 && disconnects==0 && reader.internalSocket!=INVALID_SOCKET);
    assert(reader.diagnostics.stage==NULL);
    assert(send(peer,"x",1,0)==1); await_read(reader.internalSocket);
    ILibProcessAsyncSocket(&reader,1);
    assert(dataBytes==1 && logs==0 && disconnects==0);
    agent.controlChannelIntentionalDisconnect=1;
    MeshAgent_ControlChannelFailureLog(&agent,&client,"disconnected",0,101); assert(logs==0);
    agent.controlChannelIntentionalDisconnect=0; destroying=1;
    MeshAgent_ControlChannelFailureLog(&agent,&client,"disconnected",0,101); assert(logs==0);
    closesocket(peer); closesocket(reader.internalSocket); free(reader.buffer);
    puts("PASS: successful data, would-block, script disconnect and shutdown stay quiet");
}
static void eof_case(void) {
    ILibAsyncSocketModule reader; SOCKET peer=peer_pair(&reader);
    assert(shutdown(peer,SD_SEND)==0); await_read(reader.internalSocket);
    ILibProcessAsyncSocket(&reader,1);
    assert(disconnects==1 && logs==1 && !strcmp(client.diagnostics.stage,"peer_eof"));
    assert(strstr(logLines[0],"[CONTROLCHANNEL_FAILURE]") && strstr(logLines[0],"transport=peer_eof"));
    assert(strstr(logLines[0],"nativeError=0") && reader.buffer==NULL);
    closesocket(peer); puts("PASS: graceful peer EOF is distinguished without a socket error");
}
static void reset_case(void) {
    ILibAsyncSocketModule reader; SOCKET peer=peer_pair(&reader);
    struct linger reset={1,0}; assert(setsockopt(peer,SOL_SOCKET,SO_LINGER,(char *)&reset,sizeof(reset))==0);
    closesocket(peer); await_read(reader.internalSocket); ILibProcessAsyncSocket(&reader,1);
    assert(disconnects==1 && logs==2 && client.diagnostics.nativeError==WSAECONNRESET);
    assert(!strcmp(client.diagnostics.stage,"receive") && reader.internalSocket==INVALID_SOCKET && reader.buffer==NULL);
    assert(strstr(logLines[0],"nativeError=10054") && strstr(logLines[1],"nativeError=10054"));
    puts("PASS: real TCP reset retains WSAECONNRESET through cleanup and core notification");
}
static void snapshot_cases(void) {
    ILibAsyncSocketModule reader={0}; logs=0; reader.internalSocket=23;
    WSASetLastError(10054);
    ILibAsyncSocket_RecordFailure(&reader,"tls_handshake",0,1,1234);
    assert(WSAGetLastError()==10054 && logs==1);
    ILibAsyncSocket_RecordFailure(&reader,"receive",10054,0,0);
    assert(logs==1 && reader.diagnostics.opensslError==1234 && reader.diagnostics.tlsError==1);
    ILibAsyncSocket_ConnectionDiagnostics copy;
    client.SOCK=&reader; memset(&client.diagnostics,0,sizeof(client.diagnostics)); client.webSocketCloseCode=1011;
    int closeCode; ILibWebClient_GetConnectionDiagnostics(&client,&copy,&closeCode);
    assert(copy.opensslError==1234 && closeCode==1011);
    client.diagnostics=copy; client.SOCK=NULL;
    ILibWebClient_GetConnectionDiagnostics(&client,&copy,&closeCode); assert(copy.opensslError==1234);
    ILibWebClient_GetConnectionDiagnostics(NULL,&copy,&closeCode); assert(copy.stage==NULL && closeCode==0);
    puts("PASS: first TLS error, close code, null getters and socket error state are preserved");
}
int main(void) {
    WSADATA winsock; assert(WSAStartup(MAKEWORD(2,2),&winsock)==0);
    quiet_cases(); eof_case(); reset_case(); snapshot_cases(); close_frames(); WSACleanup(); return 0;
}
'''


def main():
    if os.name != "nt":
        raise SystemExit("This probe requires Windows Winsock and Clang.")
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=root / "artifacts/validation/connection-failure-telemetry")
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    args = parser.parse_args()
    socket = (root / "microstack/ILibAsyncSocket.c").read_text()
    web = (root / "microstack/ILibWebClient.c").read_text()
    core = (root / "meshcore/agentcore.c").read_text()
    receive = extract(socket, "ILibProcessAsyncSocket")
    assert receive.index("ILibAsyncSocket_RecvErrorIsTransient(recvError)") < receive.index('ILibAsyncSocket_RecordFailure(Reader, "receive"')
    disconnect = extract(web, "ILibWebClient_OnDisconnectSink")
    assert disconnect.index("ILibAsyncSocket_GetConnectionDiagnostics") < disconnect.index("wcdo->SOCK = NULL")
    assert "memset(&module->diagnostics" in extract(socket, "ILibAsyncSocket_ConnectTo")
    reuse = socket[socket.index("void ILibAsyncSocket_UseThisSocket("):]
    assert "memset(&module->diagnostics" in reuse[:reuse.index("module->OnInterrupt = InterruptPtr;")]
    on_response = extract(core, "MeshServer_OnResponse")
    assert '"http_upgrade_rejected"' in on_response and '"connect_failed"' in on_response
    assert 'MeshAgent_ControlChannelFailureLog(agent, timedOutChannel, "pong_timeout"' in core
    close_frame = web[web.index("case WEBSOCKET_OPCODE_CLOSE:"):web.index("case WEBSOCKET_OPCODE_PING:")]
    assert close_frame.index("webSocketCloseCode =") < close_frame.index("ILibWebClient_Disconnect")
    functions = [extract(socket, "ILibAsyncSocket_RecordFailure"),
                 extract(socket, "ILibAsyncSocket_GetConnectionDiagnostics"), receive,
                 extract(web, "ILibWebClient_GetConnectionDiagnostics"),
                 extract(core, "MeshAgent_ControlChannelFailureLog")]
    args.evidence.mkdir(parents=True, exist_ok=True)
    fixture = args.evidence / "connection-failure-telemetry.c"
    executable = args.evidence / "connection-failure-telemetry.exe"
    frames = r'''
static int frameDisconnects;
static void ILibWebClient_Disconnect(void *state) { assert(state==&client); ++frameDisconnects; }
static void close_payload(char *buffer, int plen) {
    int i=0; ILibWebClientDataObject *wcdo=&client;
    switch(WEBSOCKET_OPCODE_CLOSE) {
''' + close_frame + r'''
    }
}
static void close_frames(void) {
    char normal[2]={3,(char)0xe8}, error[2]={3,(char)0xf3}, malformed[1]={3};
    close_payload(normal,2); assert(client.webSocketCloseCode==1000);
    close_payload(error,2); assert(client.webSocketCloseCode==1011);
    close_payload(NULL,0); assert(client.webSocketCloseCode==1005);
    close_payload(malformed,1); assert(client.webSocketCloseCode==-1);
    assert(frameDisconnects==4);
    puts("PASS: peer close codes, empty and malformed payloads are captured before disconnect");
}
'''
    fixture.write_text(PRELUDE + "\n".join(functions) + TESTS + frames)
    subprocess.run([args.cc, "-std=c11", "-g", "-O1", "-fsanitize=address,undefined", str(fixture), "-lws2_32", "-o", str(executable)], check=True)
    runtime_env = os.environ.copy()
    compiler = shutil.which(args.cc)
    if compiler:
        runtimes = list(Path(compiler).parent.parent.glob("lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll"))
        if runtimes:
            runtime_env["PATH"] = str(runtimes[0].parent) + os.pathsep + runtime_env.get("PATH", "")
    result = subprocess.run([str(executable.resolve())], capture_output=True, text=True, timeout=15, env=runtime_env)
    (args.evidence / "runtime.log").write_text(f"exit={result.returncode}\n" + result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    if result.returncode:
        raise SystemExit(result.returncode)
    print("PASS: production failure paths retain diagnostics before cleanup and reset on socket reuse")


if __name__ == "__main__":
    main()
