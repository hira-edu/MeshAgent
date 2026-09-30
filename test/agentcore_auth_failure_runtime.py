#!/usr/bin/env python3
"""Execute production pre-auth rejection and service-exit paths with API fixtures.

Crypto stubs inject validation outcomes; this tests cleanup/disconnect behavior,
not cryptographic correctness or Windows SCM scheduling.
"""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / 'meshcore/agentcore.c').read_text()
    types = source[source.index('typedef struct MeshCommand_BinaryPacket_AuthRequest'):source.index('typedef enum MeshCommand_AuthInfo_PlatformType')]
    start = source.index('void MeshServer_ProcessCommand(ILibWebClient_StateObject WebStateObject,')
    end = source.index('\n\t// If we get a authentication command after', start)
    auth = source[start:end] + '\n}\n'
    host = (ROOT / 'meshservice/service_host.c').read_text()
    start = host.index('    int startResult = MeshAgent_Start(')
    end = host.index('\n}\n', start)
    host_exit = 'static void serviceExit(void) {\n' + host[start:end] + '\n}\n'
    prefix = r'''
#include <assert.h>
#include <arpa/inet.h>
#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define UTIL_SHA384_HASHSIZE 48
#define UTIL_SHA256_HASHSIZE 32
#define MeshCommand_AuthRequest 1
#define MeshCommand_AuthVerify 2
#define MeshCommand_AuthConfirm 4
#define NID_sha384 1
#define ILibWebClient_WebSocket_DataType_BINARY 0
#define ILibAsyncSocket_MemoryOwnership_USER 0
#define ILibWebClient_WebSocket_FragmentFlag_Complete 0
#define ILIBLOGMESSAGEX(...) ((void)0)
#define ILibRemoteLogging_printf(...) ((void)0)
#define MeshAgent_ControlChannelDebugLog(...) ((void)0)
#define memcpy_s(dst,cap,src,len) memcpy(dst,src,len)
#define ServiceUtil_DebugPrintfA(...) ((void)0)
#define ServiceHost_LogLine(...) ((void)0)
#define FALSE 0
#define SERVICE_STOP_PENDING 3
#define SERVICE_RUNNING 4
#define SERVICE_STOPPED 1
#define ERROR_SERVICE_SPECIFIC_ERROR 1066
#define ERROR_PROCESS_ABORTED 1067
typedef unsigned long DWORD;
typedef int X509;
typedef int EVP_PKEY;
typedef int RSA;
typedef int SHA512_CTX;
typedef void* ILibWebClient_StateObject;
typedef struct MeshAgentHostContainer {
    int serverAuthState,controlChannelDebug,tlsRelaxedValidation,tlsInspectionDetected,tlsInspectionLogged,exitCode;
    void *chain,*masterDb;
    char serverWebHash[48],serverNonce[48],agentNonce[48],serverHash[48];
    struct { X509* x509; EVP_PKEY* pkey; } selfcert;
} MeshAgentHostContainer;
static char ILibScratchPad[8192],ILibScratchPad2[8192];
static int objects, disconnects, infos, decodeFails, pinMismatch, signatureFails, missingKey;
static void* object(void) { ++objects; return malloc(sizeof(int)); }
static void release(void* p) { if (p) { --objects; free(p); } }
static X509* ILibWebClient_SslGetCert(void* channel) { (void)channel; return object(); }
static void X509_free(X509* p) { release(p); }
static void EVP_PKEY_free(EVP_PKEY* p) { release(p); }
static void RSA_free(RSA* p) { release(p); }
static int d2i_X509(X509** out, const unsigned char** data, int len) { (void)data; (void)len; if(decodeFails) return 0; *out=object(); return 1; }
static int i2d_X509(X509* p,unsigned char** out) { (void)p; (void)out; return 0; }
static EVP_PKEY* X509_get_pubkey(X509* cert) { (void)cert; return missingKey==1 ? NULL : object(); }
static RSA* EVP_PKEY_get1_RSA(EVP_PKEY* key) { assert(key); return missingKey==2 ? NULL : object(); }
static void* EVP_sha384(void) { return NULL; }
static void* EVP_sha256(void) { return NULL; }
static void X509_pubkey_digest(X509* p,void* d,unsigned char* out,unsigned int* len) { (void)p; (void)d; memset(out,pinMismatch?1:0,48); *len=48; }
static int RSA_verify(int nid,unsigned char* hash,int len,unsigned char* sig,int slen,RSA* key) { (void)nid;(void)hash;(void)len;(void)sig;(void)slen;assert(key);return !signatureFails; }
static int RSA_sign(int a,unsigned char*b,int c,unsigned char*d,unsigned int*e,RSA*f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return 0; }
static void util_certhash2(X509* cert,char* out) { (void)cert; memset(out,0,48); }
static void util_keyhash2(X509* cert,char* out) { (void)cert; memset(out,0,48); }
static void util_tohex(char* in,int len,char* out) { (void)in; memset(out,'0',len*2);out[len*2]=0; }
static void SHA384_Init(SHA512_CTX*c) { *c=0; }
static void SHA384_Update(SHA512_CTX*c,void*p,int n) { (void)c;(void)p;(void)n; }
static void SHA384_Final(unsigned char*out,SHA512_CTX*c) { (void)c;memset(out,0,48); }
static void ILibSimpleDataStore_PutEx(void*a,char*b,int c,char*d,int e) { (void)a;(void)b;(void)c;(void)d;(void)e; }
static void ILibSimpleDataStore_DeleteEx(void*a,char*b,int c) { (void)a;(void)b;(void)c; }
static void ILibWebClient_WebSocket_Send(void*a,int b,char*c,int d,int e,int f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; }
static void ILibWebClient_Disconnect(void* channel) { (void)channel; assert(objects==0); ++disconnects; }
static void MeshServer_SendAgentInfo(MeshAgentHostContainer*a,void*b) { (void)a;(void)b;++infos; }
static void MeshServer_ServerAuthenticated(void*a,MeshAgentHostContainer*b) { (void)a;(void)b; }
static MeshAgentHostContainer agent;
static MeshAgentHostContainer* g_ServiceHostAgent;
static int g_ServiceHostRunning, g_ServiceHostStatusHandle, startArgc;
static char** startArgv;
static struct { DWORD dwCurrentState,dwWin32ExitCode,dwServiceSpecificExitCode; } g_ServiceHostStatus;
static int MeshAgent_Start(MeshAgentHostContainer*a,int b,char**c) { (void)a;(void)b;(void)c; return 0; }
#define SetServiceStatus(...) ((void)0)
static void reset(void) { assert(objects==0); memset(&agent,0,sizeof(agent)); disconnects=infos=decodeFails=pinMismatch=signatureFails=missingKey=0; }
'''
    main_c = r'''
static void verify(void) {
    union { unsigned short words[8]; char bytes[16]; } packet = {0};
    packet.words[0]=htons(MeshCommand_AuthVerify); packet.words[1]=htons(2);
    MeshServer_ProcessCommand(NULL,&agent,packet.bytes,10);
    assert(objects==0);
}
int main(void) {
    reset(); decodeFails=1; verify(); assert(disconnects==1 && infos==0 && agent.serverAuthState==0);
    reset(); pinMismatch=1; verify(); assert(disconnects==1 && infos==0 && agent.serverAuthState==0);
    reset(); signatureFails=1; verify(); assert(disconnects==1 && infos==0 && agent.serverAuthState==0);
    reset(); missingKey=1; verify(); assert(disconnects==1 && infos==0);
    reset(); missingKey=2; verify(); assert(disconnects==1 && infos==0);
    reset(); verify(); assert(disconnects==0 && infos==1 && agent.serverAuthState==1);
    reset(); MeshCommand_BinaryPacket_AuthRequest request={0}; request.command=htons(1); memset(request.serverHash,1,48);
    MeshServer_ProcessCommand(NULL,&agent,(char*)&request,sizeof(request)); assert(disconnects==1 && objects==0);
    reset(); MeshServer_ProcessCommand(NULL,&agent,(char*)&request,3); assert(disconnects==1 && objects==0);
    reset(); unsigned short malformed[5]={htons(2),htons(500)}; MeshServer_ProcessCommand(NULL,&agent,(char*)malformed,sizeof(malformed)); assert(disconnects==1 && objects==0);
    for (int mode=0;mode<3;++mode) {
        reset(); g_ServiceHostAgent=&agent; g_ServiceHostRunning=1;
        memset(&g_ServiceHostStatus,0,sizeof(g_ServiceHostStatus));
        g_ServiceHostStatus.dwCurrentState=mode==0 ? SERVICE_STOP_PENDING : SERVICE_RUNNING;
        agent.exitCode=mode==2 ? 42 : 0; serviceExit();
        assert(g_ServiceHostStatus.dwCurrentState==SERVICE_STOPPED && !g_ServiceHostRunning && !g_ServiceHostAgent);
        assert(g_ServiceHostStatus.dwWin32ExitCode==(mode==0 ? 0 : ERROR_SERVICE_SPECIFIC_ERROR));
        if(mode==2) assert(g_ServiceHostStatus.dwServiceSpecificExitCode==42);
    }
    puts("PASS: 9 authentication outcomes preserve cleanup/admission; 3 service exits preserve deliberate stop and report unexpected return");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='mesh-auth-failure-') as folder:
        path = pathlib.Path(folder)
        (path / 'fixture.c').write_text(prefix + types + auth + host_exit + main_c)
        subprocess.run(['cc', '-std=c11', '-fsanitize=address,undefined', '-g', str(path / 'fixture.c'), '-o', str(path / 'fixture')], check=True)
        subprocess.run([str(path / 'fixture')], check=True, timeout=15)


if __name__ == '__main__':
    main()
