#!/usr/bin/env python3
"""Execute production pre-auth rejection and TLS-callback paths with API fixtures.

Crypto stubs inject validation outcomes; this tests cleanup/disconnect behavior,
not cryptographic correctness. Service exit is covered by service_startup_control_native.py.
"""
import os
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
    start = source.index('int ValidateMeshServer(')
    validate = source[start:source.index('\n#endif', start)] + '\n'
    prefix = r'''
#include <assert.h>
#ifdef _WIN32
#include <malloc.h>
#define htons(x) _byteswap_ushort(x)
#define ntohs(x) _byteswap_ushort(x)
#else
#include <arpa/inet.h>
#include <alloca.h>
#endif
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
typedef int X509;
typedef int EVP_PKEY;
typedef int RSA;
typedef int SHA512_CTX;
typedef void* ILibWebClient_StateObject;
typedef struct MeshAgentHostContainer {
    int serverAuthState,controlChannelDebug;
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
#define UNREFERENCED_PARAMETER(p) ((void)(p))
#define STACK_OF(type) void
typedef void* ILibWebClient_RequestToken;
static void* userObjects[1];
static const char* storedWebCert;
static void** ILibWebClient_RequestToken_GetUserObjects(ILibWebClient_RequestToken token) { return token ? userObjects : NULL; }
static int ILibSimpleDataStore_Get(void* db,const char* key,char* buffer,size_t len) {
    (void)db; assert(strcmp(key,"validateWebCert")==0);
    if(!storedWebCert) return 0;
    size_t n=strlen(storedWebCert)+1; assert(n<=len); memcpy(buffer,storedWebCert,n); return (int)n;
}
static void reset(void) { assert(objects==0); memset(&agent,0,sizeof(agent)); disconnects=infos=decodeFails=pinMismatch=signatureFails=missingKey=0; }
'''
    main_c = r'''
static void verify(void) {
    union { unsigned short words[8]; char bytes[16]; } packet = {0};
    packet.words[0]=htons(MeshCommand_AuthVerify); packet.words[1]=htons(2);
    MeshServer_ProcessCommand(NULL,&agent,packet.bytes,10);
    assert(objects==0);
}
static int validateOutcome(const char* stored,int preverify,int viaToken) {
    reset(); memset(agent.serverWebHash,7,sizeof(agent.serverWebHash)); storedWebCert=stored; userObjects[0]=&agent;
    int result=ValidateMeshServer(viaToken ? (void*)1 : NULL,preverify,NULL,NULL,&agent);
    for(size_t i=0;i<sizeof(agent.serverWebHash);++i) assert(agent.serverWebHash[i]==0);
    return result;
}
int main(void) {
    assert(validateOutcome(NULL,0,1)==1 && validateOutcome(NULL,1,0)==1);
    assert(validateOutcome("0",0,1)==1 && validateOutcome("yes",0,1)==1);
    assert(validateOutcome("1",0,1)==0 && validateOutcome("1",1,1)==1);
    assert(validateOutcome("true",0,0)==0 && validateOutcome("true",1,0)==1);
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
    puts("PASS: validateWebCert opt-in returns preverify and default defers to the websocket hash check; 9 authentication outcomes preserve cleanup/admission");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='mesh-auth-failure-') as folder:
        path = pathlib.Path(folder)
        (path / 'fixture.c').write_text(prefix + types + auth + validate + main_c)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-fsanitize=address,undefined', '-g', str(path / 'fixture.c'), '-o', str(path / 'fixture')], check=True)
        subprocess.run([str(path / 'fixture')], check=True, timeout=15)


if __name__ == '__main__':
    main()
