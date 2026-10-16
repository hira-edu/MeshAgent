#!/usr/bin/env python3
"""Exercise extracted production TLS receive/queued-write code with real OpenSSL.

Uses disposable local socket pairs, memory BIO peers and an ephemeral certificate.
Only transport scheduling/logging are stubbed; no installed agent is run. macOS
uses the bundled OpenSSL archives; other POSIX hosts can supply library paths.
"""
import argparse
import hashlib
import platform
import subprocess
from pathlib import Path

from connection_failure_telemetry_native import extract

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r'''
#define _POSIX 1
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#define SOCKET int
#define MEMORYCHUNKSIZE 4096
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define ILibRemoteLogging_printf(...) ((void)0)
#define SSL_TRACE1(...) ((void)0)
#define SSL_TRACE2(...) ((void)0)
#define SEM_TRACK(...)
#define ILIBCRITICALEXIT(e) abort()
#define ignore_result(x) ((void)(x))
#define memmove_s(d,n,s,l) memmove(d,s,l)
#define ILibAsyncSocket_LastSocketError() errno
#define ILibAsyncSocket_RecvErrorIsTransient(e) ((e)==EAGAIN || (e)==EINTR)
#define ILibSpinLock_Lock(x) ((void)0)
#define ILibSpinLock_UnLock(x) ((void)0)
#define ILibLifeTime_Add(...) abort()
#define ILibForceUnBlockChain(...) ((void)0)
#define ILibMemory_Allocate(a,b,c,d) calloc(1,(a)+(b))
#define ILibAsyncSocket_MemoryOwnership_BIO 2
#define ILibAsyncSocket_Disconnect NULL
#define ILib6to4(...) ((void)0)
typedef struct ILibAsyncSocket_SendData { int UserFree, bufferSize; char *buffer; struct ILibAsyncSocket_SendData *Next; } ILibAsyncSocket_SendData;
typedef struct ILibAsyncSocketModule {
 int internalSocket,PAUSE,BeginPointer,EndPointer,MallocSize,MaxBufferSize;
 int FinConnect,SSLConnect,TLSHandshakeCompleted,TLS_HandshakeError_Occurred,SendLock;
 int timeout_milliSeconds;
 char *buffer; void *user,*OnInterrupt,*timeout_handler,*LifeTime;
 struct sockaddr_in6 SourceAddress,RemoteAddress;
 struct { const char *stage; int tlsError; unsigned long opensslError; } diagnostics;
 SSL *ssl; BIO *readBio,*writeBio; BUF_MEM *readBioBuffer,*writeBioBuffer;
 char readBioBuffer_mem[MEMORYCHUNKSIZE];
 ILibAsyncSocket_SendData *PendingPlain_Head,*PendingPlain_Tail,*PendingSend_Head,*PendingSend_Tail;
 unsigned int PendingBytesToSend;
 void (*OnData)(void *,char *,int *,int,void **,void **,int *);
 void (*OnConnect)(void *,int,void *);
 void (*OnDisconnect)(void *,void *);
 void (*OnBufferReAllocated)(void *,void *,ptrdiff_t);
} ILibAsyncSocketModule;
static char ILibAsyncSocket_ScratchPad[4096], ILibScratchPad[4096];
static int disconnects,received;
static void ILibAsyncSocket_RecordFailure(ILibAsyncSocketModule *r,const char *stage,int native,int tls,unsigned long err) {
 if(r->diagnostics.stage)return;
 r->diagnostics.stage=stage; r->diagnostics.tlsError=tls; r->diagnostics.opensslError=err;
 printf("failure stage=%s tlsError=%d opensslError=%lu hex=%lx\n",stage,tls,err,err);
}
static void ILibAsyncSocket_ClearPendingSend(ILibAsyncSocketModule *r) { assert(!r->PendingSend_Head); }
static unsigned int ILibAsyncSocket_TLSPendingBytes(ILibAsyncSocketModule *r) { return r->writeBioBuffer->length; }

// Transport/scheduler scaffolding only; all TLS calls use the real linked library.
static int ILibAsyncSocket_ProcessEncryptedBuffer(ILibAsyncSocketModule *r) {
 char wire[16384]; int n;
 while ((n=BIO_read(r->writeBio,wire,sizeof(wire)))>0) assert(send(r->internalSocket,wire,n,0)==n);
 return 0;
}
// Force the five-byte fixture buffer to move so the real receive function calls
// OnBufferReAllocated. That callback will fail a separate TLS connection.
static int force_move, realloc_callbacks;
static void *probe_realloc(void *old, size_t size) {
 if(!force_move)return realloc(old,size);
 assert(size>5);void *next=malloc(size);assert(next);memcpy(next,old,5);free(old);
 force_move=0;return next;
}
#define realloc probe_realloc
'''

TESTS = r'''
static void ondata(void *s,char *b,int *used,int len,void **i,void **u,int *p) {received+=len;*used=len;}
static void onclose(void *s,void *u) {++disconnects;}
static void pump(SSL *a,SSL *b) { char buf[16384];int n;while((n=BIO_read(SSL_get_wbio(a),buf,sizeof(buf)))>0) assert(BIO_write(SSL_get_rbio(b),buf,n)==n); }
static EVP_PKEY *key;
static X509 *cert;
static void initcert(void) {
 EVP_PKEY_CTX *p=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);assert(p);
 assert(EVP_PKEY_keygen_init(p)>0 && EVP_PKEY_CTX_set_rsa_keygen_bits(p,2048)>0 && EVP_PKEY_keygen(p,&key)>0);EVP_PKEY_CTX_free(p);
 cert=X509_new();assert(cert);X509_set_version(cert,2);ASN1_INTEGER_set(X509_get_serialNumber(cert),1);
 X509_gmtime_adj(X509_get_notBefore(cert),-60);X509_gmtime_adj(X509_get_notAfter(cert),3600);
 X509_set_pubkey(cert,key);X509_NAME *name=X509_get_subject_name(cert);
 X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(unsigned char*)"isolated-probe",-1,-1,0);
 X509_set_issuer_name(cert,name);assert(X509_sign(cert,key,EVP_sha256())>0);
}

static void actual_peer_alert(void) {
 SSL_CTX *cc=SSL_CTX_new(TLS_client_method()),*sc=SSL_CTX_new(TLS_server_method());
 SSL_CTX_set_max_proto_version(cc,TLS1_2_VERSION);SSL_CTX_set_max_proto_version(sc,TLS1_2_VERSION);
 assert(SSL_CTX_use_certificate(sc,cert)==1 && SSL_CTX_use_PrivateKey(sc,key)==1);
 SSL *c=SSL_new(cc),*s=SSL_new(sc);
 SSL_set_bio(c,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_connect_state(c);
 SSL_set_bio(s,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_accept_state(s);
 for(int i=0;i<100 && (!SSL_is_init_finished(c)||!SSL_is_init_finished(s));++i) {
  ERR_clear_error();int n=SSL_do_handshake(c);if(n<=0)assert(SSL_get_error(c,n)==SSL_ERROR_WANT_READ);pump(c,s);
  ERR_clear_error();n=SSL_do_handshake(s);if(n<=0)assert(SSL_get_error(s,n)==SSL_ERROR_WANT_READ);pump(s,c);
 }
 assert(SSL_is_init_finished(c)&&SSL_is_init_finished(s));ERR_clear_error();
 assert(SSL_write(c,"BAD",3)==3);unsigned char wire[4096];int n=BIO_read(SSL_get_wbio(c),wire,sizeof(wire));assert(n>5);
 wire[n-1]^=1;assert(BIO_write(SSL_get_rbio(s),wire,n)==n);
 char plain[32];int r=SSL_read(s,plain,sizeof(plain));assert(r<0 && SSL_get_error(s,r)==SSL_ERROR_SSL);
 ERR_clear_error();pump(s,c);r=SSL_read(c,plain,sizeof(plain));assert(r<=0 && SSL_get_error(c,r)==SSL_ERROR_SSL);
 assert(ERR_GET_REASON(ERR_peek_last_error())==SSL_R_SSLV3_ALERT_BAD_RECORD_MAC);
 SSL_free(c);SSL_free(s);SSL_CTX_free(cc);SSL_CTX_free(sc);
 printf("separate failed connection leaves queue=%lx\n",ERR_peek_last_error());
}

static void onreallocated(void *socket,void *user,ptrdiff_t delta) {
 ++realloc_callbacks;actual_peer_alert();
}

static void run(int seed,int scenario) {
 ERR_clear_error();disconnects=received=0;
 SSL_CTX *cc=SSL_CTX_new(TLS_client_method()),*sc=SSL_CTX_new(TLS_server_method());assert(cc&&sc);
 SSL_CTX_set_max_proto_version(cc,TLS1_2_VERSION);SSL_CTX_set_max_proto_version(sc,TLS1_2_VERSION);
 assert(SSL_CTX_use_certificate(sc,cert)==1 && SSL_CTX_use_PrivateKey(sc,key)==1);
 SSL *c=SSL_new(cc),*s=SSL_new(sc);
 SSL_set_bio(c,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_connect_state(c);
 SSL_set_bio(s,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_accept_state(s);
 if(scenario==3) {
  assert(SSL_do_handshake(c)<0);pump(c,s);
  ERR_clear_error();int status=SSL_do_handshake(s);assert(status<0 && SSL_get_error(s,status)==SSL_ERROR_WANT_READ);
 } else {
 for(int i=0;i<100 && (!SSL_is_init_finished(c)||!SSL_is_init_finished(s));++i) {
  ERR_clear_error();int n=SSL_do_handshake(c);if(n<=0)assert(SSL_get_error(c,n)==SSL_ERROR_WANT_READ);pump(c,s);
  ERR_clear_error();n=SSL_do_handshake(s);if(n<=0)assert(SSL_get_error(s,n)==SSL_ERROR_WANT_READ);pump(s,c);
 }
 assert(SSL_is_init_finished(c)&&SSL_is_init_finished(s));ERR_clear_error();
 }
 int sv[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0);
 ILibAsyncSocketModule r={0};r.internalSocket=sv[0];r.RemoteAddress.sin6_family=AF_UNIX;
 r.ssl=c;r.FinConnect=1;r.SSLConnect=r.TLSHandshakeCompleted=(scenario!=3);r.MallocSize=4096;r.buffer=malloc(4096);
 r.OnData=ondata;r.OnDisconnect=onclose;
 if(scenario==5) {
  free(r.buffer);r.MallocSize=5;r.buffer=malloc(5);r.OnBufferReAllocated=onreallocated;
  force_move=1;realloc_callbacks=0;
 }
 r.readBio=BIO_new_mem_buf(r.readBioBuffer_mem,sizeof(r.readBioBuffer_mem));BIO_set_mem_eof_return(r.readBio,-1);
 BIO_get_mem_ptr(r.readBio,&r.readBioBuffer);r.readBioBuffer->length=0;SSL_set0_rbio(c,r.readBio);
 r.writeBio=SSL_get_wbio(c);BIO_get_mem_ptr(r.writeBio,&r.writeBioBuffer);
 char wire[4096];int n;
 if(scenario==4) {
  // Generate a real fatal peer alert by corrupting this connection's outbound record.
  assert(SSL_write(c,"BAD",3)==3);n=BIO_read(SSL_get_wbio(c),wire,sizeof(wire));assert(n>5);
  wire[n-1]^=1;assert(BIO_write(SSL_get_rbio(s),wire,n)==n);
  char plain[32];int status=SSL_read(s,plain,sizeof(plain));assert(status<0 && SSL_get_error(s,status)==SSL_ERROR_SSL);
 } else if(scenario==2) { assert(SSL_shutdown(s)==0); }
 else if(scenario!=3) { assert(SSL_write(s,"VALID",5)==5); }
 n=BIO_read(SSL_get_wbio(s),wire,sizeof(wire));assert(n>5);
 if(scenario==1)wire[n-1]^=1; // Invalid inbound record must still fail authentication.
 if(scenario==3)n=2; // Incomplete handshake record must remain WANT_READ.
 assert(send(sv[1],wire,n,0)==n);
 ERR_clear_error();
 if(seed==2)actual_peer_alert();
 if(seed==1)ERR_put_error(ERR_LIB_SSL,148,SSL_R_SSLV3_ALERT_BAD_RECORD_MAC,__FILE__,__LINE__);
 printf("case seed=%d scenario=%d before=%lx\n",seed,scenario,ERR_peek_last_error());
 ILibProcessAsyncSocket(&r,1);
 printf("result received=%d disconnects=%d queue=%lx\n",received,disconnects,ERR_peek_last_error());
 assert(received==((scenario==0 || scenario==5)?5:0));
 if(scenario==5)assert(realloc_callbacks==1);
 assert(disconnects==(scenario==1 || scenario==2 || scenario==4));
 if(scenario==1 || scenario==4) {
  assert(r.diagnostics.stage && strcmp(r.diagnostics.stage,"tls_read")==0);
  assert(r.diagnostics.tlsError==SSL_ERROR_SSL);
  assert(ERR_GET_REASON(r.diagnostics.opensslError)==(scenario==1?SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC:SSL_R_SSLV3_ALERT_BAD_RECORD_MAC));
 } else if(scenario==2) {
  assert(r.diagnostics.stage && strcmp(r.diagnostics.stage,"peer_eof")==0);
  assert(!r.diagnostics.tlsError && !r.diagnostics.opensslError);
 } else { assert(!r.diagnostics.stage); }

 if(r.ssl)SSL_free(r.ssl);if(r.buffer)free(r.buffer);if(r.internalSocket!=-1)close(r.internalSocket);close(sv[1]);
 SSL_free(s);SSL_CTX_free(cc);SSL_CTX_free(sc);ERR_clear_error();
}

static void pending_write(void) {
 SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());assert(ctx);
 ILibAsyncSocketModule r={0};r.ssl=SSL_new(ctx);assert(r.ssl);
 SSL_set_bio(r.ssl,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_connect_state(r.ssl);
 ILibAsyncSocket_SendData *data=calloc(1,sizeof(*data));assert(data);
 data->buffer="VALID";data->bufferSize=5;r.PendingPlain_Head=r.PendingPlain_Tail=data;
 actual_peer_alert();
 assert(ILibAsyncSocket_TLSFlushPendingPlain(&r)==0);
 assert(!r.diagnostics.stage && r.PendingPlain_Head==data && r.PendingPlain_Tail==data);
 printf("pending write preserved on WANT_READ despite unrelated fatal alert\n");
 free(data);SSL_free(r.ssl);SSL_CTX_free(ctx);ERR_clear_error();
}
int main(void) {
 printf("runtime=%s\n",OpenSSL_version(OPENSSL_VERSION));initcert();
 run(0,0);run(1,0);run(2,0); // Healthy connection with clean, injected, and real peer-error queues.
 run(0,5); // Callback leaves a fatal error between two iterations of the production read loop.
 run(2,3); // Partial handshake with a real unrelated error queued.
 run(1,1);run(1,4); // Real record corruption and peer fatal alert retain their own diagnostics.
 run(2,2); // Clean peer shutdown stays a quiet close, despite an unrelated error.
 run(0,0); // A healthy connection after the fatal cases still works.
 pending_write();X509_free(cert);EVP_PKEY_free(key);puts("PASS");return 0;
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--source", type=Path, default=ROOT / "microstack/ILibAsyncSocket.c")
    parser.add_argument("--openssl-include", type=Path, default=ROOT / "openssl/include")
    parser.add_argument("--openssl-lib-dir", type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts/validation/asyncsocket-tls-error-queue")
    args = parser.parse_args()
    if platform.system() == "Windows":
        parser.error("This socketpair harness requires a POSIX host")
    lib_dir = args.openssl_lib_dir
    if lib_dir is None:
        if platform.system() != "Darwin":
            parser.error("Supply --openssl-include and --openssl-lib-dir for your OpenSSL build")
        arch = "osx-arm-64" if platform.machine() == "arm64" else "osx-x86-64"
        lib_dir = ROOT / "openssl/libstatic/macos" / arch
    args.out.mkdir(parents=True, exist_ok=True)
    source = args.source.read_text()
    code = PRELUDE + "\n" + extract(source, "ILibAsyncSocket_TLSFlushPendingPlain") + "\n" + extract(source, "ILibProcessAsyncSocket") + "\n" + TESTS
    harness = args.out / "probe.c"
    binary = args.out / "probe"
    harness.write_text(code)
    command = [args.cc, "-std=gnu11", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-Wno-incompatible-pointer-types", "-I" + str(args.openssl_include), str(harness),
               str(lib_dir / "libssl.a"), str(lib_dir / "libcrypto.a"), "-lpthread", "-o", str(binary)]
    subprocess.run(command, check=True)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
    evidence = "source_sha256=" + hashlib.sha256(source.encode()).hexdigest() + "\n" + result.stdout + result.stderr
    (args.out / "results.txt").write_text(evidence)
    print(evidence, end="")
    result.check_returncode()


if __name__ == "__main__":
    main()
