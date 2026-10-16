#!/usr/bin/env python3
"""Exercise production TLS send/queue code against real OpenSSL memory peers.

Only socket acceptance and event scheduling are injected. No installed service,
firewall rule, network endpoint, or certificate store is changed.
"""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess

from connection_failure_telemetry_native import extract

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r'''
#define WIN32 1
#define WINSOCK2 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#define MSG_NOSIGNAL 0
#define ILibRemoteLogging_printf(...) ((void)0)
#define SSL_TRACE1(...) ((void)0)
#define SSL_TRACE2(...) ((void)0)
#define TLSLOG1(...) ((void)0)
#define SEM_TRACK(...)
#define ILIBCRITICALEXIT(e) abort()
#define ignore_result(x) ((void)(x))
#define INET_SOCKADDR_LENGTH(x) sizeof(struct sockaddr_in6)
typedef void *ILibAsyncSocket_SocketModule;
typedef enum ILibAsyncSocket_MemoryOwnership {ILibAsyncSocket_MemoryOwnership_CHAIN=0, ILibAsyncSocket_MemoryOwnership_STATIC=1, ILibAsyncSocket_MemoryOwnership_USER=2, ILibAsyncSocket_MemoryOwnership_BIO=3} ILibAsyncSocket_MemoryOwnership;
typedef enum ILibAsyncSocket_SendStatus {ILibAsyncSocket_ALL_DATA_SENT=0, ILibAsyncSocket_NOT_ALL_DATA_SENT_YET=1, ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR=-1, ILibAsyncSocket_BUFFER_TOO_LARGE=-2} ILibAsyncSocket_SendStatus;
#define ILibAsyncSocket_LOCK_OVERRIDE 0x40000000
typedef struct ILibAsyncSocket_SendData {
 char *buffer; int bufferSize,bytesSent; struct sockaddr_in6 remoteAddress;
 ILibAsyncSocket_MemoryOwnership UserFree; struct ILibAsyncSocket_SendData *Next;
} ILibAsyncSocket_SendData;
typedef struct ILibAsyncSocketModule {
 struct {struct {void *ParentChain;} ChainLink; void (*SendOkPtr)(void*);} Transport;
 SOCKET internalSocket; unsigned int PendingBytesToSend,TotalBytesSent;
 int FinConnect,SSLConnect,PAUSE,ProxyState,SendLock; long long timeout_lastActivity;
 void *LifeTime,*user; SSL *ssl; BIO *readBio,*writeBio; BUF_MEM *readBioBuffer,*writeBioBuffer;
 ILibAsyncSocket_SendData *PendingSend_Head,*PendingSend_Tail,*PendingPlain_Head,*PendingPlain_Tail;
 void (*OnSendOK)(void*,void*);
 struct {const char *stage;int nativeError,tlsError;unsigned long opensslError;} diagnostics;
} ILibAsyncSocketModule;
static int native_error,scheduled,zero_sends,send_ok;
static size_t wire_size,accepted_total; static unsigned char wire[8*1024*1024];
static int plan[32],plan_count,plan_index;
static unsigned int rng=1; static int random_sends;
static int fake_send(SOCKET s,const char *b,int n,int f) {
 assert(n>0);int accepted=n;
 if(plan_index<plan_count)accepted=plan[plan_index++];
 else if(random_sends){rng=rng*1664525+1013904223; unsigned int v=rng%8; accepted=v==0?-WSAEWOULDBLOCK:v==1?-WSAENOBUFS:v==2?0:1+(rng%(unsigned int)n);}
 if(accepted<0){native_error=-accepted;return -1;}
 if(accepted>n)accepted=n;
 assert(wire_size+accepted<=sizeof(wire));memcpy(wire+wire_size,b,accepted);wire_size+=accepted;accepted_total+=accepted;return accepted;
}
#define send fake_send
#define sendto(s,b,n,f,a,l) fake_send(s,b,n,f)
#define ILibAsyncSocket_LastSocketError() native_error
#define WSAGetLastError() native_error
#define ILibAsyncSocket_SendErrorIsTransient(e) ((e)==WSAEWOULDBLOCK||(e)==WSAENOBUFS||(e)==WSAEINTR)
#define ILibMemory_Allocate(a,b,c,d) calloc(1,(a)+(b))
#define ILibMemory_GetExtraMemory(p,n) ((char*)(p)+(n))
static void ILibSpinLock_Lock(int *lock){assert(*lock==0);*lock=1;}
static void ILibSpinLock_UnLock(int *lock){assert(*lock==1);*lock=0;}
#define ILibIsRunningOnChainThread(c) 1
#define ILibForceUnBlockChain(c) ((void)0)
#define ILibGetUptime() 1
#define ILibLifeTime_Add(...) (++scheduled)
static void ILibAsyncSocket_RecordSendActivity(ILibAsyncSocketModule*m,int n){}
static void ILibAsyncSocket_RecordZeroSend(ILibAsyncSocketModule*m,const char*s,int n){++zero_sends;}
static void ILibAsyncSocket_RecordFailure(ILibAsyncSocketModule*m,const char*s,int e,int t,unsigned long o){
 if(!m->diagnostics.stage){m->diagnostics.stage=s;m->diagnostics.nativeError=e;m->diagnostics.tlsError=t;m->diagnostics.opensslError=o;}
}
static void ILibAsyncSocket_ClearPendingPlain(ILibAsyncSocketModule*);
static void on_send_ok(void*s,void*u){assert(((ILibAsyncSocketModule*)s)->SendLock==0);++send_ok;}
'''

TESTS = r'''
static EVP_PKEY *key;static X509 *cert;
static void initcert(void){
 EVP_PKEY_CTX*p=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);assert(p);
 assert(EVP_PKEY_keygen_init(p)>0&&EVP_PKEY_CTX_set_rsa_keygen_bits(p,2048)>0&&EVP_PKEY_keygen(p,&key)>0);EVP_PKEY_CTX_free(p);
 cert=X509_new();assert(cert);X509_set_version(cert,2);ASN1_INTEGER_set(X509_get_serialNumber(cert),1);
 X509_gmtime_adj(X509_get_notBefore(cert),-60);X509_gmtime_adj(X509_get_notAfter(cert),3600);X509_set_pubkey(cert,key);
 X509_NAME*name=X509_get_subject_name(cert);X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(unsigned char*)"isolated-probe",-1,-1,0);
 X509_set_issuer_name(cert,name);assert(X509_sign(cert,key,EVP_sha256())>0);
}
static void pump(SSL*a,SSL*b){char buf[16384];int n;while((n=BIO_read(SSL_get_wbio(a),buf,sizeof(buf)))>0)assert(BIO_write(SSL_get_rbio(b),buf,n)==n);}
static size_t expected_size,received_size;static unsigned char expected[8*1024*1024];
static void deliver(SSL*peer){
 if(wire_size){assert(BIO_write(SSL_get_rbio(peer),wire,(int)wire_size)==(int)wire_size);wire_size=0;}
 char plain[32768];int n;
 for(;;){ERR_clear_error();n=SSL_read(peer,plain,sizeof(plain));if(n<=0)break;
  assert(received_size+n<=expected_size);assert(!memcmp(plain,expected+received_size,n));received_size+=n;}
 int e=SSL_get_error(peer,n);if(e!=SSL_ERROR_WANT_READ){ERR_print_errors_fp(stderr);fprintf(stderr,"peer failure=%d received=%zu expected=%zu\n",e,received_size,expected_size);abort();}
}
static void run(int version,int scenario){
 SSL_CTX*cc=SSL_CTX_new(TLS_client_method()),*sc=SSL_CTX_new(TLS_server_method());assert(cc&&sc);
 assert(SSL_CTX_set_min_proto_version(cc,version)&&SSL_CTX_set_max_proto_version(cc,version));
 assert(SSL_CTX_use_certificate(sc,cert)&&SSL_CTX_use_PrivateKey(sc,key));
 SSL*c=SSL_new(cc),*s=SSL_new(sc);assert(c&&s);
 SSL_set_bio(c,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_connect_state(c);
 SSL_set_bio(s,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem()));SSL_set_accept_state(s);
 for(int i=0;i<20&&!(SSL_is_init_finished(c)&&SSL_is_init_finished(s));++i){
  ERR_clear_error();int n=SSL_do_handshake(c);if(n<=0)assert(SSL_get_error(c,n)==SSL_ERROR_WANT_READ);pump(c,s);
  ERR_clear_error();n=SSL_do_handshake(s);if(n<=0)assert(SSL_get_error(s,n)==SSL_ERROR_WANT_READ);pump(s,c);}
 assert(SSL_is_init_finished(c)&&SSL_is_init_finished(s));ERR_clear_error();
 ILibAsyncSocketModule m={0};m.ssl=c;m.readBio=SSL_get_rbio(c);m.writeBio=SSL_get_wbio(c);
 BIO_get_mem_ptr(m.writeBio,&m.writeBioBuffer);m.FinConnect=m.SSLConnect=1;m.internalSocket=42;m.OnSendOK=on_send_ok;
 expected_size=received_size=wire_size=accepted_total=0;scheduled=zero_sends=send_ok=0;plan_count=plan_index=0;random_sends=0;
 if(scenario==1){plan[0]=1;plan[1]=-WSAEWOULDBLOCK;plan[2]=7;plan[3]=0;plan[4]=-WSAENOBUFS;plan_count=5;}
 if(scenario==2){plan[0]=0;plan_count=1;}
 if(scenario==3){random_sends=1;rng=123;}
 if(scenario==4){plan[0]=-WSAEINTR;plan_count=1;}
 if(scenario==5){
  plan[0]=-WSAECONNRESET;plan_count=1;
  int ret=ILibAsyncSocket_SendTo_MultiWrite(&m,NULL,1,"fatal",(size_t)5,ILibAsyncSocket_MemoryOwnership_STATIC);
  assert(ret==ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR&&scheduled==1&&m.SendLock==0);
  assert(m.diagnostics.nativeError==WSAECONNRESET&&!strcmp(m.diagnostics.stage,"send"));
  assert(accepted_total==0);goto cleanup;
 }
 for(int i=0;i<128;++i){
  int n=1000+(i*773)%32768;unsigned char b[33768];for(int j=0;j<n;++j)b[j]=(unsigned char)(i+j*71);
  memcpy(expected+expected_size,b,n);expected_size+=n;
  int split=n/2;
  int ret=ILibAsyncSocket_SendTo_MultiWrite(&m,NULL,2,(char*)b,(size_t)split,ILibAsyncSocket_MemoryOwnership_USER,
      (char*)b+split,(size_t)(n-split),ILibAsyncSocket_MemoryOwnership_USER);
  if(ret<0||scheduled){fprintf(stderr,"unexpected disconnect version=%x scenario=%d ret=%d scheduled=%d\n",version,scenario,ret,scheduled);abort();}
  memset(b,0xee,n); // Caller may reuse/free plaintext immediately after the call.
  if(i%4==0)drain(&m);deliver(s);
 }
 for(int i=0;m.PendingSend_Head&&i<100000;++i){drain(&m);deliver(s);}
 assert(!scheduled&&!m.PendingSend_Head&&!m.PendingPlain_Head);assert(received_size==expected_size);
 assert(m.PendingBytesToSend==0&&m.TotalBytesSent==accepted_total&&m.SendLock==0);
 if(scenario==2)assert(zero_sends==1&&send_ok>0);
cleanup:
 printf("PASS TLS %x scenario=%d bytes=%zu zeroSends=%d\n",version,scenario,received_size,zero_sends);
 SSL_free(c);SSL_free(s);SSL_CTX_free(cc);SSL_CTX_free(sc);ERR_clear_error();
}
int main(int argc,char**argv){setvbuf(stdout,NULL,_IONBF,0);initcert();
 for(int version=TLS1_2_VERSION;version<=TLS1_3_VERSION;++version)for(int scenario=0;scenario<6;++scenario){if(argc>1&&atoi(argv[1])!=scenario)continue;run(version,scenario);}
 X509_free(cert);EVP_PKEY_free(key);return 0;}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'microstack/ILibAsyncSocket.c')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--scenario', type=int, choices=range(6))
    parser.add_argument('--out', type=Path, default=ROOT / 'artifacts/validation/asyncsocket-tls-send')
    args = parser.parse_args()
    if platform.system() != 'Windows':
        parser.error('Requires Windows x64, Windows SDK, and Clang')
    source = args.source.read_text()
    # Extract the complete production send path and the unmodified PostSelect
    # write phase; select readiness/connect processing is outside this probe.
    funcs = '\n'.join(extract(source, name) for name in [
        'ILibAsyncSocket_ClearPendingPlain', 'ILibAsyncSocket_ClearPendingSend',
        'ILibAsyncSocket_TLSPendingBytes', 'ILibAsyncSocket_TLSQueuePlain',
        'ILibAsyncSocket_TLSFlushPendingPlain', 'ILibAsyncSocket_SendError',
        'ILibAsyncSocket_SendTo_MultiWrite'])
    post = extract(source, 'ILibAsyncSocket_PostSelect')
    marker = '\tILibSpinLock_Lock(&(module->SendLock));\n\t// Write Handling'
    assert post.count(marker) == 1
    write = post[post.index(marker):post.rfind('}')]
    drain = 'static void drain(ILibAsyncSocketModule *module) {\nvoid *socketModule=module;\nint fd_write=1,TRY_TO_SEND=1,bytesSent=0,sendError=0,sendDeferred=0,TriggerSendOK=0;\nILibAsyncSocket_SendData *temp;\n' + write + '\n}\n'
    args.out.mkdir(parents=True, exist_ok=True)
    fixture=args.out / 'probe.c'; exe=args.out / 'probe.exe'
    fixture.write_text(PRELUDE+funcs+drain+TESTS)
    command=[args.cc,'-std=c11','-g','-O1','-fsanitize=address,undefined','-I',str(ROOT/'openssl/include'),str(fixture)]
    command += [str(ROOT/'openssl/libstatic/libssl64MT.lib'),str(ROOT/'openssl/libstatic/libcrypto64MT.lib'),'-lcrypt32','-ladvapi32','-luser32','-lws2_32']
    command+=['-o',str(exe)]
    build = subprocess.run(command,capture_output=True,text=True)
    (args.out/'build.log').write_text(build.stdout+build.stderr)
    if build.returncode:
        print(build.stdout+build.stderr,end='')
        build.check_returncode()
    env=os.environ.copy(); compiler=shutil.which(args.cc)
    if compiler:
        runtimes=list(Path(compiler).parent.parent.glob('lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll'))
        if runtimes:env['PATH']=str(runtimes[0].parent)+os.pathsep+env.get('PATH','')
    result=subprocess.run([str(exe.resolve())]+([] if args.scenario is None else [str(args.scenario)]),capture_output=True,text=True,env=env,timeout=90)
    evidence='source_sha256='+hashlib.sha256(source.encode()).hexdigest()+'\n'+result.stdout+result.stderr
    (args.out/'results.txt').write_text(evidence);print(evidence,end='');result.check_returncode()


if __name__=='__main__':
    main()
