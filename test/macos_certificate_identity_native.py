#!/usr/bin/env python3
"""Exercise the macOS certificate loader using real PKCS12 and X509 identities."""
import os
from pathlib import Path
import platform
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/agentcore.c').read_text()
start = source.index('int agent_LoadCertificates(')
body = source[start:source.index('\nint agent_VerifyMeshCertificates(', start)]
prelude = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#ifndef __APPLE__
#define __APPLE__ 1
#endif
#define UTIL_SHA384_HASHSIZE 48
#define SSL_TRACE1(...) ((void)0)
#define SSL_TRACE2(...) ((void)0)
#define ILIBLOGMESSAGEX(...) ((void)0)
#define ILibRemoteLogging_printf(...) ((void)0)
struct util_cert { X509 *x509; EVP_PKEY *pkey; };
typedef struct { void *masterDb; struct util_cert selfcert,selftlscert; char g_selfid[48]; } MeshAgentHostContainer;
static char ILibScratchPad2[65536];
static unsigned char rootP12[65536],tlsP12[65536],expected[48];
static int rootLength,tlsLength,nodeLength,hashFailure;
static void util_freecert(struct util_cert *c) { X509_free(c->x509);EVP_PKEY_free(c->pkey);memset(c,0,sizeof(*c)); }
static int util_from_p12(char *data,int length,const char *password,struct util_cert *c) {
    const unsigned char *cursor=(unsigned char*)data;PKCS12 *p=d2i_PKCS12(NULL,&cursor,length);
    if(!p)return 0;util_freecert(c);int ok=PKCS12_parse(p,password,&c->pkey,&c->x509,NULL);PKCS12_free(p);return ok;
}
static int util_keyhash(struct util_cert c,char *hash) {
    unsigned int length=48;if(hashFailure)return -1;
    return X509_pubkey_digest(c.x509,EVP_sha384(),(unsigned char*)hash,&length)==1?0:-1;
}
static int ILibSimpleDataStore_Get(void *db,const char *key,char *out,int capacity) {
    (void)db;const unsigned char *data=NULL;int length=0;
    if(!strcmp(key,"SelfNodeCert")){data=rootP12;length=rootLength;}
    if(!strcmp(key,"SelfNodeTlsCert")){data=tlsP12;length=tlsLength;}
    if(!strcmp(key,"NodeID")){data=expected;length=nodeLength;}
    if(out && length>0 && length<=capacity)memcpy(out,data,length);return length;
}
static int ILibSimpleDataStore_WasCreatedAsNew(void *db) { (void)db;return 0; }
'''
main = r'''
static int pack(X509 *cert,EVP_PKEY *key,unsigned char *out) {
    PKCS12 *p=PKCS12_create("hidden","Identity",key,cert,NULL,0,0,0,0,0);assert(p);
    int n=i2d_PKCS12(p,NULL);assert(n>0 && n<65536);unsigned char *cursor=out;
    assert(i2d_PKCS12(p,&cursor)==n);PKCS12_free(p);return n;
}
static void check(int status) {
    MeshAgentHostContainer a={0};assert(agent_LoadCertificates(&a)==status);
    if(status==0)assert(!memcmp(a.g_selfid,expected,48));
    util_freecert(&a.selfcert);util_freecert(&a.selftlscert);
}
int main(void) {
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);EVP_PKEY *key=NULL;
    assert(ctx && EVP_PKEY_keygen_init(ctx)>0 && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,2048)>0 && EVP_PKEY_keygen(ctx,&key)>0);
    EVP_PKEY_CTX_free(ctx);X509 *cert=X509_new();assert(cert);
    X509_set_version(cert,2);ASN1_INTEGER_set(X509_get_serialNumber(cert),1);
    X509_gmtime_adj(X509_getm_notBefore(cert),-60);X509_gmtime_adj(X509_getm_notAfter(cert),3600);X509_set_pubkey(cert,key);
    X509_NAME *name=X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(unsigned char*)"Historical MeshAgent",-1,-1,0));
    assert(X509_set_issuer_name(cert,name));assert(X509_sign(cert,key,EVP_sha256())>0);
    unsigned int length=48;assert(X509_pubkey_digest(cert,EVP_sha384(),expected,&length));
    int validRoot=pack(cert,key,rootP12),validTLS=pack(cert,key,tlsP12);
    rootLength=validRoot;tlsLength=validTLS;nodeLength=48;check(0);
    nodeLength=0;check(0); // Historical DB stores identity only in PKCS12.
    tlsLength=0;check(0); // Missing optional TLS certificate preserves root identity.
    rootLength=0;check(1); // Truly fresh install.
    nodeLength=48;check(2);nodeLength=0;tlsLength=validTLS;check(2);
    rootLength=1;tlsLength=0;check(2); // Corrupt root must never regenerate.
    rootLength=65537;check(2); // Oversized root record.
    rootLength=validRoot;tlsLength=1;check(2);tlsLength=65537;check(2);
    tlsLength=0;nodeLength=47;check(2);nodeLength=48;expected[0]^=1;check(2);expected[0]^=1;
    hashFailure=1;check(2);hashFailure=0;
    rootLength=pack(cert,NULL,rootP12);check(2); // Public certificate without private key.
    rootLength=pack(cert,key,rootP12);tlsLength=pack(cert,NULL,tlsP12);check(2);
    X509_free(cert);EVP_PKEY_free(key);
    puts("PASS: macOS PKCS12 identity retention; fresh versus corrupt, missing keys, mismatched NodeID and failed hash");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-mac-identity-') as folder:
    target = Path(folder)
    (target / 'probe.c').write_text(prelude + body + main)
    arch = 'osx-arm-64' if platform.machine() == 'arm64' else 'osx-x86-64'
    library = root / 'openssl/libstatic/macos' / arch / 'libcrypto.a'
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-fsanitize=address,undefined',
                    '-I', str(root / 'openssl/include'), str(target/'probe.c'), str(library),
                    '-o', str(target/'probe')], check=True)
    subprocess.run([str(target/'probe')], check=True)
