"""Exercise the production certificate loader with real signed X509 identities.

The Windows store boundary is injected so names, missing keys and duplicates are
deterministic. DER parsing, key hashes and signature verification use OpenSSL.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/agentcore.c').read_text()
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                lambda m: ' ' * len(m.group()), source, flags=re.S)

def extract(name):
    match = re.search(r'(?:static )?int ' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}'); end += 1
    return source[match.start():end]

prelude = r'''
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#ifndef WIN32
#define WIN32 1
#endif
#define UTIL_SHA384_HASHSIZE 48
#define CERTIFICATE_TLS_SERVER 2
#define MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY 8
#define SSL_TRACE1(...) ((void)0)
#define SSL_TRACE2(...) ((void)0)
#define ILIBLOGMESSAGEX(...) ((void)0)
#define ILibRemoteLogging_printf(...) ((void)0)
typedef void* wincrypto_object;
typedef int (*wincrypto_cert_match)(const unsigned char*, int, void*);
struct util_cert { X509* x509; EVP_PKEY* pkey; };
typedef struct { void* masterDb; int noCertStore; char* meshServiceName; int capabilities;
    wincrypto_object certObject; struct util_cert selfcert, selftlscert; char g_selfid[48]; void* chain; } MeshAgentHostContainer;
static char ILibScratchPad2[65536];
static X509 *oldRoot, *newRoot, *tls;
static EVP_PKEY *oldKey, *newKey, *tlsKey;
static unsigned char expected[48], tlsP12[65536], rootP12[65536]; static int tlsLength, rootLength, storedRootLength;
static int nodeLength, tlsPresent, keysPresent, opens, creations, writes, renewalMode, writeFailure;
static void util_freecert(struct util_cert* cert) { X509_free(cert->x509); EVP_PKEY_free(cert->pkey); memset(cert,0,sizeof(*cert)); }
static void util_free(void* p) { OPENSSL_free(p); }
static int util_from_cer(char* str, int len, struct util_cert* cert) {
    const unsigned char* p=(unsigned char*)str; util_freecert(cert); cert->x509=d2i_X509(NULL,&p,len); return cert->x509!=NULL;
}
static int util_from_p12(char* str,int len,const char* password,struct util_cert* cert) {
    const unsigned char* p=(unsigned char*)str; PKCS12* pk=d2i_PKCS12(NULL,&p,len); if(!pk)return 0;
    util_freecert(cert); int ok=PKCS12_parse(pk,password,&cert->pkey,&cert->x509,NULL); PKCS12_free(pk); return ok;
}
static int util_keyhash(struct util_cert cert,char* hash) { unsigned int len=48; return X509_pubkey_digest(cert.x509,EVP_sha384(),(unsigned char*)hash,&len)==1?0:-1; }
static int ILibSimpleDataStore_Get(void* store,const char* key,char* out,int capacity) {
    (void)store; const unsigned char* data=NULL; int len=0;
    if(!strcmp(key,"NodeID")){data=expected;len=nodeLength;}
    if(!strcmp(key,"SelfNodeCert")){data=rootP12;len=storedRootLength;}
    if(!strcmp(key,"SelfNodeTlsCert")&&tlsPresent){data=tlsP12;len=tlsLength;}
    if(out&&capacity>=len&&len)memcpy(out,data,len); return len;
}
static int ILibSimpleDataStore_PutEx(void* store,const char* key,int keylen,char* value,int len) {
    (void)store;(void)key;(void)keylen;(void)value;(void)len;++writes;return writeFailure ? -1 : 0;
}
static int ILibSimpleDataStore_WasCreatedAsNew(void* store) { (void)store;return 0; }
static void wincrypto_close(wincrypto_object object) { (void)object; }
static wincrypto_object wincrypto_open(int create,char* name) { (void)name;++opens;creations+=!!create;return newRoot; }
static int wincrypto_getcert(char** str,wincrypto_object object) {
    static unsigned char buffer[65536];unsigned char* cursor=buffer;*str=(char*)buffer;
    return i2d_X509((X509*)object,&cursor);
}
static wincrypto_object wincrypto_open_existing(wincrypto_cert_match match,void* user) {
    X509* roots[]={newRoot,oldRoot}; if(!keysPresent)return NULL;
    for(int i=0;i<2;++i){unsigned char* der=NULL;int len=i2d_X509(roots[i],&der);int found=match(der,len,user);OPENSSL_free(der);if(found)return roots[i];}return NULL;
}
static int wincrypto_mkCert(wincrypto_object object,char* root,wchar_t* subject,int type,wchar_t* password,char** str) {
    (void)object;(void)root;(void)subject;(void)type;(void)password;*str=NULL;if(!renewalMode)return 0;
    PKCS12* pfx=PKCS12_create("hidden","Renewed TLS",renewalMode==2?NULL:tlsKey,tls,NULL,0,0,0,0,0);assert(pfx);
    int length=i2d_PKCS12(pfx,(unsigned char**)str);PKCS12_free(pfx);return length;
}
static int agent_VerifyMeshCertificates(MeshAgentHostContainer* agent) {
    if(!agent->selftlscert.x509)return 0;
    EVP_PKEY* key=X509_get_pubkey(agent->selfcert.x509);int ok=X509_verify(agent->selftlscert.x509,key);EVP_PKEY_free(key);return ok==1?0:1;
}
'''
cases = r'''
static EVP_PKEY* key(void) { EVP_PKEY_CTX* c=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL); EVP_PKEY* p=NULL;
    assert(c&&EVP_PKEY_keygen_init(c)>0&&EVP_PKEY_CTX_set_rsa_keygen_bits(c,2048)>0&&EVP_PKEY_keygen(c,&p)>0);EVP_PKEY_CTX_free(c);return p; }
static X509* certificate(const char* name,EVP_PKEY* k,X509* issuer,EVP_PKEY* signer) {
    X509* c=X509_new();assert(c);X509_set_version(c,2);ASN1_INTEGER_set(X509_get_serialNumber(c),1);
    X509_gmtime_adj(X509_getm_notBefore(c),-60);X509_gmtime_adj(X509_getm_notAfter(c),3600);X509_set_pubkey(c,k);
    X509_NAME* n=X509_get_subject_name(c);assert(X509_NAME_add_entry_by_txt(n,"CN",MBSTRING_ASC,(const unsigned char*)name,-1,-1,0));
    assert(X509_set_issuer_name(c,issuer?X509_get_subject_name(issuer):n));assert(X509_sign(c,signer?signer:k,EVP_sha256())>0);return c;
}
static void setup(void) {
    opens=creations=writes=storedRootLength=renewalMode=writeFailure=0;nodeLength=48;tlsPresent=keysPresent=1;
    unsigned int len=48;assert(X509_pubkey_digest(oldRoot,EVP_sha384(),expected,&len));
}
static MeshAgentHostContainer agent(void) { MeshAgentHostContainer a={0};a.meshServiceName="WinDiagnosticHost";return a; }
static void cleanup(MeshAgentHostContainer* a) { util_freecert(&a->selfcert);util_freecert(&a->selftlscert); }
int main(void) {
    oldKey=key();newKey=key();tlsKey=key();oldRoot=certificate("MeshNodeCertificateNG",oldKey,NULL,NULL);
    newRoot=certificate("WinDiagnosticHost_NodeCertificate",newKey,NULL,NULL);tls=certificate("localhost",tlsKey,oldRoot,oldKey);
    PKCS12* p12=PKCS12_create("hidden","TLS",tlsKey,tls,NULL,0,0,0,0,0);assert(p12);
    unsigned char* der=NULL;tlsLength=i2d_PKCS12(p12,&der);assert(tlsLength>0&&tlsLength<sizeof(tlsP12));memcpy(tlsP12,der,tlsLength);OPENSSL_free(der);PKCS12_free(p12);
    p12=PKCS12_create("hidden","Root",oldKey,oldRoot,NULL,0,0,0,0,0);assert(p12);der=NULL;
    rootLength=i2d_PKCS12(p12,&der);assert(rootLength>0&&rootLength<sizeof(rootP12));memcpy(rootP12,der,rootLength);OPENSSL_free(der);PKCS12_free(p12);
    setup();MeshAgentHostContainer a=agent();assert(agent_LoadCertificates(&a)==0);
    assert(!memcmp(a.g_selfid,expected,48));assert(opens==0&&creations==0&&writes==0);cleanup(&a);
    setup();nodeLength=0;a=agent();assert(agent_LoadCertificates(&a)==0);assert(!memcmp(a.g_selfid,expected,48));cleanup(&a);
    setup();tlsPresent=0;renewalMode=1;a=agent();assert(agent_LoadCertificates(&a)==0&&writes==1&&!memcmp(a.g_selfid,expected,48));cleanup(&a);
    setup();tlsPresent=0;a=agent();assert(agent_LoadCertificates(&a)==2&&writes==0&&creations==0);cleanup(&a);
    setup();tlsPresent=0;renewalMode=2;a=agent();assert(agent_LoadCertificates(&a)==2&&writes==0&&creations==0);cleanup(&a);
    setup();tlsPresent=0;renewalMode=writeFailure=1;a=agent();assert(agent_LoadCertificates(&a)==2&&writes==1&&creations==0);cleanup(&a);
    setup();tlsPresent=0;renewalMode=1;assert(X509_sign(tls,newKey,EVP_sha256())>0);a=agent();assert(agent_LoadCertificates(&a)==2&&writes==0);cleanup(&a);
    assert(X509_sign(tls,oldKey,EVP_sha256())>0);
    setup();keysPresent=0;a=agent();assert(agent_LoadCertificates(&a)==2);assert(opens==0&&creations==0&&writes==0);cleanup(&a);
    setup();nodeLength=47;a=agent();assert(agent_LoadCertificates(&a)==2);assert(opens==0&&writes==0);cleanup(&a);
    setup();memset(expected,0x6b,48);a=agent();assert(agent_LoadCertificates(&a)==2);assert(opens==0&&writes==0);cleanup(&a);
    setup();storedRootLength=rootLength;keysPresent=0;a=agent();assert(agent_LoadCertificates(&a)==0);
    assert(!memcmp(a.g_selfid,expected,48)&&opens==0&&writes==0);cleanup(&a);
    setup();storedRootLength=rootLength;memset(expected,0x6b,48);a=agent();assert(agent_LoadCertificates(&a)==2);assert(opens==0&&writes==0);cleanup(&a);
    setup();storedRootLength=1;a=agent();assert(agent_LoadCertificates(&a)==2);assert(opens==0&&writes==0);cleanup(&a);
    p12=PKCS12_create("hidden","Public root",NULL,oldRoot,NULL,0,0,0,0,0);assert(p12);der=NULL;
    storedRootLength=i2d_PKCS12(p12,&der);assert(storedRootLength>0&&storedRootLength<sizeof(rootP12));
    memcpy(rootP12,der,storedRootLength);OPENSSL_free(der);PKCS12_free(p12);
    a=agent();assert(agent_LoadCertificates(&a)==2);assert(opens==0&&writes==0);cleanup(&a);
    setup();nodeLength=tlsPresent=0;a=agent();a.noCertStore=1;assert(agent_LoadCertificates(&a)==1);assert(opens==0&&writes==0);cleanup(&a);
    setup();nodeLength=tlsPresent=0;a=agent();assert(agent_LoadCertificates(&a)==1);assert(opens==0&&creations==0&&writes==0);cleanup(&a);
    X509_free(oldRoot);X509_free(newRoot);X509_free(tls);EVP_PKEY_free(oldKey);EVP_PKEY_free(newKey);EVP_PKEY_free(tlsKey);
    puts("Certificate identity: CNG rename, old DB, PKCS12, missing key, malformed and mismatched identity, fresh OpenSSL passed");return 0;
}
'''
helpers = ''
if 'agent_CertificateMatchesIdentity' in source:
    helpers = extract('agent_CertificateMatchesIdentity')
with tempfile.TemporaryDirectory(prefix='certificate-identity-') as temporary:
    path = Path(temporary); c = path / 'fixture.c'; exe = path / 'fixture.exe'
    c.write_text(prelude + helpers + extract('agent_LoadCertificates') + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-I', str(ROOT / 'openssl/include'),
                    str(c), str(ROOT / 'openssl/libstatic/libcrypto64MT.lib'), '-lcrypt32', '-ladvapi32', '-luser32', '-lws2_32', '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
