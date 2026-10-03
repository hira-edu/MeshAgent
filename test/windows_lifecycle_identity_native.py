"""Check lifecycle identity snapshots for historical exported-key databases."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'meshservice/service_deployment.c').read_text()
masked=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m.group()),source,flags=re.S)
def extract(name):
    match=re.search(r'static (?:BOOL|int) '+name+r'\s*\([^;{]+\)\s*\{',masked);assert match,name
    end,depth=match.end(),1
    while depth:depth+=(masked[end]=='{')-(masked[end]=='}');end+=1
    return source[match.start():end]

prelude=r'''
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#define UTIL_SHA384_HASHSIZE 48
typedef void* ILibSimpleDataStore;
typedef struct {char nodeId[1024],meshId[1024],serverId[1024],meshServer[1024];int nodeIdLen,meshIdLen,serverIdLen,meshServerLen;BOOL nodeIdPresent,meshIdPresent,serverIdPresent,meshServerPresent;} ServiceIdentitySnapshot;
typedef struct {wchar_t exePath[MAX_PATH],confPath[MAX_PATH],dbPath[MAX_PATH];} ServiceInstallPaths;
struct util_cert {X509* x509;EVP_PKEY* pkey;};
static unsigned char rootPfx[65536],expected[48];static int pfxLength,nodeLength,writes;
static int ILibSimpleDataStore_Get(ILibSimpleDataStore store,const char* key,char* out,int capacity){
    (void)store;const void* data=NULL;int length=0;
    if(!strcmp(key,"NodeID")){data=expected;length=nodeLength;}
    else if(!strcmp(key,"SelfNodeCert")){data=rootPfx;length=pfxLength;}
    else if(!strcmp(key,"MeshID")){data="mesh";length=4;}
    else if(!strcmp(key,"ServerID")){data="server";length=6;}
    else if(!strcmp(key,"MeshServer")){data="wss://server/agent.ashx";length=21;}
    if(out&&capacity>=length&&length)memcpy(out,data,length);return length;
}
static int util_from_p12(char* data,int length,char* password,struct util_cert* cert){
    const unsigned char* p=(unsigned char*)data;PKCS12* pk=d2i_PKCS12(NULL,&p,length);if(!pk)return 0;
    int ok=PKCS12_parse(pk,password,&cert->pkey,&cert->x509,NULL);PKCS12_free(pk);return ok;
}
static void util_freecert(struct util_cert* cert){X509_free(cert->x509);EVP_PKEY_free(cert->pkey);memset(cert,0,sizeof(*cert));}
static int util_keyhash(struct util_cert cert,char* result){unsigned int length=48;return X509_pubkey_digest(cert.x509,EVP_sha384(),(unsigned char*)result,&length)==1?0:-1;}
static void ServiceDeploy_LogInstallEvent(const wchar_t* format,...){(void)format;}
static BOOL ServiceDeploy_DataStoreValueExists(const wchar_t* db,const char* key,char* out,size_t cap,int* count){(void)db;int length=ILibSimpleDataStore_Get((void*)1,key,out,(int)cap);if(count)*count=length;return length>0;}
static BOOL ServiceDeploy_CaptureIdentitySnapshot(const wchar_t* path,ServiceIdentitySnapshot* snapshot);
static BOOL ServiceDeploy_ConfigHasRequiredKeys(const wchar_t* path){(void)path;return FALSE;}
static BOOL ServiceDeploy_BuildInstalledMshPath(const wchar_t* exe,wchar_t* out,size_t cap){(void)exe;if(cap<2)return FALSE;out[0]='x';out[1]=0;return TRUE;}
'''
cases=r'''
static BOOL ServiceDeploy_CaptureIdentitySnapshot(const wchar_t* path,ServiceIdentitySnapshot* snapshot){(void)path;return ServiceDeploy_CaptureIdentitySnapshotFromDataStore((void*)1,snapshot);}
int main(void){
    EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);EVP_PKEY* key=NULL;
    assert(ctx&&EVP_PKEY_keygen_init(ctx)>0&&EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,2048)>0&&EVP_PKEY_keygen(ctx,&key)>0);EVP_PKEY_CTX_free(ctx);
    X509* root=X509_new();assert(root);X509_set_version(root,2);ASN1_INTEGER_set(X509_get_serialNumber(root),1);
    X509_gmtime_adj(X509_getm_notBefore(root),-60);X509_gmtime_adj(X509_getm_notAfter(root),3600);X509_set_pubkey(root,key);
    X509_NAME* name=X509_get_subject_name(root);assert(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(unsigned char*)"Old exported agent root",-1,-1,0));
    assert(X509_set_issuer_name(root,name)&&X509_sign(root,key,EVP_sha256())>0);unsigned int len=48;assert(X509_pubkey_digest(root,EVP_sha384(),expected,&len));
    PKCS12* pk=PKCS12_create("hidden","Root",key,root,NULL,0,0,0,0,0);assert(pk);unsigned char* encoded=NULL;
    pfxLength=i2d_PKCS12(pk,&encoded);assert(pfxLength>0&&pfxLength<sizeof(rootPfx));memcpy(rootPfx,encoded,pfxLength);OPENSSL_free(encoded);PKCS12_free(pk);
    ServiceIdentitySnapshot snapshot;assert(ServiceDeploy_CaptureIdentitySnapshotFromDataStore((void*)1,&snapshot));
    assert(snapshot.nodeIdPresent&&snapshot.nodeIdLen==48&&!memcmp(snapshot.nodeId,expected,48));
    ServiceInstallPaths paths={0};assert(ServiceDeploy_InstalledProvisioningHealthy(&paths,NULL,0));assert(writes==0);
    nodeLength=2048;assert(!ServiceDeploy_CaptureIdentitySnapshotFromDataStore((void*)1,&snapshot));assert(writes==0);
    nodeLength=0;pfxLength=1;assert(!ServiceDeploy_CaptureIdentitySnapshotFromDataStore((void*)1,&snapshot));
    X509_free(root);EVP_PKEY_free(key);puts("Lifecycle identity: old PKCS12-derived NodeID and malformed snapshots passed");return 0;
}
'''
production=extract('ServiceDeploy_CaptureIdentitySnapshotFromDataStore')
if 'static BOOL ServiceDeploy_DataStoreIdentityPresent' in source:
    production+=extract('ServiceDeploy_DataStoreIdentityPresent')
production+=extract('ServiceDeploy_InstalledProvisioningHealthy')
with tempfile.TemporaryDirectory(prefix='lifecycle-identity-') as temporary:
    path=Path(temporary);c=path/'fixture.c';exe=path/'fixture.exe';c.write_text(prelude+production+cases)
    subprocess.run([os.environ.get('CC','clang'),'-std=c11','-I',str(ROOT/'openssl/include'),str(c),str(ROOT/'openssl/libstatic/libcrypto64MT.lib'),'-lcrypt32','-ladvapi32','-luser32','-lws2_32','-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
