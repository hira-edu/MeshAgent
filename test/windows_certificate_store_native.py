"""Validate read-only production lookup against a real disposable Windows CNG key.

The fixture uses unique key names and removes its certificates and keys on exit;
it never opens or modifies the service account's store or agent identity.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/wincrypto.cpp').read_text()
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                lambda m: ' ' * len(m.group()), source, flags=re.S)

def extract(name, text=source):
    masked_text = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                         lambda m: ' ' * len(m.group()), text, flags=re.S)
    match = re.search(r'(?:void|int|wincrypto_object)\s+__fastcall\s+' + name + r'\s*\([^;{]+\)\s*\{', masked_text)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked_text[end] == '{') - (masked_text[end] == '}'); end += 1
    return text[match.start():end]

prelude = r'''
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#define _CONSOLE 1
#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#define ILibMemory_SmartAllocate(size) calloc(1,size)
#define ILibMemory_Free(pointer) free(pointer)
#define ILIBCRITICALEXIT(code) exit(code)
typedef void* wincrypto_object;
typedef int (*wincrypto_cert_match)(const unsigned char*,int,void*);
typedef struct wincrypto_data { HCRYPTPROV hProv; HANDLE hCertStore; PCCERT_CONTEXT certCtx; } wincrypto_data;
static WCHAR tlsFixtureName[128];
static DWORD storeLocation=CERT_SYSTEM_STORE_CURRENT_USER, machineKeyFlag=0, capiMachineFlag=0;
static const char* wincrypto_ServerOids[]={"1.3.6.1.5.5.7.3.1"};
static const char* wincrypto_ClientOids[]={"1.3.6.1.5.5.7.3.2","2.16.840.1.113741.1.2.2","2.16.840.1.113741.1.2.3","2.16.840.1.113741.1.2.1"};
static int renewalActive, renewalAllocations, exportCalls, failExport;
static void* allocations[64];static WCHAR generatedName[128];static DWORD generatedFlags;
static void* trackedMalloc(size_t size){void* p=malloc(size);if(renewalActive&&p){int i=0;while(i<64&&allocations[i])++i;assert(i<64);allocations[i]=p;++renewalAllocations;}return p;}
static void trackedFree(void* p){if(p){for(int i=0;i<64;++i){if(allocations[i]==p){allocations[i]=NULL;--renewalAllocations;break;}}}free(p);}
static SECURITY_STATUS trackedCreate(NCRYPT_PROV_HANDLE provider,NCRYPT_KEY_HANDLE* key,LPCWSTR algorithm,LPCWSTR name,DWORD spec,DWORD flags){
    if(renewalActive){assert(name);wcscpy_s(generatedName,_countof(generatedName),name);generatedFlags=flags;printf("tlsFixtureKey=%ls\n",name);fflush(stdout);}
    return NCryptCreatePersistedKey(provider,key,algorithm,name,spec,flags);
}
static BOOL trackedExport(HCERTSTORE store,CRYPT_DATA_BLOB* blob,LPCWSTR password,DWORD flags){
    if(renewalActive){++exportCalls;if(exportCalls==failExport){SetLastError(NTE_FAIL);return FALSE;}
        if(failExport==3&&exportCalls==1){PCCERT_CONTEXT certificate=CertEnumCertificatesInStore(store,NULL);assert(certificate);
            assert(CertSetCertificateContextProperty(certificate,CERT_KEY_PROV_INFO_PROP_ID,0,NULL));CertFreeCertificateContext(certificate);}}
    return PFXExportCertStore(store,blob,password,flags);
}
#define malloc trackedMalloc
#define free trackedFree
#define NCryptCreatePersistedKey trackedCreate
#define PFXExportCertStore trackedExport
'''
cases = r'''
static int match(const unsigned char* der,int length,void* user) {
    PCCERT_CONTEXT expected=(PCCERT_CONTEXT)user;
    return expected&&length==(int)expected->cbCertEncoded&&!memcmp(der,expected->pbCertEncoded,length);
}
static int signature(wincrypto_object object) {
    char payload[]="Historical agent signature fixture";char* signedData=NULL;
    int length=wincrypto_sign(object,payload,sizeof(payload),&signedData);if(length<=0)return 0;
    CRYPT_VERIFY_MESSAGE_PARA verify={0};verify.cbSize=sizeof(verify);verify.dwMsgAndCertEncodingType=MY_ENCODING_TYPE;
    BYTE output[256];DWORD outputLength=sizeof(output);
    BOOL ok=CryptVerifyMessageSignature(&verify,0,(BYTE*)signedData,length,output,&outputLength,NULL);
    free(signedData);return ok&&outputLength==sizeof(payload)&&!memcmp(payload,output,outputLength);
}
static void renewal(wincrypto_object object,PCCERT_CONTEXT issuer,int exportFailure){
    char* pfx=NULL;CRYPT_DATA_BLOB blob={0};HCERTSTORE store=NULL;PCCERT_CONTEXT certificate=NULL;
    assert(!renewalAllocations);exportCalls=0;failExport=exportFailure;generatedName[0]=0;renewalActive=1;
    blob.cbData=wincrypto_mkCert(object,(char*)"CN=A renamed product",(wchar_t*)L"CN=localhost",1,(wchar_t*)L"hidden",&pfx);
    renewalActive=0;
    assert(renewalAllocations==(exportFailure?0:1));
    assert(generatedName[0]&&!(generatedFlags&NCRYPT_OVERWRITE_KEY_FLAG));
    NCRYPT_PROV_HANDLE provider=0;NCRYPT_KEY_HANDLE key=0;assert(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)==ERROR_SUCCESS);
    assert(NCryptOpenKey(provider,&key,generatedName,0,0)!=ERROR_SUCCESS);NCryptFreeObject(provider);
    if(exportFailure){assert(!blob.cbData&&!pfx);return;}
    assert(blob.cbData&&pfx);blob.pbData=(BYTE*)pfx;
    store=PFXImportCertStore(&blob,L"hidden",CRYPT_USER_KEYSET|PKCS12_NO_PERSIST_KEY);assert(store);
    certificate=CertEnumCertificatesInStore(store,NULL);assert(certificate);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE privateKey=0;DWORD spec=0;BOOL release=FALSE;
    assert(CryptAcquireCertificatePrivateKey(certificate,CRYPT_ACQUIRE_CACHE_FLAG|CRYPT_ACQUIRE_SILENT_FLAG|CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,NULL,&privateKey,&spec,&release));
    if(release){if(spec==CERT_NCRYPT_KEY_SPEC)NCryptFreeObject(privateKey);else CryptReleaseContext(privateKey,0);}
    assert(CertCompareCertificateName(X509_ASN_ENCODING,&certificate->pCertInfo->Issuer,&issuer->pCertInfo->Subject));
    assert(CryptVerifyCertificateSignatureEx(0,X509_ASN_ENCODING,CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,(void*)certificate,
        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,(void*)issuer,0,NULL));
    CertFreeCertificateContext(certificate);CertCloseStore(store,0);free(pfx);assert(!renewalAllocations);
}
static BOOL fixtureKeyName(LPCWSTR name,DWORD pid){
    WCHAR prefix[128];const WCHAR* types[]={L"identity",L"tls"};
    for(int i=0;i<2;++i){swprintf_s(prefix,_countof(prefix),L"MeshAgent-%ls-fixture-%lu-",types[i],pid);if(!_wcsnicmp(name,prefix,wcslen(prefix)))return TRUE;}
    DWORD providers[]={PROV_RSA_AES,PROV_RSA_FULL};for(int i=0;i<2;++i){swprintf_s(prefix,_countof(prefix),L"MeshAgent-CAPI-fixture-%lu-%lu-",providers[i],pid);if(!_wcsnicmp(name,prefix,wcslen(prefix)))return TRUE;}
    return FALSE;
}
static int cleanupFixture(DWORD pid,int argc,char** argv){
    if(!pid)return 1;int result=0;HCERTSTORE store=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,0,CERT_SYSTEM_STORE_CURRENT_USER,L"MY");
    if(!store)return 1;PCCERT_CONTEXT certificate=NULL;
    while((certificate=CertEnumCertificatesInStore(store,certificate))!=NULL){
        DWORD size=0;if(!CertGetCertificateContextProperty(certificate,CERT_KEY_PROV_INFO_PROP_ID,NULL,&size)||size>65536)continue;
        CRYPT_KEY_PROV_INFO* info=(CRYPT_KEY_PROV_INFO*)malloc(size);if(!info){result=1;break;}
        if(CertGetCertificateContextProperty(certificate,CERT_KEY_PROV_INFO_PROP_ID,info,&size)&&info->pwszContainerName&&fixtureKeyName(info->pwszContainerName,pid)){
            if(info->dwProvType){HCRYPTPROV provider=0;if(!CryptAcquireContextW(&provider,info->pwszContainerName,info->pwszProvName,info->dwProvType,CRYPT_DELETEKEYSET))result=1;}
            if(!CertDeleteCertificateFromStore(CertDuplicateCertificateContext(certificate)))result=1;
        }free(info);
    }if(certificate)CertFreeCertificateContext(certificate);CertCloseStore(store,0);
    NCRYPT_PROV_HANDLE provider=0;void* state=NULL;NCryptKeyName* name=NULL;WCHAR ownedNames[64][128];int count=0;
    if(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)!=ERROR_SUCCESS)return 1;
    while(NCryptEnumKeys(provider,NULL,&name,&state,0)==ERROR_SUCCESS){
        BOOL owned=fixtureKeyName(name->pszName,pid);
        for(int i=3;i<argc&&!owned;++i){WCHAR supplied[128];if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,argv[i],-1,supplied,_countof(supplied))&&
            wcslen(supplied)==46&&!wcsncmp(supplied,L"MeshAgent-TLS-",14)&&wcsspn(supplied+14,L"0123456789abcdef")==32&&!wcscmp(supplied,name->pszName))owned=TRUE;}
        if(owned){if(count>=64||wcslen(name->pszName)>=128)result=1;else wcscpy_s(ownedNames[count++],128,name->pszName);}
        NCryptFreeBuffer(name);name=NULL;
    }if(state)NCryptFreeBuffer(state);
    for(int i=0;i<count;++i){NCRYPT_KEY_HANDLE key=0;if(NCryptOpenKey(provider,&key,ownedNames[i],0,0)!=ERROR_SUCCESS)result=1;
        else if(NCryptDeleteKey(key,0)!=ERROR_SUCCESS){NCryptFreeObject(key);result=1;}}
    NCryptFreeObject(provider);return result;
}
static int classic(DWORD type,LPCWSTR providerName,DWORD spec) {
    WCHAR name[128];HCRYPTPROV provider=0,deleted=0;HCRYPTKEY key=0;
    HCERTSTORE store=NULL;PCCERT_CONTEXT created=NULL,stored=NULL;wincrypto_object found=NULL;int result=0;
    BYTE encoded[256];DWORD encodedLength=sizeof(encoded);CERT_NAME_BLOB subject;CRYPT_KEY_PROV_INFO info={0};
    CRYPT_ALGORITHM_IDENTIFIER algorithm={0};
    swprintf_s(name,_countof(name),L"MeshAgent-CAPI-fixture-%lu-%lu-%llu",type,GetCurrentProcessId(),GetTickCount64());
    if(!CryptAcquireContextW(&provider,name,providerName,type,CRYPT_NEWKEYSET|capiMachineFlag))goto done;
    if(!CryptGenKey(provider,spec,2048UL<<16,&key))goto done;
    if(!CertStrToNameW(X509_ASN_ENCODING,L"CN=MeshNodeCertificate",CERT_X500_NAME_STR,NULL,encoded,&encodedLength,NULL))goto done;
    subject.cbData=encodedLength;subject.pbData=encoded;info.pwszContainerName=name;info.pwszProvName=(LPWSTR)providerName;
    info.dwProvType=type;info.dwKeySpec=spec;info.dwFlags=capiMachineFlag;algorithm.pszObjId=(LPSTR)szOID_RSA_SHA256RSA;
    created=CertCreateSelfSignCertificate(provider,&subject,0,&info,&algorithm,NULL,NULL,NULL);if(!created)goto done;
    store=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,0,storeLocation,L"MY");if(!store)goto done;
    if(!CertAddCertificateContextToStore(store,created,CERT_STORE_ADD_NEW,&stored))goto done;
    found=wincrypto_open_existing(match,(void*)stored);if(!found||!signature(found))goto done;
    renewal(found,stored,0);
    result=1;
done:
    if(found)wincrypto_close(found);
    if(stored)CertDeleteCertificateFromStore(stored);
    if(created)CertFreeCertificateContext(created);
    if(store)CertCloseStore(store,0);
    if(key)CryptDestroyKey(key);
    if(provider){CryptReleaseContext(provider,0);CryptAcquireContextW(&deleted,name,providerName,type,CRYPT_DELETEKEYSET|capiMachineFlag);}
    return result;
}
int main(int argc,char** argv) {
    if(argc>=3&&!strcmp(argv[1],"--cleanup-fixture"))return cleanupFixture(strtoul(argv[2],NULL,10),argc,argv);
    (void)argv;if(argc>1){storeLocation=CERT_SYSTEM_STORE_LOCAL_MACHINE;machineKeyFlag=NCRYPT_MACHINE_KEY_FLAG;capiMachineFlag=CRYPT_MACHINE_KEYSET;}
    NCRYPT_PROV_HANDLE provider=0; NCRYPT_KEY_HANDLE key=0,opened=0;
    HCERTSTORE store=NULL,imported=NULL; PCCERT_CONTEXT created=NULL,stored=NULL,renewed=NULL; wincrypto_object found=NULL;
    char* pfx=NULL; CRYPT_DATA_BLOB pfxBlob={0};
    int result=1; WCHAR keyName[128]; BYTE subjectBytes[256]; DWORD subjectLength=sizeof(subjectBytes);
    CERT_NAME_BLOB subject; CRYPT_KEY_PROV_INFO info={0}; CRYPT_ALGORITHM_IDENTIFIER algorithm={0};
    swprintf_s(keyName,_countof(keyName),L"MeshAgent-identity-fixture-%lu-%llu",GetCurrentProcessId(),GetTickCount64());
    swprintf_s(tlsFixtureName,_countof(tlsFixtureName),L"MeshAgent-tls-fixture-%lu-%llu",GetCurrentProcessId(),GetTickCount64());
    if(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)!=ERROR_SUCCESS)goto cleanup;
    if(NCryptCreatePersistedKey(provider,&key,BCRYPT_RSA_ALGORITHM,keyName,0,machineKeyFlag)!=ERROR_SUCCESS)goto cleanup;
    if(NCryptFinalizeKey(key,0)!=ERROR_SUCCESS)goto cleanup;
    if(!CertStrToNameW(X509_ASN_ENCODING,L"CN=MeshAgent Disposable Certificate Lookup Fixture",CERT_X500_NAME_STR,NULL,subjectBytes,&subjectLength,NULL))goto cleanup;
    subject.cbData=subjectLength;subject.pbData=subjectBytes;
    info.pwszContainerName=keyName;info.pwszProvName=(LPWSTR)MS_KEY_STORAGE_PROVIDER;info.dwFlags=capiMachineFlag;
    algorithm.pszObjId=(LPSTR)szOID_RSA_SHA256RSA;
    created=CertCreateSelfSignCertificate(key,&subject,0,&info,&algorithm,NULL,NULL,NULL);if(!created)goto cleanup;
    store=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,0,storeLocation,L"MY");if(!store)goto cleanup;
    if(!CertAddCertificateContextToStore(store,created,CERT_STORE_ADD_NEW,&stored))goto cleanup;
    found=wincrypto_open_existing(match,(void*)stored);
    if(!found||!wincrypto_isopen(found)||!match(((wincrypto_data*)found)->certCtx->pbCertEncoded,
        ((wincrypto_data*)found)->certCtx->cbCertEncoded,(void*)stored))goto cleanup;
    if(!signature(found))goto cleanup;
    renewal(found,stored,0);WCHAR previousName[128];wcscpy_s(previousName,_countof(previousName),generatedName);
    renewal(found,stored,0);assert(wcscmp(previousName,generatedName));renewal(found,stored,1);renewal(found,stored,2);renewal(found,stored,3);
    pfxBlob.cbData=wincrypto_mkCert(found,(char*)"CN=A renamed product",(wchar_t*)L"CN=localhost",1,(wchar_t*)L"hidden",&pfx);
    if(!pfxBlob.cbData||!pfx)goto cleanup;pfxBlob.pbData=(BYTE*)pfx;
    imported=PFXImportCertStore(&pfxBlob,L"hidden",CRYPT_USER_KEYSET|PKCS12_NO_PERSIST_KEY);if(!imported)goto cleanup;
    renewed=CertEnumCertificatesInStore(imported,NULL);if(!renewed)goto cleanup;
    if(!CertCompareCertificateName(X509_ASN_ENCODING,&renewed->pCertInfo->Issuer,&stored->pCertInfo->Subject))goto cleanup;
    if(!CryptVerifyCertificateSignatureEx(0,X509_ASN_ENCODING,CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,(void*)renewed,
        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,(void*)stored,0,NULL))goto cleanup;
    wincrypto_close(found);found=NULL;
    if(wincrypto_open_existing(NULL,NULL)!=NULL||wincrypto_open_existing(match,NULL)!=NULL)goto cleanup;
    if(NCryptOpenKey(provider,&opened,keyName,0,machineKeyFlag)!=ERROR_SUCCESS)goto cleanup;
    NCryptFreeObject(opened);opened=0;
    // An inaccessible key must be refused without deleting its public certificate.
    if(NCryptDeleteKey(key,0)!=ERROR_SUCCESS)goto cleanup;key=0;
    found=wincrypto_open_existing(match,(void*)stored);if(found)goto cleanup;
    PCCERT_CONTEXT retained;
    retained=CertFindCertificateInStore(store,X509_ASN_ENCODING,0,CERT_FIND_EXISTING,stored,NULL);
    if(!retained)goto cleanup;CertFreeCertificateContext(retained);
    if(!classic(PROV_RSA_AES,MS_ENH_RSA_AES_PROV_W,AT_KEYEXCHANGE)||
        !classic(PROV_RSA_FULL,MS_ENHANCED_PROV_W,AT_KEYEXCHANGE)||
        !classic(PROV_RSA_AES,MS_ENH_RSA_AES_PROV_W,AT_SIGNATURE))goto cleanup;
    result=0;
cleanup:
    if(found)wincrypto_close(found);
    if(renewed)CertFreeCertificateContext(renewed);
    if(imported)CertCloseStore(imported,0);
    free(pfx);
    if(stored)CertDeleteCertificateFromStore(stored);
    if(created)CertFreeCertificateContext(created);
    if(store)CertCloseStore(store,0);
    if(opened)NCryptFreeObject(opened);
    if(key)NCryptDeleteKey(key,0);
    if(provider&&NCryptOpenKey(provider,&opened,tlsFixtureName,0,0)==ERROR_SUCCESS)NCryptDeleteKey(opened,0);
    if(provider)NCryptFreeObject(provider);
    if(result)fprintf(stderr,"Certificate store fixture failed: %lu\n",GetLastError());
    else puts("Certificate store: CNG and historical CAPI lookup/signing, renamed issuer TLS renewal, missing keys and residue passed");
    return result;
}
'''
with tempfile.TemporaryDirectory(prefix='certificate-store-') as temporary:
    path = Path(temporary); cpp = path / 'fixture.cpp'; exe = path / 'fixture.exe'
    # Isolate the production temporary TLS container from any existing account key.
    renewal_source = subprocess.check_output(['git', 'show', 'HEAD:meshcore/wincrypto.cpp'], cwd=ROOT).decode() if '--baseline-renewal' in sys.argv else source
    renewal = extract('wincrypto_mkCert', renewal_source).replace('L"MeshDummy"', 'tlsFixtureName')
    cpp.write_text(prelude + extract('wincrypto_isopen') + extract('wincrypto_close') +
                   extract('wincrypto_open_existing') + extract('wincrypto_random') + extract('wincrypto_sign') + renewal + cases)
    subprocess.run([os.environ.get('CXX', 'clang++'), '-std=c++14', str(cpp), '-lcrypt32', '-lncrypt', '-lbcrypt', '-ladvapi32', '-o', str(exe)], check=True)
    if '--cleanup-pid' in sys.argv:
        subprocess.run([str(exe), '--cleanup-fixture', sys.argv[sys.argv.index('--cleanup-pid') + 1]], check=True)
    else:
        process = subprocess.Popen([str(exe), *(['--machine'] if '--machine' in sys.argv else [])], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, _ = process.communicate()
        print(output.decode(errors='replace'), end='')
        names = [line.split('=', 1)[1] for line in output.decode(errors='replace').splitlines()
                 if re.fullmatch(r'tlsFixtureKey=MeshAgent-TLS-[0-9a-f]{32}', line)]
        if '--machine' not in sys.argv:
            subprocess.run([str(exe), '--cleanup-fixture', str(process.pid), *names], check=True)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, process.args)
