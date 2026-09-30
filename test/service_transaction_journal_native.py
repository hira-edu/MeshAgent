#!/usr/bin/env python3
"""Exercise the production journal codec and atomic I/O with bounded Win32 mocks.

Requires Python 3 and clang/CC. Runs locally without touching SCM or registry.
UTF-16 uses -fshort-wchar; no host libc wide-string functions are called.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
binding = (ROOT / 'meshservice/service_binding_transaction.h').read_text()
prefix = binding[:binding.index('static BOOL ServiceBinding_ReadValue')]
prefix = prefix.replace('#ifndef MESH_SERVICE_BINDING_TRANSACTION_H', '').replace('#define MESH_SERVICE_BINDING_TRANSACTION_H', '')
prelude = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef uint8_t BYTE; typedef uint16_t WORD; typedef uint32_t DWORD; typedef int BOOL;
typedef uintptr_t ULONG_PTR; typedef void* PSECURITY_DESCRIPTOR; typedef intptr_t HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#define SERVICE_CONFIG_DESCRIPTION 1
#define SERVICE_CONFIG_FAILURE_ACTIONS 2
#define SERVICE_CONFIG_FAILURE_ACTIONS_FLAG 4
#define SERVICE_CONFIG_SERVICE_SID_INFO 5
#define SERVICE_CONFIG_DELAYED_AUTO_START_INFO 6
#define SERVICE_WIN32_OWN_PROCESS 16
#define SERVICE_WIN32_SHARE_PROCESS 32
#define SERVICE_DISABLED 4
#define SERVICE_ERROR_CRITICAL 3
#define SC_ACTION_RUN_COMMAND 3
#define REG_SZ 1
#define REG_EXPAND_SZ 2
#define REG_MULTI_SZ 7
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define SECURITY_DESCRIPTOR_REVISION 1
#define SE_SELF_RELATIVE 0x8000
#define SID_REVISION 1
#define SID_MAX_SUB_AUTHORITIES 15
#define _TRUNCATE 0
#define INVALID_HANDLE_VALUE (-1)
#define GENERIC_WRITE 1
#define GENERIC_READ 2
#define CREATE_NEW 1
#define OPEN_EXISTING 2
#define FILE_ATTRIBUTE_NORMAL 0
#define FILE_FLAG_WRITE_THROUGH 1
#define MOVEFILE_REPLACE_EXISTING 1
#define MOVEFILE_WRITE_THROUGH 2
#define FILE_SHARE_READ 1
#define FILE_FLAG_OPEN_REPARSE_POINT 2
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_ACCESS_DENIED 5
#define ERROR_PATH_NOT_FOUND 3

typedef int SC_ACTION_TYPE;
typedef struct { SC_ACTION_TYPE Type; DWORD Delay; } SC_ACTION;
typedef struct { DWORD dwServiceType,dwStartType,dwErrorControl; wchar_t* lpBinaryPathName; wchar_t* lpLoadOrderGroup; DWORD dwTagId; wchar_t* lpDependencies; wchar_t* lpServiceStartName; wchar_t* lpDisplayName; } QUERY_SERVICE_CONFIGW;
typedef struct { wchar_t* lpDescription; } SERVICE_DESCRIPTIONW;
typedef struct { DWORD dwResetPeriod; wchar_t *lpRebootMsg,*lpCommand; DWORD cActions; SC_ACTION* lpsaActions; } SERVICE_FAILURE_ACTIONSW;
typedef struct { BYTE Revision,Sbz1; WORD Control; DWORD Owner,Group,Sacl,Dacl; } SECURITY_DESCRIPTOR_RELATIVE;
typedef struct { BYTE AclRevision,Sbz1; WORD AclSize,AceCount,Sbz2; } ACL;
typedef struct { BYTE AceType,AceFlags; WORD AceSize; } ACE_HEADER;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef struct { DWORD dwFileAttributes; } BY_HANDLE_FILE_INFORMATION;
static int _wcsicmp(const wchar_t* a,const wchar_t* b) { for(;;++a,++b) { int x=*a,y=*b; if(x>='A'&&x<='Z')x+=32; if(y>='A'&&y<='Z')y+=32; if(x!=y||!x)return x-y; } }
static size_t wide_len(const wchar_t* s) { size_t n=0; while(s[n])++n; return n; }
static int _snwprintf_s(wchar_t* out,size_t cap,int truncate,const wchar_t* fmt,...) {
    (void)truncate; va_list ap; size_t n=0; va_start(ap,fmt);
    for(size_t i=0;fmt[i];++i) {
        if(fmt[i]=='%'&&fmt[i+1]=='l'&&fmt[i+2]=='s') { const wchar_t* s=va_arg(ap,const wchar_t*); i+=2; while(*s) { if(n+1>=cap){va_end(ap);return -1;} out[n++]=*s++; } }
        else { if(n+1>=cap){va_end(ap);return -1;} out[n++]=fmt[i]; }
    }
    out[n]=0;va_end(ap);return (int)n;
}
static BOOL IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR p) { SECURITY_DESCRIPTOR_RELATIVE* s=p;return s->Revision==1 && (s->Control&SE_SELF_RELATIVE); }
static DWORD GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR p) { SECURITY_DESCRIPTOR_RELATIVE* s=p; return s->Dacl ? s->Dacl + ((ACL*)((BYTE*)p+s->Dacl))->AclSize : sizeof(*s); }
/* Two files model atomic replacement: handle 1 is unpublished tmp, 2 durable. */
static BYTE *files[3]; static DWORD lengths[3], lastError, failAt, reparse;
static int file_index(const wchar_t* p) { size_t n=wide_len(p); return n>=4&&!_wcsicmp(p+n-4,L".tmp")?1:2; }
static BOOL DeleteFileW(const wchar_t* p) { int i=file_index(p);free(files[i]);files[i]=NULL;lengths[i]=0;return TRUE; }
static HANDLE CreateFileW(const wchar_t* p,DWORD access,DWORD share,void* security,DWORD creation,DWORD flags,void* template) {
    (void)access;(void)share;(void)security;(void)flags;(void)template;int i=file_index(p);
    if(failAt==1){lastError=ERROR_ACCESS_DENIED;return INVALID_HANDLE_VALUE;}
    if(creation==OPEN_EXISTING&&!files[i]){lastError=ERROR_FILE_NOT_FOUND;return INVALID_HANDLE_VALUE;}
    if(creation==CREATE_NEW){assert(!files[i]);files[i]=malloc(1);lengths[i]=0;}return i;
}
static BOOL CloseHandle(HANDLE h){(void)h;return TRUE;}
static DWORD GetLastError(void){return lastError;}
static BOOL WriteFile(HANDLE h,const void* p,DWORD n,DWORD* written,void* overlap){(void)overlap;*written=failAt==2?n/2:n;files[h]=realloc(files[h],*written);memcpy(files[h],p,*written);lengths[h]=*written;return TRUE;}
static BOOL FlushFileBuffers(HANDLE h){(void)h;return failAt!=3;}
static BOOL MoveFileExW(const wchar_t* a,const wchar_t* b,DWORD flags){(void)flags;if(failAt==4)return FALSE;int x=file_index(a),y=file_index(b);free(files[y]);files[y]=files[x];lengths[y]=lengths[x];files[x]=NULL;lengths[x]=0;return TRUE;}
static BOOL GetFileInformationByHandle(HANDLE h,BY_HANDLE_FILE_INFORMATION* p){(void)h;p->dwFileAttributes=reparse;return TRUE;}
static BOOL GetFileSizeEx(HANDLE h,LARGE_INTEGER* n){n->QuadPart=lengths[h];return TRUE;}
static BOOL ReadFile(HANDLE h,void* p,DWORD n,DWORD* read,void* overlap){(void)overlap;*read=failAt==5?n/2:n;memcpy(p,files[h],*read);return TRUE;}
'''
cases = r'''
static wchar_t* add_text(BYTE* arena,DWORD* pos,const wchar_t* text,DWORD chars){wchar_t* p=(wchar_t*)(arena+*pos);memcpy(p,text,chars*2);*pos+=chars*2;return p;}
static ServiceBindingSnapshot* fixture(void){
    ServiceBindingSnapshot* s=calloc(1,sizeof(*s));DWORD pos=sizeof(QUERY_SERVICE_CONFIGW);
    s->running=TRUE;s->groupMember=TRUE;s->parametersExisted=TRUE;
    s->configBytes=4096;s->config=calloc(1,s->configBytes);QUERY_SERVICE_CONFIGW* c=s->config;
    c->dwServiceType=SERVICE_WIN32_OWN_PROCESS;c->dwStartType=2;c->dwErrorControl=1;c->dwTagId=77;
    c->lpBinaryPathName=add_text((BYTE*)c,&pos,L"C:\\Windows\\System32\\rundll32.exe",33);
    c->lpServiceStartName=add_text((BYTE*)c,&pos,L"LocalSystem",12);
    c->lpDisplayName=add_text((BYTE*)c,&pos,L"Agent",6);
    c->lpLoadOrderGroup=add_text((BYTE*)c,&pos,L"",1);
    c->lpDependencies=add_text((BYTE*)c,&pos,L"RpcSs\0Tcpip\0",13);
    for(int i=0;i<5;++i){s->extra[i]=calloc(1,4096);s->extraBytes[i]=4096;}
    pos=sizeof(SERVICE_DESCRIPTIONW);((SERVICE_DESCRIPTIONW*)s->extra[0])->lpDescription=add_text(s->extra[0],&pos,L"Before migration",17);
    SERVICE_FAILURE_ACTIONSW* a=(SERVICE_FAILURE_ACTIONSW*)s->extra[1];a->dwResetPeriod=86400;pos=sizeof(*a);
    a->lpRebootMsg=add_text(s->extra[1],&pos,L"Reboot",7);a->lpCommand=add_text(s->extra[1],&pos,L"C:\\repair.exe",14);
    pos=(pos+7)&~7u;a->cActions=2;a->lpsaActions=(SC_ACTION*)(s->extra[1]+pos);a->lpsaActions[0].Type=1;a->lpsaActions[0].Delay=7500;a->lpsaActions[1].Type=3;a->lpsaActions[1].Delay=15000;
    *(DWORD*)s->extra[2]=1;*(DWORD*)s->extra[3]=1;*(DWORD*)s->extra[4]=1;
    s->values[0].present=TRUE;s->values[0].type=4;s->values[0].size=4;s->values[0].data=malloc(4);*(DWORD*)s->values[0].data=16;
    /* Repair must checkpoint malformed Parameters bytes without interpreting. */
    s->values[9].present=TRUE;s->values[9].type=REG_SZ;s->values[9].size=3;s->values[9].data=malloc(3);memcpy(s->values[9].data,"bad",3);
    return s;
}
static ServiceJournalRecord* decode(BYTE* data,DWORD bytes){ServiceJournalBuffer b={data,bytes,0,TRUE};return ServiceJournal_Decode(&b,L"Agent");}
static void rehash(BYTE* data,DWORD n){DWORD h=ServiceJournal_Checksum(data,n-4);memcpy(data+n-4,&h,4);}
int main(void){
    assert(ServiceBinding_ValueNames[0][0]==L'T'&&ServiceBinding_ConfigLevels[0]==SERVICE_CONFIG_DESCRIPTION);
    ServiceBindingSnapshot* s=fixture(); BYTE* data=malloc(SERVICE_JOURNAL_MAX_BYTES);ServiceJournalBuffer b={data,SERVICE_JOURNAL_MAX_BYTES,0,TRUE};
    BYTE sd[sizeof(SECURITY_DESCRIPTOR_RELATIVE)+sizeof(ACL)]={0};SECURITY_DESCRIPTOR_RELATIVE* relative=(SECURITY_DESCRIPTOR_RELATIVE*)sd;relative->Revision=1;relative->Control=SE_SELF_RELATIVE;relative->Dacl=sizeof(*relative);((ACL*)(sd+sizeof(*relative)))->AclSize=sizeof(ACL);
    PSECURITY_DESCRIPTOR descriptors[5]={sd,NULL,NULL,NULL,NULL};DWORD attrs[5]={32,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu};
    assert(ServiceJournal_Encode(&b,L"Agent",SERVICE_JOURNAL_BACKED_UP,1,s,descriptors,attrs));DWORD length=b.offset;
    ServiceJournalRecord* r=decode(data,length);assert(r&&r->phase==2&&r->fileMask==1&&r->binding->running&&!r->binding->legacy&&r->binding->groupMember);
    assert(!_wcsicmp(r->binding->config->lpDisplayName,L"Agent"));assert(r->binding->config->dwTagId==77);
    assert(r->binding->config->lpDependencies[6]=='T');assert(((SERVICE_FAILURE_ACTIONSW*)r->binding->extra[1])->lpsaActions[1].Delay==15000);
    assert(r->binding->values[9].size==3&&!memcmp(r->binding->values[9].data,"bad",3));assert(r->attributes[0]==32&&r->dacl[0]);
    ServiceJournalBuffer again={malloc(SERVICE_JOURNAL_MAX_BYTES),SERVICE_JOURNAL_MAX_BYTES,0,TRUE};assert(ServiceJournal_Encode(&again,L"Agent",r->phase,r->fileMask,r->binding,r->dacl,r->attributes));assert(again.offset==length&&!memcmp(again.data,data,length));free(again.data);ServiceJournal_Free(r);
    for(DWORD n=0;n<length;++n){r=decode(data,n);assert(!r);} /* Every truncation boundary. */
    for(DWORD n=0;n<length;n+=7){data[n]^=0x40;r=decode(data,length);assert(!r);data[n]^=0x40;}
    BYTE* changed=malloc(length+4);memcpy(changed,data,length);*(DWORD*)(changed+4)=2;rehash(changed,length);assert(!decode(changed,length));
    memcpy(changed,data,length);*(DWORD*)(changed+8)=5;rehash(changed,length);assert(!decode(changed,length));
    memcpy(changed,data,length);*(DWORD*)(changed+12)=32;rehash(changed,length);assert(!decode(changed,length));
    memcpy(changed,data,length);changed[20]=0x00;changed[21]=0xd8;rehash(changed,length);assert(!decode(changed,length));
    memcpy(changed,data,length);memset(changed+16,0xff,4);rehash(changed,length);assert(!decode(changed,length));
    memcpy(changed,data,length);memmove(changed+length,changed+length-4,4);memset(changed+length-4,0,4);rehash(changed,length+4);assert(!decode(changed,length+4));
    wchar_t* saved=s->config->lpDisplayName;s->config->lpDisplayName=(wchar_t*)((BYTE*)s->config+s->configBytes);b.offset=0;b.ok=TRUE;assert(!ServiceJournal_Encode(&b,L"Agent",1,1,s,NULL,NULL));s->config->lpDisplayName=saved;
    b.offset=0;b.ok=TRUE;assert(!ServiceJournal_Encode(&b,L"Agent",2,1,s,NULL,NULL));
    relative->Dacl=0xfffffff0u;assert(!ServiceJournal_SecurityValid(sd,sizeof(sd)));relative->Dacl=sizeof(*relative);
    assert(ServiceJournal_Load(L"journal",L"Agent",&r)&&!r);
    assert(ServiceJournal_Save(L"journal",L"Agent",1,1,s,NULL,NULL));assert(ServiceJournal_Load(L"journal",L"Agent",&r)&&r&&r->phase==1);ServiceJournal_Free(r);
    assert(!ServiceJournal_Load(L"journal",L"OtherService",&r)&&!r);
    DWORD originalLength=lengths[2];BYTE* original=malloc(originalLength);memcpy(original,files[2],originalLength);
    for(DWORD failure=1;failure<=4;++failure){failAt=failure;assert(!ServiceJournal_Save(L"journal",L"Agent",2,1,s,descriptors,attrs));assert(lengths[2]==originalLength&&!memcmp(files[2],original,originalLength));failAt=0;assert(ServiceJournal_Load(L"journal",L"Agent",&r)&&r&&r->phase==1);ServiceJournal_Free(r);}
    /* Simulate a crash leaving an unpublished temporary write. */
    files[1]=malloc(10);lengths[1]=10;assert(ServiceJournal_Save(L"journal",L"Agent",2,1,s,descriptors,attrs));assert(ServiceJournal_Load(L"journal",L"Agent",&r)&&r&&r->phase==2);ServiceJournal_Free(r);
    failAt=5;assert(!ServiceJournal_Load(L"journal",L"Agent",&r)&&!r);failAt=0;
    reparse=FILE_ATTRIBUTE_REPARSE_POINT;assert(!ServiceJournal_Load(L"journal",L"Agent",&r));reparse=0;
    files[2][0]^=1;assert(!ServiceJournal_Load(L"journal",L"Agent",&r));files[2][0]^=1;
    assert(ServiceJournal_Save(L"journal",L"Agent",3,1,s,descriptors,attrs));assert(ServiceJournal_Load(L"journal",L"Agent",&r)&&r&&r->phase==3);ServiceJournal_Free(r);
    assert(ServiceJournal_Save(L"journal",L"Agent",1,0,NULL,NULL,NULL));assert(ServiceJournal_Load(L"journal",L"Agent",&r)&&r&&!r->binding);ServiceJournal_Free(r);
    free(original);free(changed);free(data);ServiceBinding_Free(s);DeleteFileW(L"journal");DeleteFileW(L"journal.tmp");
    puts("service transaction journal: roundtrip, bounds, corrupt/truncated input, raw repair values, ACLs and atomic write faults passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-service-journal-') as tmp:
    src = Path(tmp) / 'journal.c'
    exe = Path(tmp) / 'journal'
    src.write_text(prelude + prefix + '\n#include "service_transaction_journal.h"\n' + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-I', str(ROOT / 'meshservice'), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
