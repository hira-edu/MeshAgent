#!/usr/bin/env python3
"""Fault-inject the production update state functions without launching or installing."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/agentcore.c').read_text()
masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' ' * len(m.group()), source, flags=re.S)
def extract(name):
    m = re.search(r'(?:static )?(?:int|BOOL|void)\s+' + name + r'\s*\([^;{]*\)\s*\{', masked)
    assert m, name
    end, depth = m.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}'); end += 1
    return source[m.start():end]
prelude = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define WIN32 1
#define TRUE 1
#define FALSE 0
#define ERROR_GEN_FAILURE 31
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define ILIBLOGMESSSAGE(...) ((void)0)
#define ILIBLOGMESSAGEX(...) ((void)0)
typedef int BOOL; typedef unsigned long DWORD; typedef void* HANDLE;
typedef enum {ILibWaitHandle_ErrorStatus_NONE,ILibWaitHandle_ErrorStatus_TIMEOUT,ILibWaitHandle_ErrorStatus_REMOVED,ILibWaitHandle_ErrorStatus_INVALID} ILibWaitHandle_ErrorStatus;
typedef struct {HANDLE process;} MeshRuntimeHostLifecycleLaunch;
typedef struct {int forceUpdate,fakeUpdate,disableUpdate,logUpdate,updateUnzipPending,performSelfUpdate;void* masterDb;void* updateActivation;} MeshAgentHostContainer;
typedef struct {MeshAgentHostContainer* agent;MeshRuntimeHostLifecycleLaunch launch;} MeshServer_UpdateActivation;
static char keys[12][64],values[12][8];static int writes,flushes,failWrite,failFlush;
static int slot(const char* key){for(int i=0;i<12;++i){if(!keys[i][0]){strcpy(keys[i],key);return i;}if(!strcmp(keys[i],key))return i;}abort();}
static int ILibSimpleDataStore_Get(void* db,const char* key,char* out,int len){(void)db;char* v=values[slot(key)];int n=(int)strlen(v);if(out&&n<=len)memcpy(out,v,n);return n;}
static int waits,releases,failures,clears,stops,complete;
static void MeshServer_ReportUpdateFailure(MeshAgentHostContainer* a){(void)a;++failures;}
static void MeshServer_FailUpdateActivation(MeshAgentHostContainer* a,int deletePackage){assert(!a->updateActivation&&deletePackage);++failures;}
static BOOL MeshRuntimeHost_CompleteLifecycleHostW(MeshRuntimeHostLifecycleLaunch* l,DWORD* e){assert(l->process);l->process=NULL;++releases;*e=complete?0:1;return complete;}
static void MeshRuntimeHost_ReleaseLifecycleHostW(MeshRuntimeHostLifecycleLaunch* l){assert(l->process);l->process=NULL;++releases;}
#define GetLastError() 5
static void ILibStopChain(void* c){(void)c;++stops;}
static void ILibChain_AddWaitHandle(void* c,HANDLE h,int timeout,BOOL(*cb)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*),void* u){(void)c;(void)cb;assert(h&&u&&timeout==-1);++waits;}
static int opens,sleeps,writeCalls,flushCalls,closeCalls,openFailures,shortWrite,badFlush,badClose;
static wchar_t* ILibUTF8ToWide(char* p,int n){(void)p;(void)n;return L"fixture";}
static int _wfopen_s(FILE** f,const wchar_t* p,const wchar_t* mode){(void)p;assert(!wcscmp(mode,L"wb")||!wcscmp(mode,L"ab"));++opens;*f=opens<=openFailures?NULL:(FILE*)1;return *f?0:1;}
static void Sleep(int n){assert(n==100);++sleeps;}
static size_t mockWrite(const void* p,size_t s,size_t n,FILE* f){assert(p&&s==1&&f);++writeCalls;return shortWrite?n-1:n;}
static int mockFlush(FILE* f){assert(f);++flushCalls;return badFlush?-1:0;}
static int mockClose(FILE* f){assert(f);++closeCalls;return badClose?-1:0;}
#define fwrite mockWrite
#define fflush mockFlush
#define fclose mockClose
'''
cases = r'''
static void reset(void){memset(keys,0,sizeof(keys));memset(values,0,sizeof(values));writes=flushes=failWrite=failFlush=0;waits=releases=failures=clears=stops=complete=0;}
int main(void){
 MeshAgentHostContainer a={0};
 for(int success=0;success<2;++success){
  reset();memset(&a,0,sizeof(a));MeshServer_UpdateActivation* x=calloc(1,sizeof(*x));x->agent=&a;x->launch.process=(HANDLE)1;a.updateActivation=x;
  assert(MeshServer_UpdateTransferBlocked(&a));
  assert(!MeshServer_UpdateActivation_Sink(NULL,(HANDLE)1,ILibWaitHandle_ErrorStatus_TIMEOUT,x));
  assert(a.updateActivation==x&&x->launch.process&&waits==1&&releases==0&&stops==0&&clears==0);
  complete=success;MeshServer_UpdateActivation_Sink(NULL,(HANDLE)1,ILibWaitHandle_ErrorStatus_NONE,x);
  assert(!a.updateActivation&&releases==1&&stops==success&&clears==0);
 }
 reset();memset(&a,0,sizeof(a));MeshServer_UpdateActivation* x=calloc(1,sizeof(*x));x->agent=&a;x->launch.process=(HANDLE)1;a.updateActivation=x;
 MeshServer_UpdateActivation_Sink(NULL,(HANDLE)1,ILibWaitHandle_ErrorStatus_INVALID,x);assert(a.updateActivation==x&&!releases);MeshServer_ReleaseUpdateActivation(&a);assert(!a.updateActivation&&releases==1);
 x=calloc(1,sizeof(*x));x->agent=&a;x->launch.process=(HANDLE)1;a.updateActivation=x;
 MeshServer_UpdateActivation_Sink(NULL,(HANDLE)1,ILibWaitHandle_ErrorStatus_REMOVED,x);assert(!a.updateActivation&&releases==2);
 a.updateUnzipPending=1;assert(MeshServer_UpdateTransferBlocked(&a));a.updateUnzipPending=0;strcpy(values[slot("PendingUpdate")],"1");assert(MeshServer_UpdateTransferBlocked(&a));strcpy(values[slot("PendingUpdate")],"0");assert(!MeshServer_UpdateTransferBlocked(&a));
 for(int fault=0;fault<6;++fault){
  opens=sleeps=writeCalls=flushCalls=closeCalls=openFailures=shortWrite=badFlush=badClose=0;
  if(fault==1)openFailures=3;if(fault==2)openFailures=4;if(fault==3)shortWrite=1;if(fault==4)badFlush=1;if(fault==5)badClose=1;
  assert(MeshServer_WriteUpdateBlock("fixture","data",4,0)==(fault<2));
  assert(writeCalls==(fault==2?0:1));assert(closeCalls==(fault==2?0:1));assert(opens==(fault==1||fault==2?4:1));
 }
 shortWrite=badFlush=badClose=openFailures=0;writeCalls=0;assert(MeshServer_WriteUpdateBlock("fixture",NULL,0,1)&&writeCalls==0);
 puts("Native update state: late child exit, removal, transfer gate and write faults passed");return 0;
}
'''
functions = '\n'.join(extract(name) for name in ('MeshServer_UpdateTransferBlocked', 'MeshServer_UpdateActivation_Sink', 'MeshServer_ReleaseUpdateActivation', 'MeshServer_WriteUpdateBlock'))
with tempfile.TemporaryDirectory(prefix='mesh-update-state-') as tmp:
    c, exe = Path(tmp)/'state.c', Path(tmp)/'state'
    c.write_text(prelude + functions + cases)
    cmd = [os.environ.get('CC','clang'), '-std=c11', '-Wall', '-Wextra', '-Werror']
    if os.name != 'nt': cmd += ['-fsanitize=address,undefined']
    subprocess.run(cmd+[str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
# Transfer framing remains in the packet dispatcher; verify the integration guards.
start=source.index('case MeshCommand_AgentUpdate:')
end=source.index('static void MeshServer_ControlChannel_EmitDisconnected',start)
transfer=source[start:end]
assert transfer.count('if (!agent->updateDownloadActive)') == 3
assert 'agent->updateDownloadActive = MeshServer_WriteUpdateBlock' in transfer
assert 'util_appendfile' not in transfer
assert 'ILibWriteStringToDiskEx' not in transfer
