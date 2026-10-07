#!/usr/bin/env python3
"""Exercise production Windows pipe writes with delayed OS completions under ASan.

Mocks only Windows I/O and chain/queue services. The production queue, partial
write, close, cancellation and callback lifetimes are extracted unchanged.
Also compiles the whole Windows translation unit when MinGW is available.
A real Windows runtime/package gate remains required before release.
"""
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = [
    'ILibProcessPipe_WriteData_Create', 'ILibProcessPipe_FreePipe_RequestClose',
    'ILibProcessPipe_FreePipe_TryFinalize', 'ILibProcessPipe_FreePipe_TryFinalizeOnChain', 'ILibProcessPipe_FreePipe_DeferredFinalize',
    'ILibProcessPipe_FreePipe_Finalize', 'ILibProcessPipe_FreePipe',
    'ILibProcessPipe_GetWriteOverlapped', 'ILibProcessPipe_WindowsWritePump',
    'ILibProcessPipe_Process_WindowsWriteHandler', 'ILibProcessPipe_WindowsWrite',
    'ILibProcessPipe_Pipe_Close', 'ILibProcessPipe_Pipe_WriteEx_sink',
    'ILibProcessPipe_Pipe_WriteEx',
]

def extract(source, name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' '*len(m[0]), source, flags=re.S)
    for match in re.finditer(r'^(?:static )?[\w* ]+\b' + name + r'\([^;\n]*\)', source, re.M):
        opening = masked.index('{', match.end())
        if ';' in masked[match.end():opening]: continue
        depth, end = 1, opening+1
        while depth:
            depth += (masked[end]=='{')-(masked[end]=='}'); end += 1
        return match[0], source[opening:end]
    raise ValueError(name)

PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WIN32 1
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_IO_PENDING 997
#define ERROR_IO_INCOMPLETE 996
#define ERROR_OPERATION_ABORTED 995
#define ERROR_BROKEN_PIPE 109
#define INVALID_HANDLE_VALUE ((void*)(intptr_t)-1)
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define ILibCriticalLog(...) ((void)0)
typedef int BOOL;
typedef uint32_t DWORD;
typedef long LONG;
typedef void *HANDLE;
typedef struct { HANDLE hEvent; DWORD Offset,OffsetHigh; } OVERLAPPED;
typedef enum { ILibWaitHandle_ErrorStatus_NONE, ILibWaitHandle_ErrorStatus_IO_ERROR, ILibWaitHandle_ErrorStatus_INVALID_HANDLE } ILibWaitHandle_ErrorStatus;
typedef enum { ILibTransport_DoneState_ERROR=-1, ILibTransport_DoneState_COMPLETE=0, ILibTransport_DoneState_INCOMPLETE=1 } ILibTransport_DoneState;
typedef enum { ILibTransport_MemoryOwnership_CHAIN, ILibTransport_MemoryOwnership_USER, ILibTransport_MemoryOwnership_STATIC } ILibTransport_MemoryOwnership;
typedef struct ILibProcessPipe_PipeObject ILibProcessPipe_PipeObject;
typedef ILibProcessPipe_PipeObject *ILibProcessPipe_Pipe;
typedef void (*ILibProcessPipe_GenericSendOKHandler)(void*,void*);
typedef void (*ILibProcessPipe_Pipe_WriteExHandler)(ILibProcessPipe_Pipe,void*,int,int);
typedef struct { struct { void *ParentChain; } ChainLink; } Manager;
typedef struct { ILibProcessPipe_PipeObject *stdIn,*stdOut,*stdErr; } Process;
struct ILibProcessPipe_PipeObject {
 Manager *manager; Process *mProcess;
 LONG closeRequested,finalFreePending,finalizing,activeReadCallbacks,activeWriteHandler,resumePending,pendingWrite;
 int PAUSED,writeClosing,writeOverlappedHandle;
 size_t writeQueuedBytes;
 HANDLE mPipe_ReadEnd,mPipe_WriteEnd,mPipe_Reader_ResumeEvent;
 OVERLAPPED *mOverlapped,*mwOverlapped;
 void *handler,*user1,*user2,*user3,*user4,*metadata,*WriteBuffer;
 void (*brokenPipeHandler)(ILibProcessPipe_PipeObject*);
 char *buffer; ILibTransport_MemoryOwnership bufferOwner;
};
typedef struct ILibProcessPipe_WriteData {
 char *buffer; int bufferLen,offset; ILibTransport_MemoryOwnership ownership;
} ILibProcessPipe_WriteData;
#define ILibProcessPipe_WriteData_Destroy(d) if(d->ownership==ILibTransport_MemoryOwnership_CHAIN){free(d->buffer);} free(d)
static int on_chain=1;
static void (*queuedFinalize)(void*,void*);static void *queuedUser;
static int ILibIsRunningOnChainThread(void*c){(void)c;return on_chain;}
static void ILibChain_RunOnMicrostackThreadEx3(void*c,void(*f)(void*,void*),void(*a)(void*,void*),void*u){(void)c;(void)a;assert(!queuedFinalize);queuedFinalize=f;queuedUser=u;}
static int allocationFault;
static void *faultMalloc(size_t n){return allocationFault==1?NULL:malloc(n);}
static void *faultCalloc(size_t n,size_t width){return allocationFault==2?NULL:calloc(n,width);}
static Manager manager={{(void*)1}};
static int freed,closed,registered,cancelled,callbacks,mode,ready,aborted,writeCalls,eventFailure,cancelCompletes;
static DWORD offsets[16];
static DWORD lastError,completedBytes,heldLength;
static char *heldBuffer; static OVERLAPPED *heldOv;
static char delivered[256]; static size_t deliveredLength;
static LONG InterlockedIncrement(LONG*v){return ++*v;}
static LONG InterlockedDecrement(LONG*v){return --*v;}
static LONG InterlockedExchange(LONG*v,LONG n){LONG old=*v;*v=n;return old;}
static LONG InterlockedCompareExchange(LONG*v,LONG n,LONG e){LONG old=*v;if(old==e)*v=n;return old;}
static LONG ILibProcessPipe_GetStateLong(LONG*v){return *v;}
static int ILibMemory_CanaryOK(void*p){return p!=NULL;}
static void ILibMemory_Free(void*p){if(p){++freed;free(p);}}
static DWORD GetLastError(void){return lastError;}
static HANDLE CreateEvent(void*a,int b,int c,void*d){(void)a;(void)b;(void)c;(void)d;return eventFailure?NULL:(void*)9;}
static void ResetEvent(HANDLE h){assert(h==(void*)9);}
static void SetEvent(HANDLE h){(void)h;}
static BOOL CloseHandle(HANDLE h){assert(h!=NULL);assert(heldOv==NULL);++closed;return TRUE;}
// cancelCompletes models the kernel finishing a cancelled request; otherwise it stays pending.
static BOOL CancelIoEx(HANDLE h,OVERLAPPED*ov){(void)h;assert(ov==heldOv || heldOv==NULL);++cancelled;if(cancelCompletes && heldOv){ready=aborted=1;}return TRUE;}
#define HasOverlappedIoCompleted(ov) ((void)(ov), heldOv==NULL || ready)
#define Sleep(ms) ((void)(ms))
static void ILibChain_RemoveWaitHandleEx(void*c,HANDLE h,int clean){(void)c;(void)h;(void)clean;registered=0;}
#define ILibChain_RemoveWaitHandle(c,h) ILibChain_RemoveWaitHandleEx(c,h,0)
static void ILibChain_AddWaitHandle(void*c,HANDLE h,int t,BOOL(*f)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*),void*u){(void)c;(void)t;(void)f;(void)u;assert(h==(void*)9);registered=1;}
#define ILibChain_RunOnMicrostackThread(c,f,u) f(c,u)
typedef struct Node { void *value; struct Node *next; } Node;
typedef struct { Node *head,*tail; int locked; } Queue;
static void *ILibQueue_Create(void){return calloc(1,sizeof(Queue));}
static void ILibQueue_Lock(void*q){assert(!((Queue*)q)->locked);((Queue*)q)->locked=1;}
static void ILibQueue_UnLock(void*q){assert(((Queue*)q)->locked);((Queue*)q)->locked=0;}
static int ILibQueue_IsEmpty(void*q){return ((Queue*)q)->head==NULL;}
static void ILibQueue_EnQueue(void*q,void*v){Queue*a=q;Node*n=calloc(1,sizeof(Node));assert(v);n->value=v;if(a->tail)a->tail->next=n;else a->head=n;a->tail=n;}
static void *ILibQueue_PeekQueue(void*q){Queue*a=q;return a->head?a->head->value:NULL;}
static void *ILibQueue_DeQueue(void*q){Queue*a=q;Node*n=a->head;if(!n)return NULL;void*v=n->value;a->head=n->next;if(!a->head)a->tail=NULL;free(n);return v;}
static void ILibQueue_Destroy(void*q){assert(ILibQueue_IsEmpty(q));assert(!((Queue*)q)->locked);free(q);}
static void memcpy_s(void*d,size_t cap,const void*s,size_t n){assert(n<=cap);memcpy(d,s,n);}
static void deliver(const char*b,DWORD n){assert(deliveredLength+n<=sizeof(delivered));memcpy(delivered+deliveredLength,b,n);deliveredLength+=n;}
static BOOL WriteFile(HANDLE h,char*b,DWORD n,DWORD*written,OVERLAPPED*ov){
 assert(h==(void*)7 && ov && ov->hEvent==(void*)9 && !heldOv);if(writeCalls<16)offsets[writeCalls]=ov->Offset;++writeCalls;
 if(mode==3){lastError=ERROR_BROKEN_PIPE;return FALSE;}
 if(mode==1 || mode==4){heldBuffer=b;heldLength=n;heldOv=ov;ready=0;lastError=ERROR_IO_PENDING;return FALSE;}
 *written=mode==2 && n>2?2:n;deliver(b,*written);return TRUE;
}
static BOOL GetOverlappedResult(HANDLE h,OVERLAPPED*ov,DWORD*n,int wait){
 assert(h==(void*)7 && ov==heldOv && !wait);
 // ASan catches prematurely freed OVERLAPPED/buffer even on delayed cancellation.
 assert(ov->hEvent==(void*)9);if(heldLength)assert(heldBuffer[0]);
 if(!ready){lastError=ERROR_IO_INCOMPLETE;return FALSE;}
 heldOv=NULL;
 if(aborted){lastError=ERROR_OPERATION_ABORTED;return FALSE;}
 *n=completedBytes?completedBytes:heldLength;
 if(*n<=heldLength)deliver(heldBuffer,*n);
 return TRUE;
}
'''
ALLOCATORS = '\n#define malloc faultMalloc\n#define calloc faultCalloc\n'

TESTS = r'''
static ILibProcessPipe_PipeObject *newPipe(void){ILibProcessPipe_PipeObject*p=calloc(1,sizeof(*p));p->manager=&manager;p->mPipe_WriteEnd=(void*)7;p->writeOverlappedHandle=1;return p;}
static void brokenClose(ILibProcessPipe_PipeObject*p){++callbacks;ILibProcessPipe_FreePipe(p);}
static void sendClose(void*a,void*b){(void)b;++callbacks;ILibProcessPipe_FreePipe(a);}
static void directClose(ILibProcessPipe_Pipe p,void*u,int error,int bytes){(void)u;(void)error;(void)bytes;++callbacks;ILibProcessPipe_FreePipe(p);}
static void directSuccess(ILibProcessPipe_Pipe p,void*u,int error,int bytes){(void)p;(void)u;assert(!error && bytes==6);++callbacks;}
static void sendAgain(void*a,void*b){(void)b;++callbacks;ILibProcessPipe_PipeObject*p=a;p->handler=NULL;mode=1;assert(ILibProcessPipe_WindowsWrite(p,"next",4,ILibTransport_MemoryOwnership_USER)==1);}
static BOOL complete(ILibProcessPipe_PipeObject*p){ready=1;return ILibProcessPipe_Process_WindowsWriteHandler((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,p);}
int main(int argc,char**argv){
 assert(argc==2);ILibProcessPipe_PipeObject*p=newPipe();mode=1;
 if(!strcmp(argv[1],"cancel-delayed")){
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  ILibProcessPipe_FreePipe(p);assert(!freed && registered && cancelled==1);
  assert(ILibProcessPipe_Process_WindowsWriteHandler((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,p));assert(!freed && registered);
  ready=aborted=1;assert(!complete(p));assert(freed==1 && !registered);
 }else if(!strcmp(argv[1],"off-thread-close")){
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  on_chain=0;ILibProcessPipe_FreePipe(p);ILibProcessPipe_FreePipe(p);assert(queuedFinalize && !freed);
  on_chain=1;ready=aborted=1;assert(!complete(p));assert(!freed);
  void(*f)(void*,void*)=queuedFinalize;queuedFinalize=NULL;f((void*)1,queuedUser);assert(freed==1);
 }else if(!strcmp(argv[1],"partial-order-eof")){
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  assert(ILibProcessPipe_WindowsWrite(p,"GHIJ",4,ILibTransport_MemoryOwnership_USER)==1);
  ILibProcessPipe_Pipe_Close(p);assert(!closed && p->mPipe_WriteEnd);
  completedBytes=2;mode=2;assert(!complete(p));assert(deliveredLength==10 && !memcmp(delivered,"abcdefGHIJ",10));assert(p->mPipe_WriteEnd==NULL);
  ILibProcessPipe_FreePipe(p);assert(freed==1);
 }else if(!strcmp(argv[1],"broken-reentrant")){
  mode=3;p->brokenPipeHandler=brokenClose;assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==-1);assert(freed==1 && callbacks==1);
 }else if(!strcmp(argv[1],"completion-close")){
  p->handler=(void*)sendClose;p->user1=p;assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  assert(!complete(p));assert(freed==1 && callbacks==1);
 }else if(!strcmp(argv[1],"completion-write")){
  p->handler=(void*)sendAgain;p->user1=p;assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  assert(complete(p));assert(callbacks==1 && registered && p->pendingWrite==1);assert(!complete(p));assert(deliveredLength==10 && !memcmp(delivered,"abcdefnext",10));ILibProcessPipe_FreePipe(p);
 }else if(!strcmp(argv[1],"cancel-success-race")){
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);ILibProcessPipe_FreePipe(p);assert(!complete(p));assert(freed==1);
 }else if(!strcmp(argv[1],"bad-count")){
  p->brokenPipeHandler=brokenClose;assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);completedBytes=7;assert(!complete(p));assert(freed==1 && callbacks==1);
 }else if(!strcmp(argv[1],"sync-partial")){
  mode=2;assert(!ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER));assert(deliveredLength==6 && writeCalls==3);ILibProcessPipe_FreePipe(p);
 }else if(!strcmp(argv[1],"data-allocation-failure") || !strcmp(argv[1],"io-allocation-failure")){
  allocationFault=!strcmp(argv[1],"data-allocation-failure")?1:2;
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==-1);assert(freed==1 && !writeCalls);
 }else if(!strcmp(argv[1],"event-failure")){
  eventFailure=1;assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==-1);assert(freed==1 && !writeCalls);
 }else if(!strcmp(argv[1],"direct-cancel")){
  assert(ILibProcessPipe_Pipe_WriteEx(p,"abcdef",6,NULL,directClose)==1);ILibProcessPipe_FreePipe(p);assert(!freed && registered);
  ready=aborted=1;assert(!ILibProcessPipe_Pipe_WriteEx_sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,p));assert(freed==1 && !callbacks);
 }else if(!strcmp(argv[1],"direct-reentrant")){
  assert(ILibProcessPipe_Pipe_WriteEx(p,"abcdef",6,NULL,directClose)==1);ready=1;assert(!ILibProcessPipe_Pipe_WriteEx_sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,p));assert(freed==1 && callbacks==1);
 }else if(!strcmp(argv[1],"sync-handle-refused")){
  p->writeOverlappedHandle=0;p->brokenPipeHandler=brokenClose;
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==-1);
  assert(!freed && !callbacks && !cancelled && !writeCalls && !p->closeRequested);ILibProcessPipe_FreePipe(p);
 }else if(!strcmp(argv[1],"write-after-end")){
  p->brokenPipeHandler=brokenClose;
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  ILibProcessPipe_Pipe_Close(p);
  char *rejected=malloc(4);memcpy(rejected,"bad",4);
  assert(ILibProcessPipe_WindowsWrite(p,rejected,3,ILibTransport_MemoryOwnership_CHAIN)==-1);
  assert(!freed && !callbacks && !cancelled && registered && p->pendingWrite && !p->closeRequested);
  assert(!complete(p));assert(deliveredLength==6 && !memcmp(delivered,"abcdef",6) && !p->mPipe_WriteEnd);
  assert(ILibProcessPipe_WindowsWrite(p,"bad",3,ILibTransport_MemoryOwnership_USER)==-1);
  assert(!freed && !callbacks);ILibProcessPipe_FreePipe(p);
 }else if(!strcmp(argv[1],"mixed-write-refused")){
  p->brokenPipeHandler=brokenClose;
  assert(ILibProcessPipe_Pipe_WriteEx(p,"abcdef",6,NULL,directSuccess)==1);
  assert(ILibProcessPipe_WindowsWrite(p,"bad",3,ILibTransport_MemoryOwnership_USER)==-1);
  assert(!freed && !callbacks && !cancelled && registered && p->pendingWrite && !p->closeRequested);
  ready=1;assert(!ILibProcessPipe_Pipe_WriteEx_sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,p));
  assert(callbacks==1 && deliveredLength==6 && !memcmp(delivered,"abcdef",6));
  mode=2;assert(!ILibProcessPipe_WindowsWrite(p,"ok",2,ILibTransport_MemoryOwnership_USER));
  assert(deliveredLength==8 && !memcmp(delivered,"abcdefok",8));ILibProcessPipe_FreePipe(p);
 }else if(!strcmp(argv[1],"queue-accounting")){
  // Queued bytes are counted on enqueue and released only when a buffer fully drains.
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  assert(ILibProcessPipe_WindowsWrite(p,"GHIJ",4,ILibTransport_MemoryOwnership_USER)==1);assert(p->writeQueuedBytes==10);
  completedBytes=2;mode=2;assert(!complete(p));assert(p->writeQueuedBytes==0 && deliveredLength==10);ILibProcessPipe_FreePipe(p);
 }else if(!strcmp(argv[1],"queue-limit")){
  // A live child that stops reading: the write that would exceed the bound closes the
  // pipe (fail closed) instead of growing memory or dropping bytes from the stream.
  p->brokenPipeHandler=brokenClose;
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  p->writeQueuedBytes=ILibProcessPipe_MAX_QUEUED_WRITE_BYTES-3;
  char *owned=malloc(4);memcpy(owned,"GHIJ",4);
  assert(ILibProcessPipe_WindowsWrite(p,owned,4,ILibTransport_MemoryOwnership_CHAIN)==-1);
  assert(callbacks==1 && cancelled==1 && !freed && p->closeRequested);
  ready=aborted=1;assert(!complete(p));assert(freed==1 && deliveredLength==0);
 }else if(!strcmp(argv[1],"wait-failed-retired")){
  // The chain drops a registration after INVALID_HANDLE; the write is cancelled and,
  // once the kernel releases it, reported as a broken pipe and freed.
  p->brokenPipeHandler=brokenClose;cancelCompletes=1;
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  assert(!ILibProcessPipe_Process_WindowsWriteHandler((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_INVALID_HANDLE,p));
  assert(cancelled>=1 && callbacks==1 && freed==1);
 }else if(!strcmp(argv[1],"wait-failed-pinned")){
  // If cancellation cannot be confirmed, nothing the kernel may still use is freed.
  p->brokenPipeHandler=brokenClose;
  assert(ILibProcessPipe_WindowsWrite(p,"abcdef",6,ILibTransport_MemoryOwnership_USER)==1);
  assert(!ILibProcessPipe_Process_WindowsWriteHandler((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_INVALID_HANDLE,p));
  assert(cancelled==1 && !callbacks && !freed && p->pendingWrite==1 && heldOv);
  puts("PASS");return 0; // Deliberately leaked; this case runs with leak detection off.
 }else if(!strcmp(argv[1],"direct-wait-failed")){
  cancelCompletes=1;
  assert(ILibProcessPipe_Pipe_WriteEx(p,"abcdef",6,NULL,directClose)==1);
  assert(!ILibProcessPipe_Pipe_WriteEx_sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_INVALID_HANDLE,p));
  assert(cancelled>=1 && callbacks==1 && freed==1);
 }else{assert(!"unknown test");}
 assert(!heldOv && freed==1);puts("PASS");return 0;
}
'''

def main():
    out = ROOT/'artifacts/validation/process-pipe-write'; out.mkdir(parents=True, exist_ok=True)
    production = (ROOT/'microstack/ILibProcessPipe.c').read_text()
    functions = [extract(production, name) for name in FUNCTIONS]
    # Production registers with static metadata; route it to the same registration model.
    limit = re.search(r'#define ILibProcessPipe_MAX_QUEUED_WRITE_BYTES (.+)', production).group(1)
    retire = '\nstatic BOOL ILibChain_RetireCancelledIo(HANDLE h,OVERLAPPED*ov){DWORD n=0;CancelIoEx(h,ov);if(!ready)return FALSE;GetOverlappedResult(h,ov,&n,FALSE);return TRUE;}\n'
    source = PRELUDE+'#define ILibProcessPipe_MAX_QUEUED_WRITE_BYTES '+limit+'\n'+ALLOCATORS+retire+'\nstatic void ILibChain_AddWaitHandleEx(void*c,HANDLE h,int t,BOOL(*f)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*),void*u,char*m){assert(m && *m);ILibChain_AddWaitHandle(c,h,t,f,u);}\n'+'\n'.join(signature+';' for signature, _ in functions)+'\n'+'\n'.join(signature+'\n'+body for signature,body in functions)+'\n'+TESTS
    fixture = out/'write-runtime.c'; fixture.write_text(source)
    binary = out/'write-runtime'
    compiler = shutil.which('clang') or shutil.which('cc')
    subprocess.run([compiler,'-std=c11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror','-Wall','-Wextra',str(fixture),'-o',str(binary)],check=True)
    cases = ['cancel-delayed','off-thread-close','partial-order-eof','broken-reentrant','completion-close','completion-write','cancel-success-race','bad-count','sync-partial','event-failure','data-allocation-failure','io-allocation-failure','direct-cancel','direct-reentrant','sync-handle-refused','write-after-end','mixed-write-refused','queue-accounting','queue-limit','wait-failed-retired','wait-failed-pinned','direct-wait-failed']
    for case in cases:
        leaks = '0' if sys.platform=='darwin' or case=='wait-failed-pinned' else '1'
        result = subprocess.run([str(binary),case],capture_output=True,text=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=' + leaks})
        (out/(case+'.log')).write_text('exit='+str(result.returncode)+'\n'+result.stdout+result.stderr)
        result.check_returncode(); assert result.stdout.strip()=='PASS'; print('PASS '+case)
    mingw = shutil.which('x86_64-w64-mingw32-gcc')
    if mingw:
        # Existing thread-signature / SDK inline warnings are captured, not hidden.
        result = subprocess.run([mingw,'-c',str(ROOT/'microstack/ILibProcessPipe.c'),'-o',str(out/'ILibProcessPipe-win64.o'),'-DWIN32','-DMICROSTACK_NOTLS','-DMICROSTACK_NO_STDAFX','-I'+str(ROOT/'microstack'),'-Wno-error=incompatible-pointer-types'],capture_output=True,text=True)
        (out/'windows-compile.log').write_text(result.stdout+result.stderr);result.check_returncode();print('PASS whole Windows pipe translation unit compile')
    else: print('SKIP Windows translation unit compile: MinGW unavailable')

if __name__=='__main__': main()
