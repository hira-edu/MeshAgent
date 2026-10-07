#!/usr/bin/env python3
"""Compile/run production pipe transport against real Windows handles and children.

No service, clipboard, registry or installed-agent changes. Run with Python and
Clang on Windows; other hosts only cross-compile the fixture when MinGW exists.
The tiny test chain substitutes scheduling while pipe creation, writes, partial
completion and cancellation lifetimes come unchanged from production source.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
from process_pipe_write_runtime import ROOT, FUNCTIONS, extract

PRELUDE = r'''
#define WIN32 1
#include <windows.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef enum { ILibWaitHandle_ErrorStatus_NONE, ILibWaitHandle_ErrorStatus_IO_ERROR } ILibWaitHandle_ErrorStatus;
typedef enum { ILibTransport_DoneState_ERROR=-1, ILibTransport_DoneState_COMPLETE=0, ILibTransport_DoneState_INCOMPLETE=1 } ILibTransport_DoneState;
typedef enum { ILibTransport_MemoryOwnership_CHAIN, ILibTransport_MemoryOwnership_USER, ILibTransport_MemoryOwnership_STATIC } ILibTransport_MemoryOwnership;
typedef struct ILibProcessPipe_PipeObject ILibProcessPipe_PipeObject;
typedef ILibProcessPipe_PipeObject *ILibProcessPipe_Pipe;
typedef void (*ILibProcessPipe_GenericBrokenPipeHandler)(ILibProcessPipe_PipeObject*);
typedef void (*ILibProcessPipe_GenericSendOKHandler)(void*,void*);
typedef void (*ILibProcessPipe_Pipe_WriteExHandler)(ILibProcessPipe_Pipe,void*,int,int);
typedef struct ILibProcessPipe_Manager_Object { struct { void *ParentChain; } ChainLink; } ILibProcessPipe_Manager_Object;
typedef ILibProcessPipe_Manager_Object *ILibProcessPipe_Manager;
typedef struct { ILibProcessPipe_PipeObject *stdIn,*stdOut,*stdErr; } Process;
struct ILibProcessPipe_PipeObject {
 ILibProcessPipe_Manager_Object *manager; Process *mProcess;
 LONG closeRequested,finalFreePending,finalizing,activeReadCallbacks,activeWriteHandler,resumePending,pendingWrite;
 int PAUSED,writeClosing,writeOverlappedHandle;
 size_t writeQueuedBytes;
 HANDLE mPipe_ReadEnd,mPipe_WriteEnd,mPipe_Reader_ResumeEvent;
 OVERLAPPED *mOverlapped,*mwOverlapped;
 void *handler,*user1,*user2,*user3,*user4,*metadata,*WriteBuffer;
 ILibProcessPipe_GenericBrokenPipeHandler brokenPipeHandler;
 char *buffer; ILibTransport_MemoryOwnership bufferOwner;
};
typedef struct ILibProcessPipe_WriteData { char *buffer; int bufferLen,offset; ILibTransport_MemoryOwnership ownership; } ILibProcessPipe_WriteData;
#define ILibProcessPipe_WriteData_Destroy(d) if(d->ownership==ILibTransport_MemoryOwnership_CHAIN){free(d->buffer);} free(d)
#define ILibCriticalLog(...) ((void)0)
static volatile LONG ILibProcessPipe_PipeNameSequence;
#define ILibProcessPipe_PIPE_NAME_ATTEMPTS 8
static int freed;
static ILibProcessPipe_PipeObject *watched;
static LONG ILibProcessPipe_GetStateLong(LONG*v){return InterlockedCompareExchange(v,0,0);}
static int ILibMemory_CanaryOK(void*p){return p!=NULL;}
static void ILibMemory_Free(void*p){if(p==watched && p){++freed;}free(p);}
static void *ILibMemory_SmartAllocateEx(size_t size,int extra){return calloc(1,size+(size_t)extra);}
static int ILibIsRunningOnChainThread(void*c){(void)c;return TRUE;}
static void ILibChain_RunOnMicrostackThreadEx3(void*c,void(*f)(void*,void*),void(*a)(void*,void*),void*u){(void)a;f(c,u);}
static HANDLE waitEvent;
static BOOL (*waitCallback)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*);
static void *waitUser;
static void ILibChain_RemoveWaitHandleEx(void*c,HANDLE h,int clean){(void)c;(void)clean;if(h==waitEvent){waitEvent=NULL;waitUser=NULL;waitCallback=NULL;}}
#define ILibChain_RemoveWaitHandle(c,h) ILibChain_RemoveWaitHandleEx(c,h,0)
static void ILibChain_AddWaitHandle(void*c,HANDLE h,int t,BOOL(*f)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*),void*u){(void)c;(void)t;waitEvent=h;waitCallback=f;waitUser=u;}
static void ILibChain_AddWaitHandleEx(void*c,HANDLE h,int t,BOOL(*f)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*),void*u,char*m){(void)m;ILibChain_AddWaitHandle(c,h,t,f,u);}
typedef struct Node { void *value; struct Node *next; } Node;
typedef struct { Node *head,*tail; CRITICAL_SECTION lock; } Queue;
static void *ILibQueue_Create(void){Queue*q=calloc(1,sizeof(Queue));InitializeCriticalSection(&q->lock);return q;}
static void ILibQueue_Lock(void*q){EnterCriticalSection(&((Queue*)q)->lock);}
static void ILibQueue_UnLock(void*q){LeaveCriticalSection(&((Queue*)q)->lock);}
static int ILibQueue_IsEmpty(void*q){return ((Queue*)q)->head==NULL;}
static void ILibQueue_EnQueue(void*q,void*v){Queue*a=q;Node*n=calloc(1,sizeof(Node));n->value=v;if(a->tail)a->tail->next=n;else a->head=n;a->tail=n;}
static void *ILibQueue_PeekQueue(void*q){Queue*a=q;return a->head?a->head->value:NULL;}
static void *ILibQueue_DeQueue(void*q){Queue*a=q;Node*n=a->head;if(!n)return NULL;void*v=n->value;a->head=n->next;if(!a->head)a->tail=NULL;free(n);return v;}
static void ILibQueue_Destroy(void*q){assert(ILibQueue_IsEmpty(q));DeleteCriticalSection(&((Queue*)q)->lock);free(q);}
'''
TESTS = r'''
#define PAYLOAD (1024*1024)
static void dispatch(DWORD timeout){
 if(waitEvent && WaitForSingleObject(waitEvent,timeout)==WAIT_OBJECT_0){
  HANDLE h=waitEvent;void*u=waitUser;BOOL(*f)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*)=waitCallback;
  BOOL keep=f((void*)1,h,ILibWaitHandle_ErrorStatus_NONE,u);
  if(!keep && waitEvent==h && waitUser==u){waitEvent=NULL;waitUser=NULL;waitCallback=NULL;}
 }else{Sleep(1);}
}
static PROCESS_INFORMATION child(ILibProcessPipe_PipeObject*p,const char*mode){
 char exe[MAX_PATH],command[2*MAX_PATH];STARTUPINFOA si={0};PROCESS_INFORMATION pi={0};
 assert(GetModuleFileNameA(NULL,exe,sizeof(exe))>0);snprintf(command,sizeof(command),"\"%s\" --child %s",exe,mode);
 assert(ILibProcessPipe_PipeObject_DisableInherit(&p->mPipe_WriteEnd));
 si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=p->mPipe_ReadEnd;si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);si.hStdError=GetStdHandle(STD_ERROR_HANDLE);
 assert(CreateProcessA(exe,command,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi));
 CloseHandle(p->mPipe_ReadEnd);p->mPipe_ReadEnd=NULL;CloseHandle(pi.hThread);pi.hThread=NULL;return pi;
}
int main(int argc,char**argv){
 if(argc==3 && !strcmp(argv[1],"--child")){
  if(!strcmp(argv[2],"stall")){Sleep(INFINITE);return 9;}
  char buffer[4096];DWORD n,total=0;
  while(ReadFile(GetStdHandle(STD_INPUT_HANDLE),buffer,sizeof(buffer),&n,NULL) && n){
   for(DWORD i=0;i<n;i++){assert(buffer[i]==(total<PAYLOAD?'x':"tail"[total-PAYLOAD]));++total;assert(total<=PAYLOAD+4);}
  }
  assert(total==PAYLOAD+4);return 0;
 }
 ILibProcessPipe_Manager_Object manager={{(void*)1}};
 char *payload=malloc(PAYLOAD);memset(payload,'x',PAYLOAD);
 const char*modes[]={"read","cancel","crash"};
 for(int round=0;round<30;round++){
  const char*mode=modes[round%3];int before=freed;
  ILibProcessPipe_PipeObject*p=ILibProcessPipe_CreatePipeEx(&manager,4096,NULL,0,TRUE);assert(p);watched=p;
  PROCESS_INFORMATION pi=child(p,!strcmp(mode,"read")?"read":"stall");
  ULONGLONG start=GetTickCount64();
  assert(ILibProcessPipe_WindowsWrite(p,payload,PAYLOAD,ILibTransport_MemoryOwnership_USER)==ILibTransport_DoneState_INCOMPLETE);
  assert(GetTickCount64()-start<2000); // A stalled child must not block this thread.
  if(!strcmp(mode,"read")){
   assert(ILibProcessPipe_WindowsWrite(p,"tail",4,ILibTransport_MemoryOwnership_USER)==1);ILibProcessPipe_Pipe_Close(p);
   while(waitEvent && GetTickCount64()-start<10000){dispatch(10);}
   assert(!waitEvent);assert(WaitForSingleObject(pi.hProcess,10000)==WAIT_OBJECT_0);DWORD code;assert(GetExitCodeProcess(pi.hProcess,&code) && code==0);ILibProcessPipe_FreePipe(p);
  }else{
   int ticks=0;while(GetTickCount64()-start<100){dispatch(1);++ticks;}assert(ticks>10 && p->pendingWrite);
   if(!strcmp(mode,"cancel")){ILibProcessPipe_FreePipe(p);assert(freed==before);}
   assert(TerminateProcess(pi.hProcess,42));assert(WaitForSingleObject(pi.hProcess,10000)==WAIT_OBJECT_0);
   while(waitEvent && GetTickCount64()-start<10000){dispatch(10);}
   assert(!waitEvent);
  }
  assert(freed==before+1);CloseHandle(pi.hProcess);
 }
 free(payload);puts("PASS real Windows pipe: 30 drain/cancel/crash rounds, child synchronous stdio, parent responsiveness, EOF and cancellation completion");return 0;
}
'''

def main():
    out=ROOT/'artifacts/validation/process-pipe-windows';out.mkdir(parents=True,exist_ok=True)
    source=(ROOT/'microstack/ILibProcessPipe.c').read_text()
    names=FUNCTIONS+['ILibProcessPipe_CreatePipe_Abandon','ILibProcessPipe_CreatePipeEx','ILibProcessPipe_PipeObject_DisableInherit']
    functions=[extract(source,n) for n in names]
    # The production queue bound and the chain's real cancel-and-confirm helper.
    limit=re.search(r'#define ILibProcessPipe_MAX_QUEUED_WRITE_BYTES (.+)',source).group(1)
    retire=extract((ROOT/'microstack/ILibParsers.c').read_text(),'ILibChain_RetireCancelledIo')
    support='#define ILibProcessPipe_MAX_QUEUED_WRITE_BYTES '+limit+'\n'+retire[0]+'\n'+retire[1]+'\n'
    fixture=out/'windows-pipe.c';fixture.write_text(PRELUDE+'\n'+support+'\n'.join(s+';' for s,_ in functions)+'\n'+'\n'.join(s+'\n'+b for s,b in functions)+TESTS)
    compiler=(shutil.which('clang') if os.name=='nt' else shutil.which('x86_64-w64-mingw32-gcc'))
    if not compiler: print('SKIP real Windows pipe probe: Windows compiler unavailable');return
    binary=out/'windows-pipe.exe'
    result=subprocess.run([compiler,'-std=c11','-g','-O1',str(fixture),'-o',str(binary)],capture_output=True,text=True)
    (out/'compile.log').write_text(result.stdout+result.stderr);result.check_returncode();print('PASS real Windows pipe fixture compilation')
    if os.name!='nt': print('SKIP execution: requires Windows kernel');return
    result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=180)
    (out/'runtime.log').write_text(result.stdout+result.stderr);result.check_returncode();print(result.stdout.strip())
if __name__=='__main__':main()
