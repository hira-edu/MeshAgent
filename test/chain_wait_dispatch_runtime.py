#!/usr/bin/env python3
"""ASan regression for the Windows chain's TIMEOUT / INVALID_HANDLE wait dispatch.

Extracts the production dispatch helper and the remove-wait-handle APC unchanged and
runs them against a heap-backed handle list, so removing a node twice, or touching it
after a handler removed it, is reported by ASan. Handlers that remove their own
registration during an error callback are the case that used to free a node the
chain then removed again.
"""
import os
import shutil
import subprocess
import sys
from process_pipe_write_runtime import ROOT, extract

PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __stdcall
#define FALSE 0
#define TRUE 1
#define FD_SETSIZE 4
#define ILibChain_HandleInfoIndex(i) (FD_SETSIZE+i)
typedef int BOOL;
typedef void *HANDLE;
typedef uintptr_t ULONG_PTR;
typedef enum { ILibWaitHandle_ErrorStatus_NONE=0, ILibWaitHandle_ErrorStatus_INVALID_HANDLE=1, ILibWaitHandle_ErrorStatus_TIMEOUT=2 } ILibWaitHandle_ErrorStatus;
typedef BOOL (*ILibChain_WaitHandleHandler)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*);
typedef struct ILibChain_WaitHandleInfo { void *node; ILibChain_WaitHandleHandler handler; void *user; } ILibChain_WaitHandleInfo;
typedef struct { HANDLE currentHandle; ILibChain_WaitHandleInfo *currentInfo; void *auxSelectHandles; int UnblockFlag; } ILibBaseChain;
typedef struct Node { HANDLE h; struct Node *next; ILibChain_WaitHandleInfo info; } Node;
typedef struct { Node *head; } List;
static List handles;
static int removes;
static void *ILibLinkedList_GetNode_Search(void *list, void *cmp, HANDLE h){(void)cmp;for(Node*n=((List*)list)->head;n;n=n->next){if(n->h==h)return n;}return NULL;}
static void *ILibMemory_Extra(void *node){return &((Node*)node)->info;}
static int ILibMemory_CanaryOK(void *p){return p!=NULL;}
static void ILibMemory_Free(void *p){(void)p;}
// Unlinks and frees the node, so a second removal or a later access is a heap error.
static void ILibLinkedList_Remove(void *node){
 Node *n=node,**link=&handles.head;while(*link&&*link!=n)link=&(*link)->next;
 assert(*link==n);*link=n->next;++removes;free(n);
}
'''

TEST = r'''
static ILibBaseChain chain;
static HANDLE waitList[2*FD_SETSIZE];
static int calls;
static BOOL keepIt(void*c,HANDLE h,ILibWaitHandle_ErrorStatus s,void*u){(void)c;(void)h;(void)s;(void)u;++calls;return TRUE;}
static BOOL dropIt(void*c,HANDLE h,ILibWaitHandle_ErrorStatus s,void*u){(void)c;(void)h;(void)s;(void)u;++calls;return FALSE;}
// Same as a handler calling ILibChain_RemoveWaitHandle on its own handle from the chain thread.
static BOOL removeSelf(void*c,HANDLE h,ILibWaitHandle_ErrorStatus s,void*u){(void)s;(void)u;++calls;void *tmp[3]={c,h,(void*)0};ILibChain_RemoveWaitHandle_APC((ULONG_PTR)tmp);return FALSE;}
static void arm(ILibChain_WaitHandleHandler handler){
 Node *n=calloc(1,sizeof(*n));n->h=(void*)0x41;n->info.node=n;n->info.handler=handler;n->info.user=(void*)1;
 n->next=handles.head;handles.head=n;waitList[0]=n->h;waitList[ILibChain_HandleInfoIndex(0)]=&n->info;
 removes=calls=0;chain.auxSelectHandles=&handles;
}
static void settled(int expectRemoves,int expectCalls){
 assert(removes==expectRemoves && calls==expectCalls);
 assert(chain.currentHandle==NULL && chain.currentInfo==NULL);
 assert(waitList[0]==NULL && waitList[ILibChain_HandleInfoIndex(0)]==NULL);
 assert((handles.head!=NULL)==(expectRemoves==0));
 while(handles.head){Node*n=handles.head;handles.head=n->next;free(n);}
}
int main(int argc,char**argv){
 assert(argc==2);const char *c=argv[1];
 if(!strcmp(c,"invalid-keep")){arm(keepIt);ILibChain_DispatchWaitHandleError(&chain,waitList,0,ILibWaitHandle_ErrorStatus_INVALID_HANDLE);settled(1,1);}
 else if(!strcmp(c,"invalid-self-remove")){arm(removeSelf);ILibChain_DispatchWaitHandleError(&chain,waitList,0,ILibWaitHandle_ErrorStatus_INVALID_HANDLE);settled(1,1);}
 else if(!strcmp(c,"timeout-keep")){arm(keepIt);ILibChain_DispatchWaitHandleError(&chain,waitList,0,ILibWaitHandle_ErrorStatus_TIMEOUT);settled(0,1);}
 else if(!strcmp(c,"timeout-drop")){arm(dropIt);ILibChain_DispatchWaitHandleError(&chain,waitList,0,ILibWaitHandle_ErrorStatus_TIMEOUT);settled(1,1);}
 else if(!strcmp(c,"timeout-self-remove")){arm(removeSelf);ILibChain_DispatchWaitHandleError(&chain,waitList,0,ILibWaitHandle_ErrorStatus_TIMEOUT);settled(1,1);}
 else if(!strcmp(c,"no-handler")){arm(NULL);ILibChain_DispatchWaitHandleError(&chain,waitList,0,ILibWaitHandle_ErrorStatus_TIMEOUT);settled(1,0);}
 else{assert(!"unknown case");}
 puts("PASS");return 0;
}
'''

CASES = ['invalid-keep', 'invalid-self-remove', 'timeout-keep', 'timeout-drop', 'timeout-self-remove', 'no-handler']

def main():
    out = ROOT/'artifacts/validation/chain-wait-dispatch'; out.mkdir(parents=True, exist_ok=True)
    source = (ROOT/'microstack/ILibParsers.c').read_text()
    functions = [extract(source, name) for name in ['ILibChain_RemoveWaitHandle_APC', 'ILibChain_DispatchWaitHandleError']]
    fixture = out/'dispatch.c'
    fixture.write_text(PRELUDE+'\n'.join(s+';' for s, _ in functions)+'\n'+'\n'.join(s+'\n'+b for s, b in functions)+TEST)
    binary = out/'dispatch'
    compiler = shutil.which('clang') or shutil.which('cc')
    subprocess.run([compiler,'-std=c11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror','-Wall','-Wextra',str(fixture),'-o',str(binary)], check=True)
    for case in CASES:
        result = subprocess.run([str(binary), case], capture_output=True, text=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks='+('0' if sys.platform=='darwin' else '1')})
        (out/(case+'.log')).write_text('exit='+str(result.returncode)+'\n'+result.stdout+result.stderr)
        result.check_returncode(); assert result.stdout.strip() == 'PASS'; print('PASS chain wait dispatch '+case)

if __name__ == '__main__':
    main()
