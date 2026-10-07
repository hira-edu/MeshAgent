#!/usr/bin/env python3
"""ASan regression for the production chain writer's partial-completion lifetime."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
from process_pipe_write_runtime import ROOT, PRELUDE, extract

EXTRA = r'''
typedef BOOL (*ILibChain_WriteEx_Handler)(void*,HANDLE,ILibWaitHandle_ErrorStatus,DWORD,void*);
typedef uint64_t ULONGLONG;
typedef struct ILibChain_WriteEx_data {
 ILibChain_WriteEx_Handler handler; char *buffer; DWORD bytesLeft,totalWritten; ULONGLONG baseOffset;
 HANDLE fileHandle; OVERLAPPED *p; void *user; char *metadata;
} ILibChain_WriteEx_data;
static void *waitUser;
static int expectError; static DWORD expectBytes;
static void *ILibMemory_SmartAllocate(size_t size){return calloc(1,size);}
static void ILibChain_AddWaitHandleEx(void*c,HANDLE h,int t,BOOL(*f)(void*,HANDLE,ILibWaitHandle_ErrorStatus,void*),void*u,char*m){(void)m;waitUser=u;ILibChain_AddWaitHandle(c,h,t,f,u);}
// When user is the OVERLAPPED, the caller's base offset must be restored before the handler.
static BOOL completed(void*c,HANDLE h,ILibWaitHandle_ErrorStatus e,DWORD n,void*u){(void)c;(void)h;++callbacks;assert(e==(expectError?ILibWaitHandle_ErrorStatus_IO_ERROR:ILibWaitHandle_ErrorStatus_NONE) && n==expectBytes);if(u)assert(((OVERLAPPED*)u)->Offset==100);return FALSE;}
'''
TEST = r'''
int main(int argc,char**argv){
 assert(argc==2);OVERLAPPED ov={(void*)9};
 expectError=!strcmp(argv[1],"partial-then-error") || !strcmp(argv[1],"partial-then-sync-error");
 expectBytes=expectError?2:6;
 if(!strcmp(argv[1],"offset-sync-partial")){
  // A file write reissued after a short write continues at base+written, not at base.
  mode=2;ov.Offset=100;assert(ILibChain_WriteEx2((void*)1,(void*)7,&ov,"abcdef",6,completed,&ov,NULL)==0);
  assert(writeCalls==3 && offsets[0]==100 && offsets[1]==102 && offsets[2]==104 && ov.Offset==100 && deliveredLength==6);
  puts("PASS");return 0;
 }
 if(!strcmp(argv[1],"offset-async-partial")){
  mode=1;ov.Offset=100;assert(ILibChain_WriteEx2((void*)1,(void*)7,&ov,"abcdef",6,completed,&ov,NULL)==1);
  completedBytes=2;ready=1;assert(ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));
  assert(writeCalls==2 && offsets[0]==100 && offsets[1]==102 && !callbacks);
  completedBytes=0;ready=1;assert(!ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));
  assert(callbacks==1 && freed==1 && ov.Offset==100 && deliveredLength==6 && !heldOv);
  puts("PASS");return 0;
 }
 if(!strcmp(argv[1],"wait-failed-retired") || !strcmp(argv[1],"wait-failed-pinned")){
  // The chain drops the registration after INVALID_HANDLE, so the sink must settle now:
  // report and free once the kernel releases the request, otherwise keep it pinned.
  int retired=!strcmp(argv[1],"wait-failed-retired");
  mode=1;cancelCompletes=retired;expectError=1;expectBytes=0;
  assert(ILibChain_WriteEx2((void*)1,(void*)7,&ov,"abcdef",6,completed,NULL,NULL)==1);
  assert(!ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_INVALID_HANDLE,waitUser));
  assert(cancelled==1);
  if(retired){assert(callbacks==1 && freed==1 && !heldOv);}
  else{assert(!callbacks && !freed && heldOv);}
  puts("PASS");return 0;
 }
 mode=!strcmp(argv[1],"sync-partial")?2:1;
 ILibTransport_DoneState state=ILibChain_WriteEx2((void*)1,(void*)7,&ov,"abcdef",6,completed,NULL,NULL);
 if(mode==2){assert(state==0 && deliveredLength==6 && writeCalls==3 && !callbacks);}
 else if(expectError){
  assert(state==1 && !freed);completedBytes=2;ready=1;
  if(!strcmp(argv[1],"partial-then-sync-error")){mode=3;}
  else{
   assert(ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));
   assert(!freed && !callbacks);ready=aborted=1;
  }
  assert(!ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));
  assert(freed==1 && callbacks==1 && deliveredLength==2 && !memcmp(delivered,"ab",2));
 }
 else{
  assert(state==1 && !freed);
  assert(ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));assert(!freed);
  completedBytes=2;ready=1;
  assert(ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));assert(!freed && !callbacks);
  ready=1;assert(ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));assert(!freed && !callbacks);
  ready=1;assert(!ILibChain_WriteEx_Sink((void*)1,(void*)9,ILibWaitHandle_ErrorStatus_NONE,waitUser));assert(freed==1 && callbacks==1 && deliveredLength==6 && !memcmp(delivered,"abcdef",6));
 }
 assert(!heldOv);puts("PASS");return 0;
}
'''

def main():
    out=ROOT/'artifacts/validation/chain-write';out.mkdir(parents=True,exist_ok=True)
    source=(ROOT/'microstack/ILibParsers.c').read_text()
    functions=[extract(source,n) for n in ['ILibChain_RetireCancelledIo','ILibChain_WriteEx_GetOffset','ILibChain_WriteEx_SetOffset','ILibChain_WriteEx_Sink','ILibChain_WriteEx2']]
    fixture=out/'chain-write.c';fixture.write_text(PRELUDE+EXTRA+'\n'+'\n'.join(s+';' for s,_ in functions)+'\n'+'\n'.join(s+'\n'+b for s,b in functions)+TEST)
    binary=out/'chain-write'
    subprocess.run([shutil.which('clang') or 'cc','-std=c11','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(fixture),'-o',str(binary)],check=True)
    for case in ['sync-partial','async-partial','partial-then-error','partial-then-sync-error','offset-sync-partial','offset-async-partial','wait-failed-retired','wait-failed-pinned']:
        # The pinned case deliberately leaks storage the kernel might still own.
        leaks='0' if sys.platform=='darwin' or case=='wait-failed-pinned' else '1'
        result=subprocess.run([str(binary),case],capture_output=True,text=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks='+leaks})
        (out/(case+'.log')).write_text(result.stdout+result.stderr);result.check_returncode();print('PASS chain writer '+case)
    cross=shutil.which('x86_64-w64-mingw32-gcc')
    if cross:
        native=out/'windows-chain-write.c'
        native.write_text('#define WIN32 1\n#define MICROSTACK_NO_STDAFX 1\n#define MICROSTACK_NOTLS 1\n#include "ILibParsers.h"\n'+'\n'.join(s+';' for s,_ in functions)+'\n'+'\n'.join(s+'\n'+b for s,b in functions))
        subprocess.run([cross,'-std=c11','-Werror','-I'+str(ROOT/'microstack'),'-c',str(native),'-o',str(out/'windows-chain-write.o')],check=True)
        print('PASS production chain writer compile against Windows headers')
if __name__=='__main__': main()
