#!/usr/bin/env python3
"""Execute production clipboard ownership/cleanup and launch validation with OS faults.

Runs on POSIX with ASan/UBSan; uses disposable memory, never a live clipboard.
Also cross-compiles the complete native bridge against Windows headers when a
MinGW compiler is available. This does not replace the MSBuild/package/live gate.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def extract(source, name):
    start = re.search(r'^static (?:DWORD|int|BOOL) ' + name + r'\(', source, re.M).start()
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' '*len(m[0]), source, flags=re.S)
    opening = masked.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[start:end]

PRELUDE = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <stdint.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef size_t SIZE_T;
typedef void *HGLOBAL;
typedef void *HWND;
typedef int MSG;
#define HWND_MESSAGE ((void*)-3)
#define PM_REMOVE 1
#define ERROR_INVALID_WINDOW_HANDLE 1400
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_INVALID_FUNCTION 1
#define ERROR_ACCESS_DENIED 5
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_INVALID_DATA 13
#define ERROR_BUFFER_OVERFLOW 111
#define MESH_CLIPBOARD_MAX_BYTES (1024UL * 1024UL)
#define GMEM_MOVEABLE 2
#define CP_UTF8 65001
#define MB_ERR_INVALID_CHARS 8
#define WC_ERR_INVALID_CHARS 128
#define CF_UNICODETEXT 13
static int fault, opened, closes, allocations, frees, locks, unlocks, sleeps, sets, empties;
static int windowsCreated,windowsDestroyed;
static DWORD last_error;
static wchar_t clipboard[20] = L"hello";
static HGLOBAL transferred;
static DWORD GetLastError(void) { return last_error; }
static void Sleep(DWORD ms) { assert(ms==20); ++sleeps; }
static HWND GetModuleHandleW(void* name){assert(!name);return (void*)3;}
static HWND CreateWindowExW(int style,const wchar_t* klass,void* name,int flags,int x,int y,int w,int h,HWND parent,void* menu,HWND module,void* data){assert(!style && !name && !flags && !x && !y && !w && !h && parent==HWND_MESSAGE && !menu && module==(void*)3 && !data && !wcscmp(klass,L"STATIC"));if(fault==15)return NULL;++windowsCreated;return (void*)1;}
static BOOL PeekMessageW(MSG*m,HWND w,int a,int b,int remove){(void)m;assert(w==(void*)1 && !a && !b && remove==1);return FALSE;}
static BOOL DispatchMessageW(MSG*m){(void)m;return TRUE;}
static BOOL DestroyWindow(HWND w){assert(w==(void*)1);++windowsDestroyed;return TRUE;}
static BOOL OpenClipboard(HWND owner) { assert(owner==NULL || owner==(void*)1); if(fault==1 || (fault==2 && sleeps<2)) { last_error=5; return FALSE; } opened=1; return TRUE; }
static BOOL CloseClipboard(void) { assert(opened); opened=0; ++closes; return TRUE; }
static BOOL EmptyClipboard(void) { assert(opened); ++empties; if(fault==3) { last_error=5; return FALSE; } return TRUE; }
static HGLOBAL GlobalAlloc(int flags, SIZE_T bytes) { assert(flags==2); if(fault==4) return NULL; ++allocations; return calloc(1,bytes); }
static void* GlobalLock(HGLOBAL mem) { if(fault==5 || fault==17) {last_error=fault==17?0:5; return NULL;} ++locks; return mem; }
static BOOL GlobalUnlock(HGLOBAL mem) { assert(mem); ++unlocks; return TRUE; }
static HGLOBAL GlobalFree(HGLOBAL mem) { assert(mem != clipboard); ++frees; free(mem); return NULL; }
static HGLOBAL SetClipboardData(int fmt, HGLOBAL mem) { assert(opened && fmt==13); ++sets; if(fault==6) {last_error=5; return NULL;} transferred=mem; return mem; }
static BOOL IsClipboardFormatAvailable(int fmt) { assert(fmt==13); return fault!=7; }
static HGLOBAL GetClipboardData(int fmt) { assert(fmt==13 && opened); if(fault==8 || fault==16) { last_error=fault==16?0:5; return NULL; } return clipboard; }
static SIZE_T GlobalSize(HGLOBAL mem) { assert(mem==clipboard); return fault==9 ? (MESH_CLIPBOARD_MAX_BYTES+2)*sizeof(wchar_t) : (fault==10 ? 3*sizeof(wchar_t) : sizeof(clipboard)); }
// Inject encoding success/failure at the OS conversion boundary.
static int MultiByteToWideChar(int cp, int flags, const char* text, int count, wchar_t* out, int capacity) {
 assert(cp==65001 && flags==8); if(fault==11) {last_error=13;return 0;}
 if(out) {assert(capacity==count);for(int i=0;i<count;i++)out[i]=(unsigned char)text[i];} return count;
}
static int WideCharToMultiByte(int cp, int flags, const wchar_t* text, int count, char* out, int capacity, void* a, void* b) {
 assert(cp==65001 && flags==128 && !a && !b); if(fault==12) {last_error=13;return 0;}
 if(fault==13)return MESH_CLIPBOARD_MAX_BYTES+1;
 if(fault==14 && out) {last_error=13;return 0;}
 if(out) {assert(capacity==count);for(int i=0;i<count;i++)out[i]=(char)text[i];} return count;
}
#define MAX_PATH 260
#define MESH_RUNTIME_HOST_ENTRY_CLIPBOARD_BRIDGE_A "MeshClipboardBridgeW"
static int exact=1;
static void ILibProcessPipe_SetBridgePolicyRejectReasonA(const char* reason) { assert(strcmp(reason,"ok-clipboard")==0); }
static int ILibProcessPipe_IsExactSystemRuntimeHostTargetA(char* path) { return strcmp(path,"rundll32")==0; }
static int ILibProcessPipe_TryParseRuntimeHostModuleEntryA(const char* arg, const char* expected, char* module, size_t bytes, const char* reason) {
 assert(strcmp(expected,"MeshClipboardBridgeW")==0 && strcmp(reason,"clipboard-module")==0); if(strcmp(arg,"agent.dll,MeshClipboardBridgeW")) return 0; snprintf(module,bytes,"agent.dll"); return 1;
}
static int ILibProcessPipe_IsExactBridgeModuleDllPathA(const char* module, const char* expected) { assert(strcmp(module,"agent.dll")==0 && strcmp(expected,"MeshClipboardBridgeW")==0); return exact; }
'''
SESSION = r'''
typedef void *HANDLE;
typedef struct { struct { DWORD LowPart; long HighPart; } AuthenticationId; } TOKEN_STATISTICS;
#define TokenStatistics 10
static int sessionFault,tokenCloses;
static BOOL WTSQueryUserToken(DWORD id,HANDLE*out){assert(id==3);if(sessionFault==1)return FALSE;*out=(void*)2;return TRUE;}
static BOOL GetTokenInformation(HANDLE t,int kind,TOKEN_STATISTICS*out,DWORD bytes,DWORD*length){
 assert(kind==10 && bytes==sizeof(*out));*length=bytes;
 if((sessionFault==2 && t==(void*)1)||(sessionFault==3 && t==(void*)2))return FALSE;
 out->AuthenticationId.LowPart=sessionFault==4 && t==(void*)2?11:10;
 out->AuthenticationId.HighPart=sessionFault==5 && t==(void*)2?1:0;return TRUE;
}
static BOOL CloseHandle(HANDLE t){assert(t==(void*)2);++tokenCloses;return TRUE;}
static void SetLastError(DWORD error){last_error=error;}
'''
MAIN = r'''
static void reset(int failure) { assert(!opened && windowsCreated==windowsDestroyed); windowsCreated=windowsDestroyed=0; fault=failure; closes=allocations=frees=locks=unlocks=sleeps=sets=empties=0;last_error=0;transferred=NULL; }
int main(void) {
 char *text; DWORD bytes,error;
 for(sessionFault=0;sessionFault<=5;sessionFault++){
  tokenCloses=0;assert(MeshClipboard_SessionMatches((void*)1,3)==(sessionFault==0));assert(tokenCloses==(sessionFault==1?0:1));
 }
 reset(0); text=NULL; bytes=0; error=MeshClipboard_Text(1,&text,&bytes); assert(!error && bytes==5 && !memcmp(text,"hello",5));free(text);assert(closes==1 && locks==unlocks);
 for(int f=1;f<=17;f++) {
  reset(f);text=NULL;bytes=0;error=MeshClipboard_Text(1,&text,&bytes);
  if(f==2 || f==3 || f==4 || f==6 || f==9 || f==11 || f==15) {assert(!error && bytes==5);free(text);}
  else if(f==7) {assert(!error && !bytes && !text);}
  else {assert(error && !text && !bytes);}
  assert(!opened && locks==unlocks && frees==0); if(f!=1)assert(closes==1);else assert(sleeps==5);assert(!windowsCreated && !windowsDestroyed);
 }
 for(int f=0;f<=17;f++) {
  reset(f);text="write";bytes=5;error=MeshClipboard_Text(2,&text,&bytes);
  if(f==1 || f==3 || f==4 || f==5 || f==6 || f==11 || f==15 || f==17) {assert(error && sets <= 1);assert(allocations==frees);}
  else {assert(!error && bytes==0 && allocations==1 && frees==0 && transferred);GlobalFree(transferred);}
  assert(!opened && locks==unlocks);assert(allocations==frees);assert(windowsCreated==windowsDestroyed);
 }
 reset(0);text="";bytes=0;assert(!MeshClipboard_Text(2,&text,&bytes));assert(((wchar_t*)transferred)[0]==0);GlobalFree(transferred);
 reset(0);text="a\0b";bytes=3;assert(MeshClipboard_Text(2,&text,&bytes)==13 && !allocations && !empties);
 reset(0);text="x";bytes=MESH_CLIPBOARD_MAX_BYTES+1;assert(MeshClipboard_Text(2,&text,&bytes)==13 && !allocations);
 reset(0);clipboard[0]=0;text=NULL;bytes=0;assert(!MeshClipboard_Text(1,&text,&bytes) && !bytes && !text && closes==1);
 char* args[]={"agent.dll,MeshClipboardBridgeW","tsid=3",NULL,NULL};
 assert(ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("rundll32",args));
 const char* bad[]={"tsid=0","tsid=-1","tsid=1.2","tsid=4294967295","tsid=99999999999999999999","tsid=","user","tsid=3 extra",NULL};
 for(int i=0;bad[i];i++){args[1]=(char*)bad[i];assert(!ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("rundll32",args));}
 args[1]="local";assert(ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("rundll32",args));
 args[1]="tsid=4294967294";assert(ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("rundll32",args));
 args[2]="extra";assert(!ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("rundll32",args));args[2]=NULL;
 exact=0;assert(!ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("rundll32",args));exact=1;
 assert(!ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("fake-rundll32",args));args[0]="other.dll,MeshClipboardBridgeW";assert(!ILibProcessPipe_IsApprovedClipboardBridgeLaunchA("rundll32",args));
 puts("Native clipboard: bounded reads, ownership transfer, contention, allocation/conversion/lock/write failures, cleanup and launch policy passed.");return 0;
}
'''

def main():
    clipboard = (ROOT/'meshservice/clipboard_bridge.h').read_text()
    policy = (ROOT/'microstack/ILibProcessPipe.c').read_text()
    with tempfile.TemporaryDirectory(prefix='mesh-clipboard-') as directory:
        directory = Path(directory)
        c = directory/'probe.c'
        c.write_text(PRELUDE + SESSION + extract(clipboard,'MeshClipboard_SessionMatches') + extract(clipboard,'MeshClipboard_Text') + extract(policy,'ILibProcessPipe_IsApprovedClipboardBridgeLaunchA') + MAIN)
        compiler = os.environ.get('CC',shutil.which('clang') or 'cc')
        subprocess.run([compiler,'-std=c11','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(directory/'probe')],check=True)
        subprocess.run([str(directory/'probe')],check=True)
        cross = shutil.which('x86_64-w64-mingw32-gcc')
        if cross:
            c.write_text('''#include <windows.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "meshservice/runtime_host_contract.h"
#include "meshservice/process_token_contract.h"
extern BOOL MeshRuntimeHost_CopyNextTokenW(const wchar_t**, wchar_t*, size_t);
extern BOOL MeshConsoleBridge_ParseUnsignedTokenW(const wchar_t*, DWORD, DWORD, DWORD*);
#include "meshservice/clipboard_bridge.h"
DWORD compile_entry(const wchar_t* args, HINSTANCE dll) { return MeshClipboard_Run(args,dll); }
''')
            subprocess.run([cross,'-D_WIN32_WINNT=0x0601','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT),'-c',str(c),'-o',str(directory/'clipboard.o')],check=True)
            print('Complete native bridge cross-compiled against Windows headers with warnings treated as errors.')
        else:
            print('Windows-header cross-compile unavailable; run MSBuild on Windows.')
if __name__ == '__main__':
    main()
