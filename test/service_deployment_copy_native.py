#!/usr/bin/env python3
"""Fault-inject production atomic replacement and DLL-only provisioning checks.

Portable Win32 boundary mocks; no installed service or datastore is modified.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'meshservice/service_deployment.c').read_text()
masked=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m.group()),source,flags=re.S)
def extract(name):
    m=re.search(r'static (?:BOOL|const wchar_t\*)\s*'+name+r'\s*\([^;{]*\)\s*\{',masked)
    assert m,name
    end,depth=m.end(),1
    while depth:
        depth+=(masked[end]=='{')-(masked[end]=='}');end+=1
    return source[m.start():end]
prelude=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL;typedef uint32_t DWORD;typedef int HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE (-1)
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_PARAMETER 87
#define ERROR_SHARING_VIOLATION 32
#define ERROR_LOCK_VIOLATION 33
#define FILE_ATTRIBUTE_NORMAL 128
#define FILE_ATTRIBUTE_DIRECTORY 16
#define FILE_ATTRIBUTE_READONLY 1
#define FILE_ATTRIBUTE_REPARSE_POINT 1024
#define GENERIC_WRITE 1
#define FILE_SHARE_READ 1
#define OPEN_EXISTING 1
#define MOVEFILE_REPLACE_EXISTING 1
#define MOVEFILE_WRITE_THROUGH 8
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#define FAILED(x) ((x)<0)
#define SUCCEEDED(x) ((x)>=0)
static int StringCchCopyW(wchar_t* d,size_t n,const wchar_t* s){size_t k=wcslen(s);if(k>=n)return -1;memcpy(d,s,(k+1)*sizeof(wchar_t));return 0;}
static int StringCchCatW(wchar_t* d,size_t n,const wchar_t* s){return StringCchCopyW(d+wcslen(d),n-wcslen(d),s);}
static int failure,temporary,live,flushed,published;static DWORD error,attributes,tick;
static const char *original="old identity",*replacement="new identity";static const char* liveBytes;
static DWORD GetLastError(void){return error;}
static void SetLastError(DWORD e){error=e;}
static DWORD GetTickCount(void){return tick;}
static void Sleep(DWORD n){tick+=n;}
static BOOL ServiceUtil_PathsReferToSameFileW(const wchar_t* a,const wchar_t* b){return !wcscmp(a,b);}
static int GetTempFileNameW(const wchar_t* d,const wchar_t* p,int u,wchar_t* out){(void)d;(void)p;(void)u;if(failure==1){error=1117;return 0;}wcscpy(out,L"C:\\agent\\mcu.tmp");temporary=1;return 1;}
static BOOL CopyFileW(const wchar_t* a,const wchar_t* b,BOOL fail){(void)a;(void)fail;assert(wcsstr(b,L"mcu.tmp"));assert(liveBytes==original);if(failure==2){error=1117;return FALSE;}return TRUE;}
static BOOL SetFileAttributesW(const wchar_t* p,DWORD a){if(wcsstr(p,L"mcu.tmp")){if(failure==6){error=1117;return FALSE;}}else{attributes=a;}return TRUE;}
static HANDLE CreateFileW(const wchar_t* p,DWORD a,DWORD s,void* z,DWORD c,DWORD f,void* t){(void)p;(void)a;(void)s;(void)z;(void)c;(void)f;(void)t;if(failure==3){error=1117;return INVALID_HANDLE_VALUE;}return 1;}
static BOOL FlushFileBuffers(HANDLE h){(void)h;if(failure==4){error=1117;return FALSE;}flushed=1;return TRUE;}
static BOOL CloseHandle(HANDLE h){assert(h==1);return TRUE;}
static DWORD GetFileAttributesW(const wchar_t* p){(void)p;if(!live){error=ERROR_FILE_NOT_FOUND;return INVALID_FILE_ATTRIBUTES;}return failure==7?FILE_ATTRIBUTE_REPARSE_POINT:attributes;}
static BOOL MoveFileExW(const wchar_t* a,const wchar_t* b,DWORD flags){(void)a;(void)b;assert(flushed&&temporary&&(flags&MOVEFILE_WRITE_THROUGH));if(failure==5){error=1117;return FALSE;}published=live=1;temporary=0;liveBytes=replacement;return TRUE;}
static BOOL DeleteFileW(const wchar_t* p){assert(wcsstr(p,L"mcu.tmp"));temporary=0;return TRUE;}
#define ServiceDeploy_LogInstallEvent(...) ((void)0)
typedef struct {wchar_t exePath[MAX_PATH],confPath[MAX_PATH],dbPath[MAX_PATH];} ServiceInstallPaths;
static BOOL identity;
static BOOL ServiceDeploy_ConfigHasRequiredKeys(const wchar_t* p){(void)p;return FALSE;}
static BOOL ServiceDeploy_DataStoreIdentityPresent(const wchar_t* p){return p[0]&&identity;}
'''
cases=r'''
int main(void){
    for(int absent=0;absent<2;++absent)for(failure=0;failure<=7;++failure){
        temporary=flushed=published=tick=0;live=!absent;liveBytes=original;attributes=FILE_ATTRIBUTE_READONLY;
        BOOL ok=ServiceDeploy_CopyFileOverwrite(L"C:\\backup.db",L"C:\\agent\\identity.db");
        assert(ok==(!failure||(failure==7&&absent)));assert(!temporary);
        if(ok){assert(published&&liveBytes==replacement);}else{assert(!published&&live==!absent&&liveBytes==original&&attributes==FILE_ATTRIBUTE_READONLY);}
    }
    ServiceInstallPaths p={0};wcscpy(p.dbPath,L"C:\\old\\identity.db");wchar_t msh[MAX_PATH];identity=TRUE;
    assert(ServiceDeploy_InstalledProvisioningHealthy(&p,msh,MAX_PATH)&&!msh[0]);identity=FALSE;assert(!ServiceDeploy_InstalledProvisioningHealthy(&p,msh,MAX_PATH));
    assert(ServiceDeploy_BuildSiblingPathWithExtension(L"C:\\old.product\\identity",L".conf",msh,MAX_PATH));assert(!wcscmp(msh,L"C:\\old.product\\identity.conf"));
    puts("Deployment replacement: 16 fault cases preserve live bytes; DLL-only provisioning and dotted directories passed");return 0;
}
'''
functions='\n'.join(extract(n) for n in ('MeshInstaller_GetPathLeaf','ServiceDeploy_ExtractDirectoryFromPath','ServiceDeploy_BuildSiblingPathWithExtension','ServiceDeploy_BuildInstalledMshPath','ServiceDeploy_InstalledProvisioningHealthy','ServiceDeploy_CopyFileOverwrite'))
with tempfile.TemporaryDirectory(prefix='mesh-deploy-copy-') as tmp:
    c,exe=Path(tmp)/'copy.c',Path(tmp)/'copy';c.write_text(prelude+functions+cases)
    command=[os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror']
    if os.name!='nt':command+=['-fsanitize=address,undefined']
    subprocess.run(command+[str(c),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
