#!/usr/bin/env python3
"""Verify KVM session launch/credential setup without accessing the desktop.

Fault injection covers privileged transitions; a separate child exercises the
real current-user initializer. No service is installed and no root is requested.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, help='Also verify the built KVM CLI rejects invalid sessions before desktop access')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/KVM/MacOS/mac_kvm.c').read_text()
start = source.index('int MacKvm_InitializeSessionUser(')
end = source.index('\n// Return the output pipe', start)
initializer = source[start:end]
start = source.index('void* kvm_relay_setup(')
launcher = source[start:source.index('\n// Force a KVM reset', start)]
start = source.index('void kvm_relay_ExitHandler(')
exit_handler = source[start:source.index('\nvoid kvm_relay_StdOutHandler(', start)]
headers = r'''
#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
'''
mock = r'''
static uid_t realId,effectiveId,consoleId;
static gid_t realGroup,effectiveGroup;
static int failure,stage,spawnCount,spawnFail,freed;
static int initgroupsCalls,setgidCalls,setuidCalls;
static uid_t fake_getuid(void){return realId;}
static uid_t fake_geteuid(void){return effectiveId;}
static gid_t fake_getgid(void){return realGroup;}
static gid_t fake_getegid(void){return effectiveGroup;}
static int fake_stat(const char *path,struct stat *s){assert(!strcmp(path,"/dev/console"));s->st_uid=consoleId;return failure==1?-1:0;}
static int fake_getpwuid_r(uid_t uid,struct passwd *p,char*b,size_t n,struct passwd **out){
    (void)b;(void)n;assert(uid==501);if(failure==2){*out=NULL;return ENOENT;}
    memset(p,0,sizeof(*p));p->pw_uid=uid;p->pw_gid=20;p->pw_name="desktop";p->pw_dir="/Users/A & B";p->pw_shell="/bin/zsh";*out=p;return 0;
}
static int fake_initgroups(const char *name,gid_t gid){assert(!strcmp(name,"desktop")&&gid==20&&stage==0);stage=1;++initgroupsCalls;return failure==3?-1:0;}
static int fake_setgid(gid_t gid){assert(stage==1&&gid==20);stage=2;++setgidCalls;if(failure==4)return -1;realGroup=effectiveGroup=gid;return 0;}
static int fake_setuid(uid_t uid){assert(stage==2&&uid==501);stage=3;++setuidCalls;if(failure==5)return -1;realId=effectiveId=uid;return 0;}
static int fake_setenv(const char *key,const char *value,int overwrite){
    assert(effectiveId==501&&overwrite==1);
    if(!strcmp(key,"HOME"))assert(!strcmp(value,"/Users/A & B"));
    else if(!strcmp(key,"SHELL"))assert(!strcmp(value,"/bin/zsh"));
    else {assert(!strcmp(key,"USER")||!strcmp(key,"LOGNAME"));assert(!strcmp(value,"desktop"));}
    return failure==6?-1:0;
}
static int fake_unsetenv(const char *key){assert(!strcmp(key,"TMPDIR"));return failure==7?-1:0;}
static int fake_chdir(const char *path){assert(!strcmp(path,"/"));return failure==8?-1:0;}
#define getuid fake_getuid
#define geteuid fake_geteuid
#define getgid fake_getgid
#define getegid fake_getegid
#define stat fake_stat
#define getpwuid_r fake_getpwuid_r
#define initgroups fake_initgroups
#define setgid fake_setgid
#define setuid fake_setuid
#define setenv fake_setenv
#define unsetenv fake_unsetenv
#define chdir fake_chdir
// Keep the struct tag separate from the mocked stat() call.
#define fake_stat stat
'''
# Use a function-like macro so the struct stat tag remains untouched.
mock = mock.replace('#define stat fake_stat', '#define stat(path, data) fake_stat(path, data)').replace('#define fake_stat stat', '')
launcher_stubs = r'''
typedef void* ILibProcessPipe_Process;
typedef int (*ILibKVM_WriteHandler)(char*,int,void*);
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define KVM_Listener_Path "/fixture/login-window"
#define ILibProcessPipe_SpawnTypes_DEFAULT 0
static void *gChildProcess, *lastUser;
static int g_slavekvm,g_shutdown;
static void *ILibMemory_Allocate(size_t size,int extra,void*a,void*b){(void)extra;(void)a;(void)b;return calloc(1,size);}
static void ILibMemory_Free(void *p){++freed;free(p);}
static void kvm_relay_StdOutHandler(void){}
static void kvm_relay_StdErrHandler(void){}
static void ILibProcessPipe_Process_UpdateUserObject(void *p,void *u){assert(p==(void*)1);lastUser=u;}
static void *ILibProcessPipe_Manager_SpawnProcessEx3(void *mgr,char *exe,char **argv,int type,void *uid,int extra){
    (void)mgr;assert(type==0&&uid==NULL&&extra==0);++spawnCount;
    assert(!strcmp(exe,"/bin/launchctl"));
    assert(!strcmp(argv[0],"launchctl")&&!strcmp(argv[1],"asuser")&&!strcmp(argv[2],"501"));
    assert(!strcmp(argv[3],"/fixture/quoted ' agent")&&!strcmp(argv[4],"-kvm0"));
    assert(!strcmp(argv[5],"--session-uid")&&!strcmp(argv[6],"501")&&argv[7]==NULL);
    return spawnFail?NULL:(void*)1;
}
static int ILibProcessPipe_Process_GetPID(void *p){assert(p==(void*)1);return 42;}
static void ILibProcessPipe_Process_ResetMetadata(void *p,char *s){assert(p==(void*)1&&strstr(s,"42"));}
static void ILibProcessPipe_Process_AddHandlers(void *p,int size,void(*a)(void*,int,void*),void(*b)(void),void(*c)(void),void*d,void*u){
    assert(p==(void*)1&&size==65535&&a&&b&&c&&!d);lastUser=u;
}
static void *ILibProcessPipe_Process_GetStdOut(void *p){assert(p==(void*)1);return (void*)2;}
'''
main = r'''
static void reset(void){realId=effectiveId=0;realGroup=effectiveGroup=0;consoleId=501;failure=stage=initgroupsCalls=setgidCalls=setuidCalls=0;}
static int ended;
static int endSession(char *b,int n,void *reserved){assert(b==NULL&&n==0&&reserved==(void*)3);++ended;return 0;}
int main(void){
    reset();assert(MacKvm_InitializeSessionUser("501")==0);assert(stage==3&&realId==501&&realGroup==20);
    for(int i=1;i<=8;++i){reset();failure=i;assert(MacKvm_InitializeSessionUser("501")==-1);}
    reset();consoleId=502;assert(MacKvm_InitializeSessionUser("501")==-1&&stage==0);
    const char *invalid[]={"","0","-1","501x"," 501","2147483648","99999999999999999999999"};
    for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i){reset();assert(MacKvm_InitializeSessionUser(invalid[i])==-1&&stage==0);}
    reset();assert(MacKvm_InitializeSessionUser(NULL)==-1); // root cannot bypass the launcher
    reset();realId=effectiveId=501;realGroup=effectiveGroup=20;assert(MacKvm_InitializeSessionUser(NULL)==0&&stage==0);
    reset();realId=effectiveId=502;assert(MacKvm_InitializeSessionUser("501")==-1&&stage==0);
    reset();realId=effectiveId=501;assert(MacKvm_InitializeSessionUser("501")==-1); // inherited root group
    reset();assert(kvm_relay_setup("/fixture/quoted ' agent",NULL,NULL,NULL,501)==(void*)2);ILibMemory_Free(lastUser);
    reset();effectiveId=501;assert(kvm_relay_setup("/fixture/quoted ' agent",NULL,NULL,NULL,501)==(void*)2);ILibMemory_Free(lastUser);
    int before=spawnCount;effectiveId=502;assert(kvm_relay_setup("/fixture/quoted ' agent",NULL,NULL,NULL,501)==NULL&&spawnCount==before);
    effectiveId=0;assert(!strcmp(kvm_relay_setup("/fixture/quoted ' agent",NULL,NULL,NULL,0),KVM_Listener_Path)&&spawnCount==before);
    spawnFail=1;before=freed;assert(kvm_relay_setup("/fixture/quoted ' agent",NULL,NULL,NULL,501)==NULL&&freed==before+1);
    spawnFail=0;reset();assert(kvm_relay_setup("/fixture/quoted ' agent",NULL,endSession,(void*)3,501)==(void*)2);
    before=freed;kvm_relay_ExitHandler((void*)1,1,lastUser);assert(ended==1&&lastUser==NULL&&gChildProcess==NULL&&freed==before+1);
    kvm_relay_ExitHandler((void*)1,1,lastUser);assert(ended==1&&freed==before+1);
    assert(kvm_relay_setup("/fixture/quoted ' agent",NULL,endSession,(void*)3,501)==(void*)2);
    gChildProcess=NULL;kvm_relay_ExitHandler((void*)1,1,lastUser);assert(ended==1&&lastUser==NULL); // owner already closed
    puts("PASS: GUI launch argv, credential order, console switching, invalid IDs, credential/env failures, own-user compatibility, spawn cleanup");
}
'''
real_main = r'''
int main(void){
    uid_t uid=getuid();struct stat s;assert(stat("/dev/console",&s)==0);
    int shouldSucceed=uid!=0&&s.st_uid==uid;
    int result=MacKvm_InitializeSessionUser(NULL);
    assert((result==0)==shouldSucceed);
    if(result==0){struct passwd *p=getpwuid(uid);assert(p&&getenv("HOME")&&!strcmp(getenv("HOME"),p->pw_dir)&&getenv("TMPDIR")==NULL);}
    puts("PASS: actual current-user credential and environment initialization; no desktop access");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-kvm-session-') as directory:
    folder = Path(directory)
    for name, text in [('mock',headers+mock+initializer+launcher_stubs+exit_handler+launcher+main), ('real',headers+initializer+real_main)]:
        if name == 'real' and sys.platform != 'darwin':
            continue
        (folder/(name+'.c')).write_text(text)
        subprocess.run([os.environ.get('CC','clang'), '-std=gnu99', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(folder/(name+'.c')), '-o', str(folder/name)],check=True)
        subprocess.run([str(folder/name)],check=True,timeout=20)

if args.agent:
    for arguments in [
        ['-kvm0','--session-uid','0'],
        ['-kvm0','--session-uid',str(os.getuid()+1)],
        ['-kvm0','--session-uid','bad'],
        ['-kvm0','--unexpected']
    ]:
        result = subprocess.run([str(args.agent.resolve())]+arguments,capture_output=True,text=True,timeout=5)
        assert result.returncode==1 and not result.stdout and 'KVM session user initialization failed' in result.stderr, (arguments,result)
    print('PASS: built KVM entry rejects root, foreign UID and malformed arguments before desktop initialization')
