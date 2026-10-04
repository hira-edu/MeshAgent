#!/usr/bin/env python3
"""Exercise native update replacement and recovery against real temporary files.

Uses no installed services, network, screen access, or endpoint identity.
"""
import errno
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
fixture=r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
static const char *fault;
static int target,seen,crash;
static int hit(const char *name) { return fault && !strcmp(fault,name) && ++seen==target; }
static int fault_rename(const char *a,const char *b) {
 int yes=hit("rename");if(yes&&!crash){errno=EIO;return -1;}int r=rename(a,b);if(yes&&crash&&r==0)_exit(90);return r;
}
static int fault_fsync(int fd) {
 int yes=hit("fsync");if(yes&&!crash){errno=EIO;return -1;}int r=fsync(fd);if(yes&&crash&&r==0)_exit(90);return r;
}
static int fault_link(const char *a,const char *b) {
 int yes=hit("link");if(yes&&!crash){errno=EIO;return -1;}int r=link(a,b);if(yes&&crash&&r==0)_exit(90);return r;
}
static int fault_unlink(const char *a) {
 int yes=hit("unlink");if(yes&&!crash){errno=EIO;return -1;}int r=unlink(a);if(yes&&crash&&r==0)_exit(90);return r;
}
#define rename fault_rename
#define fsync fault_fsync
#define link fault_link
#define unlink fault_unlink
#include "meshcore/macos_update.c"
int main(int argc,char **argv) {
 if(argc<4)return 2;
 if(argc>4){fault=argv[4];target=atoi(argv[5]);crash=atoi(argv[6]);}
 int result;
 if(!strcmp(argv[1],"preflight"))result=MeshMacUpdate_Preflight(argv[2],argv[3]);
 else if(!strcmp(argv[1],"apply"))result=MeshMacUpdate_Apply(argv[2],argv[3]);
 else if(!strcmp(argv[1],"recover"))result=MeshMacUpdate_Recover(argv[2],atoi(argv[3]));
 else if(!strcmp(argv[1],"commit"))result=MeshMacUpdate_Commit(argv[2]);
 else return 2;
 printf("%d %d\n",result,errno);return 0;
}
'''
old=b'#!/bin/sh\nprintf "old\\n"\n'
new=b'#!/bin/sh\nprintf "1\\n"\n'
with tempfile.TemporaryDirectory(prefix='mesh-mac-update-') as folder:
    base=Path(folder);(base/'probe.c').write_text(fixture)
    probe=base/'probe'
    subprocess.run([os.environ.get('CC','clang'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare',
                    '-fsanitize=address,undefined','-I',str(root),str(base/'probe.c'),'-o',str(probe)],check=True)
    count=0
    def setup():
        global count
        count+=1;p=base/str(count);p.mkdir();live=p/'agent with spaces';stage=p/'agent with spaces.update'
        live.write_bytes(old);live.chmod(0o751);stage.write_bytes(new)
        (p/'identity.db').write_bytes(b'private identity sentinel');(p/'agent.msh').write_bytes(b'provisioning sentinel')
        return live,stage
    def run(op,live,arg='0',fault=None):
        args=[str(probe),op,str(live),str(arg)]
        if fault:args.extend(map(str,fault))
        p=subprocess.run(args,capture_output=True,text=True,timeout=15)
        if p.returncode==90:return None
        assert p.returncode==0,(p.returncode,p.stderr)
        result,error=map(int,p.stdout.split())
        assert (live.parent/'identity.db').read_bytes()==b'private identity sentinel'
        assert (live.parent/'agent.msh').read_bytes()==b'provisioning sentinel'
        return result,error
    def ok(op,live,arg='0'):
        result=run(op,live,arg);assert result[0]==0,(op,result);return result
    live,stage=setup();ok('preflight',live,stage);ok('apply',live,stage)
    assert live.read_bytes()==new and live.stat().st_mode&0o777==0o751 and not stage.exists()
    assert run('recover',live)[0]==2;ok('commit',live);ok('recover',live)
    assert live.read_bytes()==new and not Path(str(live)+'.update-backup').exists()
    live,stage=setup();ok('apply',live,stage);assert run('recover',live)[0]==2
    assert run('recover',live)[0]==1 and live.read_bytes()==old;ok('recover',live)
    live,stage=setup();ok('apply',live,stage);assert run('recover',live,'1')[0]==1 and live.read_bytes()==old
    # Busy ownership and unrelated artifacts must be preserved.
    live,stage=setup()
    with open(str(live)+'.update-lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert run('apply',live,stage)[0]==-1 and live.read_bytes()==old
    backup=Path(str(live)+'.update-backup');backup.write_bytes(b'unrelated')
    assert run('apply',live,stage)[0]==-1 and backup.read_bytes()==b'unrelated'
    live,stage=setup();ok('apply',live,stage)
    backup=Path(str(live)+'.update-backup');backup.unlink();backup.write_bytes(b'unrelated')
    assert run('recover',live,'1')[0]==-1 and backup.read_bytes()==b'unrelated' and live.read_bytes()==new
    live,stage=setup();stage.unlink();stage.symlink_to(live)
    assert run('preflight',live,stage)[0]==-1 and run('apply',live,stage)[0]==-1 and live.read_bytes()==old
    live,stage=setup();stage.write_bytes(b'not an executable');assert run('preflight',live,stage)[0]==-1 and live.read_bytes()==old
    live,stage=setup();stage.write_bytes(b'#!/bin/sh\nprintf "2\\n"\n');assert run('preflight',live,stage)[0]==-1
    # Every persistent replacement boundary is interrupted, then recovered.
    for operation,limit in [('rename',2),('fsync',5),('link',1)]:
        for nth in range(1,limit+1):
            for crash in (0,1):
                live,stage=setup();run('apply',live,stage,(operation,nth,crash))
                assert live.read_bytes() in (old,new)
                recovered=run('recover',live,'1');assert recovered[0] in (0,1), (operation,nth,crash,recovered)
                assert live.read_bytes()==old and not Path(str(live)+'.update-state').exists()
    # Once commit is durable, interrupted cleanup must keep the new executable.
    for operation,limit in [('unlink',2),('fsync',3)]:
        for nth in range(1,limit+1):
            live,stage=setup();ok('apply',live,stage);assert run('recover',live)[0]==2
            run('commit',live,'0',(operation,nth,1));recovered=run('recover',live)
            assert recovered[0] in (0,1) and live.read_bytes() in (old,new)
            if operation=='unlink':assert live.read_bytes()==new
    print('PASS: native macOS preflight, replacement, trial/commit/rollback, locks, sidecars, symlinks and crash/failure boundaries')
