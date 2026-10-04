#!/usr/bin/env python3
"""Execute production macOS update hand-off with temporary test executables."""
import os
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'meshcore/agentcore.c').read_text()
def between(a,b):
    pos=s.index(a);return s[pos:s.index(b,pos)]
save=between('static void MeshAgent_MacSaveArguments(MeshAgentHostContainer *agent, int argc, char **argv)\n{','\n#endif')
continuation=between('void MeshServer_selfupdate_continue(', '\nduk_ret_t MeshServer_selfupdate_unzip_complete(')
timeout=between('static void MeshAgent_MacUpdateTrialTimeout(', '\n#endif')
pos=s.index('if (agentHost->performSelfUpdate != 0)',s.index('int MeshAgent_Start('))
start=s.index('            char *staged = ',pos)
end=s.index('\n#else',start)
handoff=s[start:end]
prelude=r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "meshcore/macos_update.h"
#ifndef __APPLE__
#define __APPLE__ 1
#endif
typedef struct { char **execparams,*exePath;int macUpdateTrial,performSelfUpdate,exitCode;void *chain; } MeshAgentHostContainer;
static int stopped,reported,failExec,execCalls;
static void ILibStopChain(void *c){(void)c;++stopped;}
static void MeshServer_ReportUpdateFailure(MeshAgentHostContainer *a){(void)a;++reported;}
#define ILIBLOGMESSAGEX(...) ((void)0)
static char *ILibString_Copy(const char *p,int n){(void)n;return strdup(p);}
static char *MeshAgent_MakeAbsolutePath(const char *path,const char *suffix){static char out[4096];snprintf(out,sizeof(out),"%s%s",path,suffix);return out;}
static void util_deletefile(const char *path){unlink(path);}
static void *ILibMemory_SmartAllocateEx(size_t primary,size_t extra){size_t *p=calloc(1,sizeof(size_t)+primary+extra);assert(p);*p=primary;return p+1;}
static void *ILibMemory_Extra(void *p){return (char*)p+((size_t*)p)[-1];}
static void ILibMemory_Free(void *p){free((size_t*)p-1);}
static int test_execv(const char *path,char *const args[]){if(failExec && execCalls++==0){errno=ENOEXEC;return -1;}return execv(path,args);}
#define execv test_execv
'''
main=r'''
int main(int argc,char **argv){
 assert(argc>=4);failExec=atoi(argv[1]);MeshAgentHostContainer agent={0};MeshAgentHostContainer *agentHost=&agent;
 agent.exePath=argv[2];MeshAgent_MacSaveArguments(&agent,argc-2,argv+2);
 // A disabled trial timer is a no-op; an active trial stops with rollback selected.
 MeshAgent_MacUpdateTrialTimeout(&agent.macUpdateTrial);assert(!stopped);
 agent.macUpdateTrial=1;MeshAgent_MacUpdateTrialTimeout(&agent.macUpdateTrial);
 assert(stopped==1 && agent.performSelfUpdate==-1);agent.macUpdateTrial=agent.performSelfUpdate=stopped=0;
 MeshServer_selfupdate_continue(&agent);
 if(!stopped){assert(reported==1 && !agent.performSelfUpdate);ILibMemory_Free(agent.execparams);puts("REJECTED ONLINE");return 0;}
 assert(!reported && agent.performSelfUpdate==999);
'''
script=lambda label: ('#!/bin/sh\nif [ "$1" = "-updaterversion" ]; then printf "1\\n"; exit 0; fi\nprintf "'+label+'\\n%s\\n" "$$"\nprintf "%s\\n" "$@"\n').encode()
with tempfile.TemporaryDirectory(prefix='mesh-mac-handoff-') as folder:
    base=Path(folder);(base/'probe.c').write_text(prelude+save+continuation+timeout+main+handoff+'\nreturn agent.exitCode;\n}\n')
    probe=base/'probe'
    subprocess.run([os.environ.get('CC','clang'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare',
                    '-I',str(root),str(base/'probe.c'),str(root/'meshcore/macos_update.c'),'-o',str(probe)],check=True)
    options=['run','--meshServiceName=Agent & "quoted"','--configUsesCWD=1','--fakeUpdate=1','--resetnodeid']
    for scenario in ['apply','exec-failure','bad-package']:
        d=base/scenario;d.mkdir();live=d/'agent with spaces';live.write_bytes(script('OLD'));live.chmod(0o755)
        stage=Path(str(live)+'.update');stage.write_bytes(b'not executable' if scenario=='bad-package' else script('NEW'))
        db=Path(str(live)+'.db');db.write_bytes(b'identity unchanged');msh=Path(str(live)+'.msh');msh.write_bytes(b'provisioning unchanged')
        child=subprocess.Popen([str(probe),'1' if scenario=='exec-failure' else '0',str(live),*options],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=d)
        output,error=child.communicate(timeout=15);assert child.returncode==0,(output,error)
        if scenario=='bad-package':assert output.strip()=='REJECTED ONLINE' and live.read_bytes()==script('OLD')
        else:
            rows=output.splitlines();assert rows[0]==('OLD' if scenario=='exec-failure' else 'NEW'),rows
            assert int(rows[1])==child.pid and rows[2:]==options[:3],rows
        assert db.read_bytes()==b'identity unchanged' and msh.read_bytes()==b'provisioning unchanged'
    print('PASS: production hand-off preserves PID and exact argv; rejects bad packages online; exec failure restores incumbent; sidecars retained')
# A reconnect timer must not cancel the independently keyed trial deadline.
assert '&agentHost->macUpdateTrial, 120000, MeshAgent_MacUpdateTrialTimeout' in s
