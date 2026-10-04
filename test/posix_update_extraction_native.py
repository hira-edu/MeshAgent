#!/usr/bin/env python3
"""Run production unzip callbacks with delayed and duplicate completions."""
import os
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'meshcore/agentcore.c').read_text()
def between(start,end):
    a=s.index(start);return s[a:s.index(end,a)]
blocked=between('static int MeshServer_UpdateTransferBlocked(', '\n// Retry opening')
callbacks=between('duk_ret_t MeshServer_selfupdate_unzip_complete(', '\nstatic int MeshServer_UpdateFileLooksZip(')
failed=between('static void MeshServer_FailCompressedUpdate(', '\n// Process MeshCentral server commands.')
prelude=r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct { int updateUnzipPending,performSelfUpdate,logUpdate;char *exePath; } MeshAgentHostContainer;
typedef int duk_context,duk_ret_t;
static MeshAgentHostContainer state;
static int continued,failures,deletions;
#define MESH_AGENT_PTR "ptr"
#define ILIBLOGMESSSAGE(...) ((void)0)
static void duk_eval_string(duk_context*c,const char*s){(void)c;(void)s;}
static void *Duktape_GetPointerProperty(duk_context*c,int n,const char*s){(void)c;(void)n;(void)s;return &state;}
static const char *duk_safe_to_string(duk_context*c,int n){(void)c;(void)n;return "failure";}
static void duk_push_sprintf(duk_context*c,const char*f,const char*s){(void)c;(void)f;(void)s;}
static char *MeshAgent_MakeAbsolutePath(char*p,const char*s){(void)p;return (char*)s;}
static void util_deletefile(char*p){(void)p;++deletions;}
static void MeshServer_ReportUpdateFailure(MeshAgentHostContainer*a){(void)a;++failures;}
static void MeshServer_selfupdate_continue(MeshAgentHostContainer*a){++continued;a->performSelfUpdate=999;}
'''
main=r'''
int main(void){
 assert(!MeshServer_UpdateTransferBlocked(&state));
 state.updateUnzipPending=1;assert(MeshServer_UpdateTransferBlocked(&state));
 MeshServer_selfupdate_unzip_complete(NULL);
 assert(continued==1 && !state.updateUnzipPending && MeshServer_UpdateTransferBlocked(&state));
 MeshServer_selfupdate_unzip_complete(NULL);MeshServer_selfupdate_unzip_error(NULL);
 assert(continued==1 && !failures && !deletions); // Stale callback cannot delete activated binary.
 state.performSelfUpdate=0;state.updateUnzipPending=1;
 MeshServer_selfupdate_unzip_error(NULL);
 assert(!state.updateUnzipPending && !MeshServer_UpdateTransferBlocked(&state) && failures==1 && deletions==2);
 MeshServer_selfupdate_unzip_error(NULL);assert(failures==1 && deletions==2);
 state.updateUnzipPending=1;MeshServer_FailCompressedUpdate(&state,"staged");
 assert(!state.updateUnzipPending && !MeshServer_UpdateTransferBlocked(&state) && failures==2 && deletions==3);
 puts("PASS: POSIX extraction ownership, duplicate callbacks, failure cleanup, activation transfer blocking");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-posix-update-') as folder:
 p=Path(folder);(p/'test.c').write_text(prelude+blocked+callbacks+failed+main)
 subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
