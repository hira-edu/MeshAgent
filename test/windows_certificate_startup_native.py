"""Inject certificate load/generation/verification failures into startup code."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
source = (Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'meshcore/agentcore.c').read_text()
start = source.index('\tint certificateStatus = resetNodeId == 1 ? 1 : agent_LoadCertificates(agentHost);')
end = source.index('\n#else', start)
block = source[start:end]
prelude = r'''
#include <assert.h>
#include <stdio.h>
typedef struct {int exitCode;} MeshAgentHostContainer;
static int loadStatus,generateFailure,verifyFailure,generations,verifications;
static int agent_LoadCertificates(MeshAgentHostContainer* a){(void)a;return loadStatus;}
static int agent_GenerateCertificates(MeshAgentHostContainer* a,void* p){(void)a;(void)p;++generations;return generateFailure;}
static int agent_VerifyMeshCertificates(MeshAgentHostContainer* a){(void)a;++verifications;return verifyFailure;}
#define ILIBLOGMESSAGEX(...) ((void)0)
#define MeshAgent_ControlChannelDebugLog(...) ((void)0)
static int start(MeshAgentHostContainer* agentHost,int resetNodeId){
'''
cases = r'''
return 0;}
int main(void){
    for(int l=0;l<3;++l)for(int g=0;g<2;++g)for(int v=0;v<2;++v){
        loadStatus=l;generateFailure=g;verifyFailure=v;generations=verifications=0;MeshAgentHostContainer a={0};
        int expected=l==2||(l==1&&g)||v;assert(start(&a,0)==!!expected);assert(a.exitCode==!!expected);
        assert(generations==(l==1));assert(verifications==(l!=2&&!(l==1&&g)));
    }
    loadStatus=2;generateFailure=verifyFailure=0;generations=verifications=0;MeshAgentHostContainer a={0};
    assert(start(&a,1)==0&&generations==1&&verifications==1); /* Explicit reset remains supported. */
    puts("Certificate startup: generation and validation failures stop activation; loaded identities and explicit reset passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='certificate-startup-') as temporary:
    path = Path(temporary)
    c, exe = path / 'fixture.c', path / 'fixture.exe'
    c.write_text(prelude + block + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
