"""Verify the production runtime keeps SCM's actual name across branding resets."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/agentcore.c').read_text()
start = source.index('static void MeshAgent_ApplyNativeLifecycleBrandingOverrides(')
brace = source.index('{', start)
end, depth = brace + 1, 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}'); end += 1
function = source[start:end]
prelude = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#define WIN32
#endif
#define MESHAGENT_ENABLE_RUNTIME_FEATURES
struct MeshAgentHostContainer { void* masterDb; char* meshServiceName; int JSRunningAsService; };
static char active[256],display[256],description[256];
static void ServiceDeploy_ClearRuntimeBrandingOverrides(void){active[0]=display[0]=description[0]=0;}
static void ServiceDeploy_SetRuntimeServiceKeyNameUtf8(const char* name){strcpy(active,name);}
static void ServiceDeploy_SetRuntimeDisplayNameUtf8(const char* value){strcpy(display,value);}
static void ServiceDeploy_SetRuntimeServiceDescriptionUtf8(const char* value){strcpy(description,value);}
static int ILibSimpleDataStore_Get(void* db,const char* key,char* buffer,int capacity){
    (void)db;const char* value=!strcmp(key,"displayName")?"New display":"New description";int length=(int)strlen(value);
    assert(capacity>length);memcpy(buffer,value,length);return length;
}
'''
cases = r'''
int main(void){
    struct MeshAgentHostContainer service={(void*)1,(char*)"Historical Service Name",1};
    MeshAgent_ApplyNativeLifecycleBrandingOverrides(&service);
    assert(!strcmp(active,"Historical Service Name"));assert(!strcmp(display,"New display"));assert(!strcmp(description,"New description"));
    service.masterDb=NULL;MeshAgent_ApplyNativeLifecycleBrandingOverrides(&service);assert(!strcmp(active,"Historical Service Name"));assert(!*display);
    service.JSRunningAsService=0;MeshAgent_ApplyNativeLifecycleBrandingOverrides(&service);assert(!*active);
    MeshAgent_ApplyNativeLifecycleBrandingOverrides(NULL);assert(!*active);
    puts("SCM identity: historical name retained, display overrides preserved, console and null contexts cleared");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='service-name-binding-') as temporary:
    path = Path(temporary); c = path / 'fixture.c'; exe = path / 'fixture.exe'
    c.write_text(prelude + function + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
