#!/usr/bin/env python3
"""Execute production service identity selection and JS calls with real Duktape.

SCM identity and datastore fixtures are local; no service or registry is changed.
Requires a C compiler and the repository's bundled Duktape sources.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/agentcore.c').read_text()
start = source.index('#ifdef WIN32\n\t// The SCM dispatcher supplies')
end = source.index('\n\tif ((msnlen = ILibSimpleDataStore_Get(agentHost->masterDb, "displayName"', start)
selection = source[start:end]
start = source.index('#ifdef WIN32\n\t// Windows background execution enters only')
end = source.index('\n\tif (duk_peval_string(tmpCtx, "require(\'user-sessions\')', start)
service_status = source[start:end]
start = source.index('\n\tduk_push_string(tmpCtx, agentHost->meshServiceName);', end)
end = source.index('\n\tif (duk_peval(tmpCtx)', start)
reset_call = source[start:end]

prefix = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "duktape.h"
typedef struct {
    int serviceReserved, platformType, JSRunningAsService;
    void* masterDb;
    char* meshServiceName;
} MeshAgentHostContainer;
typedef struct { const char* serviceFile; } mesh_branding_definition_t;
static mesh_branding_definition_t fixtureBranding = {"BuildDefault"};
#define MESH_AGENT_SERVICE_FILE "FallbackDefault"
#define MeshConfig_GetBranding() (&fixtureBranding)
#define MeshAgent_ControlChannelDebugLog(...) ((void)0)
#define ILibMemory_Free free
#define ILibMemory_SmartAllocate malloc
#define MeshAgent_Posix_PlatformTypes_WINDOWS 10
#define MeshAgent_Posix_PlatformTypes int
static const char* storedName;
static int datastoreReads;
static int ILibSimpleDataStore_Get(void* db, const char* key, char* out, int len) {
    (void)db; assert(strcmp(key,"meshServiceName")==0); ++datastoreReads;
    if (!storedName) return 0;
    int size=(int)strlen(storedName);
    if(out) { assert(len>=size); memcpy(out,storedName,(size_t)size); }
    return size;
}
static char* ILibString_Copy(const char* value, int unused) {
    (void)unused; char* copy=malloc(strlen(value)+1); assert(copy); strcpy(copy,value); return copy;
}
static void installModules(duk_context* ctx) {
    assert(duk_peval_string(ctx,
        "var receivedName=null; var injected=false; var serviceLookups=0;"
        "function require(module) {"
        "if(module==='_agentNodeId') return {checkResetNodeId:function(name){receivedName=name;return false;}};"
        "if(module==='service-manager') return {manager:{getServiceType:function(){return 'systemd';},"
        "getService:function(name){receivedName=name;++serviceLookups;return {isMe:function(){return true;}};}}};"
        "throw Error('unexpected module');}") == 0);
    duk_pop(ctx);
}
static void assertReceived(duk_context* ctx, const char* expected) {
    duk_get_global_string(ctx,"receivedName"); assert(strcmp(duk_get_string(ctx,-1),expected)==0); duk_pop(ctx);
    duk_get_global_string(ctx,"injected"); assert(!duk_get_boolean(ctx,-1)); duk_pop(ctx);
}
'''
functions = '\n#define WIN32\nstatic void selectWindows(MeshAgentHostContainer* agentHost) { int msnlen;\n' + selection + '\n}\n'
functions += 'static void statusWindows(MeshAgentHostContainer* agentHost) {\n' + service_status + '\n}\n#undef WIN32\n'
functions += 'static void selectPosix(MeshAgentHostContainer* agentHost) { int msnlen;\n' + selection + '\n}\n'
functions += 'static void statusPosix(MeshAgentHostContainer* agentHost, duk_context* tmpCtx) { char* tmpString;\n' + service_status + '\n}\n'
functions += 'static void resetCheck(MeshAgentHostContainer* agentHost, duk_context* tmpCtx) {\n' + reset_call + '\nassert(duk_peval(tmpCtx)==0);\n}\n'
cases = r'''
int main(void) {
    MeshAgentHostContainer agent={0}; duk_context* ctx=duk_create_heap_default(); assert(ctx); installModules(ctx);
    const char* custom="Operator's \"support\"; injected=true; // \\ line\n\xe2\x80\xa8";
    for(int stale=0;stale<2;++stale) {
        storedName=stale?"ObsoleteInstalledName":NULL; datastoreReads=0;
        agent.serviceReserved=1; agent.meshServiceName=ILibString_Copy(custom,0);
        char* authoritative=agent.meshServiceName;
        selectWindows(&agent);
        assert(agent.meshServiceName==authoritative && datastoreReads==0);
        statusWindows(&agent); assert(agent.JSRunningAsService==1 && agent.platformType==10);
        resetCheck(&agent,ctx); assertReceived(ctx,custom); duk_set_top(ctx,0);
        free(agent.meshServiceName); agent.meshServiceName=NULL;
    }
    storedName="StoredFallback"; datastoreReads=0; agent.serviceReserved=1;
    selectWindows(&agent); assert(strcmp(agent.meshServiceName,storedName)==0 && datastoreReads==2); free(agent.meshServiceName);
    agent.meshServiceName=ILibString_Copy("",0); storedName=NULL;
    selectWindows(&agent); assert(strcmp(agent.meshServiceName,"BuildDefault")==0); free(agent.meshServiceName);
    agent.meshServiceName=ILibString_Copy(custom,0); agent.serviceReserved=0; storedName="StoredConsoleName";
    selectWindows(&agent); assert(strcmp(agent.meshServiceName,storedName)==0);
    statusWindows(&agent); assert(agent.JSRunningAsService==0 && agent.platformType==10); free(agent.meshServiceName);
    agent.meshServiceName=ILibString_Copy("HostDoesNotOverridePosix",0); agent.serviceReserved=1; storedName=custom;
    selectPosix(&agent); assert(strcmp(agent.meshServiceName,custom)==0);
    statusPosix(&agent,ctx); assert(agent.JSRunningAsService==1 && agent.platformType==1); assertReceived(ctx,custom);
    free(agent.meshServiceName); duk_destroy_heap(ctx);
    puts("agent service identity: SCM precedence, fallback selection and quoted service calls passed");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='meshagent-service-identity-') as directory:
    harness = Path(directory) / 'identity.c'
    executable = Path(directory) / ('identity.exe' if os.name == 'nt' else 'identity')
    harness.write_text(prefix + functions + cases)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c99', '-I' + str(ROOT / 'microscript'),
                    str(harness), str(ROOT / 'microscript/duktape.c'), '-lm', '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
