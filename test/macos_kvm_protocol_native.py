#!/usr/bin/env python3
"""Exercise production macOS KVM socket framing with fragmented/coalesced data.

No screen access or input injection. Requires Clang; runs with ASan/UBSan.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/agentcore.c').read_text()
name = 'ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_DataSink'
start = source.index('duk_ret_t ' + name + '(')
end = source.index('\nduk_ret_t ', start + 1)
body = source[start:end]
prelude = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meshcore/KVM/MacOS/mac_kvm_protocol.h"
typedef int duk_context, duk_ret_t;
typedef size_t duk_size_t;
typedef struct { void *stream; } RemoteDesktop_Ptrs;
#define KVM_IPC_SOCKET "socket"
static RemoteDesktop_Ptrs owner = {(void*)1};
static unsigned char *incoming, saved[128], emitted[128];
static size_t incomingLength, savedLength, emittedLength;
static int ended;
static void duk_push_this(duk_context *c) { (void)c; }
static void* Duktape_GetPointerProperty(duk_context*c,int i,const char*s) { (void)c;(void)i;(void)s;return &owner; }
static void* Duktape_GetBuffer(duk_context*c,int i,size_t*n) { (void)c;(void)i;*n=incomingLength;return incoming; }
static void MeshAgent_sendConsoleText(duk_context*c,const char*s) { (void)c;(void)s; }
static void ILibDuktape_DuplexStream_WriteEnd(void*s) { (void)s;++ended; }
static void ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink(char*b,int n,RemoteDesktop_Ptrs*p) {
    assert(p==&owner && n>0 && emittedLength+(size_t)n<=sizeof(emitted));
    memcpy(emitted+emittedLength,b,(size_t)n);emittedLength+=(size_t)n;
}
static void duk_push_external_buffer(duk_context*c) { (void)c; }
static void duk_config_buffer(duk_context*c,int i,void*b,size_t n) {
    (void)c;(void)i;assert(n<=sizeof(saved));memcpy(saved,b,n);savedLength=n;
}
static void duk_get_prop_string(duk_context*c,int i,const char*s) { (void)c;(void)i;(void)s; }
static void duk_swap_top(duk_context*c,int i) { (void)c;(void)i; }
#define DUK_BUFOBJ_NODEJS_BUFFER 1
static void duk_push_buffer_object(duk_context*c,int i,size_t o,size_t n,int t) { (void)c;(void)i;(void)o;(void)n;(void)t; }
static void duk_call_method(duk_context*c,int i) { (void)c;(void)i; }
'''
main = r'''
static void feed(const unsigned char* data,size_t length) {
    unsigned char input[256];
    memcpy(input,saved,savedLength);memcpy(input+savedLength,data,length);
    incoming=input;incomingLength=savedLength+length;savedLength=0;
    ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_DataSink(NULL);
}
int main(void) {
    unsigned char stream[]={0,5,0,4, 0,7,0,6,0x12,0x34, 0,27,0,8,0,0,0,4,0,5,0,4};
    for(size_t split=0;split<=sizeof(stream);++split) {
        savedLength=emittedLength=0;ended=0;
        feed(stream,split);feed(stream+split,sizeof(stream)-split);
        assert(!ended && !savedLength && emittedLength==sizeof(stream));
        assert(!memcmp(stream,emitted,sizeof(stream)));
    }
    savedLength=emittedLength=0;
    for(size_t i=0;i<sizeof(stream);++i)feed(stream+i,1);
    assert(emittedLength==sizeof(stream)&&!memcmp(stream,emitted,sizeof(stream)));
    unsigned char bad[][8]={{0,5,0,0},{0,5,0,3},{0,27,0,4},{0,27,0,8,0,0,0,0},{0,27,0,8,0xff,0xff,0xff,0xff}};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
        savedLength=emittedLength=0;ended=0;feed(bad[i],sizeof(bad[i]));
        assert(ended==1&&!emittedLength&&!savedLength);
    }
    // Exercise unaligned headers and every declared ordinary length.
    unsigned char sample[16]={0};size_t length;
    for(unsigned value=0;value<65536;++value) {
        sample[3]=(unsigned char)(value>>8);sample[4]=(unsigned char)value;
        int result=MacKvm_FrameLength(sample+1,8,&length);
        assert(result==(value<4?-1:value<=8?1:0));
    }
    puts("PASS: production macOS KVM framing, every split, jumbo frames, invalid lengths, unaligned headers");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-mac-framing-') as folder:
    target = Path(folder)
    (target/'probe.c').write_text(prelude + body + main)
    subprocess.run([os.environ.get('CC','clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(root), str(target/'probe.c'), '-o', str(target/'probe')],check=True)
    subprocess.run([str(target/'probe')],check=True)
