#!/usr/bin/env python3
"""Check silent permission queries and input denial without accessing the desktop."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/KVM/MacOS/mac_kvm.c').read_text()
core = (root / 'meshcore/agentcore.c').read_text()
assert 'kvm_check_permission' not in core + source
for forbidden in ('CGRequestScreenCaptureAccess', 'kAXTrustedCheckOptionPrompt',
                  'LSOpenCFURLRef', '_fullDiskAuthorizationStatus', '_checkFDAUsingFile'):
    assert forbidden not in source, forbidden
start = source.index('static int MacKvm_CanCaptureScreen(')
end = source.index('\nint kvm_relay_feeddata(', start)
body = source[start:end]
# Test both modern permission checks and the pre-TCC OS fallback without OS APIs.
body = body.replace('__builtin_available(macOS 10.15, *)', 'modernScreen')
body = body.replace('__builtin_available(macOS 10.9, *)', 'modernInput')
prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "meshcore/meshdefines.h"
static int modernScreen=1, modernInput=1, screenAllowed, inputAllowed;
static int screenChecks, inputChecks, events, packetLength;
static unsigned char packet[256];
static int CGPreflightScreenCaptureAccess(void) { ++screenChecks; return screenAllowed; }
static int AXIsProcessTrustedWithOptions(const void *options) { assert(options==NULL); ++inputChecks; return inputAllowed; }
static int KVM_SEND(char *p,int n) { assert(n>=4 && n<=256); memcpy(packet,p,n);packetLength=n;return n; }
static void KeyActionUnicode(int k,int f) { (void)k;(void)f;++events; }
static void KeyAction(int k,int f) { (void)k;(void)f;++events; }
static void MouseAction(int x,int y,int b,int w) { (void)x;(void)y;(void)b;(void)w;++events; }
static void set_tile_compression(int a,int b) { (void)a;(void)b; }
static void kvm_send_resolution(void) {}
#define ILIBCRITICALEXIT(x) abort()
static int KVM_AGENT_FD=-1, SCREEN_SCALE=1, COMPRESSION_RATIO, TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT, g_remotepause;
struct tileInfo_t { int crc, flag; };
static struct tileInfo_t **g_tileInfo;
'''
main = r'''
static void checkMessage(int capture, int input, const char *expected) {
    MacKvm_SendPermissionStatus(capture,input);
    assert(packet[0]==0 && packet[1]==MNG_KVM_MESSAGE);
    assert(((packet[2]<<8)|packet[3])==packetLength);
    assert((size_t)packetLength==strlen(expected)+4);
    assert(!memcmp(packet+4,expected,strlen(expected)));
}
int main(void) {
    for(int c=0;c<=1;++c)for(int i=0;i<=1;++i) {
        screenAllowed=c;inputAllowed=i;
        assert(MacKvm_CanCaptureScreen()==c && MacKvm_CanPostInput()==i);
    }
    modernScreen=modernInput=0;
    int oldScreen=screenChecks,oldInput=inputChecks;
    assert(MacKvm_CanCaptureScreen() && MacKvm_CanPostInput());
    assert(screenChecks==oldScreen && inputChecks==oldInput);
    modernScreen=modernInput=1;
    checkMessage(0,0,"macOS Screen Recording permission is required. Enable MeshAgent in System Settings > Privacy & Security.");
    checkMessage(1,0,"macOS Accessibility permission is required for keyboard and mouse control. Enable MeshAgent in System Settings > Privacy & Security.");
    checkMessage(1,1,"");
    // Aligned protocol packets: denial consumes packets without posting input;
    // grant enables existing behavior, revocation takes effect on the next packet.
    union { uint16_t align; unsigned char data[12]; } key={.data={0,1,0,6,0,65}},
        unicode={.data={0,85,0,7,0,0,65}},mouse={.data={0,2,0,10,0,0,0,10,0,10}};
    for(int phase=0;phase<3;++phase) {
        inputAllowed=phase==1;int before=events;
        assert(kvm_server_inputdata((char*)key.data,6)==6);
        assert(kvm_server_inputdata((char*)unicode.data,7)==7);
        assert(kvm_server_inputdata((char*)mouse.data,10)==10);
        assert(events==before+(inputAllowed?3:0));
    }
    inputAllowed=1;
    unsigned char unaligned[16];
    memcpy(unaligned+1,mouse.data,10);
    assert(kvm_server_inputdata((char*)unaligned+1,10)==10);
    unaligned[3]=unaligned[4]=0;
    assert(kvm_server_inputdata((char*)unaligned+1,10)==-1);
    puts("PASS: silent permission queries, OS fallback, denied/granted/revoked input, desktop status packets");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-mac-permissions-') as folder:
    target = Path(folder)
    (target / 'probe.c').write_text(prelude + body + main)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(root), str(target/'probe.c'), '-o', str(target/'probe')], check=True)
    subprocess.run([str(target/'probe')], check=True)
# Guard the screen capture call against implicit requests when permission is absent.
loop = source[source.index('void* kvm_server_mainloop('):]
assert loop.index('if (!canCapture) { usleep(250000); continue; }') < loop.index('CGDisplayCreateImage(')
