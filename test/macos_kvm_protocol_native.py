#!/usr/bin/env python3
"""Exercise production macOS KVM helper-pipe framing with fragmented/coalesced data.

Drives kvm_relay_StdOutHandler from mac_kvm.c the way ILibProcessPipe does:
the handler sees all buffered bytes, consumes one frame per call, and is called
again until it consumes nothing or everything. Invalid framing must kill the
helper. No screen access or input injection. Requires Clang; runs with ASan/UBSan.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/KVM/MacOS/mac_kvm.c').read_text()
start = source.index('void kvm_relay_StdOutHandler(')
body = source[start:source.index('\nvoid kvm_relay_StdErrHandler(', start)]
prelude = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meshcore/KVM/MacOS/mac_kvm_protocol.h"
typedef void* ILibProcessPipe_Process;
typedef int (*ILibKVM_WriteHandler)(char*, int, void*);
static unsigned char emitted[256];
static size_t emittedLength;
static int killed;
static void ILibProcessPipe_Process_SoftKill(ILibProcessPipe_Process p) { assert(p == (void*)1); ++killed; }
static int sink(char *buffer, int length, void *reserved) {
    assert(reserved == (void*)7 && length > 0 && emittedLength + (size_t)length <= sizeof(emitted));
    memcpy(emitted + emittedLength, buffer, (size_t)length); emittedLength += (size_t)length; return 0;
}
'''
main = r'''
static unsigned char pipeBuffer[256];
static size_t offset, total;
static void *user[2] = { (void*)sink, (void*)7 };
// Mirrors the ILibProcessPipe read loop: one handler call per frame until the buffer stalls or drains.
static void feed(const unsigned char *data, size_t length) {
    memmove(pipeBuffer, pipeBuffer + offset, total); offset = 0;
    assert(total + length <= sizeof(pipeBuffer));
    memcpy(pipeBuffer + total, data, length); total += length;
    while (total > 0) {
        size_t consumed = 0;
        kvm_relay_StdOutHandler((void*)1, (char*)pipeBuffer + offset, total, &consumed, user);
        assert(consumed <= total);
        if (consumed == 0) { break; }
        offset += consumed; total -= consumed;
    }
    if (total == 0) { offset = 0; }
}
static void reset(void) { offset = total = emittedLength = 0; killed = 0; }
int main(void) {
    unsigned char stream[] = {0,5,0,4, 0,7,0,6,0x12,0x34, 0,27,0,8,0,0,0,4,0,5,0,4};
    for (size_t split = 0; split <= sizeof(stream); ++split) {
        reset();
        feed(stream, split); feed(stream + split, sizeof(stream) - split);
        assert(!killed && !total && emittedLength == sizeof(stream) && !memcmp(stream, emitted, sizeof(stream)));
    }
    reset();
    for (size_t i = 0; i < sizeof(stream); ++i) { feed(stream + i, 1); }
    assert(!killed && emittedLength == sizeof(stream) && !memcmp(stream, emitted, sizeof(stream)));
    unsigned char bad[][8] = {{0,5,0,0},{0,5,0,3},{0,27,0,4},{0,27,0,8,0,0,0,0},{0,27,0,8,0xff,0xff,0xff,0xff}};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        reset(); feed(bad[i], sizeof(bad[i]));
        assert(killed == 1 && !emittedLength && !total);
    }
    // A detached session (no user object) drains output without forwarding it.
    reset(); size_t consumed = 0;
    kvm_relay_StdOutHandler((void*)1, (char*)stream, sizeof(stream), &consumed, NULL);
    assert(consumed == sizeof(stream) && !emittedLength && !killed);
    // After kvm_cleanup detaches the session, output still in the pipe is dropped, not forwarded.
    void *detached[2] = { NULL, NULL }; consumed = 0;
    kvm_relay_StdOutHandler((void*)1, (char*)stream, sizeof(stream), &consumed, detached);
    assert(consumed == sizeof(stream) && !emittedLength && !killed);
    // Exercise unaligned headers and every declared ordinary length.
    unsigned char sample[16] = {0}; size_t length;
    for (unsigned value = 0; value < 65536; ++value) {
        sample[3] = (unsigned char)(value >> 8); sample[4] = (unsigned char)value;
        int result = MacKvm_FrameLength(sample + 1, 8, &length);
        assert(result == (value < 4 ? -1 : value <= 8 ? 1 : 0));
    }
    puts("PASS: production macOS helper-pipe framing, every split, jumbo frames, invalid lengths, detached sessions, unaligned headers");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-mac-framing-') as folder:
    target = Path(folder)
    (target / 'probe.c').write_text(prelude + body + main)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(root), str(target / 'probe.c'), '-o', str(target / 'probe')], check=True)
    subprocess.run([str(target / 'probe')], check=True)
