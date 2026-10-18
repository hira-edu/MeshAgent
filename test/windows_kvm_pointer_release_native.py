#!/usr/bin/env python3
"""Run the Windows KVM relay's pointer-release functions outside Windows.

Extracts kvm_relay_note_injected_pointer() and kvm_relay_release_injected_pointer() from
meshcore/KVM/Windows/kvm.c into a C harness with a minimal relay context and a recording bridge
write, and checks: presses are released at session end; a press made before the helper moved to
another Windows session is never released into the new one; buttons another live context in the
same session holds are left alone; nothing is sent without an attached bridge; and the first
failed write stops the release. Any host with clang (or CC); ASan/UBSan; no Windows API is used.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/KVM/Windows/kvm.c').read_text().replace('\r\n', '\n')


def extract(signature):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"', lambda m: ' ' * len(m.group()), source, flags=re.S)
    start = masked.find(signature)
    assert start >= 0, signature
    end = masked.index('{', start) + 1
    depth = 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[start:end]


prelude = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "meshcore/KVM/kvm_pointer_release.h"
typedef unsigned long DWORD;
typedef long LONG;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define InterlockedCompareExchange(p, x, c) (*(p))
#define KVM_MAX_RELAY_CONTEXTS 16
typedef struct KvmRelayContext {
    LONG childUsesBridge;
    LONG bridgeTransportAttached;
    DWORD processSessionId;
    KvmPointerTrack injectedPointer;
    DWORD injectedPointerSessionId;
} KvmRelayContext;
static KvmRelayContext* gKvmRelayContexts[KVM_MAX_RELAY_CONTEXTS];
static unsigned char written[16];
static int writes, failAfter = -1;
static BOOL kvm_relay_write_bridge_input(KvmRelayContext* ctx, char* buffer, int bufferLen)
{
    (void)ctx;
    assert(bufferLen == KVM_POINTER_RELEASE_PACKET_SIZE);
    if (failAfter >= 0 && writes >= failAfter) { ++writes; return FALSE; }
    written[writes++] = (unsigned char)buffer[5];
    return TRUE;
}
static DWORD GetLastError(void) { return 0; }
static void kvm_trace_startupf(const char* fmt, ...) { (void)fmt; }
'''

cases = r'''
static void feed(KvmRelayContext* c, unsigned char b, unsigned short x, unsigned short y)
{
    char p[10] = { 0, 2, 0, 10, 0, (char)b, (char)(x >> 8), (char)(x & 0xFF), (char)(y >> 8), (char)(y & 0xFF) };
    kvm_relay_note_injected_pointer(c, p, (int)sizeof(p));
}
static void fresh(KvmRelayContext* c, DWORD session)
{
    memset(c, 0, sizeof(*c));
    c->childUsesBridge = 1; c->bridgeTransportAttached = 1; c->processSessionId = session;
    memset(gKvmRelayContexts, 0, sizeof(gKvmRelayContexts));
    gKvmRelayContexts[0] = c;
    writes = 0; failAfter = -1;
}
int main(void)
{
    KvmRelayContext a, b;

    /* A press is released at session end, then the tracker is clear. */
    fresh(&a, 1);
    feed(&a, 0x02, 10, 10); feed(&a, 0x00, 20, 20);
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 1 && written[0] == 0x04 && a.injectedPointer.held == 0);
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 1);

    /* Pressed in session 1; the helper moves to session 2; a plain move arrives there.
       The press belongs to session 1 and must not be released into session 2. */
    fresh(&a, 1);
    feed(&a, 0x02, 10, 10);
    a.processSessionId = 2;
    feed(&a, 0x00, 30, 30);
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 0);

    /* The same, with no further input: the session gate alone stops the release. */
    fresh(&a, 1);
    feed(&a, 0x02, 10, 10);
    a.processSessionId = 2;
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 0 && a.injectedPointer.held == 0);

    /* A new press in the new session is stamped with it and released normally. */
    fresh(&a, 1);
    feed(&a, 0x02, 10, 10);
    a.processSessionId = 2;
    feed(&a, 0x00, 5, 5); feed(&a, 0x08, 6, 6);
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 1 && written[0] == 0x10);

    /* Another live context in the same session holding left keeps left; right is still released. */
    fresh(&a, 1);
    memset(&b, 0, sizeof(b)); b.processSessionId = 1; gKvmRelayContexts[1] = &b;
    feed(&b, 0x02, 1, 1);
    feed(&a, 0x02, 2, 2); feed(&a, 0x08, 2, 2);
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 1 && written[0] == 0x10);

    /* A context in a different session does not protect the button. */
    fresh(&a, 1);
    memset(&b, 0, sizeof(b)); b.processSessionId = 3; gKvmRelayContexts[1] = &b;
    feed(&b, 0x02, 1, 1);
    feed(&a, 0x02, 2, 2);
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 1 && written[0] == 0x04);

    /* No attached bridge: nothing is sent, and the tracker is reset. */
    fresh(&a, 1);
    feed(&a, 0x02, 2, 2);
    a.bridgeTransportAttached = 0;
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 0 && a.injectedPointer.held == 0);

    /* The first failed write stops the release. */
    fresh(&a, 1);
    feed(&a, 0x02, 2, 2); feed(&a, 0x08, 2, 2); feed(&a, 0x20, 2, 2);
    failAfter = 0;
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 1 && a.injectedPointer.held == 0);

    /* A press released normally sends nothing at the end. */
    fresh(&a, 1);
    feed(&a, 0x02, 2, 2); feed(&a, 0x04, 2, 2);
    kvm_relay_release_injected_pointer(&a);
    assert(writes == 0);

    puts("PASS windows kvm pointer release");
    return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / 'harness.c'
    exe = Path(tmp) / 'harness'
    src.write_text(prelude + extract('static void kvm_relay_note_injected_pointer(KvmRelayContext* ctx, char* buf, int len)') + '\n' + extract('static void kvm_relay_release_injected_pointer(KvmRelayContext* ctx)') + '\n' + cases)
    cc = os.environ.get('CC', 'clang')
    subprocess.run([cc, '-std=gnu99', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-g', '-I', str(ROOT), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
