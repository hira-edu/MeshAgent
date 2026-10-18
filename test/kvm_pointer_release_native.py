#!/usr/bin/env python3
"""Unit-test the KVM pointer-release tracker (meshcore/KVM/kvm_pointer_release.h).

Compiles the production header into a small C harness with clang (or CC) under ASan/UBSan and
-Werror, then checks press/release tracking, ignored packets and the exact release packets.
Any POSIX host; no agent build, endpoint or OS input is used.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

harness = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "meshcore/KVM/kvm_pointer_release.h"

static int feed(KvmPointerTrack* t, unsigned char b, unsigned short x, unsigned short y)
{
    char p[10] = { 0, 2, 0, 10, 0, (char)b, (char)(x >> 8), (char)(x & 0xFF), (char)(y >> 8), (char)(y & 0xFF) };
    return kvm_pointer_track_packet(t, p, (int)sizeof(p));
}

static int releases(const KvmPointerTrack* t, unsigned char elsewhere, unsigned char ups[3], unsigned short* x, unsigned short* y)
{
    char packets[KVM_POINTER_RELEASE_MAX_PACKETS][KVM_POINTER_RELEASE_PACKET_SIZE];
    int n = kvm_pointer_track_release_packets(t, elsewhere, packets), i;
    for (i = 0; i < n; ++i)
    {
        const unsigned char* p = (const unsigned char*)packets[i];
        assert(p[0] == 0 && p[1] == 2 && p[2] == 0 && p[3] == 10 && p[4] == 0);
        ups[i] = p[5];
        *x = (unsigned short)((p[6] << 8) | p[7]);
        *y = (unsigned short)((p[8] << 8) | p[9]);
    }
    return n;
}

int main(void)
{
    KvmPointerTrack t;
    unsigned char ups[3] = { 0 };
    unsigned short x = 0, y = 0;
    char wheel[12] = { 0, 2, 0, 12, 0, 0, 0x01, 0x02, 0x03, 0x04, (char)0xFF, (char)0x88 };
    char bad[10] = { 0, 2, 0, 11, 0, 0x02, 0, 1, 0, 1 };
    char key[10] = { 0, 1, 0, 10, 0, 0x02, 0, 1, 0, 1 };

    kvm_pointer_track_reset(&t);
    assert(releases(&t, 0, ups, &x, &y) == 0);

    /* A left press is held until its up; the release goes to the last delivered position. */
    assert(feed(&t, 0x02, 100, 200) == 1);
    assert(feed(&t, 0x00, 150, 220) == 1);
    assert(t.held == 0x02);
    assert(releases(&t, 0, ups, &x, &y) == 1 && ups[0] == 0x04 && x == 150 && y == 220);
    assert(feed(&t, 0x04, 150, 220) == 1 && t.held == 0);

    /* Right and middle, in a fixed order. */
    feed(&t, 0x08, 1, 2); feed(&t, 0x20, 3, 4);
    assert(releases(&t, 0, ups, &x, &y) == 2 && ups[0] == 0x10 && ups[1] == 0x40 && x == 3 && y == 4);

    /* A button another live session holds is left alone. */
    assert(releases(&t, 0x08, ups, &x, &y) == 1 && ups[0] == 0x40);
    assert(releases(&t, 0x28, ups, &x, &y) == 0);

    /* A combined down and up of the same button nets to released (Windows ORs the flags). */
    kvm_pointer_track_reset(&t);
    feed(&t, 0x06, 9, 9);
    assert(t.held == 0);

    /* The double-click indication changes nothing, not even the position. */
    feed(&t, 0x02, 5, 6);
    assert(feed(&t, 0x88, 70, 80) == 1);
    assert(t.held == 0x02 && t.x == 5 && t.y == 6);

    /* A wheel packet (size 12) moves the position, presses nothing. */
    assert(kvm_pointer_track_packet(&t, wheel, (int)sizeof(wheel)) == 1);
    assert(t.held == 0x02 && t.x == 0x0102 && t.y == 0x0304);

    /* Packets the agents ignore are ignored here: wrong size, wrong type, short buffers, NULLs. */
    assert(kvm_pointer_track_packet(&t, bad, (int)sizeof(bad)) == 0);
    assert(kvm_pointer_track_packet(&t, key, (int)sizeof(key)) == 0);
    assert(kvm_pointer_track_packet(&t, wheel, 9) == 0);
    assert(kvm_pointer_track_packet(&t, wheel, 11) == 0);
    assert(kvm_pointer_track_packet(NULL, wheel, 12) == 0);
    assert(kvm_pointer_track_packet(&t, NULL, 12) == 0);
    assert(kvm_pointer_track_release_packets(NULL, 0, NULL) == 0);
    assert(t.held == 0x02);

    /* Unknown bits do not create presses. */
    kvm_pointer_track_reset(&t);
    feed(&t, 0x81, 1, 1);
    assert(t.held == 0);

    /* Coordinates up to 65535 survive the round trip. */
    feed(&t, 0x02, 65535, 65534);
    assert(releases(&t, 0, ups, &x, &y) == 1 && x == 65535 && y == 65534);

    kvm_pointer_track_reset(&t);
    assert(t.held == 0 && t.x == 0 && t.y == 0);
    puts("PASS kvm pointer release tracker");
    return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / 'harness.c'
    exe = Path(tmp) / 'harness'
    src.write_text(harness)
    cc = os.environ.get('CC', 'clang')
    subprocess.run([cc, '-std=c99', '-Wall', '-Wextra', '-Werror', '-Wunused-function', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-g', '-I', str(ROOT), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
