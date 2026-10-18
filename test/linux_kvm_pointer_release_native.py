#!/usr/bin/env python3
"""Run the Linux KVM master's input and cleanup functions with the pointer-release tracker.

Extracts kvm_relay_feeddata() and kvm_cleanup() from meshcore/KVM/Linux/linux_kvm.c into a C
harness with a real pipe standing in for the master-to-slave channel and stubbed kill/waitpid/usleep,
then checks that ending a session releases exactly the buttons it delivered, before the slave is
signalled, and nothing else. Any POSIX host with clang (or CC); ASan/UBSan; no X server is needed.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/KVM/Linux/linux_kvm.c').read_text()


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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "meshcore/KVM/kvm_pointer_release.h"
static int g_shutdown, g_totalRestartCount, kills, sleeps, killedAfterBytes;
static pid_t g_slavekvm;
static int master2slave[2];
static KvmPointerTrack g_injectedPointer;
static int pending(void) { int n = 0; char b[256]; ssize_t r; while ((r = read(master2slave[0], b, sizeof(b))) > 0) n += (int)r; return n; }
/* The slave: reads the pipe after slaveReadsAfter polls, recording what it consumed. */
static int polls, slaveReadsAfter, consumed, consumedAtKill;
static unsigned char slaveSaw[64];
static int queuedBytes(void) { int n = 0; ioctl(master2slave[0], FIONREAD, &n); return n; }
static int stub_ioctl(int fd, unsigned long req, int* n)
{
    (void)fd; (void)req;
    if (++polls > slaveReadsAfter) { int r = (int)read(master2slave[0], slaveSaw + consumed, sizeof(slaveSaw) - consumed); if (r > 0) consumed += r; }
    *n = queuedBytes();
    return 0;
}
static int stub_kill(pid_t pid, int sig) { (void)pid; (void)sig; ++kills; killedAfterBytes = queuedBytes(); consumedAtKill = consumed; return 0; }
static pid_t stub_waitpid(pid_t pid, int* code, int opt) { (void)opt; if (code) *code = 0; return pid; }
static int stub_usleep(unsigned int us) { (void)us; ++sleeps; return 0; }
#define ioctl(fd, req, n) stub_ioctl(fd, req, n)
#define kill stub_kill
#define waitpid stub_waitpid
#define usleep stub_usleep
'''

cases = r'''
#include <fcntl.h>
static void feed(unsigned char b, unsigned short x, unsigned short y)
{
    char p[10] = { 0, 2, 0, 10, 0, (char)b, (char)(x >> 8), (char)(x & 0xFF), (char)(y >> 8), (char)(y & 0xFF) };
    assert(kvm_relay_feeddata(p, (int)sizeof(p)) == 10);
}
static int drain(unsigned char* ups, int max)
{
    unsigned char b[64]; int n = (int)read(master2slave[0], b, sizeof(b)), i, c = 0;
    if (n < 0) n = 0;
    assert(n % 10 == 0);
    for (i = 0; i < n && c < max; i += 10) { assert(b[i] == 0 && b[i + 1] == 2 && b[i + 3] == 10); ups[c++] = b[i + 5]; }
    return c;
}
static void session(void) { assert(pipe(master2slave) == 0); fcntl(master2slave[0], F_SETFL, O_NONBLOCK); g_slavekvm = 4242; kills = sleeps = polls = consumed = consumedAtKill = 0; slaveReadsAfter = 2; }
int main(void)
{
    unsigned char ups[8];

    /* A held left button is released before the slave is signalled, then the slave gets one wait. */
    session();
    feed(0x02, 10, 20); feed(0x00, 30, 40);
    assert(pending() == 20);
    kvm_cleanup();
    /* The slave read the release before it was signalled, and the master waited only until then. */
    assert(consumedAtKill == 10 && slaveSaw[5] == 0x04 && killedAfterBytes == 0);
    assert(kills == 1 && sleeps == 2 && g_slavekvm == 0);
    assert(g_injectedPointer.held == 0);

    /* A session that released everything sends nothing extra and does not wait. */
    session();
    feed(0x02, 1, 1); feed(0x04, 1, 1); feed(0x08, 2, 2); feed(0x10, 2, 2);
    pending();
    kvm_cleanup();
    assert(drain(ups, 8) == 0 && kills == 1 && sleeps == 0 && polls == 0);

    /* Right and middle held: both released, in order. */
    session();
    feed(0x08, 5, 5); feed(0x20, 6, 6);
    pending();
    kvm_cleanup();
    assert(consumedAtKill == 20 && slaveSaw[5] == 0x10 && slaveSaw[15] == 0x40);

    /* A slave that never reads: the wait is bounded (25 polls of 10 ms), then the slave is signalled. */
    session();
    slaveReadsAfter = 1000;
    feed(0x02, 1, 1);
    pending();
    kvm_cleanup();
    assert(sleeps == 25 && kills == 1 && consumedAtKill == 0);

    /* No slave: nothing is written, and the tracker is still reset for the next session. */
    session();
    feed(0x02, 1, 1);
    pending();
    g_slavekvm = 0;
    kvm_cleanup();
    assert(drain(ups, 8) == 0 && kills == 0 && g_injectedPointer.held == 0);

    /* A partial write is not tracked as delivered. */
    session();
    close(master2slave[0]);
    signal(SIGPIPE, SIG_IGN);
    { char p[10] = { 0, 2, 0, 10, 0, 0x02, 0, 1, 0, 1 }; assert(kvm_relay_feeddata(p, 10) == 0); }
    assert(g_injectedPointer.held == 0);
    puts("PASS linux kvm pointer release");
    return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / 'harness.c'
    exe = Path(tmp) / 'harness'
    src.write_text(prelude + extract('int kvm_relay_feeddata(char* buf, int len)') + '\n' + extract('void kvm_cleanup()') + '\n' + cases)
    cc = os.environ.get('CC', 'clang')
    subprocess.run([cc, '-std=gnu99', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-g', '-I', str(ROOT), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
