#!/usr/bin/env python3
"""Run the production macOS relay session loop against a scripted relay.

Compiles kvm_server_mainloop() and its helpers from mac_kvm.c under ASan/UBSan
with the relay, tile encoder and input thread replaced by fakes, then checks the
packet stream sent to the agent: the resolution precedes tiles, no tiles are sent
before Screen Sharing delivers a frame, refresh resends every tile, pause holds
tiles without losing the update, resize reallocates the padded buffer, and every
failure reaches the viewer as a message. No desktop or VNC server is contacted.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/KVM/MacOS/mac_kvm.c').read_text()


def between(start, end):
    first = source.index(start)
    return source[first:source.index(end, first)]


constants = between('#define MAC_KVM_RELAY_SECRET\t', '\nint KVM_SEND(')
globals_and_messages = between('int SCREEN_WIDTH = 0;', '\nstatic int MacKvm_ExecutableDirectory(')
init = between('// Adopts the relay', '\nint kvm_server_inputdata(')
loop = between('// Encodes and sends every changed tile', '\nvoid kvm_relay_ExitHandler(')

prelude = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "meshcore/meshdefines.h"
#include "meshcore/KVM/MacOS/mac_vnc_relay.h"
#define UNREFERENCED_PARAMETER(x) (void)(x)
enum TILE_FLAGS_ENUM { TILE_TODO, TILE_SENT, TILE_MARKED_NOT_SENT, TILE_DONT_SEND };
struct tileInfo_t { int crc; enum TILE_FLAGS_ENUM flag; };
typedef void* ILibProcessPipe_Process;
typedef struct { void *items[64]; int head, tail; } FakeQueue;
typedef FakeQueue* ILibQueue;
static char *ILibCriticalLogFilename;
static uint64_t fakeTime;
static uint64_t ILibGetUptime(void) { return fakeTime; }
static ILibQueue ILibQueue_Create(void) { return calloc(1, sizeof(FakeQueue)); }
static void ILibQueue_Destroy(ILibQueue q) { assert(q->head == q->tail); free(q); }
static void ILibQueue_Lock(ILibQueue q) { (void)q; }
static void ILibQueue_UnLock(ILibQueue q) { (void)q; }
static void ILibQueue_EnQueue(ILibQueue q, void *item) { assert(q->tail < 64); q->items[q->tail++] = item; }
static int ILibQueue_IsEmpty(ILibQueue q) { return q->head == q->tail; }
static void *ILibQueue_DeQueue(ILibQueue q) { return q->items[q->head++]; }
static void *ILibMemory_SmartAllocate(size_t size) { size_t *p = calloc(1, sizeof(size_t) + size); *p = size; return p + 1; }
static size_t ILibMemory_Size(void *p) { return ((size_t*)p)[-1]; }
static void ILibMemory_Free(void *p) { free((size_t*)p - 1); }
void *tilebuffer;

// Output stream sent to the agent.
static unsigned char out[1 << 16];
static size_t outLength;
static int failWrites;
static int KVM_SEND(char *buffer, int length) {
    if (failWrites) { return -1; }
    assert(outLength + (size_t)length <= sizeof(out));
    memcpy(out + outLength, buffer, (size_t)length); outLength += (size_t)length; return length;
}

// Tile encoder: emits one picture packet per tile carrying the first desktop byte under it.
extern int TILE_WIDTH, TILE_WIDTH_COUNT, TILE_HEIGHT_COUNT;
extern struct tileInfo_t **g_tileInfo;
static int adjust_screen_size(int pixels) { int extra = pixels % TILE_WIDTH; return extra ? pixels + TILE_WIDTH - extra : pixels; }
static int reset_tile_info(int oldHeightCount) {
    if (g_tileInfo != NULL) { for (int r = 0; r < oldHeightCount; ++r) { free(g_tileInfo[r]); } free(g_tileInfo); }
    g_tileInfo = calloc((size_t)TILE_HEIGHT_COUNT, sizeof(*g_tileInfo));
    for (int r = 0; r < TILE_HEIGHT_COUNT; ++r) { g_tileInfo[r] = calloc((size_t)TILE_WIDTH_COUNT, sizeof(**g_tileInfo)); }
    return 0;
}
static int getTileAt(int x, int y, void **buffer, long long *size, void *desktop, long long desktopSize, int row, int col) {
    extern int SCREEN_WIDTH;
    assert(g_tileInfo[row][col].flag == TILE_TODO);
    size_t at = ((size_t)y * (size_t)adjust_screen_size(SCREEN_WIDTH) + (size_t)x) * 3;
    assert(at < (size_t)desktopSize);
    unsigned char *p = malloc(9);
    p[0] = 0; p[1] = MNG_KVM_PICTURE; p[2] = 0; p[3] = 9;
    p[4] = (unsigned char)(x >> 8); p[5] = (unsigned char)x; p[6] = (unsigned char)(y >> 8); p[7] = (unsigned char)y;
    p[8] = ((unsigned char*)desktop)[at];
    *buffer = p; *size = 9;
    g_tileInfo[row][col].flag = TILE_SENT;
    return 0;
}
static int compressionType, compressionLevel;
static void set_tile_compression(int type, int level) { compressionType = type; compressionLevel = level; }
'''

fakes = r'''
// Scripted relay. Each pump returns the next step; a step may also act like the input thread.
enum { STEP_PUMP, STEP_REFRESH, STEP_PAUSE, STEP_RESUME, STEP_RESIZE, STEP_STOP };
typedef struct { int action; int result; int width; int height; } Step;
static struct vnc_relay { int unused; } relayObject;
static const Step *script;
static int scriptLength, scriptAt, openFails, relayWidth, relayHeight, frame, shutdownCalls, closeCalls, pumpCalls;
static int inputStarted, inputJoined;
static vnc_relay* MacKvm_OpenRelay(char *reason, size_t capacity) {
    if (openFails) { strlcpy(reason, "Remote desktop is unavailable: Screen Sharing is turned off on this Mac.", capacity); return NULL; }
    return &relayObject;
}
int vnc_relay_pump(vnc_relay *relay, int wait) {
    assert(relay == &relayObject && (wait == 100 || wait == 0)); ++pumpCalls;
    if (wait == 0) { return 0; }	// Nothing further queued
    fakeTime += (uint64_t)wait;
    if (scriptAt == scriptLength) { return VNC_RELAY_E_CLOSED; }
    const Step *step = &script[scriptAt++];
    switch (step->action) {
        case STEP_REFRESH: g_refresh = 1; break;
        case STEP_PAUSE: g_remotepause = 1; break;
        case STEP_RESUME: g_remotepause = 0; break;
        case STEP_RESIZE: relayWidth = step->width; relayHeight = step->height; break;
        case STEP_STOP: g_shutdown = 1; break;
    }
    if (step->result & VNC_RELAY_UPDATED) { ++frame; }
    return step->result;
}
int vnc_relay_size(vnc_relay *relay, int *width, int *height) { assert(relay == &relayObject); *width = relayWidth; *height = relayHeight; return 0; }
int vnc_relay_copy_rgb24(vnc_relay *relay, uint8_t *dst, size_t size, size_t stride, int *width, int *height) {
    assert(relay == &relayObject);
    size_t paddedWidth = (size_t)((relayWidth + 31) / 32 * 32), paddedHeight = (size_t)((relayHeight + 31) / 32 * 32);
    assert(stride == paddedWidth * 3 && size == paddedWidth * paddedHeight * 3);
    for (int y = 0; y < relayHeight; ++y) { memset(dst + (size_t)y * stride, frame, (size_t)relayWidth * 3); }
    *width = relayWidth; *height = relayHeight; return 0;
}
static int releaseCalls;
int vnc_relay_release_all(vnc_relay *relay) { assert(relay == &relayObject && shutdownCalls == 0); ++releaseCalls; return 0; }
void vnc_relay_shutdown(vnc_relay *relay) { assert(relay == &relayObject && releaseCalls == 1); ++shutdownCalls; }
void vnc_relay_close(vnc_relay *relay) { assert(relay == NULL || relay == &relayObject); if (relay) { assert(inputJoined || !inputStarted); ++closeCalls; } }
const char* vnc_relay_strerror(int error) { return error == VNC_RELAY_E_TIMEOUT ? "Screen Sharing stopped responding" : "Screen Sharing connection closed"; }
static void* kvm_mainloopinput(void *param) {
    assert(param == NULL); inputStarted = 1;
    while (!g_shutdown) { usleep(1000); }
    inputJoined = 1; return NULL;
}
'''

main = r'''
typedef struct { int type; int a; int b; } Packet;
static Packet packets[512];
static int packetCount;
static char message[512];
static void parse(void) {
    packetCount = 0; message[0] = 0;
    for (size_t at = 0; at < outLength;) {
        int type = (out[at] << 8) | out[at + 1], size = (out[at + 2] << 8) | out[at + 3];
        assert(size >= 4 && at + (size_t)size <= outLength && packetCount < 512);
        Packet *p = &packets[packetCount++]; p->type = type; p->a = p->b = 0;
        if (type == MNG_KVM_SCREEN) { assert(size == 8); p->a = (out[at + 4] << 8) | out[at + 5]; p->b = (out[at + 6] << 8) | out[at + 7]; }
        else if (type == MNG_KVM_PICTURE) { p->a = out[at + 8]; }
        else if (type == MNG_KVM_MESSAGE) { memcpy(message, out + at + 4, (size_t)size - 4); message[size - 4] = 0; }
        else { assert(0); }
        at += (size_t)size;
    }
}
static void run(const Step *steps, int count, int width, int height, void *expected) {
    script = steps; scriptLength = count; scriptAt = 0; relayWidth = width; relayHeight = height; frame = 0;
    outLength = 0; shutdownCalls = closeCalls = pumpCalls = inputStarted = inputJoined = releaseCalls = 0; g_refresh = g_remotepause = 0; fakeTime = 0;
    assert(kvm_server_mainloop(NULL) == expected);
    assert(g_tileInfo == NULL && g_desktop == NULL && g_relay == NULL);
    parse();
}
// Expects: [SCREEN w h] then `tiles` pictures, all carrying `value`, starting at packet index *at.
static void expect_screen(int *at, int w, int h) { assert(packets[*at].type == MNG_KVM_SCREEN && packets[*at].a == w && packets[*at].b == h); ++*at; }
static void expect_tiles(int *at, int tiles, int value) {
    for (int i = 0; i < tiles; ++i, ++*at) { assert(packets[*at].type == MNG_KVM_PICTURE && packets[*at].a == value); }
}
int main(void) {
    openFails = 1; run(NULL, 0, 0, 0, (void*)1);
    assert(packetCount == 1 && !strcmp(message, "Remote desktop is unavailable: Screen Sharing is turned off on this Mac."));
    assert(!inputStarted && shutdownCalls == 0 && releaseCalls == 0);
    openFails = 0;

    Step noFrame[151] = {0};
    run(noFrame, 151, 3024, 1964, (void*)1);
    assert(scriptAt == 150 && packetCount == 2 && packets[0].type == MNG_KVM_SCREEN);
    assert(!strcmp(message, MAC_KVM_NO_FRAME_MESSAGE) && inputJoined && closeCalls == 1 && releaseCalls == 1);

    Step delayedFrame[154] = {0};
    delayedFrame[148].result = VNC_RELAY_UPDATED;
    delayedFrame[153].action = STEP_STOP;
    run(delayedFrame, 154, 32, 32, (void*)0);
    assert(packetCount == 2 && packets[1].type == MNG_KVM_PICTURE && !message[0]);

    const Step session[] = {
        {STEP_PUMP, 0, 0, 0},						// Nothing yet
        {STEP_REFRESH, 0, 0, 0},					// Viewer refresh before the first frame: resolution only
        {STEP_PUMP, VNC_RELAY_UPDATED, 0, 0},		// First frame (1): every tile
        {STEP_PUMP, 0, 0, 0},						// Idle: nothing
        {STEP_REFRESH, 0, 0, 0},					// Refresh: resolution and every tile again (1)
        {STEP_PAUSE, VNC_RELAY_UPDATED, 0, 0},		// Frame 2 arrives while paused: held
        {STEP_RESUME, 0, 0, 0},						// Resume: the held frame (2)
        {STEP_RESIZE, VNC_RELAY_RESIZED | VNC_RELAY_UPDATED, 64, 64},	// Frame 3 at a new size
        {STEP_PUMP, VNC_RELAY_E_TIMEOUT, 0, 0},		// Relay stalls
    };
    run(session, sizeof(session) / sizeof(session[0]), 100, 40, (void*)1);	// Ended by a relay failure
    int at = 0;
    expect_screen(&at, 100, 40);
    expect_screen(&at, 100, 40);
    expect_tiles(&at, 8, 1);
    expect_screen(&at, 100, 40);
    expect_tiles(&at, 8, 1);
    expect_tiles(&at, 8, 2);
    expect_screen(&at, 64, 64);
    expect_tiles(&at, 4, 3);
    assert(packets[at].type == MNG_KVM_MESSAGE && ++at == packetCount);
    assert(!strcmp(message, "Remote desktop ended: Screen Sharing stopped responding."));
    assert(inputStarted && inputJoined && releaseCalls == 1 && shutdownCalls == 1 && closeCalls == 1);	// Held keys released first

    const Step stop[] = { {STEP_PUMP, VNC_RELAY_UPDATED, 0, 0}, {STEP_STOP, 0, 0, 0} };
    run(stop, 2, 32, 32, (void*)0);
    at = 0; expect_screen(&at, 32, 32); expect_tiles(&at, 1, 1);
    assert(at == packetCount && inputJoined && closeCalls == 1);	// Viewer disconnect: no error message

    const Step stopDuringError[] = { {STEP_STOP, VNC_RELAY_E_CLOSED, 0, 0} };
    run(stopDuringError, 1, 32, 32, (void*)0);
    assert(packetCount == 1 && packets[0].type == MNG_KVM_SCREEN);	// Shutdown-induced relay error is not reported

    const Step broken[] = { {STEP_PUMP, VNC_RELAY_UPDATED, 0, 0}, {STEP_PUMP, VNC_RELAY_UPDATED, 0, 0} };
    failWrites = 1; run(broken, 2, 64, 32, (void*)1); failWrites = 0;
    assert(outLength == 0 && scriptAt == 1 && inputJoined);	// The agent pipe closed: stop at the first failed tile
    puts("PASS: relay session loop ordering, first-frame gating, refresh, pause, resize, relay failure, viewer disconnect and pipe failure");
}
'''

with tempfile.TemporaryDirectory(prefix='mesh-kvm-mainloop-') as folder:
    target = Path(folder)
    (target / 'probe.c').write_text(prelude + constants + globals_and_messages + fakes + init + loop + main)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                    '-fsanitize=address,undefined', '-I', str(root), str(target / 'probe.c'), '-o', str(target / 'probe')], check=True)
    subprocess.run([str(target / 'probe')], check=True, timeout=30)
