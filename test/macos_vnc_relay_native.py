#!/usr/bin/env python3
"""Drive the production macOS VNC relay client against a scripted RFB server.

The relay is compiled under ASan/UBSan into a small command harness. The test
plays the Screen Sharing side over loopback, so no real screen, Screen Sharing
service or credential is involved.
"""
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import tempfile
import threading
import time

root = Path(__file__).resolve().parents[1]
relay_source = root / 'meshcore/KVM/MacOS/mac_vnc_relay.c'

harness = r'''
#include "mac_vnc_relay.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static vnc_relay *relay;
static pthread_t worker;
static int worker_wait;
static pthread_mutex_t out = PTHREAD_MUTEX_INITIALIZER;
static void say(const char *format, ...) __attribute__((format(printf, 1, 2)));
#include <stdarg.h>
static void say(const char *format, ...) {
    va_list args; va_start(args, format);
    pthread_mutex_lock(&out); vprintf(format, args); putchar('\n'); fflush(stdout); pthread_mutex_unlock(&out);
    va_end(args);
}
static void *pump_worker(void *unused) {
    (void)unused; say("pumpbg %d", vnc_relay_pump(relay, worker_wait)); return NULL;
}
int main(void) {
    char line[256], arg[128];
    while (fgets(line, sizeof(line), stdin)) {
        int a = 0, b = 0, c = 0, d = 0, w = 0, h = 0, e;
        unsigned int u = 0;
        if (sscanf(line, "open %d %127s %d", &a, arg, &b) == 3) {
            relay = vnc_relay_open((uint16_t)a, strcmp(arg, "-") ? arg : NULL, b, NULL, NULL, &e);
            if (relay) vnc_relay_size(relay, &w, &h);
            say("open %d %d %d", e, w, h);
        } else if (sscanf(line, "pumpbg %d", &a) == 1) {
            worker_wait = a; pthread_create(&worker, NULL, pump_worker, NULL);
        } else if (sscanf(line, "pump %d", &a) == 1) {
            say("pump %d", vnc_relay_pump(relay, a));
        } else if (strncmp(line, "join", 4) == 0) {
            pthread_join(worker, NULL); say("join");
        } else if (strncmp(line, "size", 4) == 0) {
            e = vnc_relay_size(relay, &w, &h); say("size %d %d %d", e, w, h);
        } else if (sscanf(line, "fb %d %d", &a, &b) == 2) {
            vnc_relay_size(relay, &w, &h);
            size_t stride = (size_t)w * 3 + (size_t)a, size = stride * (size_t)h - (size_t)b;
            unsigned char *dst = malloc(stride * (size_t)h); memset(dst, 0xEE, stride * (size_t)h);
            e = vnc_relay_copy_rgb24(relay, dst, size, stride, &w, &h);
            pthread_mutex_lock(&out); printf("fb %d ", e);
            for (int y = 0; e == 0 && y < h; ++y) for (size_t x = 0; x < stride; ++x) printf("%02x", dst[(size_t)y * stride + x]);
            putchar('\n'); fflush(stdout); pthread_mutex_unlock(&out); free(dst);
        } else if (sscanf(line, "key %x %d", &u, &a) == 2) {
            say("key %d", vnc_relay_key(relay, u, a));
        } else if (sscanf(line, "mouse %d %d %d %d", &a, &b, &c, &d) == 4) {
            say("mouse %d", vnc_relay_mouse(relay, a, b, c, (short)d));
        } else if (sscanf(line, "vk %d", &a) == 1) {
            say("vk %x", vnc_relay_vk_to_keysym((unsigned char)a));
        } else if (sscanf(line, "uni %d", &a) == 1) {
            say("uni %x", vnc_relay_unicode_to_keysym((uint16_t)a));
        } else if (strncmp(line, "shutdown", 8) == 0) {
            vnc_relay_shutdown(relay); say("shutdown");
        } else if (strncmp(line, "close", 5) == 0) {
            vnc_relay_close(relay); relay = NULL; say("close");
        }
    }
    return 0;
}
'''

E_CONNECT, E_PROTOCOL, E_AUTH, E_UNSUPPORTED, E_CLOSED, E_TIMEOUT, E_ARG = -1, -2, -3, -4, -5, -6, -8
PIXEL_FORMAT = bytes([0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0])
ENCODINGS = bytes([2, 0, 0, 3]) + struct.pack('>iii', 0, 1, -223)
TIMEOUT_MS = 1000


class Harness:
    def __init__(self, binary):
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.lines = queue.Queue()
        threading.Thread(target=lambda: [self.lines.put(line) for line in self.process.stdout], daemon=True).start()

    def send(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()

    def expect(self, prefix, timeout=10):
        try:
            line = self.lines.get(timeout=timeout).strip()
        except queue.Empty:
            raise AssertionError(f'harness did not answer {prefix!r}')
        assert line.startswith(prefix + ' ') or line == prefix, f'expected {prefix!r}, got {line!r}'
        return line.split()[1:]

    def run(self, command):
        self.send(command)
        return self.expect(command.split()[0])

    def finish(self):
        self.process.stdin.close()
        assert self.process.wait(timeout=10) == 0, 'harness failed (sanitizer report above)'


def recv_exact(conn, length):
    data = b''
    conn.settimeout(5)
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        assert chunk, f'client closed after {len(data)} of {length} bytes'
        data += chunk
    return data


def expect_nothing(conn):
    conn.settimeout(0.2)
    try:
        data = conn.recv(1)
    except socket.timeout:
        return
    assert data == b'', f'unexpected client bytes {data!r}'


def des_response(password, challenge):
    key = bytes(int(f'{b:08b}'[::-1], 2) for b in password.encode()[:8]).ljust(8, b'\0')
    result = subprocess.run(['/usr/bin/openssl', 'enc', '-des-ecb', '-nopad', '-K', key.hex()],
                            input=challenge, capture_output=True, check=True)
    return result.stdout


def update_request(incremental, width, height):
    return struct.pack('>BBHHHH', 3, incremental, 0, 0, width, height)


def rect(x, y, w, h, encoding):
    return struct.pack('>HHHHi', x, y, w, h, encoding)


def bgrx(pixels):
    return b''.join(bytes([b, g, r, 0]) for (r, g, b) in pixels)


class Session:
    """One harness connection to one scripted server connection."""

    def __init__(self, harness, version=b'RFB 003.008\n', types=(1,), password='-', chosen=1,
                 result=0, width=4, height=3, name=b'mac', expect_open=0):
        self.h = harness
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.h.send(f'open {self.port} {password} {TIMEOUT_MS}')
        self.conn, _ = self.listener.accept()
        self.width, self.height = width, height
        self.fb = [[(0, 0, 0)] * width for _ in range(height)]
        self.conn.sendall(version)
        if not version.startswith(b'RFB 003.') or int(version[8:11]) < 8:
            self.opened(expect_open)
            return
        assert recv_exact(self.conn, 12) == b'RFB 003.008\n'
        self.conn.sendall(bytes([len(types)]) + bytes(types))
        if not types:
            self.conn.sendall(struct.pack('>I', 6) + b'nope!!')
            self.opened(expect_open)
            return
        if chosen is None:
            self.opened(expect_open)
            return
        assert recv_exact(self.conn, 1) == bytes([chosen])
        if chosen == 2:
            challenge = os.urandom(16)
            self.conn.sendall(challenge)
            assert recv_exact(self.conn, 16) == des_response(password, challenge), 'VNC auth response'
        self.conn.sendall(struct.pack('>I', result))
        if result != 0:
            self.conn.sendall(struct.pack('>I', 3) + b'bad')
            self.opened(expect_open)
            return
        assert recv_exact(self.conn, 1) == b'\x01', 'ClientInit must request a shared session'
        self.conn.sendall(struct.pack('>HH', width, height) + bytes(16) + struct.pack('>I', len(name)) + name)
        if expect_open != 0:
            self.opened(expect_open)
            return
        assert recv_exact(self.conn, 20) == PIXEL_FORMAT
        assert recv_exact(self.conn, 16) == ENCODINGS
        assert recv_exact(self.conn, 10) == update_request(0, width, height)
        self.opened(expect_open)

    def opened(self, expected):
        result = self.h.expect('open')
        assert int(result[0]) == expected, f'open returned {result}, expected {expected}'
        if expected == 0:
            assert [int(v) for v in result[1:]] == [self.width, self.height]

    def raw(self, x, y, pixels):
        self.conn.sendall(bytes([0, 0]) + struct.pack('>H', 1) + rect(x, y, len(pixels[0]), len(pixels), 0)
                          + b''.join(bgrx(row) for row in pixels))
        for j, row in enumerate(pixels):
            for i, p in enumerate(row):
                self.fb[y + j][x + i] = p

    def copyrect(self, x, y, w, h, sx, sy):
        self.conn.sendall(bytes([0, 0]) + struct.pack('>H', 1) + rect(x, y, w, h, 1) + struct.pack('>HH', sx, sy))
        before = [row[:] for row in self.fb]
        for j in range(h):
            for i in range(w):
                self.fb[y + j][x + i] = before[sy + j][sx + i]

    def pump(self, expected, incremental=1):
        assert int(self.h.run(f'pump {TIMEOUT_MS}')[0]) == expected
        if expected > 0:
            assert recv_exact(self.conn, 10) == update_request(incremental, self.width, self.height)

    def check_fb(self, pad=0):
        result = self.h.run(f'fb {pad} 0')
        assert result[0] == '0', result
        expected = ''.join(''.join(f'{r:02x}{g:02x}{b:02x}' for (r, g, b) in row) + 'ee' * pad for row in self.fb)
        assert result[1] == expected, f'framebuffer mismatch\n{result[1]}\n{expected}'

    def close(self):
        self.h.run('close')
        self.conn.close()
        self.listener.close()


def pattern(w, h, seed):
    return [[((seed + 3 * i + 17 * j) & 0xFF, (seed * 7 + i) & 0xFF, (seed + 29 * j) & 0xFF) for i in range(w)] for j in range(h)]


def test_raw_copyrect_resize(h):
    s = Session(h)
    s.raw(0, 0, pattern(4, 3, 1))
    s.pump(1)
    s.check_fb()
    s.check_fb(pad=5)
    assert h.run('fb 0 1')[0] == str(E_ARG), 'undersized destination must be rejected'
    s.copyrect(2, 1, 2, 2, 0, 0)
    s.pump(1)
    s.check_fb()
    s.copyrect(1, 1, 3, 2, 0, 0)  # overlapping, moving down-right
    s.pump(1)
    s.check_fb()
    s.copyrect(0, 0, 3, 2, 1, 1)  # overlapping, moving up-left
    s.pump(1)
    s.check_fb()
    s.raw(1, 2, [[(9, 8, 7)]])
    s.pump(1)
    s.check_fb()
    # Bell and ServerCutText are consumed without disturbing the stream.
    s.conn.sendall(b'\x02' + b'\x03\0\0\0' + struct.pack('>I', 5) + b'hello')
    s.pump(0)
    s.pump(0)
    s.conn.sendall(bytes([0, 0]) + struct.pack('>H', 1) + rect(0, 0, 6, 5, -223))
    s.width, s.height = 6, 5
    s.fb = [[(0, 0, 0)] * 6 for _ in range(5)]
    s.pump(2, incremental=0)                                     # Resized; the blank frame is not an update
    assert h.run('size') == ['0', '6', '5']
    s.check_fb()
    s.raw(0, 0, pattern(6, 5, 2))
    s.pump(1)
    s.check_fb()
    s.close()


def test_handshakes(h):
    s = Session(h, version=b'RFB 003.889\n', types=(30, 2, 35), password='s3cr3tPw', chosen=2)
    s.close()
    s = Session(h, types=(1, 2), password='longer-than-eight', chosen=2)
    s.close()
    s = Session(h, types=(1,), password='pw', chosen=None, expect_open=E_UNSUPPORTED)   # None is refused with a credential
    s.conn.close()
    s = Session(h, types=(2,), chosen=None, expect_open=E_UNSUPPORTED)
    s.conn.close()
    s = Session(h, types=(30, 35), password='pw', chosen=None, expect_open=E_UNSUPPORTED)
    s.conn.close()
    s = Session(h, types=(), expect_open=E_UNSUPPORTED)
    s.conn.close()
    s = Session(h, types=(2,), password='wrong', chosen=2, result=1, expect_open=E_AUTH)
    s.conn.close()
    s = Session(h, version=b'RFB 003.003\n', expect_open=E_UNSUPPORTED)
    s.conn.close()
    s = Session(h, version=b'XFB 003.008\n', expect_open=E_PROTOCOL)
    s.conn.close()
    s = Session(h, width=0, height=3, expect_open=E_PROTOCOL)
    s.conn.close()
    s = Session(h, width=20000, height=3, expect_open=E_PROTOCOL)
    s.conn.close()
    unused = socket.socket()
    unused.bind(('127.0.0.1', 0))
    port = unused.getsockname()[1]
    unused.close()
    h.send(f'open {port} - {TIMEOUT_MS}')
    assert h.expect('open')[0] == str(E_CONNECT)


def failing_session(h, payload, expected, then_close=False, stall=0.0):
    s = Session(h)
    s.conn.sendall(payload)
    if then_close:
        s.conn.close()
    if stall:
        h.send(f'pump {TIMEOUT_MS}')
        time.sleep(stall)
        assert h.expect('pump') == [str(expected)]
    else:
        assert h.run(f'pump {TIMEOUT_MS}') == [str(expected)]
    # Failure is sticky: no further reads or input after the stream is untrusted.
    assert h.run(f'pump {TIMEOUT_MS}') == [str(expected)]
    assert h.run('key 61 1') == [str(expected)]
    assert h.run('mouse 1 1 2 0') == [str(expected)]
    assert h.run('fb 0 0')[0] == str(expected)
    h.run('close')
    if not then_close:
        s.conn.close()
    s.listener.close()


def test_failures(h):
    update = bytes([0, 0]) + struct.pack('>H', 1)
    failing_session(h, update + rect(0, 0, 4, 3, 16), E_PROTOCOL)                  # ZRLE was not negotiated
    failing_session(h, update + rect(0, 0, 4, 3, 7), E_PROTOCOL)                   # Tight was not negotiated
    failing_session(h, update + rect(3, 0, 2, 1, 0), E_PROTOCOL)                   # Raw past the right edge
    failing_session(h, update + rect(0, 2, 1, 2, 0), E_PROTOCOL)                   # Raw past the bottom edge
    failing_session(h, update + rect(0, 0, 2, 2, 1) + struct.pack('>HH', 3, 0), E_PROTOCOL)  # CopyRect source outside
    failing_session(h, update + rect(0, 0, 0, 0, -223), E_PROTOCOL)                # Zero-size resize
    failing_session(h, b'\x01', E_PROTOCOL)                                        # Colour map in true-colour mode
    failing_session(h, b'\x09', E_PROTOCOL)                                        # Unknown message type
    failing_session(h, b'\x03\0\0\0' + struct.pack('>I', 0x7FFFFFFF), E_PROTOCOL)  # Oversized clipboard
    failing_session(h, update + rect(0, 0, 4, 3, 0) + bytes(20), E_CLOSED, then_close=True)
    failing_session(h, update + rect(0, 0, 4, 3, 0) + bytes(20), E_TIMEOUT, stall=1.5)


def test_input(h):
    s = Session(h, width=1920, height=1080)
    pointer = lambda mask, x, y: struct.pack('>BBHH', 5, mask, x, y)
    assert h.run('key 61 1') == ['0']
    assert recv_exact(s.conn, 8) == struct.pack('>BBHI', 4, 1, 0, 0x61)
    assert h.run('key ffe1 0') == ['0']
    assert recv_exact(s.conn, 8) == struct.pack('>BBHI', 4, 0, 0, 0xFFE1)
    assert h.run('key 0 1') == [str(E_ARG)]
    cases = [
        ((100, 200, 0, 0), [pointer(0, 100, 200)]),
        ((100, 200, 0x02, 0), [pointer(1, 100, 200)]),
        ((110, 210, 0, 0), [pointer(1, 110, 210)]),          # drag keeps the button held
        ((110, 210, 0x04, 0), [pointer(0, 110, 210)]),
        ((5, 6, 0x08, 0), [pointer(4, 5, 6)]),
        ((5, 6, 0x20, 0), [pointer(6, 5, 6)]),
        ((5, 6, 0x10, 0), [pointer(2, 5, 6)]),
        ((5, 6, 0x40, 0), [pointer(0, 5, 6)]),
        ((7, 8, 0x88, 0), []),                                # double-click marker: both clicks were already sent
        ((7, 8, 0, 240), [pointer(0, 7, 8)] + [pointer(8, 7, 8), pointer(0, 7, 8)] * 2),
        ((7, 8, 0, -1), [pointer(0, 7, 8)]),                  # below one step: carried over
        ((7, 8, 0, -119), [pointer(0, 7, 8), pointer(16, 7, 8), pointer(0, 7, 8)]),  # carried -1 completes a step
        ((7, 8, 0, -32768), [pointer(0, 7, 8)] + [pointer(16, 7, 8), pointer(0, 7, 8)] * 10),
        ((5000, -5, 0, 0), [pointer(0, 1919, 0)]),
        ((-1, 9999, 0x99, 0), [pointer(0, 0, 1079)]),         # unknown button value only moves
    ]
    for (x, y, button, wheel), messages in cases:
        assert h.run(f'mouse {x} {y} {button} {wheel}') == ['0']
        expected = b''.join(messages)
        assert recv_exact(s.conn, len(expected)) == expected, (x, y, button, wheel)
    expect_nothing(s.conn)

    # A frame stalled mid-rectangle must not block input from another thread.
    s.conn.sendall(bytes([0, 0]) + struct.pack('>H', 1) + rect(0, 0, 2, 1, 0) + bytes(4))
    h.send(f'pumpbg {TIMEOUT_MS}')
    time.sleep(0.2)
    assert h.run('key ff0d 1') == ['0']
    assert recv_exact(s.conn, 8) == struct.pack('>BBHI', 4, 1, 0, 0xFF0D)
    s.conn.sendall(bytes(4))
    assert h.expect('pumpbg') == ['1']
    h.run('join')
    assert recv_exact(s.conn, 10) == update_request(1, 1920, 1080)

    # Shutdown unblocks a waiting pump thread and closes the input path.
    h.send('pumpbg 5000')
    time.sleep(0.2)
    started = time.monotonic()
    h.run('shutdown')
    assert h.expect('pumpbg') == [str(E_CLOSED)]
    assert time.monotonic() - started < 1
    h.run('join')
    assert h.run('key 61 1') == [str(E_CLOSED)]
    s.close()


def test_keysyms(h):
    vk = {
        0x08: 0xFF08, 0x09: 0xFF09, 0x0D: 0xFF0D, 0x10: 0xFFE1, 0x11: 0xFFE3, 0x12: 0xFFE9, 0x14: 0xFFE5,
        0x1B: 0xFF1B, 0x20: 0x20, 0x21: 0xFF55, 0x22: 0xFF56, 0x23: 0xFF57, 0x24: 0xFF50, 0x25: 0xFF51,
        0x26: 0xFF52, 0x27: 0xFF53, 0x28: 0xFF54, 0x2D: 0xFF63, 0x2E: 0xFFFF, 0x30: 0x30, 0x39: 0x39,
        0x41: 0x61, 0x5A: 0x7A, 0x5B: 0xFFEB, 0x5C: 0xFFEC, 0x60: 0xFFB0, 0x69: 0xFFB9, 0x6A: 0xFFAA,
        0x6F: 0xFFAF, 0x70: 0xFFBE, 0x7B: 0xFFC9, 0x87: 0xFFD5, 0x90: 0xFF7F, 0xA1: 0xFFE2, 0xA3: 0xFFE4,
        0xA5: 0xFFEA, 0xBA: 0x3B, 0xBB: 0x3D, 0xBC: 0x2C, 0xBD: 0x2D, 0xBE: 0x2E, 0xBF: 0x2F, 0xC0: 0x60,
        0xDB: 0x5B, 0xDC: 0x5C, 0xDD: 0x5D, 0xDE: 0x27, 0xE2: 0x3C, 0x00: 0, 0x07: 0, 0xFF: 0,
    }
    for code, keysym in vk.items():
        assert h.run(f'vk {code}') == [f'{keysym:x}'], hex(code)
    uni = {
        0x41: 0x41, 0x7E: 0x7E, 0xE9: 0xE9, 0xFF: 0xFF, 0x20AC: 0x010020AC, 0x4E2D: 0x01004E2D,
        0x08: 0xFF08, 0x09: 0xFF09, 0x0A: 0xFF0D, 0x0D: 0xFF0D, 0x1B: 0xFF1B, 0x7F: 0xFFFF,
        0x00: 0, 0x01: 0, 0x85: 0, 0xD800: 0, 0xDFFF: 0,
    }
    for code, keysym in uni.items():
        assert h.run(f'uni {code}') == [f'{keysym:x}'], hex(code)


with tempfile.TemporaryDirectory() as directory:
    probe = Path(directory)
    (probe / 'harness.c').write_text(harness)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(relay_source.parent),
                    str(relay_source), str(probe / 'harness.c'), '-o', str(probe / 'harness')], check=True)
    h = Harness(probe / 'harness')
    test_keysyms(h)
    print('PASS: VK and Unicode keysym mapping')
    test_handshakes(h)
    print('PASS: RFB 3.8 and Apple 3.889 handshakes, None/VNC auth, refusals, bad versions and sizes')
    test_raw_copyrect_resize(h)
    print('PASS: Raw, overlapping CopyRect, DesktopSize, padded copies, bell and clipboard skipping')
    test_failures(h)
    print('PASS: unnegotiated encodings, out-of-bounds rects, bad messages, disconnect and stall fail closed')
    test_input(h)
    print('PASS: key/pointer/wheel/double-click wire format, clamping, input during stalled frame, shutdown')
    h.finish()
