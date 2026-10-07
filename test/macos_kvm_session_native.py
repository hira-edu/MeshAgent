#!/usr/bin/env python3
"""Verify the macOS Screen Sharing relay session without touching Screen Sharing.

Compiles production helper code from mac_kvm.c under ASan/UBSan:
- the credential reader against real temporary files, with fstat reporting the
  current user as root so ownership, mode, link and content rules are exercised;
- the port-ownership check against injected process tables, then against real
  libproc data for a temporary listener owned by the current user;
- console-session selection against injected preference reads/writes (no real
  Screen Sharing preference is changed);
- relay setup, failure reasons, input dispatch and helper launch with fakes.
No service is installed, no root is requested and no desktop or VNC server is
contacted.
"""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, help='Also verify the built -kvm0/-kvm1 entry points without root')
args = parser.parse_args()
if sys.platform != 'darwin':
    parser.error('This probe requires macOS')
root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/KVM/MacOS/mac_kvm.c').read_text()


def between(start, end):
    first = source.index(start)
    return source[first:source.index(end, first)]


constants = between('#define MAC_KVM_RELAY_SECRET\t', '\nint KVM_SEND(')
reader = between('int MacKvm_ReadRelaySecret(', '\n// screensharingd is socket-activated')
listener = between('int MacKvm_RelayListener(', '\n// Password-based VNC')
selector = between('static int MacKvm_SelectConsole(', '\nstatic vnc_relay* MacKvm_OpenRelay(')
opener = between('static vnc_relay* MacKvm_OpenRelay(', '\n// Runs the session\'s checks')
checker = between('int kvm_relay_check(', '\n// First-start onboarding')
dispatch = between('int kvm_server_inputdata(', '\n\nint kvm_relay_feeddata(')
exit_handler = between('void kvm_relay_ExitHandler(', '\nvoid kvm_relay_StdOutHandler(')
launcher = between('void* kvm_relay_setup(', '\n// Force a KVM reset')
cleanup = between('void kvm_cleanup(void *reserved)', '\n}\n') + '\n}\n'

headers = r'''
#define __STDC_WANT_LIB_EXT1__ 1
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <unistd.h>
#define UNREFERENCED_PARAMETER(x) (void)(x)
'''

secret_main = r'''
static int asRoot;
static int fake_fstat(int fd, struct stat *info) {
    int result = fstat(fd, info);
    if (result == 0 && asRoot && info->st_uid == getuid()) { info->st_uid = 0; }
    return result;
}
#define fstat(fd, info) fake_fstat(fd, info)
''' + reader + r'''
#undef fstat
static char dir[PATH_MAX], file[PATH_MAX];
static void put(const char *data, size_t length, mode_t mode) {
    unlink(file);
    int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, data, length) == (ssize_t)length && fchmod(fd, mode) == 0 && close(fd) == 0);
}
static int check(char *password) { return MacKvm_ReadRelaySecret(dir, password, MAC_KVM_RELAY_SECRET_MAX + 1); }
int main(int argc, char **argv) {
    char password[MAC_KVM_RELAY_SECRET_MAX + 1], other[PATH_MAX];
    assert(argc == 2);
    snprintf(dir, sizeof(dir), "%s", argv[1]);
    snprintf(file, sizeof(file), "%s/%s", dir, MAC_KVM_RELAY_SECRET);
    assert(chmod(dir, 0700) == 0);
    asRoot = 1;

    assert(check(password) == MAC_KVM_SECRET_MISSING && password[0] == 0);
    put("Ab3$ ~x9\n", 9, 0600); assert(check(password) == MAC_KVM_SECRET_OK && !strcmp(password, "Ab3$ ~x9"));
    put("k", 1, 0400); assert(check(password) == MAC_KVM_SECRET_OK && !strcmp(password, "k"));
    const char *invalid[] = { "", "\n", "123456789", "123456789\n", "ab\tc", "ab\r\n", "caf\xc3\xa9", "a\n\n" };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        put(invalid[i], strlen(invalid[i]), 0600);
        memcpy(password, "stale", 6);
        assert(check(password) == MAC_KVM_SECRET_INVALID && password[0] == 0);
    }
    put("ok", 2, 0600); assert(MacKvm_ReadRelaySecret(dir, password, MAC_KVM_RELAY_SECRET_MAX) == MAC_KVM_SECRET_INVALID);

    mode_t unsafeModes[] = { 0640, 0604, 0620, 0602, 0610, 0601 };
    for (size_t i = 0; i < sizeof(unsafeModes) / sizeof(unsafeModes[0]); ++i) {
        put("ok", 2, unsafeModes[i]); assert(check(password) == MAC_KVM_SECRET_UNSAFE);
    }
    put("ok", 2, 0600);
    snprintf(other, sizeof(other), "%s/second-name", dir);
    assert(link(file, other) == 0); assert(check(password) == MAC_KVM_SECRET_UNSAFE);
    assert(unlink(other) == 0); assert(check(password) == MAC_KVM_SECRET_OK);

    assert(unlink(file) == 0);
    snprintf(other, sizeof(other), "%s/target", dir);
    int fd = open(other, O_WRONLY | O_CREAT | O_EXCL, 0600); assert(fd >= 0 && write(fd, "ok", 2) == 2 && close(fd) == 0);
    assert(symlink(other, file) == 0); assert(check(password) == MAC_KVM_SECRET_UNSAFE);
    assert(unlink(file) == 0 && unlink(other) == 0);
    assert(mkfifo(file, 0600) == 0); assert(check(password) == MAC_KVM_SECRET_UNSAFE);	// Must not block
    assert(unlink(file) == 0);
    assert(mkdir(file, 0700) == 0); assert(check(password) == MAC_KVM_SECRET_UNSAFE);
    assert(rmdir(file) == 0);

    put("ok", 2, 0600);
    assert(chmod(dir, 0770) == 0); assert(check(password) == MAC_KVM_SECRET_UNSAFE);
    assert(chmod(dir, 0702) == 0); assert(check(password) == MAC_KVM_SECRET_UNSAFE);
    assert(chmod(dir, 0755) == 0); assert(check(password) == MAC_KVM_SECRET_OK);
    if (getuid() != 0) { asRoot = 0; assert(check(password) == MAC_KVM_SECRET_UNSAFE); asRoot = 1; }
    snprintf(other, sizeof(other), "%s/missing", dir);
    assert(MacKvm_ReadRelaySecret(other, password, sizeof(password)) == MAC_KVM_SECRET_UNSAFE);
    assert(unlink(file) == 0);
    puts("PASS: relay credential content, length, ownership, modes, hard links, symlinks, FIFOs, directories and parent directory");
}
'''

listener_fake = r'''
// Socket info carries no owner, so uid is the holding process's credential.
typedef struct { pid_t pid; int fd; int kind; int state; uint16_t port; uid_t uid; } FakeSocket;
static FakeSocket sockets[16];
static int socketCount, listFails, vanishPid, listPidsCalls, credentialFailPid, savedRootPid = -1;
static int fake_proc_listpids(uint32_t type, uint32_t info, void *buffer, int size) {
    assert(type == PROC_ALL_PIDS && info == 0);
    if (listFails) { return 0; }
    pid_t pids[16]; int count = 0;
    for (int i = 0; i < socketCount; ++i) {
        int seen = 0;
        for (int j = 0; j < count; ++j) { if (pids[j] == sockets[i].pid) { seen = 1; } }
        if (!seen) { pids[count++] = sockets[i].pid; }
    }
    pids[count++] = 0;	// The kernel lists pid 0; it must be skipped
    ++listPidsCalls;
    if (buffer == NULL) { return count * (int)sizeof(pid_t); }
    assert(size >= count * (int)sizeof(pid_t));
    memcpy(buffer, pids, (size_t)count * sizeof(pid_t));
    return count * (int)sizeof(pid_t);
}
static int fake_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int size) {
    assert(pid > 0 && arg == 0);
    if (flavor == PROC_PIDTBSDINFO) {
        assert(size == (int)sizeof(struct proc_bsdinfo));
        if (pid == credentialFailPid) { return 0; }
        for (int i = 0; i < socketCount; ++i) {
            if (sockets[i].pid != pid) { continue; }
            struct proc_bsdinfo *owner = (struct proc_bsdinfo*)buffer;
            memset(owner, 0, sizeof(*owner));
            owner->pbi_uid = owner->pbi_ruid = sockets[i].uid;
            owner->pbi_svuid = pid == savedRootPid ? 501 : sockets[i].uid;
            return size;
        }
        assert(0);
    }
    assert(flavor == PROC_PIDLISTFDS);
    if (pid == vanishPid) { return 0; }
    int count = 0;
    for (int i = 0; i < socketCount; ++i) {
        if (sockets[i].pid != pid) { continue; }
        if (buffer != NULL) {
            assert(size >= (count + 1) * (int)PROC_PIDLISTFD_SIZE);
            struct proc_fdinfo *fds = (struct proc_fdinfo*)buffer;
            fds[count].proc_fd = sockets[i].fd;
            fds[count].proc_fdtype = sockets[i].kind < 0 ? PROX_FDTYPE_VNODE : PROX_FDTYPE_SOCKET;
        }
        ++count;
    }
    return count * (int)PROC_PIDLISTFD_SIZE;
}
static int fake_proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int size) {
    assert(flavor == PROC_PIDFDSOCKETINFO && size == (int)sizeof(struct socket_fdinfo));
    for (int i = 0; i < socketCount; ++i) {
        if (sockets[i].pid != pid || sockets[i].fd != fd) { continue; }
        assert(sockets[i].kind >= 0);	// Non-socket descriptors are never queried
        struct socket_fdinfo *info = (struct socket_fdinfo*)buffer;
        memset(info, 0, sizeof(*info));
        info->psi.soi_kind = sockets[i].kind;
        info->psi.soi_stat.vst_uid = sockets[i].uid;
        info->psi.soi_proto.pri_tcp.tcpsi_state = sockets[i].state;
        info->psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = htons(sockets[i].port);
        return size;
    }
    return 0;
}
#define proc_listpids fake_proc_listpids
#define proc_pidinfo fake_proc_pidinfo
#define proc_pidfdinfo fake_proc_pidfdinfo
''' + listener + r'''
static void add(pid_t pid, int fd, int kind, int state, uint16_t port, uid_t uid) {
    sockets[socketCount++] = (FakeSocket){ pid, fd, kind, state, port, uid };
}
int main(void) {
    assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_NONE);
    add(1, 3, SOCKINFO_TCP, TSI_S_LISTEN, 5900, 0);
    assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_ROOT);
    credentialFailPid = 1; assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_FOREIGN); credentialFailPid = 0;
    savedRootPid = 1; assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_FOREIGN); savedRootPid = -1;
    add(1, 4, SOCKINFO_TCP, TSI_S_LISTEN, 5900, 0);					// launchd's IPv4 and IPv6 sockets
    add(77, 9, SOCKINFO_TCP, TSI_S_LISTEN, 5900, 0);				// The same socket handed to screensharingd
    add(88, 1, -1, 0, 0, 501);										// A vnode descriptor
    add(88, 2, SOCKINFO_TCP, TSI_S_ESTABLISHED, 5900, 501);			// A client, not a listener
    add(88, 3, SOCKINFO_IN, 0, 5900, 501);							// UDP
    add(88, 4, SOCKINFO_TCP, TSI_S_LISTEN, 5901, 501);				// Another port
    for (int i = 5; i < 12; ++i) { add(88, i, SOCKINFO_TCP, TSI_S_CLOSED, 5900, 501); }	// Grows the descriptor buffer
    assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_ROOT);
    assert(MacKvm_RelayListener(5901) == MAC_KVM_LISTENER_FOREIGN);
    add(99, 5, SOCKINFO_TCP, TSI_S_LISTEN, 5900, 501);				// A user listener beside root's
    assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_FOREIGN);
    vanishPid = 99; assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_ROOT);
    socketCount = 0; vanishPid = 0;
    add(99, 5, SOCKINFO_TCP, TSI_S_LISTEN, 5900, 501);				// Screen Sharing off, user holds the port
    assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_FOREIGN);
    listFails = 1; assert(MacKvm_RelayListener(5900) == MAC_KVM_LISTENER_ERROR);
    puts("PASS: listener ownership with root, shared, foreign, vanished, unreadable or partly root credentials, non-listening and enumeration-failure cases");
}
'''

listener_real = listener + r'''
int main(int argc, char **argv) {
    assert(argc == 4);
    uint16_t tcp = (uint16_t)atoi(argv[1]), udp = (uint16_t)atoi(argv[2]), unused = (uint16_t)atoi(argv[3]);
    int expected = getuid() == 0 ? MAC_KVM_LISTENER_ROOT : MAC_KVM_LISTENER_FOREIGN;
    assert(MacKvm_RelayListener(tcp) == expected);
    assert(MacKvm_RelayListener(udp) == MAC_KVM_LISTENER_NONE);
    assert(MacKvm_RelayListener(unused) == MAC_KVM_LISTENER_NONE);
    puts("PASS: real libproc listener ownership for a temporary TCP listener, a UDP socket and an unused port");
}
'''

console_fake = r'''
#include <CoreFoundation/CoreFoundation.h>
static CFPropertyListRef preferenceValue;
static int syncCalls, copyCalls, setCalls, failSync, ignoreWrites;
static void check_domain(CFStringRef domain, CFStringRef user, CFStringRef host) {
    assert(CFEqual(domain, CFSTR("com.apple.RemoteManagement")));
    assert(user == kCFPreferencesAnyUser && host == kCFPreferencesAnyHost);
}
static Boolean fake_sync(CFStringRef domain, CFStringRef user, CFStringRef host) {
    check_domain(domain, user, host); return ++syncCalls != failSync;
}
static CFPropertyListRef fake_copy(CFStringRef key, CFStringRef domain, CFStringRef user, CFStringRef host) {
    check_domain(domain, user, host); assert(CFEqual(key, CFSTR("VNCAlwaysStartOnConsole"))); ++copyCalls;
    return preferenceValue == NULL ? NULL : CFRetain(preferenceValue);
}
static void fake_set(CFStringRef key, CFPropertyListRef value, CFStringRef domain, CFStringRef user, CFStringRef host) {
    check_domain(domain, user, host); assert(CFEqual(key, CFSTR("VNCAlwaysStartOnConsole")) && value == kCFBooleanTrue);
    ++setCalls; if (!ignoreWrites) { preferenceValue = value; }
}
#define CFPreferencesSynchronize fake_sync
#define CFPreferencesCopyValue fake_copy
#define CFPreferencesSetValue fake_set
''' + selector + r'''
static int select_with(CFPropertyListRef value, int failure, int ignore) {
    preferenceValue = value; failSync = failure; ignoreWrites = ignore; syncCalls = copyCalls = setCalls = 0;
    return MacKvm_SelectConsole();
}
int main(void) {
    assert(select_with(NULL, 0, 0) == 0 && syncCalls == 2 && copyCalls == 2 && setCalls == 1 && preferenceValue == kCFBooleanTrue);
    assert(select_with(kCFBooleanFalse, 0, 0) == 0 && setCalls == 1);
    assert(select_with(CFSTR("true"), 0, 0) == 0 && setCalls == 1); // A string is not the server's boolean preference
    assert(select_with(kCFBooleanTrue, 0, 0) == 0 && syncCalls == 1 && copyCalls == 1 && setCalls == 0); // Idempotent
    assert(select_with(NULL, 1, 0) == -1 && copyCalls == 0 && setCalls == 0); // Cannot load system preferences
    assert(select_with(kCFBooleanFalse, 2, 0) == -1 && copyCalls == 1 && setCalls == 1); // Cannot persist selection
    assert(select_with(kCFBooleanFalse, 0, 1) == -1 && copyCalls == 2 && setCalls == 1); // Readback still rejects selection
    puts("PASS: system console-session preference selection, idempotence, type validation, sync failures and readback failure");
}
'''

session_fake = r'''
#include "meshcore/meshdefines.h"
#include "meshcore/KVM/MacOS/mac_vnc_relay.h"
struct vnc_relay { int unused; };
static struct vnc_relay fakeRelay;
static vnc_relay *g_relay = &fakeRelay;
static int g_refresh, g_remotepause, COMPRESSION_RATIO, compressionType, compressionLevel;
static uid_t effectiveId;
static int secretResult, listenerResult, openError, openCalls, listenerCalls, directoryFails;
static int consoleResult, consoleCalls;
static char openedPassword[16];
static uint32_t keys[16]; static int downs[16], keyCount;
static int mouseX, mouseY, mouseButton, mouseCalls; static short mouseWheel;
static uid_t fake_geteuid(void) { return effectiveId; }
#define geteuid fake_geteuid
static int MacKvm_ExecutableDirectory(char *path, size_t capacity) {
    if (directoryFails) { return -1; }
    return strlcpy(path, "/fixture/install", capacity) < capacity ? 0 : -1;
}
int MacKvm_ReadRelaySecret(const char *directory, char *password, size_t capacity) {
    assert(!strcmp(directory, "/fixture/install") && capacity == 9);
    if (secretResult == 0) { strlcpy(password, "s3cret!", capacity); }
    return secretResult;
}
int MacKvm_RelayListener(uint16_t port) { assert(port == 5900); ++listenerCalls; return listenerResult; }
static int MacKvm_SelectConsole(void) {
    assert(effectiveId == 0 && secretResult == 0 && listenerCalls == 1 && listenerResult == MAC_KVM_LISTENER_ROOT && openCalls == 0);
    ++consoleCalls; return consoleResult;
}
vnc_relay* vnc_relay_open(uint16_t port, const char *password, int timeout, vnc_relay_peer_check check, void *context, int *error) {
    assert(port == 5900 && timeout == 5000 && listenerCalls == 1 && consoleCalls > 0 && consoleResult == 0 && check == NULL && context == NULL);
    ++openCalls; strlcpy(openedPassword, password, sizeof(openedPassword)); *error = openError;
    return openError == 0 ? &fakeRelay : NULL;
}
const char* vnc_relay_strerror(int error) { return error == VNC_RELAY_E_AUTH ? "credential rejected" : "other"; }
static int closeCalls;
int vnc_relay_size(vnc_relay *relay, int *width, int *height) { assert(relay == &fakeRelay); *width = 1440; *height = 900; return 0; }
void vnc_relay_close(vnc_relay *relay) { assert(relay == &fakeRelay); ++closeCalls; }
int vnc_relay_key(vnc_relay *relay, uint32_t keysym, int down) {
    assert(relay == &fakeRelay && keyCount < 16); keys[keyCount] = keysym; downs[keyCount++] = down; return 0;
}
int vnc_relay_mouse(vnc_relay *relay, int x, int y, int button, short wheel) {
    assert(relay == &fakeRelay); mouseX = x; mouseY = y; mouseButton = button; mouseWheel = wheel; ++mouseCalls; return 0;
}
uint32_t vnc_relay_vk_to_keysym(unsigned char vk) { return vk == 0x41 ? 'a' : (vk == 0x14 ? 0xFFE5 : 0); }
uint32_t vnc_relay_unicode_to_keysym(uint16_t unicode) { return unicode == 0x1F ? 0 : 0x01000000u | unicode; }
static void set_tile_compression(int type, int level) { compressionType = type; compressionLevel = level; }
''' + opener + checker + dispatch + r'''
typedef void* ILibProcessPipe_Process;
typedef int (*ILibKVM_WriteHandler)(char*, int, void*);
#define ILibProcessPipe_SpawnTypes_DEFAULT 0
static void *gChildProcess, *lastUser;
static void **gChildUser;
static int killCount, resumeCount;
static int spawnCount, spawnFail, freed, ended;
static void *ILibMemory_SmartAllocate(size_t size) { return calloc(1, size); }
static void ILibMemory_Free(void *p) { ++freed; free(p); }
static void kvm_relay_StdOutHandler(void) {}
static void kvm_relay_StdErrHandler(void) {}
static void ILibProcessPipe_Process_UpdateUserObject(void *p, void *u) { assert(p == (void*)1); lastUser = u; }
static void *ILibProcessPipe_Manager_SpawnProcessEx3(void *mgr, char *exe, char **argv, int type, void *uid, int extra) {
    assert(mgr == (void*)9 && type == 0 && uid == NULL && extra == 0); ++spawnCount;
    assert(!strcmp(exe, "/fixture/quoted ' agent") && argv[0] == exe && !strcmp(argv[1], "-kvm0") && argv[2] == NULL);
    return spawnFail ? NULL : (void*)1;
}
static int ILibProcessPipe_Process_GetPID(void *p) { assert(p == (void*)1); return 42; }
static void ILibProcessPipe_Process_ResetMetadata(void *p, char *m) { assert(p == (void*)1 && strstr(m, "pid: 42")); }
static void ILibProcessPipe_Process_AddHandlers(void *p, int size, void *exit, void *out, void *err, void *ok, void *user) {
    (void)exit; (void)out; (void)err; assert(p == (void*)1 && size == 65535 && ok == NULL); lastUser = user;
}
static void *ILibProcessPipe_Process_GetStdOut(void *p) { assert(p == (void*)1); return (void*)2; }
static void ILibProcessPipe_Process_SoftKill(void *p) { assert(p == (void*)1); ++killCount; }
static void ILibProcessPipe_Pipe_Resume(void *p) { assert(p == (void*)2 && killCount > 0); ++resumeCount; }
static int endSession(char *buffer, int length, void *reserved) { assert(buffer == NULL && length == 0 && reserved == (void*)3); ++ended; return 0; }
''' + exit_handler + launcher + cleanup + r'''
static char reason[256];
static vnc_relay *open_with(uid_t euid, int dirFails, int secret, int listenerState, int error) {
    effectiveId = euid; directoryFails = dirFails; secretResult = secret; listenerResult = listenerState; openError = error;
    openCalls = listenerCalls = consoleCalls = 0; reason[0] = 0; openedPassword[0] = 0;
    return MacKvm_OpenRelay(reason, sizeof(reason));
}
static int feed(const unsigned char *packet, size_t length) { return kvm_server_inputdata((char*)packet, (int)length); }
int main(void) {
    assert(open_with(0, 0, MAC_KVM_SECRET_OK, MAC_KVM_LISTENER_ROOT, 0) == &fakeRelay && openCalls == 1 && consoleCalls == 1 && !strcmp(openedPassword, "s3cret!"));
    assert(open_with(501, 0, 0, 1, 0) == NULL && strstr(reason, "root service") && openCalls == 0 && listenerCalls == 0);
    assert(open_with(0, 1, 0, 1, 0) == NULL && strstr(reason, "installation") && openCalls == 0);
    assert(open_with(0, 0, MAC_KVM_SECRET_MISSING, 1, 0) == NULL && strstr(reason, "password dialog") && listenerCalls == 0);
    assert(open_with(0, 0, MAC_KVM_SECRET_UNSAFE, 1, 0) == NULL && strstr(reason, "unsafe ownership") && listenerCalls == 0);
    assert(open_with(0, 0, MAC_KVM_SECRET_INVALID, 1, 0) == NULL && strstr(reason, "credential is invalid") && listenerCalls == 0);
    assert(open_with(0, 0, 0, MAC_KVM_LISTENER_NONE, 0) == NULL && strstr(reason, "turned off") && openCalls == 0);
    assert(open_with(0, 0, 0, MAC_KVM_LISTENER_FOREIGN, 0) == NULL && strstr(reason, "not owned by root") && openCalls == 0);
    assert(open_with(0, 0, 0, MAC_KVM_LISTENER_ERROR, 0) == NULL && strstr(reason, "could not be verified") && openCalls == 0);
    assert(consoleCalls == 0); // Never changes preferences for an unverified listener
    consoleResult = -1;
    assert(open_with(0, 0, 0, MAC_KVM_LISTENER_ROOT, 0) == NULL && strstr(reason, "current console desktop") && consoleCalls == 1 && openCalls == 0);
    consoleResult = 0;
    assert(open_with(0, 0, 0, MAC_KVM_LISTENER_ROOT, VNC_RELAY_E_AUTH) == NULL && !strcmp(reason, "Remote desktop is unavailable: credential rejected."));
    // The readiness check reports the same outcome and disconnects after a successful handshake.
    effectiveId = 0; directoryFails = 0; secretResult = 0; listenerResult = MAC_KVM_LISTENER_ROOT; openError = 0; listenerCalls = openCalls = 0;
    assert(kvm_relay_check() == 0 && closeCalls == 1);
    listenerResult = MAC_KVM_LISTENER_FOREIGN; listenerCalls = 0;
    assert(kvm_relay_check() == 1 && closeCalls == 1);

    const unsigned char keyDown[] = {0, MNG_KVM_KEY, 0, 6, 0, 0x41}, keyUp[] = {0, MNG_KVM_KEY, 0, 6, 1, 0x41};
    const unsigned char extDown[] = {0, MNG_KVM_KEY, 0, 6, 4, 0x14}, extUp[] = {0, MNG_KVM_KEY, 0, 6, 3, 0x14};
    const unsigned char unmapped[] = {0, MNG_KVM_KEY, 0, 6, 0, 0xFF}, shortKey[] = {0, MNG_KVM_KEY, 0, 5, 0};
    assert(feed(keyDown, 6) == 6 && feed(keyUp, 6) == 6 && feed(extDown, 6) == 6 && feed(extUp, 6) == 6);
    assert(feed(unmapped, 6) == 6 && feed(shortKey, 5) == 5);
    assert(keyCount == 4 && keys[0] == 'a' && downs[0] == 1 && keys[1] == 'a' && downs[1] == 0);
    assert(keys[2] == 0xFFE5 && downs[2] == 1 && keys[3] == 0xFFE5 && downs[3] == 0);

    keyCount = 0;
    const unsigned char uniDown[] = {0, MNG_KVM_KEY_UNICODE, 0, 7, 0, 0x26, 0x3A}, uniUp[] = {0, MNG_KVM_KEY_UNICODE, 0, 7, 1, 0x26, 0x3A};
    const unsigned char uniControl[] = {0, MNG_KVM_KEY_UNICODE, 0, 7, 0, 0, 0x1F};
    assert(feed(uniDown, 7) == 7 && feed(uniUp, 7) == 7 && feed(uniControl, 7) == 7);
    assert(keyCount == 2 && keys[0] == 0x0100263Au && downs[0] == 1 && keys[1] == 0x0100263Au && downs[1] == 0);

    const unsigned char move[] = {0, MNG_KVM_MOUSE, 0, 10, 0, 0x02, 0x0A, 0x00, 0x05, 0xA0};
    const unsigned char wheel[] = {0, MNG_KVM_MOUSE, 0, 12, 0, 0x00, 0, 1, 0, 2, 0xFF, 0x88};
    const unsigned char badMouse[] = {0, MNG_KVM_MOUSE, 0, 11, 0, 0, 0, 0, 0, 0, 0};
    assert(feed(move, 10) == 10 && mouseCalls == 1 && mouseX == 2560 && mouseY == 1440 && mouseButton == 2 && mouseWheel == 0);
    assert(feed(wheel, 12) == 12 && mouseCalls == 2 && mouseX == 1 && mouseY == 2 && mouseWheel == -120);
    assert(feed(badMouse, 11) == 11 && mouseCalls == 2);

    const unsigned char refresh[] = {0, MNG_KVM_REFRESH, 0, 4}, pause[] = {0, MNG_KVM_PAUSE, 0, 5, 1};
    const unsigned char compression[] = {0, MNG_KVM_COMPRESSION, 0, 6, 1, 70};
    assert(feed(refresh, 4) == 4 && g_refresh == 1);
    assert(feed(pause, 5) == 5 && g_remotepause == 1);
    assert(feed(compression, 6) == 6 && compressionType == 1 && compressionLevel == 70 && COMPRESSION_RATIO == 100);
    const unsigned char partial[] = {0, MNG_KVM_KEY, 0, 6, 0}, broken[] = {0, MNG_KVM_KEY, 0, 3};
    assert(feed(partial, 5) == 0 && feed(broken, 4) == -1 && feed(partial, 3) == 0);

    assert(kvm_relay_setup("relative", (void*)9, endSession, (void*)3) == NULL);
    assert(kvm_relay_setup(NULL, (void*)9, endSession, (void*)3) == NULL);
    assert(kvm_relay_setup("/fixture/quoted ' agent", NULL, endSession, (void*)3) == NULL);
    assert(kvm_relay_setup("/fixture/quoted ' agent", (void*)9, NULL, (void*)3) == NULL && spawnCount == 0);
    spawnFail = 1; assert(kvm_relay_setup("/fixture/quoted ' agent", (void*)9, endSession, (void*)3) == NULL && freed == 1);
    spawnFail = 0; assert(kvm_relay_setup("/fixture/quoted ' agent", (void*)9, endSession, (void*)3) == (void*)2 && gChildProcess == (void*)1);
    void *user = lastUser; kvm_relay_ExitHandler((void*)1, 1, user);
    assert(ended == 1 && lastUser == NULL && gChildProcess == NULL && freed == 2);
    kvm_relay_ExitHandler((void*)1, 1, NULL); assert(ended == 1 && freed == 2);
    assert(kvm_relay_setup("/fixture/quoted ' agent", (void*)9, endSession, (void*)3) == (void*)2);
    gChildProcess = NULL; kvm_relay_ExitHandler((void*)1, 1, lastUser); assert(ended == 1 && lastUser == NULL);	// Owner already closed
    // Cleanup acts only for the session it serves, and detaches it before killing the helper.
    assert(kvm_relay_setup("/fixture/quoted ' agent", (void*)9, endSession, (void*)3) == (void*)2);
    void **attached = (void**)lastUser;
    kvm_cleanup((void*)4); assert(killCount == 0 && gChildProcess == (void*)1);	// A stale or other session
    kvm_cleanup((void*)3); assert(killCount == 1 && resumeCount == 1 && gChildProcess == NULL && gChildUser == NULL);
    assert(attached[0] == NULL && attached[1] == NULL);
    kvm_cleanup((void*)3); assert(killCount == 1);	// A repeated end() does nothing
    kvm_relay_ExitHandler((void*)1, 0, attached); assert(ended == 1);	// Detached: the ended session is not called back
    kvm_cleanup(NULL); assert(killCount == 1);
    puts("PASS: relay setup order, failure reasons and readiness check, key/unicode/mouse/control dispatch, framing errors, root helper launch and exit cleanup");
}
'''


def build_and_run(folder, name, text, *arguments, libraries=()):
    (folder / (name + '.c')).write_text(text)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', '-I', str(root), str(folder / (name + '.c')), *libraries, '-o', str(folder / name)], check=True)
    subprocess.run([str(folder / name), *arguments], check=True, timeout=30)


with tempfile.TemporaryDirectory(prefix='mesh-kvm-session-') as directory:
    folder = Path(directory)
    secrets = folder / 'install'
    secrets.mkdir()
    build_and_run(folder, 'secret', headers + constants + secret_main, str(secrets))
    build_and_run(folder, 'listener', headers + constants + listener_fake)
    build_and_run(folder, 'console', headers + console_fake, libraries=('-framework', 'CoreFoundation'))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        tcp.listen(1)
        udp.bind(('127.0.0.1', 0))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', 0))
            unused = probe.getsockname()[1]
        build_and_run(folder, 'listener_real', headers + constants + listener_real,
                      str(tcp.getsockname()[1]), str(udp.getsockname()[1]), str(unused))
    build_and_run(folder, 'session', headers + constants + session_fake)

if args.agent:
    agent = str(args.agent.resolve())
    result = subprocess.run([agent, '-kvm0'], stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    if os.geteuid() != 0:
        message = b'Remote desktop requires the agent to run as the root service.'
        assert result.returncode == 1 and result.stdout == bytes([0, 17, 0, len(message) + 4]) + message, result
    result = subprocess.run([agent, '-kvm0', '--session-uid', '501'], stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    assert result.returncode == 1 and not result.stdout and b'Usage: -kvm0' in result.stderr, result
    result = subprocess.run([agent, '-kvmcheck'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    if os.geteuid() != 0:
        assert result.returncode == 1 and result.stdout == 'NOT READY: ' + message.decode() + '\n', result
    result = subprocess.run([agent, '-kvmcheck', 'extra'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 1 and not result.stdout and 'Usage: -kvmcheck' in result.stderr, result
    # The stock package's KeepAlive LaunchAgent starts -kvmagent: it must idle, not run an agent.
    idle = subprocess.Popen([agent, '-kvmagent'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            idle.wait(timeout=2)
            raise AssertionError('-kvmagent exited: %r' % (idle.returncode,))
        except subprocess.TimeoutExpired:
            pass
        children = subprocess.run(['/usr/bin/pgrep', '-P', str(idle.pid)], capture_output=True, text=True)
        assert children.returncode == 1 and not children.stdout, children
    finally:
        idle.terminate()
    out, err = idle.communicate(timeout=10)
    assert idle.returncode == -15 and not out and not err, (idle.returncode, out, err)
    result = subprocess.run([agent, '-kvm1'], stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    assert result.returncode == 0 and not result.stdout, result
    print('PASS: built -kvm0 and -kvmcheck report the root requirement and reject extra arguments; -kvmagent idles until stopped; legacy -kvm1 exits cleanly')
