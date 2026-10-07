#!/usr/bin/env python3
"""Exercise first-start credential storage with real files and pipes, fake RFB.

No Screen Sharing connection, preference change, credential or root access.
Production C runs under ASan/UBSan with the fixture owner reported as root.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path)
args = parser.parse_args()
if sys.platform != 'darwin':
    parser.error('Requires macOS')
root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/KVM/MacOS/mac_kvm.c').read_text()


def between(start, end):
    first = source.index(start)
    return source[first:source.index(end, first)]


constants = between('#define MAC_KVM_RELAY_SECRET\t', '\nint KVM_SEND(')
reader = between('int MacKvm_ReadRelaySecret(', '\n// screensharingd is socket-activated')
onboarding = between('int kvm_relay_credential_status(', '\n// Adopts the relay')
fixture = r'''
#define __STDC_WANT_LIB_EXT1__ 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
''' + constants + r'''
#define VNC_RELAY_OK 0
#define VNC_RELAY_DEFAULT_PORT 5900
typedef int vnc_relay;
static vnc_relay relay;
static char directory[PATH_MAX], file[PATH_MAX];
static int rootOwner = 1, effectiveRoot = 1, badDirectory, listener = MAC_KVM_LISTENER_ROOT;
static int consoleFails, authFails, syncFails, openCalls, closeCalls, consoleCalls;
static int fake_fstat(int fd, struct stat *info) {
    int result = fstat(fd, info);
    if (result == 0) { info->st_uid = rootOwner ? 0 : 501; }
    return result;
}
static int fake_fsync(int fd) { if (syncFails) { errno = EIO; return -1; } return fsync(fd); }
#define fstat fake_fstat
#define fsync fake_fsync
#define geteuid() (effectiveRoot ? 0 : 501)
static int MacKvm_ExecutableDirectory(char *path, size_t capacity) {
    if (badDirectory) { return -1; }
    snprintf(path, capacity, "%s", directory); return 0;
}
static int MacKvm_RelayListener(uint16_t port) { assert(port == 5900); return listener; }
static int MacKvm_SelectConsole(void) { ++consoleCalls; return consoleFails ? -1 : 0; }
static vnc_relay* vnc_relay_open(uint16_t port, const char *password, int timeout, void *check, void *context, int *error) {
    assert(port == 5900 && timeout == 5000 && !check && !context);
    assert(!strcmp(password, "Ab3$ ~x9")); ++openCalls; *error = authFails ? -1 : 0;
    return authFails ? NULL : &relay;
}
static void vnc_relay_close(vnc_relay *p) { assert(p == &relay); ++closeCalls; }
''' + reader + onboarding + r'''
static int provision(const char *value) {
    int fds[2], saved = dup(STDIN_FILENO); assert(saved >= 0 && pipe(fds) == 0);
    assert(write(fds[1], value, strlen(value)) == (ssize_t)strlen(value)); close(fds[1]);
    assert(dup2(fds[0], STDIN_FILENO) == 0); close(fds[0]);
    int result = kvm_relay_provision();
    assert(dup2(saved, STDIN_FILENO) == 0); close(saved); return result;
}
int main(int argc, char **argv) {
    char password[9], other[PATH_MAX]; struct stat info;
    assert(argc == 2); snprintf(directory, sizeof(directory), "%s", argv[1]);
    snprintf(file, sizeof(file), "%s/vncrelay.secret", directory);
    assert(chmod(directory, 0700) == 0);
    assert(kvm_relay_credential_status() == 1);
    effectiveRoot = 0; assert(kvm_relay_credential_status() == 2 && provision("Ab3$ ~x9") == 1 && openCalls == 0); effectiveRoot = 1;
    badDirectory = 1; assert(kvm_relay_credential_status() == 2); badDirectory = 0;
    rootOwner = 0; assert(kvm_relay_credential_status() == 2 && provision("Ab3$ ~x9") == 1); rootOwner = 1;
    assert(chmod(directory, 0770) == 0 && kvm_relay_credential_status() == 2);
    assert(MacKvm_StoreRelaySecret(directory, "Ab3$ ~x9", 8) == -1); assert(chmod(directory, 0700) == 0);
    const char *invalid[] = {"", "123456789", "ab\n", "ab\t", "caf\xc3\xa9"};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
        assert(provision(invalid[i]) == 1 && openCalls == 0 && access(file, F_OK) != 0);
        assert(MacKvm_StoreRelaySecret(directory, invalid[i], strlen(invalid[i])) == -1);
    }
    listener = MAC_KVM_LISTENER_FOREIGN;
    assert(provision("Ab3$ ~x9") == 1 && consoleCalls == 0 && openCalls == 0);
    listener = MAC_KVM_LISTENER_NONE; assert(provision("Ab3$ ~x9") == 1 && openCalls == 0);
    listener = MAC_KVM_LISTENER_ERROR; assert(provision("Ab3$ ~x9") == 1 && openCalls == 0);
    listener = MAC_KVM_LISTENER_ROOT; consoleFails = 1;
    assert(provision("Ab3$ ~x9") == 1 && consoleCalls == 1 && openCalls == 0); consoleFails = 0;
    authFails = 1; assert(provision("Ab3$ ~x9") == 1 && access(file, F_OK) != 0 && closeCalls == 0); authFails = 0;
    syncFails = 1; assert(provision("Ab3$ ~x9") == 1 && access(file, F_OK) != 0 && closeCalls == 1); syncFails = 0;
    // umask cannot remove the required read bit; persisted file is exactly 0600.
    mode_t old = umask(0777); assert(provision("Ab3$ ~x9") == 0); umask(old);
    assert(stat(file, &info) == 0 && (info.st_mode & 0777) == 0600 && info.st_nlink == 1 && info.st_size == 8);
    assert(kvm_relay_credential_status() == 0 && MacKvm_ReadRelaySecret(directory, password, sizeof(password)) == 0 && !strcmp(password, "Ab3$ ~x9"));
    int previous = openCalls;
    assert(provision("different") == 0 && openCalls == previous); // Reuses incumbent without reauth or write
    assert(MacKvm_StoreRelaySecret(directory, "new", 3) == -1);
    assert(MacKvm_ReadRelaySecret(directory, password, sizeof(password)) == 0 && !strcmp(password, "Ab3$ ~x9"));
    assert(chmod(file, 0644) == 0 && kvm_relay_credential_status() == 2 && provision("Ab3$ ~x9") == 1);
    assert(unlink(file) == 0);
    snprintf(other, sizeof(other), "%s/target", directory);
    int fd = open(other, O_WRONLY|O_CREAT|O_EXCL, 0600); assert(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0);
    assert(symlink(other, file) == 0 && kvm_relay_credential_status() == 2 && provision("Ab3$ ~x9") == 1);
    assert(MacKvm_StoreRelaySecret(directory, "new", 3) == -1 && stat(other, &info) == 0 && info.st_size == 4);
    assert(unlink(file) == 0 && unlink(other) == 0);
    puts("PASS: first-start native provisioning, private stdin, root checks, validation before save, exclusive 0600 storage, reuse, symlink rejection and failed-write cleanup");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-kvm-provision-') as name:
    folder = Path(name)
    (folder / 'install').mkdir()
    (folder / 'probe.c').write_text(fixture)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(folder / 'probe.c'), '-o', str(folder / 'probe')], check=True)
    subprocess.run([str(folder / 'probe'), str(folder / 'install')], check=True, timeout=30)

if args.agent and os.geteuid() != 0:
    for switch, expected in [('-kvmcredentialstatus', 2), ('-kvmprovision', 1)]:
        for extra in [[], ['extra']]:
            result = subprocess.run([str(args.agent.resolve()), switch, *extra], input=b'fixture!', capture_output=True, timeout=10)
            assert result.returncode == expected and not result.stdout and b'fixture!' not in result.stderr, result
    print('PASS: built provisioning entry points reject non-root and extra arguments without exposing stdin')
