#include "mac_kvm_ipc.h"
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/dyld.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef MESH_KVM_IPC_ROOT
#define MESH_KVM_IPC_ROOT "/var/run/meshagent"
#endif

int MacKvm_IpcPath(const char *executable, char *path, size_t capacity)
{
    char image[PATH_MAX], canonical[PATH_MAX];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    char hex[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    uint32_t size = sizeof(image);
    if (geteuid() != 0 || path == NULL) { errno = EACCES; return -1; }
    if (executable == NULL)
    {
        if (_NSGetExecutablePath(image, &size) != 0) { errno = ENAMETOOLONG; return -1; }
        executable = image;
    }
    if (realpath(executable, canonical) == NULL) { return -1; }
    if (CC_SHA256(canonical, (CC_LONG)strlen(canonical), digest) == NULL) { errno = EIO; return -1; }
    for (size_t i = 0; i < sizeof(digest); ++i) { snprintf(hex + i * 2, 3, "%02x", digest[i]); }
    int count = snprintf(path, capacity, "%s/kvm-%s", MESH_KVM_IPC_ROOT, hex);
    if (count < 0 || (size_t)count >= capacity || (size_t)count >= sizeof(((struct sockaddr_un*)0)->sun_path))
    { errno = ENAMETOOLONG; return -1; }
    return 0;
}

static int MacKvm_IpcPrivateDirectory(void)
{
    struct stat info;
    if (geteuid() != 0) { errno = EACCES; return -1; }
    if (mkdir(MESH_KVM_IPC_ROOT, 0700) != 0 && errno != EEXIST) { return -1; }
    if (lstat(MESH_KVM_IPC_ROOT, &info) != 0) { return -1; }
    if (!S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0077) != 0)
    { errno = EACCES; return -1; }
    return 0;
}

int MacKvm_IpcListen(const char *path, int *lockFd)
{
    struct sockaddr_un address;
    struct stat info;
    int lock = -1, listener = -1, bound = 0, error;
    char lockPath[PATH_MAX];
    *lockFd = -1;
    if (MacKvm_IpcPrivateDirectory() != 0) { return -1; }
    if (path == NULL || strncmp(path, MESH_KVM_IPC_ROOT "/kvm-", strlen(MESH_KVM_IPC_ROOT "/kvm-")) != 0 ||
        strlen(path) >= sizeof(address.sun_path) || strchr(path + strlen(MESH_KVM_IPC_ROOT) + 1, '/') != NULL)
    { errno = EINVAL; return -1; }
    if (snprintf(lockPath, sizeof(lockPath), "%s.lock", path) >= (int)sizeof(lockPath)) { errno = ENAMETOOLONG; return -1; }
    lock = open(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0) { return -1; }
    if (fstat(lock, &info) != 0) { goto fail; }
    if (!S_ISREG(info.st_mode) || info.st_uid != 0 || info.st_nlink != 1 || (info.st_mode & 0077) != 0)
    { errno = EACCES; goto fail; }
    // An active helper owns this lock. Never unlink its live socket.
    if (flock(lock, LOCK_EX | LOCK_NB) != 0) { goto fail; }
    if (lstat(path, &info) == 0)
    {
        if (!S_ISSOCK(info.st_mode) || info.st_uid != 0) { errno = EEXIST; goto fail; }
        if (unlink(path) != 0) { goto fail; }
    }
    else if (errno != ENOENT) { goto fail; }
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || fcntl(listener, F_SETFD, FD_CLOEXEC) != 0) { goto fail; }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (bind(listener, (struct sockaddr*)&address, SUN_LEN(&address)) != 0) { goto fail; }
    bound = 1;
    if (chmod(path, 0600) != 0 || listen(listener, 4) != 0) { goto fail; }
    *lockFd = lock;
    return listener;
fail:
    error = errno;
    if (listener >= 0) { close(listener); }
    if (bound) { unlink(path); }
    if (lock >= 0) { close(lock); }
    errno = error;
    return -1;
}

int MacKvm_IpcAccept(int listener, const atomic_int *stopping)
{
    struct pollfd wait = { listener, POLLIN, 0 };
    while (!atomic_load(stopping))
    {
        int ready = poll(&wait, 1, 100);
        if (ready < 0 && errno == EINTR) { continue; }
        if (ready < 0) { return -1; }
        if (ready == 0) { continue; }
        if (!(wait.revents & POLLIN)) { errno = EIO; return -1; }
        int client = accept(listener, NULL, NULL);
        if (client < 0 && errno == EINTR) { continue; }
        if (client < 0) { return -1; }
        uid_t uid;
        gid_t gid;
        if (getpeereid(client, &uid, &gid) == 0 && uid == 0 && fcntl(client, F_SETFD, FD_CLOEXEC) == 0) { return client; }
        close(client);
    }
    errno = ECANCELED;
    return -1;
}

void MacKvm_IpcClose(int listener, int lockFd, const char *path)
{
    if (listener >= 0) { close(listener); }
    if (lockFd >= 0)
    {
        struct stat info;
        if (path != NULL && lstat(path, &info) == 0 && S_ISSOCK(info.st_mode) && info.st_uid == 0) { unlink(path); }
        close(lockFd);
    }
}
