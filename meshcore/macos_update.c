#include "macos_update.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
typedef struct MeshMacUpdateRecord
{
    uint32_t magic, version, state, reserved;
    uint64_t oldDevice, oldInode, newDevice, newInode;
} MeshMacUpdateRecord;
#define MESH_MAC_UPDATE_MAGIC 0x4d555031u

static int paths(const char* executable, char* backup, char* journal)
{
    if (executable == NULL || executable[0] != '/') { errno = EINVAL; return -1; }
    if (snprintf(backup, PATH_MAX, "%s.update-backup", executable) >= PATH_MAX ||
        snprintf(journal, PATH_MAX, "%s.update-state", executable) >= PATH_MAX)
    { errno = ENAMETOOLONG; return -1; }
    return 0;
}
static int syncDirectory(const char* executable)
{
    char directory[PATH_MAX];
    int fd, result, error;
    if (strlen(executable) >= sizeof(directory)) { errno = ENAMETOOLONG; return -1; }
    strcpy(directory, executable);
    char* slash = strrchr(directory, '/');
    if (slash == NULL) { errno = EINVAL; return -1; }
    slash[slash == directory ? 1 : 0] = 0;
    fd = open(directory, O_RDONLY | O_DIRECTORY);
    if (fd < 0) { return -1; }
    result = fsync(fd); error = errno;
    if (close(fd) != 0 && result == 0) { return -1; }
    errno = error; return result;
}
static int sameFile(const struct stat* value, uint64_t device, uint64_t inode)
{
    return S_ISREG(value->st_mode) && (uint64_t)value->st_dev == device && (uint64_t)value->st_ino == inode;
}
// The persistent lock file is never unlinked: removing it could let two
// processes lock different inodes for the same installed executable.
static int lockUpdate(const char* executable)
{
    char path[PATH_MAX];
    struct stat info;
    if (snprintf(path, sizeof(path), "%s.update-lock", executable) >= sizeof(path))
    { errno = ENAMETOOLONG; return -1; }
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { return -1; }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || flock(fd, LOCK_EX | LOCK_NB) != 0)
    { int error = errno ? errno : EINVAL; close(fd); errno = error; return -1; }
    return fd;
}
// Publish whole records atomically. A crash during write must not leave a
// partial journal that prevents the incumbent from starting on the next boot.
static int recordState(const char* path, MeshMacUpdateRecord* record, uint32_t state)
{
    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", path) >= sizeof(temporary))
    { errno = ENAMETOOLONG; return -1; }
    int fd = mkstemp(temporary), error = 0;
    if (fd < 0) { return -1; }
    record->state = state;
    if (write(fd, record, sizeof(*record)) != sizeof(*record)) { error = errno ? errno : EIO; }
    if (!error && fsync(fd) != 0) { error = errno; }
    if (close(fd) != 0 && !error) { error = errno; }
    if (!error && rename(temporary, path) != 0) { error = errno; }
    if (!error && syncDirectory(path) != 0) { error = errno; }
    if (error) { unlink(temporary); errno = error; return -1; }
    return 0;
}
static int readRecord(const char* file, MeshMacUpdateRecord* record)
{
    int fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC), error = 0;
    struct stat info;
    if (fd < 0) { return -1; }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size != sizeof(*record) ||
        read(fd, record, sizeof(*record)) != sizeof(*record) ||
        record->magic != MESH_MAC_UPDATE_MAGIC || record->version != 1 || record->state > 2)
    { error = EINVAL; }
    close(fd);
    if (error) { errno = error; return -1; }
    return 0;
}
static int retire(const char* executable, const char* backup, const char* journal, const MeshMacUpdateRecord* record)
{
    struct stat saved;
    if (lstat(backup, &saved) == 0)
    {
        // Only remove our recorded incumbent, never an unrelated file/symlink.
        if (!sameFile(&saved, record->oldDevice, record->oldInode)) { errno = ESTALE; return -1; }
        if (unlink(backup) != 0) { return -1; }
    }
    else if (errno != ENOENT) { return -1; }
    if (unlink(journal) != 0 && errno != ENOENT) { return -1; }
    return syncDirectory(executable);
}

int MeshMacUpdate_Preflight(const char* executable, const char* staged)
{
    struct stat original, candidate;
    int fd, descriptors[2], status = 0, error = 0;
    pid_t child, waited = 0;
    posix_spawn_file_actions_t actions;
    char output[16] = {0};
    char* args[] = {(char*)staged, "-updaterversion", NULL};
    if (executable == NULL || staged == NULL || executable[0] != '/' || staged[0] != '/')
    { errno = EINVAL; return -1; }
    if (lstat(executable, &original) != 0 || !S_ISREG(original.st_mode)) { errno = EINVAL; return -1; }
    fd = open(staged, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { return -1; }
    if (fstat(fd, &candidate) != 0 || !S_ISREG(candidate.st_mode) || candidate.st_size == 0 ||
        (original.st_dev == candidate.st_dev && original.st_ino == candidate.st_ino))
    { close(fd); errno = EINVAL; return -1; }
    if ((candidate.st_uid != original.st_uid || candidate.st_gid != original.st_gid) &&
        fchown(fd, original.st_uid, original.st_gid) != 0)
    { error = errno; close(fd); errno = error; return -1; }
    if (fchmod(fd, original.st_mode & 0777) != 0) { error = errno; close(fd); errno = error; return -1; }
    if (close(fd) != 0 || pipe(descriptors) != 0) { return -1; }
    // Keep pipe fds away from stdio even when launchd supplies closed descriptors.
    for (int i = 0; i < 2; ++i)
    {
        if (descriptors[i] <= STDERR_FILENO)
        {
            int replacement = fcntl(descriptors[i], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
            if (replacement < 0)
            { error = errno; close(descriptors[0]); close(descriptors[1]); errno = error; return -1; }
            close(descriptors[i]); descriptors[i] = replacement;
        }
        else if (fcntl(descriptors[i], F_SETFD, FD_CLOEXEC) != 0)
        { error = errno; close(descriptors[0]); close(descriptors[1]); errno = error; return -1; }
    }
    error = posix_spawn_file_actions_init(&actions);
    if (error == 0)
    {
        if ((error = posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO)) == 0 &&
            (error = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)) == 0 &&
            (error = posix_spawn_file_actions_addclose(&actions, descriptors[0])) == 0 &&
            (error = posix_spawn_file_actions_addclose(&actions, descriptors[1])) == 0)
        { error = posix_spawn(&child, staged, &actions, NULL, args, environ); }
        posix_spawn_file_actions_destroy(&actions);
    }
    close(descriptors[1]);
    if (error == 0)
    {
        for (int attempt = 0; attempt < 200; ++attempt)
        {
            waited = waitpid(child, &status, WNOHANG);
            if (waited == child || (waited < 0 && errno != EINTR)) { break; }
            usleep(50000);
        }
        if (waited != child)
        {
            error = waited == 0 || errno == EINTR ? ETIMEDOUT : errno;
            if (waited == 0 || errno == EINTR)
            {
                kill(child, SIGKILL);
                while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            }
        }
        else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { error = ENOEXEC; }
        if (error == 0)
        {
            if (fcntl(descriptors[0], F_SETFL, O_NONBLOCK) < 0) { error = errno; }
            else
            {
                ssize_t length = read(descriptors[0], output, sizeof(output));
                if (!((length == 2 && memcmp(output, "1\n", 2) == 0) ||
                      (length == 3 && memcmp(output, "1\r\n", 3) == 0))) { error = ENOEXEC; }
            }
        }
    }
    close(descriptors[0]);
    errno = error; return error ? -1 : 0;
}

int MeshMacUpdate_Apply(const char* executable, const char* staged)
{
    char backup[PATH_MAX], journal[PATH_MAX];
    struct stat oldInfo, newInfo, opened, existing;
    MeshMacUpdateRecord record = {MESH_MAC_UPDATE_MAGIC, 1, 0, 0, 0, 0, 0, 0};
    int lock, fd, result = -1, error;
    if (paths(executable, backup, journal) != 0 || staged == NULL) { errno = EINVAL; return -1; }
    lock = lockUpdate(executable);
    if (lock < 0) { return -1; }
    if (lstat(journal, &existing) == 0 || errno != ENOENT) { errno = EEXIST; goto done; }
    if (lstat(backup, &existing) == 0 || errno != ENOENT) { errno = EEXIST; goto done; }
    if (lstat(executable, &oldInfo) != 0 || lstat(staged, &newInfo) != 0) { goto done; }
    if (!S_ISREG(oldInfo.st_mode) || !S_ISREG(newInfo.st_mode) || newInfo.st_size == 0 ||
        oldInfo.st_dev != newInfo.st_dev || oldInfo.st_ino == newInfo.st_ino)
    { errno = EINVAL; goto done; }
    fd = open(staged, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { goto done; }
    error = 0;
    if (fstat(fd, &opened) != 0 || !sameFile(&opened, newInfo.st_dev, newInfo.st_ino)) { error = ESTALE; }
    if (!error && (opened.st_uid != oldInfo.st_uid || opened.st_gid != oldInfo.st_gid) &&
        fchown(fd, oldInfo.st_uid, oldInfo.st_gid) != 0) { error = errno; }
    if (!error && fchmod(fd, oldInfo.st_mode & 0777) != 0) { error = errno; }
    if (!error && fsync(fd) != 0) { error = errno; }
    if (close(fd) != 0 && !error) { error = errno; }
    if (error) { errno = error; goto done; }
    record.oldDevice = oldInfo.st_dev; record.oldInode = oldInfo.st_ino;
    record.newDevice = newInfo.st_dev; record.newInode = newInfo.st_ino;
    if (recordState(journal, &record, 0) != 0) { goto done; }
    if (link(executable, backup) != 0) { goto done; }
    if (lstat(backup, &existing) != 0 || !sameFile(&existing, record.oldDevice, record.oldInode) ||
        lstat(staged, &existing) != 0 || !sameFile(&existing, record.newDevice, record.newInode))
    { errno = ESTALE; goto done; }
    if (syncDirectory(executable) != 0 || rename(staged, executable) != 0) { goto done; }
    result = syncDirectory(executable);
done:
    // On any failure keep the journal. Recover decides from the actual inode
    // whether to discard preparation or restore the saved executable.
    error = errno; close(lock); errno = error; return result;
}

int MeshMacUpdate_Recover(const char* executable, int forceRollback)
{
    char backup[PATH_MAX], journal[PATH_MAX];
    MeshMacUpdateRecord record;
    struct stat current, saved;
    int lock, result = -1, error;
    if (paths(executable, backup, journal) != 0) { return -1; }
    // Do not create a lock on normal startup when no transaction exists.
    if (lstat(journal, &current) != 0) { return errno == ENOENT ? 0 : -1; }
    lock = lockUpdate(executable);
    if (lock < 0) { return -1; }
    if (readRecord(journal, &record) != 0) { if (errno == ENOENT) { result = 0; } goto done; }
    if (lstat(executable, &current) != 0) { goto done; }
    if (record.state == 2)
    {
        if (!sameFile(&current, record.newDevice, record.newInode)) { errno = ESTALE; goto done; }
        result = retire(executable, backup, journal, &record); goto done;
    }
    if (sameFile(&current, record.oldDevice, record.oldInode))
    { result = retire(executable, backup, journal, &record); goto done; }
    if (!sameFile(&current, record.newDevice, record.newInode) || lstat(backup, &saved) != 0 ||
        !sameFile(&saved, record.oldDevice, record.oldInode)) { errno = ESTALE; goto done; }
    if (record.state == 0 && !forceRollback)
    { result = recordState(journal, &record, 1) == 0 ? 2 : -1; goto done; }
    if (rename(backup, executable) != 0 || syncDirectory(executable) != 0) { goto done; }
    if (unlink(journal) != 0 || syncDirectory(executable) != 0) { goto done; }
    result = 1;
done:
    error = errno; close(lock); errno = error; return result;
}

int MeshMacUpdate_Commit(const char* executable)
{
    char backup[PATH_MAX], journal[PATH_MAX];
    MeshMacUpdateRecord record;
    struct stat current, saved;
    int lock, result = -1, error;
    if (paths(executable, backup, journal) != 0) { return -1; }
    if (lstat(journal, &current) != 0) { return errno == ENOENT ? 0 : -1; }
    lock = lockUpdate(executable);
    if (lock < 0) { return -1; }
    if (readRecord(journal, &record) != 0) { if (errno == ENOENT) { result = 0; } goto done; }
    if (lstat(executable, &current) != 0 || !sameFile(&current, record.newDevice, record.newInode))
    { errno = ESTALE; goto done; }
    if (record.state != 2 && (lstat(backup, &saved) != 0 || !sameFile(&saved, record.oldDevice, record.oldInode)))
    { errno = ESTALE; goto done; }
    if (recordState(journal, &record, 2) == 0) { result = retire(executable, backup, journal, &record); }
done:
    error = errno; close(lock); errno = error; return result;
}
