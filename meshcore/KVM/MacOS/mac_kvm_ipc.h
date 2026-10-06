#ifndef MESH_MAC_KVM_IPC_H
#define MESH_MAC_KVM_IPC_H
#include <stddef.h>
#include <stdatomic.h>

int MacKvm_IpcPath(const char *executable, char *path, size_t capacity);
int MacKvm_IpcListen(const char *path, int *lockFd);
int MacKvm_IpcAccept(int listener, const atomic_int *stopping);
void MacKvm_IpcClose(int listener, int lockFd, const char *path);
#endif
