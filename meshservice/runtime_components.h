#ifndef MESH_RUNTIME_COMPONENTS_H
#define MESH_RUNTIME_COMPONENTS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_RUNTIME_COMPONENT_STATUS_VERSION 1u
#define MESH_RUNTIME_COMPONENT_SHA256_SIZE 32u

typedef enum MeshRuntimeComponentState
{
    MESH_RUNTIME_COMPONENTS_UNAVAILABLE = 0,
    MESH_RUNTIME_COMPONENTS_VALIDATED = 1
} MeshRuntimeComponentState;

typedef struct MeshRuntimeComponentStatus
{
    DWORD size;
    DWORD version;
    DWORD state;
    DWORD lastError;
    DWORD x86Machine;
    DWORD x86Size;
    DWORD x64Machine;
    DWORD x64Size;
    BYTE x86Sha256[MESH_RUNTIME_COMPONENT_SHA256_SIZE];
    BYTE x64Sha256[MESH_RUNTIME_COMPONENT_SHA256_SIZE];
} MeshRuntimeComponentStatus;

BOOL MeshRuntimeComponents_Initialize(void);
BOOL MeshRuntimeComponents_GetStatus(MeshRuntimeComponentStatus* status);
BOOL MeshRuntimeComponents_InstallControllers(
    wchar_t* x86Path,
    size_t x86PathCount,
    wchar_t* x64Path,
    size_t x64PathCount);

#ifdef __cplusplus
}
#endif

#endif
