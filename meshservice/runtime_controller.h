#ifndef MESH_RUNTIME_CONTROLLER_H
#define MESH_RUNTIME_CONTROLLER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_RUNTIME_PROTOCOL_VERSION 1u
#define MESH_RUNTIME_REQUEST_ID_CHARS 37u

typedef enum MeshRuntimeOperation
{
    MESH_RUNTIME_STATUS = 1,
    MESH_RUNTIME_LOAD = 2,
    MESH_RUNTIME_UNLOAD = 3
} MeshRuntimeOperation;

int MeshRuntimeRelay_IsUuid(const char* value);
int MeshRuntimeRelay_Operation(const char* value, uint32_t* command);

#ifdef __cplusplus
}
#endif
#endif
