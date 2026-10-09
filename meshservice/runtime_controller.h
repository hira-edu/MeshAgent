#ifndef MESH_RUNTIME_CONTROLLER_H
#define MESH_RUNTIME_CONTROLLER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_RUNTIME_PROTOCOL_VERSION 1u
#define MESH_RUNTIME_REQUEST_ID_CHARS 37u
#define MESH_RUNTIME_PIPE_MAGIC 0x3143524eu
#define MESH_RUNTIME_PIPE_REQUEST_SIZE 32u
#define MESH_RUNTIME_PIPE_RESPONSE_SIZE 64u

typedef enum MeshRuntimeOperation
{
    MESH_RUNTIME_STATUS = 1,
    MESH_RUNTIME_LOAD = 2,
    MESH_RUNTIME_UNLOAD = 3
} MeshRuntimeOperation;

typedef enum MeshRuntimeControllerResult
{
    MESH_RUNTIME_ACCEPTED = 0,
    MESH_RUNTIME_INVALID_MESSAGE = 1,
    MESH_RUNTIME_UNSUPPORTED_VERSION = 2,
    MESH_RUNTIME_UNSUPPORTED_COMMAND = 3,
    MESH_RUNTIME_PERSISTENCE_FAILED = 4
} MeshRuntimeControllerResult;

typedef struct MeshRuntimePipeRequest
{
    uint32_t magic;
    uint32_t size;
    uint32_t version;
    uint32_t command;
    uint64_t requestId;
    uint32_t reserved[2];
} MeshRuntimePipeRequest;

typedef struct MeshRuntimePipeResponse
{
    uint32_t magic;
    uint32_t size;
    uint32_t version;
    uint32_t command;
    uint64_t requestId;
    uint32_t result;
    uint32_t flags;
    uint32_t matchedTargetCount;
    uint32_t residentTargetCount;
    uint32_t activeTargetCount;
    uint32_t inactiveTargetCount;
    uint32_t failedTargetCount;
    uint32_t lastError;
    uint32_t reserved[2];
} MeshRuntimePipeResponse;

int MeshRuntimeRelay_IsUuid(const char* value);
int MeshRuntimeRelay_Operation(const char* value, uint32_t* command);
void MeshRuntimeRelay_MakeRequest(uint32_t command, uint64_t requestId, MeshRuntimePipeRequest* request);
int MeshRuntimeRelay_ValidateResponse(
    const MeshRuntimePipeRequest* request,
    const MeshRuntimePipeResponse* response);

#ifdef __cplusplus
}
#endif
#endif
