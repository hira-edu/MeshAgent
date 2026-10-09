#include "runtime_controller.h"
#include <string.h>

typedef char MeshRuntimePipeRequestSizeMustBe32[
    sizeof(MeshRuntimePipeRequest) == MESH_RUNTIME_PIPE_REQUEST_SIZE ? 1 : -1];
typedef char MeshRuntimePipeResponseSizeMustBe64[
    sizeof(MeshRuntimePipeResponse) == MESH_RUNTIME_PIPE_RESPONSE_SIZE ? 1 : -1];

static int MeshRuntimeRelay_Hex(char value)
{
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

int MeshRuntimeRelay_IsUuid(const char* value)
{
    size_t index;
    if (value == NULL) { return 0; }
    for (index = 0; index < 36; ++index)
    {
        if (index == 8 || index == 13 || index == 18 || index == 23)
        { if (value[index] != '-') { return 0; } }
        else if (!MeshRuntimeRelay_Hex(value[index])) { return 0; }
    }
    return value[36] == 0;
}

int MeshRuntimeRelay_Operation(const char* value, uint32_t* command)
{
    if (value == NULL || command == NULL) { return 0; }
    if (strcmp(value, "getStatus") == 0) { *command = MESH_RUNTIME_STATUS; return 1; }
    if (strcmp(value, "load") == 0) { *command = MESH_RUNTIME_LOAD; return 1; }
    if (strcmp(value, "unload") == 0) { *command = MESH_RUNTIME_UNLOAD; return 1; }
    return 0;
}

void MeshRuntimeRelay_MakeRequest(uint32_t command, uint64_t requestId, MeshRuntimePipeRequest* request)
{
    memset(request, 0, sizeof(*request));
    request->magic = MESH_RUNTIME_PIPE_MAGIC;
    request->size = sizeof(*request);
    request->version = MESH_RUNTIME_PROTOCOL_VERSION;
    request->command = command;
    request->requestId = requestId;
}

int MeshRuntimeRelay_ValidateResponse(
    const MeshRuntimePipeRequest* request,
    const MeshRuntimePipeResponse* response)
{
    return request != NULL && response != NULL &&
        response->magic == MESH_RUNTIME_PIPE_MAGIC &&
        response->size == sizeof(*response) &&
        response->version == MESH_RUNTIME_PROTOCOL_VERSION &&
        response->command == request->command &&
        response->requestId == request->requestId &&
        response->reserved[0] == 0 && response->reserved[1] == 0;
}
