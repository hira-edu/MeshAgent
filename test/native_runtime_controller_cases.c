#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "runtime_controller.h"

int main(void)
{
    MeshRuntimePipeRequest request;
    MeshRuntimePipeResponse response = {0};
    uint32_t command = 0;
    assert(MESH_RUNTIME_ACCEPTED == 0 && MESH_RUNTIME_INVALID_MESSAGE == 1 &&
        MESH_RUNTIME_UNSUPPORTED_VERSION == 2 && MESH_RUNTIME_UNSUPPORTED_COMMAND == 3 &&
        MESH_RUNTIME_PERSISTENCE_FAILED == 4);
    assert(sizeof(request) == 32);
    assert(sizeof(response) == 64);
    assert(MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-00000000000A"));
    assert(MeshRuntimeRelay_Operation("getStatus", &command) && command == MESH_RUNTIME_STATUS);
    assert(MeshRuntimeRelay_Operation("load", &command) && command == MESH_RUNTIME_LOAD);
    assert(MeshRuntimeRelay_Operation("unload", &command) && command == MESH_RUNTIME_UNLOAD);
    assert(!MeshRuntimeRelay_Operation("setPolicy", &command));
    MeshRuntimeRelay_MakeRequest(MESH_RUNTIME_LOAD, 0x1122334455667788ULL, &request);
    assert(request.magic == MESH_RUNTIME_PIPE_MAGIC && request.size == 32 &&
        request.version == 1 && request.command == MESH_RUNTIME_LOAD &&
        request.requestId == 0x1122334455667788ULL &&
        request.reserved[0] == 0 && request.reserved[1] == 0);
    response.magic = request.magic;
    response.size = sizeof(response);
    response.version = request.version;
    response.command = request.command;
    response.requestId = request.requestId;
    assert(MeshRuntimeRelay_ValidateResponse(&request, &response));
    response.requestId++;
    assert(!MeshRuntimeRelay_ValidateResponse(&request, &response));
    response.requestId = request.requestId;
    response.reserved[1] = 1;
    assert(!MeshRuntimeRelay_ValidateResponse(&request, &response));
    puts("PASS native runtime relay framing: fixed commands, exact correlation, reserved validation");
    return 0;
}
