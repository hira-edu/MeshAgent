#include "runtime_controller.h"
#include <string.h>

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
    if (strcmp(value, "getStatus") == 0)
    {
        *command = MESH_RUNTIME_STATUS;
        return 1;
    }
    if (strcmp(value, "load") == 0)
    {
        *command = MESH_RUNTIME_LOAD;
        return 1;
    }
    if (strcmp(value, "unload") == 0)
    {
        *command = MESH_RUNTIME_UNLOAD;
        return 1;
    }
    return 0;
}
