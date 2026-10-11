#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "runtime_controller.h"

int main(void)
{
    uint32_t command = 0;

    /* UUID validation */
    assert(MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-000000000001"));
    assert(MeshRuntimeRelay_IsUuid("12345678-1234-1234-1234-123456789abc"));
    assert(MeshRuntimeRelay_IsUuid("abcdef01-2345-6789-abcd-ef0123456789"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-00000000000A"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-00000000000"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-0000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("000000000000000000000000000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("00000000_0000_0000_0000_000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("0000000-00000-0000-0000-000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("00000000:0000:0000:0000:000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("00000000/0000/0000/0000/000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-00000000000/"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-00000000000:"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-00000000000@"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-00000000000g"));
    assert(!MeshRuntimeRelay_IsUuid(" 00000000-0000-0000-0000-000000000001"));
    assert(!MeshRuntimeRelay_IsUuid("00000000-0000-0000-0000-000000000001 "));
    assert(!MeshRuntimeRelay_IsUuid(NULL));
    assert(!MeshRuntimeRelay_IsUuid(""));

    /* Operation mapping: getStatus */
    command = 0;
    assert(MeshRuntimeRelay_Operation("getStatus", &command) && command == MESH_RUNTIME_STATUS);

    /* Operation mapping: load */
    command = 0;
    assert(MeshRuntimeRelay_Operation("load", &command) && command == MESH_RUNTIME_LOAD);

    /* Operation mapping: unload */
    command = 0;
    assert(MeshRuntimeRelay_Operation("unload", &command) && command == MESH_RUNTIME_UNLOAD);

    /* Unsupported operations and case sensitivity */
    command = 0xAA55AA55;
    assert(!MeshRuntimeRelay_Operation("status", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("activate", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("start", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("stop", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("setPolicy", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("kill", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("GetStatus", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("LOAD", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("Unload", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("getStatus ", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("", &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation(NULL, &command) && command == 0xAA55AA55);
    assert(!MeshRuntimeRelay_Operation("getStatus", NULL));
    assert(!MeshRuntimeRelay_Operation("load", NULL));
    assert(!MeshRuntimeRelay_Operation("unload", NULL));

    puts("PASS native runtime relay: UUID validation and operation mapping");
    return 0;
}
