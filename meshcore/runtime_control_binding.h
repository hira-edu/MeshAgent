#ifndef MESH_RUNTIME_CONTROL_BINDING_H
#define MESH_RUNTIME_CONTROL_BINDING_H

#include "../microscript/duktape.h"
#include "../meshservice/runtime_components.h"

/* Startup validation runs before the agent chain. Command processing only
 * snapshots already validated data and never hashes images on the event loop. */
void MeshRuntimeBinding_Initialize(const MeshRuntimeComponentStatus* components);
void MeshRuntimeBinding_Shutdown(void);
duk_ret_t MeshRuntimeBinding_Execute(duk_context* ctx);

#endif
