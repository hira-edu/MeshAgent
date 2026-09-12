#ifndef MESHCORE_CONFIG_RUNTIME_CONFIG_H
#define MESHCORE_CONFIG_RUNTIME_CONFIG_H

#include "config_common.h"

typedef struct mesh_runtime_profile_s
{
    uint8_t runtimeEnabled;
    uint8_t svchostMode;
    uint8_t manageFiles;
    uint8_t manageRegistry;
    uint8_t eventTraceDiagnostics;
    uint8_t debugDiagnostics;
    uint8_t nativeApiMode;
    uint8_t bundleExtract;
} mesh_runtime_profile_t;

static const mesh_runtime_profile_t g_meshRuntimeProfile =
{
    MESH_AGENT_RUNTIME_ENABLED,
    MESH_AGENT_SVCHOST_MODE,
    MESH_AGENT_MANAGE_FILES,
    MESH_AGENT_MANAGE_REGISTRY,
    MESH_AGENT_EVENT_TRACE_DIAGNOSTICS,
    MESH_AGENT_DEBUG_DIAGNOSTICS,
    MESH_AGENT_NATIVE_API_MODE,
    MESH_AGENT_BUNDLE_EXTRACT_DEFAULT
};

#endif /* MESHCORE_CONFIG_RUNTIME_CONFIG_H */
