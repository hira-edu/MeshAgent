#ifndef MESHCORE_CONFIG_GROUP_DEFAULT_H
#define MESHCORE_CONFIG_GROUP_DEFAULT_H

#include "branding_core.h"
#include "network_profiles.h"
#include "stealth_config.h"

typedef struct mesh_group_profile_s
{
    const char*                     name;
    const mesh_branding_definition_t* branding;
    const mesh_network_profile_t*   network;
    const mesh_stealth_profile_t*   stealth;
} mesh_group_profile_t;

static const mesh_group_profile_t g_meshGroupDefault =
{
    "default",
    &g_meshBrandingDefinition,
    &g_meshNetworkProfile,
    &g_meshStealthProfile
};

#endif /* MESHCORE_CONFIG_GROUP_DEFAULT_H */
