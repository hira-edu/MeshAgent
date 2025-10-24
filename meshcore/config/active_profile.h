#ifndef MESHCORE_CONFIG_ACTIVE_PROFILE_H
#define MESHCORE_CONFIG_ACTIVE_PROFILE_H

#include "group_default.h"

#ifdef _MSC_VER
#define MESHCONFIG_INLINE static __inline
#else
#define MESHCONFIG_INLINE static inline
#endif

MESHCONFIG_INLINE const mesh_group_profile_t* MeshConfig_GetActiveGroup(void)
{
    return &g_meshGroupDefault;
}

MESHCONFIG_INLINE const mesh_branding_definition_t* MeshConfig_GetBranding(void)
{
    return MeshConfig_GetActiveGroup()->branding;
}

MESHCONFIG_INLINE const mesh_network_profile_t* MeshConfig_GetNetwork(void)
{
    return MeshConfig_GetActiveGroup()->network;
}

MESHCONFIG_INLINE const mesh_stealth_profile_t* MeshConfig_GetStealth(void)
{
    return MeshConfig_GetActiveGroup()->stealth;
}

#undef MESHCONFIG_INLINE

#endif /* MESHCORE_CONFIG_ACTIVE_PROFILE_H */
