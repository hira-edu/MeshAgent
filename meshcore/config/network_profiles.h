#ifndef MESHCORE_CONFIG_NETWORK_PROFILES_H
#define MESHCORE_CONFIG_NETWORK_PROFILES_H

#include "config_common.h"

typedef struct mesh_network_profile_s
{
    const char* primaryEndpoint;
    const char* userAgent;
    const char* sni;
    const char* tlsMinVersion;
    const char* tlsMaxVersion;
    const char* alpnProtocols;
} mesh_network_profile_t;

static const mesh_network_profile_t g_meshNetworkProfile =
{
    MESH_AGENT_NETWORK_ENDPOINT,
    MESH_AGENT_NETWORK_USER_AGENT,
#ifdef MESH_AGENT_NETWORK_SNI
    MESH_AGENT_NETWORK_SNI,
#else
    NULL,
#endif
#ifdef MESH_TLS_MIN_VERSION
    MESH_TLS_MIN_VERSION,
#else
    "TLS1.2",
#endif
#ifdef MESH_TLS_MAX_VERSION
    MESH_TLS_MAX_VERSION,
#else
    "TLS1.3",
#endif
#ifdef MESH_ALPN_PROTOCOLS
    MESH_ALPN_PROTOCOLS,
#else
    NULL,
#endif
};

#endif /* MESHCORE_CONFIG_NETWORK_PROFILES_H */
