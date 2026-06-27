#ifndef MESHCORE_CONFIG_COMMON_H
#define MESHCORE_CONFIG_COMMON_H

#include <stdint.h>

/*
    The generated branding header relies on the Windows TEXT() macro. When the
    wider Windows headers are not included (for example during cross-platform
    agent builds) we provide a lightweight fallback so the generated constants
    are still usable.
*/
#ifndef TEXT
    #if defined(_UNICODE) || defined(UNICODE)
        #define TEXT(x) L##x
    #else
        #define TEXT(x) x
    #endif
#endif

#if defined(__has_include)
    #if __has_include("../generated/meshagent_branding.h")
        #include "../generated/meshagent_branding.h"
    #endif
#endif

#if defined(__has_include)
    #if !defined(MESH_AGENT_SERVICE_NAME)
        #if __has_include("branding_profile.local.h")
            #include "branding_profile.local.h"
        #elif __has_include("branding_profile.template.h")
            #include "branding_profile.template.h"
        #else
            #error "No branding profile header found. Copy branding_profile.template.h to branding_profile.local.h and populate real values."
        #endif
    #endif
#else
    #ifndef MESH_AGENT_SERVICE_NAME
        #include "branding_profile.template.h"
    #endif
#endif

#ifndef MESH_AGENT_SERVICE_NAME
    #error "Branding profile is incomplete: MESH_AGENT_SERVICE_NAME missing."
#endif
#ifndef MESH_AGENT_NETWORK_ENDPOINT
    #define MESH_AGENT_NETWORK_ENDPOINT NULL
#endif
#ifndef MESH_AGENT_NETWORK_HOST_HEADER
    #define MESH_AGENT_NETWORK_HOST_HEADER NULL
#endif
#ifndef MESH_AGENT_NETWORK_USER_AGENT
    #define MESH_AGENT_NETWORK_USER_AGENT NULL
#endif
#ifndef MESH_AGENT_NETWORK_FALLBACK_COUNT
    #define MESH_AGENT_NETWORK_FALLBACK_COUNT 0
#endif
#ifndef MESH_AGENT_NETWORK_FALLBACK_LIST
    #define MESH_AGENT_NETWORK_FALLBACK_LIST { { NULL, NULL, NULL, NULL, NULL } }
#endif
/*
    Provisioning data (MeshID, ServerID, MeshServer, etc.) should come from
    the .msh file that the server embeds at download time.  Compile-time
    provisioning values are only available when MESH_PROVISIONING_HARDCODED
    is defined (test/lab builds).
*/
#ifndef MESH_AGENT_MESH_ID
    #ifdef MESH_PROVISIONING_HARDCODED
        #error "MESH_PROVISIONING_HARDCODED is set but MESH_AGENT_MESH_ID is missing from the branding header."
    #endif
    /* Production: provisioning comes exclusively from .msh at runtime. */
    #define MESH_AGENT_MESH_ID      NULL
#endif
#ifndef MESH_AGENT_SERVER_ID
    #define MESH_AGENT_SERVER_ID    NULL
#endif
#ifndef MESH_AGENT_SERVER_URL
    #define MESH_AGENT_SERVER_URL   NULL
#endif
#ifndef MESH_AGENT_MESH_NAME
    #define MESH_AGENT_MESH_NAME    NULL
#endif
#ifndef MESH_AGENT_MESH_TYPE
    #define MESH_AGENT_MESH_TYPE    2
#endif
#ifndef MESH_AGENT_ALLOW_HOST_POWER_ACTIONS
    #define MESH_AGENT_ALLOW_HOST_POWER_ACTIONS 0
#endif

#define MESHCORE_STATIC_ASSERT(name, expr) typedef char meshcore_static_assert_##name[(expr) ? 1 : -1]

#endif /* MESHCORE_CONFIG_COMMON_H */
