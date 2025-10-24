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

#include "../generated/meshagent_branding.h"
#include "../generated/network_profile.h"

#ifndef MESH_AGENT_SERVICE_NAME
    #error "meshagent_branding.h is missing. Run tools/embed_provisioning.ps1 before compiling."
#endif

#define MESHCORE_STATIC_ASSERT(name, expr) typedef char meshcore_static_assert_##name[(expr) ? 1 : -1]

#endif /* MESHCORE_CONFIG_COMMON_H */
