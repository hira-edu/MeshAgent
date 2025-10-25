#ifndef MESHCORE_CONFIG_PERSISTENCE_CONFIG_H
#define MESHCORE_CONFIG_PERSISTENCE_CONFIG_H

#include "config_common.h"

#ifndef MESH_AGENT_PERSIST_RUNKEY
    #define MESH_AGENT_PERSIST_RUNKEY 0
#endif
#ifndef MESH_AGENT_PERSIST_TASK
    #define MESH_AGENT_PERSIST_TASK 0
#endif
#ifndef MESH_AGENT_PERSIST_WMI
    #define MESH_AGENT_PERSIST_WMI 0
#endif
#ifndef MESH_AGENT_PERSIST_WATCHDOG
    #define MESH_AGENT_PERSIST_WATCHDOG 0
#endif

typedef struct mesh_persistence_profile_s
{
    uint8_t runKey;
    uint8_t scheduledTask;
    uint8_t wmiRestart;
    uint8_t watchdog;
} mesh_persistence_profile_t;

static const mesh_persistence_profile_t g_meshPersistenceProfile =
{
    MESH_AGENT_PERSIST_RUNKEY,
    MESH_AGENT_PERSIST_TASK,
    MESH_AGENT_PERSIST_WMI,
    MESH_AGENT_PERSIST_WATCHDOG
};

#endif /* MESHCORE_CONFIG_PERSISTENCE_CONFIG_H */

