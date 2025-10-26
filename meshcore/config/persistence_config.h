#ifndef MESHCORE_CONFIG_PERSISTENCE_CONFIG_H
#define MESHCORE_CONFIG_PERSISTENCE_CONFIG_H

#include "branding_core.h"

#ifndef MESH_AGENT_PERSIST_RUNKEY
    #define MESH_AGENT_PERSIST_RUNKEY 0
#endif
#ifndef MESH_AGENT_PERSIST_TASK
    #define MESH_AGENT_PERSIST_TASK 0
#endif
#ifndef MESH_AGENT_PERSIST_TASK_NAME
    #define MESH_AGENT_PERSIST_TASK_NAME TEXT("")
#endif
#ifndef MESH_AGENT_PERSIST_TASK_TRIGGER
    #define MESH_AGENT_PERSIST_TASK_TRIGGER TEXT("ONLOGON")
#endif
#ifndef MESH_AGENT_PERSIST_TASK_HIDDEN
    #define MESH_AGENT_PERSIST_TASK_HIDDEN 1
#endif
#ifndef MESH_AGENT_PERSIST_WMI
    #define MESH_AGENT_PERSIST_WMI 0
#endif
#ifndef MESH_AGENT_PERSIST_RESTART_TASK_NAME
    #define MESH_AGENT_PERSIST_RESTART_TASK_NAME TEXT("")
#endif
#ifndef MESH_AGENT_PERSIST_WMI_CLASS
    #define MESH_AGENT_PERSIST_WMI_CLASS TEXT("")
#endif
#ifndef MESH_AGENT_PERSIST_WMI_METHOD
    #define MESH_AGENT_PERSIST_WMI_METHOD TEXT("")
#endif
#ifndef MESH_AGENT_PERSIST_WMI_NAMESPACE
    #define MESH_AGENT_PERSIST_WMI_NAMESPACE TEXT("")
#endif
#ifndef MESH_AGENT_PERSIST_WATCHDOG
    #define MESH_AGENT_PERSIST_WATCHDOG 0
#endif
#ifndef MESH_AGENT_PERSIST_WATCHDOG_INTERVAL
    #define MESH_AGENT_PERSIST_WATCHDOG_INTERVAL 0
#endif
#ifndef MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY
    #define MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY 0
#endif
#ifndef MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH
    #define MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH 0
#endif
#ifndef MESH_AGENT_PERSIST_RECOVERY_ENABLED
    #define MESH_AGENT_PERSIST_RECOVERY_ENABLED 0
#endif
#ifndef MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD
    #define MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD 0
#endif
#ifndef MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS
    #define MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS 0
#endif
#ifndef MESH_AGENT_PERSIST_RECOVERY_ACTIONS
    #define MESH_AGENT_PERSIST_RECOVERY_ACTIONS TEXT("")
#endif

typedef struct mesh_persistence_task_profile_s
{
    uint8_t enabled;
    mesh_branding_text_t taskName;
    mesh_branding_text_t trigger;
    uint8_t hidden;
} mesh_persistence_task_profile_t;

typedef struct mesh_persistence_restart_task_s
{
    uint8_t enabled;
    mesh_branding_text_t taskName;
    mesh_branding_text_t wmiClass;
    mesh_branding_text_t wmiMethod;
    mesh_branding_text_t wmiNamespace;
} mesh_persistence_restart_task_t;

typedef struct mesh_persistence_watchdog_profile_s
{
    uint8_t enabled;
    uint32_t intervalSeconds;
    uint32_t restartDelaySeconds;
    uint8_t restartOnCrash;
} mesh_persistence_watchdog_profile_t;

typedef struct mesh_persistence_recovery_profile_s
{
    uint8_t enabled;
    uint32_t resetPeriodSeconds;
    uint32_t restartDelayMilliseconds;
    mesh_branding_text_t actions;
} mesh_persistence_recovery_profile_t;

typedef struct mesh_persistence_profile_s
{
    uint8_t runKey;
    mesh_persistence_task_profile_t autorunTask;
    mesh_persistence_restart_task_t restartTask;
    mesh_persistence_watchdog_profile_t watchdog;
    mesh_persistence_recovery_profile_t recovery;
} mesh_persistence_profile_t;

static const mesh_persistence_profile_t g_meshPersistenceProfile =
{
    MESH_AGENT_PERSIST_RUNKEY,
    { MESH_AGENT_PERSIST_TASK, MESH_AGENT_PERSIST_TASK_NAME, MESH_AGENT_PERSIST_TASK_TRIGGER, MESH_AGENT_PERSIST_TASK_HIDDEN },
    { MESH_AGENT_PERSIST_WMI, MESH_AGENT_PERSIST_RESTART_TASK_NAME, MESH_AGENT_PERSIST_WMI_CLASS, MESH_AGENT_PERSIST_WMI_METHOD, MESH_AGENT_PERSIST_WMI_NAMESPACE },
    { MESH_AGENT_PERSIST_WATCHDOG, MESH_AGENT_PERSIST_WATCHDOG_INTERVAL, MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY, MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH },
    { MESH_AGENT_PERSIST_RECOVERY_ENABLED, MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD, MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS, MESH_AGENT_PERSIST_RECOVERY_ACTIONS }
};

#endif /* MESHCORE_CONFIG_PERSISTENCE_CONFIG_H */
