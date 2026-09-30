#ifndef MESH_SERVICE_DEFAULTS_H
#define MESH_SERVICE_DEFAULTS_H

// Shared generic branding strings used when generated branding values are
// unavailable. Deployment-specific names belong in the generated branding
// header or the .msh file the server embeds.
#define SERVICE_FALLBACK_DESCRIPTION       L"remote management agent service."
#define SERVICE_FALLBACK_NAME              L"MeshAgent"
#define SERVICE_FALLBACK_DISPLAY_NAME      L"Mesh Agent Service"
#define SERVICE_FALLBACK_EXE_NAME          L"meshagent.exe"
#define SERVICE_FALLBACK_DLL_NAME          L"meshsvc.dll"
#define SERVICE_FALLBACK_DB_NAME           L"meshagent.db"
#define SERVICE_FALLBACK_CONF_NAME         L"meshagent.conf"
#define SERVICE_FALLBACK_LOG_NAME          L"meshagent.log"

// Installation ACL defaults.
//
// Install root must be traversable by interactive users so the per-session helper
// (KVM/etc) can execute the host binary via CreateProcessAsUser(). Do not inherit
// the interactive ACE to child objects; binaries are explicitly ACL'd as needed.
#define SERVICE_SECURE_DIR_DACL_SDDL       L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)"
#define SERVICE_INSTALL_ROOT_DACL_SDDL     L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;IU)(A;;0x1200a9;;;AU)"
#define SERVICE_HOST_EXE_DACL_SDDL         L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;IU)(A;;0x1200a9;;;AU)"
// DLL must be readable/executable by the target interactive session so the
// rundll32 bridge can load it after TokenSessionId reassignment.
#define SERVICE_DLL_DACL_SDDL              L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;IU)(A;;0x1200a9;;;AU)"

/*
 * Persistence toggle reference:
 *   - Run key / autorun task / restart task flags come from branding_config.persistence.*
 *   - Watchdog + service recovery settings (interval, delays, actions) map to
 *     MESH_AGENT_PERSIST_WATCHDOG_* and MESH_AGENT_PERSIST_RECOVERY_* defines.
 *   - See docs/CONFIGURATION.md for operator guidance on supported overrides.
 */

#endif /* MESH_SERVICE_DEFAULTS_H */
