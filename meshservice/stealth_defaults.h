#ifndef MESH_SERVICE_STEALTH_DEFAULTS_H
#define MESH_SERVICE_STEALTH_DEFAULTS_H

// Shared generic branding strings used when generated branding values are
// unavailable. Deployment-specific names belong in the generated branding
// header or the .msh file the server embeds.
#define STEALTH_FALLBACK_SERVICE_DESCRIPTION L"remote management agent service."
#define STEALTH_FALLBACK_SERVICE_NAME        L"MeshAgent"
#define STEALTH_FALLBACK_DISPLAY_NAME        L"Mesh Agent Service"
#define STEALTH_FALLBACK_EXE_NAME            L"meshagent.exe"
#define STEALTH_FALLBACK_DLL_NAME            L"meshsvc.dll"
#define STEALTH_FALLBACK_DB_NAME             L"meshagent.db"
#define STEALTH_FALLBACK_CONF_NAME           L"meshagent.conf"
#define STEALTH_FALLBACK_LOG_NAME            L"meshagent.log"

// Installation ACL defaults.
//
// Install root must be traversable by interactive users so the per-session helper
// (KVM/etc) can execute the host binary via CreateProcessAsUser(). Do not inherit
// the interactive ACE to child objects; binaries are explicitly ACL'd as needed.
#define STEALTH_SECURE_DIR_DACL_SDDL         L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
#define STEALTH_INSTALL_ROOT_DACL_SDDL       L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OI;0x1200a9;;;IU)"
#define STEALTH_HOST_EXE_DACL_SDDL           L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;IU)"
// BUGFIX: DLL needs same ACL as EXE to allow rundll32 USER spawn type to load it
#define STEALTH_SVCHOST_DLL_DACL_SDDL        L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;IU)"

/*
 * Persistence toggle reference:
 *   - Run key / autorun task / restart task flags come from branding_config.persistence.*
 *   - Watchdog + service recovery settings (interval, delays, actions) map to
 *     MESH_AGENT_PERSIST_WATCHDOG_* and MESH_AGENT_PERSIST_RECOVERY_* defines.
 *   - See STEALTHLAB_CONFIG_GUIDE.md for operator guidance on per-group overrides.
 */

#endif /* MESH_SERVICE_STEALTH_DEFAULTS_H */
