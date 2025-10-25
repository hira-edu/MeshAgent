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

#endif /* MESH_SERVICE_STEALTH_DEFAULTS_H */
