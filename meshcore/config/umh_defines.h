/*
    Centralized UMH (User Mode Hook) companion service identifiers.
    These are the SINGLE SOURCE OF TRUTH for the MasterService name,
    pipe GUID, and related constants. C consumers include this header;
    JS consumers (RecoveryCore.js) carry a copy annotated with an SSOT comment.
*/
#ifndef MESHCORE_CONFIG_UMH_DEFINES_H
#define MESHCORE_CONFIG_UMH_DEFINES_H

#define MESHAGENT_MASTER_SERVICE_EXE_NAME     L"MasterService.exe"
#define MESHAGENT_MASTER_SERVICE_SERVICE_NAME L"AdvancedHookService"
#define MESHAGENT_UMH_CONTROL_PIPE_NAME      L"\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-control"

/* Narrow-char variants for JS interop / logging */
#define MESHAGENT_UMH_CONTROL_PIPE_NAME_A     "\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-control"
#define MESHAGENT_MASTER_SERVICE_NAME_A       "AdvancedHookService"

#endif /* MESHCORE_CONFIG_UMH_DEFINES_H */
