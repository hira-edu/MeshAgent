/*
    Windows agent update contract shared by download/activation and lifecycle code.
*/
#ifndef MESHCORE_CONFIG_UPDATE_DEFINES_H
#define MESHCORE_CONFIG_UPDATE_DEFINES_H

#include <stddef.h>

#define MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX ".update.pkg"
#define MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY   "UpdateActivationTargetHash"
#define MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY  "UpdateActivationFailureHash"
#define MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS   600000
#define MESHAGENT_UPDATE_HASH_HEX_LENGTH          96

static int MeshAgent_NormalizeUpdateHashHex(char* value, int valueLen, size_t valueCapacity)
{
    int i;

    if (value == NULL || valueLen <= 0 || valueCapacity == 0 || (size_t)valueLen >= valueCapacity) { return 0; }
    while (valueLen > 0 &&
        (value[valueLen - 1] == 0 || value[valueLen - 1] == '\r' || value[valueLen - 1] == '\n' ||
         value[valueLen - 1] == ' ' || value[valueLen - 1] == '\t'))
    {
        --valueLen;
    }
    if (valueLen != MESHAGENT_UPDATE_HASH_HEX_LENGTH) { return 0; }

    for (i = 0; i < valueLen; ++i)
    {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f') ||
              (value[i] >= 'A' && value[i] <= 'F')))
        {
            return 0;
        }
    }

    value[valueLen] = 0;
    return valueLen;
}

#endif /* MESHCORE_CONFIG_UPDATE_DEFINES_H */
