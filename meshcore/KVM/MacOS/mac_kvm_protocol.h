#ifndef MESH_MAC_KVM_PROTOCOL_H
#define MESH_MAC_KVM_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include "../../meshdefines.h"

/* 1: complete frame, 0: retain incomplete bytes, -1: invalid framing.
 * Both the user-session pipe and login-window socket carry this same stream. */
static int MacKvm_FrameLength(const unsigned char* bytes, size_t available, size_t* length)
{
    uint32_t payload;
    unsigned int type, header;
    *length = 0;
    if (available < 4) { return 0; }
    type = ((unsigned int)bytes[0] << 8) | bytes[1];
    header = ((unsigned int)bytes[2] << 8) | bytes[3];
    if (type == MNG_JUMBO)
    {
        if (header != 8) { return -1; }
        if (available < 8) { return 0; }
        payload = ((uint32_t)bytes[4] << 24) | ((uint32_t)bytes[5] << 16) | ((uint32_t)bytes[6] << 8) | bytes[7];
        if (payload < 4 || payload > INT_MAX - 8) { return -1; }
        *length = (size_t)payload + 8;
    }
    else
    {
        if (header < 4) { return -1; }
        *length = header;
    }
    return available >= *length ? 1 : 0;
}
#endif
