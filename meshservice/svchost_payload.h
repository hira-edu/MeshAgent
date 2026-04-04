#ifndef SVCHOST_PAYLOAD_H
#define SVCHOST_PAYLOAD_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL MeshSvchostPayload_WriteToPath(const wchar_t* destination);

#ifdef __cplusplus
}
#endif

#endif /* SVCHOST_PAYLOAD_H */
