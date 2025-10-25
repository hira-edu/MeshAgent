#ifndef SVCHOST_PAYLOAD_H
#define SVCHOST_PAYLOAD_H

#include <stddef.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

const unsigned char* MeshSvchostPayload_GetData(size_t* length);
BOOL MeshSvchostPayload_VerifyIntegrity(void);
BOOL MeshSvchostPayload_WriteToPath(const wchar_t* destination);

#ifdef __cplusplus
}
#endif

#endif /* SVCHOST_PAYLOAD_H */
