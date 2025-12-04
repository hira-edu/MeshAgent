#ifndef MESH_SERVICE_SECURITY_H
#define MESH_SERVICE_SECURITY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL MeshService_HardenServiceDaclByName(const wchar_t* serviceName);
void MeshService_HardenServiceDacl(void);

#ifdef __cplusplus
}
#endif

#endif /* MESH_SERVICE_SECURITY_H */
