#ifndef MESH_SERVICE_SECURITY_H
#define MESH_SERVICE_SECURITY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_SERVICE_DACL_SDDL \
    L"D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" \
    L"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" \
    L"(A;;LCRP;;;AU)" \
    L"(A;;LCRP;;;SU)"

BOOL MeshService_HardenServiceDaclByName(const wchar_t* serviceName);
void MeshService_HardenServiceDacl(void);
BOOL MeshService_ValidateServiceDaclByName(const wchar_t* serviceName, wchar_t* actualSddl, size_t actualSddlCch);

#ifdef __cplusplus
}
#endif

#endif /* MESH_SERVICE_SECURITY_H */
