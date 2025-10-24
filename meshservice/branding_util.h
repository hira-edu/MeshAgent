#ifndef MESH_SERVICE_BRANDING_UTIL_H
#define MESH_SERVICE_BRANDING_UTIL_H

#include "meshcore/config/active_profile.h"

static __inline mesh_branding_text_t MeshService_GetServiceNameText(void)
{
    return MeshConfig_GetBranding()->serviceName;
}

static __inline mesh_branding_text_t MeshService_GetServiceFileText(void)
{
    return MeshConfig_GetBranding()->serviceFile;
}

static __inline void MeshService_CopyBrandingTextToWide(mesh_branding_text_t text, wchar_t* dest, size_t count)
{
    if (dest == NULL || count == 0) { return; }
#if defined(UNICODE) || defined(_UNICODE)
    if (text != NULL)
    {
        lstrcpynW(dest, text, (int)count);
    }
    else
    {
        dest[0] = L'\0';
    }
#else
    if (text != NULL)
    {
        MultiByteToWideChar(CP_ACP, 0, text, -1, dest, (int)count);
    }
    else
    {
        dest[0] = L'\0';
    }
#endif
    dest[count - 1] = L'\0';
}

#endif /* MESH_SERVICE_BRANDING_UTIL_H */
