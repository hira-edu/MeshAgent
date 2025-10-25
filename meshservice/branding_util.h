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

static __inline mesh_branding_text_t MeshService_GetInstallRootText(void)
{
    return MeshConfig_GetBranding()->installRoot;
}

static __inline mesh_branding_text_t MeshService_GetLogDirectoryText(void)
{
    return MeshConfig_GetBranding()->logDirectory;
}

static __inline mesh_branding_text_t MeshService_GetBinaryNameText(void)
{
    return MeshConfig_GetBranding()->binaryName;
}

static __inline mesh_branding_text_t MeshService_GetSvchostDllNameText(void)
{
    return MeshConfig_GetBranding()->svchostDllName;
}

static __inline mesh_branding_text_t MeshService_GetDatabaseFileNameText(void)
{
    return MeshConfig_GetBranding()->databaseFileName;
}

static __inline mesh_branding_text_t MeshService_GetConfigFileNameText(void)
{
    return MeshConfig_GetBranding()->configFileName;
}

static __inline mesh_branding_text_t MeshService_GetLogFileNameText(void)
{
    return MeshConfig_GetBranding()->logFileName;
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

static __inline void MeshService_CopyBrandingPathToWide(mesh_branding_text_t text, wchar_t* dest, size_t count)
{
    MeshService_CopyBrandingTextToWide(text, dest, count);
    if (dest != NULL)
    {
        for (size_t i = 0; dest[i] != L'\0'; ++i)
        {
            if (dest[i] == L'/')
            {
                dest[i] = L'\\';
            }
        }
    }
}

#endif /* MESH_SERVICE_BRANDING_UTIL_H */
