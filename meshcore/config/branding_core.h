#ifndef MESHCORE_CONFIG_BRANDING_CORE_H
#define MESHCORE_CONFIG_BRANDING_CORE_H

#include "config_common.h"

#if defined(_UNICODE) || defined(UNICODE)
    typedef const wchar_t* mesh_branding_text_t;
#else
    typedef const char* mesh_branding_text_t;
#endif

typedef struct mesh_branding_definition_s
{
    mesh_branding_text_t serviceFile;
    mesh_branding_text_t serviceName;
    mesh_branding_text_t logDirectory;
    const char*          companyName;
    const char*          productName;
    const char*          fileDescription;
    const char*          internalName;
    const char*          originalFilename;
    const char*          copyrightNotice;
    uint16_t             fileVersion[4];
    uint16_t             productVersion[4];
} mesh_branding_definition_t;

static const mesh_branding_definition_t g_meshBrandingDefinition =
{
    MESH_AGENT_SERVICE_FILE,
    MESH_AGENT_SERVICE_NAME,
    MESH_AGENT_LOG_DIRECTORY,
    MESH_AGENT_COMPANY_NAME,
    MESH_AGENT_PRODUCT_NAME,
    MESH_AGENT_FILE_DESCRIPTION,
    MESH_AGENT_INTERNAL_NAME,
    MESH_AGENT_ORIGINAL_FILENAME,
    MESH_AGENT_COPYRIGHT,
    { MESH_AGENT_FILE_VERSION_MAJOR, MESH_AGENT_FILE_VERSION_MINOR, MESH_AGENT_FILE_VERSION_BUILD, MESH_AGENT_FILE_VERSION_REVISION },
    { MESH_AGENT_PRODUCT_VERSION_MAJOR, MESH_AGENT_PRODUCT_VERSION_MINOR, MESH_AGENT_PRODUCT_VERSION_BUILD, MESH_AGENT_PRODUCT_VERSION_REVISION }
};

MESHCORE_STATIC_ASSERT(file_version_array_size, (sizeof(g_meshBrandingDefinition.fileVersion) / sizeof(uint16_t)) == 4);
MESHCORE_STATIC_ASSERT(product_version_array_size, (sizeof(g_meshBrandingDefinition.productVersion) / sizeof(uint16_t)) == 4);

#endif /* MESHCORE_CONFIG_BRANDING_CORE_H */
