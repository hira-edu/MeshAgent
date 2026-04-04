#ifndef MESHCORE_CONFIG_BRANDING_CORE_H
#define MESHCORE_CONFIG_BRANDING_CORE_H

#include "config_common.h"

/* Generic fallback paths — deployment-specific values come from the generated
   branding header or the .msh file the server embeds at download time. */
#ifndef MESH_AGENT_INSTALL_ROOT
    #define MESH_AGENT_INSTALL_ROOT TEXT("C:/ProgramData/MeshAgent")
#endif
#ifndef MESH_AGENT_LOG_DIRECTORY
    #define MESH_AGENT_LOG_DIRECTORY TEXT("C:/ProgramData/MeshAgent/logs")
#endif
#ifndef MESH_AGENT_BINARY_NAME
    #define MESH_AGENT_BINARY_NAME TEXT("meshagent.exe")
#endif
#ifndef MESH_AGENT_SVCHOST_DLL
    #define MESH_AGENT_SVCHOST_DLL TEXT("meshsvc.dll")
#endif
#ifndef MESH_AGENT_ARTIFACT_DB
    #define MESH_AGENT_ARTIFACT_DB TEXT("meshagent.db")
#endif
#ifndef MESH_AGENT_ARTIFACT_CONFIG
    #define MESH_AGENT_ARTIFACT_CONFIG TEXT("meshagent.conf")
#endif
#ifndef MESH_AGENT_ARTIFACT_LOG
    #define MESH_AGENT_ARTIFACT_LOG TEXT("meshagent.log")
#endif

#if defined(_UNICODE) || defined(UNICODE)
    typedef const wchar_t* mesh_branding_text_t;
#else
    typedef const char* mesh_branding_text_t;
#endif

typedef struct mesh_branding_definition_s
{
    mesh_branding_text_t serviceFile;
    mesh_branding_text_t serviceName;
    mesh_branding_text_t installRoot;
    mesh_branding_text_t logDirectory;
    mesh_branding_text_t binaryName;
    mesh_branding_text_t svchostDllName;
    mesh_branding_text_t databaseFileName;
    mesh_branding_text_t configFileName;
    mesh_branding_text_t logFileName;
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
    MESH_AGENT_INSTALL_ROOT,
    MESH_AGENT_LOG_DIRECTORY,
    MESH_AGENT_BINARY_NAME,
    MESH_AGENT_SVCHOST_DLL,
    MESH_AGENT_ARTIFACT_DB,
    MESH_AGENT_ARTIFACT_CONFIG,
    MESH_AGENT_ARTIFACT_LOG,
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
