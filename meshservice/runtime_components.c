#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "runtime_component_resources.h"
#include "runtime_components.h"

#define MESH_RUNTIME_RESOURCE_TYPE_RCDATA 10u
#define MESH_RUNTIME_MAX_PE_SECTIONS 96u

typedef struct MeshRuntimeResource
{
    const BYTE* data;
    DWORD size;
} MeshRuntimeResource;

static INIT_ONCE g_MeshRuntimeComponentInitOnce = INIT_ONCE_STATIC_INIT;
static MeshRuntimeComponentStatus g_MeshRuntimeComponentStatus = {
    sizeof(MeshRuntimeComponentStatus),
    MESH_RUNTIME_COMPONENT_STATUS_VERSION,
    MESH_RUNTIME_COMPONENTS_UNAVAILABLE,
    ERROR_NOT_READY,
    0, 0, 0, 0,
    {0}, {0}
};

static DWORD MeshRuntimeComponents_ReadU32(const BYTE* value)
{
    return ((DWORD)value[0]) |
        ((DWORD)value[1] << 8) |
        ((DWORD)value[2] << 16) |
        ((DWORD)value[3] << 24);
}

static WORD MeshRuntimeComponents_ReadU16(const BYTE* value)
{
    return (WORD)(value[0] | ((WORD)value[1] << 8));
}

static ULONGLONG MeshRuntimeComponents_ReadU64(const BYTE* value)
{
    return ((ULONGLONG)MeshRuntimeComponents_ReadU32(value)) |
        ((ULONGLONG)MeshRuntimeComponents_ReadU32(value + 4) << 32);
}

static BOOL MeshRuntimeComponents_LoadResource(
    HMODULE module,
    WORD identifier,
    MeshRuntimeResource* resource)
{
    HRSRC resourceInfo;
    HGLOBAL loaded;
    DWORD size;
    const void* data;
    if (module == NULL || resource == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    resourceInfo = FindResourceW(
        module,
        MAKEINTRESOURCEW(identifier),
        MAKEINTRESOURCEW(MESH_RUNTIME_RESOURCE_TYPE_RCDATA));
    if (resourceInfo == NULL) { return FALSE; }
    size = SizeofResource(module, resourceInfo);
    if (size < 4096u || size > MESH_RUNTIME_COMPONENT_MAX_SIZE)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    loaded = LoadResource(module, resourceInfo);
    if (loaded == NULL) { return FALSE; }
    data = LockResource(loaded);
    if (data == NULL)
    {
        SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
        return FALSE;
    }
    resource->data = (const BYTE*)data;
    resource->size = size;
    return TRUE;
}

static BOOL MeshRuntimeComponents_LoadCatalog(
    HMODULE module,
    MeshRuntimeResource* resource)
{
    HRSRC resourceInfo;
    HGLOBAL loaded;
    DWORD size;
    const void* data;
    resourceInfo = FindResourceW(
        module,
        MAKEINTRESOURCEW(IDR_RUNTIME_COMPONENT_CATALOG),
        MAKEINTRESOURCEW(MESH_RUNTIME_RESOURCE_TYPE_RCDATA));
    if (resourceInfo == NULL) { return FALSE; }
    size = SizeofResource(module, resourceInfo);
    if (size != MESH_RUNTIME_CATALOG_HEADER_SIZE +
            MESH_RUNTIME_CATALOG_ENTRY_COUNT * MESH_RUNTIME_CATALOG_ENTRY_SIZE)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    loaded = LoadResource(module, resourceInfo);
    if (loaded == NULL) { return FALSE; }
    data = LockResource(loaded);
    if (data == NULL)
    {
        SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
        return FALSE;
    }
    resource->data = (const BYTE*)data;
    resource->size = size;
    return TRUE;
}

static BOOL MeshRuntimeComponents_Hash(
    const BYTE* data,
    DWORD size,
    BYTE result[MESH_RUNTIME_COMPONENT_SHA256_SIZE])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR hashObject = NULL;
    DWORD hashObjectSize = 0;
    DWORD resultSize = 0;
    DWORD error = ERROR_INVALID_DATA;
    NTSTATUS status;
    BOOL success = FALSE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) { goto cleanup; }
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&hashObjectSize,
        sizeof(hashObjectSize),
        &resultSize,
        0);
    if (!BCRYPT_SUCCESS(status) || hashObjectSize == 0) { goto cleanup; }
    hashObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, hashObjectSize);
    if (hashObject == NULL)
    {
        error = ERROR_OUTOFMEMORY;
        goto cleanup;
    }
    status = BCryptCreateHash(
        algorithm,
        &hash,
        hashObject,
        hashObjectSize,
        NULL,
        0,
        0);
    if (!BCRYPT_SUCCESS(status)) { goto cleanup; }
    status = BCryptHashData(hash, (PUCHAR)data, size, 0);
    if (!BCRYPT_SUCCESS(status)) { goto cleanup; }
    status = BCryptFinishHash(hash, result, MESH_RUNTIME_COMPONENT_SHA256_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { goto cleanup; }
    success = TRUE;

cleanup:
    if (hash != NULL) { BCryptDestroyHash(hash); }
    if (hashObject != NULL) { HeapFree(GetProcessHeap(), 0, hashObject); }
    if (algorithm != NULL) { BCryptCloseAlgorithmProvider(algorithm, 0); }
    if (!success) { SetLastError(error); }
    return success;
}

static BOOL MeshRuntimeComponents_ValidatePe(
    const MeshRuntimeResource* resource,
    WORD expectedMachine)
{
    DWORD peOffset;
    DWORD signature;
    WORD machine;
    WORD sectionCount;
    WORD optionalSize;
    WORD characteristics;
    const BYTE* optionalHeader;
    WORD optionalMagic;
    DWORD dataDirectoryOffset;
    DWORD numberOfDirectoriesOffset;
    DWORD numberOfDirectories;
    DWORD sectionAlignment;
    DWORD fileAlignment;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    DWORD entryPoint;
    BOOL entryPointValid = FALSE;
    DWORD index;
    if (resource == NULL || resource->data == NULL || resource->size < 64u ||
        resource->data[0] != 'M' || resource->data[1] != 'Z')
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    peOffset = MeshRuntimeComponents_ReadU32(resource->data + 0x3c);
    if (peOffset < 0x40u || peOffset > resource->size - 24u)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    signature = MeshRuntimeComponents_ReadU32(resource->data + peOffset);
    machine = MeshRuntimeComponents_ReadU16(resource->data + peOffset + 4);
    sectionCount = MeshRuntimeComponents_ReadU16(resource->data + peOffset + 6);
    optionalSize = MeshRuntimeComponents_ReadU16(resource->data + peOffset + 20);
    characteristics = MeshRuntimeComponents_ReadU16(resource->data + peOffset + 22);
    if (signature != IMAGE_NT_SIGNATURE || machine != expectedMachine ||
        (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0 ||
        (characteristics & IMAGE_FILE_DLL) != 0 || sectionCount == 0 ||
        sectionCount > MESH_RUNTIME_MAX_PE_SECTIONS ||
        optionalSize < 64u ||
        (ULONGLONG)peOffset + 24u + optionalSize > resource->size)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    optionalHeader = resource->data + peOffset + 24u;
    optionalMagic = MeshRuntimeComponents_ReadU16(optionalHeader);
    if (machine == IMAGE_FILE_MACHINE_I386 && optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        dataDirectoryOffset = 96u;
        numberOfDirectoriesOffset = 92u;
    }
    else if (machine == IMAGE_FILE_MACHINE_AMD64 && optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        dataDirectoryOffset = 112u;
        numberOfDirectoriesOffset = 108u;
    }
    else
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    if (optionalSize < dataDirectoryOffset + 8u)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    numberOfDirectories = MeshRuntimeComponents_ReadU32(optionalHeader + numberOfDirectoriesOffset);
    sectionAlignment = MeshRuntimeComponents_ReadU32(optionalHeader + 32);
    fileAlignment = MeshRuntimeComponents_ReadU32(optionalHeader + 36);
    sizeOfImage = MeshRuntimeComponents_ReadU32(optionalHeader + 56);
    sizeOfHeaders = MeshRuntimeComponents_ReadU32(optionalHeader + 60);
    entryPoint = MeshRuntimeComponents_ReadU32(optionalHeader + 16);
    if (numberOfDirectories > (optionalSize - dataDirectoryOffset) / 8u ||
        sectionAlignment == 0 || (sectionAlignment & (sectionAlignment - 1u)) != 0 ||
        fileAlignment == 0 || (fileAlignment & (fileAlignment - 1u)) != 0 ||
        sectionAlignment < fileAlignment ||
        (sectionAlignment < 0x1000u
            ? fileAlignment != sectionAlignment
            : (fileAlignment < 0x200u || fileAlignment > 0x10000u)) ||
        entryPoint == 0 || sizeOfImage == 0 || sizeOfImage % sectionAlignment != 0 ||
        sizeOfHeaders == 0 || sizeOfHeaders % fileAlignment != 0 ||
        sizeOfHeaders > sizeOfImage || sizeOfHeaders > resource->size ||
        (ULONGLONG)peOffset + 24u + optionalSize +
            (ULONGLONG)sectionCount * 40u > sizeOfHeaders)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    for (index = 0; index < sectionCount; ++index)
    {
        const BYTE* section = resource->data + peOffset + 24u + optionalSize + index * 40u;
        DWORD virtualSize = MeshRuntimeComponents_ReadU32(section + 8);
        DWORD virtualAddress = MeshRuntimeComponents_ReadU32(section + 12);
        DWORD rawSize = MeshRuntimeComponents_ReadU32(section + 16);
        DWORD rawOffset = MeshRuntimeComponents_ReadU32(section + 20);
        DWORD sectionCharacteristics = MeshRuntimeComponents_ReadU32(section + 36);
        DWORD span = virtualSize > rawSize ? virtualSize : rawSize;
        DWORD priorIndex;
        if (virtualAddress % sectionAlignment != 0 ||
            (rawSize != 0 &&
             (rawOffset % fileAlignment != 0 || rawSize % fileAlignment != 0)) ||
            (sectionAlignment < 0x1000u && rawOffset != virtualAddress))
        {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }
        if (rawSize != 0 &&
            (rawOffset >= resource->size ||
             (ULONGLONG)rawOffset + rawSize > resource->size))
        {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }
        if (span != 0 &&
            (virtualAddress < sizeOfHeaders || virtualAddress >= sizeOfImage ||
             (ULONGLONG)virtualAddress + span > sizeOfImage))
        {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }
        if (rawSize != 0 && rawOffset < sizeOfHeaders)
        {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }
        if (entryPoint >= virtualAddress &&
            (ULONGLONG)entryPoint < (ULONGLONG)virtualAddress + rawSize &&
            (sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
        { entryPointValid = TRUE; }
        for (priorIndex = 0; priorIndex < index; ++priorIndex)
        {
            const BYTE* prior = resource->data + peOffset + 24u + optionalSize + priorIndex * 40u;
            DWORD priorVirtualSize = MeshRuntimeComponents_ReadU32(prior + 8);
            DWORD priorVirtualAddress = MeshRuntimeComponents_ReadU32(prior + 12);
            DWORD priorRawSize = MeshRuntimeComponents_ReadU32(prior + 16);
            DWORD priorRawOffset = MeshRuntimeComponents_ReadU32(prior + 20);
            DWORD priorSpan = priorVirtualSize > priorRawSize ? priorVirtualSize : priorRawSize;
            if ((span != 0 && priorSpan != 0 &&
                 (ULONGLONG)virtualAddress < (ULONGLONG)priorVirtualAddress + priorSpan &&
                 (ULONGLONG)priorVirtualAddress < (ULONGLONG)virtualAddress + span) ||
                (rawSize != 0 && priorRawSize != 0 &&
                 (ULONGLONG)rawOffset < (ULONGLONG)priorRawOffset + priorRawSize &&
                 (ULONGLONG)priorRawOffset < (ULONGLONG)rawOffset + rawSize))
            {
                SetLastError(ERROR_BAD_EXE_FORMAT);
                return FALSE;
            }
        }
    }
    if (!entryPointValid)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    /* RuntimeLoader owns its internal DLL contract. MeshAgent validates the
     * packaged controller as a complete architecture-matched application and
     * deliberately does not inspect or decide its runtime behavior. */
    return TRUE;
}

static BOOL MeshRuntimeComponents_Validate(
    MeshRuntimeComponentStatus* result)
{
    HMODULE module = NULL;
    MeshRuntimeResource catalog = {0};
    MeshRuntimeResource images[MESH_RUNTIME_CATALOG_ENTRY_COUNT] = {0};
    BYTE hashes[MESH_RUNTIME_CATALOG_ENTRY_COUNT][MESH_RUNTIME_COMPONENT_SHA256_SIZE] = {{0}};
    DWORD seenRoles = 0;
    DWORD index;

    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&MeshRuntimeComponents_Initialize,
            &module))
    {
        return FALSE;
    }
    if (!MeshRuntimeComponents_LoadCatalog(module, &catalog))
    {
        return FALSE;
    }
    if (MeshRuntimeComponents_ReadU32(catalog.data) != MESH_RUNTIME_CATALOG_MAGIC ||
        MeshRuntimeComponents_ReadU32(catalog.data + 4) != MESH_RUNTIME_CATALOG_VERSION ||
        MeshRuntimeComponents_ReadU32(catalog.data + 8) != MESH_RUNTIME_CATALOG_HEADER_SIZE ||
        MeshRuntimeComponents_ReadU32(catalog.data + 12) != MESH_RUNTIME_CATALOG_ENTRY_COUNT)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    if (!MeshRuntimeComponents_LoadResource(module, IDR_RUNTIME_CONTROLLER_X86, &images[0]) ||
        !MeshRuntimeComponents_LoadResource(module, IDR_RUNTIME_CONTROLLER_X64, &images[1]) ||
        !MeshRuntimeComponents_ValidatePe(&images[0], IMAGE_FILE_MACHINE_I386) ||
        !MeshRuntimeComponents_ValidatePe(&images[1], IMAGE_FILE_MACHINE_AMD64))
    {
        return FALSE;
    }
    for (index = 0; index < MESH_RUNTIME_CATALOG_ENTRY_COUNT; ++index)
    {
        const BYTE* entry = catalog.data + MESH_RUNTIME_CATALOG_HEADER_SIZE +
            index * MESH_RUNTIME_CATALOG_ENTRY_SIZE;
        DWORD role = MeshRuntimeComponents_ReadU32(entry);
        DWORD machine = MeshRuntimeComponents_ReadU32(entry + 4);
        ULONGLONG size = MeshRuntimeComponents_ReadU64(entry + 8);
        DWORD imageIndex;
        DWORD expectedMachine;
        DWORD roleBit;
        if (role == MESH_RUNTIME_COMPONENT_ROLE_CONTROLLER_X86)
        {
            imageIndex = 0;
            expectedMachine = IMAGE_FILE_MACHINE_I386;
            roleBit = 1u;
        }
        else if (role == MESH_RUNTIME_COMPONENT_ROLE_CONTROLLER_X64)
        {
            imageIndex = 1;
            expectedMachine = IMAGE_FILE_MACHINE_AMD64;
            roleBit = 2u;
        }
        else
        {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
        if ((seenRoles & roleBit) != 0 || machine != expectedMachine ||
            size != images[imageIndex].size)
        {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
        if (!MeshRuntimeComponents_Hash(
                images[imageIndex].data,
                images[imageIndex].size,
                hashes[imageIndex]))
        {
            return FALSE;
        }
        if (memcmp(
                hashes[imageIndex],
                entry + 16,
                MESH_RUNTIME_COMPONENT_SHA256_SIZE) != 0)
        {
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
        seenRoles |= roleBit;
    }
    if (seenRoles != 3u)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    result->x86Machine = IMAGE_FILE_MACHINE_I386;
    result->x86Size = images[0].size;
    result->x64Machine = IMAGE_FILE_MACHINE_AMD64;
    result->x64Size = images[1].size;
    memcpy(result->x86Sha256, hashes[0], MESH_RUNTIME_COMPONENT_SHA256_SIZE);
    memcpy(result->x64Sha256, hashes[1], MESH_RUNTIME_COMPONENT_SHA256_SIZE);
    return TRUE;
}

static BOOL CALLBACK MeshRuntimeComponents_InitializeOnce(
    PINIT_ONCE once,
    PVOID parameter,
    PVOID* context)
{
    DWORD error;
    UNREFERENCED_PARAMETER(once);
    UNREFERENCED_PARAMETER(parameter);
    UNREFERENCED_PARAMETER(context);
    if (MeshRuntimeComponents_Validate(&g_MeshRuntimeComponentStatus))
    {
        g_MeshRuntimeComponentStatus.state = MESH_RUNTIME_COMPONENTS_VALIDATED;
        g_MeshRuntimeComponentStatus.lastError = ERROR_SUCCESS;
        return TRUE;
    }
    error = GetLastError();
    g_MeshRuntimeComponentStatus.state = MESH_RUNTIME_COMPONENTS_UNAVAILABLE;
    g_MeshRuntimeComponentStatus.lastError =
        error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
    return TRUE;
}

BOOL MeshRuntimeComponents_Initialize(void)
{
    if (!InitOnceExecuteOnce(
            &g_MeshRuntimeComponentInitOnce,
            MeshRuntimeComponents_InitializeOnce,
            NULL,
            NULL))
    {
        return FALSE;
    }
    if (g_MeshRuntimeComponentStatus.state != MESH_RUNTIME_COMPONENTS_VALIDATED)
    {
        SetLastError(g_MeshRuntimeComponentStatus.lastError);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL MeshRuntimeComponents_GetStatus(MeshRuntimeComponentStatus* status)
{
    if (status == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (status->size < sizeof(MeshRuntimeComponentStatus))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    (void)MeshRuntimeComponents_Initialize();
    *status = g_MeshRuntimeComponentStatus;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static BOOL MeshRuntimeComponents_FileMatches(
    const wchar_t* path,
    const MeshRuntimeResource* resource)
{
    HANDLE file;
    LARGE_INTEGER size;
    BYTE* bytes = NULL;
    DWORD read = 0;
    BOOL matches = FALSE;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { return FALSE; }
    if (GetFileSizeEx(file, &size) && size.QuadPart == resource->size)
    {
        bytes = (BYTE*)HeapAlloc(GetProcessHeap(), 0, resource->size);
        if (bytes != NULL && ReadFile(file, bytes, resource->size, &read, NULL) &&
            read == resource->size && memcmp(bytes, resource->data, resource->size) == 0)
        { matches = TRUE; }
    }
    if (bytes != NULL) { HeapFree(GetProcessHeap(), 0, bytes); }
    CloseHandle(file);
    return matches;
}

static BOOL MeshRuntimeComponents_WriteController(
    const wchar_t* path,
    const MeshRuntimeResource* resource)
{
    wchar_t temporary[MAX_PATH * 4];
    HANDLE file;
    DWORD written = 0;
    BOOL success = FALSE;
    if (MeshRuntimeComponents_FileMatches(path, resource)) { return TRUE; }
    if (swprintf_s(temporary, _countof(temporary), L"%s.%lu.%llu.tmp", path,
            GetCurrentProcessId(), GetTickCount64()) < 0)
    { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { return FALSE; }
    if (WriteFile(file, resource->data, resource->size, &written, NULL) &&
        written == resource->size && FlushFileBuffers(file))
    { success = TRUE; }
    if (!CloseHandle(file)) { success = FALSE; }
    if (success)
    {
        success = MoveFileExW(temporary, path,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (!success)
    {
        DWORD error = GetLastError();
        DeleteFileW(temporary);
        SetLastError(error);
    }
    return success;
}

BOOL MeshRuntimeComponents_InstallControllers(
    wchar_t* x86Path,
    size_t x86PathCount,
    wchar_t* x64Path,
    size_t x64PathCount)
{
    HMODULE module = NULL;
    wchar_t modulePath[MAX_PATH * 4];
    wchar_t* slash;
    MeshRuntimeResource x86 = {0};
    MeshRuntimeResource x64 = {0};
    DWORD length;
    if (x86Path == NULL || x64Path == NULL || x86PathCount == 0 || x64PathCount == 0)
    { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!MeshRuntimeComponents_Initialize()) { return FALSE; }
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&MeshRuntimeComponents_Initialize, &module))
    { return FALSE; }
    length = GetModuleFileNameW(module, modulePath, _countof(modulePath));
    if (length == 0 || length >= _countof(modulePath))
    { if (length >= _countof(modulePath)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); } return FALSE; }
    slash = wcsrchr(modulePath, L'\\');
    if (slash == NULL) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    *slash = 0;
    if (swprintf_s(x86Path, x86PathCount, L"%s\\native-runtime-controller-x86.exe", modulePath) < 0 ||
        swprintf_s(x64Path, x64PathCount, L"%s\\native-runtime-controller-x64.exe", modulePath) < 0)
    { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (!MeshRuntimeComponents_LoadResource(module, IDR_RUNTIME_CONTROLLER_X86, &x86) ||
        !MeshRuntimeComponents_LoadResource(module, IDR_RUNTIME_CONTROLLER_X64, &x64))
    { return FALSE; }
    if (!MeshRuntimeComponents_WriteController(x86Path, &x86) ||
        !MeshRuntimeComponents_WriteController(x64Path, &x64))
    { return FALSE; }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}
