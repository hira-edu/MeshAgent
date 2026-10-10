/* Admission for a historical copied Windows service loader, never a canonical
 * host or permission to terminate a shared process. The caller must separately
 * establish the service account, DLL/datastore identity and protected DACLs. */
#ifndef MESH_SERVICE_LEGACY_HOST_H
#define MESH_SERVICE_LEGACY_HOST_H

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <aclapi.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

static BOOL ServiceLegacyHost_NormalizePath(const wchar_t* path, wchar_t* normalized, size_t capacity)
{
    wchar_t full[MAX_PATH];
    const wchar_t* p;
    DWORD count;
    size_t length, used = 3;
    if (!normalized || !capacity) { return FALSE; }
    normalized[0] = 0;
    if (!path || (length = wcslen(path)) < 4 || length >= MAX_PATH * 4 || capacity < 4 ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\') { return FALSE; }
    memcpy(normalized, path, 3 * sizeof(wchar_t));
    for (p = path + 3; *p; ++p)
    {
        if (*p < L' ' || wcschr(L"\"/:*?|<>%~", *p)) { goto invalid; }
        if (*p == L'\\' && normalized[used - 1] == L'\\') { goto invalid; }
        if (*p == L'\\' && (normalized[used - 1] == L'.' || normalized[used - 1] == L' ')) { goto invalid; }
        if (used + 1 >= capacity || used + 1 >= MAX_PATH) { goto invalid; }
        normalized[used++] = *p;
    }
    normalized[used] = 0;
    if (normalized[used - 1] == L'\\' || normalized[used - 1] == L'.' || normalized[used - 1] == L' ') { goto invalid; }
    count = GetFullPathNameW(normalized, MAX_PATH, full, NULL);
    if (count && count < MAX_PATH && !_wcsicmp(normalized, full)) { return TRUE; }
invalid:
    normalized[0] = 0;
    return FALSE;
}

static BOOL ServiceLegacyHost_IsCanonicalPath(const wchar_t* path)
{
    wchar_t normalized[MAX_PATH];
    return ServiceLegacyHost_NormalizePath(path, normalized, _countof(normalized)) && !_wcsicmp(path, normalized);
}

/* Migration admission only: SYSTEM and Administrators retain effective full
 * control, while all other principals are limited to read/execute. The root
 * must be protected; a sibling file may inherit from that validated root. */
static BOOL ServiceLegacyHost_PermissionsSupported(PSECURITY_DESCRIPTOR descriptor, BOOL requireProtected)
{
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    PSID owner = NULL;
    PACL dacl = NULL;
    BOOL defaulted, present;
    DWORD systemAccess = 0, adminAccess = 0;
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    if (!descriptor || !IsValidSecurityDescriptor(descriptor) ||
        !GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        (requireProtected && !(control & SE_DACL_PROTECTED)) ||
        !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !owner || !IsValidSid(owner) ||
        (!IsWellKnownSid(owner, WinLocalSystemSid) && !IsWellKnownSid(owner, WinBuiltinAdministratorsSid)) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) ||
        !present || !dacl || !IsValidAcl(dacl)) { return FALSE; }
    for (DWORD i = 0; i < dacl->AceCount; ++i)
    {
        ACCESS_ALLOWED_ACE* ace = NULL;
        DWORD mask;
        PSID sid;
        BOOL system, administrators;
        if (!GetAce(dacl, i, (LPVOID*)&ace) || !ace || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (ace->Header.AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE |
                INHERIT_ONLY_ACE | INHERITED_ACE)) ||
            ace->Header.AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 8) { return FALSE; }
        sid = (PSID)&ace->SidStart;
        if (!IsValidSid(sid) || GetLengthSid(sid) > ace->Header.AceSize - FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart)) { return FALSE; }
        system = IsWellKnownSid(sid, WinLocalSystemSid);
        administrators = IsWellKnownSid(sid, WinBuiltinAdministratorsSid);
        mask = ace->Mask;
        MapGenericMask(&mask, &mapping);
        if (mask & ~FILE_ALL_ACCESS) { return FALSE; }
        if (!system && !administrators && (mask & ~(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE))) { return FALSE; }
        if (!(ace->Header.AceFlags & INHERIT_ONLY_ACE))
        {
            if (system) { systemAccess |= mask; }
            if (administrators) { adminAccess |= mask; }
        }
    }
    return (systemAccess & FILE_ALL_ACCESS) == FILE_ALL_ACCESS &&
        (adminAccess & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
}

static BOOL ServiceLegacyHost_ValidatePermissions(const wchar_t* path, BOOL requireProtected)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BOOL ok = FALSE;
    DWORD error;
    if (!ServiceLegacyHost_IsCanonicalPath(path)) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    error = GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &descriptor);
    if (error == ERROR_SUCCESS)
    {
        ok = ServiceLegacyHost_PermissionsSupported(descriptor, requireProtected);
        if (!ok) { error = ERROR_ACCESS_DENIED; }
    }
    if (descriptor) { LocalFree(descriptor); }
    SetLastError(error);
    return ok;
}

/* Validate and copy exact canonical paths; never rewrite a historical binding.
 * The caller retains the original command verbatim in its rollback checkpoint. */
static BOOL ServiceLegacyHost_ParseImage(const wchar_t* image, const wchar_t* installedDll,
    wchar_t* hostOut, size_t capacity)
{
    wchar_t host[MAX_PATH], dll[MAX_PATH], rawHost[MAX_PATH * 4], parsedHost[MAX_PATH];
    const wchar_t *separator, *arguments, *start, *end;
    size_t directoryLength, hostLength, dllLength, rawLength;
    BOOL quoted;
    if (!hostOut || !capacity) { return FALSE; }
    hostOut[0] = 0;
    if (!image || !ServiceLegacyHost_NormalizePath(installedDll, dll, _countof(dll))) { return FALSE; }
    dllLength = wcslen(dll);
    if (dllLength < 7 || _wcsicmp(dll + dllLength - 4, L".dll")) { return FALSE; }
    separator = wcsrchr(dll, L'\\');
    directoryLength = (size_t)(separator - dll) + 1;
    if (directoryLength <= 3 || directoryLength + 11 >= MAX_PATH) { return FALSE; }
    memcpy(host, dll, directoryLength * sizeof(wchar_t));
    memcpy(host + directoryLength, L"svchost.exe", 12 * sizeof(wchar_t));
    hostLength = directoryLength + 11;
    quoted = image[0] == L'"';
    start = image + (quoted ? 1 : 0);
    end = wcschr(start, quoted ? L'"' : L' ');
    if (!end || !(rawLength = (size_t)(end - start)) || rawLength >= _countof(rawHost)) { return FALSE; }
    memcpy(rawHost, start, rawLength * sizeof(wchar_t)); rawHost[rawLength] = 0;
    if (!ServiceLegacyHost_NormalizePath(rawHost, parsedHost, _countof(parsedHost)) || _wcsicmp(parsedHost, host)) { return FALSE; }
    arguments = end + (quoted ? 1 : 0);
    if (_wcsicmp(arguments, L" -k netsvcs") && _wcsicmp(arguments, L" -k netsvcs -p")) { return FALSE; }
    if (hostLength + 1 > capacity) { return FALSE; }
    memcpy(hostOut, host, (hostLength + 1) * sizeof(wchar_t));
    return TRUE;
}

static BOOL ServiceLegacyHost_VersionString(const BYTE* version, WORD language, WORD codepage,
    const wchar_t* key, const wchar_t* expected)
{
    wchar_t query[96];
    wchar_t* value = NULL;
    UINT count = 0;
    if (_snwprintf_s(query, _countof(query), _TRUNCATE, L"\\StringFileInfo\\%04x%04x\\%ls",
        language, codepage, key) < 0) { return FALSE; }
    return VerQueryValueW(version, query, (LPVOID*)&value, &count) && value &&
        count == wcslen(expected) + 1 && value[count - 1] == 0 && !_wcsicmp(value, expected);
}

static BOOL ServiceLegacyHost_VersionIdentity(const wchar_t* path)
{
    DWORD ignored = 0, size = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, path, &ignored);
    BYTE* version;
    struct ServiceLegacyHost_Translation { WORD language, codepage; } *translations = NULL;
    UINT bytes = 0;
    BOOL ok = FALSE;
    if (!size || size > 1024 * 1024) { return FALSE; }
    version = (BYTE*)malloc(size);
    if (!version) { return FALSE; }
    if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, path, 0, size, version) ||
        !VerQueryValueW(version, L"\\VarFileInfo\\Translation", (LPVOID*)&translations, &bytes) ||
        !translations || !bytes || bytes % sizeof(*translations)) { goto done; }
    for (UINT i = 0; i < bytes / sizeof(*translations); ++i)
    {
        if (!ServiceLegacyHost_VersionString(version, translations[i].language, translations[i].codepage,
                L"OriginalFilename", L"svchost.exe") ||
            !ServiceLegacyHost_VersionString(version, translations[i].language, translations[i].codepage,
                L"CompanyName", L"Microsoft Corporation")) { goto done; }
    }
    ok = TRUE;
done:
    free(version);
    return ok;
}

/* Read signer identity only from the successfully verified provider state. */
static LONG ServiceLegacyHost_VerifyWindowsTrust(WINTRUST_DATA* trust)
{
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    wchar_t organization[128], commonName[128];
    CRYPT_PROVIDER_DATA* provider;
    CRYPT_PROVIDER_SGNR* signer;
    CRYPT_PROVIDER_CERT* certificate;
    trust->cbStruct = sizeof(*trust);
    trust->dwUIChoice = WTD_UI_NONE;
    trust->fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust->dwStateAction = WTD_STATEACTION_VERIFY;
    trust->dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, trust);
    if (status == ERROR_SUCCESS)
    {
        provider = WTHelperProvDataFromStateData(trust->hWVTStateData);
        signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : NULL;
        certificate = signer ? WTHelperGetProvCertFromChain(signer, 0) : NULL;
        if (!certificate || !certificate->pCert ||
            CertGetNameStringW(certificate->pCert, CERT_NAME_ATTR_TYPE, 0, (void*)szOID_ORGANIZATION_NAME,
                organization, _countof(organization)) != _countof(L"Microsoft Corporation") ||
            _wcsicmp(organization, L"Microsoft Corporation") ||
            CertGetNameStringW(certificate->pCert, CERT_NAME_ATTR_TYPE, 0, (void*)szOID_COMMON_NAME,
                commonName, _countof(commonName)) <= 1 ||
            (_wcsicmp(commonName, L"Microsoft Windows") && _wcsicmp(commonName, L"Microsoft Windows Publisher")))
        { status = TRUST_E_SUBJECT_NOT_TRUSTED; }
    }
    if (trust->hWVTStateData)
    {
        trust->dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, trust);
        trust->hWVTStateData = NULL;
    }
    return status;
}

/* The copied file must hash to a member of an installed signed catalog. A file
 * name or an otherwise valid catalog signature alone does not establish this. */
static BOOL ServiceLegacyHost_VerifyCatalog(const wchar_t* path, HANDLE file)
{
    /* These SHA-2 catalog APIs require Windows 8. Resolve dynamically so this
     * migration-only capability cannot prevent older hosts loading the agent. */
    typedef BOOL (WINAPI *ServiceLegacyHost_AcquireCatalog)(HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
    typedef BOOL (WINAPI *ServiceLegacyHost_HashCatalogFile)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);
    HMODULE module = GetModuleHandleW(L"wintrust.dll");
    ServiceLegacyHost_AcquireCatalog acquire = module ?
        (ServiceLegacyHost_AcquireCatalog)GetProcAddress(module, "CryptCATAdminAcquireContext2") : NULL;
    ServiceLegacyHost_HashCatalogFile hashFile = module ?
        (ServiceLegacyHost_HashCatalogFile)GetProcAddress(module, "CryptCATAdminCalcHashFromFileHandle2") : NULL;
    const wchar_t* algorithms[] = {L"SHA256", L"SHA1"};
    if (!acquire || !hashFile) { return FALSE; }
    for (size_t algorithm = 0; algorithm < _countof(algorithms); ++algorithm)
    {
        HCATADMIN admin = NULL;
        HCATINFO catalog = NULL;
        BYTE hash[64];
        DWORD hashLength = sizeof(hash);
        wchar_t member[129];
        BOOL ok = FALSE;
        if (!acquire(&admin, NULL, algorithms[algorithm], NULL, 0)) { continue; }
        LARGE_INTEGER zero = {0};
        if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN) ||
            !hashFile(admin, file, &hashLength, hash, 0) ||
            !hashLength || hashLength > sizeof(hash)) { CryptCATAdminReleaseContext(admin, 0); continue; }
        for (DWORD i = 0; i < hashLength; ++i)
        {
            static const wchar_t digits[] = L"0123456789ABCDEF";
            member[2 * i] = digits[hash[i] >> 4]; member[2 * i + 1] = digits[hash[i] & 15];
        }
        member[2 * hashLength] = 0;
        while ((catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, hashLength, 0, &catalog)) != NULL)
        {
            CATALOG_INFO info = {0};
            WINTRUST_CATALOG_INFO catalogInfo = {0};
            WINTRUST_DATA trust = {0};
            info.cbStruct = sizeof(info);
            if (!CryptCATCatalogInfoFromContext(catalog, &info, 0)) { continue; }
            catalogInfo.cbStruct = sizeof(catalogInfo);
            catalogInfo.pcwszCatalogFilePath = info.wszCatalogFile;
            catalogInfo.pcwszMemberTag = member;
            catalogInfo.pcwszMemberFilePath = path;
            catalogInfo.hMemberFile = file;
            catalogInfo.pbCalculatedFileHash = hash;
            catalogInfo.cbCalculatedFileHash = hashLength;
            catalogInfo.hCatAdmin = admin;
            trust.dwUnionChoice = WTD_CHOICE_CATALOG;
            trust.pCatalog = &catalogInfo;
            if (ServiceLegacyHost_VerifyWindowsTrust(&trust) == ERROR_SUCCESS) { ok = TRUE; break; }
        }
        if (catalog) { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); }
        CryptCATAdminReleaseContext(admin, 0);
        if (ok) { return TRUE; }
    }
    return FALSE;
}

/* Pin every ancestor against rename and the file against write/delete while
 * checking its signature and signed, neutral version resource. No files change.
 * Trust retrieval is cache-only; absent chain/revocation evidence fails closed. */
static BOOL ServiceLegacyHost_ValidateFile(const wchar_t* path)
{
    wchar_t ancestor[MAX_PATH], finalPath[MAX_PATH + 8];
    HANDLE directories[MAX_PATH / 2] = {0}, file = INVALID_HANDLE_VALUE;
    size_t opened = 0;
    BY_HANDLE_FILE_INFORMATION info;
    WINTRUST_FILE_INFO fileInfo = {0};
    WINTRUST_DATA trust = {0};
    BOOL ok = FALSE;
    DWORD count, error = ERROR_INVALID_DATA;
    if (!ServiceLegacyHost_IsCanonicalPath(path)) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    memcpy(ancestor, path, (wcslen(path) + 1) * sizeof(wchar_t));
    for (wchar_t* p = ancestor + 2; *p; ++p)
    {
        if (*p != L'\\') { continue; }
        wchar_t* cut = p == ancestor + 2 ? p + 1 : p;
        wchar_t saved = *cut;
        *cut = 0;
        HANDLE directory = CreateFileW(ancestor, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        *cut = saved;
        if (directory == INVALID_HANDLE_VALUE) { error = GetLastError(); goto done; }
        directories[opened++] = directory;
        if (!GetFileInformationByHandle(directory, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) { goto done; }
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); goto done; }
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) { goto done; }
    count = GetFinalPathNameByHandleW(file, finalPath, _countof(finalPath), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!count || count >= _countof(finalPath) || wcsncmp(finalPath, L"\\\\?\\", 4) || _wcsicmp(finalPath + 4, path)) { goto done; }
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path;
    fileInfo.hFile = file;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &fileInfo;
    LONG status = ServiceLegacyHost_VerifyWindowsTrust(&trust);
    if (status != ERROR_SUCCESS &&
        (status != TRUST_E_NOSIGNATURE || !ServiceLegacyHost_VerifyCatalog(path, file)))
    { error = (DWORD)status; goto done; }
    if (!ServiceLegacyHost_VersionIdentity(path)) { goto done; }
    ok = TRUE;
done:
    if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); }
    while (opened) { CloseHandle(directories[--opened]); }
    SetLastError(ok ? ERROR_SUCCESS : error);
    return ok;
}
#endif
