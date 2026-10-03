/* Durable, bounded checkpoint for the known deployment mutation surface.
 * Version 1 uses DWORD scalars and UTF-16 strings, never native pointers.
 * The caller supplies canonical paths in the protected deployment state folder. */
#ifndef MESH_SERVICE_TRANSACTION_JOURNAL_H
#define MESH_SERVICE_TRANSACTION_JOURNAL_H
#define SERVICE_JOURNAL_MAX_BYTES (2 * 1024 * 1024)
#define SERVICE_JOURNAL_PREPARED 1
#define SERVICE_JOURNAL_BACKED_UP 2
#define SERVICE_JOURNAL_COMMITTED 3
#define SERVICE_JOURNAL_ROLLED_BACK 4
#define SERVICE_JOURNAL_ACTIVATING 5
#define SERVICE_JOURNAL_NULL 0xffffffffUL

static BOOL ServiceJournal_PhaseValid(DWORD phase)
{
    return phase == SERVICE_JOURNAL_PREPARED ||
        phase == SERVICE_JOURNAL_BACKED_UP ||
        phase == SERVICE_JOURNAL_COMMITTED ||
        phase == SERVICE_JOURNAL_ROLLED_BACK ||
        phase == SERVICE_JOURNAL_ACTIVATING;
}

static BOOL ServiceJournal_PhaseRequiresBackups(DWORD phase)
{
    return phase == SERVICE_JOURNAL_BACKED_UP || phase == SERVICE_JOURNAL_ACTIVATING;
}

typedef struct ServiceJournalRecord {
    DWORD phase, fileMask;
    ServiceBindingSnapshot* binding;
    PSECURITY_DESCRIPTOR dacl[5];
    DWORD attributes[5];
} ServiceJournalRecord;
typedef struct ServiceJournalBuffer { BYTE* data; DWORD size, offset; BOOL ok; } ServiceJournalBuffer;

static void ServiceJournal_Free(ServiceJournalRecord* record)
{
    size_t i;
    if (!record) { return; }
    ServiceBinding_Free(record->binding);
    for (i = 0; i < 5; ++i) { free(record->dacl[i]); }
    free(record);
}
static void ServiceJournal_Put(ServiceJournalBuffer* b, const void* data, DWORD size)
{
    if (!b->ok || size > b->size - b->offset) { b->ok = FALSE; return; }
    if (size) { memcpy(b->data + b->offset, data, size); }
    b->offset += size;
}
static void ServiceJournal_Get(ServiceJournalBuffer* b, void* data, DWORD size)
{
    if (!b->ok || size > b->size - b->offset) { b->ok = FALSE; return; }
    if (size) { memcpy(data, b->data + b->offset, size); }
    b->offset += size;
}
static void ServiceJournal_Put32(ServiceJournalBuffer* b, DWORD value) { ServiceJournal_Put(b, &value, 4); }
static DWORD ServiceJournal_Get32(ServiceJournalBuffer* b) { DWORD v = 0; ServiceJournal_Get(b, &v, 4); return v; }
static BOOL ServiceJournal_InBounds(const void* base, DWORD size, const void* p, DWORD bytes)
{
    ULONG_PTR start = (ULONG_PTR)base, address = (ULONG_PTR)p;
    return p && address >= start && address - start <= size && bytes <= size - (address - start);
}
/* Reject malformed UTF-16 and embedded/trailing strings; MULTI_SZ permits
 * interior NULs but must have exactly its terminal double NUL. */
static BOOL ServiceJournal_TextValid(const wchar_t* s, DWORD bytes, BOOL multi)
{
    DWORD i, count = bytes / 2;
    if (sizeof(wchar_t) != 2 || bytes % 2 || count < (multi ? 2UL : 1UL) || s[count - 1] || (multi && s[count - 2])) { return FALSE; }
    for (i = 0; i < count; ++i)
    {
        unsigned int c = (unsigned short)s[i];
        if (c >= 0xd800 && c <= 0xdbff)
        {
            if (++i >= count || (unsigned short)s[i] < 0xdc00 || (unsigned short)s[i] > 0xdfff) { return FALSE; }
        }
        else if (c >= 0xdc00 && c <= 0xdfff) { return FALSE; }
        else if (!c && ((!multi && i + 1 != count) || (multi && i + 1 < count && !s[i + 1] && i + 2 != count))) { return FALSE; }
    }
    return TRUE;
}
static void ServiceJournal_PutText(ServiceJournalBuffer* b, const void* base, DWORD size, const wchar_t* s, BOOL multi)
{
    DWORD bytes = 0;
    if (!s) { ServiceJournal_Put32(b, SERVICE_JOURNAL_NULL); return; }
    if (((ULONG_PTR)s & 1) || !ServiceJournal_InBounds(base, size, s, 2)) { b->ok = FALSE; return; }
    do
    {
        if (!ServiceJournal_InBounds(base, size, s, bytes + 2)) { b->ok = FALSE; return; }
        bytes += 2;
        if (!s[bytes / 2 - 1] && (!multi || (bytes >= 4 && !s[bytes / 2 - 2]))) { break; }
    } while (bytes <= SERVICE_BINDING_MAX_BYTES);
    if (!ServiceJournal_TextValid(s, bytes, multi)) { b->ok = FALSE; return; }
    ServiceJournal_Put32(b, bytes); ServiceJournal_Put(b, s, bytes);
}
static wchar_t* ServiceJournal_GetText(ServiceJournalBuffer* b, BYTE* arena, DWORD* used, BOOL multi)
{
    DWORD bytes = ServiceJournal_Get32(b);
    wchar_t* s;
    if (bytes == SERVICE_JOURNAL_NULL) { return NULL; }
    if (!b->ok || bytes > SERVICE_BINDING_MAX_BYTES - *used || bytes > b->size - b->offset) { b->ok = FALSE; return NULL; }
    s = (wchar_t*)(arena + *used);
    ServiceJournal_Get(b, s, bytes);
    if (!ServiceJournal_TextValid(s, bytes, multi)) { b->ok = FALSE; return NULL; }
    *used += bytes;
    return s;
}
static DWORD ServiceJournal_Checksum(const BYTE* bytes, DWORD size)
{
    DWORD value = 2166136261UL, i;
    for (i = 0; i < size; ++i) { value = (value ^ bytes[i]) * 16777619UL; }
    return value;
}
static BOOL ServiceJournal_SecurityValid(const BYTE* data, DWORD size)
{
    SECURITY_DESCRIPTOR_RELATIVE sd;
    DWORD offsets[4], i;
    if (size < sizeof(sd) || size > SERVICE_BINDING_MAX_BYTES) { return FALSE; }
    memcpy(&sd, data, sizeof(sd));
    if (sd.Revision != SECURITY_DESCRIPTOR_REVISION || !(sd.Control & SE_SELF_RELATIVE)) { return FALSE; }
    offsets[0] = sd.Owner; offsets[1] = sd.Group; offsets[2] = sd.Sacl; offsets[3] = sd.Dacl;
    for (i = 0; i < 4; ++i)
    {
        DWORD off = offsets[i];
        if (!off) { continue; }
        if (off < sizeof(sd) || off % 4 || off > size || size - off < 8) { return FALSE; }
        if (i < 2)
        {
            if (data[off] != SID_REVISION || data[off + 1] > SID_MAX_SUB_AUTHORITIES || (DWORD)(8 + data[off + 1] * 4) > size - off) { return FALSE; }
        }
        else
        {
            ACL acl;
            DWORD pos, j;
            memcpy(&acl, data + off, sizeof(acl));
            if (acl.AclSize < sizeof(acl) || acl.AclSize > size - off) { return FALSE; }
            pos = sizeof(acl);
            for (j = 0; j < acl.AceCount; ++j)
            {
                ACE_HEADER ace;
                if (sizeof(ace) > acl.AclSize - pos) { return FALSE; }
                memcpy(&ace, data + off + pos, sizeof(ace));
                if (ace.AceSize < sizeof(ace) || ace.AceSize > acl.AclSize - pos) { return FALSE; }
                pos += ace.AceSize;
            }
        }
    }
    return IsValidSecurityDescriptor((PSECURITY_DESCRIPTOR)data);
}
static BOOL ServiceJournal_Encode(ServiceJournalBuffer* b, const wchar_t* name, DWORD phase, DWORD fileMask,
    const ServiceBindingSnapshot* s, PSECURITY_DESCRIPTOR const* dacl, const DWORD* attrs)
{
    size_t i;
    const QUERY_SERVICE_CONFIGW* c;
    if ((s && !s->config) || !ServiceJournal_PhaseValid(phase) || fileMask & ~31UL) { return FALSE; }
    c = s ? s->config : NULL;
    ServiceJournal_Put32(b, 0x4a42534dUL); ServiceJournal_Put32(b, 1);
    ServiceJournal_Put32(b, phase); ServiceJournal_Put32(b, fileMask);
    ServiceJournal_PutText(b, name, 512, name, FALSE);
    ServiceJournal_Put32(b, s ? 1 : 0);
    if (s)
    {
    ServiceJournal_Put32(b, (s->running ? 1 : 0) | (s->legacy ? 2 : 0) |
        (s->legacyGroupMember ? 4 : 0) | (s->parametersExisted ? 8 : 0) |
        (s->serviceGroupMember ? 16 : 0));
    if (s->configBytes < sizeof(*c) || s->configBytes > SERVICE_BINDING_MAX_BYTES) { return FALSE; }
    ServiceJournal_Put32(b, c->dwServiceType); ServiceJournal_Put32(b, c->dwStartType);
    ServiceJournal_Put32(b, c->dwErrorControl); ServiceJournal_Put32(b, c->dwTagId);
    ServiceJournal_PutText(b, c, s->configBytes, c->lpBinaryPathName, FALSE);
    ServiceJournal_PutText(b, c, s->configBytes, c->lpLoadOrderGroup, FALSE);
    ServiceJournal_PutText(b, c, s->configBytes, c->lpDependencies, TRUE);
    ServiceJournal_PutText(b, c, s->configBytes, c->lpServiceStartName, FALSE);
    ServiceJournal_PutText(b, c, s->configBytes, c->lpDisplayName, FALSE);
    for (i = 0; i < 5; ++i)
    {
        const BYTE* e = s->extra[i];
        if (!e || s->extraBytes[i] > SERVICE_BINDING_MAX_BYTES) { return FALSE; }
        if (i == 0)
        {
            if (s->extraBytes[i] < sizeof(SERVICE_DESCRIPTIONW)) { return FALSE; }
            ServiceJournal_PutText(b, e, s->extraBytes[i], ((const SERVICE_DESCRIPTIONW*)e)->lpDescription, FALSE);
        }
        else if (i == 1)
        {
            const SERVICE_FAILURE_ACTIONSW* a = (const SERVICE_FAILURE_ACTIONSW*)e;
            DWORD j;
            if (s->extraBytes[i] < sizeof(*a) || a->cActions > SERVICE_BINDING_MAX_BYTES / sizeof(SC_ACTION) ||
                (a->cActions && !ServiceJournal_InBounds(e, s->extraBytes[i], a->lpsaActions, a->cActions * sizeof(SC_ACTION)))) { return FALSE; }
            ServiceJournal_Put32(b, a->dwResetPeriod);
            ServiceJournal_PutText(b, e, s->extraBytes[i], a->lpRebootMsg, FALSE);
            ServiceJournal_PutText(b, e, s->extraBytes[i], a->lpCommand, FALSE);
            ServiceJournal_Put32(b, a->cActions);
            for (j = 0; j < a->cActions; ++j) { ServiceJournal_Put32(b, a->lpsaActions[j].Type); ServiceJournal_Put32(b, a->lpsaActions[j].Delay); }
        }
        else { if (s->extraBytes[i] < 4) { return FALSE; } ServiceJournal_Put(b, e, 4); }
    }
    for (i = 0; i < _countof(s->values); ++i)
    {
        const ServiceBindingValue* v = &s->values[i];
        if (v->size > SERVICE_BINDING_MAX_BYTES || (v->size && !v->data)) { return FALSE; }
        ServiceJournal_Put32(b, v->present ? 1 : 0); ServiceJournal_Put32(b, v->type);
        ServiceJournal_Put32(b, v->present ? v->size : 0); if (v->present) { ServiceJournal_Put(b, v->data, v->size); }
    }
    }
    for (i = 0; i < 5; ++i)
    {
        DWORD size = dacl && dacl[i] ? GetSecurityDescriptorLength(dacl[i]) : 0;
        if (size && !ServiceJournal_SecurityValid((const BYTE*)dacl[i], size)) { return FALSE; }
        if (ServiceJournal_PhaseRequiresBackups(phase) && (fileMask & (1UL << i)) && !size) { return FALSE; }
        ServiceJournal_Put32(b, attrs ? attrs[i] : INVALID_FILE_ATTRIBUTES);
        ServiceJournal_Put32(b, size); if (size) { ServiceJournal_Put(b, dacl[i], size); }
    }
    if (!b->ok) { return FALSE; }
    ServiceJournal_Put32(b, ServiceJournal_Checksum(b->data, b->offset));
    return b->ok;
}
static ServiceJournalRecord* ServiceJournal_Decode(ServiceJournalBuffer* b, const wchar_t* name)
{
    ServiceJournalRecord* r = (ServiceJournalRecord*)calloc(1, sizeof(*r));
    ServiceBindingSnapshot* s;
    QUERY_SERVICE_CONFIGW* c;
    DWORD used, flags, checksum;
    size_t i;
    wchar_t savedName[256];
    if (!r) { return NULL; }
    s = NULL;
    if (b->size < 24 || b->size > SERVICE_JOURNAL_MAX_BYTES) { goto fail; }
    memcpy(&checksum, b->data + b->size - 4, 4);
    if (checksum != ServiceJournal_Checksum(b->data, b->size - 4)) { goto fail; }
    b->size -= 4;
    if (ServiceJournal_Get32(b) != 0x4a42534dUL || ServiceJournal_Get32(b) != 1) { goto fail; }
    r->phase = ServiceJournal_Get32(b); r->fileMask = ServiceJournal_Get32(b);
    if (!ServiceJournal_PhaseValid(r->phase) || r->fileMask & ~31UL) { goto fail; }
    used = ServiceJournal_Get32(b);
    if (used > sizeof(savedName) || used > b->size - b->offset) { goto fail; }
    ServiceJournal_Get(b, savedName, used);
    if (!b->ok || !ServiceJournal_TextValid(savedName, used, FALSE) || _wcsicmp(name, savedName)) { goto fail; }
    flags = ServiceJournal_Get32(b);
    if (!b->ok || flags > 1) { goto fail; }
    if (flags)
    {
    r->binding = s = (ServiceBindingSnapshot*)calloc(1, sizeof(*s));
    if (!s) { goto fail; }
    flags = ServiceJournal_Get32(b);
    if (flags & ~31UL) { goto fail; }
    s->running = (flags & 1) != 0; s->legacy = (flags & 2) != 0;
    s->legacyGroupMember = (flags & 4) != 0; s->parametersExisted = (flags & 8) != 0;
    s->serviceGroupMember = (flags & 16) != 0;
    s->config = c = (QUERY_SERVICE_CONFIGW*)calloc(1, SERVICE_BINDING_MAX_BYTES);
    if (!c) { goto fail; }
    used = sizeof(*c); s->configBytes = SERVICE_BINDING_MAX_BYTES;
    c->dwServiceType = ServiceJournal_Get32(b); c->dwStartType = ServiceJournal_Get32(b);
    c->dwErrorControl = ServiceJournal_Get32(b); c->dwTagId = ServiceJournal_Get32(b);
    c->lpBinaryPathName = ServiceJournal_GetText(b, (BYTE*)c, &used, FALSE);
    c->lpLoadOrderGroup = ServiceJournal_GetText(b, (BYTE*)c, &used, FALSE);
    c->lpDependencies = ServiceJournal_GetText(b, (BYTE*)c, &used, TRUE);
    c->lpServiceStartName = ServiceJournal_GetText(b, (BYTE*)c, &used, FALSE);
    c->lpDisplayName = ServiceJournal_GetText(b, (BYTE*)c, &used, FALSE);
    if (!b->ok || !c->lpBinaryPathName || !c->lpDisplayName || !c->lpServiceStartName ||
        _wcsicmp(c->lpServiceStartName, L"LocalSystem") || c->dwStartType > SERVICE_DISABLED ||
        c->dwErrorControl > SERVICE_ERROR_CRITICAL ||
        (c->dwServiceType != SERVICE_WIN32_OWN_PROCESS && c->dwServiceType != SERVICE_WIN32_SHARE_PROCESS)) { goto fail; }
    for (i = 0; i < 5; ++i)
    {
        BYTE* e = s->extra[i] = (BYTE*)calloc(1, SERVICE_BINDING_MAX_BYTES);
        if (!e) { goto fail; }
        s->extraBytes[i] = SERVICE_BINDING_MAX_BYTES;
        if (i == 0) { used = sizeof(SERVICE_DESCRIPTIONW); ((SERVICE_DESCRIPTIONW*)e)->lpDescription = ServiceJournal_GetText(b, e, &used, FALSE); }
        else if (i == 1)
        {
            SERVICE_FAILURE_ACTIONSW* a = (SERVICE_FAILURE_ACTIONSW*)e;
            DWORD j;
            used = sizeof(*a); a->dwResetPeriod = ServiceJournal_Get32(b);
            a->lpRebootMsg = ServiceJournal_GetText(b, e, &used, FALSE);
            a->lpCommand = ServiceJournal_GetText(b, e, &used, FALSE);
            used = (used + 7) & ~7UL;
            a->cActions = ServiceJournal_Get32(b);
            if (!b->ok || a->cActions > (SERVICE_BINDING_MAX_BYTES - used) / sizeof(SC_ACTION)) { goto fail; }
            a->lpsaActions = a->cActions ? (SC_ACTION*)(e + used) : NULL;
            for (j = 0; j < a->cActions; ++j)
            {
                DWORD type = ServiceJournal_Get32(b);
                if (type > SC_ACTION_RUN_COMMAND) { goto fail; }
                a->lpsaActions[j].Type = (SC_ACTION_TYPE)type;
                a->lpsaActions[j].Delay = ServiceJournal_Get32(b);
            }
        }
        else { ServiceJournal_Get(b, e, 4); }
        if (!b->ok) { goto fail; }
    }
    for (i = 0; i < _countof(s->values); ++i)
    {
        ServiceBindingValue* v = &s->values[i];
        DWORD present = ServiceJournal_Get32(b);
        v->present = present == 1; v->type = ServiceJournal_Get32(b); v->size = ServiceJournal_Get32(b);
        if (!b->ok || present > 1 || (!present && v->size) || v->size > SERVICE_BINDING_MAX_BYTES || v->size > b->size - b->offset) { goto fail; }
        if (v->size)
        {
            v->data = (BYTE*)malloc(v->size);
            if (!v->data) { goto fail; }
            ServiceJournal_Get(b, v->data, v->size);
        }
    }
    }
    for (i = 0; i < 5; ++i)
    {
        DWORD size;
        r->attributes[i] = ServiceJournal_Get32(b); size = ServiceJournal_Get32(b);
        if (!b->ok || size > SERVICE_BINDING_MAX_BYTES || size > b->size - b->offset) { goto fail; }
        if (ServiceJournal_PhaseRequiresBackups(r->phase) && (r->fileMask & (1UL << i)) && !size) { goto fail; }
        if (size)
        {
            r->dacl[i] = malloc(size);
            if (!r->dacl[i]) { goto fail; }
            ServiceJournal_Get(b, r->dacl[i], size);
            if (!ServiceJournal_SecurityValid((const BYTE*)r->dacl[i], size)) { goto fail; }
        }
    }
    if (!b->ok || b->offset != b->size) { goto fail; }
    return r;
fail:
    ServiceJournal_Free(r); return NULL;
}
#ifndef SERVICE_JOURNAL_CODEC_ONLY
static BOOL ServiceJournal_Save(const wchar_t* path, const wchar_t* name, DWORD phase, DWORD fileMask,
    const ServiceBindingSnapshot* binding, PSECURITY_DESCRIPTOR const* dacl, const DWORD* attributes)
{
    ServiceJournalBuffer b = {0};
    wchar_t temp[MAX_PATH];
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    BOOL ok = FALSE;
    if (_snwprintf_s(temp, _countof(temp), _TRUNCATE, L"%ls.tmp", path) < 0) { return FALSE; }
    b.data = (BYTE*)malloc(SERVICE_JOURNAL_MAX_BYTES); b.size = SERVICE_JOURNAL_MAX_BYTES; b.ok = TRUE;
    if (!b.data || !ServiceJournal_Encode(&b, name, phase, fileMask, binding, dacl, attributes)) { goto done; }
    /* A prior crash may leave only the unpublished temporary checkpoint. */
    DeleteFileW(temp);
    file = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE) { goto done; }
    ok = WriteFile(file, b.data, b.offset, &written, NULL) && written == b.offset && FlushFileBuffers(file);
    CloseHandle(file); file = INVALID_HANDLE_VALUE;
    if (ok) { ok = MoveFileExW(temp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH); }
done:
    if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); }
    if (!ok) { DeleteFileW(temp); }
    free(b.data); return ok;
}
/* Absence is success with *record == NULL; malformed/unreadable is failure. */
static BOOL ServiceJournal_Load(const wchar_t* path, const wchar_t* name, ServiceJournalRecord** record)
{
    ServiceJournalBuffer b = {0};
    HANDLE file;
    LARGE_INTEGER size;
    DWORD read = 0;
    BOOL ok = FALSE;
    *record = NULL;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) { DWORD error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND; }
    {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(file, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) { goto done; }
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 24 || size.QuadPart > SERVICE_JOURNAL_MAX_BYTES) { goto done; }
    b.size = (DWORD)size.QuadPart; b.data = (BYTE*)malloc(b.size); b.ok = TRUE;
    if (!b.data || !ReadFile(file, b.data, b.size, &read, NULL) || read != b.size) { goto done; }
    *record = ServiceJournal_Decode(&b, name); ok = *record != NULL;
done:
    CloseHandle(file); free(b.data); return ok;
}
#endif
#endif
