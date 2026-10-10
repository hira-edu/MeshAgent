#!/usr/bin/env python3
"""Compile real copied-loader admission; read Windows trust and disposable files.

No service/registry mutations or certificate installation. Signature verification
uses the production cache-only policy. A real system/copy positive is mandatory.
"""
import os
import ctypes
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = r'''
#include <assert.h>
#include <stdio.h>
#include "service_legacy_host.h"
#include <sddl.h>
static void permissions(const wchar_t* sddl, BOOL protectedRoot, BOOL expected) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    assert(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL));
    BOOL actual = ServiceLegacyHost_PermissionsSupported(descriptor, protectedRoot);
    if (actual != expected) { fwprintf(stderr,L"ACL expected=%d actual=%d protectedRoot=%d SDDL=%ls\n",expected,actual,protectedRoot,sddl); abort(); }
    LocalFree(descriptor);
}
static void permissionTests(void) {
    const wchar_t* root = L"O:BAG:BAD:PAI(A;OI;0x1200a9;;;IU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    const wchar_t* file = L"O:BAG:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;IU)";
    permissions(root, TRUE, TRUE);
    permissions(file, FALSE, TRUE);
    permissions(file, TRUE, FALSE);
    permissions(L"O:SYD:P(A;;GA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;WD)", TRUE, TRUE);
    /* Multiple applicable allow ACEs may jointly grant effective full control. */
    permissions(L"O:BAD:P(A;;0x1200a9;;;SY)(A;;0xd0156;;;SY)(A;;FA;;;BA)", TRUE, TRUE);
    permissions(L"O:WDD:P(A;;FA;;;SY)(A;;FA;;;BA)", TRUE, FALSE);
    permissions(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", TRUE, FALSE);
    permissions(L"O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)", TRUE, FALSE);
    permissions(L"O:BAD:P", TRUE, FALSE);
    permissions(L"O:BAD:P(A;;FA;;;SY)", TRUE, FALSE);
    permissions(L"O:BAD:P(A;;FRFX;;;SY)(A;;FA;;;BA)", TRUE, FALSE);
    permissions(L"O:BAD:P(A;OICIIO;FA;;;SY)(A;;FA;;;BA)", TRUE, FALSE);
    permissions(L"O:BAD:P(A;;FA;;;SY)(A;OICIIO;FA;;;BA)", TRUE, FALSE);
    permissions(L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(D;;FW;;;WD)", TRUE, FALSE);
    const wchar_t* badMasks[] = {L"FA",L"FW",L"GW",L"GA",L"SD",L"WD",L"WO",L"0x2",L"0x4",L"0x10",L"0x40",L"0x100",L"0x200",L"0x1000000",L"0x2000000"};
    for (size_t i=0;i<_countof(badMasks);++i) {
        wchar_t sddl[160];
        assert(_snwprintf_s(sddl,_countof(sddl),_TRUNCATE,L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;%ls;;;WD)",badMasks[i])>0);
        permissions(sddl,TRUE,FALSE);
    }
    /* Reject unsafe inherited/inherit-only grants as well as effective grants. */
    permissions(L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;OICIIO;FW;;;IU)",TRUE,FALSE);
    permissions(L"O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FW;;;IU)",FALSE,FALSE);
    SECURITY_DESCRIPTOR absent, nullDacl;
    assert(InitializeSecurityDescriptor(&absent,SECURITY_DESCRIPTOR_REVISION));
    assert(InitializeSecurityDescriptor(&nullDacl,SECURITY_DESCRIPTOR_REVISION));
    BYTE owner[SECURITY_MAX_SID_SIZE]; DWORD ownerSize=sizeof(owner);
    assert(CreateWellKnownSid(WinBuiltinAdministratorsSid,NULL,owner,&ownerSize));
    assert(SetSecurityDescriptorOwner(&absent,owner,FALSE));
    assert(SetSecurityDescriptorOwner(&nullDacl,owner,FALSE));
    assert(SetSecurityDescriptorDacl(&nullDacl,TRUE,NULL,FALSE));
    assert(!ServiceLegacyHost_PermissionsSupported(&absent,FALSE));
    assert(!ServiceLegacyHost_PermissionsSupported(&nullDacl,FALSE));
    assert(!ServiceLegacyHost_PermissionsSupported(NULL,FALSE));
    PSECURITY_DESCRIPTOR descriptor=NULL; PACL dacl=NULL; BOOL present,defaulted; ACE_HEADER* ace=NULL;
    assert(ConvertStringSecurityDescriptorToSecurityDescriptorW(root,SDDL_REVISION_1,&descriptor,NULL));
    assert(GetSecurityDescriptorDacl(descriptor,&present,&dacl,&defaulted));
    assert(GetAce(dacl,0,(LPVOID*)&ace));
    BYTE originalType=ace->AceType;
    ace->AceType=ACCESS_ALLOWED_OBJECT_ACE_TYPE;
    assert(!ServiceLegacyHost_PermissionsSupported(descriptor,TRUE));
    ace->AceType=0x7f;
    assert(!ServiceLegacyHost_PermissionsSupported(descriptor,TRUE));
    ace->AceType=originalType; ace->AceFlags|=SUCCESSFUL_ACCESS_ACE_FLAG;
    assert(!ServiceLegacyHost_PermissionsSupported(descriptor,TRUE));
    LocalFree(descriptor);
    assert(!ServiceLegacyHost_ValidatePermissions(NULL,TRUE));
    assert(!ServiceLegacyHost_ValidatePermissions(L"C:\\nonexistent-mesh-legacy-acl-fixture\\missing.exe",FALSE));
    puts("copied-host ACL: observed protected root and inherited file accepted; writable, untrusted, unprotected, absent/null, unknown and incomplete grants rejected");
}
int wmain(int argc, wchar_t** argv) {
    wchar_t host[MAX_PATH], normalized[MAX_PATH];
    if (argc == 3) {
        BOOL catalog = !_wcsnicmp(argv[1], L"catalog-", 8);
        BOOL expected = !_wcsicmp(argv[1] + (catalog ? 8 : 0), L"valid");
        BOOL actual;
        if (catalog) {
            HANDLE file=CreateFileW(argv[2],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
            assert(file!=INVALID_HANDLE_VALUE);
            actual=ServiceLegacyHost_VerifyCatalog(argv[2],file);CloseHandle(file);
        } else { actual = ServiceLegacyHost_ValidateFile(argv[2]); }
        DWORD error = GetLastError();
        if (actual != expected) { fwprintf(stderr,L"expected=%d actual=%d error=0x%08lx file=%ls\n",expected,actual,error,argv[2]); return 1; }
        return 0;
    }
    permissionTests();
    const wchar_t* good[] = {
        L"C:\\Agent\\svchost.exe -k netsvcs",
        L"C:\\Agent\\svchost.exe -k netsvcs -p",
        L"\"C:\\Agent\\svchost.exe\" -k netsvcs",
        L"\"C:\\Agent\\svchost.exe\" -k netsvcs -p"
    };
    for (size_t i=0;i<_countof(good);++i) {
        assert(ServiceLegacyHost_ParseImage(good[i],L"C:\\Agent\\agent.dll",host,MAX_PATH));
        assert(!_wcsicmp(host,L"C:\\Agent\\svchost.exe"));
    }
    assert(ServiceLegacyHost_ParseImage(L"\"C:\\Agent Space\\svchost.exe\" -k netsvcs",L"C:\\Agent Space\\agent.dll",host,MAX_PATH));
    const wchar_t* bad[] = {
        L"C:\\Other\\svchost.exe -k netsvcs", L"C:\\Agent\\svchost.exe -k evil",
        L"C:\\Agent\\svchost.exe -k netsvcs -p extra", L"C:\\Agent\\svchost.exe -p -k netsvcs",
        L"C:\\Agent\\svchost.exe -k netsvcs2", L"C:\\Agent\\svchost.exe -k netsvcs ",
        L"C:\\Agent\\svchost.exe\t-k netsvcs", L" C:\\Agent\\svchost.exe -k netsvcs",
        L"C:\\Agent\\.\\svchost.exe -k netsvcs", L"C:\\Agent\\..\\Agent\\svchost.exe -k netsvcs",
        L"C:/Agent/svchost.exe -k netsvcs", L"\\\\?\\C:\\Agent\\svchost.exe -k netsvcs",
        L"\\\\server\\Agent\\svchost.exe -k netsvcs", L"C:Agent\\svchost.exe -k netsvcs",
        L"C:\\Agent\\svchost.exe:stream -k netsvcs", L"C:\\Agent\\svchost.exe. -k netsvcs",
        L"C:\\Agent.\\svchost.exe -k netsvcs", L"C:\\Agent \\svchost.exe -k netsvcs",
        L"\"C:\\Agent\\svchost.exe -k netsvcs", L"\"C:\\Agent\\svchost.exe\"x -k netsvcs",
        L"%ProgramData%\\Agent\\svchost.exe -k netsvcs", L"C:\\AGENT~1\\svchost.exe -k netsvcs",
        L"", L"C:\\Agent\\other.exe -k netsvcs",
        L"C:\\\\Agent\\svchost.exe -k netsvcs", L"C:\\Agent\\\\svchost.exe -k netsvcs"
    };
    for(size_t i=0;i<_countof(bad);++i) {
        host[0]='x';assert(!ServiceLegacyHost_ParseImage(bad[i],L"C:\\Agent\\agent.dll",host,MAX_PATH));assert(!host[0]);
    }
    assert(!ServiceLegacyHost_ParseImage(L"C:\\Agent Space\\svchost.exe -k netsvcs",L"C:\\Agent Space\\agent.dll",host,MAX_PATH));
    assert(!ServiceLegacyHost_ParseImage(good[0],L"C:\\Agent\\agent.exe",host,MAX_PATH));
    assert(!ServiceLegacyHost_ParseImage(good[0],L"C:\\Agent\\..\\Agent\\agent.dll",host,MAX_PATH));
    assert(!ServiceLegacyHost_ParseImage(good[0],L"C:\\Agent\\agent.dll",host,3));
    assert(!ServiceLegacyHost_ParseImage(NULL,L"C:\\Agent\\agent.dll",host,MAX_PATH));
    assert(ServiceLegacyHost_NormalizePath(L"C:\\Agent\\agent.dll",normalized,MAX_PATH)&&!wcscmp(normalized,L"C:\\Agent\\agent.dll"));
    assert(!ServiceLegacyHost_NormalizePath(L"C:\\\\Agent\\\\agent.dll",normalized,MAX_PATH)&&!normalized[0]);
    assert(!ServiceLegacyHost_ParseImage(good[0],L"C:\\\\Agent\\agent.dll",host,MAX_PATH));
    assert(!ServiceLegacyHost_NormalizePath(L"C:\\Agent\\.\\agent.dll",normalized,MAX_PATH)&&!normalized[0]);
    assert(!ServiceLegacyHost_NormalizePath(L"C:\\Agent\\agent.dll",normalized,3)&&!normalized[0]);
    assert(!ServiceLegacyHost_IsCanonicalPath(L"C:\\\\Agent\\agent.dll"));
    puts("copied-host parser: exact command accepted; repeated separators and other aliases rejected");
    return 0;
}
'''

if os.name != 'nt':
    raise SystemExit('This probe requires real Windows trust APIs and Windows headers')

with tempfile.TemporaryDirectory(prefix='mesh-legacy-host-') as temporary:
    # The Python installation may choose an 8.3 TEMP path. Production admission
    # intentionally rejects that alias, so use its actual long path for fixtures.
    long_path = ctypes.create_unicode_buffer(32768)
    assert ctypes.windll.kernel32.GetLongPathNameW(temporary, long_path, len(long_path))
    directory = Path(long_path.value)
    source = directory / 'probe.c'
    executable = directory / 'probe.exe'
    source.write_text(DRIVER)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I', str(ROOT / 'meshservice'), str(source), '-o', str(executable),
                    '-lwintrust', '-lcrypt32', '-lversion', '-ladvapi32'], check=True)
    subprocess.run([str(executable)], check=True)

    def verify(path, expected, catalog=False):
        mode = ('catalog-' if catalog else '') + ('valid' if expected else 'invalid')
        subprocess.run([str(executable), mode, str(path)], check=True)

    system = Path(os.environ['WINDIR']) / 'System32'
    verify(system / 'svchost.exe', True)
    copied = directory / 'svchost.exe'
    shutil.copyfile(system / 'svchost.exe', copied)
    verify(copied, True)
    verify(system / 'svchost.exe', True, catalog=True)
    verify(copied, True, catalog=True)
    verify(directory, False)
    verify(directory / 'missing.exe', False)
    verify(executable, False)
    # A trusted Microsoft Windows binary is insufficient without svchost identity.
    wrong = directory / 'other-svchost.exe'
    shutil.copyfile(system / 'kernel32.dll', wrong)
    verify(wrong, False)

    tampered = directory / 'tampered.exe'
    data = bytearray(copied.read_bytes())
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    section = pe + 24 + optional_size
    raw_offset = struct.unpack_from('<I', data, section + 20)[0]
    assert 0 < raw_offset < len(data)
    data[raw_offset] ^= 0x01  # Change a hashed image section, not the excluded checksum.
    tampered.write_bytes(data)
    verify(tampered, False)
    verify(tampered, False, catalog=True)

    import _winapi
    junction = directory / 'junction'
    try:
        _winapi.CreateJunction(str(directory), str(junction))
        verify(junction / 'svchost.exe', False)
    finally:
        if junction.exists():
            os.rmdir(junction)
    print('copied-host native trust: system/copy and catalog membership accepted; unsigned, wrong identity, tampered, missing, directory and junction rejected')
