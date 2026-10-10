#!/usr/bin/env python3
"""Run production transaction-state ACL predicates on real Windows descriptors.

Only the descriptor-read boundary is substituted. No filesystem ACL, service,
registry or installed file is changed; compilation uses a temporary directory.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def extract(source, name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'static BOOL\s+' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]


fixture = r'''
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <assert.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include "service_defaults.h"
static PSECURITY_DESCRIPTOR fixtureDescriptor;
static DWORD readError;
static DWORD descriptorRead(LPWSTR path, SE_OBJECT_TYPE type, SECURITY_INFORMATION requested,
    PSID* owner, PSID* group, PACL* dacl, PACL* sacl, PSECURITY_DESCRIPTOR* output) {
    assert(!wcscmp(path,L"C:\\Agent\\state") && type == SE_FILE_OBJECT);
    assert(!owner && !group && !sacl);
    assert(requested == DACL_SECURITY_INFORMATION || requested == (DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION));
    if(readError) return readError;
    DWORD size=GetSecurityDescriptorLength(fixtureDescriptor);
    *output=LocalAlloc(LMEM_FIXED,size);assert(*output);
    memcpy(*output,fixtureDescriptor,size);
    if(dacl) { BOOL present,defaulted;assert(GetSecurityDescriptorDacl(*output,&present,dacl,&defaulted)); }
    return ERROR_SUCCESS;
}
#define GetNamedSecurityInfoW descriptorRead
'''

cases = r'''
static void check(const wchar_t* sddl, BOOL expected, BOOL current) {
    assert(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&fixtureDescriptor,NULL));
    readError=0;SetLastError(0);
    BOOL result=ServiceDeploy_ValidateTransactionStateDacl(L"C:\\Agent\\state");
    if(result!=expected)fwprintf(stderr,L"expected=%d actual=%d SDDL=%ls\n",expected,result,sddl);
    assert(result==expected);
    if(!expected)assert(GetLastError()==ERROR_ACCESS_DENIED);
    /* General validation keeps requiring the current exact template. */
    assert(ServiceDeploy_ValidatePathDacl(L"C:\\Agent\\state")==current);
    LocalFree(fixtureDescriptor);fixtureDescriptor=NULL;
}
int main(void) {
    check(L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",TRUE,FALSE);
    check(L"O:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",TRUE,FALSE);
    check(L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)",TRUE,TRUE);
    check(L"O:BAD:PAI(A;OICI;0x1200a9;;;AU)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",TRUE,TRUE);
    check(L"O:WDD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;IU)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FW;;;AU)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)",FALSE,FALSE);
    check(L"O:BAD:P(A;;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P(A;OI;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICIIO;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICIID;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICI;FA;;;SY)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P(A;OICI;FRFX;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P(D;;FW;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",FALSE,FALSE);
    check(L"O:BAD:P",FALSE,FALSE);
    check(L"O:BAD:NO_ACCESS_CONTROL",FALSE,FALSE);
    check(L"O:BA",FALSE,FALSE);
    readError=ERROR_SHARING_VIOLATION;
    assert(!ServiceDeploy_ValidateTransactionStateDacl(L"C:\\Agent\\state"));
    assert(GetLastError()==ERROR_SHARING_VIOLATION);
    puts("Transaction state ACL: 21 real descriptors and read failure passed; current general policy unchanged");
    return 0;
}
'''

if os.name != 'nt':
    raise SystemExit('This probe requires Windows security descriptor APIs')
legacy = (ROOT / 'meshservice/service_legacy_host.h').read_text(encoding='utf-8-sig')
deployment = (ROOT / 'meshservice/service_deployment.c').read_text(encoding='utf-8-sig')
production = '\n'.join(extract(legacy, name) for name in (
    'ServiceLegacyHost_NormalizePath', 'ServiceLegacyHost_IsCanonicalPath',
    'ServiceLegacyHost_PermissionsSupported', 'ServiceLegacyHost_ValidatePermissions'))
production += '\n' + '\n'.join(extract(deployment, name) for name in (
    'ServiceDeploy_AclMatchesExpected', 'ServiceDeploy_ValidatePathDaclWithExpected',
    'ServiceDeploy_ValidatePathDacl', 'ServiceDeploy_ValidateTransactionStateDacl'))
with tempfile.TemporaryDirectory(prefix='mesh-transaction-state-acl-') as temporary:
    directory = Path(temporary)
    source, executable = directory / 'probe.c', directory / 'probe.exe'
    source.write_text(fixture + production + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I', str(ROOT / 'meshservice'), str(source), '-o', str(executable), '-ladvapi32'], check=True)
    subprocess.run([str(executable)], check=True)
