"""Run production historical SCM command classification without mutating services."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
deploy = (ROOT / 'meshservice/service_deployment.c').read_text()
binding = (ROOT / 'meshservice/service_binding_transaction.h').read_text()
host = (ROOT / 'meshservice/service_host.c').read_text()

def extract(source, name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'(?:static )?(?:BOOL|const wchar_t\*)\s*' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}'); end += 1
    return source[match.start():end]

prelude = r'''
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <stdio.h>
#include <wchar.h>
#define MESH_RUNTIME_HOST_ENTRY_LEGACY_SERVICE_W L"MeshServiceHostW"
static const wchar_t *image, *entry, *parameterDll;
static int hijackedPrefix;
static DWORD fixtureAttributes(const wchar_t* path) {
    if(hijackedPrefix&&!_wcsicmp(path,L"C:\\Program.exe"))return FILE_ATTRIBUTE_NORMAL;
    SetLastError(ERROR_FILE_NOT_FOUND);return INVALID_FILE_ATTRIBUTES;
}
#define GetFileAttributesW fixtureAttributes
static BOOL ServiceDeploy_QueryServiceImagePathW(const wchar_t* name,wchar_t* output,size_t cap) {
    (void)name;return image&&SUCCEEDED(StringCchCopyW(output,cap,image));
}
static BOOL ServiceDeploy_ReadServiceParameterString(const wchar_t* name,const wchar_t* key,wchar_t* output,size_t cap) {
    (void)name;const wchar_t* value=!wcscmp(key,L"ServiceMain")?entry:parameterDll;
    return value&&SUCCEEDED(StringCchCopyW(output,cap,value));
}
static BOOL ServiceHost_BuildImagePath(const wchar_t* dll,wchar_t* output,size_t cap) {
    return SUCCEEDED(StringCchPrintfW(output,cap,L"\"C:\\Windows\\System32\\rundll32.exe\" \"%ls\",MeshServiceHostW",dll));
}
static BOOL ServiceHost_IsServiceImagePath(const wchar_t* name,const wchar_t* command) {
    (void)name;return !_wcsicmp(command,L"\"C:\\Windows\\System32\\svchost.exe\" -k scoped-Agent");
}
static UINT fixtureSystem(wchar_t* output,UINT cap) {
    StringCchCopyW(output,cap,L"C:\\Windows\\System32");return (UINT)wcslen(output);
}
#define GetSystemDirectoryW fixtureSystem
'''
cases = r'''
static void accepted(const wchar_t* command,const wchar_t* expected) {
    wchar_t output[MAX_PATH*4];image=command;assert(ServiceDeploy_IsLegacyMeshAgentService(L"Agent",output,_countof(output)));
    assert(!_wcsicmp(output,expected));
}
static void rejected(const wchar_t* command) {
    wchar_t output[MAX_PATH*4];image=command;assert(!ServiceDeploy_IsLegacyMeshAgentService(L"Agent",output,_countof(output)));
}
int main(void) {
    accepted(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Legacy\\diagsvc.dll\",MeshServiceHostW",L"C:\\Legacy\\diagsvc.dll");
    accepted(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Legacy\\meshsvc.dll\",Stealth_SvchostServiceMain",L"C:\\Legacy\\meshsvc.dll");
    accepted(L"C:\\Windows\\System32\\rundll32.exe \"C:\\Legacy\\meshsvc.dll\",Stealth_SvchostServiceMain",L"C:\\Legacy\\meshsvc.dll");
    accepted(L"\"C:\\Windows\\System32\\rundll32.exe\"\t\"C:\\Legacy\\meshsvc.dll\",MeshServiceHostW  ",L"C:\\Legacy\\meshsvc.dll");
    accepted(L"C:\\Program Files\\Mesh Agent\\MeshAgent.exe -run",L"C:\\Program Files\\Mesh Agent\\MeshAgent.exe");
    hijackedPrefix=1;rejected(L"C:\\Program Files\\Mesh Agent\\MeshAgent.exe -run");
    accepted(L"\"C:\\Program Files\\Mesh Agent\\MeshAgent.exe\" -run",L"C:\\Program Files\\Mesh Agent\\MeshAgent.exe");hijackedPrefix=0;
    accepted(L"\"C:\\Historical Names\\diaghost.exe\" -run",L"C:\\Historical Names\\diaghost.exe");
    rejected(L"C:\\Windows\\System32\\cmd.exe /c C:\\Legacy\\MeshAgent.exe");
    rejected(L"\"C:\\fake\\rundll32.exe\" \"C:\\Legacy\\meshsvc.dll\",Stealth_SvchostServiceMain");
    rejected(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Legacy\\meshsvc.dll\",OtherExport");
    rejected(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Legacy\\meshsvc.dll\",Stealth_SvchostServiceMain extra");
    rejected(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Legacy\\..\\meshsvc.dll\",MeshServiceHostW");
    rejected(L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Legacy\\meshsvc.exe\",MeshServiceHostW");
    entry=L"Stealth_SvchostServiceMain";parameterDll=L"C:\\Legacy\\meshsvc.dll";
    accepted(L"%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",parameterDll);
    rejected(L"C:\\fake\\svchost.exe -k netsvcs");rejected(NULL);
    image=L"\"C:\\Windows\\System32\\rundll32.exe\" \"C:\\Legacy\\diagsvc.dll\",MeshServiceHostW";
    wchar_t tiny[1];assert(!ServiceDeploy_IsLegacyMeshAgentService(L"Agent",tiny,_countof(tiny)));
    puts("Historical discovery: quoted/unquoted EXE, old callback, shared host, arguments and foreign hosts passed");return 0;
}
'''
arrays = '\n'.join(re.search(r'static const wchar_t\* const '+name+r'\[\] = \{.*?\};', deploy, re.S).group()
                   for name in ('g_LegacyExeNames',))
production = (extract(host,'ServiceHost_ParseImagePath') + extract(binding,'ServiceBinding_IsLegacyExe') +
              extract(binding,'ServiceBinding_ParseCallbackImage') + extract(binding,'ServiceBinding_ImageSupported') + arrays + extract(deploy,'ServiceDeploy_wcsistr') +
              extract(deploy,'ServiceDeploy_PathContainsLeafInsensitive') + extract(deploy,'ServiceDeploy_ExtractExecutableFromCommand') +
              extract(deploy,'ServiceDeploy_IsLegacyMeshAgentService'))
with tempfile.TemporaryDirectory(prefix='historical-discovery-') as temporary:
    path=Path(temporary); c=path/'fixture.c'; exe=path/'fixture.exe';c.write_text(prelude+production+cases)
    subprocess.run([os.environ.get('CC','clang'),'-std=c11',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
