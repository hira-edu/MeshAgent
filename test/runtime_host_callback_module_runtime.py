"""Exercise production callback admission under real rundll32 without an SCM install."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda match: ' ' * len(match.group()), source, flags=re.S)
    match = re.search(r'(?:static )?(?:BOOL|void) (?:CALLBACK )?' + name + r'\s*\([^;{]+\)\s*\{', masked)
    if not match:
        raise ValueError('Missing production function: ' + name)
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'win32':
        parser.error('Requires Windows and MSBuild C++ tools')
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    host = (ROOT / 'meshservice/service_host.c').read_text(encoding='utf-8-sig')
    runtime = (ROOT / 'meshservice/runtime_host_contract.c').read_text(encoding='utf-8-sig')
    prelude = r'''
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <strsafe.h>
#define MESH_RUNTIME_HOST_ENTRY_SERVICE_W L"MeshServiceHostW"
#define ServiceHost_LogLine(...) ((void)0)
static SERVICE_STATUS g_ServiceHostStatus;
static void WINAPI ServiceHost_ServiceMain(DWORD argc, LPWSTR* argv)
{ UNREFERENCED_PARAMETER(argc); UNREFERENCED_PARAMETER(argv); }
static BOOL FixtureDispatch(SERVICE_TABLE_ENTRYW* table)
{
    wchar_t marker[MAX_PATH * 4] = {0};
    FILE* output = NULL;
    if (!table[0].lpServiceProc || table[1].lpServiceProc ||
        !GetEnvironmentVariableW(L"MESH_CALLBACK_MARKER", marker, ARRAYSIZE(marker)) ||
        _wfopen_s(&output, marker, L"wb") != 0) { return FALSE; }
    fputs("SCM_DISPATCH_REACHED", output);
    fclose(output);
    return TRUE;
}
#define StartServiceCtrlDispatcherW FixtureDispatch
'''
    code = prelude + '\n'.join([
        function(runtime, 'MeshRuntimeHost_FileExistsW'),
        function(runtime, 'MeshRuntimeHost_GetSystemHostPathW'),
        function(host, 'ServiceHost_BuildImagePath'),
        function(host, 'ServiceHost_ParseImagePath'),
        function(host, 'MeshServiceHostW')])
    (evidence / 'callback-host.c').write_text(code, encoding='utf-8')
    (evidence / 'callback-host.def').write_text('EXPORTS\nMeshServiceHostW\n', encoding='utf-8')
    project = r'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
<PropertyGroup Label="Globals"><WindowsTargetPlatformVersion>10.0.22621.0</WindowsTargetPlatformVersion></PropertyGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
<PropertyGroup Label="Configuration"><ConfigurationType>DynamicLibrary</ConfigurationType><PlatformToolset>v143</PlatformToolset></PropertyGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
<PropertyGroup><OutDir>$(MSBuildProjectDirectory)\bin\</OutDir><IntDir>$(OutDir)obj\</IntDir><TargetName>callback-host</TargetName></PropertyGroup>
<ItemDefinitionGroup><ClCompile><WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError><PreprocessorDefinitions>UNICODE;_UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions></ClCompile><Link><ModuleDefinitionFile>callback-host.def</ModuleDefinitionFile><SubSystem>Windows</SubSystem></Link></ItemDefinitionGroup>
<ItemGroup><ClCompile Include="callback-host.c" /></ItemGroup>
<Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>'''
    project_path = evidence / 'callback-host.vcxproj'
    project_path.write_text(project, encoding='utf-8')
    build = subprocess.run(['msbuild', str(project_path), '/nologo', '/verbosity:minimal',
                            '/p:Configuration=Release', '/p:Platform=x64'], capture_output=True, text=True, timeout=120)
    (evidence / 'build.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        raise RuntimeError(build.stdout + build.stderr)
    dll = evidence / 'bin/callback-host.dll'
    marker = evidence / 'dispatch-marker.txt'
    host_exe = Path(os.environ['SystemRoot']) / 'System32/rundll32.exe'
    env = {**os.environ, 'MESH_CALLBACK_MARKER': str(marker)}
    rows = []
    for label, suffix, expected in [('canonical', '', 0), ('extra-argument', ' extra', 87)]:
        marker.unlink(missing_ok=True)
        command = f'"{host_exe}" "{dll}",MeshServiceHostW{suffix}'
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
        reached = marker.exists() and marker.read_text() == 'SCM_DISPATCH_REACHED'
        ok = result.returncode == expected and reached == (label == 'canonical')
        rows.append({'name': label, 'command': command, 'exitCode': result.returncode,
                     'dispatchReached': reached, 'stdout': result.stdout, 'stderr': result.stderr, 'ok': ok})
        print(('PASS ' if ok else 'FAIL ') + label)
    (evidence / 'result.json').write_text(json.dumps({'success': all(row['ok'] for row in rows), 'cases': rows}, indent=2))
    if not all(row['ok'] for row in rows):
        raise RuntimeError('Real rundll32 callback admission failed')


if __name__ == '__main__':
    main()
