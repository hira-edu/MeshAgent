"""Exercise the production lifecycle manifest writer/reader using real Windows INI APIs."""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import ctypes
import stat
from xml.sax.saxutils import escape

ROOT = pathlib.Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(r"^(?:static )?(?:BOOL|const wchar_t\*) " + re.escape(name) + r"\(", source, re.M)
    if not match:
        raise ValueError("Function not found: " + name)
    start = source.index("{", match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Requires Windows and MSBuild C++ tools")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source = (ROOT / "meshservice/rundll32_contract.c").read_text(encoding="utf-8-sig")
    definitions = "\n".join(re.findall(r"^#define MESH_LIFECYCLE_.*$", source, re.M))
    names = ["MeshRundll32_FileExistsW", "MeshRundll32_ManifestBoolW", "MeshRundll32_WriteManifestStringW",
             "MeshRundll32_LifecycleActionNameW", "MeshRundll32_LifecycleActionFromStringW",
             "MeshRundll32_ReadLifecycleManifestW", "MeshRundll32_WriteLifecycleManifestW"]
    harness = '#include "rundll32_contract.h"\n#include <stdio.h>\n#include <wchar.h>\n#include <strsafe.h>\n'
    harness += definitions + "\n" + "\n\n".join(function(source, name) for name in names)
    launch_fixture = (ROOT / "test/fixtures/lifecycle_launch_errors.c").read_text()
    harness += "\n" + launch_fixture.replace("/* PRODUCTION_LAUNCHER */", function(source, "MeshRundll32_LaunchLifecycleHostW"))
    harness += r'''
int wmain(int argc, wchar_t** argv)
{
    MeshRundll32LifecycleManifest read;
    BOOL wrote, parsed, equal, exists;
    DWORD error;
    if (argc == 2 && wcscmp(argv[1], L"--launch-errors") == 0) { return TestLaunchErrors(); }
    if (argc == 4 && wcscmp(argv[1], L"--write-error") == 0)
    {
        wrote = MeshRundll32_WriteLifecycleManifestW(argv[2], MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL,
            L"source.exe", NULL, NULL, NULL, TRUE);
        error = GetLastError();
        printf("{\"wrote\":%d,\"error\":%lu}\n", wrote, error);
        return !wrote && error == wcstoul(argv[3], NULL, 10) ? 0 : 1;
    }
    if (argc != 4) { return 2; }
    wrote = MeshRundll32_WriteLifecycleManifestW(argv[1], MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL,
        argv[2], argv[2], argv[3], argv[3], FALSE);
    error = wrote ? ERROR_SUCCESS : GetLastError();
    parsed = wrote && MeshRundll32_ReadLifecycleManifestW(argv[1], &read);
    equal = parsed && wcscmp(read.sourceExePath, argv[2]) == 0 && wcscmp(read.sourceDllPath, argv[2]) == 0 &&
        wcscmp(read.displayName, argv[3]) == 0 && wcscmp(read.serviceDescription, argv[3]) == 0 &&
        read.action == MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL && read.requireConfig == FALSE;
    exists = parsed && GetFileAttributesW(read.sourceExePath) != INVALID_FILE_ATTRIBUTES;
    printf("{\"wrote\":%d,\"parsed\":%d,\"equal\":%d,\"sourceExists\":%d,\"error\":%lu,\"acp\":%u}\n",
        wrote, parsed, equal, exists, error, GetACP());
    return equal && exists ? 0 : 1;
}
'''
    (evidence / "manifest-test.c").write_text(harness, encoding="utf-8")
    project = r'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration>
    <ProjectConfiguration Include="Release|Win32"><Configuration>Release</Configuration><Platform>Win32</Platform></ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals"><WindowsTargetPlatformVersion>10.0.22621.0</WindowsTargetPlatformVersion></PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset></PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup><OutDir>$(MSBuildProjectDirectory)\$(Platform)\</OutDir><IntDir>$(OutDir)obj\</IntDir><TargetName>manifest-test</TargetName></PropertyGroup>
  <ItemDefinitionGroup><ClCompile><WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError>
    <AdditionalIncludeDirectories>REPO_INCLUDE</AdditionalIncludeDirectories><PreprocessorDefinitions>UNICODE;_UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
  </ClCompile><Link><SubSystem>Console</SubSystem></Link></ItemDefinitionGroup>
  <ItemGroup><ClCompile Include="manifest-test.c" /></ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>'''.replace("REPO_INCLUDE", escape(str(ROOT / "meshservice")))
    project_path = evidence / "manifest-test.vcxproj"
    project_path.write_text(project, encoding="utf-8")
    rows = []
    for platform in ["x64", "Win32"]:
        build = subprocess.run(["msbuild", str(project_path), "/nologo", "/verbosity:minimal", "/p:Configuration=Release", "/p:Platform=" + platform],
                               capture_output=True, text=True, timeout=120)
        (evidence / (platform + "-build.log")).write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(build.stdout + build.stderr)
        result = subprocess.run([str(evidence / platform / "manifest-test.exe"), "--launch-errors"], capture_output=True, text=True, timeout=15)
        rows.append({"platform": platform, "name": "launch-errors", "exitCode": result.returncode,
                     "stdout": result.stdout, "stderr": result.stderr, "ok": result.returncode == 0})
        print(("PASS " if result.returncode == 0 else "FAIL ") + platform + " launch-errors")
        for label, folder in [("ascii", "Desktop"), ("chinese", "\u684c\u9762"), ("mixed", "\u684c\u9762-\u0627\u0644\u0645\u0643\u062a\u0628-\U0001f4c1")]:
            case = evidence / (platform + "-" + label)
            package = case / "OneDrive" / folder / "meshagent64-HiraEduDevices (8).exe"
            package.parent.mkdir(parents=True, exist_ok=True)
            package.write_bytes(b"data-only source fixture; never executed")
            manifest = case / "manifest.ini"
            description = "Support " + folder
            for generation in ["new", "rewrite"]:
                if generation == "rewrite":
                    manifest.write_bytes(b"[Lifecycle]\r\nSourceExe=old.exe\r\n")
                result = subprocess.run([str(evidence / platform / "manifest-test.exe"), str(manifest), str(package), description],
                                        capture_output=True, text=True, timeout=15)
                row = {"platform": platform, "name": label + "-" + generation, "exitCode": result.returncode,
                       "stdout": result.stdout, "stderr": result.stderr}
                row["ok"] = result.returncode == 0
                if manifest.exists():
                    data = manifest.read_bytes()
                    row["utf16Bom"] = data.startswith(b"\xff\xfe")
                    row["ok"] = row["ok"] and row["utf16Bom"]
                rows.append(row)
                print(("PASS " if row["ok"] else "FAIL ") + platform + " " + row["name"])
        for label, expected in [("missing-parent", 3), ("read-only", 5), ("locked", 32)]:
            manifest = evidence / (platform + "-" + label + ".ini")
            handle = None
            if label == "missing-parent":
                manifest = manifest / "manifest.ini"
            else:
                manifest.write_bytes(b"original data")
            if label == "read-only":
                manifest.chmod(stat.S_IREAD)
            if label == "locked":
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                              ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
                kernel.CreateFileW.restype = ctypes.c_void_p
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                handle = kernel.CreateFileW(str(manifest), 0x80000000, 0, None, 3, 0, None)
                if handle == ctypes.c_void_p(-1).value:
                    raise ctypes.WinError(ctypes.get_last_error())
            try:
                result = subprocess.run([str(evidence / platform / "manifest-test.exe"), "--write-error", str(manifest), str(expected)],
                                        capture_output=True, text=True, timeout=15)
            finally:
                if handle is not None and not kernel.CloseHandle(handle):
                    raise ctypes.WinError(ctypes.get_last_error())
                if label == "read-only":
                    manifest.chmod(stat.S_IWRITE)
            ok = result.returncode == 0 and (label == "missing-parent" or manifest.read_bytes() == b"original data")
            rows.append({"platform": platform, "name": label, "stdout": result.stdout, "stderr": result.stderr, "ok": ok})
            print(("PASS " if ok else "FAIL ") + platform + " " + label)
    report = {"ok": all(row["ok"] for row in rows), "installerExecuted": False, "rows": rows}
    (evidence / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
