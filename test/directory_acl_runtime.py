"""Check intended authenticated read/execute access without granting writes; never launch an agent."""

import argparse
import json
import pathlib
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <authz.h>
#include <stdio.h>
#include "stealth_defaults.h"

int main(void)
{
    const wchar_t* descriptors[] = {
        L"O:SYG:SY" STEALTH_SECURE_DIR_DACL_SDDL, L"O:SYG:SY" STEALTH_INSTALL_ROOT_DACL_SDDL,
        L"O:SYG:SY" STEALTH_HOST_EXE_DACL_SDDL, L"O:SYG:SY" STEALTH_SVCHOST_DLL_DACL_SDDL
    };
    const char* names[] = { "data-directory", "install-root", "host-exe", "service-dll" };
    const wchar_t* principals[] = { L"S-1-5-18", L"S-1-5-32-544", L"S-1-5-11", L"S-1-5-4", L"S-1-5-32-545", L"S-1-1-0" };
    const char* labels[] = { "SYSTEM", "Administrators", "AuthenticatedUsers", "Interactive", "Users", "Everyone" };
    const DWORD rights[] = { FILE_READ_DATA, FILE_WRITE_DATA, FILE_EXECUTE };
    const char* rightsNames[] = { "read", "write", "execute" };
    AUTHZ_RESOURCE_MANAGER_HANDLE manager = NULL;
    unsigned int failures = 0, checks = 0;
    if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, NULL, NULL, NULL, L"ACL regression", &manager)) { return 2; }
    for (unsigned int d = 0; d < ARRAYSIZE(descriptors); ++d)
    {
        PSECURITY_DESCRIPTOR descriptor = NULL;
        PACL acl = NULL;
        BOOL present = FALSE, defaulted = FALSE;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptors[d], SDDL_REVISION_1, &descriptor, NULL)) { return 2; }
        if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || !acl) { return 2; }
        // Data directories intentionally inherit Authenticated Users read/execute.
        // Root/helper read permissions remain scoped to those objects.
        for (DWORD a = 0; a < acl->AceCount; ++a)
        {
            ACCESS_ALLOWED_ACE* ace = NULL;
            if (!GetAce(acl, a, (void**)&ace) || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) { return 2; }
            BOOL privileged = IsWellKnownSid(&ace->SidStart, WinLocalSystemSid) || IsWellKnownSid(&ace->SidStart, WinBuiltinAdministratorsSid);
            BYTE inheritance = ace->Header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
            BOOL ok = privileged || (d == 0 ?
                IsWellKnownSid(&ace->SidStart, WinAuthenticatedUserSid) && inheritance == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) :
                inheritance == 0);
            ++checks;
            if (!ok) { ++failures; }
            printf("%s %s ace-%lu scope\n", ok ? "PASS" : "FAIL", names[d], a);
        }
        for (unsigned int p = 0; p < ARRAYSIZE(principals); ++p)
        {
            PSID sid = NULL;
            AUTHZ_CLIENT_CONTEXT_HANDLE context = NULL;
            LUID id = { 0 };
            if (!ConvertStringSidToSidW(principals[p], &sid)) { return 2; }
            // Synthetic identities: no token, group lookup, account or host changes.
            if (!AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, sid, manager, NULL, id, NULL, &context)) { return 2; }
            for (unsigned int r = 0; r < ARRAYSIZE(rights); ++r)
            {
                AUTHZ_ACCESS_REQUEST request = { 0 };
                AUTHZ_ACCESS_REPLY reply = { 0 };
                DWORD granted = 0, error = 0;
                request.DesiredAccess = rights[r];
                reply.ResultListLength = 1;
                reply.GrantedAccessMask = &granted;
                reply.Error = &error;
                if (!AuthzAccessCheck(0, context, &request, NULL, descriptor, NULL, 0, &reply, NULL)) { return 2; }
                BOOL expected = p < 2 || ((p == 2 || (d != 0 && p == 3)) && r != 1);
                BOOL allowed = error == ERROR_SUCCESS && (granted & rights[r]) == rights[r];
                BOOL ok = (error == ERROR_SUCCESS || error == ERROR_ACCESS_DENIED) && allowed == expected;
                ++checks;
                if (!ok) { ++failures; }
                printf("%s %s %s %s allowed=%d expected=%d error=%lu\n", ok ? "PASS" : "FAIL", names[d], labels[p], rightsNames[r], allowed, expected, error);
            }
            if (!AuthzFreeContext(context)) { return 2; }
            LocalFree(sid);
        }
        LocalFree(descriptor);
    }
    if (!AuthzFreeResourceManager(manager)) { return 2; }
    printf("checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
'''

PROJECT = r'''<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration>
    <ProjectConfiguration Include="Release|Win32"><Configuration>Release</Configuration><Platform>Win32</Platform></ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals"><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset></PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup><OutDir>$(MSBuildProjectDirectory)\$(Platform)\</OutDir><IntDir>$(OutDir)obj\</IntDir><TargetName>acl-test</TargetName></PropertyGroup>
  <ItemDefinitionGroup>
    <ClCompile><WarningLevel>Level4</WarningLevel><TreatWarningAsError>true</TreatWarningAsError></ClCompile>
    <Link><SubSystem>Console</SubSystem><AdditionalDependencies>authz.lib;advapi32.lib;%(AdditionalDependencies)</AdditionalDependencies></Link>
  </ItemDefinitionGroup>
  <ItemGroup><ClCompile Include="acl-test.c" /></ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    parser.add_argument("--header", type=pathlib.Path, default=ROOT / "meshservice/stealth_defaults.h")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows and MSBuild C++ tools are required")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.header, evidence / "stealth_defaults.h")
    (evidence / "acl-test.c").write_text(FIXTURE, encoding="utf-8")
    project = evidence / "acl-test.vcxproj"
    project.write_text(PROJECT, encoding="utf-8")
    rows = []
    for platform in ["x64", "Win32"]:
        build = subprocess.run(["msbuild", str(project), "/nologo", "/verbosity:minimal",
                                "/p:Configuration=Release", "/p:Platform=" + platform],
                               capture_output=True, text=True, timeout=120)
        (evidence / (platform + "-build.log")).write_text(build.stdout + build.stderr, encoding="utf-8")
        if build.returncode:
            raise RuntimeError(build.stdout + build.stderr)
        result = subprocess.run([str(evidence / platform / "acl-test.exe")],
                                capture_output=True, text=True, timeout=15)
        (evidence / (platform + "-access.log")).write_text(result.stdout + result.stderr, encoding="utf-8")
        rows.append({"platform": platform, "passed": result.returncode == 0,
                     "exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        print(("PASS " if result.returncode == 0 else "FAIL ") + platform + " authenticated read/execute and write restrictions")
    report = {"ok": all(row["passed"] for row in rows), "agentExecuted": False,
              "hostPermissionsChanged": False, "results": rows}
    (evidence / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
