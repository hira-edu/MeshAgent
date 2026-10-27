"""Read installer/deployment manifests with the real Windows Unicode profile API."""
import argparse
import ctypes
import importlib.util
import json
import pathlib
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]


def js_function(source, name):
    start = source.find("\nfunction " + name + "(")
    if start < 0:
        raise RuntimeError("Top-level function not found: " + name)
    start += 1
    # These top-level functions end with an unindented closing brace.
    end = source.index("\n}", start) + 2
    return source[start:end]


def js_statement(source, statement):
    if ("\n" + statement + "\n") not in source:
        raise RuntimeError("Top-level statement not found in agent-installer.js: " + statement)
    return statement


# writeWindowsLifecycleManifest and every top-level declaration it reaches, in dependency order.
# A missing entry surfaces as a ReferenceError in the writer's stderr, which the failure reports.
INSTALLER_WRITER_DEPENDENCIES = [
    "installerParameterValue", "installerParameterEx", "installerParameter",
    "getWindowsLifecycleServiceName", "createWindowsLifecycleWorkDir",
    "isWindowsLifecycleServiceNameValid", "sanitizeWindowsLifecycleManifestValue",
    "writeWindowsLifecycleManifest",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    parser.add_argument("--console", type=pathlib.Path, default=ROOT / "meshconsole/Release/MeshConsole64.exe")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Requires Windows, Node.js and a built MeshConsole64.exe")
    if not args.console.is_file():
        parser.error("Built MeshConsole64.exe not found at " + str(args.console) +
                     "; build meshconsole (Release|x64) or pass --console <path>")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    source = str(evidence / "OneDrive" / "\u684c\u9762-\u0627\u0644\u0645\u0643\u062a\u0628-\U0001f4c1" / "meshagent64-Devices (8).exe")
    pathlib.Path(source).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(source).write_bytes(b"data-only fixture; never executed")
    description = "Support \u684c\u9762 \u0645\u0643\u062a\u0628 \U0001f4c1"
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetPrivateProfileStringW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                              ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_wchar_p]
    kernel.GetPrivateProfileStringW.restype = ctypes.c_uint32
    rows = []

    def check(label, manifest, expected):
        values = {}
        for key in expected:
            buf = ctypes.create_unicode_buffer(4096)
            count = kernel.GetPrivateProfileStringW("Lifecycle", key, "", buf, len(buf), str(manifest))
            if count == len(buf) - 1:
                raise RuntimeError("Profile field truncated: " + key)
            values[key] = buf.value
        ok = values == expected and manifest.read_bytes().startswith(b"\xff\xfe")
        rows.append({"writer": label, "ok": ok, "values": values})
        print(("PASS " if ok else "FAIL ") + label)

    installer = (ROOT / "modules/agent-installer.js").read_text(encoding="utf-8-sig")
    functions = js_statement(installer, "var windowsLifecycleWorkDirCount = 0;") + "\n"
    functions += "\n".join(js_function(installer, name) for name in INSTALLER_WRITER_DEPENDENCIES)
    service_name = "Mesh Agent \u684c\u9762 \u0645\u0643\u062a\u0628 \U0001f4c1"
    # runWindowsNativeLifecycle passes the installer's --key=value argument array to the writer.
    parms = ["--displayName=" + description, "--description=" + description, "--meshServiceName=" + service_name]
    for label, executable in [("installer-node", "node"), ("installer-native", str(args.console))]:
        directory = pathlib.Path(tempfile.mkdtemp(prefix=label + "-", dir=evidence))
        # MeshConsole keeps running after an uncaught script exception, so every error must reach process.exit().
        code = functions + "\ntry {\nvar cleanupPaths = [];\n"
        code += "var manifestPath = writeWindowsLifecycleManifest('validate-package'," + json.dumps(source) + ","
        code += json.dumps(source) + "," + json.dumps(parms) + ",cleanupPaths);"
        # Absolute: MeshConsole resolves relative paths against its own directory, not the cwd.
        code += "require('fs').writeFileSync(" + json.dumps(str(directory / "writer-result.json"))
        code += ", JSON.stringify({manifest: manifestPath, cleanup: cleanupPaths}));"
        code += "\n} catch (e) { process.stderr.write('writer failed: ' + (e.stack || e) + '\\n'); process.exit(1); }\n"
        code += "process.exit(0);"
        script = directory / "writer.js"
        script.write_text(code, encoding="ascii")
        # Both engines run the same script file. MeshConsole's -exec copies at most sizeof(ILibScratchPad)
        # (4096) bytes of its argument (meshconsole/main.c), which truncates this script.
        command = [executable, str(script)]
        try:
            result = subprocess.run(command, cwd=directory, env=dict(os.environ, TEMP=str(directory), TMP=str(directory)),
                                    capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        except subprocess.TimeoutExpired as timeout:
            raise RuntimeError(label + " did not exit within 20s; stderr:\n" +
                               (timeout.stderr or b"").decode("utf-8", "replace") + "\nstdout:\n" +
                               (timeout.stdout or b"").decode("utf-8", "replace")) from None
        (directory / "stdout.txt").write_bytes(result.stdout)
        (directory / "stderr.txt").write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(label + " exited " + str(result.returncode) + "; stderr:\n" +
                               result.stderr.decode("utf-8", "replace") + "\nstdout:\n" + result.stdout.decode("utf-8", "replace"))
        # The writer stages each manifest in its own fresh mesh-lifecycle-* work directory under TEMP.
        manifests = list(directory.glob("mesh-lifecycle-*/lifecycle.ini"))
        if len(manifests) != 1 or list(directory.glob("*.ini")):
            raise RuntimeError(label + " did not write exactly one manifest in a lifecycle work directory")
        written = json.loads((directory / "writer-result.json").read_text(encoding="utf-8"))
        if pathlib.Path(written["manifest"]) != manifests[0]:
            raise RuntimeError(label + " returned " + written["manifest"] + " instead of " + str(manifests[0]))
        if [pathlib.Path(p) for p in written["cleanup"]] != [manifests[0].parent, manifests[0]]:
            raise RuntimeError(label + " did not register its work directory and manifest for cleanup: " +
                               json.dumps(written["cleanup"]))
        check(label, manifests[0], {"Action": "validate-package", "SourceExe": source, "SourceDll": source,
                                  "DisplayName": description, "Description": description,
                                  "ServiceName": service_name, "RequireConfig": "1"})

    helper = (ROOT / "test/lib/runtime_host_lifecycle.js").read_text()
    functions = "\n".join(js_function(helper, name) for name in ["sanitizeManifestValue", "writeManifest"])
    manifest = evidence / "test-helper.ini"
    fields = {"action": "validate-package", "sourceExe": source, "sourceDll": source,
              "displayName": description, "description": description, "requireConfig": True}
    code = "const fs=require('fs');\n" + functions + "\nwriteManifest(" + json.dumps(str(manifest)) + "," + json.dumps(fields) + ");"
    subprocess.run(["node", "-e", code], check=True, capture_output=True, timeout=15)
    check("test-helper-node", manifest, {"SourceExe": source, "SourceDll": source, "Description": description})

    # Capture the actual deploy command; execute only its manifest-writing prefix.
    # Explicit fixture paths take precedence over any branding config, so no checkout's
    # branding_config.local.json is read and a worktree without one still has the paths
    # deploy.py requires (require_windows_branding).
    install_root = str(evidence / "install-root")
    deploy_branding = {"MESHCENTRAL_INSTALL_ROOT": install_root,
                       "MESHCENTRAL_LIFECYCLE_DLL": install_root + "\\lifecycle-fixture.dll",
                       "MESHCENTRAL_LIFECYCLE_STATE_DIR": str(evidence / "deploy")}
    os.environ.update(deploy_branding)
    spec = importlib.util.spec_from_file_location("manifest_deploy", ROOT / "deploy.py")
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    loaded = {"MESHCENTRAL_INSTALL_ROOT": deploy.WINDOWS_INSTALL_ROOT,
              "MESHCENTRAL_LIFECYCLE_DLL": deploy.WINDOWS_LIFECYCLE_DLL,
              "MESHCENTRAL_LIFECYCLE_STATE_DIR": deploy.WINDOWS_LIFECYCLE_STATE_DIR}
    if loaded != deploy_branding:
        raise RuntimeError("deploy.py did not use the fixture lifecycle paths: " + json.dumps(loaded))
    captured = []
    deploy.run_meshctrl = lambda args, *unused, **kwargs: captured.append(args) or SimpleNamespace(returncode=0, stdout="", stderr="")
    update_source = source + deploy.WINDOWS_UPDATE_PACKAGE_SUFFIXES[0]
    deploy.activate_remote_pending_update("unused", update_source, "unused", "unused")
    command = captured[0][captured[0].index("--run") + 1]
    prefix, invocation = command.split("; & ", 1)
    assert "MeshLifecycleHostW" in invocation
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", prefix], check=True, capture_output=True, timeout=15)
    check("deployment-powershell", evidence / "deploy/deploy-activate.ini", {"Action": "update", "SourceExe": update_source, "RequireConfig": "0"})
    report = {"ok": all(row["ok"] for row in rows), "installerExecuted": False, "rows": rows}
    (evidence / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
