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
    start = source.index("function " + name + "(")
    # These top-level functions end with an unindented closing brace.
    end = source.index("\n}", start) + 2
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Requires Windows, Node.js and a built MeshConsole64.exe")
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
    functions = "\n".join(js_function(installer, name) for name in
                          ["sanitizeWindowsLifecycleManifestValue", "writeWindowsLifecycleManifest"])
    for label, executable in [("installer-node", "node"), ("installer-native", str(ROOT / "meshconsole/Release/MeshConsole64.exe"))]:
        directory = pathlib.Path(tempfile.mkdtemp(prefix=label + "-", dir=evidence))
        code = functions + "\n"
        code += "writeWindowsLifecycleManifest('validate-package'," + json.dumps(source) + "," + json.dumps(source) + ","
        code += "{getParameter:function(){return " + json.dumps(description) + ";}});process.exit(0);"
        script = directory / "writer.js"
        script.write_text(code, encoding="ascii")
        command = [executable, str(script)] if label.endswith("node") else [executable, "-exec", code]
        result = subprocess.run(command, cwd=directory, env=dict(os.environ, TEMP=str(directory), TMP=str(directory)),
                                capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        (directory / "stdout.txt").write_bytes(result.stdout)
        (directory / "stderr.txt").write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(label + " exited " + str(result.returncode))
        manifests = list(directory.glob("*.ini"))
        if len(manifests) != 1:
            raise RuntimeError(label + " did not write one manifest")
        check(label, manifests[0], {"Action": "validate-package", "SourceExe": source, "SourceDll": source,
                                  "DisplayName": description, "Description": description, "RequireConfig": "1"})

    helper = (ROOT / "test/lib/rundll32_lifecycle.js").read_text()
    functions = "\n".join(js_function(helper, name) for name in ["sanitizeManifestValue", "writeManifest"])
    manifest = evidence / "test-helper.ini"
    fields = {"action": "validate-package", "sourceExe": source, "sourceDll": source,
              "displayName": description, "description": description, "requireConfig": True}
    code = "const fs=require('fs');\n" + functions + "\nwriteManifest(" + json.dumps(str(manifest)) + "," + json.dumps(fields) + ");"
    subprocess.run(["node", "-e", code], check=True, capture_output=True, timeout=15)
    check("test-helper-node", manifest, {"SourceExe": source, "SourceDll": source, "Description": description})

    # Capture the actual deploy command; execute only its manifest-writing prefix.
    spec = importlib.util.spec_from_file_location("manifest_deploy", ROOT / "deploy.py")
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    captured = []
    deploy.run_meshctrl = lambda args, *unused, **kwargs: captured.append(args) or SimpleNamespace(returncode=0, stdout="", stderr="")
    deploy.WINDOWS_LIFECYCLE_STATE_DIR = str(evidence / "deploy")
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
