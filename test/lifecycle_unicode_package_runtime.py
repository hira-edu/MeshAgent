"""Run the built lifecycle DLL's read-only preflight on packages in Unicode folders."""
import argparse
import ctypes
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", action="append", required=True, type=pathlib.Path)
    parser.add_argument("--dll", required=True, type=pathlib.Path)
    parser.add_argument("--manifest-fixture", required=True, type=pathlib.Path)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WritePrivateProfileStringW.argtypes = [ctypes.c_wchar_p] * 4
    kernel.WritePrivateProfileStringW.restype = ctypes.c_int
    rows = []
    for index, package in enumerate(args.package):
        for label, folder in [("chinese", "\u684c\u9762"), ("mixed", "\u684c\u9762-\u0627\u0644\u0645\u0643\u062a\u0628-\U0001f4c1")]:
            case = evidence / (str(index) + "-" + label)
            source = case / "OneDrive" / folder / "meshagent64-Devices (8).exe"
            source.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(package, source)
            manifest = case / "manifest.ini"
            # Use the compiled production writer, not a Python serialization substitute.
            result = subprocess.run([str(args.manifest_fixture.resolve()), str(manifest), str(source), "Unicode package validation"],
                                    capture_output=True, timeout=15)
            if result.returncode:
                raise RuntimeError("Native manifest round trip failed")
            if not kernel.WritePrivateProfileStringW("Lifecycle", "Action", "validate-package", str(manifest)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not kernel.WritePrivateProfileStringW("Lifecycle", "RequireConfig", "1", str(manifest)):
                raise ctypes.WinError(ctypes.get_last_error())
            # The fixed host receives the production manifest. This action never installs.
            import os
            command = [str(pathlib.Path(os.environ["SystemRoot"]) / "System32/rundll32.exe"),
                       str(args.dll.resolve()) + ",MeshLifecycleHostW", str(manifest)]
            result = subprocess.run(command, capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
            (case / "stdout.txt").write_bytes(result.stdout)
            (case / "stderr.txt").write_bytes(result.stderr)
            text = result.stdout.decode("utf-8", errors="replace")
            reports = []
            for line in text.splitlines():
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        reports.append(value)
                except ValueError:
                    pass
            ok = result.returncode == 0 and any(report.get("success") is True for report in reports)
            rows.append({"package": str(package.resolve()), "source": str(source), "exitCode": result.returncode,
                         "reports": reports, "ok": ok})
            print(("PASS " if ok else "FAIL ") + package.name + " " + label)
    report = {"ok": all(row["ok"] for row in rows), "action": "validate-package", "installerExecuted": False, "rows": rows}
    (evidence / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
