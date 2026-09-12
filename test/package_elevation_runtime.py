"""Check the Windows loader's embedded UAC contract without executing a package."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import pathlib
import sys
import xml.etree.ElementTree as ET


def read_manifest(file_path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel.LoadLibraryExW.restype = wintypes.HMODULE
    kernel.FindResourceW.argtypes = [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p]
    kernel.FindResourceW.restype = wintypes.HANDLE
    kernel.SizeofResource.argtypes = [wintypes.HMODULE, wintypes.HANDLE]
    kernel.SizeofResource.restype = wintypes.DWORD
    kernel.LoadResource.argtypes = [wintypes.HMODULE, wintypes.HANDLE]
    kernel.LoadResource.restype = wintypes.HANDLE
    kernel.LockResource.argtypes = [wintypes.HANDLE]
    kernel.LockResource.restype = ctypes.c_void_p
    kernel.FreeLibrary.argtypes = [wintypes.HMODULE]
    kernel.FreeLibrary.restype = wintypes.BOOL
    # DATAFILE | IMAGE_RESOURCE: never resolve imports or execute DllMain/code.
    module = kernel.LoadLibraryExW(str(file_path), None, 0x02 | 0x20)
    if not module:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        resource = kernel.FindResourceW(module, 1, 24)  # CREATEPROCESS_MANIFEST_RESOURCE_ID, RT_MANIFEST
        if not resource:
            raise ctypes.WinError(ctypes.get_last_error())
        size = kernel.SizeofResource(module, resource)
        if not size:
            raise ctypes.WinError(ctypes.get_last_error())
        loaded = kernel.LoadResource(module, resource)
        if not loaded:
            raise ctypes.WinError(ctypes.get_last_error())
        address = kernel.LockResource(loaded)
        if not address:
            raise RuntimeError("LockResource returned NULL")
        return ctypes.string_at(address, size)
    finally:
        if not kernel.FreeLibrary(module):
            raise ctypes.WinError(ctypes.get_last_error())


def check(file_path):
    row = {"path": str(file_path), "ok": False}
    try:
        row["sha256"] = hashlib.sha256(file_path.read_bytes()).hexdigest()
        root = ET.fromstring(read_manifest(file_path))
        levels = root.findall(".//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel")
        if len(levels) != 1:
            raise ValueError("Expected exactly one requestedExecutionLevel")
        row.update(levels[0].attrib)
        row["ok"] = row.get("level") == "requireAdministrator" and row.get("uiAccess") == "false"
        if not row["ok"]:
            row["error"] = "Service installers must request administrator consent before execution"
    except (OSError, RuntimeError, ValueError, ET.ParseError) as error:
        row["error"] = str(error)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="+", type=pathlib.Path)
    parser.add_argument("--evidence", type=pathlib.Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows is required for data-only resource inspection")
    rows = [check(file_path.resolve()) for file_path in args.packages]
    report = {"ok": all(row["ok"] for row in rows), "packagesExecuted": False, "results": rows}
    text = json.dumps(report, indent=2) + "\n"
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "package-elevation.json").write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
