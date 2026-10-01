"""Reject a DLL whose required lifecycle entry point was removed."""

import pathlib
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deploy  # noqa: E402


def main():
    dll = ROOT / "meshservice/x64/MeshServiceBundle/MeshService-2022.dll"
    assert dll.is_file(), "Build the x64 service bundle before running this probe"
    assert deploy.has_service_host_export(dll)
    assert deploy.has_service_host_export(dll, b"Stealth_SvchostServiceMain")

    original = dll.read_bytes()
    with tempfile.TemporaryDirectory(prefix="meshagent-export-gate-") as directory:
        for export_name in (b"MeshServiceHostW", b"Stealth_SvchostServiceMain"):
            offset = original.rfind(export_name + b"\0")
            assert offset >= 0, f"Built DLL does not contain {export_name!r}"
            changed = bytearray(original)
            changed[offset:offset + len(export_name)] = b"X" * len(export_name)
            broken = pathlib.Path(directory) / (export_name.decode("ascii") + ".dll")
            broken.write_bytes(changed)
            assert not deploy.has_service_host_export(broken, export_name)

    local_artifacts = deploy.get_present_local_artifacts()
    report = deploy.validate_local_service_bundle_artifacts(local_artifacts)
    assert report["ok"], report["errors"]
    assert report["artifacts"]["dll"]["service_host_export"] is True
    assert report["artifacts"]["dll"]["legacy_service_host_export"] is True
    print("service_host_export_gate=pass")


if __name__ == "__main__":
    main()
