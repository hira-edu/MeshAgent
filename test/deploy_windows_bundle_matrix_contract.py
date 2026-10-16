#!/usr/bin/env python3
"""Unit contracts for x64/ARM64 deployment bundle parity validation."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy  # noqa: E402


def pe_image(machine: int, marker: bytes) -> bytes:
    image = bytearray(0x100)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    image[0x90:0x90 + len(marker)] = marker
    return bytes(image)


class DeployWindowsBundleMatrixContract(unittest.TestCase):
    def create_fixture(self, root: Path, arm64_machine: int = 0xAA64):
        definitions = {
            "MeshService64.exe": pe_image(0x8664, b"x64-exe"),
            "MeshService64.dll": pe_image(0x8664, b"x64-dll"),
            "service_bundle.dll": pe_image(0x8664, b"x64-dll"),
            "MeshServiceARM64.exe": pe_image(0xAA64, b"arm64-exe"),
            "MeshServiceARM64.dll": pe_image(arm64_machine, b"arm64-dll"),
            "service_bundle_arm64.dll": pe_image(arm64_machine, b"arm64-dll"),
        }
        entries = []
        for name, content in definitions.items():
            path = root / name
            path.write_bytes(content)
            entries.append({"name": name, "local_path": str(path)})
        return entries

    def test_accepts_matching_architecture_matrix(self):
        with tempfile.TemporaryDirectory(prefix="meshagent-deploy-matrix-") as directory:
            root = Path(directory)
            entries = self.create_fixture(root)

            def embedded_payload(exe_path):
                name = "MeshServiceARM64.dll" if "ARM64" in Path(exe_path).name else "MeshService64.dll"
                return (root / name).read_bytes()

            with mock.patch.object(deploy, "has_service_host_export", return_value=True), mock.patch.object(
                deploy, "extract_embedded_service_bundle", side_effect=embedded_payload
            ):
                report = deploy.validate_local_service_bundle_artifacts(entries)

            self.assertTrue(report["ok"], report["errors"])
            self.assertEqual(report["artifacts"]["exe"]["machine"], 0x8664)
            self.assertEqual(
                report["artifacts"]["architectures"]["arm64"]["dll"]["machine"],
                0xAA64,
            )

    def test_rejects_mislabeled_arm64_binary(self):
        with tempfile.TemporaryDirectory(prefix="meshagent-deploy-matrix-") as directory:
            root = Path(directory)
            entries = self.create_fixture(root, arm64_machine=0x8664)
            with mock.patch.object(deploy, "has_service_host_export", return_value=True), mock.patch.object(
                deploy,
                "extract_embedded_service_bundle",
                side_effect=lambda exe_path: (
                    root / ("MeshServiceARM64.dll" if "ARM64" in Path(exe_path).name else "MeshService64.dll")
                ).read_bytes(),
            ):
                report = deploy.validate_local_service_bundle_artifacts(entries)

            self.assertFalse(report["ok"])
            self.assertTrue(any("MeshServiceARM64.dll machine" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
