#!/usr/bin/env python3
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "refresh_service_bundle", ROOT / "tools" / "refresh_service_bundle.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ServiceBundleRefreshContract(unittest.TestCase):
    def test_architecture_outputs_are_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "branding.json"
            config.write_text(
                json.dumps({"branding": {"serviceDllName": "testsvc.dll"}}),
                encoding="utf-8",
            )
            x64 = root / "x64.dll"
            arm64 = root / "arm64.dll"
            x64.write_bytes(b"x64-service-bundle")
            arm64.write_bytes(b"arm64-service-bundle")

            MODULE.refresh_service_bundle(root, x64, config, "x64")
            compatibility = root / "meshservice/embedded/service_bundle.dll"
            self.assertEqual(
                (root / "meshservice/embedded/x64/service_bundle.dll").read_bytes(),
                x64.read_bytes(),
            )
            self.assertEqual(compatibility.read_bytes(), x64.read_bytes())
            self.assertEqual(
                (root / "meshservice/installer/components/testsvc.dll").read_bytes(),
                x64.read_bytes(),
            )
            compatibility_metadata = root / "meshcore/embedded/generated/service_bundle.json"
            self.assertEqual(
                json.loads(compatibility_metadata.read_text(encoding="utf-8"))[
                    "architecture"
                ],
                "x64",
            )

            MODULE.refresh_service_bundle(root, arm64, config, "arm64")
            self.assertEqual(
                (root / "meshservice/embedded/arm64/service_bundle.dll").read_bytes(),
                arm64.read_bytes(),
            )
            self.assertEqual(compatibility.read_bytes(), x64.read_bytes())
            self.assertEqual(
                (root / "meshservice/embedded/x64/service_bundle.dll").read_bytes(),
                x64.read_bytes(),
            )
            self.assertEqual(
                json.loads(compatibility_metadata.read_text(encoding="utf-8"))[
                    "architecture"
                ],
                "x64",
            )
            metadata = json.loads(
                (root / "meshcore/embedded/generated/service_bundle.arm64.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["architecture"], "arm64")
            self.assertIsNone(metadata["compatibilityEmbeddedDll"])
            self.assertIsNone(metadata["installerDll"])

    def test_rejects_unknown_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "branding.json"
            config.write_text("{}", encoding="utf-8")
            dll = root / "bundle.dll"
            dll.write_bytes(b"bundle")
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                MODULE.refresh_service_bundle(root, dll, config, "mips")


if __name__ == "__main__":
    unittest.main()
