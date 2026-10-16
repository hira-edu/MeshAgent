import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "generate_provisioning_manifest.py"
SPEC = importlib.util.spec_from_file_location("generate_provisioning_manifest", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ProvisioningManifestGeneratorContract(unittest.TestCase):
    def setUp(self):
        self.config = {
            "provisioning": {
                "meshName": "Office",
                "meshType": "2",
                "meshId": "0X1234",
                "serverId": "ABCD",
                "serverUrl": "wss://agents.example.test:443/agent.ashx",
            },
            "branding": {
                "serviceName": "MeshAgent",
                "displayName": "Mesh Agent Service",
                "companyName": "Example",
                "description": "remote support agent",
                "binaryName": "meshagent.exe",
            },
        }

    def test_generates_complete_single_source_manifest(self):
        manifest = MODULE.build_manifest(self.config)
        self.assertEqual(
            manifest.splitlines(),
            [
                "MeshName=Office",
                "MeshType=2",
                "MeshID=0X1234",
                "ServerID=ABCD",
                "MeshServer=wss://agents.example.test:443/agent.ashx",
                "meshServiceName=MeshAgent",
                "displayName=Mesh Agent Service",
                "companyName=Example",
                "description=remote support agent",
                "fileName=meshagent.exe",
            ],
        )

    def test_placeholders_are_non_deployment_only(self):
        self.config["provisioning"]["meshId"] = "REPLACE_WITH_MESH_ID"
        with self.assertRaisesRegex(ValueError, "deployment placeholder"):
            MODULE.build_manifest(self.config)
        self.assertIn(
            "MeshID=REPLACE_WITH_MESH_ID",
            MODULE.build_manifest(self.config, allow_placeholders=True),
        )

    def test_rejects_missing_or_multiline_values(self):
        self.config["branding"]["serviceName"] = ""
        with self.assertRaisesRegex(ValueError, "must be populated"):
            MODULE.build_manifest(self.config)
        self.config["branding"]["serviceName"] = "bad\nvalue"
        with self.assertRaisesRegex(ValueError, "single line"):
            MODULE.build_manifest(self.config)


if __name__ == "__main__":
    unittest.main()
