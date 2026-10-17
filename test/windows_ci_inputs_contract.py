import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('prepare_ci', ROOT / 'tools/prepare_windows_ci.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)
CONFIG = {'branding': {'serviceName': 'FixtureAgent', 'displayName': 'Fixture Agent'}}
MANIFEST = 'MeshID=0x' + 'ab' * 48 + '\nServerID=' + 'cd' * 48 + '\nMeshServer=wss://fixture.invalid/agent.ashx\n'


class CiInputs(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'branding_config.json').write_text(json.dumps(CONFIG))

    def test_validation_fixture_cannot_be_published(self):
        self.assertFalse(CI.prepare_inputs(self.root, {}))
        self.assertIn('validation.invalid', (self.root / 'MeshAgent.msh').read_text())
        for env in ({}, {'BRANDING_CONFIG_JSON': json.dumps(CONFIG)}, {'PROVISIONING_MSH': MANIFEST}):
            with self.assertRaises(ValueError):
                CI.prepare_inputs(self.root, env, True)

    def test_explicit_inputs_are_preserved(self):
        env = {'BRANDING_CONFIG_JSON': json.dumps(CONFIG), 'PROVISIONING_MSH': MANIFEST}
        self.assertTrue(CI.prepare_inputs(self.root, env, True))
        self.assertEqual((self.root / 'MeshAgent.msh').read_text().strip(), MANIFEST.strip())

    def test_invalid_inputs_do_not_replace_existing_files(self):
        output = self.root / 'MeshAgent.msh'
        output.write_text('old')
        for manifest in ('MeshID=x', MANIFEST + 'MeshID=duplicate\n',
                         MANIFEST + 'meshServiceName=Other\n',
                         MANIFEST.replace('wss://', 'https://')):
            with self.assertRaises(ValueError):
                CI.prepare_inputs(self.root, {'BRANDING_CONFIG_JSON': json.dumps(CONFIG), 'PROVISIONING_MSH': manifest}, True)
            self.assertEqual(output.read_text(), 'old')
        with self.assertRaises(ValueError):
            CI.prepare_inputs(self.root, {'BRANDING_CONFIG_JSON': json.dumps({'branding': {
                'serviceName': 'REPLACE_WITH_SERVICE', 'displayName': 'Template'}}), 'PROVISIONING_MSH': MANIFEST}, True)


if __name__ == '__main__':
    unittest.main()
