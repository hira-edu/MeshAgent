"""Fault-injection tests; never invoke Docker, SSH, systemd, or a live endpoint."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if os.name == 'nt':
    # Only the Linux import surface is stubbed. Production filesystem/state code runs.
    sys.modules.setdefault('fcntl', types.SimpleNamespace())
    sys.modules.setdefault('pwd', types.SimpleNamespace())
MANAGER = load('release_manager', 'tools/deployment/release_manager.py')
ENTRY = load('ci_entry', 'tools/deployment/ci_entry.py')
SOURCES = load('resolve_sources', 'tools/resolve_deploy_sources.py')
DIGEST = 'sha256:' + 'a' * 64
PREVIOUS = 'sha256:' + 'b' * 64


class ControllerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = self.root / 'base'
        self.state = self.root / 'state'
        self.state.mkdir()
        (self.base / 'meshcentral-data').mkdir(parents=True)
        self.config_path = self.base / 'meshcentral-data/config.json'
        self.original_config = {'settings': {'noagentupdate': True, 'keep': 'private-fixture'}}
        self.config_path.write_text(json.dumps(self.original_config))
        self.config = {'image': 'ghcr.io/fixture/release', 'meshcentral_version': '1.2.5',
                       'health_url': 'https://fixture.invalid/health.ashx', 'enable_fleet_update': True}
        self.release = self.root / 'release'
        self.release.mkdir()
        self.patches = {}
        if os.name == 'nt':
            patch = mock.patch.object(MANAGER.os, 'chown', create=True)
            patch.start()
            self.addCleanup(patch.stop)
        for name, value in {'BASE': self.base, 'STATE': self.state}.items():
            patch = mock.patch.object(MANAGER, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        for name, result in {'run': '', 'prepare': self.release, 'seed_agents': self.release / 'runtime',
                             'start': None, 'remove_container': None, 'healthy': True}.items():
            patch = mock.patch.object(MANAGER, name, return_value=result)
            self.patches[name] = patch.start()
            self.addCleanup(patch.stop)

    def test_success_records_digest_and_enables_fleet(self):
        MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text())['digest'], DIGEST)
        self.assertFalse(json.loads(self.config_path.read_text())['settings']['noagentupdate'])
        self.assertFalse((self.state / 'transaction.json').exists())
        self.patches['run'].assert_called_once_with('systemctl', 'disable', '--now', 'meshcentral')

    def test_failed_readiness_restores_legacy_and_policy(self):
        self.patches['healthy'].side_effect = [True, False, True]
        with self.assertRaisesRegex(RuntimeError, 'readiness'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads(self.config_path.read_text()), self.original_config)
        self.assertIsNone(json.loads((self.state / 'active.json').read_text()))
        self.assertFalse((self.state / 'transaction.json').exists())
        self.assertIn(mock.call('systemctl', 'enable', '--now', 'meshcentral'), self.patches['run'].call_args_list)

    def test_failed_candidate_restores_previous_container(self):
        previous = {'digest': PREVIOUS, 'directory': 'old', 'runtime': 'old-runtime'}
        (self.state / 'active.json').write_text(json.dumps(previous))
        self.patches['start'].side_effect = [RuntimeError('candidate start'), None]
        with self.assertRaisesRegex(RuntimeError, 'candidate start'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text()), previous)
        self.assertEqual(self.patches['start'].call_args_list[-1], mock.call(self.config, previous))
        self.patches['run'].assert_not_called()

    def test_preparation_failure_does_not_stop_service(self):
        self.patches['prepare'].side_effect = RuntimeError('pull failed')
        with self.assertRaisesRegex(RuntimeError, 'pull failed'):
            MANAGER.promote(self.config, DIGEST)
        self.patches['run'].assert_not_called()
        self.patches['remove_container'].assert_not_called()
        self.assertFalse((self.state / 'transaction.json').exists())

    def test_unhealthy_incumbent_is_not_changed(self):
        self.patches['healthy'].return_value = False
        with self.assertRaisesRegex(RuntimeError, 'Current production'):
            MANAGER.promote(self.config, DIGEST)
        self.patches['prepare'].assert_not_called()
        self.patches['run'].assert_not_called()

    def test_failed_recovery_keeps_journal_and_blocks_next_deploy(self):
        self.patches['healthy'].side_effect = [True, False, False]
        with self.assertRaisesRegex(RuntimeError, 'Recovery health failed'):
            MANAGER.promote(self.config, DIGEST)
        self.assertTrue((self.state / 'transaction.json').is_file())
        with self.assertRaisesRegex(RuntimeError, 'interrupted transaction'):
            MANAGER.promote(self.config, DIGEST)

    def test_same_digest_does_not_restart(self):
        (self.state / 'active.json').write_text(json.dumps({'digest': DIGEST}))
        MANAGER.promote(self.config, DIGEST)
        self.patches['run'].assert_not_called()
        self.patches['prepare'].assert_not_called()

    def test_failure_stopping_legacy_keeps_recovery_record(self):
        self.patches['run'].side_effect = RuntimeError('systemctl failed')
        with self.assertRaisesRegex(RuntimeError, 'systemctl failed'):
            MANAGER.promote(self.config, DIGEST)
        self.assertTrue((self.state / 'transaction.json').exists())


class InputTests(unittest.TestCase):
    def test_registry_job_token_is_bounded_and_delivered_as_a_service_credential(self):
        credentials = {'username': 'release-app[bot]', 'token': 'ghs_' + 'a' * 40}
        self.assertEqual(ENTRY.registry_credentials(json.dumps(credentials)), credentials)
        self.assertIn('--property=LoadCredential=ghcr:/run/fixture', ENTRY.command('deploy ' + DIGEST, '/run/fixture'))
        for value in ('{}', 'x' * 2049, json.dumps(dict(credentials, token='bad\nvalue')),
                      json.dumps(dict(credentials, username='--config=/tmp/elsewhere'))):
            with self.subTest(value=value), self.assertRaises((ValueError, KeyError)):
                ENTRY.registry_credentials(value)

    def test_forced_command_cannot_execute_arbitrary_commands(self):
        self.assertEqual(ENTRY.command('deploy ' + DIGEST)[-1], DIGEST)
        for value in ('deploy latest', 'deploy ' + DIGEST + '; id', 'deploy ' + DIGEST + '\n',
                      'recover', 'deploy -x', 'deploy sha256:' + 'a' * 63):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ENTRY.command(value)

    def test_only_default_branch_events_can_deploy(self):
        event = {'repository': {'default_branch': 'main'}, 'inputs': {'deploy_to_server': 'true'}}
        env = {'GITHUB_REF': 'refs/heads/main', 'AUTO_DEPLOY': 'true'}
        self.assertTrue(SOURCES.requested('push', event, env))
        self.assertTrue(SOURCES.requested('repository_dispatch', event, env))
        self.assertTrue(SOURCES.requested('workflow_dispatch', event, env))
        self.assertFalse(SOURCES.requested('pull_request', event, env))
        for ref in ('refs/tags/v1', 'refs/heads/feature', 'refs/pull/1/merge'):
            self.assertFalse(SOURCES.requested('push', event, dict(env, GITHUB_REF=ref)))
        self.assertFalse(SOURCES.requested('push', event, dict(env, AUTO_DEPLOY='false')))

    def test_manifest_tamper_and_persistent_file_mount_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'data-core').mkdir()
            source = root / 'data-core/meshcore.js'
            source.write_bytes(b'code')
            manifest = {'schema': 1, 'meshcentral_version': '1.2.5',
                        'files': {'data-core/meshcore.js': hashlib.sha256(b'code').hexdigest()},
                        'mounts': [{'source': 'data-core/meshcore.js', 'target': str(MANAGER.BASE / 'meshcentral-data') + '/meshcore.js'}]}
            path = root / 'manifest.json'
            path.write_text(json.dumps(manifest))
            MANAGER.validate_manifest(root, '1.2.5')
            with self.assertRaises(ValueError):
                MANAGER.validate_manifest(root, '1.2.6')
            source.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'digest'):
                MANAGER.validate_manifest(root, '1.2.5')
            source.write_bytes(b'code')
            manifest['mounts'][0]['target'] = str(MANAGER.BASE / 'meshcentral-data/config.json')
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                MANAGER.validate_manifest(root, '1.2.5')


if __name__ == '__main__':
    unittest.main()
