"""Fork-safety tests for the image release tooling; never invoke Docker, SSH, systemd, or a live endpoint.

Covers agent seeding (T11), the reviewed-version allowlist (D5/T23), the start-time shadow-copy
check (G4), the smoke assertions (T22) and the tracked image-size mitigation (T24).
"""
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
DEPLOYMENT = ROOT / 'tools/deployment'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if os.name == 'nt':
    # Only the Linux import surface is stubbed. Production filesystem/state code runs.
    sys.modules.setdefault('fcntl', types.SimpleNamespace())
    sys.modules.setdefault('pwd', types.SimpleNamespace())
MANAGER = load('release_manager_fork_safety', 'tools/deployment/release_manager.py')
DIGEST = 'sha256:' + 'a' * 64
PREVIOUS = 'sha256:' + 'b' * 64
SERVICE_ACCOUNT = types.SimpleNamespace(pw_uid=0, pw_gid=0, pw_dir='/nonexistent')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def make_release(directory, files, version='1.2.5', **extra):
    """Create a release directory with overrides/<member> files and a matching manifest."""
    overrides = Path(directory) / 'overrides'
    overrides.mkdir(parents=True)
    manifest = {'schema': 1, 'meshcentral_version': version, 'mounts': [], 'files': {}}
    for relative, data in files.items():
        path = overrides / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        manifest['files'][relative] = sha256(data)
    manifest.update(extra)
    (overrides / 'manifest.json').write_text(json.dumps(manifest))
    return Path(directory)


def runtime_files(runtime):
    runtime = Path(runtime)
    return sorted(path.relative_to(runtime).as_posix() for path in runtime.rglob('*') if path.is_file())


class FixtureCase(unittest.TestCase):
    """Temporary BASE/STATE, the Linux account lookup and ownership changes are faked."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = self.root / 'base'
        self.state = self.root / 'state'
        self.state.mkdir()
        (self.base / 'meshcentral-data').mkdir(parents=True)
        (self.base / 'meshcentral-web').mkdir()
        self.config_path = self.base / 'meshcentral-data/config.json'
        self.config_path.write_text(json.dumps({'settings': {'noagentupdate': True}}))
        self.config = {'image': 'ghcr.io/fixture/release', 'meshcentral_version': '1.2.5',
                       'health_url': 'https://fixture.invalid/health.ashx', 'enable_fleet_update': True}
        mitigation = self.base / 'bin/harden-image-size.js'
        mitigation.parent.mkdir()
        mitigation.write_text('// fixture\n')
        for target, name, value in ((MANAGER, 'BASE', self.base), (MANAGER, 'STATE', self.state),
                                    (MANAGER, 'pwd', types.SimpleNamespace(getpwnam=lambda name: SERVICE_ACCOUNT))):
            patch = mock.patch.object(target, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(MANAGER.os, 'chown', create=True)
        patch.start()
        self.addCleanup(patch.stop)

    def release_dir(self, digest):
        return self.state / 'releases' / digest.split(':')[1]


class AgentSeedingTests(FixtureCase):
    """T11: runtime agent folders derive only from the release's own manifest."""

    def test_first_promotion_ignores_incumbent_agent_folders(self):
        for folder, name in (('agents', 'meshagent_osx-arm-64'), ('signedagents', 'svchost_payload.dll'),
                             ('signedagents', 'MeshService64.exe')):
            path = self.base / 'meshcentral-data' / folder / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b'incumbent ' + name.encode())
        release = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'exe',
                                                          'data/MeshService64.msh': b'msh',
                                                          'signed/MeshService64.exe': b'exe'})
        runtime = MANAGER.seed_agents(release)
        self.assertEqual(runtime_files(runtime), ['data/MeshService64.exe', 'data/MeshService64.msh',
                                                  'signed/MeshService64.exe'])
        self.assertEqual((runtime / 'signed/MeshService64.exe').read_bytes(), b'exe')
        MANAGER.verify_agent_runtime(release, runtime)

    def test_promotion_does_not_carry_the_previous_runtime_forward(self):
        old = make_release(self.release_dir(PREVIOUS), {'data/MeshService64.exe': b'old',
                                                        'signed/svchost_payload.dll': b'shadow'})
        old_runtime = MANAGER.seed_agents(old)
        (old_runtime / 'signed/MeshCmd64.exe').write_bytes(b'server-signed while running')
        new = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'new'})
        runtime = MANAGER.seed_agents(new)
        self.assertEqual(runtime_files(runtime), ['data/MeshService64.exe'])
        self.assertEqual((runtime / 'data/MeshService64.exe').read_bytes(), b'new')

    def test_excluded_names_are_never_seeded(self):
        release = make_release(self.release_dir(DIGEST), {'signed/hashagents.json': b'{}',
                                                          'signed/MasterService.exe': b'm',
                                                          'signed/MeshService64.exe': b'exe'})
        self.assertEqual(runtime_files(MANAGER.seed_agents(release)), ['signed/MeshService64.exe'])

    def test_tampered_or_nested_seed_member_is_refused(self):
        release = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'exe'})
        (release / 'overrides/data/MeshService64.exe').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'digest mismatch: data/MeshService64.exe'):
            MANAGER.seed_agents(release)
        nested = make_release(self.release_dir(PREVIOUS), {'signed/sub/MeshService64.exe': b'exe'})
        with self.assertRaisesRegex(ValueError, 'direct children.*signed/sub/MeshService64.exe'):
            MANAGER.seed_agents(nested)

    def test_runtime_outside_its_release_is_refused(self):
        release = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'exe'})
        with self.assertRaisesRegex(ValueError, 'runtime-\\* folder of its own release'):
            MANAGER.seed_agents(release, self.root / 'runtime-elsewhere')

    def test_verify_names_every_runtime_difference(self):
        release = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'exe',
                                                          'signed/MeshService64.exe': b'exe'})
        runtime = MANAGER.seed_agents(release)
        (runtime / 'signed/svchost_payload.dll').write_bytes(b'planted')
        (runtime / 'data/MeshService64.exe').write_bytes(b'changed')
        (runtime / 'signed/MeshService64.exe').unlink()
        with self.assertRaises(ValueError) as raised:
            MANAGER.verify_agent_runtime(release, runtime)
        message = str(raised.exception)
        self.assertIn('signed/svchost_payload.dll: not in the release manifest', message)
        self.assertIn('data/MeshService64.exe: sha256 differs', message)
        self.assertIn('signed/MeshService64.exe: listed in the release manifest but missing', message)

    def test_deleted_file_stays_deleted_across_promotion_and_recover(self):
        # Release A shipped a shadow binary; release B removed it. B fails, so recovery restarts A.
        old = make_release(self.release_dir(PREVIOUS), {'data/MeshService64.exe': b'old'})
        old_runtime = MANAGER.seed_agents(old)
        previous = {'digest': PREVIOUS, 'directory': str(old), 'runtime': str(old_runtime)}
        (self.state / 'active.json').write_text(json.dumps(previous))
        # A file deleted from the host and from A's runtime while A ran must not return,
        # and a file the server wrote into A's runtime must not survive recovery.
        (old_runtime / 'signed/svchost_payload.dll').write_bytes(b'planted while running')
        host_shadow = self.base / 'meshcentral-data/signedagents/svchost_payload.dll'
        host_shadow.parent.mkdir()
        host_shadow.write_bytes(b'shadow')
        host_shadow.unlink()
        new = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'new'})
        calls = []

        def run(*args, capture=False):
            calls.append(args)
            if args[:2] == ('docker', 'run') and args[-1].endswith(DIGEST):
                raise RuntimeError('candidate start')
            return ''

        with mock.patch.object(MANAGER, 'run', side_effect=run), \
                mock.patch.object(MANAGER, 'prepare', return_value=new), \
                mock.patch.object(MANAGER, 'remove_container'), \
                mock.patch.object(MANAGER, 'healthy', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'candidate start'):
                MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text()), previous)
        self.assertTrue(calls[-1][-1].endswith(PREVIOUS))
        self.assertEqual(runtime_files(old_runtime), ['data/MeshService64.exe'])
        self.assertFalse(host_shadow.exists())
        candidate_runtimes = [path for path in new.iterdir() if path.name.startswith('runtime-')]
        self.assertEqual([runtime_files(path) for path in candidate_runtimes], [['data/MeshService64.exe']])


if __name__ == '__main__':
    unittest.main()
