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
INSTALLER = load('install_controller_fork_safety', 'tools/deployment/install_controller.py')
DIGEST = 'sha256:' + 'a' * 64
PREVIOUS = 'sha256:' + 'b' * 64
SERVICE_ACCOUNT = types.SimpleNamespace(pw_uid=0, pw_gid=0, pw_dir='/nonexistent')
FORK_REVISION = 'c' * 40
SCHEMA1_CONFIG = {'image': 'ghcr.io/fixture/release', 'health_url': 'https://fixture.invalid/health.ashx',
                  'meshcentral_version': '1.2.5', 'enable_fleet_update': False}


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
        self.config = {'schema': 2, 'image': 'ghcr.io/fixture/release', 'reviewed_versions': ['1.2.5'],
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


def write_manifest_fixture(root, version='1.2.5', **extra):
    """A minimal release overrides folder for validate_manifest."""
    root = Path(root)
    (root / 'data-core').mkdir(parents=True, exist_ok=True)
    (root / 'data-core/meshcore.js').write_bytes(b'code')
    manifest = {'schema': 1, 'meshcentral_version': version,
                'files': {'data-core/meshcore.js': sha256(b'code')},
                'mounts': [{'source': 'data-core/meshcore.js',
                            'target': str(MANAGER.BASE / 'meshcentral-data') + '/meshcore.js'}]}
    manifest.update(extra)
    (root / 'manifest.json').write_text(json.dumps(manifest))
    return root


class ConfigPolicyTests(unittest.TestCase):
    """D5/T23: the controller keeps an allowlist of reviewed versions."""

    def test_schema1_config_migrates_to_an_allowlist_of_its_single_version(self):
        migrated = MANAGER.migrate_config(SCHEMA1_CONFIG)
        self.assertEqual(migrated, {'schema': 2, 'image': SCHEMA1_CONFIG['image'],
                                    'health_url': SCHEMA1_CONFIG['health_url'],
                                    'reviewed_versions': ['1.2.5'], 'enable_fleet_update': False})
        self.assertEqual(MANAGER.migrate_config(migrated), migrated)
        self.assertIn('meshcentral_version', SCHEMA1_CONFIG)  # input is not modified

    def test_unmigrated_or_mixed_config_is_refused_with_the_migration_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'meshcentral-deploy.json'
            path.write_text(json.dumps(SCHEMA1_CONFIG))
            with mock.patch.object(MANAGER, 'CONFIG', path), \
                    self.assertRaisesRegex(ValueError, 'retired single meshcentral_version.*--upgrade'):
                MANAGER.load_config()
        with self.assertRaisesRegex(ValueError, 'mixes meshcentral_version'):
            MANAGER.migrate_config(dict(SCHEMA1_CONFIG, reviewed_versions=['1.2.6']))

    def test_reviewed_versions_must_be_an_explicit_list_of_exact_versions(self):
        config = MANAGER.migrate_config(SCHEMA1_CONFIG)
        for versions in ([], '1.2.5', ['1.2'], ['1.2.5', '1.2.5'], ['v1.2.5'], ['1.2.*'], None):
            with self.subTest(versions=versions), self.assertRaisesRegex(ValueError, 'reviewed_versions'):
                MANAGER.validate_config(dict(config, reviewed_versions=versions))
        MANAGER.validate_config(dict(config, reviewed_versions=['1.2.5', '1.2.6', '1.3.0-fork.1']))
        with self.assertRaisesRegex(ValueError, 'schema'):
            MANAGER.validate_config(dict(config, schema=3))


class ManifestVersionTests(unittest.TestCase):
    """D5/T23: each manifest records the version it was reviewed for and its fork revision."""

    def test_old_manifest_is_valid_through_its_recorded_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary)
            MANAGER.validate_manifest(root, ['1.2.5', '1.2.6'])
            self.assertEqual(MANAGER.release_identity(json.loads((root / 'manifest.json').read_text())),
                             ('1.2.5', '1.2.5', None))

    def test_unreviewed_version_is_refused_with_a_clear_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary, '1.2.7', reviewedUpstreamVersion='1.2.7')
            with self.assertRaisesRegex(ValueError, r'MeshCentral 1\.2\.7 is not a reviewed version '
                                                    r'\(reviewed_versions: 1\.2\.5, 1\.2\.6\)'):
                MANAGER.validate_manifest(root, ['1.2.5', '1.2.6'])

    def test_reviewed_version_must_match_the_packaged_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary, '1.2.6', reviewedUpstreamVersion='1.2.5')
            with self.assertRaisesRegex(ValueError, "reviewed for MeshCentral '1.2.5' but packages MeshCentral 1.2.6"):
                MANAGER.validate_manifest(root, ['1.2.5', '1.2.6'])

    def test_fork_revision_must_be_a_full_commit_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary, forkRevision=FORK_REVISION, reviewedUpstreamVersion='1.2.5')
            MANAGER.validate_manifest(root, ['1.2.5'])
            for revision in ('c' * 39, 'C' * 40, 'main', 40):
                write_manifest_fixture(temporary, forkRevision=revision)
                with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, 'forkRevision'):
                    MANAGER.validate_manifest(root, ['1.2.5'])

    def test_allowlist_must_be_a_list_not_a_substring_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary, '1.2.5')
            with self.assertRaisesRegex(ValueError, 'reviewed_versions'):
                MANAGER.validate_manifest(root, '1.2.5-fork.1')


class VersionLifecycleTests(FixtureCase):
    """prepare, start and recover all validate against the allowlist."""

    def setUp(self):
        super().setUp()
        self.config['reviewed_versions'] = ['1.2.5', '1.2.6']
        self.run_calls = []
        self.fail_candidate = False

        def run(*args, capture=False):
            self.run_calls.append(args)
            if self.fail_candidate and args[:2] == ('docker', 'run') and args[-1].endswith(DIGEST):
                raise RuntimeError('candidate start')
            return ''

        for name, value in {'run': mock.Mock(side_effect=run), 'remove_container': mock.Mock(),
                            'healthy': mock.Mock(return_value=True)}.items():
            patch = mock.patch.object(MANAGER, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        # prepare() only inspects the image cache through subprocess.run; report it cached.
        patch = mock.patch.object(MANAGER.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0))
        patch.start()
        self.addCleanup(patch.stop)

    def promote_previous(self, version):
        old = make_release(self.release_dir(PREVIOUS), {'data/MeshService64.exe': b'old'}, version)
        previous = {'digest': PREVIOUS, 'directory': str(old), 'runtime': str(MANAGER.seed_agents(old))}
        (self.state / 'active.json').write_text(json.dumps(previous))
        return previous

    def test_rollback_to_an_older_reviewed_release_after_a_newer_version_is_allowlisted(self):
        previous = self.promote_previous('1.2.5')  # written before the identity fields existed
        make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'new'}, '1.2.6',
                     reviewedUpstreamVersion='1.2.6', forkRevision=FORK_REVISION)
        self.fail_candidate = True
        with self.assertRaisesRegex(RuntimeError, 'candidate start'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text()), previous)
        self.assertTrue(self.run_calls[-1][-1].endswith(PREVIOUS))

    def test_prepare_refuses_an_unreviewed_release_before_touching_the_service(self):
        self.promote_previous('1.2.5')
        make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'new'}, '1.2.7')
        with self.assertRaisesRegex(ValueError, r'1\.2\.7 is not a reviewed version'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(self.run_calls, [])
        MANAGER.remove_container.assert_not_called()
        self.assertFalse((self.state / 'transaction.json').exists())

    def test_recover_refuses_a_previous_release_whose_version_was_withdrawn(self):
        previous = self.promote_previous('1.2.5')
        self.config['reviewed_versions'] = ['1.2.6']
        transaction = {'previous': previous, 'candidate': None,
                       'config_backup': str(self.state / 'config-backup.json'),
                       'config_metadata': {'uid': 0, 'gid': 0, 'mode': 0o600}}
        (self.state / 'config-backup.json').write_text(self.config_path.read_text())
        with self.assertRaisesRegex(ValueError, r'1\.2\.5 is not a reviewed version'):
            MANAGER.recover(self.config, transaction)
        self.assertEqual(self.run_calls, [])


class ControllerUpgradeTests(unittest.TestCase):
    """install_controller.py --upgrade replaces controller code and migrates the configuration."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / 'etc/meshcentral-deploy.json'
        self.state = self.root / 'state'
        paths = {'CONFIG': self.config, 'SUDOERS': self.root / 'etc/sudoers.d/meshcentral-deploy',
                 'CONTROLLER': self.root / 'libexec/meshcentral-release',
                 'CI_ENTRY': self.root / 'sbin/meshcentral-ci-entry'}
        for path in paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('installed before upgrade\n')
        self.config.write_text(json.dumps(SCHEMA1_CONFIG))
        installed = {INSTALLER.CONTROLLER: paths['CONTROLLER'], INSTALLER.CI_ENTRY: paths['CI_ENTRY']}
        code = tuple((name, installed[destination], mode) for name, destination, mode in INSTALLER.CODE)
        lock = types.SimpleNamespace(flock=mock.Mock(), LOCK_EX=2, LOCK_NB=4)
        patches = [mock.patch.object(INSTALLER, name, value) for name, value in paths.items()]
        patches += [mock.patch.object(INSTALLER, 'CODE', code), mock.patch.object(INSTALLER, 'fcntl', lock),
                    mock.patch.object(INSTALLER.release_manager, 'STATE', self.state),
                    mock.patch.object(INSTALLER.release_manager, 'CONFIG', self.config),
                    mock.patch.object(INSTALLER.os, 'chown', create=True)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.paths = paths

    def test_upgrade_migrates_config_keeps_a_backup_and_installs_code(self):
        original = self.config.read_bytes()
        INSTALLER.upgrade()
        self.assertEqual(json.loads(self.config.read_text()), MANAGER.migrate_config(SCHEMA1_CONFIG))
        backups = list(self.config.parent.glob('meshcentral-deploy.json.pre-upgrade-*'))
        self.assertEqual([path.read_bytes() for path in backups], [original])
        expected = (DEPLOYMENT / 'release_manager.py').read_text(encoding='utf-8')
        self.assertEqual(self.paths['CONTROLLER'].read_text(encoding='utf-8'), expected)
        INSTALLER.fcntl.flock.assert_called_once()
        # A second upgrade leaves the already-current configuration alone.
        INSTALLER.upgrade()
        self.assertEqual(len(list(self.config.parent.glob('meshcentral-deploy.json.pre-upgrade-*'))), 1)

    def test_upgrade_refuses_during_an_interrupted_transaction(self):
        self.state.mkdir()
        (self.state / 'transaction.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'interrupted transaction'):
            INSTALLER.upgrade()
        self.assertEqual(json.loads(self.config.read_text()), SCHEMA1_CONFIG)
        self.assertEqual(self.paths['CONTROLLER'].read_text(), 'installed before upgrade\n')

    def test_upgrade_requires_an_existing_complete_installation(self):
        self.paths['SUDOERS'].unlink()
        with self.assertRaisesRegex(ValueError, 'incomplete.*sudoers'):
            INSTALLER.upgrade()
        self.config.unlink()
        with self.assertRaisesRegex(ValueError, 'No controller configuration'):
            INSTALLER.upgrade()

    def test_upgrade_refuses_while_another_operation_holds_the_lock(self):
        INSTALLER.fcntl.flock.side_effect = BlockingIOError()
        with self.assertRaisesRegex(RuntimeError, 'operation is running'):
            INSTALLER.upgrade()
        self.assertEqual(json.loads(self.config.read_text()), SCHEMA1_CONFIG)


if __name__ == '__main__':
    unittest.main()
