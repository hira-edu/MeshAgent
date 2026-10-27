"""Fork-safety tests for the image release tooling; never invoke Docker, SSH, systemd, or a live endpoint.

Covers agent seeding (T11), the reviewed-version allowlist (D5/T23), the start-time shadow-copy
check (G4), the smoke assertions (T22), the tracked image-size mitigation (T24) and the
image build context (T20).
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
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
SHADOW = load('meshcentral_shadow_check_fork_safety', 'tools/deployment/meshcentral_shadow_check.py')
SMOKE = load('smoke_checks_fork_safety', 'tools/deployment/smoke_checks.py')
SMOKE_IMAGE = load('smoke_image_fork_safety', 'tools/deployment/smoke_image.py')
INSTALLER = load('install_controller_fork_safety', 'tools/deployment/install_controller.py')
DIGEST = 'sha256:' + 'a' * 64
PREVIOUS = 'sha256:' + 'b' * 64
SERVICE_ACCOUNT = types.SimpleNamespace(pw_uid=0, pw_gid=0, pw_dir='/nonexistent')
FORK_REVISION = 'c' * 40
TRACKED_MITIGATION = DEPLOYMENT / 'harden-image-size.js'
TRACKED_DROPIN = DEPLOYMENT / '30-harden-image-size.conf'
# Installed copies use LF whatever the checkout's line endings are.
MITIGATION_SHA = hashlib.sha256(TRACKED_MITIGATION.read_text(encoding='utf-8').encode('utf-8')).hexdigest()
FIXTURE_MITIGATION = b'// fixture mitigation\n'
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
                       'health_url': 'https://fixture.invalid/health.ashx', 'enable_fleet_update': True,
                       'image_size_mitigation_sha256': sha256(FIXTURE_MITIGATION)}
        mitigation = self.base / 'bin/harden-image-size.js'
        mitigation.parent.mkdir()
        mitigation.write_bytes(FIXTURE_MITIGATION)
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
        migrated = MANAGER.migrate_config(SCHEMA1_CONFIG, MITIGATION_SHA)
        self.assertEqual(migrated, {'schema': 2, 'image': SCHEMA1_CONFIG['image'],
                                    'health_url': SCHEMA1_CONFIG['health_url'],
                                    'reviewed_versions': ['1.2.5'], 'enable_fleet_update': False,
                                    'image_size_mitigation_sha256': MITIGATION_SHA})
        self.assertEqual(MANAGER.migrate_config(migrated, MITIGATION_SHA), migrated)
        self.assertIn('meshcentral_version', SCHEMA1_CONFIG)  # input is not modified

    def test_unmigrated_or_mixed_config_is_refused_with_the_migration_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'meshcentral-deploy.json'
            path.write_text(json.dumps(SCHEMA1_CONFIG))
            with mock.patch.object(MANAGER, 'CONFIG', path), \
                    self.assertRaisesRegex(ValueError, 'retired single meshcentral_version.*--upgrade'):
                MANAGER.load_config()
        with self.assertRaisesRegex(ValueError, 'mixes meshcentral_version'):
            MANAGER.migrate_config(dict(SCHEMA1_CONFIG, reviewed_versions=['1.2.6']), MITIGATION_SHA)

    def test_reviewed_versions_must_be_an_explicit_list_of_exact_versions(self):
        config = MANAGER.migrate_config(SCHEMA1_CONFIG, MITIGATION_SHA)
        for versions in ([], '1.2.5', ['1.2'], ['1.2.5', '1.2.5'], ['v1.2.5'], ['1.2.*'], None):
            with self.subTest(versions=versions), self.assertRaisesRegex(ValueError, 'reviewed_versions'):
                MANAGER.validate_config(dict(config, reviewed_versions=versions))
        MANAGER.validate_config(dict(config, reviewed_versions=['1.2.5', '1.2.6', '1.3.0-fork.1']))
        with self.assertRaisesRegex(ValueError, 'schema'):
            MANAGER.validate_config(dict(config, schema=3))
        config.pop('image_size_mitigation_sha256')
        with self.assertRaisesRegex(ValueError, 'image_size_mitigation_sha256 is missing.*--upgrade'):
            MANAGER.validate_config(config)


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
        self.shadow_check = self.root / 'libexec/meshcentral_shadow_check.py'
        installed = {INSTALLER.CONTROLLER: paths['CONTROLLER'], INSTALLER.CI_ENTRY: paths['CI_ENTRY'],
                     INSTALLER.SHADOW_CHECK: self.shadow_check}
        code = tuple((name, installed[destination], mode) for name, destination, mode in INSTALLER.CODE)
        lock = types.SimpleNamespace(flock=mock.Mock(), LOCK_EX=2, LOCK_NB=4)
        # An installed mitigation identical to the tracked files (production must be reconciled first).
        self.mitigation = self.root / 'opt/meshcentral/bin/harden-image-size.js'
        self.dropin = self.root / 'etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf'
        for source, destination in ((TRACKED_MITIGATION, self.mitigation), (TRACKED_DROPIN, self.dropin)):
            destination.parent.mkdir(parents=True)
            destination.write_bytes(source.read_text(encoding='utf-8').encode('utf-8'))
        files = ((TRACKED_MITIGATION.name, self.mitigation, False), (TRACKED_DROPIN.name, self.dropin, True))
        patches = [mock.patch.object(INSTALLER, name, value) for name, value in paths.items()]
        patches += [mock.patch.object(INSTALLER, 'MITIGATION', self.mitigation),
                    mock.patch.object(INSTALLER, 'MITIGATION_FILES', files),
                    mock.patch.object(INSTALLER.subprocess, 'run'),
                    mock.patch.object(INSTALLER, 'CODE', code), mock.patch.object(INSTALLER, 'fcntl', lock),
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
        self.assertEqual(json.loads(self.config.read_text()), MANAGER.migrate_config(SCHEMA1_CONFIG, MITIGATION_SHA))
        INSTALLER.subprocess.run.assert_not_called()  # identical mitigation: nothing installed or reloaded
        backups = list(self.config.parent.glob('meshcentral-deploy.json.pre-upgrade-*'))
        self.assertEqual([path.read_bytes() for path in backups], [original])
        expected = (DEPLOYMENT / 'release_manager.py').read_text(encoding='utf-8')
        self.assertEqual(self.paths['CONTROLLER'].read_text(encoding='utf-8'), expected)
        self.assertEqual(self.shadow_check.read_text(encoding='utf-8'),
                         (DEPLOYMENT / 'meshcentral_shadow_check.py').read_text(encoding='utf-8'))
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

    def test_upgrade_refuses_a_differing_installed_mitigation_before_changing_anything(self):
        self.mitigation.write_bytes(b'// edited on the server\n')
        with self.assertRaisesRegex(ValueError, 'differs from the tracked'):
            INSTALLER.upgrade()
        self.assertEqual(self.paths['CONTROLLER'].read_text(), 'installed before upgrade\n')
        self.assertEqual(json.loads(self.config.read_text()), SCHEMA1_CONFIG)

    def test_upgrade_refuses_while_another_operation_holds_the_lock(self):
        INSTALLER.fcntl.flock.side_effect = BlockingIOError()
        with self.assertRaisesRegex(RuntimeError, 'operation is running'):
            INSTALLER.upgrade()
        self.assertEqual(json.loads(self.config.read_text()), SCHEMA1_CONFIG)


def write(path, data=b'x'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class ShadowCheckTests(unittest.TestCase):
    """G4: the importable check names every unlisted or changed shadow copy."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for folder in ('meshcentral-data', 'meshcentral-web'):
            (self.root / folder).mkdir()

    def problems(self, allowlist=None, **options):
        return SHADOW.find_shadow_files(self.root, allowlist or {}, **options)

    def test_every_governed_location_is_reported(self):
        data, web = self.root / 'meshcentral-data', self.root / 'meshcentral-web'
        for path in (data / 'meshcore.js', data / 'meshcore.min.js', data / 'modules_meshcore/win-dispatcher.js',
                     data / 'agents/meshagent_osx-arm-64', data / 'signedagents/svchost_payload.dll',
                     data / 'plugins/stfdeploy/stfdeploy.js', web / 'views/default3.handlebars',
                     web / 'public/scripts/r0-umair-reconnect-canary.js'):
            write(path)
        (data / 'modules_meshcore_min').mkdir()
        (web / 'emails').mkdir()
        with self.assertRaises(SHADOW.ShadowCopyError) as raised:
            SHADOW.check(self.root, {})
        message = str(raised.exception)
        for name in ('meshcentral-data/meshcore.js: not in the release shadow allowlist',
                     'meshcentral-data/meshcore.min.js:', 'meshcentral-data/modules_meshcore/win-dispatcher.js:',
                     'meshcentral-data/agents/meshagent_osx-arm-64:', 'meshcentral-data/signedagents/svchost_payload.dll:',
                     'meshcentral-data/plugins/stfdeploy/stfdeploy.js:', 'meshcentral-web/views/default3.handlebars:',
                     'meshcentral-web/public/scripts/r0-umair-reconnect-canary.js:',
                     'meshcentral-data/modules_meshcore_min/: empty folder still hides the package copy',
                     'meshcentral-web/emails/: empty folder'):
            self.assertIn(name, message)
        self.assertIn('shadowAllowlist', message)

    def test_listed_file_passes_and_a_changed_one_reports_both_digests(self):
        custom = write(self.root / 'meshcentral-web/public/scripts/custom.js', b'custom')
        allowlist = {'meshcentral-web/public/scripts/custom.js': sha256(b'custom')}
        SHADOW.check(self.root, allowlist)
        custom.write_bytes(b'edited')
        self.assertEqual(self.problems(allowlist), [
            'meshcentral-web/public/scripts/custom.js: sha256 ' + sha256(b'edited') +
            ' differs from the allowlisted ' + sha256(b'custom')])

    def test_files_outside_governed_locations_are_not_shadows(self):
        for relative in ('meshcentral-data/config.json', 'meshcentral-data/agenterrorlogs.txt',
                         'meshcentral-data/meshcentral.db', 'meshcentral-data/public/old.js',
                         'meshcentral-web/translations.json'):
            write(self.root / relative)
        (self.root / 'meshcentral-data/agents').mkdir()
        self.assertEqual(self.problems(), [])

    def test_symbolic_links_are_reported(self):
        target = write(self.root / 'elsewhere.js')
        link = self.root / 'meshcentral-data/meshcore.js'
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest('Symlinks are unavailable: ' + str(error))
        self.assertEqual(self.problems({'meshcentral-data/meshcore.js': sha256(b'x')}),
                         ['meshcentral-data/meshcore.js: symbolic link'])

    def test_mounted_paths_are_hidden_and_overlays_replace_host_folders(self):
        write(self.root / 'meshcentral-data/meshcore.js', b'')  # Docker's mount-point placeholder
        write(self.root / 'meshcentral-data/signedagents/stale.exe')  # hidden by the runtime mount
        runtime = self.root / 'runtime/signed'
        write(runtime / 'MeshService64.exe', b'exe')
        overlays = {'meshcentral-data/signedagents': runtime}
        self.assertEqual(self.problems(hidden=['meshcentral-data/meshcore.js'], overlays=overlays),
                         ['meshcentral-data/signedagents/MeshService64.exe: not in the release shadow allowlist'])
        self.assertEqual(self.problems({'meshcentral-data/signedagents/MeshService64.exe': sha256(b'exe')},
                                       hidden=['meshcentral-data/meshcore.js'], overlays=overlays), [])

    def test_missing_install_folder_fails_loudly(self):
        (self.root / 'meshcentral-web').rmdir()
        with self.assertRaisesRegex(SHADOW.ShadowCopyError, 'meshcentral-web is not a directory'):
            SHADOW.check(self.root, {})

    def test_malformed_allowlists_are_refused(self):
        digest = sha256(b'x')
        SHADOW.parse_allowlist([{'path': 'meshcentral-web/public/scripts/custom.js', 'sha256': digest}])
        for entries in ({'path': 'x'}, [{'path': '/opt/meshcentral/meshcentral-data/meshcore.js', 'sha256': digest}],
                        [{'path': 'meshcentral-web/public/../../etc/passwd', 'sha256': digest}],
                        [{'path': 'meshcentral-web\\public\\x.js', 'sha256': digest}],
                        [{'path': 'meshcentral-data/config.json', 'sha256': digest}],
                        [{'path': 'meshcentral-data/meshcore.js', 'sha256': digest.upper()}],
                        [{'path': 'meshcentral-data/meshcore.js', 'sha256': digest, 'note': 'x'}],
                        [{'path': 'meshcentral-data/meshcore.js', 'sha256': digest}] * 2):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                SHADOW.parse_allowlist(entries)

    def test_command_line_reports_violations_and_exit_status(self):
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps({'shadowAllowlist': []}))
        self.assertEqual(SHADOW.main(['--root', str(self.root), '--manifest', str(manifest)]), 0)
        write(self.root / 'meshcentral-data/meshcore.js')
        with mock.patch('sys.stderr', new_callable=lambda: __import__('io').StringIO()) as stderr:
            self.assertEqual(SHADOW.main(['--root', str(self.root), '--manifest', str(manifest)]), 1)
        self.assertIn('meshcentral-data/meshcore.js: not in the release shadow allowlist', stderr.getvalue())


class StartShadowCheckTests(FixtureCase):
    """G4 runs in start and recover, against the folders as the container sees them."""

    def setUp(self):
        super().setUp()
        self.docker_runs = []
        for patch in (mock.patch.object(MANAGER, 'run', side_effect=lambda *args, **kw: self.docker_runs.append(args)),
                      mock.patch.object(MANAGER, 'remove_container')):
            patch.start()
            self.addCleanup(patch.stop)

    def release(self, digest=DIGEST, **extra):
        directory = make_release(self.release_dir(digest), {'data/MeshService64.exe': b'exe'}, **extra)
        return {'digest': digest, 'directory': str(directory), 'runtime': str(MANAGER.seed_agents(directory))}

    def test_start_refuses_unlisted_shadow_copies_before_running_the_container(self):
        write(self.base / 'meshcentral-data/meshcore.js', b'')
        write(self.base / 'meshcentral-web/views/default3.handlebars')
        with self.assertRaises(MANAGER.meshcentral_shadow_check.ShadowCopyError) as raised:
            MANAGER.start(self.config, self.release())
        self.assertIn('meshcentral-data/meshcore.js: not in the release shadow allowlist', str(raised.exception))
        self.assertIn('meshcentral-web/views/default3.handlebars:', str(raised.exception))
        self.assertEqual(self.docker_runs, [])

    def test_start_accepts_allowlisted_files_and_paths_covered_by_its_mounts(self):
        write(self.base / 'meshcentral-web/public/scripts/custom.js', b'custom')
        write(self.base / 'meshcentral-data/meshcore.js', b'')  # covered by this release's mount
        directory = make_release(
            self.release_dir(DIGEST), {'data/MeshService64.exe': b'exe', 'data-core/meshcore.js': b'core'},
            mounts=[{'source': 'data-core/meshcore.js', 'target': str(self.base / 'meshcentral-data') + '/meshcore.js'}],
            shadowAllowlist=[{'path': 'meshcentral-web/public/scripts/custom.js', 'sha256': sha256(b'custom')}])
        release = {'digest': DIGEST, 'directory': str(directory), 'runtime': str(MANAGER.seed_agents(directory))}
        MANAGER.start(self.config, release)
        self.assertEqual(len(self.docker_runs), 1)

    def test_recover_runs_the_check_for_the_previous_release(self):
        previous = self.release(PREVIOUS)
        write(self.base / 'meshcentral-data/modules_meshcore/win-dispatcher.js')
        transaction = {'previous': previous, 'candidate': None,
                       'config_backup': str(write(self.state / 'config-backup.json', self.config_path.read_bytes())),
                       'config_metadata': {'uid': 0, 'gid': 0, 'mode': 0o600}}
        with self.assertRaisesRegex(MANAGER.meshcentral_shadow_check.ShadowCopyError,
                                    'meshcentral-data/modules_meshcore/win-dispatcher.js'):
            MANAGER.recover(self.config, transaction)
        self.assertEqual(self.docker_runs, [])

    def test_allowlist_cannot_contradict_the_release_agent_files(self):
        release = self.release(shadowAllowlist=[{'path': 'meshcentral-data/agents/MeshService64.exe',
                                                 'sha256': sha256(b'other')}])
        with self.assertRaisesRegex(ValueError, 'disagree on meshcentral-data/agents/MeshService64.exe'):
            MANAGER.start(self.config, release)

    def test_malformed_allowlist_is_refused_at_preparation(self):
        directory = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'exe'},
                                 shadowAllowlist=[{'path': 'meshcentral-data/config.json', 'sha256': sha256(b'x')}])
        with self.assertRaisesRegex(ValueError, 'governed folder'):
            MANAGER.validate_manifest(directory / 'overrides', self.config['reviewed_versions'])


class TrackedMitigationTests(unittest.TestCase):
    """T24: the production image-size mitigation is tracked and installed from the repository."""

    def test_tracked_files_agree_on_the_preload_path(self):
        dropin = TRACKED_DROPIN.read_text(encoding='utf-8')
        self.assertIn('Environment="NODE_OPTIONS=--require /opt/meshcentral/bin/harden-image-size.js"', dropin)
        self.assertEqual(INSTALLER.MITIGATION.as_posix(), '/opt/meshcentral/bin/harden-image-size.js')
        self.assertEqual((MANAGER.BASE / 'bin/harden-image-size.js').as_posix(), INSTALLER.MITIGATION.as_posix())
        destinations = {name: destination.as_posix() for name, destination, _ in INSTALLER.MITIGATION_FILES}
        self.assertEqual(destinations, {
            'harden-image-size.js': '/opt/meshcentral/bin/harden-image-size.js',
            '30-harden-image-size.conf': '/etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf'})

    def test_shim_disables_the_unpatched_parsers_and_logs_the_smoke_marker(self):
        shim = TRACKED_MITIGATION.read_text(encoding='utf-8')
        self.assertIn("var DISABLE = ['icns', 'jxl', 'jxl-stream', 'heif'];", shim)
        self.assertIn("'harden-image-size: disabled unpatched parsers: '", shim)
        self.assertEqual(SMOKE.HARDEN_MARKER, 'harden-image-size: disabled unpatched parsers: icns, jxl, jxl-stream, heif')


class MitigationInstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.mitigation = self.root / 'opt/meshcentral/bin/harden-image-size.js'
        self.dropin = self.root / 'etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf'
        files = ((TRACKED_MITIGATION.name, self.mitigation, False), (TRACKED_DROPIN.name, self.dropin, True))
        for patch in (mock.patch.object(INSTALLER, 'MITIGATION', self.mitigation),
                      mock.patch.object(INSTALLER, 'MITIGATION_FILES', files),
                      mock.patch.object(INSTALLER.subprocess, 'run'),
                      mock.patch.object(INSTALLER.os, 'chown', create=True)):
            patch.start()
            self.addCleanup(patch.stop)

    def test_missing_files_are_installed_with_lf_endings_and_systemd_reloads(self):
        self.assertEqual(INSTALLER.install_mitigation(), MITIGATION_SHA)
        self.assertEqual(self.mitigation.read_bytes(), TRACKED_MITIGATION.read_text(encoding='utf-8').encode('utf-8'))
        self.assertNotIn(b'\r\n', self.dropin.read_bytes())
        INSTALLER.subprocess.run.assert_called_once_with(['systemctl', 'daemon-reload'], check=True)

    def test_identical_installed_files_are_kept_without_a_reload(self):
        INSTALLER.install_mitigation()
        INSTALLER.subprocess.run.reset_mock()
        before = self.mitigation.stat().st_mtime_ns
        self.assertEqual(INSTALLER.install_mitigation(), MITIGATION_SHA)
        self.assertEqual(self.mitigation.stat().st_mtime_ns, before)
        INSTALLER.subprocess.run.assert_not_called()

    def test_a_differing_installed_file_is_refused_and_left_alone(self):
        self.mitigation.parent.mkdir(parents=True)
        self.mitigation.write_bytes(b'// locally edited\n')
        with self.assertRaisesRegex(ValueError, 'harden-image-size.js differs from the tracked'):
            INSTALLER.install_mitigation()
        self.assertEqual(self.mitigation.read_bytes(), b'// locally edited\n')
        self.assertFalse(self.dropin.exists())
        INSTALLER.subprocess.run.assert_not_called()

    def test_a_missing_tracked_source_is_refused(self):
        with mock.patch.object(INSTALLER, 'SOURCE', self.root):
            with self.assertRaisesRegex(ValueError, 'Missing tracked mitigation source'):
                INSTALLER.install_mitigation()


class StartMitigationTests(FixtureCase):
    """start() preloads exactly the installed mitigation and refuses a missing or changed copy."""

    def setUp(self):
        super().setUp()
        self.docker_runs = []
        patch = mock.patch.object(MANAGER, 'run', side_effect=lambda *args, **kw: self.docker_runs.append(args))
        patch.start()
        self.addCleanup(patch.stop)
        directory = make_release(self.release_dir(DIGEST), {'data/MeshService64.exe': b'exe'})
        self.release = {'digest': DIGEST, 'directory': str(directory), 'runtime': str(MANAGER.seed_agents(directory))}
        self.mitigation = self.base / 'bin/harden-image-size.js'

    def test_container_preloads_the_mitigation_read_only(self):
        MANAGER.start(self.config, self.release)
        args = self.docker_runs[0]
        self.assertIn('NODE_OPTIONS=--require=' + str(self.mitigation), args)
        self.assertIn('type=bind,src={0},dst={0},readonly'.format(self.mitigation), args)

    def test_missing_or_changed_mitigation_is_refused(self):
        self.mitigation.write_bytes(b'// changed\n')
        with self.assertRaisesRegex(ValueError, 'differs from the copy install_controller.py installed'):
            MANAGER.start(self.config, self.release)
        self.mitigation.unlink()
        with self.assertRaisesRegex(ValueError, 'mitigation .* is missing.*--upgrade'):
            MANAGER.start(self.config, self.release)
        self.assertEqual(self.docker_runs, [])


CORE_HASH = 'd' * 96


def smoke_manifest(**changes):
    manifest = {'schema': 1, 'meshcentral_version': '1.2.5', 'reviewedUpstreamVersion': '1.2.5',
                'forkRevision': FORK_REVISION, 'agentCoreHashes': {'windows-amd64': CORE_HASH},
                'agentBinaries': {'4': {'localname': 'MeshService64.exe', 'unsigned': True,
                                        'path': 'node_modules/meshcentral/agents/MeshService64.exe',
                                        'sha256': sha256(b'agent')}},
                'files': {}, 'mounts': []}
    manifest.update(changes)
    return manifest


def cores_page(rows):
    """The /meshagents?cores=1 page as webserver.js 1.2.5:6550-6555 renders it."""
    page = ('<html><head><title>Mesh Agents Cores</title><style>table,th,td { border:1px solid black;'
            'border-collapse:collapse;padding:3px; }</style></head><body style=overflow:auto><table>'
            '<tr style="background-color:lightgray"><th>Name</th><th>Size</th><th>Comp</th>'
            '<th>Decompressed Hash SHA384</th></tr>')
    for name, digest in rows:
        page += ('<tr><td>' + name.replace(' ', '&nbsp;') + '</td><td style="text-align:right"><a download '
                 'href="/meshagents?dlcore=' + name + '">1234</a></td><td style="text-align:right"><a download '
                 'href="/meshagents?dlccore=' + name + '">567</a></td><td>' + digest + '</td></tr>')
    return page + '</table><a href="/meshagents">Mesh Agents</a></body></html>'


class FakeServer:
    def __init__(self, version='MeshCentral v1.2.5', cores=None):
        self.version, self.cores, self.logins = version, cores or {'windows-amd64': CORE_HASH}, []

    def get(self, path):
        assert path == SMOKE.VERSION_PATH, path
        return self.version

    def login(self, username, password):
        self.logins.append((username, password))

    def core_hashes(self):
        return self.cores


class SmokeExpectationTests(unittest.TestCase):
    """T22: the smoke test needs the fork identity in the manifest and refuses images without it."""

    def test_fork_manifest_yields_the_identity_to_prove(self):
        expected = SMOKE.expectations(smoke_manifest())
        self.assertEqual((expected['version'], expected['forkRevision']), ('1.2.5', FORK_REVISION))

    def test_pre_fork_or_incomplete_manifests_are_refused_naming_each_field(self):
        manifest = smoke_manifest()
        for field in ('forkRevision', 'agentCoreHashes', 'agentBinaries'):
            del manifest[field]
        with self.assertRaises(SMOKE.SmokeFailure) as raised:
            SMOKE.expectations(manifest)
        for text in ('forkRevision is missing', 'images built before the fork', 'agentCoreHashes', 'agentBinaries'):
            self.assertIn(text, str(raised.exception))

    def test_malformed_agent_entries_are_refused(self):
        good = smoke_manifest()['agentBinaries']['4']
        for entry in (dict(good, path='/opt/meshcentral/node_modules/meshcentral/agents/MeshService64.exe'),
                      dict(good, path='node_modules/meshcentral/agents/MeshService.exe'),
                      dict(good, path='node_modules/../agents/MeshService64.exe'),
                      dict(good, unsigned='yes'), dict(good, sha256='A' * 64),
                      {key: value for key, value in good.items() if key != 'localname'}):
            with self.subTest(entry=entry), self.assertRaisesRegex(SMOKE.SmokeFailure, r"agentBinaries\['4'\]"):
                SMOKE.expectations(smoke_manifest(agentBinaries={'4': entry}))
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'reviewedUpstreamVersion'):
            SMOKE.expectations(smoke_manifest(reviewedUpstreamVersion='1.2.4'))


class SmokeAssertionTests(unittest.TestCase):
    """T22: version, fork revision, served core hash, selected on-disk agent file, preload."""

    def setUp(self):
        self.expected = SMOKE.expectations(smoke_manifest())
        self.files = {'node_modules/meshcentral/agents/MeshService64.exe': b'agent'}

    def exists(self, relative):
        return relative in self.files

    def digest(self, relative):
        return sha256(self.files[relative])

    def test_agent_selection_mirrors_meshcentral_precedence(self):
        entry = {'localname': 'MeshService64.exe', 'unsigned': False}
        package = 'node_modules/meshcentral/agents/MeshService64.exe'
        signed = 'meshcentral-data/signedagents/MeshService64.exe'
        data = 'meshcentral-data/agents/MeshService64.exe'
        for present, selected in (({package}, package), ({package, signed}, signed),
                                  ({package, signed, data}, data), ({package, data}, data)):
            with self.subTest(present=present):
                self.assertEqual(SMOKE.selected_agent_path(entry, present.__contains__), selected)
        unsigned = dict(entry, unsigned=True)
        self.assertEqual(SMOKE.selected_agent_path(unsigned, {package, signed, data}.__contains__), package)

    def test_on_disk_agent_file_must_be_the_manifest_file(self):
        self.assertEqual(SMOKE.check_agent_binaries(self.expected, self.exists, self.digest), [])
        self.files['node_modules/meshcentral/agents/MeshService64.exe'] = b'other build'
        self.assertEqual(SMOKE.check_agent_binaries(self.expected, self.exists, self.digest), [
            'agent 4: node_modules/meshcentral/agents/MeshService64.exe has sha256 ' + sha256(b'other build') +
            ', manifest expects ' + sha256(b'agent')])
        self.files.clear()
        self.assertIn('does not exist', SMOKE.check_agent_binaries(self.expected, self.exists, self.digest)[0])

    def test_a_data_folder_copy_that_wins_selection_is_reported(self):
        expected = SMOKE.expectations(smoke_manifest(agentBinaries={'4': dict(
            smoke_manifest()['agentBinaries']['4'], unsigned=False)}))
        self.files['meshcentral-data/agents/MeshService64.exe'] = b'stale'
        self.assertEqual(SMOKE.check_agent_binaries(expected, self.exists, self.digest), [
            'agent 4: MeshCentral selects meshcentral-data/agents/MeshService64.exe, manifest expects '
            'node_modules/meshcentral/agents/MeshService64.exe'])

    def test_core_table_is_parsed_and_compared(self):
        served = SMOKE.parse_core_hashes(cores_page([('windows-amd64', CORE_HASH), ('linux noamt', 'e' * 96)]))
        self.assertEqual(served, {'windows-amd64': CORE_HASH, 'linux noamt': 'e' * 96})
        self.assertEqual(SMOKE.check_core_hashes(served, self.expected), [])
        self.assertEqual(SMOKE.check_core_hashes({'windows-amd64': 'f' * 96}, self.expected), [
            "agent core 'windows-amd64' is served with SHA-384 " + 'f' * 96 + ', manifest expects ' + CORE_HASH])
        self.assertEqual(SMOKE.check_core_hashes({}, self.expected), ["agent core 'windows-amd64' is not served"])
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'listed no agent cores'):
            SMOKE.parse_core_hashes(cores_page([]))
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'Unexpected agent core table row'):
            SMOKE.parse_core_hashes(cores_page([('windows-amd64', 'not-a-hash')]))

    def test_version_revision_and_preload_checks(self):
        self.assertEqual(SMOKE.check_served_version('MeshCentral v1.2.5', self.expected), [])
        self.assertEqual(SMOKE.check_served_version('MeshCentral v1.2.6', self.expected),
                         ["served version 'MeshCentral v1.2.6' is not MeshCentral v1.2.5"])
        self.assertEqual(SMOKE.check_fork_revision(json.dumps({'version': '1.2.5', 'forkRevision': FORK_REVISION}),
                                                   self.expected), [])
        self.assertIn('forkRevision None', SMOKE.check_fork_revision('{"version": "1.2.5"}', self.expected)[0])
        shim = TRACKED_MITIGATION.read_text(encoding='utf-8')
        logged = 'harden-image-size: disabled unpatched parsers: ' + ', '.join(
            re.search(r"var DISABLE = \[([^]]*)\]", shim).group(1).replace("'", '').split(', '))
        self.assertEqual(SMOKE.check_preload('MeshCentral HTTP server running\n' + logged + '\n'), [])
        self.assertIn('preload did not run', SMOKE.check_preload(
            'harden-image-size: WARNING - could not harden image-size: Cannot find module')[0])

    def test_run_checks_reports_every_failure_together(self):
        server = FakeServer(version='MeshCentral v1.2.6', cores={'windows-amd64': 'f' * 96})
        self.files.clear()
        with self.assertRaises(SMOKE.SmokeFailure) as raised:
            SMOKE.run_checks(smoke_manifest(), server, ('smoke', 'secret'), 'no marker', '{}', self.exists, self.digest)
        message = str(raised.exception)
        for text in ('preload did not run', 'served version', 'forkRevision', "agent core 'windows-amd64'",
                     'agent 4:'):
            self.assertIn(text, message)
        self.assertEqual(server.logins, [('smoke', 'secret')])
        passing = FakeServer()
        self.files['node_modules/meshcentral/agents/MeshService64.exe'] = b'agent'
        SMOKE.run_checks(smoke_manifest(), passing, ('smoke', 'secret'), SMOKE.HARDEN_MARKER,
                         json.dumps({'forkRevision': FORK_REVISION}), self.exists, self.digest)


class SmokeCommandTests(unittest.TestCase):
    """T22: the smoke runs against a local duplicate server with the same assertions."""

    def test_duplicate_server_mode_reads_the_local_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write(root / 'node_modules/meshcentral/agents/MeshService64.exe', b'agent')
            write(root / 'node_modules/meshcentral/package.json',
                  json.dumps({'version': '1.2.5', 'forkRevision': FORK_REVISION}).encode())
            manifest = write(root / 'manifest.json', json.dumps(smoke_manifest()).encode())
            log = write(root / 'server.log', (SMOKE.HARDEN_MARKER + '\n').encode())
            server = FakeServer()
            with mock.patch.dict(os.environ, {'SMOKE_USERNAME': 'smoke', 'SMOKE_PASSWORD': 'secret'}), \
                    mock.patch.object(SMOKE_IMAGE.smoke_checks, 'Server', return_value=server):
                SMOKE_IMAGE.main(['--server-url', 'http://127.0.0.1:4430', '--install-root', str(root),
                                  '--manifest', str(manifest), '--server-log', str(log)])
            self.assertEqual(server.logins, [('smoke', 'secret')])
            write(root / 'node_modules/meshcentral/agents/MeshService64.exe', b'changed')
            with mock.patch.dict(os.environ, {'SMOKE_USERNAME': 'smoke', 'SMOKE_PASSWORD': 'secret'}), \
                    mock.patch.object(SMOKE_IMAGE.smoke_checks, 'Server', return_value=FakeServer()), \
                    self.assertRaisesRegex(SMOKE_IMAGE.smoke_checks.SmokeFailure, 'agent 4: .* has sha256'):
                SMOKE_IMAGE.main(['--server-url', 'http://127.0.0.1:4430', '--install-root', str(root),
                                  '--manifest', str(manifest), '--server-log', str(log)])

    def test_partial_duplicate_server_options_and_missing_credentials_are_refused(self):
        with mock.patch('sys.stderr'), self.assertRaises(SystemExit):
            SMOKE_IMAGE.main(['--server-url', 'http://127.0.0.1:4430'])
        with mock.patch.dict(os.environ, {'SMOKE_USERNAME': '', 'SMOKE_PASSWORD': ''}), \
                self.assertRaisesRegex(ValueError, 'SMOKE_USERNAME and SMOKE_PASSWORD'):
            SMOKE_IMAGE.smoke_server('http://127.0.0.1:4430', '.', 'manifest.json', 'server.log')

    def test_image_mode_refuses_mutable_references_before_docker(self):
        with mock.patch.object(SMOKE_IMAGE, 'run') as run, \
                self.assertRaisesRegex(ValueError, 'immutable registry digest'):
            SMOKE_IMAGE.smoke_image('ghcr.io/fixture/release:latest')
        run.assert_not_called()

    def test_image_mode_preloads_the_tracked_mitigation(self):
        self.assertEqual(SMOKE_IMAGE.MITIGATION_SOURCE, TRACKED_MITIGATION)
        self.assertEqual(SMOKE_IMAGE.MITIGATION_TARGET, INSTALLER.MITIGATION.as_posix())


def docker_ignore_rules(path):
    rules = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            negate = line.startswith('!')
            pattern = line[1:] if negate else line
            regex = ''.join('.*' if part == '**' else re.escape(part).replace(r'\*', '[^/]*').replace(r'\?', '[^/]')
                            for part in re.split(r'(\*\*)', pattern.strip('/')))
            rules.append((negate, re.compile(regex + r'\Z')))
    return rules


def docker_excludes(rules, path):
    """Docker's rule: the last pattern matching the path or one of its parents decides."""
    parts = path.split('/')
    candidates = ['/'.join(parts[:index]) for index in range(1, len(parts) + 1)]
    excluded = False
    for negate, regex in rules:
        if any(regex.match(candidate) for candidate in candidates):
            excluded = not negate
    return excluded


class DockerContextTests(unittest.TestCase):
    """T20: local state never enters the image build context; every COPY source still does."""

    def setUp(self):
        self.rules = docker_ignore_rules(DEPLOYMENT / 'Dockerfile.dockerignore')

    def test_every_dockerfile_copy_source_is_sent(self):
        sources = []
        for line in (DEPLOYMENT / 'Dockerfile').read_text(encoding='utf-8').splitlines():
            words = line.split()
            if words[:1] == ['COPY'] and not any(word.startswith('--from') for word in words):
                sources += words[1:-1]
        self.assertIn('MeshCentral', sources)
        self.assertIn('artifacts', sources)
        for source in sources:
            with self.subTest(source=source):
                self.assertFalse(docker_excludes(self.rules, source))

    def test_files_the_build_reads_are_sent(self):
        for path in ('MeshCentral/package-lock.json', 'MeshCentral/agents/meshcore.js',
                     'MeshCentral/agents/hashagents.js', 'MeshCentral/public/scripts/agent-desktop-0.0.2.js',
                     'MeshCentral/plugins/nativeruntime/nativeruntime.js', 'MeshCentral/meshagent.js',
                     'MeshCentral/THIRD_PARTY_NOTICES.txt',
                     'artifacts/MeshServiceRuntime-MeshService64.exe/MeshService64.exe'):
            with self.subTest(path=path):
                self.assertFalse(docker_excludes(self.rules, path))

    def test_local_state_secrets_and_siblings_are_not_sent(self):
        for path in ('MeshCentral/node_modules/meshcentral/meshcentral.js', 'MeshCentral/meshcentral-data/config.json',
                     'MeshCentral/meshcentral-data/agentserver-cert-private.key', 'MeshCentral/server-backups/dump.zip',
                     'MeshCentral/meshcentral-web/public/scripts/custom.js', 'MeshCentral/meshcentral-files/x',
                     'MeshCentral/meshcentral-backups/x', 'MeshCentral/meshcentral-recordings/x',
                     'MeshAgent/branding_config.local.json', 'MeshAgent/artifacts/validation/report.json',
                     'MeshAgent/tools/deployment/Dockerfile', 'meshcentral-fork-ssot/SSOT.md', 'UserModeHook/build/x'):
            with self.subTest(path=path):
                self.assertTrue(docker_excludes(self.rules, path))

    def test_matcher_follows_docker_last_match_semantics(self):
        rules = [(False, re.compile(r'[^/]*\Z')), (True, re.compile(r'a/b\Z'))]
        self.assertFalse(docker_excludes(rules, 'a/b'))
        self.assertTrue(docker_excludes(rules, 'a/c'))


# A stand-in for image-size 2.0.2's public surface (types, disableTypes, imageSize and its
# "disabled file type" refusal), with variants for a changed or broken package.
FAKE_IMAGE_SIZE = r"""
var mode = require('./mode.json').mode;
var types = ['bmp', 'heif', 'icns', 'jpg', 'jxl', 'jxl-stream', 'png'];
if (mode === 'renamed') { types = types.map(function (t) { return t === 'jxl-stream' ? 'jxl-codestream' : t; }); }
var disabled = [];
function detect(b) {
    if (b.slice(0, 4).toString() === 'icns') { return 'icns'; }
    if (b[0] === 0xff && b[1] === 0x0a) { return 'jxl-stream'; }
    var box = b.slice(4, 8).toString();
    if (box === 'JXL ') { return 'jxl'; }
    if (box === 'ftyp') { return 'heif'; }
}
exports.types = types;
exports.imageSize = function (b) {
    var t = detect(b);
    if (disabled.indexOf(t) >= 0) { throw new TypeError('disabled file type: ' + t); }
    return { width: 1, height: 1, type: t };
};
if (mode !== 'no-disable') { exports.disableTypes = function (list) { if (mode !== 'noop') { disabled = list; } }; }
"""


@unittest.skipUnless(shutil.which('node'), 'Node.js is required to run the preload shim')
class MitigationShimTests(unittest.TestCase):
    """T24 follow-up: the shim resolves image-size like MeshCentral does and fails closed."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # A non-/opt install layout: <root>/srv/node_modules/{meshcentral,image-size}.
        self.main = write(self.root / 'srv/node_modules/meshcentral/meshcentral.js',
                          b"console.log('meshcentral main ran');\n")
        self.elsewhere = self.root / 'elsewhere'
        self.elsewhere.mkdir()

    def install_image_size(self, folder, mode='ok'):
        package = folder / 'node_modules/image-size'
        write(package / 'package.json', json.dumps({'name': 'image-size', 'version': '2.0.2',
                                                    'main': 'index.js'}).encode())
        write(package / 'index.js', FAKE_IMAGE_SIZE.encode())
        write(package / 'mode.json', json.dumps({'mode': mode}).encode())

    def start(self, main=None, cwd=None):
        environment = {key: value for key, value in os.environ.items() if key != 'NODE_OPTIONS'}
        return subprocess.run(['node', '--require', str(TRACKED_MITIGATION), str(main or self.main)],
                              cwd=str(cwd or self.elsewhere), env=environment, capture_output=True,
                              text=True, timeout=60)

    def assert_refused(self, result, reason):
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('meshcentral main ran', result.stdout)
        self.assertIn('refusing to start MeshCentral with the unpatched image-size parsers enabled', result.stderr)
        self.assertIn(reason, result.stderr)
        self.assertNotEqual(SMOKE.check_preload(result.stdout + result.stderr), [])

    def test_no_install_path_is_hardcoded(self):
        self.assertNotIn('/opt/', TRACKED_MITIGATION.read_text(encoding='utf-8'))

    def test_resolves_from_the_started_script_in_a_non_opt_layout(self):
        self.install_image_size(self.root / 'srv')
        result = self.start()  # working directory has no node_modules
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [SMOKE.HARDEN_MARKER, 'meshcentral main ran'])
        self.assertEqual(SMOKE.check_preload(result.stdout), [])

    def test_falls_back_to_the_working_directory(self):
        self.install_image_size(self.elsewhere)
        main = write(self.root / 'bare/meshcentral.js', b"console.log('meshcentral main ran');\n")
        result = self.start(main=main)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(SMOKE.HARDEN_MARKER, result.stdout)

    def test_missing_image_size_stops_the_process(self):
        self.assert_refused(self.start(), 'image-size cannot be resolved from')

    def test_missing_disable_api_stops_the_process(self):
        self.install_image_size(self.root / 'srv', 'no-disable')
        self.assert_refused(self.start(), 'does not provide disableTypes()')

    def test_changed_parser_layout_stops_the_process(self):
        self.install_image_size(self.root / 'srv', 'renamed')
        self.assert_refused(self.start(), 'no longer lists the parser(s) jxl-stream')

    def test_a_parser_that_stays_enabled_stops_the_process(self):
        self.install_image_size(self.root / 'srv', 'noop')
        self.assert_refused(self.start(), 'the icns probe was parsed')


if __name__ == '__main__':
    unittest.main()
