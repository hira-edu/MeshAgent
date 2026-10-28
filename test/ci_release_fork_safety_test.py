"""Fork-safety tests for the image release tooling; never invoke Docker, SSH, systemd, or a live endpoint.

Covers tarball-only releases (Stage 4: no overlay mounts, no seeded agent folders; DEP-22, DEP-25,
PRD-3), the reviewed-version allowlist (D5/T23), the start-time shadow-copy check (G4, N6), the smoke
assertions (T22), the retired image-size preload (T24, DEP-21), the image build (release_image.js,
T21) and the image build context (T20).
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
SCHEMA1_CONFIG = {'image': 'ghcr.io/fixture/release', 'health_url': 'https://fixture.invalid/health.ashx',
                  'meshcentral_version': '1.2.5', 'enable_fleet_update': False}
# A schema-2 configuration as install_controller wrote it while the image-size preload was policy.
SCHEMA2_CONFIG = {'schema': 2, 'image': 'ghcr.io/fixture/release', 'health_url': 'https://fixture.invalid/health.ashx',
                  'reviewed_versions': ['1.2.5'], 'enable_fleet_update': False,
                  'image_size_mitigation_sha256': 'e' * 64}
CURRENT_CONFIG = {'schema': 3, 'image': 'ghcr.io/fixture/release', 'health_url': 'https://fixture.invalid/health.ashx',
                  'reviewed_versions': ['1.2.5'], 'enable_fleet_update': False}
LEGACY_SCRIPT = b'// production harden-image-size.js\n'
LEGACY_DROPIN = b'[Service]\nEnvironment="NODE_OPTIONS=--require /opt/meshcentral/bin/harden-image-size.js"\n'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha384(data):
    return hashlib.sha384(data).hexdigest()


AGENT = b'fork agent build'
CORE_HASH = 'd' * 96
INTEGRITY = 'sha512-' + 'A' * 86 + '=='
PACKAGED_COMMIT = 'f' * 40
AGENT_BUILD = {'repository': 'hira-edu/MeshAgent', 'commit': '3' * 40}


def fork_manifest(version='1.3.1', **changes):
    """A schema-2 release manifest as release_image.js writes it."""
    manifest = {'schema': 2, 'meshcentral_version': version, 'reviewedUpstreamVersion': version,
                'forkRevision': FORK_REVISION,
                'package': {'tarball': 'meshcentral-' + version + '.tgz', 'integrity': INTEGRITY,
                            'packagedCommit': PACKAGED_COMMIT},
                'agentBuild': dict(AGENT_BUILD),
                'agentBinaries': {'4': {'localname': 'MeshService64.exe', 'unsigned': True,
                                        'path': 'node_modules/meshcentral/agents/MeshService64.exe',
                                        'size': len(AGENT), 'sha384': sha384(AGENT)}},
                'agentCoreHashes': {'windows-amt': CORE_HASH},
                'shadowAllowlist': []}
    manifest.update(changes)
    return manifest


def make_release(directory, version='1.3.1', **changes):
    """Create a prepared release directory: <directory>/release/manifest.json, as prepare() copies it."""
    folder = Path(directory) / 'release'
    folder.mkdir(parents=True)
    (folder / 'manifest.json').write_text(json.dumps(fork_manifest(version, **changes)))
    return Path(directory)


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
        self.config = {'schema': 3, 'image': 'ghcr.io/fixture/release', 'reviewed_versions': ['1.3.1'],
                       'health_url': 'https://fixture.invalid/health.ashx', 'enable_fleet_update': True}
        # The legacy host preload paths, absent unless a test installs them.
        self.legacy = (self.base / 'bin/harden-image-size.js',
                       self.root / 'etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf')
        for target, name, value in ((MANAGER, 'BASE', self.base), (MANAGER, 'STATE', self.state),
                                    (MANAGER, 'LEGACY_PRELOAD', self.legacy),
                                    (MANAGER, 'pwd', types.SimpleNamespace(getpwnam=lambda name: SERVICE_ACCOUNT))):
            patch = mock.patch.object(target, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(MANAGER.os, 'chown', create=True)
        patch.start()
        self.addCleanup(patch.stop)

    def release_dir(self, digest):
        return self.state / 'releases' / digest.split(':')[1]

    def release(self, digest=DIGEST, version='1.3.1', **changes):
        return {'digest': digest, 'directory': str(make_release(self.release_dir(digest), version, **changes))}


def write(path, data=b'x'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class TarballReleaseTests(FixtureCase):
    """DEP-22/DEP-25/PRD-3: a release is the image's package; nothing is mounted over it or seeded."""

    def setUp(self):
        super().setUp()
        self.run_calls = []
        for name, value in {'run': mock.Mock(side_effect=lambda *args, **kw: self.run_calls.append(args)),
                            'remove_container': mock.Mock(), 'healthy': mock.Mock(return_value=True)}.items():
            patch = mock.patch.object(MANAGER, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def docker_run(self):
        runs = [call for call in self.run_calls if call[:2] == ('docker', 'run')]
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_the_container_mounts_only_the_persistent_folders(self):
        MANAGER.start(self.config, self.release())
        args = self.docker_run()
        mounts = [args[index + 1] for index, arg in enumerate(args) if arg == '--mount']
        self.assertEqual(mounts, ['type=bind,src={0},dst={0}'.format(self.base / name) + suffix for name, suffix in (
            ('meshcentral-data', ''), ('meshcentral-files', ''), ('meshcentral-web', ',readonly'),
            ('meshcentral-recordings', ''), ('meshcentral-backups', ''))])
        self.assertTrue(args[-1].endswith('@' + DIGEST))

    def test_promotion_seeds_no_agent_folders_and_keeps_none_of_the_host_copies_out_of_the_check(self):
        # The host's signed/data agent folders are no longer replaced by a release runtime: the fork
        # serves its agents from the package, and any copy left there must pass the shadow check.
        write(self.base / 'meshcentral-data/signedagents/MeshService64.exe', b'retired signed copy')
        with mock.patch.object(MANAGER, 'prepare', return_value=make_release(self.release_dir(DIGEST))), \
                self.assertRaisesRegex(MANAGER.meshcentral_shadow_check.ShadowCopyError,
                                       'meshcentral-data/signedagents/MeshService64.exe: not in the release'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(self.run_calls, [])  # refused before the host service was stopped
        self.assertFalse((self.state / 'transaction.json').exists())

    def test_a_promoted_release_records_no_agent_runtime(self):
        with mock.patch.object(MANAGER, 'prepare', return_value=make_release(self.release_dir(DIGEST))):
            MANAGER.promote(self.config, DIGEST)
        active = json.loads((self.state / 'active.json').read_text())
        self.assertEqual(active, {'digest': DIGEST, 'directory': str(self.release_dir(DIGEST))})
        self.assertEqual(sorted(path.name for path in self.release_dir(DIGEST).iterdir()), ['release'])

    def test_overlay_releases_are_refused(self):
        folder = self.root / 'overlay'
        folder.mkdir()
        legacy = {'schema': 1, 'meshcentral_version': '1.2.5', 'files': {'data-core/meshcore.js': 'a' * 64},
                  'mounts': [{'source': 'data-core/meshcore.js', 'target': '/opt/meshcentral/meshcentral-data/meshcore.js'}]}
        for manifest in (legacy, fork_manifest(mounts=[]), fork_manifest(files={})):
            (folder / 'manifest.json').write_text(json.dumps(manifest))
            with self.subTest(manifest=sorted(manifest)), self.assertRaisesRegex(ValueError, 'Overlay release refused'):
                MANAGER.validate_manifest(folder, ['1.2.5', '1.3.1'])

    def test_the_release_folder_holds_only_its_manifest(self):
        directory = make_release(self.release_dir(DIGEST))
        MANAGER.validate_manifest(directory / 'release', ['1.3.1'])
        write(directory / 'release/data/MeshService64.exe', b'seed')
        with self.assertRaisesRegex(ValueError, 'only a regular manifest.json, found: data, manifest.json'):
            MANAGER.validate_manifest(directory / 'release', ['1.3.1'])

    def test_unknown_or_missing_manifest_fields_are_refused(self):
        folder = self.root / 'fields'
        folder.mkdir()
        incomplete = fork_manifest()
        del incomplete['agentBinaries']
        for manifest, text in ((incomplete, "missing \\['agentBinaries'\\]"),
                               (fork_manifest(signedAgents={}), "unknown \\['signedAgents'\\]"),
                               (fork_manifest(schema=3), 'Unsupported release manifest schema: 3')):
            (folder / 'manifest.json').write_text(json.dumps(manifest))
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, text):
                MANAGER.validate_manifest(folder, ['1.3.1'])

    def test_a_linked_release_manifest_is_refused(self):
        directory = make_release(self.release_dir(DIGEST))
        manifest = directory / 'release/manifest.json'
        target = write(self.root / 'elsewhere.json', manifest.read_bytes())
        manifest.unlink()
        try:
            manifest.symlink_to(target)
        except OSError as error:
            self.skipTest('Symlinks are unavailable: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'only a regular manifest.json'):
            MANAGER.validate_manifest(directory / 'release', ['1.3.1'])

    def test_prepare_extracts_the_image_release_folder(self):
        def run(*args, capture=False):
            self.run_calls.append(args)
            if args[:2] == ('docker', 'cp'):
                make_release(Path(args[3]).parent)
            return ''

        MANAGER.run.side_effect = run
        with mock.patch.object(MANAGER.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)):
            directory = MANAGER.prepare(self.config, DIGEST)
        copy = [call for call in self.run_calls if call[:2] == ('docker', 'cp')][0]
        self.assertTrue(copy[2].endswith(':/opt/meshcentral/release'))
        self.assertEqual(directory, self.release_dir(DIGEST))
        self.assertTrue((directory / 'release/manifest.json').is_file())


class ConfigPolicyTests(unittest.TestCase):
    """D5/T23: the controller keeps an allowlist of reviewed versions."""

    def test_schema1_config_migrates_to_an_allowlist_of_its_single_version(self):
        migrated = MANAGER.migrate_config(SCHEMA1_CONFIG)
        self.assertEqual(migrated, CURRENT_CONFIG)
        self.assertEqual(MANAGER.migrate_config(migrated), migrated)
        self.assertIn('meshcentral_version', SCHEMA1_CONFIG)  # input is not modified

    def test_schema2_config_loses_the_retired_mitigation_digest(self):
        self.assertEqual(MANAGER.migrate_config(SCHEMA2_CONFIG), CURRENT_CONFIG)
        self.assertIn('image_size_mitigation_sha256', SCHEMA2_CONFIG)  # input is not modified
        with self.assertRaisesRegex(ValueError, 'Unsupported release controller configuration schema'):
            MANAGER.migrate_config(dict(CURRENT_CONFIG, schema=4))

    def test_a_config_that_still_names_the_preload_is_refused_until_migrated(self):
        # Fail closed: the controller never silently drops the preload policy the operator configured.
        for config in (SCHEMA2_CONFIG, dict(CURRENT_CONFIG, image_size_mitigation_sha256='e' * 64)):
            with self.subTest(schema=config['schema']), \
                    self.assertRaisesRegex(ValueError, 'image_size_mitigation_sha256.*retired image-size preload.*--upgrade'):
                MANAGER.validate_config(config)
        without_key = {key: value for key, value in SCHEMA2_CONFIG.items() if key != 'image_size_mitigation_sha256'}
        with self.assertRaisesRegex(ValueError, 'schema'):
            MANAGER.validate_config(without_key)

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
        for schema in (2, 4):
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, 'schema'):
                MANAGER.validate_config(dict(config, schema=schema))


def write_manifest_fixture(root, version='1.3.1', **changes):
    """A release folder for validate_manifest."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / 'manifest.json').write_text(json.dumps(fork_manifest(version, **changes)))
    return root


class ManifestVersionTests(unittest.TestCase):
    """D5/T23: each manifest records the version it was reviewed for and its fork revision."""

    def test_fork_release_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary)
            MANAGER.validate_manifest(root, ['1.2.5', '1.3.1'])
            self.assertEqual(MANAGER.release_identity(json.loads((root / 'manifest.json').read_text())),
                             ('1.3.1', '1.3.1', FORK_REVISION))

    def test_unreviewed_version_is_refused_with_a_clear_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary, '1.3.2')
            with self.assertRaisesRegex(ValueError, r'MeshCentral 1\.3\.2 is not a reviewed version '
                                                    r'\(reviewed_versions: 1\.2\.5, 1\.3\.1\)'):
                MANAGER.validate_manifest(root, ['1.2.5', '1.3.1'])

    def test_reviewed_version_must_match_the_packaged_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary, '1.3.1', reviewedUpstreamVersion='1.2.5')
            with self.assertRaisesRegex(ValueError, "reviewed for MeshCentral '1.2.5' but packages MeshCentral 1.3.1"):
                MANAGER.validate_manifest(root, ['1.2.5', '1.3.1'])

    def test_fork_revision_must_be_a_full_commit_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary)
            for revision in ('c' * 39, 'C' * 40, 'main', 40, None):
                write_manifest_fixture(temporary, forkRevision=revision)
                with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, 'forkRevision'):
                    MANAGER.validate_manifest(root, ['1.3.1'])

    def test_allowlist_must_be_a_list_not_a_substring_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = write_manifest_fixture(temporary)
            with self.assertRaisesRegex(ValueError, 'reviewed_versions'):
                MANAGER.validate_manifest(root, '1.3.1-fork.1')


class VersionLifecycleTests(FixtureCase):
    """prepare, start and recover all validate against the allowlist."""

    def setUp(self):
        super().setUp()
        self.config['reviewed_versions'] = ['1.3.1', '1.3.2']
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
        previous = self.release(PREVIOUS, version)
        (self.state / 'active.json').write_text(json.dumps(previous))
        return previous

    def test_rollback_to_an_older_reviewed_release_after_a_newer_version_is_allowlisted(self):
        previous = self.promote_previous('1.3.1')
        make_release(self.release_dir(DIGEST), '1.3.2')
        self.fail_candidate = True
        with self.assertRaisesRegex(RuntimeError, 'candidate start'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text()), previous)
        self.assertTrue(self.run_calls[-1][-1].endswith(PREVIOUS))

    def test_prepare_refuses_an_unreviewed_release_before_touching_the_service(self):
        self.promote_previous('1.3.1')
        make_release(self.release_dir(DIGEST), '1.3.3')
        with self.assertRaisesRegex(ValueError, r'1\.3\.3 is not a reviewed version'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(self.run_calls, [])
        MANAGER.remove_container.assert_not_called()
        self.assertFalse((self.state / 'transaction.json').exists())

    def test_recover_refuses_a_previous_release_whose_version_was_withdrawn(self):
        previous = self.promote_previous('1.3.1')
        self.config['reviewed_versions'] = ['1.3.2']
        transaction = {'previous': previous, 'candidate': None,
                       'config_backup': str(self.state / 'config-backup.json'),
                       'config_metadata': {'uid': 0, 'gid': 0, 'mode': 0o600}}
        (self.state / 'config-backup.json').write_text(self.config_path.read_text())
        with self.assertRaisesRegex(ValueError, r'1\.3\.1 is not a reviewed version'):
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
        # The 1.2.5 host service's preload, which an upgrade must leave in place for that service.
        self.legacy = (self.root / 'opt/meshcentral/bin/harden-image-size.js',
                       self.root / 'etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf')
        for path, data in zip(self.legacy, (LEGACY_SCRIPT, LEGACY_DROPIN)):
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
        patches = [mock.patch.object(INSTALLER, name, value) for name, value in paths.items()]
        patches += [mock.patch.object(INSTALLER.release_manager, 'LEGACY_PRELOAD', self.legacy),
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
        self.assertEqual(json.loads(self.config.read_text()), CURRENT_CONFIG)
        INSTALLER.subprocess.run.assert_not_called()  # nothing installed into or reloaded for the host service
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

    def test_upgrade_removes_the_mitigation_digest_and_leaves_the_host_preload(self):
        self.config.write_text(json.dumps(SCHEMA2_CONFIG))
        with mock.patch('sys.stdout', new_callable=lambda: __import__('io').StringIO()) as stdout:
            INSTALLER.upgrade()
        self.assertEqual(json.loads(self.config.read_text()), CURRENT_CONFIG)
        self.assertIn('Removed image_size_mitigation_sha256', stdout.getvalue())
        self.assertEqual([path.read_bytes() for path in self.legacy], [LEGACY_SCRIPT, LEGACY_DROPIN])
        INSTALLER.subprocess.run.assert_not_called()
        backups = list(self.config.parent.glob('meshcentral-deploy.json.pre-upgrade-*'))
        self.assertEqual([json.loads(path.read_text()) for path in backups], [SCHEMA2_CONFIG])

    def test_upgrade_refuses_while_another_operation_holds_the_lock(self):
        INSTALLER.fcntl.flock.side_effect = BlockingIOError()
        with self.assertRaisesRegex(RuntimeError, 'operation is running'):
            INSTALLER.upgrade()
        self.assertEqual(json.loads(self.config.read_text()), SCHEMA1_CONFIG)


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

    def test_the_upstream_agent_download_cache_must_not_exist(self):
        # N6: 1.3.1 downloads agents into meshcentral-data/agentbuilds; the fork never reads it.
        cache = self.root / 'meshcentral-data/agentbuilds'
        cache.mkdir()
        expected = ["meshcentral-data/agentbuilds: must not exist: upstream 1.3.1's agent download cache, "
                    'which the fork never reads; remove it']
        self.assertEqual(self.problems(), expected)
        write(cache / 'meshagent_osx-arm-64', b'downloaded')
        self.assertEqual(self.problems({'meshcentral-data/agentbuilds/meshagent_osx-arm-64': sha256(b'downloaded')}),
                         expected)
        with self.assertRaisesRegex(ValueError, 'cannot allow meshcentral-data/agentbuilds/meshagent_osx-arm-64'):
            SHADOW.parse_allowlist([{'path': 'meshcentral-data/agentbuilds/meshagent_osx-arm-64',
                                     'sha256': sha256(b'downloaded')}])
        with self.assertRaisesRegex(SHADOW.ShadowCopyError, '(?s)Cannot record.*agentbuilds: must not exist'):
            SHADOW.snapshot(self.root)

    def test_provisioning_files_beside_the_agents_shadow_nothing(self):
        # D14: per-environment .msh files stay in meshcentral-data/agents; the server never reads them.
        for name in ('MeshService.msh', 'MeshService64.msh', 'MeshServiceARM64.msh', 'WinDiagnosticHost.msh'):
            write(self.root / 'meshcentral-data/agents' / name, b'MeshName=fixture')
        self.assertEqual(self.problems(), [])
        write(self.root / 'meshcentral-data/agents/MeshService64.exe', b'stale 1.2.5 copy')
        write(self.root / 'meshcentral-data/agents/sub/MeshService64.msh', b'nested')
        write(self.root / 'meshcentral-data/signedagents/MeshService64.msh', b'signed folder')
        self.assertEqual(self.problems(), [
            'meshcentral-data/agents/MeshService64.exe: not in the release shadow allowlist',
            'meshcentral-data/agents/sub/MeshService64.msh: not in the release shadow allowlist',
            'meshcentral-data/signedagents/MeshService64.msh: not in the release shadow allowlist'])

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
    """G4 runs before promotion and in start and recover, against the host folders the container mounts."""

    def setUp(self):
        super().setUp()
        self.docker_runs = []
        for patch in (mock.patch.object(MANAGER, 'run', side_effect=lambda *args, **kw: self.docker_runs.append(args)),
                      mock.patch.object(MANAGER, 'remove_container')):
            patch.start()
            self.addCleanup(patch.stop)

    def test_start_refuses_unlisted_shadow_copies_before_running_the_container(self):
        write(self.base / 'meshcentral-data/meshcore.js', b'')
        write(self.base / 'meshcentral-web/views/default3.handlebars')
        write(self.base / 'meshcentral-data/agentbuilds/MeshService64.exe')
        with self.assertRaises(MANAGER.meshcentral_shadow_check.ShadowCopyError) as raised:
            MANAGER.start(self.config, self.release())
        for text in ('meshcentral-data/meshcore.js: not in the release shadow allowlist',
                     'meshcentral-web/views/default3.handlebars:', 'meshcentral-data/agentbuilds: must not exist'):
            self.assertIn(text, str(raised.exception))
        self.assertEqual(self.docker_runs, [])

    def test_start_accepts_allowlisted_files(self):
        write(self.base / 'meshcentral-web/public/scripts/custom.js', b'custom')
        write(self.base / 'meshcentral-data/plugins/nativeruntime/nativeruntime.js', b'plugin')
        MANAGER.start(self.config, self.release(shadowAllowlist=[
            {'path': 'meshcentral-web/public/scripts/custom.js', 'sha256': sha256(b'custom')},
            {'path': 'meshcentral-data/plugins/nativeruntime/nativeruntime.js', 'sha256': sha256(b'plugin')}]))
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

    def test_malformed_allowlist_is_refused_at_preparation(self):
        directory = make_release(self.release_dir(DIGEST),
                                 shadowAllowlist=[{'path': 'meshcentral-data/config.json', 'sha256': sha256(b'x')}])
        with self.assertRaisesRegex(ValueError, 'governed folder'):
            MANAGER.validate_manifest(directory / 'release', self.config['reviewed_versions'])


class ServerConfigPathTests(FixtureCase):
    """The container mounts only /opt/meshcentral/meshcentral-*: a config path elsewhere would make the server
    fail to back up, record or serve there (the read-only root has no such folder)."""

    SECRET = 'fixture-session-key-never-printed'

    def setUp(self):
        super().setUp()
        self.run_calls = []
        for name, value in {'run': mock.Mock(side_effect=lambda *args, **kw: self.run_calls.append(args)),
                            'remove_container': mock.Mock(), 'healthy': mock.Mock(return_value=True),
                            'prepare': mock.Mock(return_value=make_release(self.release_dir(DIGEST)))}.items():
            patch = mock.patch.object(MANAGER, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    @staticmethod
    def server_config(settings=None, domains=None):
        config = {'settings': dict({'sessionKey': ServerConfigPathTests.SECRET}, **(settings or {}))}
        if domains is not None:
            config['domains'] = domains
        return config

    def use(self, settings=None, domains=None):
        self.config_path.write_text(json.dumps(self.server_config(settings, domains)))

    def refused(self, server_config, *texts):
        """Checked as the VPS controller sees it: install root /opt/meshcentral, the container's working directory."""
        with self.assertRaises(ValueError) as raised:
            MANAGER.check_server_config_paths(server_config, '/opt/meshcentral')
        message = str(raised.exception)
        for text in texts:
            self.assertIn(text, message)
        self.assertNotIn(self.SECRET, message)
        return message

    def accepted(self, server_config):
        MANAGER.check_server_config_paths(server_config, '/opt/meshcentral')

    def test_paths_inside_the_mounted_folders_are_accepted(self):
        for backup in ('/opt/meshcentral/meshcentral-backups', 'meshcentral-backups', './meshcentral-backups/daily',
                       '/opt/meshcentral/meshcentral-files/../meshcentral-backups'):
            with self.subTest(backup=backup):
                self.accepted(self.server_config({'autoBackup': {'backupPath': backup}}, {'': {
                    'sessionRecording': {'filepath': 'meshcentral-recordings'},
                    'webPublicPath': '/opt/meshcentral/meshcentral-web/public-default'}}))

    def test_a_missing_key_uses_the_mounted_default(self):
        # MeshCentral 1.3.1 installed as node_modules/meshcentral defaults backuppath to
        # <install root>/meshcentral-backups (meshcentral.js:90, applied at :2232) and recordings to
        # <install root>/meshcentral-recordings (:91); both are mounted read-write.
        config = self.server_config({'autoBackup': {'backupIntervalHours': 24, 'keepLastDaysBackup': 14}},
                                    {'': {'sessionRecording': {}}})
        self.accepted(config)
        self.assertEqual(MANAGER.server_config_paths(config), [])
        self.assertIn('meshcentral-backups', MANAGER.WRITABLE_MOUNTS)
        self.assertIn('meshcentral-recordings', MANAGER.WRITABLE_MOUNTS)

    def test_the_production_backup_folder_is_refused(self):
        self.refused(self.server_config({'autobackup': {'backuppath': '/var/meshcentral-backups', 'intervalhours': 24}}),
                     'settings.autobackup.backuppath = /var/meshcentral-backups: the release container does not '
                     'mount it, so the server cannot write it there',
                     'written paths must be under /opt/meshcentral/meshcentral-data, /opt/meshcentral/meshcentral-files, '
                     '/opt/meshcentral/meshcentral-recordings, /opt/meshcentral/meshcentral-backups)')

    def test_relative_and_escaping_paths_resolve_from_the_working_directory(self):
        self.refused(self.server_config({'autobackup': {'backuppath': '../meshcentral-backups'}}),
                     'settings.autobackup.backuppath = /opt/meshcentral-backups:')
        self.refused(self.server_config({'autobackup': {'backuppath': 'meshcentral-backups/../../../var/backups'}}),
                     'settings.autobackup.backuppath = /var/backups:')

    def test_a_backup_path_inside_the_data_folder_is_refused(self):
        self.refused(self.server_config({'autobackup': {'backuppath': 'meshcentral-data/backups'}}),
                     'settings.autobackup.backuppath = /opt/meshcentral/meshcentral-data/backups: MeshCentral refuses '
                     'a backup path inside meshcentral-data')

    def test_disabled_autobackup_and_disabled_domains_are_not_checked(self):
        for disabled in (False, 'false'):
            with self.subTest(autobackup=disabled):
                self.accepted(self.server_config({'autobackup': disabled},
                                                 {'_old': {'sessionrecording': {'filepath': '/var/recordings'}}}))

    def test_recording_web_and_error_log_paths_outside_the_mounts_are_refused(self):
        message = self.refused(self.server_config(
            {'meshErrorLogPath': '/var/log/meshcentral'},
            {'': {'sessionRecording': {'filePath': '/srv/recordings'}},
             'customer': {'webViewsPath': '/srv/views', 'webPublicPath': 'meshcentral-files/public'}}),
            'settings.mesherrorlogpath = /var/log/meshcentral: ', 'domains[""].sessionrecording.filepath = /srv/recordings: ',
            'domains["customer"].webviewspath = /srv/views: the release container does not mount it, so the server '
            'cannot read it there')
        self.assertNotIn('webpublicpath', message)  # meshcentral-files is mounted, so it can be read

    def test_web_folders_are_read_only_so_nothing_may_be_written_there(self):
        self.refused(self.server_config({'autobackup': {'backuppath': 'meshcentral-web/backups'}}),
                     'settings.autobackup.backuppath = /opt/meshcentral/meshcentral-web/backups:')

    def test_promotion_refuses_before_stopping_anything_and_start_refuses_too(self):
        self.use({'autobackup': {'backuppath': '/var/meshcentral-backups'}})
        with self.assertRaisesRegex(ValueError, 'backuppath = /var/meshcentral-backups'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(self.run_calls, [])
        self.assertFalse((self.state / 'transaction.json').exists())
        with self.assertRaisesRegex(ValueError, 'backuppath = /var/meshcentral-backups'):
            MANAGER.start(self.config, self.release(PREVIOUS))
        self.assertEqual(self.run_calls, [])

    def test_an_unreadable_config_is_refused_without_its_content(self):
        self.config_path.write_text('{"settings": {"sessionKey": "' + self.SECRET + '"')
        with self.assertRaisesRegex(ValueError, 'config.json is not valid JSON') as raised:
            MANAGER.check_server_config()
        self.assertNotIn(self.SECRET, str(raised.exception))


class RetiredPreloadTests(FixtureCase):
    """D4/DEP-21: no image-size preload is tracked, installed, mounted or required by a release start."""

    def setUp(self):
        super().setUp()
        self.docker_runs = []
        self.run_calls = []

        def run(*args, capture=False):
            self.run_calls.append(args)
            if args[:2] == ('docker', 'run'):
                self.docker_runs.append(args)
            return ''

        for name, value in {'run': mock.Mock(side_effect=run), 'remove_container': mock.Mock(),
                            'healthy': mock.Mock(return_value=True)}.items():
            patch = mock.patch.object(MANAGER, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.candidate = make_release(self.release_dir(DIGEST))
        patch = mock.patch.object(MANAGER, 'prepare', return_value=self.candidate)
        patch.start()
        self.addCleanup(patch.stop)

    def install_legacy_preload(self):
        for path, data in zip(self.legacy, (LEGACY_SCRIPT, LEGACY_DROPIN)):
            write(path, data)

    def retired(self):
        return sorted(path.relative_to(self.state / 'retired-host-preload').as_posix()
                      for path in (self.state / 'retired-host-preload').rglob('*') if path.is_file())

    def test_no_preload_is_tracked_or_installed(self):
        for name in ('harden-image-size.js', '30-harden-image-size.conf'):
            self.assertFalse((DEPLOYMENT / name).exists(), name)
        self.assertFalse(hasattr(INSTALLER, 'MITIGATION_FILES'))
        self.assertNotIn('NODE_OPTIONS', (DEPLOYMENT / 'smoke_image.py').read_text(encoding='utf-8').split('"""', 2)[2])

    def test_container_starts_without_node_options_or_a_preload_mount(self):
        MANAGER.start(self.config, self.release(PREVIOUS))
        args = self.docker_runs[0]
        self.assertFalse([arg for arg in args if 'NODE_OPTIONS' in arg or 'harden-image-size' in arg], args)

    def test_first_release_retires_the_host_preload_after_promotion(self):
        self.install_legacy_preload()
        with mock.patch('sys.stdout', new_callable=lambda: __import__('io').StringIO()) as stdout:
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text())['digest'], DIGEST)
        self.assertFalse(any(path.exists() for path in self.legacy))
        retired = self.retired()
        self.assertEqual([name.split('/', 1)[1] for name in retired], ['30-harden-image-size.conf', 'harden-image-size.js'])
        stamp = retired[0].split('/')[0]
        archive = self.state / 'retired-host-preload' / stamp
        self.assertEqual((archive / 'harden-image-size.js').read_bytes(), LEGACY_SCRIPT)
        self.assertEqual((archive / '30-harden-image-size.conf').read_bytes(), LEGACY_DROPIN)
        for path, data in zip(self.legacy, (LEGACY_SCRIPT, LEGACY_DROPIN)):
            self.assertIn('Retired the legacy image-size preload: moved ' + str(path) + ' (sha256 ' + sha256(data) + ')',
                          stdout.getvalue())
        self.assertEqual(self.run_calls[-1], ('systemctl', 'daemon-reload'))
        self.assertLess(self.run_calls.index(('systemctl', 'disable', '--now', 'meshcentral')),
                        self.run_calls.index(('systemctl', 'daemon-reload')))

    def test_a_failed_first_release_restarts_the_host_with_its_preload(self):
        self.install_legacy_preload()

        def fail_candidate(*args, capture=False):
            self.run_calls.append(args)
            if args[:2] == ('docker', 'run'):
                raise RuntimeError('candidate start')
            return ''

        MANAGER.run.side_effect = fail_candidate
        with self.assertRaisesRegex(RuntimeError, 'candidate start'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual([path.read_bytes() for path in self.legacy], [LEGACY_SCRIPT, LEGACY_DROPIN])
        self.assertIn(('systemctl', 'enable', '--now', 'meshcentral'), self.run_calls)
        self.assertNotIn(('systemctl', 'daemon-reload'), self.run_calls)

    def test_a_host_without_the_preload_is_left_alone(self):
        MANAGER.promote(self.config, DIGEST)
        self.assertNotIn(('systemctl', 'daemon-reload'), self.run_calls)
        self.assertFalse((self.state / 'retired-host-preload').exists())

    def test_a_linked_preload_is_refused_before_anything_stops(self):
        target = write(self.root / 'elsewhere.conf', LEGACY_DROPIN)
        self.legacy[1].parent.mkdir(parents=True)
        try:
            self.legacy[1].symlink_to(target)
        except OSError as error:
            self.skipTest('Symlinks are unavailable: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'legacy image-size preload .* is not a regular file'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(self.run_calls, [])
        self.assertFalse((self.state / 'transaction.json').exists())

    def test_a_retirement_failure_keeps_the_promoted_release_and_says_so(self):
        self.install_legacy_preload()
        with mock.patch.object(MANAGER.shutil, 'move', side_effect=OSError('read-only file system')):
            with self.assertRaisesRegex(RuntimeError, 'Promoted ' + DIGEST + ', but retiring the legacy image-size '
                                                      'preload failed: read-only file system'):
                MANAGER.promote(self.config, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text())['digest'], DIGEST)
        self.assertFalse((self.state / 'transaction.json').exists())
        self.assertNotIn(('systemctl', 'enable', '--now', 'meshcentral'), self.run_calls)


def cores_page(rows):
    """The /meshagents?cores=1 page as webserver.js renders it."""
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
    def __init__(self, version='MeshCentral v1.3.1', cores=None, agents=None):
        self.version, self.cores, self.logins = version, cores or {'windows-amt': CORE_HASH}, []
        self.agents = {'4': AGENT} if agents is None else agents

    def get(self, path):
        assert path == SMOKE.VERSION_PATH, path
        return self.version

    def login(self, username, password):
        self.logins.append((username, password))

    def core_hashes(self):
        return self.cores

    def agent(self, archid):
        if archid not in self.agents:
            raise SMOKE.SmokeFailure('/meshagents?id=' + archid + ' returned HTTP 404')
        return self.agents[archid]


def installed_tree(**changes):
    """An install root's files as the fork image has them, relative to /opt/meshcentral."""
    files = {
        'node_modules/.package-lock.json': json.dumps({'packages': {'node_modules/meshcentral': {
            'version': '1.3.1', 'resolved': 'file:dist/meshcentral-1.3.1.tgz', 'integrity': INTEGRITY}}}).encode(),
        'node_modules/meshcentral/agents/module-versions.json': json.dumps({'commit': PACKAGED_COMMIT, 'modules': {}}).encode(),
        'node_modules/meshcentral/agents/agent-defaults.json': json.dumps({
            'schema': 'meshcentral-fork-agents/1', 'build': AGENT_BUILD,
            'files': [{'filename': 'MeshService64.exe', 'size': len(AGENT), 'sha384': sha384(AGENT)}]}).encode(),
        'node_modules/meshcentral/agents/MeshService64.exe': AGENT,
        'node_modules/meshcentral/daemon': b''}
    files.update(changes)
    return {path: data for path, data in files.items() if data is not None}


class FakeFiles:
    def __init__(self, files):
        self.files = files

    def exists(self, relative):
        return relative in self.files or any(path.startswith(relative + '/') for path in self.files)

    def read(self, relative):
        return self.files[relative].decode('utf-8')

    def digest(self, relative):
        return len(self.files[relative]), sha384(self.files[relative])


class SmokeExpectationTests(unittest.TestCase):
    """T22: the smoke test needs the fork tarball identity in the manifest and refuses images without it."""

    def test_fork_manifest_yields_the_identity_to_prove(self):
        expected = SMOKE.expectations(fork_manifest())
        self.assertEqual((expected['version'], expected['forkRevision']), ('1.3.1', FORK_REVISION))
        self.assertEqual(expected['pins'], {'MeshService64.exe': (len(AGENT), sha384(AGENT))})

    def test_overlay_or_incomplete_manifests_are_refused_naming_each_field(self):
        manifest = fork_manifest(schema=1)
        for field in ('forkRevision', 'package', 'agentBuild', 'agentCoreHashes', 'agentBinaries'):
            del manifest[field]
        with self.assertRaises(SMOKE.SmokeFailure) as raised:
            SMOKE.expectations(manifest)
        for text in ('schema 1 is not 2', 'forkRevision is missing', 'package must give', 'agentBuild',
                     'agentCoreHashes', 'agentBinaries'):
            self.assertIn(text, str(raised.exception))

    def test_agent_entries_must_name_the_package_file_and_its_pin(self):
        good = fork_manifest()['agentBinaries']['4']
        for entry in (dict(good, path='meshcentral-data/agents/MeshService64.exe'),
                      dict(good, path='node_modules/meshcentral/agents/MeshService.exe'),
                      dict(good, path='/opt/meshcentral/node_modules/meshcentral/agents/MeshService64.exe'),
                      dict(good, unsigned='yes'), dict(good, sha384='A' * 96), dict(good, size=0),
                      dict(good, size=True), dict(good, sha256='a' * 64),
                      {key: value for key, value in good.items() if key != 'localname'}):
            with self.subTest(entry=entry), self.assertRaisesRegex(SMOKE.SmokeFailure, r"agentBinaries\['4'\]"):
                SMOKE.expectations(fork_manifest(agentBinaries={'4': entry}))
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'two different pins'):
            SMOKE.expectations(fork_manifest(agentBinaries={'4': good, '10004': dict(good, size=good['size'] + 1)}))
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'reviewedUpstreamVersion'):
            SMOKE.expectations(fork_manifest(reviewedUpstreamVersion='1.2.5'))
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'package must give'):
            SMOKE.expectations(fork_manifest(package=dict(fork_manifest()['package'], tarball='meshcentral-1.2.5.tgz')))


class SmokeAssertionTests(unittest.TestCase):
    """T22/N6: version, installed tarball, package pins, served cores and agents from the package only."""

    def setUp(self):
        self.expected = SMOKE.expectations(fork_manifest())

    def test_agent_selection_mirrors_the_fork_server(self):
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

    def test_the_package_file_must_have_the_pinned_size_and_sha384(self):
        self.assertEqual(SMOKE.check_agent_binaries(self.expected, FakeFiles(installed_tree())), [])
        changed = FakeFiles(installed_tree(**{'node_modules/meshcentral/agents/MeshService64.exe': b'other build'}))
        self.assertEqual(SMOKE.check_agent_binaries(self.expected, changed), [
            'agent 4: node_modules/meshcentral/agents/MeshService64.exe has 11 bytes, SHA384 ' + sha384(b'other build') +
            '; pinned ' + str(len(AGENT)) + ' bytes, SHA384 ' + sha384(AGENT)])
        missing = FakeFiles(installed_tree(**{'node_modules/meshcentral/agents/MeshService64.exe': None}))
        self.assertIn('does not exist', SMOKE.check_agent_binaries(self.expected, missing)[0])

    def test_a_data_folder_copy_that_would_win_is_reported(self):
        entry = dict(fork_manifest()['agentBinaries']['4'], unsigned=False)
        expected = SMOKE.expectations(fork_manifest(agentBinaries={'4': entry}))
        files = FakeFiles(installed_tree(**{'meshcentral-data/agents/MeshService64.exe': b'stale'}))
        self.assertEqual(SMOKE.check_agent_binaries(expected, files), [
            'agent 4: MeshCentral selects meshcentral-data/agents/MeshService64.exe, not the package file '
            'node_modules/meshcentral/agents/MeshService64.exe'])

    def test_unsigned_agents_are_served_byte_for_byte(self):
        self.assertEqual(SMOKE.check_served_agents(FakeServer(), self.expected), [])
        problems = SMOKE.check_served_agents(FakeServer(agents={'4': AGENT + b'msh'}), self.expected)
        self.assertEqual(problems, ['agent 4: /meshagents?id=4 served ' + str(len(AGENT) + 3) + ' bytes, SHA384 ' +
                                    sha384(AGENT + b'msh') + '; pinned ' + str(len(AGENT)) + ' bytes, SHA384 ' +
                                    sha384(AGENT)])
        self.assertEqual(SMOKE.check_served_agents(FakeServer(agents={}), self.expected),
                         ['agent 4: /meshagents?id=4 returned HTTP 404'])
        signed = SMOKE.expectations(fork_manifest(agentBinaries={'4': dict(fork_manifest()['agentBinaries']['4'],
                                                                           unsigned=False)}))
        self.assertEqual(SMOKE.check_served_agents(FakeServer(agents={}), signed), [])

    def test_the_installed_package_is_the_manifest_tarball_with_the_daemon_marker(self):
        self.assertEqual(SMOKE.check_installed_package(FakeFiles(installed_tree()), self.expected), [])
        other = installed_tree(**{
            'node_modules/.package-lock.json': json.dumps({'packages': {'node_modules/meshcentral': {
                'version': '1.2.5', 'integrity': 'sha512-' + 'B' * 86 + '=='}}}).encode(),
            'node_modules/meshcentral/agents/module-versions.json': json.dumps({'commit': 'e' * 40}).encode(),
            'node_modules/meshcentral/daemon': None})
        problems = SMOKE.check_installed_package(FakeFiles(other), self.expected)
        for text in ("installed meshcentral version '1.2.5' is not 1.3.1", 'is not the manifest tarball ' + INTEGRITY,
                     'module-versions.json dates the package by', 'daemon is missing'):
            self.assertTrue(any(text in problem for problem in problems), (text, problems))

    def test_the_package_pins_are_the_manifest_agents(self):
        self.assertEqual(SMOKE.check_agent_pins(FakeFiles(installed_tree()), self.expected), [])
        pins = {'schema': 'meshcentral-fork-agents/1', 'build': dict(AGENT_BUILD, commit='4' * 40),
                'files': [{'filename': 'MeshService64.exe', 'size': 1, 'sha384': sha384(AGENT)},
                          {'filename': 'MeshService.exe', 'size': 2, 'sha384': 'a' * 96}]}
        problems = SMOKE.check_agent_pins(FakeFiles(installed_tree(**{
            'node_modules/meshcentral/agents/agent-defaults.json': json.dumps(pins).encode()})), self.expected)
        self.assertEqual(len(problems), 3)
        self.assertIn('pins build', problems[0])
        self.assertIn('agent pin MeshService.exe: package pins', problems[1])
        self.assertIn('agent pin MeshService64.exe: package pins (1,', problems[2])

    def test_core_table_is_parsed_and_compared(self):
        served = SMOKE.parse_core_hashes(cores_page([('windows-amt', CORE_HASH), ('linux noamt', 'e' * 96)]))
        self.assertEqual(served, {'windows-amt': CORE_HASH, 'linux noamt': 'e' * 96})
        self.assertEqual(SMOKE.check_core_hashes(served, self.expected), [])
        self.assertEqual(SMOKE.check_core_hashes({'windows-amt': 'f' * 96}, self.expected), [
            "agent core 'windows-amt' is served with SHA-384 " + 'f' * 96 + ', manifest expects ' + CORE_HASH])
        self.assertEqual(SMOKE.check_core_hashes({}, self.expected), ["agent core 'windows-amt' is not served"])
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'listed no agent cores'):
            SMOKE.parse_core_hashes(cores_page([]))
        with self.assertRaisesRegex(SMOKE.SmokeFailure, 'Unexpected agent core table row'):
            SMOKE.parse_core_hashes(cores_page([('windows-amt', 'not-a-hash')]))

    def test_version_and_image_size_checks(self):
        self.assertEqual(SMOKE.check_served_version('MeshCentral v1.3.1', self.expected), [])
        self.assertEqual(SMOKE.check_served_version('MeshCentral v1.2.5', self.expected),
                         ["served version 'MeshCentral v1.2.5' is not MeshCentral v1.3.1"])
        self.assertEqual(SMOKE.check_no_image_size(FakeFiles(installed_tree())), [])
        files = FakeFiles(installed_tree(**{'node_modules/image-size/package.json': b'{}'}))
        self.assertEqual(SMOKE.check_no_image_size(files), [
            'node_modules/image-size is installed; the fork package tree must not contain image-size'])

    def test_run_checks_reports_every_failure_together(self):
        server = FakeServer(version='MeshCentral v1.2.5', cores={'windows-amt': 'f' * 96}, agents={})
        files = FakeFiles(installed_tree(**{'node_modules/image-size/index.js': b'', 'node_modules/meshcentral/daemon': None,
                                            'node_modules/meshcentral/agents/MeshService64.exe': None}))
        with self.assertRaises(SMOKE.SmokeFailure) as raised:
            SMOKE.run_checks(fork_manifest(), server, ('smoke', 'secret'), files)
        message = str(raised.exception)
        for text in ('node_modules/image-size is installed', 'served version', 'daemon is missing',
                     "agent core 'windows-amt'", 'agent 4: node_modules/meshcentral/agents/MeshService64.exe does not exist',
                     'agent 4: /meshagents?id=4 returned HTTP 404'):
            self.assertIn(text, message)
        self.assertEqual(server.logins, [('smoke', 'secret')])
        SMOKE.run_checks(fork_manifest(), FakeServer(), ('smoke', 'secret'), FakeFiles(installed_tree()))


class SmokeCommandTests(unittest.TestCase):
    """T22: the smoke runs against a local duplicate server with the same assertions."""

    def test_duplicate_server_mode_reads_the_local_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, data in installed_tree().items():
                write(root / relative, data)
            manifest = write(root / 'manifest.json', json.dumps(fork_manifest()).encode())
            server = FakeServer()
            with mock.patch.dict(os.environ, {'SMOKE_USERNAME': 'smoke', 'SMOKE_PASSWORD': 'secret'}), \
                    mock.patch.object(SMOKE_IMAGE.smoke_checks, 'Server', return_value=server):
                SMOKE_IMAGE.main(['--server-url', 'http://127.0.0.1:4430', '--install-root', str(root),
                                  '--manifest', str(manifest)])
            self.assertEqual(server.logins, [('smoke', 'secret')])
            write(root / 'node_modules/meshcentral/agents/MeshService64.exe', b'changed')
            with mock.patch.dict(os.environ, {'SMOKE_USERNAME': 'smoke', 'SMOKE_PASSWORD': 'secret'}), \
                    mock.patch.object(SMOKE_IMAGE.smoke_checks, 'Server', return_value=FakeServer()), \
                    self.assertRaisesRegex(SMOKE_IMAGE.smoke_checks.SmokeFailure, 'agent 4: .* has 7 bytes'):
                SMOKE_IMAGE.main(['--server-url', 'http://127.0.0.1:4430', '--install-root', str(root),
                                  '--manifest', str(manifest)])

    def test_partial_duplicate_server_options_and_missing_credentials_are_refused(self):
        with mock.patch('sys.stderr'), self.assertRaises(SystemExit):
            SMOKE_IMAGE.main(['--server-url', 'http://127.0.0.1:4430'])
        with mock.patch.dict(os.environ, {'SMOKE_USERNAME': '', 'SMOKE_PASSWORD': ''}), \
                self.assertRaisesRegex(ValueError, 'SMOKE_USERNAME and SMOKE_PASSWORD'):
            SMOKE_IMAGE.smoke_server('http://127.0.0.1:4430', '.', 'manifest.json')

    def test_image_mode_refuses_mutable_references_before_docker(self):
        with mock.patch.object(SMOKE_IMAGE, 'run') as run, \
                self.assertRaisesRegex(ValueError, 'immutable registry digest'):
            SMOKE_IMAGE.smoke_image('ghcr.io/fixture/release:latest')
        run.assert_not_called()

    def test_image_mode_reads_the_release_folder_the_controller_reads(self):
        self.assertEqual(SMOKE_IMAGE.MANIFEST, MANAGER.IMAGE_RELEASE + '/manifest.json')


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


DOCKERFILE = (DEPLOYMENT / 'Dockerfile').read_text(encoding='utf-8')


class DockerContextTests(unittest.TestCase):
    """T20: local state never enters the image build context; every COPY source still does."""

    def setUp(self):
        self.rules = docker_ignore_rules(DEPLOYMENT / 'Dockerfile.dockerignore')

    def test_every_dockerfile_copy_source_is_sent(self):
        sources = []
        for line in DOCKERFILE.splitlines():
            words = line.split()
            if words[:1] == ['COPY'] and not any(word.startswith('--from') for word in words):
                sources += [word for word in words[1:-1] if not word.startswith('--')]
        self.assertEqual(sources, ['MeshCentral', 'agent-builds', 'MeshAgent/tools/deployment/release_image.js'])
        for source in sources:
            with self.subTest(source=source):
                self.assertFalse(docker_excludes(self.rules, source))

    def test_files_the_build_reads_are_sent(self):
        for path in ('MeshCentral/.git/HEAD', 'MeshCentral/.git/objects/pack/pack-1.pack', 'MeshCentral/package.json',
                     'MeshCentral/agents/agent-defaults.json', 'MeshCentral/agents/meshcore.js',
                     'MeshCentral/deploy/scripts/pack.js', 'MeshCentral/deploy/package-lock.json',
                     'MeshCentral/deploy/meshcentral-web/public/scripts/custom.js',
                     'MeshCentral/plugins/nativeruntime/nativeruntime.js', 'MeshCentral/meshagent.js',
                     'agent-builds/MeshService64.exe', 'MeshAgent/tools/deployment/release_image.js'):
            with self.subTest(path=path):
                self.assertFalse(docker_excludes(self.rules, path))

    def test_local_state_secrets_and_siblings_are_not_sent(self):
        for path in ('MeshCentral/node_modules/meshcentral/meshcentral.js', 'MeshCentral/meshcentral-data/config.json',
                     'MeshCentral/meshcentral-data/agentserver-cert-private.key', 'MeshCentral/server-backups/dump.zip',
                     'MeshCentral/meshcentral-web/public/scripts/custom.js', 'MeshCentral/meshcentral-files/x',
                     'MeshCentral/deploy/node_modules/meshcentral/meshcentral.js', 'MeshCentral/deploy/dist/meshcentral-1.3.1.tgz',
                     'MeshCentral/deploy/meshcentral-data/config.json',
                     'MeshCentral/deploy/meshcentral-data/agentserver-cert-private.key',
                     'MeshCentral/deploy/server-backups/dump.zip', 'MeshCentral/deploy/meshcentral-backups/x',
                     'MeshAgent/branding_config.local.json', 'MeshAgent/artifacts/validation/report.json',
                     'MeshAgent/deploy.py', 'MeshAgent/tools/deployment/Dockerfile', 'artifacts/MeshServiceRuntime-x/x.exe',
                     'meshcentral-fork-ssot/SSOT.md', 'UserModeHook/build/x'):
            with self.subTest(path=path):
                self.assertTrue(docker_excludes(self.rules, path))

    def test_matcher_follows_docker_last_match_semantics(self):
        rules = [(False, re.compile(r'[^/]*\Z')), (True, re.compile(r'a/b\Z'))]
        self.assertFalse(docker_excludes(rules, 'a/b'))
        self.assertTrue(docker_excludes(rules, 'a/c'))


class DockerfileTests(unittest.TestCase):
    """The release image is the fork tarball on Node 24.22.1, packed on Linux and checked against the lock."""

    def test_both_stages_use_node_24_22_1_pinned_by_digest(self):
        bases = re.findall(r'^FROM (\S+)', DOCKERFILE, re.M)
        self.assertEqual(bases, ['node:24.22.1-bookworm-slim@sha256:'
                                 'be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c'] * 2)

    def test_the_build_packs_with_the_pinned_agents_verifies_the_lock_and_installs_only_the_lock(self):
        steps = [
            'node /build/MeshCentral/deploy/scripts/pack.js --agents /build/agent-builds --json > /build/pack-record.txt',
            'node /build/release_image.js verify-pack --meshcentral /build/MeshCentral --pack-record /build/pack-record.txt',
            'npm ci --omit=dev --no-audit --no-fund',
            'touch node_modules/meshcentral/daemon',
            'node /build/release_image.js manifest --meshcentral /build/MeshCentral --pack-record /build/pack-record.txt']
        positions = [DOCKERFILE.find(step) for step in steps]
        self.assertNotIn(-1, positions, positions)
        self.assertEqual(positions, sorted(positions))
        for retired in ('prepare_release_image', 'deploy.py', 'configure_agent_certificate_history', 'release-overrides',
                        'hashagents', 'NODE_OPTIONS', 'harden-image-size', 'python'):
            self.assertNotIn(retired, DOCKERFILE)

    def test_the_runtime_stage_runs_the_installed_package_as_the_node_user(self):
        runtime = DOCKERFILE.split('\nFROM ', 2)[2]
        self.assertIn('COPY --from=build --chown=root:root /opt/meshcentral /opt/meshcentral', runtime)
        self.assertIn('USER node', runtime)
        self.assertIn('ENTRYPOINT ["node", "/opt/meshcentral/node_modules/meshcentral/meshcentral.js"]', runtime)


@unittest.skipUnless(shutil.which('node'), 'Node.js is required to run release_image.js')
class ReleaseImageTests(unittest.TestCase):
    """release_image.js: the Linux pack must be the locked tarball (T21) and the manifest is computed from the
    installed package."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tarball = b'fork tarball bytes'
        self.integrity = 'sha512-' + __import__('base64').b64encode(hashlib.sha512(self.tarball).digest()).decode()
        self.meshcentral = self.root / 'MeshCentral'
        write(self.meshcentral / 'deploy/dist/meshcentral-1.3.1.tgz', self.tarball)
        write(self.meshcentral / 'deploy/package.json', json.dumps(
            {'dependencies': {'meshcentral': 'file:dist/meshcentral-1.3.1.tgz'}}).encode())
        self.lock(self.integrity)
        self.record = {'tarball': 'deploy/dist/meshcentral-1.3.1.tgz', 'version': '1.3.1', 'commit': FORK_REVISION,
                       'integrity': self.integrity, 'packagedCommit': PACKAGED_COMMIT, 'agentBuild': AGENT_BUILD,
                       'agents': [{'filename': 'MeshService64.exe', 'size': len(AGENT), 'sha384': sha384(AGENT)}],
                       'platform': 'linux'}

    def lock(self, integrity):
        write(self.meshcentral / 'deploy/package-lock.json', json.dumps({'packages': {'node_modules/meshcentral': {
            'version': '1.3.1', 'resolved': 'file:dist/meshcentral-1.3.1.tgz', 'integrity': integrity}}}).encode())

    def verify(self):
        record = write(self.root / 'pack-record.txt', ('deploy/dist/meshcentral-1.3.1.tgz: 1 files\nintegrity x\n' +
                                                       json.dumps(self.record, indent=2) + '\n').encode())
        return subprocess.run(['node', str(DEPLOYMENT / 'release_image.js'), 'verify-pack', '--meshcentral',
                               str(self.meshcentral), '--pack-record', str(record)],
                              capture_output=True, text=True, timeout=60)

    def test_the_locked_linux_pack_passes(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('matches the locked tarball ' + self.integrity, result.stdout)

    def test_a_pack_the_lock_does_not_pin_is_refused(self):
        self.lock('sha512-' + 'A' * 86 + '==')
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('T21: the Linux pack of MeshCentral ' + FORK_REVISION + ' gives ' + self.integrity, result.stderr)
        self.assertIn('re-lock from a Linux pack of this commit (D4)', result.stderr)

    def test_a_non_linux_pack_or_a_changed_tarball_is_refused(self):
        self.record['platform'] = 'win32'
        self.assertIn('release packs run on Linux (D4)', self.verify().stderr)
        self.record['platform'] = 'linux'
        write(self.meshcentral / 'deploy/dist/meshcentral-1.3.1.tgz', b'changed after packing')
        self.assertIn('but pack.js recorded ' + self.integrity, self.verify().stderr)


class HostRecoveryTests(FixtureCase):
    """G4 on the first-migration fallback: the host service restarts only on the folders it ran with."""

    HOST_FILES = {'meshcentral-data/meshcore.js': b'host core',
                  'meshcentral-data/modules_meshcore/clipboard.js': b'host module',
                  'meshcentral-web/views/default3.handlebars': b'host view',
                  'meshcentral-web/public/scripts/custom.js': b'custom'}

    def setUp(self):
        super().setUp()
        for relative, data in self.HOST_FILES.items():
            write(self.base / relative, data)
        # The candidate allowlists the host files, so it reaches `docker run` and fails there.
        allowlist = [{'path': relative, 'sha256': sha256(data)} for relative, data in self.HOST_FILES.items()]
        self.candidate = make_release(self.release_dir(DIGEST), shadowAllowlist=allowlist)
        self.calls = []
        self.during_candidate = lambda: None
        for name, value in {'run': mock.Mock(side_effect=self.fake_run), 'prepare': mock.Mock(return_value=self.candidate),
                            'remove_container': mock.Mock(), 'healthy': mock.Mock(return_value=True)}.items():
            patch = mock.patch.object(MANAGER, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def fake_run(self, *args, capture=False):
        self.calls.append(args)
        if args[:2] == ('docker', 'run'):
            self.during_candidate()
            raise RuntimeError('candidate start')
        return ''

    def restarted_host(self):
        return ('systemctl', 'enable', '--now', 'meshcentral') in self.calls

    def test_unchanged_host_folders_are_restored(self):
        with self.assertRaisesRegex(RuntimeError, 'candidate start'):
            MANAGER.promote(self.config, DIGEST)
        self.assertTrue(self.restarted_host())
        self.assertIsNone(json.loads((self.state / 'active.json').read_text()))
        self.assertFalse((self.state / 'transaction.json').exists())

    def test_a_file_added_or_changed_while_stopped_blocks_the_restart(self):
        def candidate_side_effects():
            write(self.base / 'meshcentral-data/modules_meshcore/win-dispatcher.js', b'')  # mount placeholder
            write(self.base / 'meshcentral-data/meshcore.js', b'changed core')
        self.during_candidate = candidate_side_effects
        with self.assertRaises(MANAGER.meshcentral_shadow_check.ShadowCopyError) as raised:
            MANAGER.promote(self.config, DIGEST)
        message = str(raised.exception)
        self.assertIn('Not restoring the host MeshCentral service', message)
        self.assertIn('meshcentral-data/modules_meshcore/win-dispatcher.js: not in the release shadow allowlist', message)
        self.assertIn('meshcentral-data/meshcore.js: sha256 ' + sha256(b'changed core'), message)
        self.assertFalse(self.restarted_host())
        self.assertTrue((self.state / 'transaction.json').is_file())

    def test_a_transaction_without_a_host_record_needs_the_operator(self):
        transaction = {'previous': None, 'candidate': None,
                       'config_backup': str(write(self.state / 'config-backup.json', self.config_path.read_bytes())),
                       'config_metadata': {'uid': 0, 'gid': 0, 'mode': 0o600}}
        with self.assertRaisesRegex(RuntimeError, 'no record of the host shadow copies.*Operator action is needed'):
            MANAGER.recover(self.config, transaction)
        self.assertFalse(self.restarted_host())

    def test_a_host_the_candidate_would_refuse_is_refused_before_anything_stops(self):
        (self.base / 'meshcentral-data/modules_meshcore_min').mkdir()
        with self.assertRaisesRegex(MANAGER.meshcentral_shadow_check.ShadowCopyError,
                                    '(?s)modules_meshcore_min/: empty folder'):
            MANAGER.promote(self.config, DIGEST)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.state / 'transaction.json').exists())
        self.assertEqual(list(self.state.glob('config-*.json')), [])

    def test_snapshot_records_every_governed_file_and_tolerates_a_missing_web_folder(self):
        self.assertEqual(SHADOW.snapshot(self.base),
                         {relative: sha256(data) for relative, data in self.HOST_FILES.items()})
        for relative in self.HOST_FILES:
            if relative.startswith('meshcentral-web/'):
                (self.base / relative).unlink()
        for folder in ('public/scripts', 'public', 'views', ''):
            (self.base / 'meshcentral-web' / folder).rmdir()
        self.assertEqual(sorted(SHADOW.snapshot(self.base)), ['meshcentral-data/meshcore.js',
                                                               'meshcentral-data/modules_meshcore/clipboard.js'])
        with self.assertRaisesRegex(SHADOW.ShadowCopyError, 'meshcentral-web is not a directory'):
            SHADOW.check(self.base, {})  # a release start still requires both folders


if __name__ == '__main__':
    unittest.main()
