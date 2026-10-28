"""Preview-instance tests for the release controller; never invoke Docker, SSH, systemd, or a live endpoint.

A second, independent server instance (preview.high.support) is deployed by the same controller with its own
install root, state, lock, controller configuration, container, service account and health URL. Production
keeps its paths and argv. Every mismatch between the instances is refused: a configuration of the other
instance, overlapping or linked paths, another instance's container, ports, database, host or certificates.
Also checks the MeshCentral config template of the preview instance.
"""
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / 'tools/deployment'
TEMPLATE = DEPLOYMENT / 'meshcentral-preview-config.template.json'
PRODUCTION_FLAGS = ROOT / 'tools/duplicate_server/production_flags.json'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if os.name == 'nt':
    # Only the Linux import surface is stubbed. Production filesystem/state code runs.
    sys.modules.setdefault('fcntl', types.SimpleNamespace())
    sys.modules.setdefault('pwd', types.SimpleNamespace())
MANAGER = load('release_manager_preview', 'tools/deployment/release_manager.py')
ENTRY = load('ci_entry_preview', 'tools/deployment/ci_entry.py')
INSTALLER = load('install_controller_preview', 'tools/deployment/install_controller.py')
DIGEST = 'sha256:' + 'a' * 64
PREVIOUS = 'sha256:' + 'b' * 64
SECRET = 'fixture-secret-never-printed'
PREVIEW_URI = 'mongodb://meshcentral_preview:' + SECRET + '@127.0.0.1:27017/meshcentral_preview?authSource=meshcentral_preview'
PREVIEW_HEALTH = 'https://preview.high.support/health.ashx'
PRODUCTION_CONFIG = {'schema': 3, 'image': 'ghcr.io/fixture/release', 'reviewed_versions': ['1.2.5', '1.3.1'],
                     'health_url': 'https://console.fixture.invalid/health.ashx', 'enable_fleet_update': False}
PREVIEW_CONFIG = dict(PRODUCTION_CONFIG, instance='preview', health_url=PREVIEW_HEALTH, enable_fleet_update=True)


def manifest(**changes):
    value = {'schema': 2, 'meshcentral_version': '1.3.1', 'reviewedUpstreamVersion': '1.3.1', 'forkRevision': 'c' * 40,
             'package': {}, 'agentBuild': {}, 'agentBinaries': {}, 'agentCoreHashes': {}, 'shadowAllowlist': []}
    value.update(changes)
    return value


def make_release(directory):
    folder = Path(directory) / 'release'
    folder.mkdir(parents=True)
    (folder / 'manifest.json').write_text(json.dumps(manifest()))
    return Path(directory)


def write(path, data=b'x'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def filled_template():
    """The tracked template with its placeholders replaced, as the operator writes it."""
    config = json.loads(TEMPLATE.read_text(encoding='utf-8'))
    settings = config['settings']
    settings['mongoDb'] = PREVIEW_URI
    for key in ('sessionKey', 'dbEncryptKey', 'dbRecordsEncryptKey'):
        settings[key] = SECRET + '-' + key
    return config


def try_symlink(test, link, target):
    """Link a folder: a symbolic link, or on Windows without that privilege a junction (resolved the same way)."""
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        try:
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
        except (ImportError, AttributeError, OSError):
            test.skipTest('Symlinks are unavailable: ' + str(error))


class TwoInstanceCase(unittest.TestCase):
    """Both instances get temporary host paths; ``self.activate`` selects one, as main() does."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        replaced = {}
        for name, instance in MANAGER.INSTANCES.items():
            top = self.root / name
            replaced[name] = dataclasses.replace(instance, base=top / 'base', state=top / 'state',
                                                 config=top / 'etc/meshcentral-deploy.json')
            for folder in ('meshcentral-data', 'meshcentral-web'):
                (top / 'base' / folder).mkdir(parents=True)
            (top / 'state').mkdir()
            (top / 'etc').mkdir()
        self.instances = replaced
        # Registered first, so it runs last: the module returns to production after the patches stop.
        self.addCleanup(MANAGER.activate, 'production')
        self.accounts = []
        account = types.SimpleNamespace(pw_uid=0, pw_gid=0)
        for target, name, value in ((MANAGER, 'pwd', types.SimpleNamespace(
                getpwnam=lambda user: self.accounts.append(user) or account)),
                                    (MANAGER, 'HOST_PRELOAD', (self.root / 'production/base/bin/harden-image-size.js',
                                                               self.root / 'etc/30-harden-image-size.conf'))):
            patch = mock.patch.object(target, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.dict(MANAGER.INSTANCES, replaced)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(MANAGER.os, 'chown', create=True)
        patch.start()
        self.addCleanup(patch.stop)

    def activate(self, name):
        instance = MANAGER.activate(name)
        self.base, self.state = instance.base, instance.state
        self.server_config_path = self.base / 'meshcentral-data/config.json'
        return instance


class InstanceDefinitionTests(unittest.TestCase):
    def test_production_keeps_the_paths_and_names_of_the_first_release(self):
        production = MANAGER.INSTANCES['production']
        self.assertEqual((production.base, production.state, production.config, production.container,
                          production.account, production.host_service, production.mount_root, production.health_url),
                         (Path('/opt/meshcentral'), Path('/var/lib/meshcentral-deploy'),
                          Path('/etc/meshcentral-deploy.json'), 'meshcentral-production', 'meshcentral', 'meshcentral',
                          None, None))
        # The module defaults are production's, so an unchanged invocation deploys production.
        self.assertIs(MANAGER.INSTANCE, production)
        self.assertEqual((MANAGER.BASE, MANAGER.STATE, MANAGER.CONFIG, MANAGER.CONTAINER),
                         (production.base, production.state, production.config, production.container))

    def test_preview_follows_the_fixed_decisions(self):
        preview = MANAGER.INSTANCES['preview']
        self.assertEqual((preview.base, preview.state, preview.config, preview.container, preview.health_url,
                          preview.database, preview.server_host),
                         (Path('/opt/meshcentral-preview'), Path('/var/lib/meshcentral-deploy-preview'),
                          Path('/etc/meshcentral-deploy-preview.json'), 'meshcentral-preview', PREVIEW_HEALTH,
                          'meshcentral_preview', 'preview.high.support'))
        self.assertIsNone(preview.host_service)
        self.assertEqual(preview.mount_root, PurePosixPath('/opt/meshcentral'))
        self.assertEqual(preview.distinct_from, ('production',))

    def test_instances_share_no_path_name_port_or_database(self):
        production, preview = MANAGER.INSTANCES['production'], MANAGER.INSTANCES['preview']
        for field in ('base', 'state', 'config', 'container', 'account', 'database'):
            self.assertNotEqual(getattr(production, field), getattr(preview, field), field)
        self.assertFalse({production.web_port, production.mps_port} & {preview.web_port, preview.mps_port})
        for first, second in ((production.base, preview.base), (production.state, preview.state)):
            self.assertFalse(first in second.parents or second in first.parents)

    def test_preview_ports_are_free_on_the_surveyed_host(self):
        # vps-survey.txt listeners: caddy 80/443/4445/4446/2019, cloudflared 20241, mongod 27017, sshd 22,
        # production MeshCentral 4430/4433.
        surveyed = {22, 80, 443, 2019, 4430, 4433, 4445, 4446, 20241, 27017}
        preview = MANAGER.INSTANCES['preview']
        self.assertFalse({preview.web_port, preview.mps_port} & surveyed)

    def test_activate_selects_every_path_together_and_refuses_unknown_instances(self):
        self.addCleanup(MANAGER.activate, 'production')
        preview = MANAGER.activate('preview')
        self.assertEqual((MANAGER.BASE, MANAGER.STATE, MANAGER.CONFIG, MANAGER.CONTAINER, MANAGER.SERVICE_ACCOUNT,
                          MANAGER.HOST_SERVICE, MANAGER.MOUNT_ROOT, MANAGER.LEGACY_PRELOAD),
                         (preview.base, preview.state, preview.config, preview.container, preview.account, None,
                          preview.mount_root, ()))
        MANAGER.activate('production')
        self.assertEqual(MANAGER.LEGACY_PRELOAD, MANAGER.HOST_PRELOAD)
        with self.assertRaisesRegex(ValueError, "Unknown instance 'staging'"):
            MANAGER.activate('staging')


class ControllerConfigTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(MANAGER.activate, 'production')

    def test_each_instance_accepts_only_its_own_configuration(self):
        MANAGER.validate_config(dict(PRODUCTION_CONFIG))
        MANAGER.validate_config(dict(PRODUCTION_CONFIG, instance='production'))
        with self.assertRaisesRegex(ValueError, "configuration of instance 'preview', not production"):
            MANAGER.validate_config(dict(PREVIEW_CONFIG))
        MANAGER.activate('preview')
        MANAGER.validate_config(dict(PREVIEW_CONFIG))
        with self.assertRaisesRegex(ValueError, "configuration of instance 'production', not preview"):
            MANAGER.validate_config(dict(PRODUCTION_CONFIG, health_url=PREVIEW_HEALTH))
        with self.assertRaisesRegex(ValueError, "configuration of instance 'production', not preview"):
            MANAGER.validate_config(dict(PREVIEW_CONFIG, instance='production'))

    def test_health_urls_never_cross(self):
        with self.assertRaisesRegex(ValueError, 'belongs to the preview instance'):
            MANAGER.validate_config(dict(PRODUCTION_CONFIG, health_url=PREVIEW_HEALTH))
        MANAGER.activate('preview')
        with self.assertRaisesRegex(ValueError, 'The preview health_url must be ' + re.escape(PREVIEW_HEALTH)):
            MANAGER.validate_config(dict(PREVIEW_CONFIG, health_url=PRODUCTION_CONFIG['health_url']))

    def test_an_explicit_instance_is_checked_without_activating_it(self):
        MANAGER.validate_config(dict(PREVIEW_CONFIG), 'preview')
        with self.assertRaisesRegex(ValueError, 'not production'):
            MANAGER.validate_config(dict(PREVIEW_CONFIG), 'production')
        self.assertEqual(MANAGER.new_instance_config('preview', 'ghcr.io/fixture/release', ('1.3.1',), False),
                         {'schema': 3, 'instance': 'preview', 'image': 'ghcr.io/fixture/release',
                          'health_url': PREVIEW_HEALTH, 'reviewed_versions': ['1.3.1'], 'enable_fleet_update': False})

    def test_a_missing_preview_configuration_names_the_installation_command(self):
        MANAGER.activate('preview')
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(MANAGER, 'CONFIG', Path(temporary) / 'meshcentral-deploy-preview.json'), \
                self.assertRaisesRegex(ValueError, 'No controller configuration for the preview instance.*'
                                                   'install_controller.py --instance preview'):
            MANAGER.load_config()


class ForcedCommandTests(unittest.TestCase):
    def test_production_argv_is_unchanged(self):
        self.assertEqual(ENTRY.command('deploy ' + DIGEST, '/run/fixture'),
                         ['systemd-run', '--unit=meshcentral-deploy', '--collect', '--wait', '--pipe',
                          '--property=Type=exec', '--property=TimeoutStartSec=30min',
                          '--property=LoadCredential=ghcr:/run/fixture',
                          '/usr/local/libexec/meshcentral-release', 'deploy', DIGEST])

    def test_deploy_preview_runs_the_preview_instance_in_its_own_unit(self):
        self.assertEqual(ENTRY.command('deploy-preview ' + DIGEST, '/run/fixture'),
                         ['systemd-run', '--unit=meshcentral-deploy-preview', '--collect', '--wait', '--pipe',
                          '--property=Type=exec', '--property=TimeoutStartSec=30min',
                          '--property=LoadCredential=ghcr:/run/fixture',
                          '/usr/local/libexec/meshcentral-release', '--instance', 'preview', 'deploy', DIGEST])

    def test_only_the_two_digest_commands_are_accepted(self):
        for value in ('deploy-preview latest', 'deploy-preview ' + DIGEST + '; id', 'deploy-preview ' + DIGEST + '\n',
                      'deploy-preview  ' + DIGEST, 'deploy-production ' + DIGEST, 'deploy --instance preview ' + DIGEST,
                      'deploy-preview', 'preview ' + DIGEST, 'deploy-preview sha256:' + 'a' * 63):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ENTRY.command(value)

    def test_every_forced_command_names_a_controller_instance(self):
        for name, (unit, arguments) in ENTRY.COMMANDS.items():
            instance = arguments[1] if arguments else 'production'
            self.assertEqual(list(arguments), [] if instance == 'production' else ['--instance', instance])
            self.assertIn(instance, MANAGER.INSTANCES)
            self.assertEqual(unit, 'meshcentral-deploy' + ('' if instance == 'production' else '-' + instance))
        self.assertEqual(sorted(ENTRY.COMMANDS), ['deploy', 'deploy-preview'])


class PreviewPromotionTests(TwoInstanceCase):
    def setUp(self):
        super().setUp()
        self.activate('preview')
        self.server_config_path.write_text(json.dumps(filled_template()))
        self.original_server_config = self.server_config_path.read_bytes()
        self.calls = []
        self.candidate = make_release(self.state / 'releases' / DIGEST.split(':')[1])
        self.mocks = {}
        for name, value in {'run': mock.Mock(side_effect=lambda *args, **kw: self.calls.append(args) or ''),
                            'prepare': mock.Mock(return_value=self.candidate),
                            'remove_container': mock.Mock(side_effect=lambda: self.calls.append(('remove',))),
                            'healthy': mock.Mock(return_value=True)}.items():
            patch = mock.patch.object(MANAGER, name, value)
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)
        # Production's host preload is present; a preview deploy must leave it alone.
        for path in MANAGER.HOST_PRELOAD:
            write(path, b'production preload')

    def docker_run(self):
        runs = [call for call in self.calls if call[:2] == ('docker', 'run')]
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_first_preview_deploy_needs_no_host_service(self):
        MANAGER.promote(PREVIEW_CONFIG, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text())['digest'], DIGEST)
        self.assertFalse([call for call in self.calls if call[0] == 'systemctl'])
        # No incumbent health check: only the candidate is probed.
        self.mocks['healthy'].assert_called_once_with(PREVIEW_CONFIG, DIGEST)
        self.assertLess(self.calls.index(('remove',)), self.calls.index(self.docker_run()))
        self.assertTrue(all(path.read_bytes() == b'production preload' for path in MANAGER.HOST_PRELOAD))
        self.assertFalse((self.state / 'retired-host-preload').exists())
        self.assertTrue(json.loads(self.server_config_path.read_text())['settings']['noagentupdate'] is False)

    def test_the_preview_container_runs_from_its_own_folders_as_its_own_account(self):
        MANAGER.promote(PREVIEW_CONFIG, DIGEST)
        args = self.docker_run()
        self.assertEqual(args[args.index('--name') + 1], 'meshcentral-preview')
        self.assertEqual(args[args.index('--label') + 1], 'meshcentral-release.instance=preview')
        self.assertEqual(self.accounts, ['meshcentral-preview'])
        mounts = [args[index + 1] for index, arg in enumerate(args) if arg == '--mount']
        self.assertEqual(mounts, ['type=bind,src={},dst=/opt/meshcentral/{}{}'.format(self.base / name, name, suffix)
                                  for name, suffix in (('meshcentral-data', ''), ('meshcentral-files', ''),
                                                       ('meshcentral-web', ',readonly'),
                                                       ('meshcentral-recordings', ''), ('meshcentral-backups', ''))])
        self.assertTrue(args[-1].endswith('@' + DIGEST))

    def test_a_failed_first_preview_deploy_leaves_the_preview_stopped(self):
        self.mocks['healthy'].return_value = False
        with mock.patch('sys.stdout', new_callable=io.StringIO) as stdout, \
                self.assertRaisesRegex(RuntimeError, 'readiness'):
            MANAGER.promote(PREVIEW_CONFIG, DIGEST)
        self.assertIn('No earlier preview release to restore', stdout.getvalue())
        self.assertIsNone(json.loads((self.state / 'active.json').read_text()))
        self.assertFalse((self.state / 'transaction.json').exists())
        self.assertEqual(self.server_config_path.read_bytes(), self.original_server_config)
        self.assertFalse([call for call in self.calls if call[0] == 'systemctl'])
        self.assertEqual(self.calls.count(('remove',)), 2)  # before the candidate and in recovery
        self.assertEqual(self.mocks['healthy'].call_count, 1)  # nothing to probe after recovery

    def test_a_later_preview_deploy_protects_and_restores_the_previous_preview_release(self):
        previous = {'digest': PREVIOUS, 'directory': str(make_release(self.state / 'releases/previous'))}
        (self.state / 'active.json').write_text(json.dumps(previous))
        self.mocks['healthy'].side_effect = [True, False, True]
        with self.assertRaisesRegex(RuntimeError, 'readiness'):
            MANAGER.promote(PREVIEW_CONFIG, DIGEST)
        self.assertEqual(json.loads((self.state / 'active.json').read_text()), previous)
        self.mocks['healthy'].return_value = False
        self.mocks['healthy'].side_effect = None
        with self.assertRaisesRegex(RuntimeError, 'Current preview service is unhealthy'):
            MANAGER.promote(PREVIEW_CONFIG, DIGEST)

    def test_production_state_is_never_touched(self):
        production = self.instances['production']
        before = sorted(path.relative_to(production.base.parent) for path in production.base.parent.rglob('*'))
        MANAGER.promote(PREVIEW_CONFIG, DIGEST)
        after = sorted(path.relative_to(production.base.parent) for path in production.base.parent.rglob('*'))
        self.assertEqual(before, after)


class PreviewServerConfigTests(TwoInstanceCase):
    def setUp(self):
        super().setUp()
        self.activate('preview')

    def problems(self, config, instance=None):
        problems = MANAGER.server_config_instance_problems(config, instance)
        self.assertNotIn(SECRET, '\n'.join(problems))
        return problems

    def assertProblem(self, config, text, instance=None):
        problems = self.problems(config, instance)
        self.assertTrue(any(text in problem for problem in problems), problems)

    def test_the_filled_template_fits_the_preview_and_not_production(self):
        self.assertEqual(self.problems(filled_template()), [])
        MANAGER.check_server_config_paths(filled_template(), '/opt/meshcentral')
        production = self.problems(filled_template(), 'production')
        for text in ('settings.port = 4440 is a port of the preview instance',
                     'settings.mpsport = 4441 is a port of the preview instance',
                     'settings.mongodbname = meshcentral_preview is the preview instance\'s database',
                     'settings.cert names preview.high.support', 'settings.agentaliasdns names preview.high.support',
                     'domains[""].certurl names preview.high.support'):
            self.assertTrue(any(text in problem for problem in production), (text, production))

    def test_unreplaced_template_placeholders_are_refused(self):
        config = json.loads(TEMPLATE.read_text(encoding='utf-8'))
        problems = self.problems(config)
        self.assertEqual(sorted(problem for problem in problems if 'placeholder' in problem),
                         ['config.settings.' + key + ' still holds a REPLACE_ template placeholder'
                          for key in sorted(('mongoDb', 'sessionKey', 'dbEncryptKey', 'dbRecordsEncryptKey'))])

    def test_production_defaults_are_refused_for_the_preview(self):
        config = filled_template()
        del config['settings']['mongoDbName']
        self.assertProblem(config, "settings.mongodbname = meshcentral is the production instance's database "
                                   "(MeshCentral's default when the key is absent)")
        del config['settings']['mpsPort']
        self.assertProblem(config, "settings.mpsport = 4433 is a port of the production instance (MeshCentral's "
                                   "default when the key is absent)")
        self.assertProblem(config, 'settings.mpsport must be 4441 for the preview instance, found 4433')

    def test_each_preview_setting_is_exact(self):
        cases = (('port', 4430, 'settings.port = 4430 is a port of the production instance'),
                 ('port', '4440', 'settings.port must be 4440 for the preview instance, found "4440"'),
                 ('portBind', '0.0.0.0', 'settings.portbind must be "127.0.0.1"'),
                 ('redirPort', 80, 'settings.redirport must be 0'),
                 ('mpsPortBind', None, 'settings.mpsportbind must be "127.0.0.1"'),
                 ('mongoDb', None, 'settings.mongodb must give the MongoDB URI'),
                 ('cert', 'high.support', 'settings.cert must be "preview.high.support"'),
                 ('agentAliasDNS', 'agents.high.support', 'settings.agentaliasdns names agents.high.support'))
        for key, value, text in cases:
            config = filled_template()
            if value is None:
                del config['settings'][key]
            else:
                config['settings'][key] = value
            with self.subTest(key=key, value=value):
                self.assertProblem(config, text)
        config = filled_template()
        config['domains']['']['certUrl'] = 'https://agents.high.support:443/'
        self.assertProblem(config, 'domains[""].certurl names agents.high.support')

    def test_mps_may_be_disabled(self):
        config = filled_template()
        config['settings']['mpsPort'] = 0
        del config['settings']['mpsPortBind']
        self.assertEqual(self.problems(config), [])

    def test_production_refuses_only_the_preview_values(self):
        self.assertEqual(self.problems({'settings': {'port': 4430, 'mongodb': PREVIEW_URI, 'cert': 'high.support',
                                                     'agentAliasDNS': 'agents.high.support'}}, 'production'), [])
        self.assertEqual(self.problems({}, 'production'), [])
        self.assertProblem({'settings': {'mongodb': PREVIEW_URI, 'mongoDbName': 'meshcentral_preview'}},
                           "is the preview instance's database", 'production')

    def test_preview_paths_are_the_containers(self):
        self.server_config_path.write_text(json.dumps(filled_template()))
        MANAGER.check_server_config()
        config = filled_template()
        config['settings']['autoBackup']['backupPath'] = '/opt/meshcentral-preview/meshcentral-backups'
        self.server_config_path.write_text(json.dumps(config))
        with self.assertRaises(ValueError) as raised:
            MANAGER.check_server_config()
        message = str(raised.exception)
        self.assertIn('settings.autobackup.backuppath = /opt/meshcentral-preview/meshcentral-backups', message)
        self.assertIn('The preview container mounts ' + str(self.base) + '/<folder> at /opt/meshcentral/<folder>', message)
        self.assertNotIn(SECRET, message)

    def test_start_refuses_a_config_for_the_wrong_instance_before_docker(self):
        config = filled_template()
        config['settings']['port'] = 4430
        self.server_config_path.write_text(json.dumps(config))
        with mock.patch.object(MANAGER, 'run') as run, \
                self.assertRaisesRegex(ValueError, 'does not fit the preview instance'):
            MANAGER.start(PREVIEW_CONFIG, {'digest': DIGEST, 'directory': str(make_release(self.root / 'r'))})
        run.assert_not_called()


class IsolationTests(TwoInstanceCase):
    def test_separate_folders_pass(self):
        for name in ('production', 'preview'):
            with self.subTest(instance=name):
                self.activate(name)
                MANAGER.check_instance_isolation()

    def test_a_preview_root_linked_to_production_is_refused(self):
        preview = self.instances['preview']
        moved = preview.base.with_name('unused')
        preview.base.rename(moved)
        try_symlink(self, preview.base, self.instances['production'].base)
        self.activate('preview')
        with self.assertRaisesRegex(ValueError, 'preview install root .* overlaps the production install root'):
            MANAGER.check_instance_isolation()

    def test_a_preview_folder_linked_into_production_is_refused(self):
        production = self.instances['production']
        (production.base / 'meshcentral-backups').mkdir()
        try_symlink(self, self.instances['preview'].base / 'meshcentral-backups', production.base / 'meshcentral-backups')
        self.activate('preview')
        with self.assertRaisesRegex(ValueError, 'preview mounted folder .*meshcentral-backups .* overlaps the production '
                                                'install root'):
            MANAGER.check_instance_isolation()
        with mock.patch.object(MANAGER, 'run') as run, self.assertRaisesRegex(ValueError, 'overlap'):
            MANAGER.start(PREVIEW_CONFIG, {'digest': DIGEST, 'directory': str(make_release(self.root / 'r'))})
        run.assert_not_called()

    def test_a_preview_state_inside_production_is_refused(self):
        with mock.patch.dict(MANAGER.INSTANCES, {'preview': dataclasses.replace(
                self.instances['preview'], state=self.instances['production'].base / 'preview-state')}):
            self.activate('preview')
            with self.assertRaisesRegex(ValueError, 'preview state directory .* overlaps the production install root'):
                MANAGER.check_instance_isolation()


class IdentitySeparationTests(TwoInstanceCase):
    def test_production_certificates_in_the_preview_are_refused_under_any_name(self):
        production = self.instances['production'].base / 'meshcentral-data'
        preview = self.instances['preview'].base / 'meshcentral-data'
        write(production / 'agentserver-cert-public.crt', b'production agent certificate')
        write(production / 'agentserver-cert-private.key', b'production agent key')
        write(preview / 'webserver-cert-public.crt', b'preview web certificate')
        self.activate('preview')
        MANAGER.check_identity_separation()
        write(preview / 'root-cert-private.key', b'production agent key')
        with self.assertRaisesRegex(ValueError, "root-cert-private.key equals the production instance's "
                                                'agentserver-cert-private.key') as raised:
            MANAGER.check_identity_separation()
        self.assertNotIn('production agent key', str(raised.exception))

    def test_production_is_not_blocked_by_the_preview(self):
        for base in (self.instances['production'].base, self.instances['preview'].base):
            write(base / 'meshcentral-data/agentserver-cert-public.crt', b'same')
        self.activate('production')
        MANAGER.check_identity_separation()


class ContainerOwnershipTests(TwoInstanceCase):
    def info(self, label=None, sources=()):
        labels = {} if label is None else {'meshcentral-release.instance': label}
        return {'State': {'Running': True}, 'Config': {'Image': 'ghcr.io/fixture/release@' + DIGEST, 'Labels': labels},
                'Mounts': [{'Type': 'bind', 'Source': str(PurePosixPath(Path(source).as_posix()))} for source in sources] +
                          [{'Type': 'tmpfs', 'Source': ''}]}

    def remove(self, info):
        calls = []
        with mock.patch.object(MANAGER, 'inspect_container', return_value=info), \
                mock.patch.object(MANAGER, 'run', side_effect=lambda *args, **kw: calls.append(args)):
            MANAGER.remove_container()
        return calls

    def test_preview_stops_only_its_own_container(self):
        self.activate('preview')
        own = self.info('preview', [self.base / 'meshcentral-data'])
        self.assertEqual(self.remove(own), [('docker', 'stop', '--time', '60', 'meshcentral-preview'),
                                            ('docker', 'rm', 'meshcentral-preview')])
        for info, text in ((self.info('production'), "labelled for instance 'production', not preview"),
                           (self.info(None), "labelled for instance None, not preview"),
                           (self.info('preview', [self.instances['production'].base / 'meshcentral-data']),
                            'outside the preview install root')):
            with self.subTest(text=text), self.assertRaisesRegex(RuntimeError, 'Not stopping it: .*' + re.escape(text)):
                self.remove(info)

    def test_production_accepts_the_unlabelled_container_of_older_controllers(self):
        self.activate('production')
        self.assertEqual(len(self.remove(self.info(None, [self.base / 'meshcentral-data']))), 2)
        self.assertEqual(len(self.remove(self.info('production'))), 2)
        with self.assertRaisesRegex(RuntimeError, "labelled for instance 'preview'"):
            self.remove(self.info('preview'))

    def test_a_foreign_container_is_never_reported_healthy(self):
        self.activate('preview')
        with mock.patch.object(MANAGER, 'inspect_container', return_value=self.info('production')), \
                mock.patch.object(MANAGER.urllib.request, 'urlopen', side_effect=OSError('no network in tests')):
            self.assertFalse(MANAGER.healthy(PREVIEW_CONFIG, DIGEST, attempts=1))


class PreviewInstallationTests(TwoInstanceCase):
    """install_controller.py --instance preview, beside an installed production controller."""

    def setUp(self):
        super().setUp()
        etc = self.root / 'etc'
        self.paths = {'CONFIG': etc / 'meshcentral-deploy.json', 'SUDOERS': etc / 'sudoers.d/meshcentral-deploy',
                      'CONTROLLER': self.root / 'libexec/meshcentral-release',
                      'CI_ENTRY': self.root / 'sbin/meshcentral-ci-entry'}
        shadow = self.root / 'libexec/meshcentral_shadow_check.py'
        installed = {INSTALLER.CONTROLLER: self.paths['CONTROLLER'], INSTALLER.CI_ENTRY: self.paths['CI_ENTRY'],
                     INSTALLER.SHADOW_CHECK: shadow}
        self.code = tuple((name, installed[destination], mode) for name, destination, mode in INSTALLER.CODE)
        for name, destination, _ in self.code:
            write(destination, INSTALLER.normalized_text(DEPLOYMENT / name))
        write(self.paths['SUDOERS'], b'meshdeploy ALL=(root) NOPASSWD: /usr/local/sbin/meshcentral-ci-entry\n')
        write(self.paths['CONFIG'], json.dumps(PRODUCTION_CONFIG).encode())
        self.production_bytes = self.paths['CONFIG'].read_bytes()
        # The preview instance is not installed yet: no state, config or install root.
        preview = self.instances['preview']
        for path in sorted(preview.base.rglob('*'), reverse=True) + [preview.base, preview.state]:
            path.rmdir()
        self.users = {'meshdeploy'}
        account = types.SimpleNamespace(pw_uid=0, pw_gid=0)

        def getpwnam(user):
            if user not in self.users:
                raise KeyError(user)
            return account

        def run(args, check=False, **kwargs):
            self.commands.append(args)
            if args[0] == 'useradd':
                self.users.add(args[-1])
            return types.SimpleNamespace(returncode=0)

        self.commands = []
        patches = [mock.patch.object(INSTALLER, name, value) for name, value in self.paths.items()]
        patches += [mock.patch.object(INSTALLER, 'CODE', self.code),
                    mock.patch.object(INSTALLER, 'pwd', types.SimpleNamespace(getpwnam=getpwnam)),
                    mock.patch.object(INSTALLER.subprocess, 'run', side_effect=run),
                    mock.patch.object(INSTALLER.os, 'chown', create=True),
                    mock.patch.object(INSTALLER, 'release_manager', MANAGER)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def install(self, enable_fleet_update=False):
        with mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            INSTALLER.install_instance('preview', enable_fleet_update)
        return stdout.getvalue()

    def test_installs_the_preview_beside_production_without_changing_it(self):
        output = self.install(enable_fleet_update=True)
        preview = self.instances['preview']
        self.assertEqual(json.loads(preview.config.read_text()),
                         {'schema': 3, 'instance': 'preview', 'image': PRODUCTION_CONFIG['image'],
                          'health_url': PREVIEW_HEALTH, 'reviewed_versions': PRODUCTION_CONFIG['reviewed_versions'],
                          'enable_fleet_update': True})
        self.assertEqual(sorted(path.name for path in preview.base.iterdir()), sorted(MANAGER.MOUNTED_FOLDERS))
        self.assertEqual(self.commands, [['useradd', '--system', '--user-group', '--no-create-home', '--home-dir',
                                          '/nonexistent', '--shell', '/usr/sbin/nologin', 'meshcentral-preview']])
        self.assertEqual(self.paths['CONFIG'].read_bytes(), self.production_bytes)
        for name, destination, _ in self.code:
            self.assertEqual(destination.read_bytes(), INSTALLER.normalized_text(DEPLOYMENT / name))
        self.assertIn('Production was not changed', output)
        self.assertIs(MANAGER.INSTANCE, MANAGER.INSTANCES['preview'])
        MANAGER.validate_config(json.loads(preview.config.read_text()))

    def test_the_installed_code_must_be_this_checkout(self):
        controller = self.paths['CONTROLLER']
        controller.write_text('# controller before the preview instance existed\n')
        with self.assertRaisesRegex(ValueError, 'install_controller.py --upgrade.*\n  ' + re.escape(str(controller)) +
                                                ' differs from'):
            self.install()
        self.assertFalse(self.instances['preview'].config.exists())
        self.assertEqual(self.commands, [])

    def test_existing_preview_state_account_or_folders_are_refused(self):
        preview = self.instances['preview']
        for prepare, text in ((lambda: write(preview.config, b'{}'), 'controller configuration already exists'),
                              (lambda: preview.state.mkdir(parents=True), 'state directory already exists'),
                              (lambda: write(preview.base / 'meshcentral-data/config.json', b'{}'),
                               'is not an empty folder'),
                              (lambda: self.users.add('meshcentral-preview'), 'meshcentral-preview account already exists')):
            with self.subTest(text=text):
                prepare()
                with self.assertRaisesRegex(ValueError, text):
                    self.install()
                self.assertEqual(self.commands, [])
                for path in (preview.config,):
                    if path.exists():
                        path.unlink()
                if preview.state.exists():
                    preview.state.rmdir()
                if preview.base.exists():
                    for path in sorted(preview.base.rglob('*'), reverse=True):
                        path.unlink() if path.is_file() else path.rmdir()
                    preview.base.rmdir()
                self.users.discard('meshcentral-preview')

    def test_production_must_be_installed_first(self):
        self.paths['SUDOERS'].unlink()
        with self.assertRaisesRegex(ValueError, 'Install the production controller first; missing .*sudoers'):
            self.install()
        write(self.paths['SUDOERS'], b'rule\n')
        self.users.discard('meshdeploy')
        with self.assertRaisesRegex(ValueError, 'meshdeploy account'):
            self.install()

    def test_a_preview_configuration_at_the_production_path_is_refused(self):
        self.paths['CONFIG'].write_text(json.dumps(PREVIEW_CONFIG))
        with self.assertRaisesRegex(ValueError, "configuration of instance 'preview', not production"):
            self.install()

    def test_command_line_keeps_preview_installation_separate_from_upgrade_and_fresh_install(self):
        for argv in (['--instance', 'preview', '--upgrade'], ['--instance', 'preview', '--image', 'ghcr.io/x/y'],
                     ['--instance', 'preview', '--health-url', PREVIEW_HEALTH]):
            with self.subTest(argv=argv), mock.patch.object(sys, 'argv', ['install_controller.py'] + argv), \
                    mock.patch.object(INSTALLER.os, 'geteuid', return_value=0, create=True), \
                    mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
                INSTALLER.main()
        self.assertEqual(self.commands, [])


class SharedCodeUpgradeTests(TwoInstanceCase):
    """--upgrade replaces code both instances run, so it also holds the preview lock."""

    def setUp(self):
        super().setUp()
        self.flock = mock.Mock()
        patches = [mock.patch.object(INSTALLER, 'fcntl', types.SimpleNamespace(flock=self.flock, LOCK_EX=2, LOCK_NB=4)),
                   mock.patch.object(INSTALLER, 'release_manager', MANAGER)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_the_preview_lock_is_held_when_the_preview_is_installed(self):
        with INSTALLER.instance_lock('preview'):
            self.flock.assert_called_once()
        self.assertTrue((self.instances['preview'].state / 'lock').exists())

    def test_nothing_is_locked_when_the_preview_is_not_installed(self):
        self.instances['preview'].state.rmdir()
        with INSTALLER.instance_lock('preview'):
            pass
        self.flock.assert_not_called()

    def test_a_running_or_interrupted_preview_operation_blocks_the_upgrade(self):
        self.flock.side_effect = BlockingIOError()
        with self.assertRaisesRegex(RuntimeError, 'A preview release controller operation is running'):
            with INSTALLER.instance_lock('preview'):
                pass
        self.flock.side_effect = None
        write(self.instances['preview'].state / 'transaction.json', b'{}')
        with self.assertRaisesRegex(RuntimeError, 'interrupted preview transaction.*--instance preview recover'):
            with INSTALLER.instance_lock('preview'):
                pass


class TemplateTests(unittest.TestCase):
    """The template is production's settings with only the documented preview substitutions."""

    # Every production_flags.json key without an inline value, with the template's value (None: left out).
    # Preview substitutions, and production values captured outside the repository ("evidence" keys:
    # meshcentral-fork-ssot/evidence/live/config-extra-values.json, non-secret).
    PREVIEW_VALUES = {
        'settings': {'aliasPort': 443, 'cert': 'preview.high.support', 'port': 4440, 'portBind': '127.0.0.1',
                     'mpsPortBind': '127.0.0.1', 'tlsOffload': '127.0.0.1,::1', 'agentAliasDNS': 'preview.high.support',
                     'mongodb': 'REPLACE_WITH_THE_PREVIEW_MONGODB_URI', 'sessionKey': 'REPLACE_WITH_A_FRESH_SESSION_KEY',
                     'dbEncryptKey': 'REPLACE_WITH_A_FRESH_DB_ENCRYPT_KEY',
                     'dbRecordsEncryptKey': 'REPLACE_WITH_A_FRESH_DB_RECORDS_ENCRYPT_KEY', 'dataPath': None,
                     'autobackup': {'backupPath': '/opt/meshcentral/meshcentral-backups', 'backupIntervalHours': 24,
                                    'keepLastDaysBackup': 14, 'backupSkipFoldersGlob': [
                                        '**/apparmor/**', '**/cache/**', '**/tmp/**', 'backups', 'meshcores', 'staging',
                                        'umh-backups', 'node_modules', 'bin', 'meshcentral-backups',
                                        '@(!(meshcentral-data))', 'meshcentral-data/certificate-history-backups']},
                     'ciphers': 'HIGH:!aNULL:!MD5', 'cookieIpCheck': 'none'},
        'domain': {'allowedorigin': ['preview.high.support'], 'certurl': 'https://preview.high.support:443/',
                   'title': 'High Support Preview', 'url': None, 'agentwebcerthashes': None, 'agentwebcerturls': None,
                   'customFiles': None, 'auth': 'default',
                   'agentConfig': ['coreDumpEnabled=1', 'connectionTimeout=60', 'retryAttempts=10', 'retryDelay=20',
                                   'agentPing=60', 'agentPong=60', 'ignoreProxyFile=1']},
    }

    @classmethod
    def setUpClass(cls):
        cls.template = json.loads(TEMPLATE.read_text(encoding='utf-8'))
        cls.flags = json.loads(PRODUCTION_FLAGS.read_text(encoding='utf-8'))

    @staticmethod
    def lowered(section):
        return {key.lower(): value for key, value in section.items()}

    def check_section(self, flags, actual, preview_values):
        actual = self.lowered(actual)
        preview_values = self.lowered(preview_values)
        for key, spec in flags.items():
            with self.subTest(key=key):
                if 'value' in spec:
                    self.assertEqual(actual.get(key.lower()), spec['value'])
                    continue
                self.assertIn(key.lower(), preview_values, 'production_flags.json ' + key + ' needs a preview decision')
                expected = preview_values[key.lower()]
                if expected is None:
                    self.assertNotIn(key.lower(), actual)
                elif isinstance(expected, dict):
                    self.assertEqual(self.lowered(actual[key.lower()]), self.lowered(expected))
                else:
                    self.assertEqual(actual.get(key.lower()), expected)
        flagged = {key.lower() for key in flags}
        return sorted(key for key in actual if key not in flagged)

    def test_settings_equal_production_except_the_preview_substitutions(self):
        extra = self.check_section(self.flags['settings'], self.template['settings'], self.PREVIEW_VALUES['settings'])
        # Keys production leaves at MeshCentral's defaults, which the preview must set to stay off production's.
        self.assertEqual(extra, ['mongodbname', 'mpsport'])
        self.assertEqual(self.template['settings']['mpsPort'], MANAGER.INSTANCES['preview'].mps_port)
        self.assertEqual(self.template['settings']['mongoDbName'], MANAGER.INSTANCES['preview'].database)

    def test_default_domain_equals_production_except_the_preview_substitutions(self):
        domain = self.template['domains']['']
        extra = self.check_section(self.flags['domain'], domain, self.PREVIEW_VALUES['domain'])
        self.assertEqual(extra, [key.lower() for key in self.flags['after_inventory']['domain']])
        for key, spec in self.flags['after_inventory']['domain'].items():
            self.assertEqual(self.lowered(domain).get(key.lower()), spec['value'])
        self.assertEqual(list(self.template['domains']), [''])

    def test_the_template_holds_no_secret_and_uses_the_container_paths(self):
        settings = self.template['settings']
        for key in ('mongoDb', 'sessionKey', 'dbEncryptKey', 'dbRecordsEncryptKey'):
            self.assertTrue(settings[key].startswith(MANAGER.TEMPLATE_PLACEHOLDER), key)
        self.assertNotIn('://', settings['mongoDb'])
        self.assertEqual(MANAGER.server_config_paths(self.template),
                         [('settings.autobackup.backuppath', '/opt/meshcentral/meshcentral-backups', 'write')])
        MANAGER.check_server_config_paths(self.template, str(MANAGER.INSTANCES['preview'].mount_root))
        self.assertNotIn('/opt/meshcentral-preview/meshcentral-', json.dumps(settings))


if __name__ == '__main__':
    unittest.main()
