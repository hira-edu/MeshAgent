#!/usr/bin/env python3
"""Install the release controller and restricted SSH account without switching services.

Controller code is installed from this checkout.

--upgrade replaces the installed controller code of an existing installation from this checkout
and migrates the configuration to the current schema (see release_manager.migrate_config). It does
not touch the host service's legacy image-size preload: the 1.2.5 host installation keeps it until
the first container release is promoted, which retires it (release_manager.retire_legacy_preload).
The controller code is shared by every instance, so --upgrade also holds the preview instance's lock
when that instance is installed.

--instance preview installs the preview instance (release_manager.INSTANCES['preview']) beside an
installed production controller whose code equals this checkout: its service account, its
persistent folders and its controller configuration. It reads production's configuration (image
repository and reviewed versions) and writes nothing of production's. The preview deploys through
the same CI key and forced command (`deploy-preview sha256:<digest>`).
"""
import argparse
import contextlib
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
import release_manager  # noqa: E402  (configuration schema and migration live with the controller)

CONFIG = Path('/etc/meshcentral-deploy.json')
SUDOERS = Path('/etc/sudoers.d/meshcentral-deploy')
CONTROLLER = Path('/usr/local/libexec/meshcentral-release')
CI_ENTRY = Path('/usr/local/sbin/meshcentral-ci-entry')
PACKAGE = Path('/opt/meshcentral/node_modules/meshcentral/package.json')
# The controller imports this module from its own directory.
SHADOW_CHECK = CONTROLLER.parent / 'meshcentral_shadow_check.py'
# Repository file -> installed path and mode, for every file the controller runs.
CODE = (('release_manager.py', CONTROLLER, 0o755), ('ci_entry.py', CI_ENTRY, 0o755),
        ('meshcentral_shadow_check.py', SHADOW_CHECK, 0o644))


def normalized_text(source):
    # Normalize source checkout line endings; installed files always use LF.
    return source.read_text(encoding='utf-8').encode('utf-8')


def install(source, destination, mode):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(normalized_text(source))
    os.chown(destination, 0, 0)
    destination.chmod(mode)


def write_private_json(path, data):
    """Write JSON readable by root only, replacing ``path`` atomically."""
    temporary = path.with_name(path.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    release_manager.sync_directory(path.parent)


def require_sources():
    for name, _, _ in CODE:
        if not (SOURCE / name).is_file():
            raise ValueError('Missing controller source: ' + str(SOURCE / name))


def install_code():
    for name, destination, mode in CODE:
        install(SOURCE / name, destination, mode)


def migrate_config_file():
    """Migrate the installed configuration in place, keeping the original beside it.

    Returns the backup path, or None when the configuration was already current.
    """
    original = CONFIG.read_bytes()
    current = json.loads(original)
    migrated = release_manager.migrate_config(current)
    if migrated == current:
        return None
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = CONFIG.with_name(CONFIG.name + '.pre-upgrade-' + stamp)
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    write_private_json(CONFIG, migrated)
    if release_manager.RETIRED_MITIGATION_KEY in current:
        print('Removed ' + release_manager.RETIRED_MITIGATION_KEY + ' from ' + str(CONFIG) + ': release images '
              'no longer install image-size, so the controller preloads nothing. The host service keeps its '
              'preload until the first container release is promoted.')
    return backup


@contextlib.contextmanager
def instance_lock(name):
    """Hold a non-production instance's controller lock while it is installed (nothing otherwise)."""
    state = release_manager.INSTANCES[name].state
    if not state.is_dir():
        yield
        return
    with (state / 'lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('A ' + name + ' release controller operation is running; retry the upgrade after it ends')
        if (state / 'transaction.json').exists():
            raise RuntimeError('An interrupted ' + name + ' transaction exists. Run "meshcentral-release --instance ' +
                               name + ' recover" before upgrading the controller.')
        yield


def upgrade():
    """Replace the controller code and migrate the configuration."""
    if not CONFIG.is_file():
        raise ValueError('No controller configuration at ' + str(CONFIG) + '; run a fresh installation instead')
    for path in (CONTROLLER, CI_ENTRY, SUDOERS):
        if not path.is_file():
            raise ValueError('Existing installation is incomplete; inspect it before upgrading: ' + str(path))
    require_sources()
    release_manager.STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (release_manager.STATE / 'lock').open('w') as lock:
        # The same lock serializes promotions, so no deployment runs during the upgrade.
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('A release controller operation is running; retry the upgrade after it ends')
        if (release_manager.STATE / 'transaction.json').exists():
            raise RuntimeError('An interrupted transaction exists. Run recover before upgrading the controller.')
        with contextlib.ExitStack() as other_instances:
            # Every installed instance runs this code, so none of them may be mid-operation either.
            for name in release_manager.INSTANCES:
                if name != 'production':
                    other_instances.enter_context(instance_lock(name))
            install_code()
            backup = migrate_config_file()
    config = release_manager.load_config()
    print('Controller code upgraded from ' + str(SOURCE) + '.')
    if backup:
        print('Configuration migrated to schema ' + str(release_manager.CONFIG_SCHEMA) +
              '; previous file kept at ' + str(backup) + '.')
    print('Reviewed MeshCentral versions: ' + ', '.join(config['reviewed_versions']))


def fresh_install(args):
    if not re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+', args.image):
        raise ValueError('Invalid GHCR repository')
    if not args.health_url.startswith('https://') or not args.health_url.endswith('/health.ashx'):
        raise ValueError('Use the public HTTPS health.ashx endpoint')
    public_key = args.public_key.read_text().strip()
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?', public_key):
        raise ValueError('Provide one dedicated Ed25519 public key')
    subprocess.run(['docker', 'info'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'is-active', '--quiet', 'meshcentral'], check=True)
    # The running host installation is the version reviewed at installation time.
    version = json.loads(PACKAGE.read_text())['version']
    service_account = pwd.getpwnam('meshcentral')
    if CONFIG.exists():
        raise ValueError('Controller already configured; use --upgrade or review changes in place instead of overwriting policy')
    try:
        account = pwd.getpwnam('meshdeploy')
    except KeyError:
        account = None
    if account is not None:
        raise ValueError('meshdeploy already exists; inspect its ownership and access before installation')
    for destination in (SUDOERS, CONTROLLER, CI_ENTRY, SHADOW_CHECK):
        if destination.exists():
            raise ValueError('Existing controller file requires operator review: ' + str(destination))
    require_sources()
    for name in ('meshcentral-files', 'meshcentral-web', 'meshcentral-recordings', 'meshcentral-backups'):
        directory = Path('/opt/meshcentral') / name
        if not directory.exists():
            directory.mkdir(mode=0o750)
            os.chown(directory, service_account.pw_uid, service_account.pw_gid)
    subprocess.run(['useradd', '--system', '--create-home', '--shell', '/bin/sh', 'meshdeploy'], check=True)
    account = pwd.getpwnam('meshdeploy')
    install_code()
    config = release_manager.new_config(args.image, args.health_url, version, args.enable_fleet_update)
    SUDOERS.write_text('meshdeploy ALL=(root) NOPASSWD: ' + str(CI_ENTRY) + '\n')
    SUDOERS.chmod(0o440)
    subprocess.run(['visudo', '-cf', str(SUDOERS)], check=True)
    ssh = Path(account.pw_dir) / '.ssh'
    ssh.mkdir(mode=0o700, exist_ok=True)
    authorized = ssh / 'authorized_keys'
    if authorized.exists():
        raise ValueError('Dedicated account already has keys; inspect before replacing them')
    authorized.write_text(r'restrict,command="sudo -n /usr/local/sbin/meshcentral-ci-entry \"$SSH_ORIGINAL_COMMAND\"" ' + public_key + '\n')
    authorized.chmod(0o600)
    for path in (ssh, authorized):
        os.chown(path, account.pw_uid, account.pw_gid)
    write_private_json(CONFIG, config)
    print('Controller installed. Existing MeshCentral is still running under systemd.')
    print('Reviewed MeshCentral versions: ' + ', '.join(config['reviewed_versions']))
    print('Review GitHub environment/registry access before the first digest promotion.')


def installed_code_problems():
    """Name every installed controller file that is missing or differs from this checkout."""
    problems = []
    for name, destination, _ in CODE:
        if not destination.is_file():
            problems.append(str(destination) + ' is missing')
        elif destination.read_bytes() != normalized_text(SOURCE / name):
            problems.append(str(destination) + ' differs from ' + str(SOURCE / name))
    return problems


def install_instance(name, enable_fleet_update):
    """Install a non-production instance beside the production controller, writing nothing of production's."""
    instance = release_manager.INSTANCES[name]
    if instance.host_service or name == 'production':
        raise ValueError('The production controller is installed without --instance')
    require_sources()
    # Shared with production: the CI key and forced command, the sudoers rule and the controller code.
    for path in (CONFIG, SUDOERS, CONTROLLER, CI_ENTRY):
        if not path.is_file():
            raise ValueError('Install the production controller first; missing ' + str(path))
    try:
        pwd.getpwnam('meshdeploy')
    except KeyError:
        raise ValueError('The meshdeploy account of the production installation is missing') from None
    problems = installed_code_problems()
    if problems:
        raise ValueError('The installed controller code is not this checkout\'s, so it cannot deploy the ' + name +
                         ' instance yet. Run "install_controller.py --upgrade" from this checkout first:\n  ' +
                         '\n  '.join(problems))
    production = release_manager.validate_config(json.loads(CONFIG.read_text()), 'production')
    release_manager.activate(name)
    release_manager.check_instance_isolation()
    for path, what in ((instance.config, 'controller configuration'), (instance.state, 'state directory')):
        if path.exists() or path.is_symlink():
            raise ValueError('The ' + name + ' ' + what + ' already exists; inspect it before installing: ' + str(path))
    base = instance.base
    if base.is_symlink() or (base.exists() and (not base.is_dir() or any(base.iterdir()))):
        raise ValueError(str(base) + ' already exists and is not an empty folder; inspect it before installing')
    try:
        pwd.getpwnam(instance.account)
    except KeyError:
        pass
    else:
        raise ValueError('The ' + instance.account + ' account already exists; inspect its files and access before '
                         'installing')
    config = release_manager.new_instance_config(name, production['image'], production['reviewed_versions'],
                                                 enable_fleet_update)
    subprocess.run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
                    '--shell', '/usr/sbin/nologin', instance.account], check=True)
    account = pwd.getpwnam(instance.account)
    base.mkdir(mode=0o755, exist_ok=True)
    os.chown(base, 0, 0)
    base.chmod(0o755)
    for folder in release_manager.MOUNTED_FOLDERS:
        directory = base / folder
        directory.mkdir(mode=0o750)
        os.chown(directory, account.pw_uid, account.pw_gid)
        directory.chmod(0o750)
    write_private_json(instance.config, config)
    print('Installed the ' + name + ' instance: account ' + instance.account + ', folders under ' + str(base) +
          ', configuration ' + str(instance.config) + '. Production was not changed.')
    print('Reviewed MeshCentral versions (from ' + str(CONFIG) + '): ' + ', '.join(config['reviewed_versions']))
    print('Before the first deploy, write ' + str(base / 'meshcentral-data/config.json') + ' from '
          'tools/deployment/meshcentral-preview-config.template.json (owner ' + instance.account + ', mode 0600).')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upgrade', action='store_true',
                        help='upgrade the controller code and configuration of an existing installation')
    parser.add_argument('--instance', choices=sorted(release_manager.INSTANCES), default='production',
                        help='install another server instance beside production (default: production)')
    parser.add_argument('--public-key', type=Path)
    parser.add_argument('--image')
    parser.add_argument('--health-url')
    parser.add_argument('--enable-fleet-update', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Administrator installation is required')
    if args.instance != 'production':
        if args.upgrade:
            parser.error('--upgrade replaces the controller code every instance shares and migrates the production '
                         'configuration; run it without --instance')
        if args.public_key or args.image or args.health_url:
            parser.error('the ' + args.instance + ' instance uses the installed CI key, the production image repository '
                         'and its fixed health URL; only --enable-fleet-update applies')
        install_instance(args.instance, args.enable_fleet_update)
    elif args.upgrade:
        if args.public_key or args.image or args.health_url or args.enable_fleet_update:
            parser.error('--upgrade keeps the installed policy; edit it in place instead of passing installation options')
        upgrade()
    else:
        if not (args.public_key and args.image and args.health_url):
            parser.error('a fresh installation requires --public-key, --image and --health-url')
        fresh_install(args)


if __name__ == '__main__':
    main()
