#!/usr/bin/env python3
"""Install the release controller and restricted SSH account without switching services.

--upgrade replaces the installed controller code of an existing installation from this checkout
and migrates its configuration to the current schema (see release_manager.migrate_config).
"""
import argparse
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


def install(source, destination, mode):
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Normalize source checkout line endings before installing executable scripts.
    destination.write_text(source.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
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
    return backup


def upgrade():
    """Replace the controller code and migrate the configuration of an existing installation."""
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
    mitigation = Path('/opt/meshcentral/bin/harden-image-size.js')
    if not mitigation.is_file():
        raise ValueError('Inspect the existing production mitigation before installing')
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
    config = release_manager.new_config(args.image, args.health_url, version, args.enable_fleet_update)
    for name in ('meshcentral-files', 'meshcentral-web', 'meshcentral-recordings', 'meshcentral-backups'):
        directory = Path('/opt/meshcentral') / name
        if not directory.exists():
            directory.mkdir(mode=0o750)
            os.chown(directory, service_account.pw_uid, service_account.pw_gid)
    subprocess.run(['useradd', '--system', '--create-home', '--shell', '/bin/sh', 'meshdeploy'], check=True)
    account = pwd.getpwnam('meshdeploy')
    install_code()
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upgrade', action='store_true',
                        help='upgrade the controller code and configuration of an existing installation')
    parser.add_argument('--public-key', type=Path)
    parser.add_argument('--image')
    parser.add_argument('--health-url')
    parser.add_argument('--enable-fleet-update', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Administrator installation is required')
    if args.upgrade:
        if args.public_key or args.image or args.health_url or args.enable_fleet_update:
            parser.error('--upgrade keeps the installed policy; edit it in place instead of passing installation options')
        upgrade()
    else:
        if not (args.public_key and args.image and args.health_url):
            parser.error('a fresh installation requires --public-key, --image and --health-url')
        fresh_install(args)


if __name__ == '__main__':
    main()
