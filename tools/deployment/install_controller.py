#!/usr/bin/env python3
"""Install the release controller and restricted SSH account without switching services."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess


def install(source, destination, mode):
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Normalize source checkout line endings before installing executable scripts.
    destination.write_text(source.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
    os.chown(destination, 0, 0)
    destination.chmod(mode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--health-url', required=True)
    parser.add_argument('--enable-fleet-update', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Administrator installation is required')
    if not re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+', args.image):
        raise ValueError('Invalid GHCR repository')
    if not args.health_url.startswith('https://') or not args.health_url.endswith('/health.ashx'):
        raise ValueError('Use the public HTTPS health.ashx endpoint')
    public_key = args.public_key.read_text().strip()
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?', public_key):
        raise ValueError('Provide one dedicated Ed25519 public key')
    subprocess.run(['docker', 'info'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'is-active', '--quiet', 'meshcentral'], check=True)
    package = Path('/opt/meshcentral/node_modules/meshcentral/package.json')
    version = json.loads(package.read_text())['version']
    service_account = pwd.getpwnam('meshcentral')
    mitigation = Path('/opt/meshcentral/bin/harden-image-size.js')
    if not mitigation.is_file():
        raise ValueError('Inspect the existing production mitigation before installing')
    config = Path('/etc/meshcentral-deploy.json')
    if config.exists():
        raise ValueError('Controller already configured; review changes in place instead of overwriting policy')
    try:
        account = pwd.getpwnam('meshdeploy')
    except KeyError:
        account = None
    if account is not None:
        raise ValueError('meshdeploy already exists; inspect its ownership and access before installation')
    for destination in ('/etc/sudoers.d/meshcentral-deploy', '/usr/local/libexec/meshcentral-release',
                        '/usr/local/sbin/meshcentral-ci-entry'):
        if Path(destination).exists():
            raise ValueError('Existing controller file requires operator review: ' + destination)
    source = Path(__file__).resolve().parent
    for name in ('release_manager.py', 'ci_entry.py'):
        if not (source / name).is_file():
            raise ValueError('Missing controller source: ' + name)
    for name in ('meshcentral-files', 'meshcentral-web', 'meshcentral-recordings', 'meshcentral-backups'):
        directory = Path('/opt/meshcentral') / name
        if not directory.exists():
            directory.mkdir(mode=0o750)
            os.chown(directory, service_account.pw_uid, service_account.pw_gid)
    subprocess.run(['useradd', '--system', '--create-home', '--shell', '/bin/sh', 'meshdeploy'], check=True)
    account = pwd.getpwnam('meshdeploy')
    install(source / 'release_manager.py', Path('/usr/local/libexec/meshcentral-release'), 0o755)
    install(source / 'ci_entry.py', Path('/usr/local/sbin/meshcentral-ci-entry'), 0o755)
    sudoers = Path('/etc/sudoers.d/meshcentral-deploy')
    sudoers.write_text('meshdeploy ALL=(root) NOPASSWD: /usr/local/sbin/meshcentral-ci-entry\n')
    sudoers.chmod(0o440)
    subprocess.run(['visudo', '-cf', str(sudoers)], check=True)
    ssh = Path(account.pw_dir) / '.ssh'
    ssh.mkdir(mode=0o700, exist_ok=True)
    authorized = ssh / 'authorized_keys'
    if authorized.exists():
        raise ValueError('Dedicated account already has keys; inspect before replacing them')
    authorized.write_text(r'restrict,command="sudo -n /usr/local/sbin/meshcentral-ci-entry \"$SSH_ORIGINAL_COMMAND\"" ' + public_key + '\n')
    authorized.chmod(0o600)
    for path in (ssh, authorized):
        os.chown(path, account.pw_uid, account.pw_gid)
    config.write_text(json.dumps({'image': args.image, 'health_url': args.health_url,
                                 'meshcentral_version': version,
                                 'enable_fleet_update': args.enable_fleet_update}, indent=2) + '\n')
    config.chmod(0o600)
    print('Controller installed. Existing MeshCentral is still running under systemd.')
    print('Review GitHub environment/registry access before the first digest promotion.')


if __name__ == '__main__':
    main()
