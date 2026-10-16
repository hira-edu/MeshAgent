#!/usr/bin/env python3
"""Root-owned VPS release controller. Install once; CI may submit only image digests.

The controller runs in a systemd unit so loss of SSH does not interrupt promotion.
Persistent application data is never replaced or restored by an image rollback.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
import uuid

BASE = Path('/opt/meshcentral')
STATE = Path('/var/lib/meshcentral-deploy')
CONFIG = Path('/etc/meshcentral-deploy.json')
CONTAINER = 'meshcentral-production'


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None,
                          timeout=900).stdout


def sync_directory(directory):
    if hasattr(os, 'O_DIRECTORY'):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_json(path, data):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def validate_digest(value):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise ValueError('An immutable sha256 image digest is required')
    return value


def load_config():
    config = json.loads(CONFIG.read_text())
    if not re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+', config['image']):
        raise ValueError('Only the configured GHCR image repository is accepted')
    if not config['health_url'].startswith('https://') or not config['health_url'].endswith('/health.ashx'):
        raise ValueError('health_url must be an HTTPS MeshCentral health.ashx endpoint')
    if not isinstance(config.get('enable_fleet_update'), bool):
        raise ValueError('Explicit enable_fleet_update policy is required')
    return config


def validate_manifest(directory, expected_version):
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest['schema'] != 1 or manifest['meshcentral_version'] != expected_version:
        raise ValueError('Server version changes require a separately reviewed database migration')
    for relative, expected in manifest['files'].items():
        path = PurePosixPath(relative)
        if path.is_absolute() or '..' in path.parts or ',' in relative:
            raise ValueError('Unsafe release member')
        source = directory / relative
        if source.is_symlink() or not source.is_file() or any(p.is_symlink() for p in source.parents):
            raise ValueError('Release members must be regular files')
        with source.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('Release content digest mismatch')
    targets = set()
    for mount in manifest['mounts']:
        source, target = mount['source'], mount['target']
        if source not in manifest['files'] or target in targets:
            raise ValueError('Invalid or duplicate release mount')
        role, relative = source.split('/', 1)
        roots = {'data-core': str(BASE / 'meshcentral-data'),
                 'data-plugin': str(BASE / 'meshcentral-data/plugins'),
                 'web-public': str(BASE / 'meshcentral-web/public')}
        if role not in roots or target != roots[role] + '/' + relative:
            raise ValueError('Release mount outside approved roots')
        if role == 'data-core' and not (relative in ('meshcore.js', 'meshcore.min.js', 'recoverycore.js') or
                                        relative.startswith(('modules_meshcore/', 'modules_meshcore_min/'))):
            raise ValueError('Release cannot replace persistent configuration or identities')
        if role == 'data-plugin' and not relative.startswith('nativeruntime/'):
            raise ValueError('Unapproved plugin mount')
        if role == 'web-public' and not relative.startswith('scripts/'):
            raise ValueError('Unapproved web mount')
        targets.add(target)
    return manifest


def inspect_container():
    result = subprocess.run(['docker', 'inspect', CONTAINER], capture_output=True, text=True, timeout=30)
    if result.returncode:
        return None
    return json.loads(result.stdout)[0]


def healthy(config, digest=None, attempts=24):
    for attempt in range(attempts):
        service_ok = False
        if digest:
            info = inspect_container()
            service_ok = bool(info and info['State']['Running'] and
                              info['Config']['Image'] == config['image'] + '@' + digest)
        else:
            service_ok = subprocess.run(['systemctl', 'is-active', '--quiet', 'meshcentral']).returncode == 0
        try:
            # Non-cacheable request, exact status/body, CA/hostname verification enabled.
            url = config['health_url'] + '?release_probe=' + uuid.uuid4().hex
            request = urllib.request.Request(url, headers={'Cache-Control': 'no-cache, no-store'})
            with urllib.request.urlopen(request, timeout=10) as response:
                if service_ok and response.status == 200 and response.url == url and response.read(32) == b'ok':
                    return True
        except (OSError, ValueError):
            pass
        if attempt + 1 < attempts:
            time.sleep(5)
    return False


def prepare(config, digest):
    image = config['image'] + '@' + digest
    # Retained immutable images permit rollback without a live registry token.
    cached = subprocess.run(['docker', 'image', 'inspect', image], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=30).returncode == 0
    if not cached:
        credential_directory = os.environ.get('CREDENTIALS_DIRECTORY')
        if not credential_directory:
            raise ValueError('A short-lived GHCR job credential is required to pull a new image')
        credentials = json.loads((Path(credential_directory) / 'ghcr').read_text())
        with tempfile.TemporaryDirectory(prefix='meshcentral-registry-') as directory:
            subprocess.run(['docker', '--config', directory, 'login', 'ghcr.io',
                            '--username', credentials['username'], '--password-stdin'],
                           input=credentials['token'], text=True, check=True,
                           stdout=subprocess.DEVNULL, timeout=60)
            run('docker', '--config', directory, 'pull', image)
    directory = STATE / 'releases' / digest.split(':')[1]
    if directory.exists():
        validate_manifest(directory / 'overrides', config['meshcentral_version'])
        return directory
    temporary = directory.with_name(directory.name + '.preparing')
    if temporary.exists():
        raise RuntimeError('Incomplete preparation exists; inspect it before retrying')
    temporary.mkdir(parents=True)
    extraction = 'meshcentral-extract-' + uuid.uuid4().hex
    try:
        run('docker', 'create', '--name', extraction, image)
        run('docker', 'cp', extraction + ':/opt/meshcentral/release-overrides', str(temporary / 'overrides'))
        validate_manifest(temporary / 'overrides', config['meshcentral_version'])
        os.replace(temporary, directory)
    finally:
        subprocess.run(['docker', 'rm', '-f', extraction], check=False, stdout=subprocess.DEVNULL)
    return directory


def seed_agents(directory, previous):
    # A fresh copy per promotion avoids reusing a signed cache for a different image.
    # Preserve macOS/Linux payloads published by their separate platform pipelines.
    state = directory / ('runtime-' + uuid.uuid4().hex)
    state.mkdir()
    for role, live in (('data', 'agents'), ('signed', 'signedagents')):
        source = Path(previous['runtime']) / role if previous else BASE / 'meshcentral-data' / live
        target = state / role
        if source.exists():
            if source.is_symlink() or any(path.is_symlink() for path in source.rglob('*')):
                raise ValueError('Symlink in incumbent agent runtime state')
            shutil.copytree(source, target)
        else:
            target.mkdir()
        for path in (directory / 'overrides' / role).iterdir():
            shutil.copyfile(path, target / path.name)
        for name in ('hashagents.json', 'MasterService.exe'):
            (target / name).unlink(missing_ok=True)
    user = pwd.getpwnam('meshcentral')
    for path in [state, *state.rglob('*')]:
        if path.is_symlink():
            raise ValueError('Symlink in agent runtime state')
        os.chown(path, user.pw_uid, user.pw_gid)
    return state


def start(config, release):
    directory = Path(release['directory'])
    manifest = validate_manifest(directory / 'overrides', config['meshcentral_version'])
    user = pwd.getpwnam('meshcentral')
    args = ['docker', 'run', '--detach', '--name', CONTAINER, '--restart', 'unless-stopped',
            '--network', 'host', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--user', f'{user.pw_uid}:{user.pw_gid}',
            '--init', '--stop-timeout', '60', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--log-driver', 'local', '--log-opt', 'max-size=20m', '--log-opt', 'max-file=5']
    def mount(source, target, readonly=False):
        args.extend(['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')])
    for name in ('meshcentral-data', 'meshcentral-files', 'meshcentral-web',
                 'meshcentral-recordings', 'meshcentral-backups'):
        mount(BASE / name, BASE / name, name == 'meshcentral-web')
    for role, name in (('data', 'agents'), ('signed', 'signedagents')):
        mount(Path(release['runtime']) / role, BASE / 'meshcentral-data' / name, role == 'data')
    for item in manifest['mounts']:
        mount(directory / 'overrides' / item['source'], item['target'], True)
    # Preserve the existing production image-size mitigation across the migration.
    mitigation = BASE / 'bin/harden-image-size.js'
    if not mitigation.is_file():
        raise ValueError('Required production image-size mitigation is missing')
    mount(mitigation, mitigation, True)
    args.extend(['--env', 'NODE_OPTIONS=--require=' + str(mitigation)])
    args.append(config['image'] + '@' + release['digest'])
    run(*args)


def remove_container():
    if inspect_container() is not None:
        run('docker', 'stop', '--time', '60', CONTAINER)
        run('docker', 'rm', CONTAINER)


def apply_fleet_policy(enabled):
    path = BASE / 'meshcentral-data/config.json'
    data = json.loads(path.read_text())
    settings = data.setdefault('settings', {})
    for key in list(settings):
        if key.lower() == 'noagentupdate':
            del settings[key]
    settings['noagentupdate'] = not enabled
    # Keep the incumbent file owner and mode. Credentials never enter release metadata.
    temporary = path.with_suffix('.fleet-tmp')
    shutil.copy2(path, temporary)
    stat = path.stat()
    os.chown(temporary, stat.st_uid, stat.st_gid)
    with temporary.open('w') as stream:
        json.dump(data, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def recover(config, transaction):
    remove_container()
    config_backup = Path(transaction['config_backup'])
    # A promotion is serialized; configuration editing must use the same maintenance lock.
    path = BASE / 'meshcentral-data/config.json'
    temporary = path.with_suffix('.recovery-tmp')
    with temporary.open('wb') as stream:
        stream.write(config_backup.read_bytes())
        stream.flush()
        os.fsync(stream.fileno())
    metadata = transaction['config_metadata']
    os.chown(temporary, metadata['uid'], metadata['gid'])
    temporary.chmod(metadata['mode'])
    os.replace(temporary, path)
    sync_directory(path.parent)
    previous = transaction['previous']
    if previous:
        start(config, previous)
    else:
        run('systemctl', 'enable', '--now', 'meshcentral')
    if not healthy(config, previous['digest'] if previous else None):
        raise RuntimeError('Recovery health failed; transaction retained for operator recovery')
    atomic_json(STATE / 'active.json', previous)
    (STATE / 'transaction.json').unlink()
    sync_directory(STATE)


def promote(config, digest):
    active_path = STATE / 'active.json'
    previous = json.loads(active_path.read_text()) if active_path.exists() else None
    journal = STATE / 'transaction.json'
    if journal.exists():
        raise RuntimeError('An interrupted transaction exists. Run recover before another deployment.')
    if previous and previous['digest'] == digest:
        if not healthy(config, digest):
            raise RuntimeError('Active release is unhealthy')
        print('Requested digest is already active')
        return
    if not healthy(config, previous['digest'] if previous else None, attempts=1):
        raise RuntimeError('Current production service is unhealthy; refusing promotion')
    directory = prepare(config, digest)
    runtime = seed_agents(directory, previous)
    release = {'digest': digest, 'directory': str(directory), 'runtime': str(runtime)}
    backup = STATE / ('config-' + uuid.uuid4().hex + '.json')
    config_path = BASE / 'meshcentral-data/config.json'
    metadata = config_path.stat()
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    with backup.open('r+b') as stream:
        os.fsync(stream.fileno())
    transaction = {'previous': previous, 'candidate': release, 'config_backup': str(backup),
                   'config_metadata': {'uid': metadata.st_uid, 'gid': metadata.st_gid,
                                       'mode': metadata.st_mode & 0o777}}
    atomic_json(journal, transaction)
    try:
        if previous:
            remove_container()
        else:
            # Retain the host installation for first-migration rollback.
            run('systemctl', 'disable', '--now', 'meshcentral')
        apply_fleet_policy(config['enable_fleet_update'])
        start(config, release)
        if not healthy(config, digest):
            raise RuntimeError('Candidate failed service and HTTPS readiness checks')
        atomic_json(active_path, release)
        atomic_json(STATE / 'previous.json', previous)
        journal.unlink()
        sync_directory(STATE)
        print('Promoted ' + digest)
    except BaseException:
        recover(config, transaction)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('deploy', 'recover', 'rollback', 'status'))
    parser.add_argument('digest', nargs='?')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run through the installed root-owned systemd release controller')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config = load_config()
        if args.command == 'deploy':
            promote(config, validate_digest(args.digest or ''))
        elif args.command == 'recover':
            recover(config, json.loads((STATE / 'transaction.json').read_text()))
        elif args.command == 'rollback':
            previous = json.loads((STATE / 'previous.json').read_text())
            if not previous:
                raise ValueError('First migration rollback requires the retained host-service recovery procedure')
            promote(config, validate_digest(previous['digest']))
        else:
            print((STATE / 'active.json').read_text() if (STATE / 'active.json').exists() else 'null')


if __name__ == '__main__':
    main()
