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


# Controller configuration schema 2 replaced the single 'meshcentral_version' value with an
# allowlist of reviewed MeshCentral versions ('reviewed_versions').
CONFIG_SCHEMA = 2
VERSION_PATTERN = r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?'
FORK_REVISION_PATTERN = r'[0-9a-f]{40}'


def validate_reviewed_versions(versions):
    if (not isinstance(versions, list) or not versions or
            not all(isinstance(version, str) and re.fullmatch(VERSION_PATTERN, version) for version in versions)):
        raise ValueError('reviewed_versions must be a non-empty list of exact MeshCentral versions, e.g. ["1.2.5"]')
    if len(set(versions)) != len(versions):
        raise ValueError('reviewed_versions lists a version more than once')
    return versions


def validate_config(config):
    if 'meshcentral_version' in config:
        raise ValueError(str(CONFIG) + ' uses the retired single meshcentral_version policy; '
                         'migrate it with "install_controller.py --upgrade" before deploying')
    if config.get('schema') != CONFIG_SCHEMA:
        raise ValueError('Unsupported release controller configuration schema: ' + repr(config.get('schema')))
    if not re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+', config['image']):
        raise ValueError('Only the configured GHCR image repository is accepted')
    if not config['health_url'].startswith('https://') or not config['health_url'].endswith('/health.ashx'):
        raise ValueError('health_url must be an HTTPS MeshCentral health.ashx endpoint')
    if not isinstance(config.get('enable_fleet_update'), bool):
        raise ValueError('Explicit enable_fleet_update policy is required')
    validate_reviewed_versions(config.get('reviewed_versions'))
    return config


def new_config(image, health_url, reviewed_version, enable_fleet_update):
    return validate_config({'schema': CONFIG_SCHEMA, 'image': image, 'health_url': health_url,
                            'reviewed_versions': [reviewed_version],
                            'enable_fleet_update': enable_fleet_update})


def migrate_config(config):
    """Return the schema-2 form of a controller configuration; schema-2 input is returned unchanged.

    The single reviewed value of a schema-1 configuration becomes the first allowlist entry,
    so every release that the old configuration accepted is still accepted.
    """
    config = dict(config)
    if 'meshcentral_version' in config:
        if 'schema' in config or 'reviewed_versions' in config:
            raise ValueError('Configuration mixes meshcentral_version with schema 2 fields; resolve it by hand')
        config['reviewed_versions'] = [config.pop('meshcentral_version')]
        config['schema'] = CONFIG_SCHEMA
    return validate_config(config)


def load_config():
    return validate_config(json.loads(CONFIG.read_text()))


def release_identity(manifest):
    """Return (packaged version, reviewed upstream version, fork revision or None).

    Manifests written before the fork carry neither identity field: their reviewed version is
    the version they recorded, and they have no fork revision.
    """
    version = manifest['meshcentral_version']
    reviewed = manifest.get('reviewedUpstreamVersion', version)
    revision = manifest.get('forkRevision')
    if not isinstance(version, str) or not re.fullmatch(VERSION_PATTERN, version):
        raise ValueError('Release manifest has an invalid meshcentral_version: ' + repr(version))
    if reviewed != version:
        raise ValueError('Release manifest was reviewed for MeshCentral ' + repr(reviewed) +
                         ' but packages MeshCentral ' + version)
    if revision is not None and (not isinstance(revision, str) or not re.fullmatch(FORK_REVISION_PATTERN, revision)):
        raise ValueError('Release manifest forkRevision must be a full lowercase git commit sha: ' + repr(revision))
    return version, reviewed, revision


def validate_manifest(directory, reviewed_versions):
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest['schema'] != 1:
        raise ValueError('Unsupported release manifest schema: ' + repr(manifest['schema']))
    _, reviewed, _ = release_identity(manifest)
    if reviewed not in validate_reviewed_versions(reviewed_versions):
        raise ValueError('MeshCentral ' + reviewed + ' is not a reviewed version (reviewed_versions: ' +
                         ', '.join(reviewed_versions) + '). Server version changes require a separately '
                         'reviewed database migration; add the version to reviewed_versions only after that review.')
    for relative, expected in manifest['files'].items():
        path = PurePosixPath(relative)
        if path.is_absolute() or '..' in path.parts or ',' in relative:
            raise ValueError('Unsafe release member')
        source = directory / relative
        release_parent = directory
        release_parent_symlink = directory.is_symlink()
        for part in path.parts[:-1]:
            release_parent /= part
            release_parent_symlink = release_parent_symlink or release_parent.is_symlink()
        if source.is_symlink() or not source.is_file() or release_parent_symlink:
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
        validate_manifest(directory / 'overrides', config['reviewed_versions'])
        return directory
    temporary = directory.with_name(directory.name + '.preparing')
    if temporary.exists():
        raise RuntimeError('Incomplete preparation exists; inspect it before retrying')
    temporary.mkdir(parents=True)
    extraction = 'meshcentral-extract-' + uuid.uuid4().hex
    try:
        run('docker', 'create', '--name', extraction, image)
        run('docker', 'cp', extraction + ':/opt/meshcentral/release-overrides', str(temporary / 'overrides'))
        validate_manifest(temporary / 'overrides', config['reviewed_versions'])
        os.replace(temporary, directory)
    finally:
        subprocess.run(['docker', 'rm', '-f', extraction], check=False, stdout=subprocess.DEVNULL)
    return directory


# Runtime agent folders: manifest role -> folder it replaces inside meshcentral-data.
AGENT_ROLES = (('data', 'agents'), ('signed', 'signedagents'))
# Never seeded into a runtime, even when a release lists them (unchanged policy).
AGENT_SEED_EXCLUDED = ('hashagents.json', 'MasterService.exe')


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def agent_seed(manifest):
    """Return {role: {name: sha256}} for the runtime agent folders, from the manifest alone."""
    seed = {role: {} for role, _ in AGENT_ROLES}
    for relative, digest in manifest['files'].items():
        role, _, name = relative.partition('/')
        if role not in seed:
            continue
        if not name or '/' in name:
            raise ValueError('Agent seed members must be direct children of their role folder: ' + relative)
        if name not in AGENT_SEED_EXCLUDED:
            seed[role][name] = digest
    return seed


def release_manifest(directory):
    return json.loads((directory / 'overrides' / 'manifest.json').read_text())


def seed_agents(directory, runtime=None):
    """Build the writable agent folders for one release from that release's manifest only.

    Nothing is copied from the incumbent installation or from another release's runtime,
    so a binary removed from a release, or deleted from the host, never comes back.
    With ``runtime`` set, that existing runtime of the same release is rebuilt in place
    (recovery reuses the previous release's runtime path).
    """
    directory = Path(directory)
    seed = agent_seed(release_manifest(directory))
    if runtime is None:
        runtime = directory / ('runtime-' + uuid.uuid4().hex)
    runtime = Path(runtime)
    if runtime.parent != directory or not runtime.name.startswith('runtime-'):
        raise ValueError('Agent runtime must be a runtime-* folder of its own release: ' + str(runtime))
    staging = runtime.with_name(runtime.name + '.seeding')
    if staging.exists():
        raise RuntimeError('Incomplete agent runtime seeding exists; inspect it before retrying: ' + str(staging))
    staging.mkdir()
    for role, files in seed.items():
        target = staging / role
        target.mkdir()
        for name, digest in files.items():
            source = directory / 'overrides' / role / name
            if source.is_symlink() or not source.is_file():
                raise ValueError('Release agent seed member is not a regular file: ' + role + '/' + name)
            shutil.copyfile(source, target / name)
            if file_sha256(target / name) != digest:
                raise ValueError('Release agent seed member digest mismatch: ' + role + '/' + name)
    user = pwd.getpwnam('meshcentral')
    for path in [staging, *staging.rglob('*')]:
        os.chown(path, user.pw_uid, user.pw_gid)
    if runtime.is_symlink():
        raise ValueError('Agent runtime is a symlink: ' + str(runtime))
    if runtime.exists():
        # The release's own manifest is the only source; server-written state is regenerated.
        shutil.rmtree(runtime)
    os.replace(staging, runtime)
    return runtime


def verify_agent_runtime(directory, runtime):
    """Fail unless the runtime holds exactly the release's manifest agent files."""
    seed = agent_seed(release_manifest(Path(directory)))
    runtime = Path(runtime)
    problems = []
    if runtime.is_symlink() or not runtime.is_dir():
        raise ValueError('Agent runtime is missing or not a directory: ' + str(runtime))
    for role, files in seed.items():
        folder = runtime / role
        if folder.is_symlink() or not folder.is_dir():
            problems.append(role + '/: missing or not a directory')
            continue
        present = set()
        for path in sorted(folder.rglob('*')):
            relative = path.relative_to(runtime).as_posix()
            if path.is_symlink():
                problems.append(relative + ': symbolic link')
            elif path.is_dir():
                problems.append(relative + ': unexpected directory')
            elif path.parent != folder or path.name not in files:
                problems.append(relative + ': not in the release manifest')
            else:
                present.add(path.name)
                if file_sha256(path) != files[path.name]:
                    problems.append(relative + ': sha256 differs from the release manifest')
        for name in sorted(set(files) - present):
            problems.append(role + '/' + name + ': listed in the release manifest but missing')
    if problems:
        raise ValueError('Agent runtime does not match its release manifest (' + str(runtime) + '):\n  ' +
                         '\n  '.join(problems))


def start(config, release):
    directory = Path(release['directory'])
    manifest = validate_manifest(directory / 'overrides', config['reviewed_versions'])
    verify_agent_runtime(directory, release['runtime'])
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
        # Rebuild the previous runtime from its own manifest; state written while it ran
        # (or planted since) is discarded rather than carried into the recovered service.
        seed_agents(Path(previous['directory']), Path(previous['runtime']))
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
    runtime = seed_agents(directory)
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
