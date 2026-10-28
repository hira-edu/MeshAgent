#!/usr/bin/env python3
"""Root-owned VPS release controller. Install once; CI may submit only image digests.

The controller runs in a systemd unit so loss of SSH does not interrupt promotion.
Persistent application data is never replaced or restored by an image rollback.

A release image is the fork package installed from its tarball and nothing else (Stage 4, D11): it
carries one release manifest (/opt/meshcentral/release/manifest.json) and no overlay files, mounts
or agent folders. Agents are served from the package, verified against agents/agent-defaults.json.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

# The shadow-copy check is installed beside the controller (install_controller.CODE).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import meshcentral_shadow_check  # noqa: E402

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
# allowlist of reviewed MeshCentral versions ('reviewed_versions'). Schema 3 retired the image-size
# preload and its 'image_size_mitigation_sha256' (the fork no longer installs image-size).
CONFIG_SCHEMA = 3
RETIRED_MITIGATION_KEY = 'image_size_mitigation_sha256'
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
    if RETIRED_MITIGATION_KEY in config:
        # Refused, not ignored: the key records the image-size preload policy this controller no longer
        # applies, so the operator acknowledges the change through the one reviewed migration path.
        raise ValueError(str(CONFIG) + ' still sets ' + RETIRED_MITIGATION_KEY + ' (the retired image-size '
                         'preload); migrate it with "install_controller.py --upgrade" before deploying')
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
    """Return the current (schema 3) form of a controller configuration.

    Schema 1: the single reviewed value becomes the first allowlist entry, so every release the
    old configuration accepted is still accepted. Schema 2: the retired image-size mitigation
    digest is removed. Other settings are kept unchanged.
    """
    config = dict(config)
    if 'meshcentral_version' in config:
        if 'schema' in config or 'reviewed_versions' in config:
            raise ValueError('Configuration mixes meshcentral_version with schema 2 fields; resolve it by hand')
        config['reviewed_versions'] = [config.pop('meshcentral_version')]
    elif config.get('schema') not in (2, CONFIG_SCHEMA):
        raise ValueError('Unsupported release controller configuration schema: ' + repr(config.get('schema')))
    config.pop(RETIRED_MITIGATION_KEY, None)
    config['schema'] = CONFIG_SCHEMA
    return validate_config(config)


def load_config():
    return validate_config(json.loads(CONFIG.read_text()))


def release_identity(manifest):
    """Return (packaged version, reviewed upstream version, fork revision) of a release manifest."""
    version = manifest.get('meshcentral_version')
    reviewed = manifest.get('reviewedUpstreamVersion')
    revision = manifest.get('forkRevision')
    if not isinstance(version, str) or not re.fullmatch(VERSION_PATTERN, version):
        raise ValueError('Release manifest has an invalid meshcentral_version: ' + repr(version))
    if reviewed != version:
        raise ValueError('Release manifest was reviewed for MeshCentral ' + repr(reviewed) +
                         ' but packages MeshCentral ' + version)
    if not isinstance(revision, str) or not re.fullmatch(FORK_REVISION_PATTERN, revision):
        raise ValueError('Release manifest forkRevision must be a full lowercase git commit sha: ' + repr(revision))
    return version, reviewed, revision


# The image path of the release manifest, and the folder prepare() copies it into.
IMAGE_RELEASE = '/opt/meshcentral/release'
RELEASE_FOLDER = 'release'
MANIFEST_SCHEMA = 2
MANIFEST_FIELDS = {'schema', 'meshcentral_version', 'reviewedUpstreamVersion', 'forkRevision', 'package',
                   'agentBuild', 'agentBinaries', 'agentCoreHashes', 'shadowAllowlist'}
# Fields of the retired overlay release (schema 1): mapped files, their mounts and seeded agent folders.
OVERLAY_FIELDS = ('files', 'mounts')


def validate_manifest(directory, reviewed_versions):
    """Validate the release folder copied out of an image and return its manifest.

    Only tarball releases (schema 2) are accepted. Overlay releases, which mounted mapped code over
    the data and web folders and seeded agent folders (DEP-22, DEP-25), are refused.
    """
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Release folder is missing or not a directory: ' + str(directory))
    entries = sorted(path.name for path in directory.iterdir())
    if entries != ['manifest.json'] or (directory / 'manifest.json').is_symlink() or \
            not (directory / 'manifest.json').is_file():
        raise ValueError('Release folder must hold only a regular manifest.json, found: ' + ', '.join(entries))
    manifest = json.loads((directory / 'manifest.json').read_text())
    if not isinstance(manifest, dict):
        raise ValueError('Release manifest is not a JSON object')
    overlays = [field for field in OVERLAY_FIELDS if field in manifest]
    if manifest.get('schema') == 1 or overlays:
        raise ValueError('Overlay release refused: the manifest carries ' + (', '.join(overlays) or 'schema 1') +
                         '. Releases are built from the fork tarball only and mount nothing over '
                         'meshcentral-data or meshcentral-web.')
    if manifest.get('schema') != MANIFEST_SCHEMA:
        raise ValueError('Unsupported release manifest schema: ' + repr(manifest.get('schema')))
    if set(manifest) != MANIFEST_FIELDS:
        raise ValueError('Release manifest fields differ from schema 2: missing ' +
                         repr(sorted(MANIFEST_FIELDS - set(manifest))) + ', unknown ' +
                         repr(sorted(set(manifest) - MANIFEST_FIELDS)))
    _, reviewed, _ = release_identity(manifest)
    if reviewed not in validate_reviewed_versions(reviewed_versions):
        raise ValueError('MeshCentral ' + reviewed + ' is not a reviewed version (reviewed_versions: ' +
                         ', '.join(reviewed_versions) + '). Server version changes require a separately '
                         'reviewed database migration; add the version to reviewed_versions only after that review.')
    # Fail at preparation, not at start, when the release's shadow allowlist is malformed.
    meshcentral_shadow_check.parse_allowlist(manifest['shadowAllowlist'])
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
        validate_manifest(directory / RELEASE_FOLDER, config['reviewed_versions'])
        return directory
    temporary = directory.with_name(directory.name + '.preparing')
    if temporary.exists():
        raise RuntimeError('Incomplete preparation exists; inspect it before retrying')
    temporary.mkdir(parents=True)
    extraction = 'meshcentral-extract-' + uuid.uuid4().hex
    try:
        run('docker', 'create', '--name', extraction, image)
        run('docker', 'cp', extraction + ':' + IMAGE_RELEASE, str(temporary / RELEASE_FOLDER))
        validate_manifest(temporary / RELEASE_FOLDER, config['reviewed_versions'])
        os.replace(temporary, directory)
    finally:
        subprocess.run(['docker', 'rm', '-f', extraction], check=False, stdout=subprocess.DEVNULL)
    return directory


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def release_manifest(release):
    return json.loads((Path(release['directory']) / RELEASE_FOLDER / 'manifest.json').read_text())


def check_shadow_copies(manifest):
    """G4: fail unless every file that would shadow the package is allowlisted by this release.

    The container mounts the host's meshcentral-data and meshcentral-web unchanged, so the host
    folders are exactly what the server will see.
    """
    meshcentral_shadow_check.check(BASE, meshcentral_shadow_check.parse_allowlist(manifest['shadowAllowlist']))


def start(config, release):
    manifest = validate_manifest(Path(release['directory']) / RELEASE_FOLDER, config['reviewed_versions'])
    # Runs at every start, including recovery and rollback, so data/web copies placed since the
    # release was promoted are refused rather than trusted.
    check_shadow_copies(manifest)
    user = pwd.getpwnam('meshcentral')
    args = ['docker', 'run', '--detach', '--name', CONTAINER, '--restart', 'unless-stopped',
            '--network', 'host', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--user', f'{user.pw_uid}:{user.pw_gid}',
            '--init', '--stop-timeout', '60', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--log-driver', 'local', '--log-opt', 'max-size=20m', '--log-opt', 'max-file=5']
    def mount(source, target, readonly=False):
        args.extend(['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')])
    # Only the persistent folders: the code, its agents and its cores come from the image's package.
    for name in ('meshcentral-data', 'meshcentral-files', 'meshcentral-web',
                 'meshcentral-recordings', 'meshcentral-backups'):
        mount(BASE / name, BASE / name, name == 'meshcentral-web')
    # No NODE_OPTIONS: the release image does not install image-size, so nothing is preloaded.
    args.append(config['image'] + '@' + release['digest'])
    run(*args)


# The host service's image-size preload (DEP-21), installed before the fork release. The 1.2.5 host
# installation needs it for as long as it is the rollback target of an interrupted first migration, so
# it is retired only after a container release has been promoted, and kept for the manual return to it.
LEGACY_PRELOAD = (Path('/opt/meshcentral/bin/harden-image-size.js'),
                  Path('/etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf'))
RETIRED_PRELOAD = 'retired-host-preload'


def check_legacy_preload():
    """Refuse before anything changes when a legacy preload path is not a regular file."""
    for path in LEGACY_PRELOAD:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError('The legacy image-size preload ' + str(path) + ' is not a regular file; '
                             'inspect it and remove it by hand before deploying')


def retire_legacy_preload():
    """Move the legacy host preload into the controller state, naming each file. Returns the moved paths.

    Runs after every successful promotion; a host without the preload is left unchanged.
    """
    present = [path for path in LEGACY_PRELOAD if path.is_symlink() or path.exists()]
    if not present:
        return []
    check_legacy_preload()
    archive = STATE / RETIRED_PRELOAD / time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    archive.mkdir(mode=0o700, parents=True)
    for path in present:
        digest = file_sha256(path)
        shutil.move(str(path), str(archive / path.name))
        print('Retired the legacy image-size preload: moved ' + str(path) + ' (sha256 ' + digest + ') to ' +
              str(archive / path.name))
    sync_directory(archive)
    if LEGACY_PRELOAD[1] in present:
        run('systemctl', 'daemon-reload')
    return present


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
        # The retained host installation has no release manifest. Its explicit allowlist is the
        # snapshot promote() recorded while that service was healthy, before stopping it; anything
        # added or changed since (for example a candidate mount's placeholder file) blocks the restart.
        allowlist = transaction.get('host_shadow_allowlist')
        if allowlist is None:
            raise RuntimeError('Not restoring the host MeshCentral service: this transaction has no record of the '
                               'host shadow copies (written by an older controller). Operator action is needed: '
                               'inspect meshcentral-data and meshcentral-web, then start the meshcentral service '
                               'by hand. The transaction is retained.')
        try:
            meshcentral_shadow_check.check(BASE, allowlist, allow_missing=True)
        except meshcentral_shadow_check.ShadowCopyError as error:
            raise meshcentral_shadow_check.ShadowCopyError(
                'Not restoring the host MeshCentral service: its data or web folders changed after the promotion '
                'stopped it. Operator action is needed; the transaction is retained.\n' + str(error)) from error
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
    release = {'digest': digest, 'directory': str(directory)}
    check_legacy_preload()
    # The same shadow check start() runs, before anything is stopped: a host that the candidate would
    # refuse is reported without an outage.
    check_shadow_copies(release_manifest(release))
    # First migration: record the healthy host installation's shadow copies, the explicit allowlist
    # recover() checks before restarting the host service. Refuses before anything is stopped.
    host_allowlist = None if previous else meshcentral_shadow_check.snapshot(BASE)
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
    if not previous:
        transaction['host_shadow_allowlist'] = host_allowlist
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
    # After the commit: a failure here leaves the promoted release running and is reported, not rolled back.
    try:
        retire_legacy_preload()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise RuntimeError('Promoted ' + digest + ', but retiring the legacy image-size preload failed: ' +
                           str(error) + '. Move ' + ' and '.join(str(path) for path in LEGACY_PRELOAD) +
                           ' out by hand and run systemctl daemon-reload.') from error


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
