#!/usr/bin/env python3
"""Root-owned VPS release controller. Install once; CI may submit only image digests.

The controller runs in a systemd unit so loss of SSH does not interrupt promotion.
Persistent application data is never replaced or restored by an image rollback.

A release image is the fork package installed from its tarball and nothing else (Stage 4, D11): it
carries one release manifest (/opt/meshcentral/release/manifest.json) and no overlay files, mounts
or agent folders. Agents are served from the package, verified against agents/agent-defaults.json.

One controller serves two independent server instances on the same host (INSTANCES): production
(the default; its paths, container and argv are those of the first release) and preview
(preview.high.support). A process serves exactly one instance, selected by --instance before
anything else runs (activate); each instance has its own install root, state, lock, controller
configuration, container, service account and health URL, and every mismatch between them is refused.
"""
import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
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


@dataclass(frozen=True)
class Instance:
    """One server instance the controller deploys. Paths are host paths."""
    name: str
    base: Path            # host folder holding meshcentral-data, -files, -web, -recordings, -backups
    state: Path           # releases, active/previous/transaction records, the lock
    config: Path          # controller configuration
    container: str
    account: str          # service account the container runs as
    host_service: str | None  # the retained pre-container systemd service (first migration), if any
    mount_root: PurePosixPath | None  # container folder the persistent folders are mounted under; None: their host path
    health_url: str | None  # fixed public health URL, or None when the configuration names it
    web_port: int         # MeshCentral settings.port (127.0.0.1, behind Caddy)
    mps_port: int         # MeshCentral settings.mpsport
    database: str         # MongoDB database (settings.mongodbname)
    server_host: str | None  # the public host of the instance's server and agents, when fixed here
    distinct_from: tuple  # instances whose certificates and keys this instance must never hold


# The image's install root: MeshCentral derives every default path from it (meshcentral.js:89-101).
IMAGE_ROOT = PurePosixPath('/opt/meshcentral')
INSTANCES = {
    'production': Instance('production', Path('/opt/meshcentral'), Path('/var/lib/meshcentral-deploy'),
                           Path('/etc/meshcentral-deploy.json'), 'meshcentral-production', 'meshcentral',
                           'meshcentral', None, None, 4430, 4433, 'meshcentral', None, ()),
    'preview': Instance('preview', Path('/opt/meshcentral-preview'), Path('/var/lib/meshcentral-deploy-preview'),
                        Path('/etc/meshcentral-deploy-preview.json'), 'meshcentral-preview', 'meshcentral-preview',
                        None, IMAGE_ROOT, 'https://preview.high.support/health.ashx', 4440, 4441,
                        'meshcentral_preview', 'preview.high.support', ('production',)),
}
# Docker label naming the instance a container was started for.
INSTANCE_LABEL = 'meshcentral-release.instance'

# The active instance (activate() selects it). Production by default.
INSTANCE = INSTANCES['production']
BASE = INSTANCE.base
STATE = INSTANCE.state
CONFIG = INSTANCE.config
CONTAINER = INSTANCE.container
SERVICE_ACCOUNT = INSTANCE.account
HOST_SERVICE = INSTANCE.host_service
MOUNT_ROOT = INSTANCE.mount_root


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


def validate_config(config, instance=None):
    """Validate a controller configuration for ``instance`` (a name; default: the active instance).

    The configuration names its instance ("instance"; absent means production, the form every production
    configuration has had), and a configuration of another instance is refused.
    """
    instance = INSTANCES[instance] if instance else INSTANCE
    path = CONFIG if instance is INSTANCE else instance.config
    named = config.get('instance', 'production')
    if named != instance.name:
        raise ValueError(str(path) + ' is the controller configuration of instance ' + repr(named) + ', not ' +
                         instance.name + '; refusing to use it')
    if 'meshcentral_version' in config:
        raise ValueError(str(path) + ' uses the retired single meshcentral_version policy; '
                         'migrate it with "install_controller.py --upgrade" before deploying')
    if RETIRED_MITIGATION_KEY in config:
        # Refused, not ignored: the key records the image-size preload policy this controller no longer
        # applies, so the operator acknowledges the change through the one reviewed migration path.
        raise ValueError(str(path) + ' still sets ' + RETIRED_MITIGATION_KEY + ' (the retired image-size '
                         'preload); migrate it with "install_controller.py --upgrade" before deploying')
    if config.get('schema') != CONFIG_SCHEMA:
        raise ValueError('Unsupported release controller configuration schema: ' + repr(config.get('schema')))
    if not re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+', config['image']):
        raise ValueError('Only the configured GHCR image repository is accepted')
    if not config['health_url'].startswith('https://') or not config['health_url'].endswith('/health.ashx'):
        raise ValueError('health_url must be an HTTPS MeshCentral health.ashx endpoint')
    if instance.health_url and config['health_url'] != instance.health_url:
        raise ValueError('The ' + instance.name + ' health_url must be ' + instance.health_url)
    for other in INSTANCES.values():
        if other is not instance and other.health_url and config['health_url'] == other.health_url:
            raise ValueError('health_url ' + config['health_url'] + ' belongs to the ' + other.name +
                             ' instance; the ' + instance.name + ' instance must probe its own server')
    if not isinstance(config.get('enable_fleet_update'), bool):
        raise ValueError('Explicit enable_fleet_update policy is required')
    validate_reviewed_versions(config.get('reviewed_versions'))
    return config


def new_config(image, health_url, reviewed_version, enable_fleet_update):
    return validate_config({'schema': CONFIG_SCHEMA, 'image': image, 'health_url': health_url,
                            'reviewed_versions': [reviewed_version],
                            'enable_fleet_update': enable_fleet_update})


def new_instance_config(instance, image, reviewed_versions, enable_fleet_update):
    """A configuration for a non-production instance: it names the instance and its fixed health URL."""
    definition = INSTANCES[instance]
    return validate_config({'schema': CONFIG_SCHEMA, 'instance': definition.name, 'image': image,
                            'health_url': definition.health_url, 'reviewed_versions': list(reviewed_versions),
                            'enable_fleet_update': enable_fleet_update}, definition.name)


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
    if not CONFIG.is_file():
        raise ValueError('No controller configuration for the ' + INSTANCE.name + ' instance at ' + str(CONFIG) +
                         '; install it with install_controller.py' +
                         ('' if INSTANCE.name == 'production' else ' --instance ' + INSTANCE.name))
    return validate_config(json.loads(CONFIG.read_text()))


def activate(name):
    """Select the instance this process serves. Called once, before anything else runs."""
    global INSTANCE, BASE, STATE, CONFIG, CONTAINER, SERVICE_ACCOUNT, HOST_SERVICE, MOUNT_ROOT, LEGACY_PRELOAD
    if name not in INSTANCES:
        raise ValueError('Unknown instance ' + repr(name) + '; expected one of ' + ', '.join(sorted(INSTANCES)))
    INSTANCE = INSTANCES[name]
    BASE, STATE, CONFIG = INSTANCE.base, INSTANCE.state, INSTANCE.config
    CONTAINER, SERVICE_ACCOUNT = INSTANCE.container, INSTANCE.account
    HOST_SERVICE, MOUNT_ROOT = INSTANCE.host_service, INSTANCE.mount_root
    # The image-size preload belongs to the production host service; no other instance has one.
    LEGACY_PRELOAD = HOST_PRELOAD if HOST_SERVICE else ()
    return INSTANCE


def container_root():
    """The container folder the persistent folders are mounted under (production: their own host paths)."""
    return MOUNT_ROOT if MOUNT_ROOT is not None else BASE


def _overlaps(first, second):
    return first == second or first in second.parents or second in first.parents


def check_instance_isolation():
    """Refuse when the active instance's host paths are, contain or lie inside another instance's.

    Symbolic links are resolved, so a preview folder linked to production's is refused. Each mounted
    folder is checked too, since the container writes through it.
    """
    problems = []
    mine = [('install root', BASE), ('state directory', STATE), ('controller configuration', CONFIG)]
    mine += [('mounted folder', BASE / name) for name in MOUNTED_FOLDERS]
    for other in INSTANCES.values():
        if other.name == INSTANCE.name:
            continue
        theirs = (('install root', other.base), ('state directory', other.state),
                  ('controller configuration', other.config))
        for label, path in mine:
            resolved = Path(path).resolve()
            for other_label, other_path in theirs:
                if _overlaps(resolved, Path(other_path).resolve()):
                    problems.append('the ' + INSTANCE.name + ' ' + label + ' ' + str(path) + ' resolves to ' +
                                    str(resolved) + ', which overlaps the ' + other.name + ' ' + other_label + ' ' +
                                    str(other_path))
    if problems:
        raise ValueError('Instance paths overlap; refusing to act on the ' + INSTANCE.name + ' instance:\n  ' +
                         '\n  '.join(problems))


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


def container_problem(info):
    """Why the inspected container is not the active instance's, or None.

    It must carry the instance label (production also accepts the unlabelled container of the first
    controller releases) and bind-mount only folders of the instance's own install root.
    """
    label = ((info.get('Config') or {}).get('Labels') or {}).get(INSTANCE_LABEL)
    if label != INSTANCE.name and not (label is None and INSTANCE.name == 'production'):
        return 'container ' + CONTAINER + ' is labelled for instance ' + repr(label) + ', not ' + INSTANCE.name
    root = PurePosixPath(Path(BASE).as_posix())
    for item in info.get('Mounts') or []:
        source = PurePosixPath(str(item.get('Source', '')))
        if item.get('Type') == 'bind' and not (source == root or root in source.parents):
            return ('container ' + CONTAINER + ' mounts ' + str(source) + ', outside the ' + INSTANCE.name +
                    ' install root ' + str(root))
    return None


def healthy(config, digest=None, attempts=24):
    for attempt in range(attempts):
        service_ok = False
        if digest:
            info = inspect_container()
            service_ok = bool(info and info['State']['Running'] and
                              info['Config']['Image'] == config['image'] + '@' + digest and
                              container_problem(info) is None)
        elif HOST_SERVICE:
            service_ok = subprocess.run(['systemctl', 'is-active', '--quiet', HOST_SERVICE]).returncode == 0
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


# The folders start() mounts into the container: written by the server, and read only.
WRITABLE_MOUNTS = ('meshcentral-data', 'meshcentral-files', 'meshcentral-recordings', 'meshcentral-backups')
READONLY_MOUNTS = ('meshcentral-web',)
MOUNTED_FOLDERS = ('meshcentral-data', 'meshcentral-files', 'meshcentral-web',
                   'meshcentral-recordings', 'meshcentral-backups')


def _lower_keys(value):
    if isinstance(value, dict):
        return {str(key).lower(): _lower_keys(item) for key, item in value.items()}
    return value


def server_config_paths(server_config):
    """Return [(key, value, access)] for every host path the MeshCentral config names (fork at 1.3.1).

    Keys are matched case-insensitively, as MeshCentral lowercases them (common.js objKeysToLower,
    meshcentral.js getConfig). access is 'write' or 'read'. settings.datapath and settings.filespath are
    not listed: the container's --datapath and --filespath override them (getConfig copies the command
    line over config.settings).
    """
    config = _lower_keys(server_config) if isinstance(server_config, dict) else {}
    settings = config.get('settings') if isinstance(config.get('settings'), dict) else {}
    paths = []
    # Autobackup runs unless it is false (meshcentral.js:2210-2212); backuppath goes through path.resolve
    # (meshcentral.js:2232), so a relative value is taken from the working directory.
    autobackup = settings.get('autobackup')
    if autobackup not in (False, 'false') and isinstance(autobackup, dict) and isinstance(autobackup.get('backuppath'), str):
        paths.append(('settings.autobackup.backuppath', autobackup['backuppath'], 'write'))
    # mesherrors.txt is appended there (meshcentral.js:732).
    if isinstance(settings.get('mesherrorlogpath'), str):
        paths.append(('settings.mesherrorlogpath', settings['mesherrorlogpath'], 'write'))
    domains = config.get('domains') if isinstance(config.get('domains'), dict) else {}
    for name, domain in domains.items():
        if name.startswith('_') or not isinstance(domain, dict):
            continue  # domains whose name starts with "_" are deleted at start (meshcentral.js:1522)
        label = 'domains[' + json.dumps(name) + ']'
        recording = domain.get('sessionrecording')
        # Recordings are written there (meshrelay.js:511-513, meshdesktopmultiplex.js:1013-1015,
        # webserver.js:5456-5458) and listed and served from there (webserver.js:4443, meshuser.js:1206).
        if isinstance(recording, dict) and isinstance(recording.get('filepath'), str) and recording['filepath']:
            paths.append((label + '.sessionrecording.filepath', recording['filepath'], 'write'))
        # Domain web overrides are served from there (meshcentral.js:1589-1595, webserver.js:4086).
        for key in ('webviewspath', 'webpublicpath', 'webemailspath'):
            if isinstance(domain.get(key), str):
                paths.append((label + '.' + key, domain[key], 'read'))
    return paths


def check_server_config_paths(server_config, base=None):
    """Refuse a MeshCentral config that names a host path the container does not mount.

    The container runs with a read-only root and the working directory /opt/meshcentral, so the server
    could neither write nor read such a path: backups or recordings would fail at run time. The error
    names each key and its path and no other configuration value.
    """
    root = PurePosixPath(Path(base or BASE).as_posix())
    allowed = {'write': [root / name for name in WRITABLE_MOUNTS],
               'read': [root / name for name in WRITABLE_MOUNTS + READONLY_MOUNTS]}
    problems = []
    for key, value, access in server_config_paths(server_config):
        resolved = PurePosixPath(posixpath.normpath(posixpath.join(str(root), value)))
        if not any(resolved == folder or folder in resolved.parents for folder in allowed[access]):
            problems.append(key + ' = ' + str(resolved) + ': the release container does not mount it, so the server '
                            'cannot ' + access + ' it there (' + ('written' if access == 'write' else 'read') +
                            ' paths must be under ' + ', '.join(str(folder) for folder in allowed[access]) + ')')
        elif key == 'settings.autobackup.backuppath' and (resolved == root / 'meshcentral-data' or
                                                        root / 'meshcentral-data' in resolved.parents):
            problems.append(key + ' = ' + str(resolved) + ': MeshCentral refuses a backup path inside '
                            'meshcentral-data and makes no backups (db.js checkBackupCapability)')
    if problems:
        raise ValueError('The MeshCentral configuration names paths outside the release container\'s mounts:\n  ' +
                         '\n  '.join(problems))


# Values the operator must replace in tools/deployment/meshcentral-preview-config.template.json.
TEMPLATE_PLACEHOLDER = 'REPLACE_'
# MeshCentral's values when the keys are absent: database (db.js:1012-1013) and MPS port.
DEFAULT_DATABASE = 'meshcentral'
DEFAULT_MPS_PORT = 4433
LOOPBACK = '127.0.0.1'


def _url_host(value):
    match = re.fullmatch(r'[a-z][a-z0-9+.-]*://([^/:?#]+).*', value.strip(), re.IGNORECASE) \
        if isinstance(value, str) else None
    return match.group(1).lower() if match else None


def _placeholders(value, label):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _placeholders(item, label + '.' + str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _placeholders(item, label + '[' + str(index) + ']')
    elif isinstance(value, str) and value.startswith(TEMPLATE_PLACEHOLDER):
        yield label


def server_config_instance_problems(server_config, instance=None):
    """Return why a MeshCentral config does not fit ``instance`` (a name; default: the active instance).

    Every instance refuses another instance's listening ports, database and public host. An instance with
    a fixed public host (preview) must also use exactly its own: web port and MPS port (or 0) bound to
    127.0.0.1, redirect port 0, a MongoDB URI with its database, its host in cert, agentAliasDNS and the
    default domain's certUrl, and no unreplaced template placeholder. Messages name keys and non-secret
    values only (ports, database and host names); the MongoDB URI and secrets are never printed.
    """
    instance = INSTANCES[instance] if instance else INSTANCE
    config = _lower_keys(server_config) if isinstance(server_config, dict) else {}
    settings = config.get('settings') if isinstance(config.get('settings'), dict) else {}
    domains = config.get('domains') if isinstance(config.get('domains'), dict) else {}
    default_domain = domains.get('') if isinstance(domains.get(''), dict) else {}
    port, mps_port = settings.get('port'), settings.get('mpsport', DEFAULT_MPS_PORT)
    database = settings.get('mongodbname', DEFAULT_DATABASE)

    def text(value):
        return value if isinstance(value, str) else None

    hosts = (('settings.cert', text(settings.get('cert'))),
             ('settings.agentaliasdns', text(settings.get('agentaliasdns'))),
             ('domains[""].certurl', _url_host(default_domain.get('certurl'))))
    problems = []
    for other in INSTANCES.values():
        if other is instance:
            continue
        for key, value in (('settings.port', port), ('settings.mpsport', mps_port)):
            if type(value) is int and value in (other.web_port, other.mps_port):
                problems.append(key + ' = ' + str(value) + ' is a port of the ' + other.name + ' instance' +
                                ('' if key[9:] in settings else ' (MeshCentral\'s default when the key is absent)'))
        if 'mongodb' in settings and database == other.database:
            problems.append('settings.mongodbname = ' + str(database) + ' is the ' + other.name + ' instance\'s '
                            'database' + ('' if 'mongodbname' in settings else
                                          ' (MeshCentral\'s default when the key is absent)'))
        for key, host in hosts:
            if other.server_host and host and host.lower() == other.server_host:
                problems.append(key + ' names ' + host + ', the ' + other.name + ' instance\'s host')
    if instance.server_host:
        def exact(key, value, expected):
            if type(value) is not type(expected) or value != expected:
                problems.append(key + ' must be ' + json.dumps(expected) + ' for the ' + instance.name + ' instance' +
                                (', found ' + json.dumps(value) if isinstance(value, (int, str)) else ''))

        exact('settings.port', port, instance.web_port)
        exact('settings.portbind', settings.get('portbind'), LOOPBACK)
        exact('settings.redirport', settings.get('redirport'), 0)
        if type(mps_port) is not int or mps_port != 0:
            exact('settings.mpsport', mps_port, instance.mps_port)
            exact('settings.mpsportbind', settings.get('mpsportbind'), LOOPBACK)
        if not isinstance(settings.get('mongodb'), str) or not settings['mongodb'].strip():
            problems.append('settings.mongodb must give the MongoDB URI of the ' + instance.name + ' database user')
        exact('settings.mongodbname', settings.get('mongodbname'), instance.database)
        exact('settings.cert', settings.get('cert'), instance.server_host)
        for key, host in hosts[1:]:
            if host is not None and host != instance.server_host:
                problems.append(key + ' names ' + host + '; the ' + instance.name + ' instance uses ' +
                                instance.server_host)
        problems += [label + ' still holds a ' + TEMPLATE_PLACEHOLDER + ' template placeholder'
                     for label in _placeholders(server_config, 'config')]
    return problems


def check_server_config_instance(server_config):
    problems = server_config_instance_problems(server_config)
    if problems:
        raise ValueError('The MeshCentral configuration does not fit the ' + INSTANCE.name + ' instance:\n  ' +
                         '\n  '.join(problems))


def check_server_config():
    """check_server_config_paths and check_server_config_instance on the meshcentral-data/config.json the
    container will read. Its paths are the container's: the folders are mounted under container_root()."""
    path = BASE / 'meshcentral-data/config.json'
    try:
        server_config = json.loads(path.read_text(encoding='utf-8'))
    except ValueError as error:
        raise ValueError(str(path) + ' is not valid JSON (' + type(error).__name__ + ')') from None
    try:
        check_server_config_paths(server_config, container_root())
    except ValueError as error:
        if MOUNT_ROOT is None:
            raise
        raise ValueError(str(error) + '\n  The ' + INSTANCE.name + ' container mounts ' + str(BASE) + '/<folder> at ' +
                         str(MOUNT_ROOT) + '/<folder>; write configuration paths as the container sees them.') from None
    check_server_config_instance(server_config)


def check_identity_separation():
    """Refuse when the active instance's meshcentral-data holds a certificate or key file of an instance it
    must stay distinct from: a copied agent certificate would give both servers one ServerID. Files are
    compared by sha256 in memory; only their names are printed."""
    data = BASE / 'meshcentral-data'
    problems = []
    for name in INSTANCE.distinct_from:
        other = INSTANCES[name].base / 'meshcentral-data'
        theirs = {}
        for path in (sorted(other.glob('*-cert-*')) if other.is_dir() else ()):
            if path.is_file():
                theirs.setdefault(file_sha256(path), path.name)
        for path in (sorted(data.glob('*-cert-*')) if data.is_dir() else ()):
            digest = file_sha256(path) if path.is_file() else None
            if digest in theirs:
                problems.append(str(path) + ' equals the ' + name + ' instance\'s ' + theirs[digest])
    if problems:
        raise ValueError('The ' + INSTANCE.name + ' instance must generate its own certificates and keys (its own '
                         'ServerID); move these files out of ' + str(data) + ':\n  ' + '\n  '.join(problems))


def start(config, release):
    manifest = validate_manifest(Path(release['directory']) / RELEASE_FOLDER, config['reviewed_versions'])
    check_instance_isolation()
    # Runs at every start, including recovery and rollback, so data/web copies placed since the
    # release was promoted are refused rather than trusted.
    check_shadow_copies(manifest)
    check_server_config()
    check_identity_separation()
    user = pwd.getpwnam(SERVICE_ACCOUNT)
    args = ['docker', 'run', '--detach', '--name', CONTAINER, '--label', INSTANCE_LABEL + '=' + INSTANCE.name,
            '--restart', 'unless-stopped',
            '--network', 'host', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--user', f'{user.pw_uid}:{user.pw_gid}',
            '--init', '--stop-timeout', '60', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--log-driver', 'local', '--log-opt', 'max-size=20m', '--log-opt', 'max-file=5']
    def mount(source, target, readonly=False):
        args.extend(['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')])
    # Only the persistent folders: the code, its agents and its cores come from the image's package.
    for name in MOUNTED_FOLDERS:
        mount(BASE / name, container_root() / name, name in READONLY_MOUNTS)
    # No NODE_OPTIONS: the release image does not install image-size, so nothing is preloaded.
    args.append(config['image'] + '@' + release['digest'])
    run(*args)


# The host service's image-size preload (DEP-21), installed before the fork release. The 1.2.5 host
# installation needs it for as long as it is the rollback target of an interrupted first migration, so
# it is retired only after a container release has been promoted, and kept for the manual return to it.
HOST_PRELOAD = (Path('/opt/meshcentral/bin/harden-image-size.js'),
                Path('/etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf'))
# The active instance's preload (activate): production's host service has one, other instances none.
LEGACY_PRELOAD = HOST_PRELOAD
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
    info = inspect_container()
    if info is not None:
        problem = container_problem(info)
        if problem:
            raise RuntimeError('Not stopping it: ' + problem + '. Inspect the container by hand.')
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
    elif not HOST_SERVICE:
        # No earlier release and no host service: the instance stays stopped.
        print('No earlier ' + INSTANCE.name + ' release to restore; the ' + INSTANCE.name + ' instance is stopped.')
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
        run('systemctl', 'enable', '--now', HOST_SERVICE)
    if (previous or HOST_SERVICE) and not healthy(config, previous['digest'] if previous else None):
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
    # An instance with nothing running yet (no release, no host service) has no incumbent to protect.
    if (previous or HOST_SERVICE) and not healthy(config, previous['digest'] if previous else None, attempts=1):
        raise RuntimeError('Current ' + INSTANCE.name + ' service is unhealthy; refusing promotion')
    directory = prepare(config, digest)
    release = {'digest': digest, 'directory': str(directory)}
    check_legacy_preload()
    # The same checks start() runs, before anything is stopped: a host that the candidate would
    # refuse is reported without an outage.
    check_instance_isolation()
    check_shadow_copies(release_manifest(release))
    check_server_config()
    check_identity_separation()
    # First migration: record the healthy host installation's shadow copies, the explicit allowlist
    # recover() checks before restarting the host service. Refuses before anything is stopped.
    host_allowlist = meshcentral_shadow_check.snapshot(BASE) if not previous and HOST_SERVICE else None
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
    if not previous and HOST_SERVICE:
        transaction['host_shadow_allowlist'] = host_allowlist
    atomic_json(journal, transaction)
    try:
        if previous or not HOST_SERVICE:
            # Without a host service this also removes a container of this instance left without a record.
            remove_container()
        else:
            # Retain the host installation for first-migration rollback.
            run('systemctl', 'disable', '--now', HOST_SERVICE)
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
    parser.add_argument('--instance', choices=sorted(INSTANCES), default='production',
                        help='server instance to act on (default: production)')
    parser.add_argument('command', choices=('deploy', 'recover', 'rollback', 'status'))
    parser.add_argument('digest', nargs='?')
    args = parser.parse_args()
    activate(args.instance)
    if os.geteuid() != 0:
        raise SystemExit('Run through the installed root-owned systemd release controller')
    check_instance_isolation()
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
                raise ValueError('First migration rollback requires the retained host-service recovery procedure'
                                 if HOST_SERVICE else 'No previous ' + INSTANCE.name + ' release to roll back to')
            promote(config, validate_digest(previous['digest']))
        else:
            print((STATE / 'active.json').read_text() if (STATE / 'active.json').exists() else 'null')


if __name__ == '__main__':
    main()
