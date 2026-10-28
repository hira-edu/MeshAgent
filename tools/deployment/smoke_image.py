"""Boot the exact published image against disposable data before promotion, and prove its identity.

Image mode (CI): RELEASE_IMAGE=<registry digest or local image ID> python smoke_image.py
    Boots the image read-only as production runs it (no NODE_OPTIONS preload), restarts it against
    the persisted disposable data, then runs the smoke_checks assertions against the release
    manifest inside the image.

Duplicate-server mode: python smoke_image.py --server-url URL --install-root DIR --manifest FILE,
    with SMOKE_USERNAME and SMOKE_PASSWORD set for an account on that server. Runs the same
    assertions against an already running local duplicate server. Its config must define the
    redirect {"release-smoke-version": "~showversion"} in the default domain.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke_checks  # noqa: E402

INSTALL_ROOT = '/opt/meshcentral'
MANIFEST = INSTALL_ROOT + '/release/manifest.json'
SMOKE_USER = 'release-smoke'


def run(*args, capture=False):
    return subprocess.check_output(args, text=True).strip() if capture else subprocess.check_call(args)


def wait_ready(name, attempts, failure):
    port = run('docker', 'port', name, '4430/tcp', capture=True).rsplit(':', 1)[1]
    for _ in range(attempts):
        if run('docker', 'inspect', '--format', '{{.State.Running}}', name, capture=True) != 'true':
            raise RuntimeError('Image exited during readiness')
        try:
            with urllib.request.urlopen('http://127.0.0.1:' + port + '/health.ashx', timeout=2) as response:
                if response.status == 200 and response.read(32) == b'ok':
                    return port
        except OSError:
            pass
        time.sleep(2)
    raise RuntimeError(failure)


def image_manifest(image, directory):
    """Copy the release manifest out of the image without running it."""
    extraction = 'meshcentral-smoke-manifest-' + uuid.uuid4().hex
    try:
        run('docker', 'create', '--name', extraction, image)
        run('docker', 'cp', extraction + ':' + MANIFEST, str(directory / 'manifest.json'))
    finally:
        subprocess.run(['docker', 'rm', '-f', extraction], check=False, stdout=subprocess.DEVNULL)
    return json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))


class ContainerFiles:
    """Answers smoke_checks file questions from inside the running container."""

    def __init__(self, name):
        self.name = name

    def exists(self, relative):
        return subprocess.run(['docker', 'exec', self.name, 'test', '-e', INSTALL_ROOT + '/' + relative],
                              check=False).returncode == 0

    def digest(self, relative):
        path = INSTALL_ROOT + '/' + relative
        size = int(run('docker', 'exec', self.name, 'stat', '--format=%s', path, capture=True))
        return size, run('docker', 'exec', self.name, 'sha384sum', path, capture=True).split()[0]

    def read(self, relative):
        return run('docker', 'exec', self.name, 'cat', INSTALL_ROOT + '/' + relative, capture=True)


class LocalFiles:
    """Answers smoke_checks file questions from a local install root (duplicate-server mode)."""

    def __init__(self, root):
        self.root = Path(root)

    def exists(self, relative):
        return (self.root / relative).exists()

    def read(self, relative):
        return (self.root / relative).read_text(encoding='utf-8')

    def digest(self, relative):
        with (self.root / relative).open('rb') as stream:
            data = stream.read()
        return len(data), hashlib.sha384(data).hexdigest()


def smoke_image(image):
    name = 'meshcentral-smoke-' + uuid.uuid4().hex
    if re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        # Local integration builds use their immutable Docker image ID. CI uses
        # the published registry digest and always pulls it before testing.
        run('docker', 'image', 'inspect', image, capture=True)
    elif re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}', image):
        run('docker', 'pull', image)
    else:
        raise ValueError('Smoke testing requires an immutable registry digest or local image ID')
    with tempfile.TemporaryDirectory(prefix='meshcentral-smoke-') as temporary:
        root = Path(temporary)
        manifest = image_manifest(image, root)
        smoke_checks.expectations(manifest)  # refuse a non-fork image before booting it
        for folder in ('data', 'files', 'backups', 'recordings'):
            (root / folder).mkdir(mode=0o777)
            (root / folder).chmod(0o777)  # Disposable fixtures, never production data.
        config = {'settings': {'cert': 'localhost', 'port': 4430, 'redirport': 0, 'mpsport': 0,
                               'wanonly': True, 'tlsoffload': True, 'exactports': True,
                               'noagentupdate': True},
                  'domains': {'': {'redirects': {smoke_checks.VERSION_PATH: '~showversion'}}}}
        (root / 'data/config.json').write_text(json.dumps(config))
        password = secrets.token_urlsafe(24)  # disposable account on disposable data
        mounts = ['--mount', 'type=bind,src=' + str(root / 'data') + ',dst=' + INSTALL_ROOT + '/meshcentral-data',
                  '--mount', 'type=bind,src=' + str(root / 'files') + ',dst=' + INSTALL_ROOT + '/meshcentral-files',
                  '--mount', 'type=bind,src=' + str(root / 'backups') + ',dst=' + INSTALL_ROOT + '/meshcentral-backups',
                  '--mount', 'type=bind,src=' + str(root / 'recordings') + ',dst=' + INSTALL_ROOT + '/meshcentral-recordings']
        hardening = ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                     '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m']
        try:
            run('docker', 'run', '--rm', *hardening, *mounts, image,
                '--datapath', INSTALL_ROOT + '/meshcentral-data', '--filespath', INSTALL_ROOT + '/meshcentral-files',
                '--createaccount', SMOKE_USER, '--pass', password)
            run('docker', 'run', '-d', '--name', name, *hardening, *mounts, '-p', '127.0.0.1::4430', image)
            wait_ready(name, 90, 'Image did not become ready with locked dependencies and read-only root')
            # Verify restart against persisted disposable data, not only first boot.
            run('docker', 'restart', '--time', '30', name)
            # Docker may reassign an ephemeral published port after restart.
            port = wait_ready(name, 45, 'Image restart did not become ready')
            files = ContainerFiles(name)
            expected = smoke_checks.run_checks(
                manifest, smoke_checks.Server('http://127.0.0.1:' + port), (SMOKE_USER, password), files)
            print('Exact release digest passed boot and restart readiness and identity checks: MeshCentral ' +
                  expected['version'] + ', fork ' + expected['forkRevision'])
        finally:
            subprocess.run(['docker', 'logs', '--tail', '100', name], check=False)
            subprocess.run(['docker', 'rm', '-f', name], check=False)
            # The container creates fixture files as UID 1000; remove through Docker.
            subprocess.run(['docker', 'run', '--rm', '--user', '0', '--entrypoint', 'sh',
                            '--mount', 'type=bind,src=' + str(root) + ',dst=/fixture', image,
                            '-c', 'find /fixture -mindepth 1 -delete'], check=False)


def smoke_server(server_url, install_root, manifest_path):
    """Run the release assertions against an already running duplicate server."""
    credentials = (os.environ.get('SMOKE_USERNAME', ''), os.environ.get('SMOKE_PASSWORD', ''))
    if not all(credentials):
        raise ValueError('SMOKE_USERNAME and SMOKE_PASSWORD must name an account on the duplicate server')
    manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    expected = smoke_checks.run_checks(manifest, smoke_checks.Server(server_url), credentials,
                                       LocalFiles(install_root))
    print('Duplicate server passed identity checks: MeshCentral ' + expected['version'] + ', fork ' +
          expected['forkRevision'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--server-url', help='duplicate-server mode: base URL of the running server')
    parser.add_argument('--install-root', type=Path, help='duplicate-server mode: folder holding node_modules and meshcentral-data')
    parser.add_argument('--manifest', type=Path, help='duplicate-server mode: the release manifest.json to assert')
    args = parser.parse_args(argv)
    server_mode = (args.server_url, args.install_root, args.manifest)
    if any(server_mode):
        if not all(server_mode):
            parser.error('duplicate-server mode needs --server-url, --install-root and --manifest')
        smoke_server(*server_mode)
    else:
        smoke_image(os.environ['RELEASE_IMAGE'])


if __name__ == '__main__':
    main()
