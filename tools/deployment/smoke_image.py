"""Boot the exact published image against disposable data before promotion."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request
import uuid


def run(*args, capture=False):
    return subprocess.check_output(args, text=True).strip() if capture else subprocess.check_call(args)


def main():
    image = os.environ['RELEASE_IMAGE']
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
        for folder in ('data', 'files', 'backups', 'recordings'):
            (root / folder).mkdir(mode=0o777)
            (root / folder).chmod(0o777)  # Disposable fixtures, never production data.
        config = {'settings': {'cert': 'localhost', 'port': 4430, 'redirport': 0, 'mpsport': 0,
                               'wanonly': True, 'tlsoffload': True, 'exactports': True,
                               'noagentupdate': True}, 'domains': {'': {}}}
        (root / 'data/config.json').write_text(json.dumps(config))
        try:
            run('docker', 'run', '-d', '--name', name, '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges:true', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
                '--mount', 'type=bind,src=' + str(root / 'data') + ',dst=/opt/meshcentral/meshcentral-data',
                '--mount', 'type=bind,src=' + str(root / 'files') + ',dst=/opt/meshcentral/meshcentral-files',
                '--mount', 'type=bind,src=' + str(root / 'backups') + ',dst=/opt/meshcentral/meshcentral-backups',
                '--mount', 'type=bind,src=' + str(root / 'recordings') + ',dst=/opt/meshcentral/meshcentral-recordings',
                '-p', '127.0.0.1::4430', image)
            port = run('docker', 'port', name, '4430/tcp', capture=True).rsplit(':', 1)[1]
            for _ in range(90):
                if run('docker', 'inspect', '--format', '{{.State.Running}}', name, capture=True) != 'true':
                    raise RuntimeError('Image exited during readiness')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:' + port + '/health.ashx', timeout=2) as response:
                        if response.status == 200 and response.read(32) == b'ok':
                            # Verify restart against persisted disposable data, not only first boot.
                            break
                except OSError:
                    pass
                time.sleep(2)
            else:
                raise RuntimeError('Image did not become ready with locked dependencies and read-only root')
            run('docker', 'restart', '--time', '30', name)
            # Docker may reassign an ephemeral published port after restart.
            port = run('docker', 'port', name, '4430/tcp', capture=True).rsplit(':', 1)[1]
            for _ in range(45):
                try:
                    with urllib.request.urlopen('http://127.0.0.1:' + port + '/health.ashx', timeout=2) as response:
                        if response.status == 200 and response.read(32) == b'ok':
                            print('Exact release digest passed boot and restart readiness')
                            return
                except OSError:
                    pass
                time.sleep(2)
            raise RuntimeError('Image restart did not become ready')
        finally:
            subprocess.run(['docker', 'logs', '--tail', '100', name], check=False)
            subprocess.run(['docker', 'rm', '-f', name], check=False)
            # The container creates fixture files as UID 1000; remove through Docker.
            subprocess.run(['docker', 'run', '--rm', '--user', '0', '--entrypoint', 'sh',
                            '--mount', 'type=bind,src=' + str(root) + ',dst=/fixture', image,
                            '-c', 'find /fixture -mindepth 1 -delete'], check=False)


if __name__ == '__main__':
    main()
