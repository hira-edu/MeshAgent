"""Submit a digest to the restricted VPS release controller using pinned SSH trust.

RELEASE_CHANNEL selects the controller command: production sends `deploy sha256:<digest>`, preview sends
`deploy-preview sha256:<digest>` (the controller's forced command accepts nothing else). The short-lived
registry credential goes on stdin, never on the command line.
"""
import os
import json
from pathlib import Path
import re
import subprocess
import tempfile

COMMANDS = {'production': 'deploy', 'preview': 'deploy-preview'}


def controller_command(channel, digest):
    if channel not in COMMANDS:
        raise ValueError('RELEASE_CHANNEL must be production or preview')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ValueError('Invalid image digest')
    return COMMANDS[channel] + ' ' + digest


def main():
    env = os.environ
    for key in ('RELEASE_CHANNEL', 'SSH_HOST', 'SSH_USER', 'SSH_PRIVATE_KEY', 'SSH_KNOWN_HOSTS', 'RELEASE_DIGEST',
                'REGISTRY_TOKEN', 'REGISTRY_USERNAME'):
        if not env.get(key, '').strip():
            raise ValueError('Missing required deployment setting: ' + key)
    host, user = env['SSH_HOST'], env['SSH_USER']
    port = env.get('SSH_PORT', '22') or '22'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]*', host) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', user):
        raise ValueError('Invalid SSH host/user')
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid SSH port')
    remote_command = controller_command(env['RELEASE_CHANNEL'], env['RELEASE_DIGEST'])
    with tempfile.TemporaryDirectory(prefix='meshcentral-ci-') as directory:
        key, hosts = Path(directory) / 'key', Path(directory) / 'known_hosts'
        key.write_text(env['SSH_PRIVATE_KEY'].strip() + '\n')
        hosts.write_text(env['SSH_KNOWN_HOSTS'].strip() + '\n')
        key.chmod(0o600)
        hosts.chmod(0o600)
        subprocess.run(['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                        '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(hosts),
                        '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                        '-p', port, '-i', str(key), user + '@' + host, remote_command],
                       input=json.dumps({'username': env['REGISTRY_USERNAME'], 'token': env['REGISTRY_TOKEN']}),
                       text=True, check=True, timeout=1900)


if __name__ == '__main__':
    main()
