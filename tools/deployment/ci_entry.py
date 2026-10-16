#!/usr/bin/env python3
"""Restricted, root-owned SSH forced-command entry point; accepts only a digest."""
import re
import json
import os
import subprocess
import sys
import tempfile


def command(value, credential_path=None):
    match = re.fullmatch(r'deploy (sha256:[0-9a-f]{64})', value)
    if not match:
        raise ValueError('Only deploy sha256:<digest> is allowed')
    credentials = ['--property=LoadCredential=ghcr:' + credential_path] if credential_path else []
    return ['systemd-run', '--unit=meshcentral-deploy', '--collect', '--wait', '--pipe',
            '--property=Type=exec', '--property=TimeoutStartSec=30min', *credentials,
            '/usr/local/libexec/meshcentral-release', 'deploy', match.group(1)]


def registry_credentials(value):
    if len(value) > 2048:
        raise ValueError('Registry credential input is too large')
    credentials = json.loads(value)
    if (set(credentials) != {'username', 'token'} or
            not re.fullmatch(r'[A-Za-z0-9_-]{1,100}(?:\[bot\])?', credentials['username']) or
            not re.fullmatch(r'[A-Za-z0-9_]{20,1024}', credentials['token'])):
        raise ValueError('Invalid short-lived registry credential')
    return credentials


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Exactly one forced-command argument is required')
    command(sys.argv[1])  # Reject unsupported commands before reading credentials.
    credentials = registry_credentials(sys.stdin.read(2049))
    with tempfile.NamedTemporaryFile(mode='w', prefix='meshcentral-ghcr-', dir='/run', delete=True) as credential:
        os.chmod(credential.name, 0o600)
        json.dump(credentials, credential)
        credential.flush()
        raise SystemExit(subprocess.run(command(sys.argv[1], credential.name), check=False).returncode)
