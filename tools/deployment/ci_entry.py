#!/usr/bin/env python3
"""Restricted, root-owned SSH forced-command entry point; accepts only a digest.

`deploy sha256:<digest>` deploys production (unchanged since the first release) and
`deploy-preview sha256:<digest>` deploys the preview instance. Each runs the controller in its own
systemd unit, so the two instances' deployments never share a unit name.

    meshcentral-ci-entry [--only <instance>] "<forced command>"

`--only <instance>`, set in a key's authorized_keys forced command, limits that key to one instance:
a key held by the auto-deploying preview environment cannot then submit a production deploy.
"""
import re
import json
import os
import subprocess
import sys
import tempfile

CONTROLLER = '/usr/local/libexec/meshcentral-release'
# Forced command -> (instance, systemd unit, controller arguments before the command). Mirrors
# release_manager.INSTANCES (checked by test/ci_release_preview_instance_test.py).
COMMANDS = {'deploy': ('production', 'meshcentral-deploy', ()),
            'deploy-preview': ('preview', 'meshcentral-deploy-preview', ('--instance', 'preview'))}
INSTANCES = tuple(instance for instance, _, _ in COMMANDS.values())


def command(value, credential_path=None, only=None):
    match = re.fullmatch(r'(deploy|deploy-preview) (sha256:[0-9a-f]{64})', value)
    if not match:
        raise ValueError('Only deploy sha256:<digest> or deploy-preview sha256:<digest> is allowed')
    instance, unit, arguments = COMMANDS[match.group(1)]
    if only is not None and instance != only:
        raise ValueError('This key may deploy only the ' + str(only) + ' instance')
    credentials = ['--property=LoadCredential=ghcr:' + credential_path] if credential_path else []
    return ['systemd-run', '--unit=' + unit, '--collect', '--wait', '--pipe',
            '--property=Type=exec', '--property=TimeoutStartSec=30min', *credentials,
            CONTROLLER, *arguments, 'deploy', match.group(2)]


def parse_arguments(argv):
    """Return (only, forced command) from the entry's arguments, refusing any other form."""
    if len(argv) == 1:
        return None, argv[0]
    if len(argv) == 3 and argv[0] == '--only' and argv[1] in INSTANCES:
        return argv[1], argv[2]
    raise ValueError('Usage: meshcentral-ci-entry [--only ' + '|'.join(INSTANCES) + '] "<forced command>"')


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
    only, forced = parse_arguments(sys.argv[1:])
    command(forced, only=only)  # Reject unsupported commands before reading credentials.
    credentials = registry_credentials(sys.stdin.read(2049))
    with tempfile.NamedTemporaryFile(mode='w', prefix='meshcentral-ghcr-', dir='/run', delete=True) as credential:
        os.chmod(credential.name, 0o600)
        json.dump(credentials, credential)
        credential.flush()
        raise SystemExit(subprocess.run(command(forced, credential.name, only), check=False).returncode)
