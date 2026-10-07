#!/usr/bin/env python3
"""Exercise deploy.py's macOS release profile without contacting a server.

Covers the profile's artifact selection and staging isolation, that the Windows
profile still requires Windows branding, embedded-module decoding against the real
ILibDuktape_Polyfills.c, the core-module override rule and the macOS binary checks.
Pass --agent to also validate a built macOS agent against the current tree.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, help='built meshagent_osx-arm-64 to validate')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
for name in ('MESHCENTRAL_INSTALL_ROOT', 'MESHCENTRAL_LIFECYCLE_DLL', 'MESHCENTRAL_BRANDING_CONFIG', 'BRANDING_CONFIG_PATH'):
    os.environ.pop(name, None)


def load():
    spec = importlib.util.spec_from_file_location('deployment', root / 'deploy.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deployment = load()
if not (root / 'branding_config.local.json').exists():
    # Without branding the tool still imports; only the Windows profile refuses to run.
    try:
        deployment.apply_platform_profile('windows')
        raise AssertionError('Windows profile ran without Windows branding')
    except RuntimeError as error:
        assert 'Active Windows branding installRoot/serviceDllName is required' in str(error)
windows_artifacts = set(deployment.ARTIFACTS)
assert 'MeshService64.exe' in windows_artifacts and 'meshagent_osx-arm-64' not in windows_artifacts

deployment.apply_platform_profile('macos')
assert set(deployment.ARTIFACTS) == {'meshagent_osx-arm-64'}
assert deployment.ARTIFACTS['meshagent_osx-arm-64']['publish_targets'] == ('data',)
assert set(deployment.CORE_ARTIFACTS) == {'macosinstaller.js'}
assert deployment.REQUIRED_AGENT_ARTIFACTS == {'meshagent_osx-arm-64'}
assert deployment.HASHAGENTS_TRACKED_FILENAMES == set() and deployment.SIGNED_RUNTIME_MUTABLE_FILENAMES == set()
assert deployment.STAGING_DIR.endswith('/staging-macos'), 'macOS staging must not share the Windows staging area'
assert not any(name.startswith('MeshService') or name.endswith('.dll') for name in deployment.ARTIFACTS)

polyfills = (root / 'microscript' / 'ILibDuktape_Polyfills.c').read_text(encoding='utf-8')
embedded = deployment.decode_embedded_modules(polyfills)
assert len(embedded) >= 50, len(embedded)
for name in ('user-sessions', 'service-manager', 'clipboard'):
    source = (root / 'modules' / f'{name}.js').read_text(encoding='utf-8').replace('\r\n', '\n')
    assert embedded[name]['source'] == source, f'{name} does not decode to modules/{name}.js'
assert len(embedded['service-manager']['literals']) > 1, 'chunked module literals'

# Override rule: only a differing copy dated later than (or against an undated) embedded module conflicts.
modules = {'dated': {'source': 'new\n', 'timestamp': '2026-10-07T00:00:00.000Z', 'literals': []},
           'undated': {'source': 'new\n', 'timestamp': None, 'literals': []}}
def conflicts(module, source, mtime):
    return deployment.find_core_module_override_conflicts(modules, [{'path': f'/x/{module}.js', 'module': module, 'mtime': mtime, 'source': source}])
assert conflicts('dated', 'old\n', '2026-10-06T10:12:47.123456Z') == []
assert len(conflicts('dated', 'old\n', '2026-10-07T00:00:00.000001Z')) == 1
assert 'tools/embed_modules.py dated' in conflicts('dated', 'old\n', '2026-10-08T00:00:00Z')[0]
assert conflicts('dated', 'new\r\n', '2026-10-08T00:00:00Z') == [], 'line endings alone are not a conflict'
assert len(conflicts('undated', 'old\n', '2020-01-01T00:00:00Z')) == 1
assert conflicts('absent', 'old\n', '2030-01-01T00:00:00Z') == []

# Loader selection: one directory, .min.js preferred when minifying, no Windows/AMT modules.
listing = [{'name': n, 'mtime': 't', 'source': n} for n in
           ('clipboard.js', 'clipboard.min.js', 'user-sessions.js', 'win-console.min.js', 'amt-lme.js', 'smbios.min.js', 'linux-dbus.min.js', 'notes.json')]
chosen = {e['module']: e['path'] for e in deployment.select_macos_core_modules('/d', True, listing)}
assert chosen == {'clipboard': '/d/clipboard.min.js', 'user-sessions': '/d/user-sessions.js', 'linux-dbus': '/d/linux-dbus.min.js'}, chosen
chosen = {e['module']: e['path'] for e in deployment.select_macos_core_modules('/d', False, listing)}
assert chosen['clipboard'] == '/d/clipboard.js' and 'win-console' not in chosen, chosen

# Binary checks: arm64 Mach-O; every literal of each built-in module present, where a
# single-line literal includes its date; gated modules absent from the build are ignored.
literals = {
    'chunked': {'source': '', 'timestamp': None, 'literals': ['QUJD', 'REVG'], 'marker': None},
    'single': {'source': '', 'timestamp': 'd2', 'literals': ["addCompressedModule('single', Buffer.from('X', 'base64'), 'd2');"],
               'marker': "addCompressedModule('single', Buffer.from('"},
    'gated': {'source': '', 'timestamp': None, 'literals': ["addCompressedModule('gated', Buffer.from('Y', 'base64'));"],
              'marker': "addCompressedModule('gated', Buffer.from('"},
}
header = (0xFEEDFACF).to_bytes(4, 'little') + (0x0100000C).to_bytes(4, 'little')
current = b"\0QUJD\0REVG\0addCompressedModule('single', Buffer.from('X', 'base64'), 'd2');\0"
with tempfile.TemporaryDirectory() as directory:
    sources = Path(directory) / 'sources.c'
    sources.write_text('')
    def check(name, data):
        path = Path(directory) / name
        path.write_bytes(data)
        return deployment.validate_macos_agent_binary(path, literals, sources)
    assert check('ok', header + current) == []
    assert 'not an arm64 Mach-O' in check('elf', b'\x7fELF' + b'\0' * 20 + current)[0]
    assert 'not an arm64 Mach-O' in check('x86', (0xFEEDFACF).to_bytes(4, 'little') + (0x01000007).to_bytes(4, 'little') + current)[0]
    assert 'stale: chunked' in check('stale-chunk', header + current.replace(b'REVG', b'ZZZZ'))[0]
    # Same payload, older date: only the date changed in the re-embed.
    assert 'stale: single' in check('stale-date', header + current.replace(b"'d2'", b"'d1'"))[0]
    old = Path(directory) / 'old'
    old.write_bytes(header + current)
    os.utime(old, (1, 1))
    assert 'older than' in deployment.validate_macos_agent_binary(old, literals, sources)[0]

if args.agent:
    errors = deployment.validate_macos_agent_binary(args.agent, embedded, root / 'microscript' / 'ILibDuktape_Polyfills.c')
    assert errors == [], errors

print('PASS: macOS profile selection and staging isolation, Windows branding still required, '
      'embedded module decoding, override rule and binary checks' + (' plus the built agent' if args.agent else ''))
