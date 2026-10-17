"""Assemble a complete, locked MeshCentral runtime plus verified native artifacts.

Runs inside the image build, with no production credentials or network deploys.
The manual deploy map remains the authority for supported custom overrides.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deploy


def materialize(artifacts):
    sources = {}
    for name in ('MeshService64.exe', 'MeshServiceARM64.exe', 'MeshService.exe'):
        folder = artifacts / ('MeshServiceRuntime-' + name)
        sources[name] = folder / name
        sources[name.replace('.exe', '.msh')] = folder / name.replace('.exe', '.msh')
    dll64 = artifacts / 'MeshServiceRuntime-diagsvc.dll/MeshService-2022.dll'
    dllarm = artifacts / 'MeshServiceRuntime-MeshServiceARM64.dll/MeshServiceARM64.dll'
    sources.update({'MeshService64.dll': dll64, 'diagsvc.dll': dll64,
                    'service_bundle.dll': dll64, 'MeshServiceARM64.dll': dllarm,
                    'service_bundle_arm64.dll': dllarm,
                    'WinDiagnosticHost.msh': sources['MeshService64.msh']})
    for name, source in sources.items():
        if not source.is_file() or source.is_symlink():
            raise ValueError('Required CI artifact missing: ' + name)
    for name, source in sources.items():
        target = ROOT / deploy.ARTIFACTS[name]['local_path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    report = deploy.validate_local_service_bundle_artifacts(deploy.get_present_local_artifacts())
    if not report['ok']:
        raise ValueError('; '.join(report['errors']))


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def assemble(base, artifacts):
    materialize(artifacts)
    server = base / 'node_modules/meshcentral'
    loader = server / 'meshcentral.js'
    loader.write_text(deploy.align_proxy_certificate_sni(
        deploy.version_meshcentral_module_loader(loader.read_text(encoding='utf-8'))), encoding='utf-8')
    overrides = base / 'release-overrides'
    overrides.mkdir()
    mounts = []
    for name, entry in deploy.CORE_ARTIFACTS.items():
        if name == 'meshcentral.js':
            continue
        source = ROOT / entry['local_path']
        if not source.is_file():
            raise ValueError('Missing mapped MeshCentral source: ' + name)
        for role in entry['publish_targets']:
            relative = entry['remote_relative_path']
            if role.startswith('module-'):
                folder = {'module-root': server, 'module-core': server / 'agents',
                          'module-public': server / 'public'}[role]
                copy(source, folder / relative)
            else:
                destination = deploy.get_core_publish_path(role, relative)
                local = role + '/' + relative
                copy(source, overrides / local)
                mounts.append({'source': local, 'target': destination})
    for name, entry in deploy.ARTIFACTS.items():
        if name not in deploy.REQUIRED_AGENT_ARTIFACTS:
            continue
        source = ROOT / entry['local_path']
        for role in entry['publish_targets']:
            if role == 'module':
                copy(source, server / 'agents' / entry['remote_filename'])
            else:
                copy(source, overrides / role / entry['remote_filename'])
    # The read-only module agent directory must contain hashes for this exact image.
    mapping = deploy.load_hashagents_mapping()
    hashes = {}
    for name, architecture in mapping.items():
        path = server / 'agents' / name
        if path.is_file():
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha384').hexdigest().upper()
            hashes[str(architecture)] = {'filename': name, 'hash': digest, 'size': path.stat().st_size,
                                         'mtime': datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()}
    (server / 'agents/hashagents.json').write_text(json.dumps(hashes, indent=2) + '\n', encoding='utf-8')
    # Seed directories are copied into per-release writable state on the VPS.
    # Existing non-Windows agents are preserved separately by the release manager.
    copy(server / 'package.json', overrides / 'server-package.json')
    manifest = {'schema': 1, 'meshcentral_version': json.loads((server / 'package.json').read_text())['version'],
                'mounts': mounts, 'files': {}}
    for path in sorted(overrides.rglob('*')):
        if path.is_file():
            manifest['files'][path.relative_to(overrides).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (overrides / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    assemble(Path('/opt/meshcentral'), Path('/inputs/artifacts'))
