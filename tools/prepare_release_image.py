"""Place the coordinated release's Windows service artifacts where the release gates read them.

hook's validate-release job calls materialize() on the downloaded build legs, then runs
test/release_signing_bundle_gate.js and test/release_bundle_gate.js against the local paths that
deploy.ARTIFACTS names. Every required artifact must be a regular file, and the copied set must pass
deploy.validate_local_service_bundle_artifacts.

This module no longer assembles the release image: the image is the fork tarball installed with
npm ci (tools/deployment/Dockerfile), with no overlay files, no seeded data/signed agent folders and
no generated hashagents.json (Stage 4, DEP-22, DEP-25, PRD-3).
"""
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
