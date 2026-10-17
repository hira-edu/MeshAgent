"""Export mapped manual-installation source overrides for review in a GitHub branch.

Never reads config.json, certificates, database files, provisioning, or user files.
Does not overwrite the source checkout, commit, or push automatically.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deploy


def export(destination):
    destination.mkdir(parents=True, exist_ok=False)
    report = []
    for name, entry in deploy.CORE_ARTIFACTS.items():
        if not entry['local_path'].startswith('../MeshCentral/'):
            continue
        relative = entry['local_path'][len('../MeshCentral/'):]
        # Prefer the package copy; plugins only exist in the persistent plugin root.
        roles = entry['publish_targets']
        role = next((role for role in roles if role.startswith('module-')), roles[0])
        remote = deploy.get_core_publish_path(role, entry['remote_relative_path'])
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if deploy.scp_download(remote, target) is False:
            raise RuntimeError('Export failed: ' + relative)
        local = ROOT.parent / 'MeshCentral' / relative
        data = target.read_bytes()
        report.append({'path': relative, 'sha256': hashlib.sha256(data).hexdigest(),
                       'differs': not local.is_file() or local.read_bytes() != data})
    (destination / 'export-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    for item in report:
        if item['differs']:
            print('Review VPS source difference: ' + item['path'])
    print('Review this export in a MeshCentral source branch, then commit and push normally.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    export(parser.parse_args().output.resolve())
