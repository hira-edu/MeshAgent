"""Fast-forward all three source checkouts without discarding or merging local work."""
import argparse
from pathlib import Path
import subprocess

REPOSITORIES = ('MeshAgent', 'MeshCentral', 'hook')


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def sync(parent):
    revisions = []
    # Validate every checkout before fetching or modifying any working tree.
    for name in REPOSITORIES:
        root = parent / name
        if git(root, 'status', '--porcelain', '--untracked-files=normal'):
            raise ValueError(f'{name} has local changes; commit/stash them explicitly before syncing')
        branch = git(root, 'branch', '--show-current')
        if not branch:
            raise ValueError(f'{name} is detached; select its branch explicitly')
        git(root, 'rev-parse', '--abbrev-ref', '@{upstream}')
    for name in REPOSITORIES:
        git(parent / name, 'fetch', '--prune', 'origin')
    for name in REPOSITORIES:
        root = parent / name
        current, upstream = git(root, 'rev-parse', 'HEAD'), git(root, 'rev-parse', '@{upstream}')
        if git(root, 'merge-base', current, upstream) != current:
            raise ValueError(f'{name} has unpushed or divergent commits; no working trees were updated')
        revisions.append((root, current, upstream))
    for root, current, upstream in revisions:
        if git(root, 'rev-parse', 'HEAD') != current or git(root, 'status', '--porcelain'):
            raise ValueError(f'{root.name} changed during sync; refusing to overwrite work')
        git(root, 'merge', '--ff-only', upstream)
        print(root.name + ': ' + upstream)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, default=Path(__file__).resolve().parents[2])
    sync(parser.parse_args().parent.resolve())
