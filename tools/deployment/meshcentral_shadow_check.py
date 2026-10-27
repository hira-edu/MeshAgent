#!/usr/bin/env python3
"""G4: refuse to run MeshCentral while files outside the package shadow it.

MeshCentral 1.2.5 prefers copies in its data and web folders over the files in its package:

- ``meshcentral-data/meshcore.js`` makes the core, ``meshcore.min.js`` and both
  ``modules_meshcore[_min]`` folders come from the data folder only (meshcentral.js:2932-2938,
  2978-2983); an empty ``modules_meshcore_min`` is still used when minifycore is on;
- ``meshcentral-data/agents`` and ``signedagents`` beat the package agents per file
  (meshcentral.js:3624-3629);
- plugins load only from ``meshcentral-data/plugins`` and are merged into the cores;
- ``meshcentral-web/views`` and ``public`` beat the package per file, and a
  ``meshcentral-web/emails`` folder hides the package emails entirely.

Every regular file in those places must be listed, with its sha256, in the allowlist of the
release that is about to run. Anything unlisted, changed, linked or special fails the check,
naming each file. The check reads only; it never deletes or repairs anything.

Importable (release_manager.start uses it, deploy.py can use the same function) and runnable:

    meshcentral_shadow_check.py --root /opt/meshcentral --manifest release-overrides/manifest.json
"""
import argparse
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

DATA = 'meshcentral-data'
WEB = 'meshcentral-web'
# Entries directly inside meshcentral-data that replace the package core or modules.
DATA_PATTERNS = ('meshcore*.js', 'modules_meshcore*')
# Folders whose whole content shadows the package.
SHADOW_FOLDERS = (DATA + '/agents', DATA + '/signedagents', DATA + '/plugins',
                  WEB + '/views', WEB + '/public', WEB + '/emails')
# Folders that change what is served by existing at all, even when empty.
PRESENCE_PATTERNS = (DATA + '/modules_meshcore*', WEB + '/emails')
SHA256 = re.compile(r'[0-9a-f]{64}')


class ShadowCopyError(ValueError):
    """Raised when shadow copies would override the MeshCentral package."""


def is_shadow_path(relative):
    """True when ``relative`` (POSIX, from the install root) is a place this check governs."""
    parts = PurePosixPath(relative).parts
    if len(parts) >= 2 and parts[0] == DATA and any(fnmatchcase(parts[1], pattern) for pattern in DATA_PATTERNS):
        return True
    return any(relative == folder or relative.startswith(folder + '/') for folder in SHADOW_FOLDERS)


def parse_allowlist(entries):
    """Validate a manifest ``shadowAllowlist`` and return {relative path: sha256}."""
    if not isinstance(entries, list):
        raise ValueError('shadowAllowlist must be a list of {"path", "sha256"} entries')
    allowlist = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'path', 'sha256'}:
            raise ValueError('shadowAllowlist entries must have exactly "path" and "sha256": ' + repr(entry))
        path, digest = entry['path'], entry['sha256']
        if not isinstance(path, str) or not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError('shadowAllowlist entry needs a relative path and a lowercase sha256: ' + repr(entry))
        pure = PurePosixPath(path)
        if (pure.is_absolute() or '..' in pure.parts or '.' in pure.parts or '\\' in path or
                pure.as_posix() != path or not is_shadow_path(path)):
            raise ValueError('shadowAllowlist path must be a normalized path inside a governed folder: ' + path)
        if path in allowlist:
            raise ValueError('shadowAllowlist lists a path more than once: ' + path)
        allowlist[path] = digest
    return allowlist


def _sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _governed_entries(root, hidden=(), overlays=None, allow_missing=False):
    """Yield (kind, relative, path) for every governed entry: 'file', 'symlink', 'empty' or 'special'.

    ``allow_missing`` treats an absent meshcentral-data or meshcentral-web as empty (a host
    installation without web overrides); a release container always mounts both.
    """
    root = Path(root)
    overlays = dict(overlays or {})
    hidden = {PurePosixPath(path).as_posix() for path in hidden}
    for folder in (DATA, WEB):
        path = root / folder
        if path.is_symlink() or (path.exists() and not path.is_dir()) or (not path.exists() and not allow_missing):
            raise ShadowCopyError('Cannot check shadow copies: ' + str(path) + ' is not a directory')

    def covered(relative):
        return any(relative == path or relative.startswith(path + '/') for path in hidden)

    def visit(relative, path):
        if covered(relative):
            return
        if path.is_symlink():
            yield 'symlink', relative, path
        elif path.is_dir():
            children = sorted(path.iterdir())
            if not children and any(fnmatchcase(relative, pattern) for pattern in PRESENCE_PATTERNS):
                yield 'empty', relative, path
            for child in children:
                yield from visit(relative + '/' + child.name, child)
        elif path.is_file():
            yield 'file', relative, path
        elif path.exists():
            yield 'special', relative, path

    if (root / DATA).is_dir():
        for entry in sorted((root / DATA).iterdir()):
            relative = DATA + '/' + entry.name
            if relative not in SHADOW_FOLDERS and any(fnmatchcase(entry.name, pattern) for pattern in DATA_PATTERNS):
                yield from visit(relative, entry)
    for relative in SHADOW_FOLDERS:
        yield from visit(relative, Path(overlays.pop(relative)) if relative in overlays else root / relative)
    if overlays:
        raise ValueError('Overlays outside the governed folders: ' + ', '.join(sorted(overlays)))


def _problem(kind, relative, path, allowlist):
    if kind == 'symlink':
        return relative + ': symbolic link'
    if kind == 'empty':
        return relative + '/: empty folder still hides the package copy'
    if kind == 'special':
        return relative + ': not a regular file'
    expected = allowlist.get(relative)
    if expected is None:
        return relative + ': not in the release shadow allowlist'
    actual = _sha256(path)
    if actual != expected:
        return relative + ': sha256 ' + actual + ' differs from the allowlisted ' + expected
    return None


def find_shadow_files(root, allowlist, hidden=(), overlays=None, allow_missing=False):
    """Return one message per shadowing file, or an empty list.

    ``root`` holds meshcentral-data and meshcentral-web. ``hidden`` lists relative paths whose host
    content is covered by a verified release mount, so MeshCentral never sees it. ``overlays`` maps a
    relative folder to the host folder mounted in its place, which is scanned instead.
    """
    problems = (_problem(kind, relative, path, allowlist)
                for kind, relative, path in _governed_entries(root, hidden, overlays, allow_missing))
    return [problem for problem in problems if problem]


def check(root, allowlist, hidden=(), overlays=None, allow_missing=False):
    """Raise ShadowCopyError naming every shadowing file; return None when there are none."""
    problems = find_shadow_files(root, allowlist, hidden, overlays, allow_missing)
    if problems:
        raise ShadowCopyError('Shadow copies would override the MeshCentral package under ' + str(root) +
                              '. Remove them, or list them with their sha256 in the release manifest '
                              'shadowAllowlist:\n  ' + '\n  '.join(problems))


def snapshot(root):
    """Return {relative path: sha256} of every governed file of a host installation.

    Used as the explicit allowlist that restoring that installation is checked against. Refuses
    an installation with entries an allowlist cannot express (links, special files, empty folders
    that hide the package), naming each.
    """
    allowlist, problems = {}, []
    for kind, relative, path in _governed_entries(root, allow_missing=True):
        if kind == 'file':
            allowlist[relative] = _sha256(path)
        else:
            problems.append(_problem(kind, relative, path, {}))
    if problems:
        raise ShadowCopyError('Cannot record the shadow copies of ' + str(root) + ':\n  ' + '\n  '.join(problems))
    return allowlist


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--root', type=Path, required=True, help='folder holding meshcentral-data and meshcentral-web')
    parser.add_argument('--manifest', type=Path, required=True, help='release manifest.json with shadowAllowlist')
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
    try:
        check(args.root, parse_allowlist(manifest.get('shadowAllowlist', [])))
    except ShadowCopyError as error:
        print(error, file=sys.stderr)
        return 1
    print('No shadow copies under ' + str(args.root))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
