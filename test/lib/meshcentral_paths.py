"""The one way MeshAgent tests locate the MeshCentral fork checkout and its installed npm package.

test/lib/meshcentral_paths.js implements the same rules for the Node tests; keep them in step.

MeshCentral root:  MESHCENTRAL_ROOT when set (it must exist and look like the fork), otherwise the
                   sibling <MeshAgent root>/../MeshCentral, where the MeshAgent root is two levels
                   above this file. Worktrees under MeshAgent/.claude/worktrees have no sibling, so
                   they must set MESHCENTRAL_ROOT. Nothing missing is ever returned.
Installed package: one of the named layouts in PACKAGE_LAYOUTS. Exactly one must exist.
Fork files:        files of the fork package at the repo root, such as meshagent.js.

Every function takes optional env and meshagent_root arguments so the helper's own tests can point
it at temporary layouts; tests should call them without arguments.

Import from a test in test/:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
    import meshcentral_paths
"""
import json
import os
from pathlib import Path
from typing import NamedTuple

MESHAGENT_ROOT = Path(__file__).resolve().parents[2]

# Files every MeshCentral fork checkout has at its root, before and after the Stage 1 restructure.
ROOT_MARKERS = (("meshagent.js", "file"), ("agents", "directory"))

PACKAGE_LAYOUTS = (
    # The wrapper's package.json and node_modules at the repo root (before Stage 1).
    ("wrapper-root", Path("node_modules") / "meshcentral"),
    # The wrapper moved under deploy/ (Stage 1).
    ("deploy", Path("deploy") / "node_modules" / "meshcentral"),
)


class MeshCentralPathError(RuntimeError):
    pass


class InstalledPackage(NamedTuple):
    layout: str
    path: Path


def _exists(target):
    try:
        target.stat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as error:
        raise MeshCentralPathError(f"Cannot inspect {target}: {error}") from error
    return True


def _check_root(root, source):
    hint = "Set MESHCENTRAL_ROOT to the MeshCentral fork checkout."
    if not _exists(root):
        raise MeshCentralPathError(f"MeshCentral checkout not found at {root} ({source}). {hint}")
    if not root.is_dir():
        raise MeshCentralPathError(f"MeshCentral path {root} ({source}) is not a directory. {hint}")
    missing = [
        f"{rel} ({kind})"
        for rel, kind in ROOT_MARKERS
        if not ((root / rel).is_file() if kind == "file" else (root / rel).is_dir())
    ]
    if missing:
        raise MeshCentralPathError(
            f"MeshCentral path {root} ({source}) does not look like the MeshCentral fork: missing "
            f"{', '.join(missing)}. {hint}")
    return root


def meshcentral_root(env=None, meshagent_root=None):
    """Return the absolute MeshCentral checkout root, or raise MeshCentralPathError."""
    env = os.environ if env is None else env
    meshagent_root = Path(os.path.abspath(meshagent_root or MESHAGENT_ROOT))
    from_env = env.get("MESHCENTRAL_ROOT")
    if from_env:
        return _check_root(Path(os.path.abspath(from_env)), "from MESHCENTRAL_ROOT")
    return _check_root(Path(os.path.abspath(meshagent_root.parent / "MeshCentral")),
                       f"sibling of the MeshAgent root {meshagent_root}; MESHCENTRAL_ROOT is not set")


def installed_package_dir(env=None, meshagent_root=None):
    """Return InstalledPackage(layout, path) for the installed meshcentral npm package.

    Raises MeshCentralPathError when neither layout or both layouts are present.
    """
    root = meshcentral_root(env, meshagent_root)
    candidates = [InstalledPackage(name, root / rel) for name, rel in PACKAGE_LAYOUTS]
    describe = " and ".join(f"{c.layout} ({c.path})" for c in candidates)
    present = [c for c in candidates if _exists(c.path)]
    if not present:
        raise MeshCentralPathError(
            f"Installed meshcentral package not found: neither {describe} exists. Install the wrapper dependencies.")
    if len(present) > 1:
        raise MeshCentralPathError(
            f"Installed meshcentral package is ambiguous: both {describe} exist. Remove the stale layout.")
    found = present[0]
    if not found.path.is_dir():
        raise MeshCentralPathError(
            f"Installed meshcentral package path {found.path} (layout {found.layout}) is not a directory.")
    manifest_path = found.path / "package.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise MeshCentralPathError(
            f"Installed meshcentral package (layout {found.layout}) has no readable package.json at "
            f"{manifest_path}: {error}") from error
    if manifest.get("name") != "meshcentral":
        raise MeshCentralPathError(
            f"Installed package at {found.path} (layout {found.layout}) is named "
            f"{json.dumps(manifest.get('name'))}, not \"meshcentral\".")
    return found


def fork_file(rel, env=None, meshagent_root=None):
    """Return the absolute path of a fork package file at the MeshCentral repo root.

    The root is validated; whether the file itself must exist is the caller's check, because some
    inputs are optional.
    """
    if not isinstance(rel, (str, Path)) or str(rel) == "" or Path(rel).is_absolute() or Path(rel).drive:
        raise MeshCentralPathError(
            f"fork_file needs a relative path inside the MeshCentral checkout, got {rel!r}")
    root = meshcentral_root(env, meshagent_root)
    target = Path(os.path.abspath(root / rel))
    try:
        relative = target.relative_to(root)
    except ValueError:
        relative = None
    if relative is None or str(relative) in ("", ".") or relative.parts[0] == "..":
        raise MeshCentralPathError(f"fork_file path {rel!r} leaves the MeshCentral checkout {root}")
    return target
