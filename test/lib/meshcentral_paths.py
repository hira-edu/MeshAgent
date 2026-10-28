"""The one way MeshAgent tests locate the MeshCentral fork checkout and its installed npm package.

test/lib/meshcentral_paths.js implements the same rules for the Node tests; keep them in step.

MeshCentral root:  MESHCENTRAL_ROOT when set (it must exist and look like the fork), otherwise the
                   sibling <MeshAgent root>/../MeshCentral, where the MeshAgent root is two levels
                   above this file. Worktrees under MeshAgent/.claude/worktrees have no sibling, so
                   they must set MESHCENTRAL_ROOT. Nothing missing is ever returned.
Installed package: <root>/deploy/node_modules/meshcentral, installed by the deployment wrapper
                   (Stage 1). A package at <root>/node_modules/meshcentral is a stale install from
                   before Stage 1 and is refused, because Node would resolve it first from the root.
Fork files:        files of the fork package at the repo root, such as meshagent.js.
Upstream package:  the stock npm package pinned in meshcentral_upstream_reference.json, extracted
                   into a git-ignored cache by test/lib/fetch_upstream_reference.py and verified
                   against the pinned tree digest on first use. Tests that compare the fork with
                   stock upstream read it here; since Stage 1 the installed package is the fork.

Every function takes optional env and meshagent_root arguments so the helper's own tests can point
it at temporary layouts; tests should call them without arguments.

Import from a test in test/:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
    import meshcentral_paths
"""
import json
import os
from pathlib import Path

MESHAGENT_ROOT = Path(__file__).resolve().parents[2]

# Files every MeshCentral fork checkout has at its root, before and after the Stage 1 restructure.
ROOT_MARKERS = (("meshagent.js", "file"), ("agents", "directory"))

# The installed package, relative to the MeshCentral root (Stage 1 layout).
PACKAGE_DIR = Path("deploy") / "node_modules" / "meshcentral"
# The pre-Stage-1 location. It is never used: its presence is an error (see installed_package_dir).
STALE_ROOT_PACKAGE_DIR = Path("node_modules") / "meshcentral"


class MeshCentralPathError(RuntimeError):
    pass


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
    """Return the absolute folder of the installed meshcentral npm package.

    Raises MeshCentralPathError when it is missing, is not the meshcentral package, or a stale
    pre-Stage-1 install sits at the root.
    """
    env = os.environ if env is None else env
    root = meshcentral_root(env, meshagent_root)
    stale = root / STALE_ROOT_PACKAGE_DIR
    if _exists(stale):
        how = (f"MESHCENTRAL_ROOT points at {root}" if env.get("MESHCENTRAL_ROOT")
               else f"MESHCENTRAL_ROOT is not set, so the sibling checkout {root} is used")
        raise MeshCentralPathError(
            f"Stale pre-Stage-1 meshcentral install at {stale} ({how}). Since Stage 1 the package is "
            f"installed only at {root / PACKAGE_DIR}. Set MESHCENTRAL_ROOT to a MeshCentral checkout or "
            f"worktree without a root node_modules, or remove {root / 'node_modules'}.")
    directory = root / PACKAGE_DIR
    if not _exists(directory):
        raise MeshCentralPathError(
            f"Installed meshcentral package not found at {directory}. Install the wrapper dependencies "
            f"(npm ci in {root / WRAPPER_DIR}).")
    if not directory.is_dir():
        raise MeshCentralPathError(f"Installed meshcentral package path {directory} is not a directory.")
    manifest_path = directory / "package.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise MeshCentralPathError(
            f"Installed meshcentral package has no readable package.json at {manifest_path}: {error}") from error
    if manifest.get("name") != "meshcentral":
        raise MeshCentralPathError(
            f"Installed package at {directory} is named {json.dumps(manifest.get('name'))}, not \"meshcentral\".")
    return directory


# The deployment wrapper (Stage 1 layout): <root>/deploy, whose package.json is named
# meshcentral-deploy. It holds the wrapper package.json and lockfile, deploy/node_modules,
# meshcentral-web (custom.js), scripts/ and the config template. Before Stage 1 these sat at the
# repo root, where no wrapper is accepted: tests that read wrapper files need the Stage 1 layout.
WRAPPER_DIR = "deploy"
WRAPPER_PACKAGE_NAME = "meshcentral-deploy"


def wrapper_dir(env=None, meshagent_root=None):
    """Return <root>/deploy after checking its package.json is the meshcentral-deploy wrapper."""
    directory = meshcentral_root(env, meshagent_root) / WRAPPER_DIR
    manifest_path = directory / "package.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise MeshCentralPathError(
            f"MeshCentral deployment wrapper not found: {manifest_path} is not a readable package.json ({error}). "
            "These files moved under deploy/ in Stage 1; point MESHCENTRAL_ROOT at a checkout with the Stage 1 "
            "layout.") from error
    if manifest.get("name") != WRAPPER_PACKAGE_NAME:
        raise MeshCentralPathError(
            f"MeshCentral deployment wrapper {manifest_path} is named {json.dumps(manifest.get('name'))}, "
            f"not \"{WRAPPER_PACKAGE_NAME}\".")
    return directory


def wrapper_file(rel, env=None, meshagent_root=None):
    """Return the absolute path of a file inside the deployment wrapper (existence is the caller's check)."""
    if not isinstance(rel, (str, Path)) or str(rel) == "" or Path(rel).is_absolute() or Path(rel).drive:
        raise MeshCentralPathError(
            f"wrapper_file needs a relative path inside the deployment wrapper, got {rel!r}")
    directory = wrapper_dir(env, meshagent_root)
    target = Path(os.path.abspath(directory / rel))
    try:
        relative = target.relative_to(directory)
    except ValueError:
        relative = None
    if relative is None or str(relative) in ("", ".") or relative.parts[0] == "..":
        raise MeshCentralPathError(f"wrapper_file path {rel!r} leaves the deployment wrapper {directory}")
    return target


REFERENCE_PIN_PATH = Path(__file__).resolve().parent / "meshcentral_upstream_reference.json"
UPSTREAM_CACHE_ENV = "MESHCENTRAL_UPSTREAM_CACHE"
FETCH_COMMAND = "python test/lib/fetch_upstream_reference.py"
REFERENCE_MARKER = "reference.json"


def load_reference_pin(pin_path=None):
    """Return the pinned upstream package description (name, version, tarball, integrity, treeDigest)."""
    pin_path = Path(pin_path or REFERENCE_PIN_PATH)
    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise MeshCentralPathError(f"Cannot read the upstream reference pin {pin_path}: {error}") from error
    for key in ("name", "version", "tarball", "integrity", "treeDigest", "fileCount"):
        if not pin.get(key):
            raise MeshCentralPathError(f"Upstream reference pin {pin_path} has no {key}")
    if not str(pin["integrity"]).startswith("sha512-") or not str(pin["treeDigest"]).startswith("sha256:"):
        raise MeshCentralPathError(f"Upstream reference pin {pin_path} needs a sha512- integrity and a sha256: treeDigest")
    return pin


def upstream_cache_root(env=None, meshagent_root=None):
    """Return the folder that holds extracted upstream references (MESHCENTRAL_UPSTREAM_CACHE, or
    <MeshAgent root>/artifacts/meshcentral-upstream, which git ignores)."""
    env = os.environ if env is None else env
    from_env = env.get(UPSTREAM_CACHE_ENV)
    if from_env:
        return Path(os.path.abspath(from_env))
    return Path(os.path.abspath(Path(meshagent_root or MESHAGENT_ROOT) / "artifacts" / "meshcentral-upstream"))


def reference_dir(pin, env=None, meshagent_root=None):
    """Return <cache>/<name>-<version>, which holds package/ and reference.json."""
    return upstream_cache_root(env, meshagent_root) / f"{pin['name']}-{pin['version']}"


def _walk_tree(root):
    entries = []
    stack = [root]
    while stack:
        current = stack.pop()
        with os.scandir(current) as listing:
            for entry in listing:
                full = Path(entry.path)
                if entry.is_symlink():
                    raise MeshCentralPathError(f"Upstream reference holds a link, which a package never has: {full}")
                if entry.is_dir(follow_symlinks=False):
                    stack.append(full)
                elif entry.is_file(follow_symlinks=False):
                    entries.append(full.relative_to(root).as_posix())
                else:
                    raise MeshCentralPathError(f"Upstream reference holds a non-regular file: {full}")
    return entries


def tree_digest(root):
    """Return (digest, file_count) for a package tree.

    The digest is sha256 over one line per regular file, "<sha256 hex> <size> <posix path>\\n",
    sorted by the UTF-8 bytes of the path. test/lib/meshcentral_paths.js computes the same value.
    """
    import hashlib
    root = Path(root)
    paths = sorted(_walk_tree(root), key=lambda rel: rel.encode("utf-8"))
    outer = hashlib.sha256()
    for rel in paths:
        inner = hashlib.sha256()
        size = 0
        with open(root / rel, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                inner.update(chunk)
                size += len(chunk)
        outer.update(f"{inner.hexdigest()} {size} {rel}\n".encode("utf-8"))
    return "sha256:" + outer.hexdigest(), len(paths)


_VERIFIED_UPSTREAM = {}


def upstream_package_dir(env=None, meshagent_root=None, pin_path=None):
    """Return the extracted, verified stock upstream package pinned in meshcentral_upstream_reference.json.

    The cache is populated only by test/lib/fetch_upstream_reference.py; this function never uses
    the network. It raises MeshCentralPathError, naming the command to run, when the cache is
    missing, was made from another pin, or its tree no longer matches the pinned digest.
    """
    pin = load_reference_pin(pin_path)
    ref_dir = reference_dir(pin, env, meshagent_root)
    package = ref_dir / "package"
    label = f"pinned upstream {pin['name']} {pin['version']} reference"
    hint = f"Populate it with: {FETCH_COMMAND}"
    if UPSTREAM_CACHE_ENV in (env if env is not None else os.environ):
        hint += f" (with the same {UPSTREAM_CACHE_ENV})"
    key = (str(package), pin["treeDigest"])
    if key in _VERIFIED_UPSTREAM:
        return package
    if not package.is_dir():
        raise MeshCentralPathError(f"The {label} is missing: {package} does not exist. {hint}")
    marker_path = ref_dir / REFERENCE_MARKER
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise MeshCentralPathError(f"The {label} at {ref_dir} has no readable {REFERENCE_MARKER}: {error}. {hint}") from error
    for field in ("name", "version", "integrity", "treeDigest"):
        if marker.get(field) != pin[field]:
            raise MeshCentralPathError(
                f"The {label} at {ref_dir} was made from another pin ({field} {marker.get(field)!r}, pinned "
                f"{pin[field]!r}). {hint}")
    digest, count = tree_digest(package)
    if digest != pin["treeDigest"] or count != pin["fileCount"]:
        raise MeshCentralPathError(
            f"The {label} at {package} fails its integrity check: tree {digest} with {count} files, pinned "
            f"{pin['treeDigest']} with {pin['fileCount']} files. {hint}")
    try:
        manifest = json.loads((package / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise MeshCentralPathError(f"The {label} has no readable package.json: {error}. {hint}") from error
    if manifest.get("name") != pin["name"] or manifest.get("version") != pin["version"]:
        raise MeshCentralPathError(
            f"The {label} package.json is {manifest.get('name')}@{manifest.get('version')}. {hint}")
    _VERIFIED_UPSTREAM[key] = True
    return package


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
