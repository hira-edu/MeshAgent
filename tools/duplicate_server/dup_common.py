"""Shared paths, pins and helpers for the local duplicate MeshCentral server.

Everything the duplicate runs lives under one runtime root (default C:\\mc-dup).
Nothing here installs services, edits PATH, or talks to the production server.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
WORKTREE_ROOT = TOOL_DIR.parents[1]

# Runtime root. MC_DUP_ROOT exists for the contract tests, which use a temp dir.
DUP_ROOT = Path(os.environ.get("MC_DUP_ROOT", r"C:\mc-dup"))
ROOT_MARKER = ".mc-dup-root"
DOWNLOADS = DUP_ROOT / "downloads"
TOOLS = DUP_ROOT / "tools"
MONGO_DIR = DUP_ROOT / "mongo"
MONGO_DATA = MONGO_DIR / "data"
SECRETS = DUP_ROOT / "secrets"
RUN_DIR = DUP_ROOT / "run"
REPORTS = DUP_ROOT / "reports"


def layout_reports(layout):
    """The report files of one layout: names with "-<layout>-" or ending "-<layout>.json".

    Matched case-sensitively in Python: a Windows glob such as "*-B*" ignores case and would also
    match layout A's "manifest-A-built.json"."""
    import re
    pattern = re.compile(r"-" + re.escape(layout) + r"(-|\.json$)")
    if not REPORTS.exists():
        return []
    return sorted(path for path in REPORTS.glob("*.json") if pattern.search(path.name))
DENYLIST_PATH = DUP_ROOT / "denylist.json"

# Pinned Node runtimes, one per layout (LAYOUTS[...]["node"]). Each win-x64 zip must match both
# nodejs.org's SHASUMS256.txt for that release and the sha256 recorded here.
#   20.20.2: production until the Stage 4 cutover (2026-10-27 inventory); layout A.
#   24.22.1: the fork at MeshCentral 1.3.1 (operator, 2026-10-29: upstream's own image is node:24.22.1,
#            and 1.3.1's autobackup needs Node 22+ for fs.promises.glob); layout B.
NODE_RUNTIMES = {
    "20.20.2": "dc3700fdd57a63eedb8fd7e3c7baaa32e6a740a1b904167ff4204bc68ed8bf77",
    "24.22.1": "d2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5",
}


class NodeRuntime:
    """Paths and download facts of one pinned portable Node under the runtime root."""

    def __init__(self, version):
        if version not in NODE_RUNTIMES:
            raise DupError(f"Node {version} is not a pinned runtime; pinned: {sorted(NODE_RUNTIMES)}")
        self.version = version
        self.zip = f"node-v{version}-win-x64.zip"
        self.url = f"https://nodejs.org/dist/v{version}/{self.zip}"
        self.shasums_url = f"https://nodejs.org/dist/v{version}/SHASUMS256.txt"
        self.zip_sha256 = NODE_RUNTIMES[version]
        self.home = TOOLS / f"node-v{version}-win-x64"
        self.exe = self.home / "node.exe"
        self.npm_cli = self.home / "node_modules" / "npm" / "bin" / "npm-cli.js"


MONGO_VERSION = "7.0.31"
MONGO_ZIP = f"mongodb-windows-x86_64-{MONGO_VERSION}.zip"
MONGO_URL = f"https://fastdl.mongodb.org/windows/{MONGO_ZIP}"
MONGO_SHA_URL = MONGO_URL + ".sha256"
MONGO_ZIP_SHA256 = "3b19606c87d20ab2ef8d5dc802b455088d8408624fcb7d45de140af6d753e09a"
MONGO_HOME = TOOLS / f"mongodb-win32-x86_64-windows-{MONGO_VERSION}"
MONGOD_EXE = MONGO_HOME / "bin" / "mongod.exe"
# MongoDB Database Tools (mongodump) for MeshCentral's autobackup. The publisher's checksum is the sha256
# in its release feed (downloads.mongodb.org/tools/db/release.json); the zip must match it and the pin.
MONGO_TOOLS_VERSION = "100.20.0"
MONGO_TOOLS_ZIP = f"mongodb-database-tools-windows-x86_64-{MONGO_TOOLS_VERSION}.zip"
MONGO_TOOLS_URL = f"https://fastdl.mongodb.org/tools/db/{MONGO_TOOLS_ZIP}"
MONGO_TOOLS_FEED_URL = "https://downloads.mongodb.org/tools/db/release.json"
MONGO_TOOLS_ZIP_SHA256 = "b65a32595db38cdf0f413d53cac440c4a6ddac0d224405b550e4100535bdd5ca"
MONGO_TOOLS_HOME = TOOLS / f"mongodb-database-tools-windows-x86_64-{MONGO_TOOLS_VERSION}"
MONGODUMP_EXE = MONGO_TOOLS_HOME / "bin" / "mongodump.exe"
MONGO_HOST = "127.0.0.1"
MONGO_PORT = 27018

# The stock npm MeshCentral production runs until the Stage 4 cutover (layout A).
MESHCENTRAL_VERSION = "1.2.5"

# Sibling inputs (read-only).
SSOT_ROOT = Path(os.environ.get("MC_DUP_SSOT", r"C:\Users\Workstation\Documents\GitHub\meshcentral-fork-ssot"))
EVIDENCE = SSOT_ROOT / "evidence"
LAYOUT_A_TAR = EVIDENCE / "production-layout-a" / "layout-a.tar"
PRODUCTION_HASHES = EVIDENCE / "live" / "hashes.tsv"
PRODUCTION_SUMMARY = EVIDENCE / "live" / "summary.txt"
EXTRA_VALUES_PATH = EVIDENCE / "live" / "config-extra-values.json"
LAYOUT_A_MODULES_TAR = EVIDENCE / "production-layout-a" / "layout-a-modules-posix.tar"
PRODUCTION_UNTRACKED = EVIDENCE / "production-untracked"

# A: production as it runs until the Stage 4 cutover (stock 1.2.5 on Node 20).
# B: the fork package as Stage 6 landed it (MeshCentral 1.3.1 plus the fork, on Node 24).
LAYOUTS = {
    "A": {"port": 4431, "mpsport": None, "db": "meshcentral_dupA", "cert": "mc-dup-a.localhost", "node": "20.20.2"},
    "B": {"port": 4432, "mpsport": 4434, "db": "meshcentral_dupB", "cert": "mc-dup-b.localhost", "node": "24.22.1"},
}


class DupError(RuntimeError):
    """A duplicate-server step failed; the message says which and why."""


def layout_node(name):
    """The pinned Node runtime a layout runs on (LAYOUTS[name]["node"])."""
    if name not in LAYOUTS:
        raise DupError(f"Unknown layout {name!r}; expected one of {sorted(LAYOUTS)}")
    return NodeRuntime(LAYOUTS[name]["node"])


def node_runtimes():
    """Every pinned runtime some layout uses, in version order."""
    return [NodeRuntime(version) for version in sorted({cfg["node"] for cfg in LAYOUTS.values()})]


def layout_root(name):
    if name not in LAYOUTS:
        raise DupError(f"Unknown layout {name!r}; expected one of {sorted(LAYOUTS)}")
    return DUP_ROOT / name


def log(message):
    print(message, flush=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def read_json(path):
    path = Path(path)
    if not path.is_file():
        raise DupError(f"Required file is missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


SECRET_FLAGS = ("--pass", "--hashpass")


def run(command, cwd=None, env=None, timeout=1800, capture=False):
    """Run a command and fail with its output when it exits non-zero."""
    shown = [str(part) for part in command]
    for index, part in enumerate(shown[:-1]):
        if part in SECRET_FLAGS:
            shown[index + 1] = "***"
    log("  $ " + " ".join(shown))
    result = subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd) if cwd else None,
        env=env,
        timeout=timeout,
        capture_output=capture,
        text=True,
    )
    if result.returncode != 0:
        detail = ""
        if capture:
            detail = "\n" + (result.stdout or "") + (result.stderr or "")
        raise DupError(f"Command failed with exit code {result.returncode}: {command[0]} {command[1:3]}{detail}")
    return result


def node_env(runtime, extra=None):
    """Environment for a pinned Node runtime; PATH is changed for the child only."""
    env = dict(os.environ)
    env["PATH"] = str(runtime.home) + os.pathsep + env.get("PATH", "")
    env.pop("NODE_OPTIONS", None)
    # Keep npm's cache inside the runtime root so teardown removes it.
    env["npm_config_cache"] = str(DUP_ROOT / "npm-cache")
    env["npm_config_update_notifier"] = "false"
    env["npm_config_fund"] = "false"
    env["npm_config_audit"] = "false"
    # The registry connection here drops intermittently; let npm retry fetches before failing.
    env["npm_config_fetch_retries"] = "6"
    env["npm_config_fetch_retry_mintimeout"] = "5000"
    env["npm_config_fetch_retry_maxtimeout"] = "120000"
    if extra:
        env.update(extra)
    return env


def npm(runtime, args, cwd, timeout=1800):
    """npm as shipped with a pinned Node runtime (each layout installs with its own Node and npm)."""
    if not runtime.npm_cli.is_file():
        raise DupError(f"Pinned npm is missing at {runtime.npm_cli}; run setup first")
    return run([runtime.exe, runtime.npm_cli] + list(args), cwd=cwd, env=node_env(runtime), timeout=timeout)


def require_root_marker():
    marker = DUP_ROOT / ROOT_MARKER
    if not marker.is_file():
        raise DupError(f"{DUP_ROOT} is not a duplicate-server root (missing {ROOT_MARKER}); run setup first")


def create_root():
    DUP_ROOT.mkdir(parents=True, exist_ok=True)
    marker = DUP_ROOT / ROOT_MARKER
    if not marker.exists():
        marker.write_text("Created by MeshAgent tools/duplicate_server. teardown deletes this whole folder.\n", encoding="utf-8")


def safe_root_for_delete():
    """Return the runtime root only when it is unmistakably ours."""
    root = DUP_ROOT.resolve()
    if root.parent == root or len(root.parts) < 2:
        raise DupError(f"Refusing to delete a drive root: {root}")
    for protected in (WORKTREE_ROOT.resolve(), SSOT_ROOT.resolve(), Path.home().resolve()):
        if root == protected or protected.is_relative_to(root):
            raise DupError(f"Refusing to delete {root}: it contains {protected}")
    if not (root / ROOT_MARKER).is_file():
        raise DupError(f"Refusing to delete {root}: missing {ROOT_MARKER}")
    return root


def ensure_windows():
    if sys.platform != "win32":
        raise DupError("The duplicate server tooling targets Windows (portable win-x64 Node and MongoDB)")
