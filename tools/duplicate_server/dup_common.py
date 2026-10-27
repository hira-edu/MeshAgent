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
DENYLIST_PATH = DUP_ROOT / "denylist.json"

# Pinned runtimes (production 2026-10-27: Node 20.20.2, MongoDB 7.0.31).
NODE_VERSION = "20.20.2"
NODE_ZIP = f"node-v{NODE_VERSION}-win-x64.zip"
NODE_URL = f"https://nodejs.org/dist/v{NODE_VERSION}/{NODE_ZIP}"
NODE_SHASUMS_URL = f"https://nodejs.org/dist/v{NODE_VERSION}/SHASUMS256.txt"
NODE_ZIP_SHA256 = "dc3700fdd57a63eedb8fd7e3c7baaa32e6a740a1b904167ff4204bc68ed8bf77"
NODE_HOME = TOOLS / f"node-v{NODE_VERSION}-win-x64"
NODE_EXE = NODE_HOME / "node.exe"
NPM_CLI = NODE_HOME / "node_modules" / "npm" / "bin" / "npm-cli.js"

MONGO_VERSION = "7.0.31"
MONGO_ZIP = f"mongodb-windows-x86_64-{MONGO_VERSION}.zip"
MONGO_URL = f"https://fastdl.mongodb.org/windows/{MONGO_ZIP}"
MONGO_SHA_URL = MONGO_URL + ".sha256"
MONGO_ZIP_SHA256 = "3b19606c87d20ab2ef8d5dc802b455088d8408624fcb7d45de140af6d753e09a"
MONGO_HOME = TOOLS / f"mongodb-win32-x86_64-windows-{MONGO_VERSION}"
MONGOD_EXE = MONGO_HOME / "bin" / "mongod.exe"
MONGO_HOST = "127.0.0.1"
MONGO_PORT = 27018

MESHCENTRAL_VERSION = "1.2.5"

# Sibling inputs (read-only).
SSOT_ROOT = Path(os.environ.get("MC_DUP_SSOT", r"C:\Users\Workstation\Documents\GitHub\meshcentral-fork-ssot"))
EVIDENCE = SSOT_ROOT / "evidence"
LAYOUT_A_TAR = EVIDENCE / "production-layout-a" / "layout-a.tar"
PRODUCTION_HASHES = EVIDENCE / "live" / "hashes.tsv"
PRODUCTION_SUMMARY = EVIDENCE / "live" / "summary.txt"
PRODUCTION_UNTRACKED = EVIDENCE / "production-untracked"

LAYOUTS = {
    "A": {"port": 4431, "mpsport": None, "db": "meshcentral_dupA", "cert": "mc-dup-a.localhost"},
    "B": {"port": 4432, "mpsport": 4434, "db": "meshcentral_dupB", "cert": "mc-dup-b.localhost"},
}


class DupError(RuntimeError):
    """A duplicate-server step failed; the message says which and why."""


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


def node_env(extra=None):
    """Environment for the pinned Node; PATH is changed for the child only."""
    env = dict(os.environ)
    env["PATH"] = str(NODE_HOME) + os.pathsep + env.get("PATH", "")
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


def npm(args, cwd, timeout=1800):
    if not NPM_CLI.is_file():
        raise DupError(f"Pinned npm is missing at {NPM_CLI}; run setup first")
    return run([NODE_EXE, NPM_CLI] + list(args), cwd=cwd, env=node_env(), timeout=timeout)


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
