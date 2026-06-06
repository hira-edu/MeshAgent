#!/usr/bin/env python3
"""
MeshAgent Deployment Tool
=========================
End-to-end staging, deployment, rollback, and remote management for MeshCentral agents.

Usage:
    python deploy.py status          - Server status, service health, disk, agents
    python deploy.py stage           - Upload build artifacts to staging area
    python deploy.py deploy          - Backup current → move staged → rehash → restart
    python deploy.py rollback        - Restore previous agent backup
    python deploy.py config          - View current MeshCentral config
    python deploy.py config edit     - Download config, open in editor, upload, restart
    python deploy.py logs [N]        - Tail last N lines of MeshCentral logs
    python deploy.py health          - Post-deploy health check
    python deploy.py ssh <command>   - Run arbitrary command on server
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def resolve_ssh_config_path():
    """Return an operator-specified SSH config or a known local failover config if present."""
    configured = os.environ.get("MESHCENTRAL_SSH_CONFIG")
    if configured:
        return configured
    candidate = Path(tempfile.gettempdir()) / "meshcentral_proxy_failover.sshconfig"
    if candidate.exists():
        return str(candidate)
    return None


# ─── Server Configuration ────────────────────────────────────────────────────

SERVER = os.environ.get("MESHCENTRAL_SERVER", "")
USER = os.environ.get("MESHCENTRAL_USER", "root")
SSH_KEY = os.path.expanduser("~/.ssh/id_ed25519")
SSH_CONFIG_PATH = resolve_ssh_config_path()
SSH_HOST = os.environ.get("MESHCENTRAL_SSH_HOST", "meshcentral")

# Remote paths
MESHCENTRAL_BASE = "/opt/meshcentral"
DATA_AGENTS = f"{MESHCENTRAL_BASE}/meshcentral-data/agents"
SIGNED_AGENTS = f"{MESHCENTRAL_BASE}/meshcentral-data/signedagents"
MODULE_AGENTS = f"{MESHCENTRAL_BASE}/node_modules/meshcentral/agents"
CONFIG_FILE = f"{MESHCENTRAL_BASE}/meshcentral-data/config.json"
STAGING_DIR = f"{MESHCENTRAL_BASE}/staging"
BACKUP_DIR = f"{MESHCENTRAL_BASE}/backups"
SERVICE_NAME = "meshcentral"
SVCHOST_EMBEDDED_RESOURCE_ID = 101
SVCHOST_EMBEDDED_RESOURCE_TYPE = 10

PUBLISH_ROLE_DIRS = {
    "data": DATA_AGENTS,
    "signed": SIGNED_AGENTS,
    "module": MODULE_AGENTS,
}
PUBLISH_ROLE_BACKUP_DIRS = {
    "data": "dataagents",
    "signed": "signedagents",
    "module": "moduleagents",
}
HASHAGENTS_MANIFEST_ROLES = ("module", "signed")

# Local build artifacts to deploy
LOCAL_REPO = Path(__file__).parent.resolve()
LOCAL_MESHCENTRAL_REPO = LOCAL_REPO.parent / "MeshCentral"
LOCAL_USERMODEHOOK_REPO = LOCAL_REPO.parent / "UserModeHook"
MANIFEST_DIR = LOCAL_REPO / "docs" / "testing" / "artifacts"
ARTIFACTS = {
    # "friendly name": {"local_path": ..., "remote_filename": ..., "publish_targets": (...)}
    "MeshService64.exe": {
        "local_path": "meshservice/x64/StealthLab/MeshService-2022.exe",
        "remote_filename": "MeshService64.exe",
        "publish_targets": ("data", "signed", "module"),
    },
    "MeshService.exe": {
        "local_path": "meshservice/StealthLab/MeshService-2022.exe",
        "remote_filename": "MeshService.exe",
        "publish_targets": ("data", "signed", "module"),
    },
    "MeshService64.dll": {
        "local_path": "meshservice/x64/StealthLab_DLL/MeshService-2022.dll",
        "remote_filename": "MeshService64.dll",
        "publish_targets": ("signed", "module"),
    },
    "svchost_payload.dll": {
        "local_path": "meshservice/embedded/svchost_payload.dll",
        "remote_filename": "svchost_payload.dll",
        "publish_targets": ("signed", "module"),
    },
    "diagsvc.dll": {
        "local_path": "meshservice/x64/StealthLab_DLL/MeshService-2022.dll",
        "remote_filename": "diagsvc.dll",
        "publish_targets": ("data",),
    },
    "MeshService64.msh": {
        "local_path": "meshservice/x64/StealthLab/MeshService-2022.msh",
        "remote_filename": "MeshService64.msh",
        "publish_targets": ("data", "signed", "module"),
    },
    "MeshService.msh": {
        "local_path": "meshservice/StealthLab/MeshService-2022.msh",
        "remote_filename": "MeshService.msh",
        "publish_targets": ("data", "signed", "module"),
    },
    "WinDiagnosticHost.msh": {
        "local_path": "WinDiagnosticHost.msh",
        "remote_filename": "WinDiagnosticHost.msh",
        "publish_targets": ("data", "signed", "module"),
    },
    "MasterService.exe": {
        "local_path": "../UserModeHook/build-fresh/bin/Release/MasterService.exe",
        "remote_filename": "MasterService.exe",
        "publish_targets": (),
    },
}

# Additional deploy target for MasterService (public userfiles for agent download)
_USERFILES_USER = os.environ.get("MESHCENTRAL_USERFILES_USER", "")
USERFILES_DIR = f"{MESHCENTRAL_BASE}/meshcentral-files/domain/user-{_USERFILES_USER}/Public" if _USERFILES_USER else ""
MESHCENTRAL_CONTROL_URL = os.environ.get("MESHCENTRAL_CONTROL_URL", "")
MESHCENTRAL_CONTROL_USER = os.environ.get("MESHCENTRAL_CONTROL_USER", "")
HASHAGENTS_TRACKED_FILENAMES = {"MeshService.exe", "MeshService64.exe"}
SIGNED_RUNTIME_MUTABLE_FILENAMES = set(HASHAGENTS_TRACKED_FILENAMES)
REQUIRED_AGENT_ARTIFACTS = {
    "MeshService64.exe",
    "MeshService.exe",
    "MeshService64.dll",
    "svchost_payload.dll",
    "diagsvc.dll",
    "MeshService64.msh",
    "MeshService.msh",
    "WinDiagnosticHost.msh",
}
WINDOWS_INSTALL_ROOT = os.environ.get("MESHCENTRAL_INSTALL_ROOT", r"C:\ProgramData\MeshAgent")
WINDOWS_UPDATE_PACKAGE_SUFFIX = ".update.pkg"
WINDOWS_LIFECYCLE_DLL = os.environ.get("MESHCENTRAL_LIFECYCLE_DLL", "")
WINDOWS_LIFECYCLE_STATE_DIR = os.environ.get("MESHCENTRAL_LIFECYCLE_STATE_DIR", r"%ProgramData%\MeshAgent\state\rundll32-lifecycle")
REMOTE_COMMAND_RETRIES = int(os.environ.get("MESHCENTRAL_SSH_RETRIES", "3"))
REMOTE_RETRY_DELAY_SECONDS = float(os.environ.get("MESHCENTRAL_SSH_RETRY_DELAY", "2"))
RETRYABLE_REMOTE_ERROR_SNIPPETS = (
    "connection timed out",
    "timed out",
    "banner exchange",
    "connection reset",
    "connection closed",
    "reset by peer",
    "broken pipe",
    "i/o timeout",
    "proxy error",
    "kex_exchange_identification",
)
REMOTE_PUBLISH_VERIFICATION_TRANSPORT_ERROR = "Remote publish verification unavailable: SSH transport failed"

# ─── SSH Helpers ──────────────────────────────────────────────────────────────

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    "-i", SSH_KEY,
]


def should_retry_remote_result(result):
    """Return True when an SSH-family process failed in a retryable transport way."""
    if result is None:
        return True
    if result.returncode == 0:
        return False
    stderr = (result.stderr or "").lower()
    stdout = (result.stdout or "").lower()
    combined = f"{stderr}\n{stdout}"
    if result.returncode == 255:
        return True
    return any(snippet in combined for snippet in RETRYABLE_REMOTE_ERROR_SNIPPETS)


def run_remote_process(full_cmd, timeout):
    """Run an SSH-family process with retries for transient transport failures."""
    last_result = None
    last_timeout = None
    attempts = max(1, REMOTE_COMMAND_RETRIES)
    for attempt in range(1, attempts + 1):
        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as ex:
            last_timeout = ex
            if attempt < attempts:
                time.sleep(REMOTE_RETRY_DELAY_SECONDS * attempt)
                continue
            return None, ex
        last_result = result
        if should_retry_remote_result(result) and attempt < attempts:
            time.sleep(REMOTE_RETRY_DELAY_SECONDS * attempt)
            continue
        return result, None
    return last_result, last_timeout


def build_remote_cmd(binary):
    """Build an SSH-family command honoring an optional external SSH config file."""
    cmd = [binary]
    if SSH_CONFIG_PATH:
        cmd.extend(["-F", SSH_CONFIG_PATH])
    cmd.extend(SSH_OPTS)
    return cmd


def get_remote_target():
    """Return the SSH target string for the configured deployment route."""
    return f"{USER}@{SSH_HOST}" if USER else SSH_HOST


def ssh_cmd(command, capture=True, check=True):
    """Execute a command on the remote server via SSH."""
    full_cmd = build_remote_cmd("ssh") + [get_remote_target(), command]
    result, timeout_error = run_remote_process(full_cmd, timeout=60)
    if timeout_error is not None:
        if check:
            print("[ERROR] Remote command timed out:")
            print(f"  CMD: {command}")
        return None
    if result is None:
        if check:
            print("[ERROR] Remote command failed without a result:")
            print(f"  CMD: {command}")
        return None
    if should_retry_remote_result(result):
        if check:
            print(f"[ERROR] Remote transport failed (exit {result.returncode}):")
            print(f"  CMD: {command}")
            if result.stderr:
                print(f"  STDERR: {result.stderr.strip()}")
        return None
    if check and result.returncode != 0:
        print(f"[ERROR] Remote command failed (exit {result.returncode}):")
        print(f"  CMD: {command}")
        if result.stderr:
            print(f"  STDERR: {result.stderr.strip()}")
        return None
    return result.stdout.strip() if capture else result


def scp_upload(local_path, remote_path):
    """Upload a file to the server via SCP."""
    full_cmd = build_remote_cmd("scp") + [str(local_path), f"{get_remote_target()}:{remote_path}"]
    result, timeout_error = run_remote_process(full_cmd, timeout=120)
    if timeout_error is not None:
        print(f"[ERROR] SCP upload timed out: {local_path} → {remote_path}")
        return False
    if result is None or should_retry_remote_result(result):
        print(f"[ERROR] SCP upload transport failed: {local_path} → {remote_path}")
        if result is not None and result.stderr:
            print(f"  STDERR: {result.stderr.strip()}")
        return False
    if result.returncode != 0:
        print(f"[ERROR] SCP upload failed: {local_path} → {remote_path}")
        print(f"  STDERR: {result.stderr.strip()}")
        return False
    return True


def scp_download(remote_path, local_path):
    """Download a file from the server via SCP."""
    full_cmd = build_remote_cmd("scp") + [f"{get_remote_target()}:{remote_path}", str(local_path)]
    result, timeout_error = run_remote_process(full_cmd, timeout=120)
    if timeout_error is not None:
        print(f"[ERROR] SCP download timed out: {remote_path} → {local_path}")
        return False
    if result is None or should_retry_remote_result(result):
        print(f"[ERROR] SCP download transport failed: {remote_path} → {local_path}")
        if result is not None and result.stderr:
            print(f"  STDERR: {result.stderr.strip()}")
        return False
    if result.returncode != 0:
        print(f"[ERROR] SCP download failed: {remote_path} → {local_path}")
        return False
    return True


def file_digest(path, algorithm="sha384"):
    """Return a hex digest for a local file."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def remote_digest(path, algorithm="sha384"):
    """Return a hex digest for a remote file or None if missing."""
    result = ssh_cmd(f"{algorithm}sum {path} 2>/dev/null || echo MISSING", check=False)
    if result and "MISSING" not in result:
        return result.split()[0]
    return None


def remote_size(path):
    """Return remote file size in bytes or None if missing."""
    result = ssh_cmd(f"stat -c %s {path} 2>/dev/null || echo MISSING", check=False)
    if result and "MISSING" not in result:
        try:
            return int(result.strip())
        except ValueError:
            return None
    return None


def extract_embedded_svchost_payload(exe_path):
    """Extract the embedded svchost DLL RCDATA payload from a Windows executable."""
    if os.name != "nt":
        raise RuntimeError("Embedded svchost payload extraction is only supported on Windows")

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    load_library_ex = kernel32.LoadLibraryExW
    load_library_ex.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    load_library_ex.restype = wintypes.HMODULE

    find_resource = kernel32.FindResourceW
    find_resource.argtypes = [wintypes.HMODULE, wintypes.LPCWSTR, wintypes.LPCWSTR]
    find_resource.restype = wintypes.HRSRC

    load_resource = kernel32.LoadResource
    load_resource.argtypes = [wintypes.HMODULE, wintypes.HRSRC]
    load_resource.restype = wintypes.HGLOBAL

    lock_resource = kernel32.LockResource
    lock_resource.argtypes = [wintypes.HGLOBAL]
    lock_resource.restype = wintypes.LPVOID

    size_of_resource = kernel32.SizeofResource
    size_of_resource.argtypes = [wintypes.HMODULE, wintypes.HRSRC]
    size_of_resource.restype = wintypes.DWORD

    free_library = kernel32.FreeLibrary
    free_library.argtypes = [wintypes.HMODULE]
    free_library.restype = wintypes.BOOL

    load_library_as_datafile = 0x00000002
    module = load_library_ex(str(exe_path), None, load_library_as_datafile)
    if not module:
        raise OSError(ctypes.get_last_error(), f"LoadLibraryExW failed for {exe_path}")

    try:
        resource = find_resource(
            module,
            ctypes.cast(ctypes.c_void_p(SVCHOST_EMBEDDED_RESOURCE_ID), wintypes.LPCWSTR),
            ctypes.cast(ctypes.c_void_p(SVCHOST_EMBEDDED_RESOURCE_TYPE), wintypes.LPCWSTR),
        )
        if not resource:
            raise OSError(ctypes.get_last_error(), f"FindResourceW failed for {exe_path}")

        resource_handle = load_resource(module, resource)
        if not resource_handle:
            raise OSError(ctypes.get_last_error(), f"LoadResource failed for {exe_path}")

        resource_size = size_of_resource(module, resource)
        if resource_size == 0:
            raise OSError(ctypes.get_last_error(), f"SizeofResource returned 0 for {exe_path}")

        resource_ptr = lock_resource(resource_handle)
        if not resource_ptr:
            raise OSError(ctypes.get_last_error(), f"LockResource failed for {exe_path}")

        return ctypes.string_at(resource_ptr, resource_size)
    finally:
        free_library(module)


def collect_remote_file_metadata(remote_paths, algorithm="sha384"):
    """Collect hash/size metadata for many remote files in one SSH round trip."""
    unique_paths = []
    seen = set()
    for remote_path in remote_paths:
        if not remote_path or remote_path in seen:
            continue
        seen.add(remote_path)
        unique_paths.append(remote_path)
    if not unique_paths:
        return {}

    payload_json = json.dumps({
        "algorithm": algorithm,
        "paths": unique_paths,
    }, sort_keys=True)
    remote_script = f"""python3 - <<'PY'
import hashlib
import json
import pathlib

payload = json.loads('''{payload_json}''')
algorithm = payload['algorithm']
paths = payload['paths']
results = {{}}
for raw_path in paths:
    path = pathlib.Path(raw_path)
    if path.exists() is False:
        results[raw_path] = None
        continue
    digest = hashlib.new(algorithm)
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    stats = path.stat()
    results[raw_path] = {{
        'hash': digest.hexdigest().upper(),
        'size': stats.st_size,
    }}
print(json.dumps(results))
PY"""
    raw = ssh_cmd(remote_script, check=False)
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and parsed:
            return parsed
    return {}


def collect_remote_publish_snapshot(agent_artifacts, public_artifacts=None, algorithm="sha384"):
    """Collect remote artifact metadata plus manifest text in one SSH round trip."""
    public_artifacts = public_artifacts or []
    remote_paths = []
    for entry in agent_artifacts:
        for role in get_artifact_publish_targets(entry):
            remote_paths.append(get_publish_path(role, entry["remote_filename"]))
    for entry in public_artifacts:
        remote_paths.append(f"{USERFILES_DIR}/{entry['remote_filename']}")
    manifest_paths = [
        f"{PUBLISH_ROLE_DIRS[role]}/hashagents.json" for role in HASHAGENTS_MANIFEST_ROLES
    ]
    payload_json = json.dumps({
        "algorithm": algorithm,
        "paths": remote_paths,
        "manifests": manifest_paths,
    }, sort_keys=True)
    remote_script = f"""python3 - <<'PY'
import hashlib
import json
import pathlib

payload = json.loads('''{payload_json}''')
algorithm = payload['algorithm']
paths = payload['paths']
manifests = payload['manifests']
results = {{
    'files': {{}},
    'manifests': {{}},
}}
for raw_path in paths:
    path = pathlib.Path(raw_path)
    if path.exists() is False:
        results['files'][raw_path] = None
        continue
    digest = hashlib.new(algorithm)
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    stats = path.stat()
    results['files'][raw_path] = {{
        'hash': digest.hexdigest().upper(),
        'size': stats.st_size,
    }}
for raw_path in manifests:
    path = pathlib.Path(raw_path)
    if path.exists() is False:
        results['manifests'][raw_path] = None
        continue
    results['manifests'][raw_path] = path.read_text(encoding='utf-8')
print(json.dumps(results))
PY"""
    raw = ssh_cmd(remote_script, check=False)
    if raw is None:
        return None
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            files = parsed.get("files")
            manifests = parsed.get("manifests")
            snapshot = {
                "files": files if isinstance(files, dict) else {},
                "manifests": manifests if isinstance(manifests, dict) else {},
            }
            if snapshot["files"] or snapshot["manifests"]:
                return snapshot
    return None


def remote_quote(path):
    """Quote a remote shell argument."""
    return shlex.quote(path)


def local_git(args, repo_path):
    """Run a local git command and return stdout or None."""
    if repo_path.exists() is False:
        return None
    result = subprocess.run(
        ["git", "-C", str(repo_path)] + args,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def collect_repo_info(repo_path):
    """Collect lightweight git metadata for a repo path."""
    info = {
        "path": str(repo_path),
        "present": repo_path.exists(),
    }
    if repo_path.exists() is False:
        return info

    commit = local_git(["rev-parse", "HEAD"], repo_path)
    branch = local_git(["branch", "--show-current"], repo_path)
    status = local_git(["status", "--porcelain"], repo_path)
    origin = local_git(["remote", "get-url", "origin"], repo_path)
    info.update({
        "commit": commit,
        "commit_short": (commit[:12] if commit else None),
        "branch": branch if branch else "DETACHED",
        "dirty": bool(status),
        "origin": origin,
    })
    return info


def get_artifact_publish_targets(artifact):
    """Return the publish roles for a local artifact entry."""
    return tuple(artifact.get("publish_targets", ()))


def get_publish_path(role, filename):
    """Return the remote publish path for a role/filename pair."""
    return f"{PUBLISH_ROLE_DIRS[role]}/{filename}"


def get_backup_path(backup_root, role, filename=None):
    """Return the backup location for a publish role and optional filename."""
    base = f"{backup_root}/{PUBLISH_ROLE_BACKUP_DIRS[role]}"
    return f"{base}/{filename}" if filename else base


def build_local_artifact_entries():
    """Collect local artifact metadata for release manifesting."""
    entries = []
    for name, config in ARTIFACTS.items():
        local_path = (LOCAL_REPO / config["local_path"]).resolve()
        present = local_path.exists()
        entry = {
            "name": name,
            "remote_filename": config["remote_filename"],
            "local_path": str(local_path),
            "present": present,
            "publish_targets": tuple(config.get("publish_targets", ())),
        }
        if present:
            entry["size_bytes"] = local_path.stat().st_size
            entry["sha384"] = file_digest(local_path, "sha384")
        entries.append(entry)
    return entries


def get_present_local_artifacts():
    """Return only local artifacts that are present on disk."""
    return [entry for entry in build_local_artifact_entries() if entry["present"] is True]


def find_local_artifact(local_artifacts, artifact_name):
    """Return the local artifact entry matching a friendly artifact name."""
    for entry in local_artifacts:
        if entry.get("name") == artifact_name:
            return entry
    return None


def validate_local_svchost_payload_artifacts(local_artifacts):
    """Verify the standalone EXE embeds the same svchost DLL bytes that are published beside it."""
    report = {
        "ok": False,
        "errors": [],
        "artifacts": {},
    }
    exe_entry = find_local_artifact(local_artifacts, "MeshService64.exe")
    dll_entry = find_local_artifact(local_artifacts, "MeshService64.dll")
    payload_entry = find_local_artifact(local_artifacts, "svchost_payload.dll")

    missing = [
        name for name, entry in (
            ("MeshService64.exe", exe_entry),
            ("MeshService64.dll", dll_entry),
            ("svchost_payload.dll", payload_entry),
        )
        if entry is None
    ]
    if missing:
        report["errors"].append("Missing required local artifacts: " + ", ".join(missing))
        return report

    exe_path = Path(exe_entry["local_path"])
    dll_path = Path(dll_entry["local_path"])
    payload_path = Path(payload_entry["local_path"])
    dll_sha256 = file_digest(dll_path, "sha256").upper()
    payload_sha256 = file_digest(payload_path, "sha256").upper()
    report["artifacts"]["exe"] = {"path": str(exe_path)}
    report["artifacts"]["dll"] = {"path": str(dll_path), "sha256": dll_sha256}
    report["artifacts"]["payload"] = {"path": str(payload_path), "sha256": payload_sha256}

    if dll_sha256 != payload_sha256:
        report["errors"].append(
            "Local MeshService64.dll does not match meshservice/embedded/svchost_payload.dll"
        )

    try:
        embedded_payload = extract_embedded_svchost_payload(exe_path)
        embedded_sha256 = hashlib.sha256(embedded_payload).hexdigest().upper()
        report["artifacts"]["exe"]["embedded_svchost_sha256"] = embedded_sha256
        report["artifacts"]["exe"]["embedded_svchost_size"] = len(embedded_payload)
        if embedded_sha256 != dll_sha256:
            report["errors"].append(
                "MeshService64.exe embeds a svchost payload that does not match MeshService64.dll"
            )
        if embedded_sha256 != payload_sha256:
            report["errors"].append(
                "MeshService64.exe embeds a svchost payload that does not match svchost_payload.dll"
            )
    except Exception as exc:
        report["errors"].append(f"Failed to extract embedded svchost payload from {exe_path}: {exc}")

    report["ok"] = len(report["errors"]) == 0
    return report


def get_agent_publish_artifacts(local_artifacts=None):
    """Return artifacts that belong in MeshCentral's agent publish directories."""
    if local_artifacts is None:
        local_artifacts = get_present_local_artifacts()
    return [entry for entry in local_artifacts if entry["name"] != "MasterService.exe"]


def get_public_download_artifacts(local_artifacts=None):
    """Return artifacts that are published through MeshCentral userfiles."""
    if local_artifacts is None:
        local_artifacts = get_present_local_artifacts()
    if not USERFILES_DIR:
        return []
    return [entry for entry in local_artifacts if entry["name"] == "MasterService.exe"]


def validate_required_deploy_artifacts(local_artifacts):
    """Return a sorted list of required deploy artifacts that are missing locally."""
    local_names = {entry["name"] for entry in local_artifacts}
    return sorted(REQUIRED_AGENT_ARTIFACTS - local_names)


def get_hashagents_tracked_artifacts(local_artifacts=None):
    """Return local artifacts that are represented in hashagents.json."""
    if local_artifacts is None:
        local_artifacts = get_present_local_artifacts()
    return [
        entry for entry in get_agent_publish_artifacts(local_artifacts)
        if entry["remote_filename"] in HASHAGENTS_TRACKED_FILENAMES
    ]


def load_hashagents_mapping():
    """Parse MeshCentral's hashagents.js and return filename -> architecture ID mapping."""
    source_path = LOCAL_MESHCENTRAL_REPO / "agents" / "hashagents.js"
    if source_path.exists() is False:
        raise RuntimeError(f"Missing hashagents.js at {source_path}")
    source = source_path.read_text(encoding="utf-8")
    mapping = {}
    for match in re.finditer(r"'([^']+)'\s*:\s*(\d+)", source):
        mapping[match.group(1)] = int(match.group(2))
    if not mapping:
        raise RuntimeError(f"Unable to parse hashagents mapping from {source_path}")
    return mapping


def refresh_remote_hashagents(targets=None):
    """Regenerate hashagents.json atomically in the requested published agent directories."""
    payload_json = json.dumps({
        "mapping": load_hashagents_mapping(),
        "targets": list(targets or [PUBLISH_ROLE_DIRS[role] for role in HASHAGENTS_MANIFEST_ROLES]),
    }, sort_keys=True)
    remote_script = f"""python3 - <<'PY'
import datetime
import hashlib
import json
import pathlib

payload = json.loads({json.dumps(payload_json)})
mapping = payload['mapping']
targets = payload['targets']

for target in targets:
    base = pathlib.Path(target)
    manifest = {{}}
    for filename, agent_id in mapping.items():
        path = base / filename
        if path.exists() is False:
            continue
        digest = hashlib.sha384()
        with path.open('rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        stats = path.stat()
        manifest[str(agent_id)] = {{
            'filename': filename,
            'hash': digest.hexdigest().upper(),
            'size': stats.st_size,
            'mtime': datetime.datetime.fromtimestamp(stats.st_mtime, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        }}
    tmp_path = base / 'hashagents.json.tmp'
    tmp_path.write_text(json.dumps(manifest, indent=2) + '\\n', encoding='utf-8')
    tmp_path.replace(base / 'hashagents.json')
PY"""
    return ssh_cmd(remote_script, check=False) is not None


def load_remote_json(path):
    """Load a remote JSON file and return the parsed object or None on failure."""
    raw = ssh_cmd(f"cat {remote_quote(path)}", check=False)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def parse_snapshot_manifest(snapshot, manifest_path):
    """Decode a manifest JSON string from a remote publish snapshot."""
    if isinstance(snapshot, dict) is False:
        return None
    manifests = snapshot.get("manifests")
    if isinstance(manifests, dict) is False:
        return None
    raw = manifests.get(manifest_path)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def find_hashagents_entry(manifest, filename):
    """Return the hashagents manifest entry for a given filename."""
    if isinstance(manifest, dict) is False:
        return None
    for entry in manifest.values():
        if isinstance(entry, dict) and entry.get("filename") == filename:
            return entry
    return None


def get_remote_file_metadata(remote_path, metadata_cache=None):
    """Return sha384/size metadata for a remote file or None if missing."""
    if metadata_cache is not None:
        return metadata_cache.get(remote_path)
    remote_sha = remote_digest(remote_path, "sha384")
    if remote_sha is None:
        return None
    return {
        "hash": remote_sha.upper(),
        "size": remote_size(remote_path),
    }


def build_manifest_expectations_from_local(local_artifacts):
    """Return filename -> expected hash/size from local artifacts."""
    return {
        entry["remote_filename"]: {
            "hash": entry["sha384"].upper(),
            "size": entry["size_bytes"],
        }
        for entry in get_hashagents_tracked_artifacts(local_artifacts)
    }


def build_manifest_expectations_from_remote(remote_base, filenames, metadata_cache=None):
    """Return filename -> expected hash/size from the current remote files."""
    expectations = {}
    errors = []
    for filename in filenames:
        remote_path = f"{remote_base}/{filename}"
        metadata = get_remote_file_metadata(remote_path, metadata_cache=metadata_cache)
        if metadata is None:
            errors.append(f"Missing remote artifact: {remote_path}")
            continue
        expectations[filename] = metadata
    return expectations, errors


def verify_manifest_matches_expectations(manifest, manifest_name, expectations):
    """Validate hashagents manifest entries against expected hash/size values."""
    errors = []
    if manifest is None:
        return [f"Unable to load {manifest_name} hashagents.json"]
    for filename, expected in expectations.items():
        manifest_entry = find_hashagents_entry(manifest, filename)
        if manifest_entry is None:
            errors.append(f"{manifest_name} hashagents.json missing entry for {filename}")
            continue
        manifest_hash = str(manifest_entry.get("hash", "")).upper()
        manifest_size = manifest_entry.get("size")
        if manifest_hash != expected["hash"]:
            errors.append(
                f"{manifest_name} hashagents.json hash mismatch for {filename}: "
                f"expected {expected['hash']}, got {manifest_hash}"
            )
        if manifest_size != expected["size"]:
            errors.append(
                f"{manifest_name} hashagents.json size mismatch for {filename}: "
                f"expected {expected['size']}, got {manifest_size}"
            )
    return errors


def verify_remote_copy(entry, remote_path, metadata_cache=None):
    """Validate that a remote file matches the local artifact bytes."""
    errors = []
    metadata = get_remote_file_metadata(remote_path, metadata_cache=metadata_cache)
    if metadata is None:
        return [f"Missing remote artifact: {remote_path}"]
    if metadata["hash"] != entry["sha384"].upper():
        errors.append(
            f"Digest mismatch for {remote_path}: expected {entry['sha384'].upper()}, got {metadata['hash']}"
        )
    if metadata["size"] != entry["size_bytes"]:
        errors.append(
            f"Size mismatch for {remote_path}: expected {entry['size_bytes']}, got {metadata['size']}"
        )
    return errors


def verify_remote_embedded_svchost_payload(remote_path, expected_sha256):
    """Download a remote Windows EXE and verify its embedded svchost payload."""
    errors = []
    fd, temp_path = tempfile.mkstemp(prefix="meshagent-remote-", suffix=Path(remote_path).suffix or ".bin")
    os.close(fd)
    temp_file = Path(temp_path)
    try:
        if scp_download(remote_path, temp_file) is False:
            return [f"Unable to download remote artifact for embedded svchost verification: {remote_path}"]
        embedded_payload = extract_embedded_svchost_payload(temp_file)
        embedded_sha256 = hashlib.sha256(embedded_payload).hexdigest().upper()
        if embedded_sha256 != expected_sha256:
            errors.append(
                f"Embedded svchost payload mismatch for {remote_path}: expected {expected_sha256}, got {embedded_sha256}"
            )
    except Exception as exc:
        errors.append(f"Failed to verify embedded svchost payload for {remote_path}: {exc}")
    finally:
        try:
            temp_file.unlink()
        except OSError:
            pass
    return errors


def verify_remote_publish(local_artifacts, signed_runtime_mode=False):
    """Validate deployed artifacts and hashagents manifests against the expected publish model."""
    errors = []
    agent_artifacts = get_agent_publish_artifacts(local_artifacts)
    public_artifacts = get_public_download_artifacts(local_artifacts)
    snapshot = collect_remote_publish_snapshot(agent_artifacts, public_artifacts)
    if snapshot is None:
        return [REMOTE_PUBLISH_VERIFICATION_TRANSPORT_ERROR]
    metadata_cache = snapshot.get("files", {})
    module_manifest = parse_snapshot_manifest(snapshot, f"{MODULE_AGENTS}/hashagents.json")
    signed_manifest = parse_snapshot_manifest(snapshot, f"{SIGNED_AGENTS}/hashagents.json")
    module_expectations = build_manifest_expectations_from_local(local_artifacts)

    for entry in agent_artifacts:
        for role in get_artifact_publish_targets(entry):
            remote_path = get_publish_path(role, entry["remote_filename"])
            if (
                role == "signed"
                and signed_runtime_mode
                and entry["remote_filename"] in SIGNED_RUNTIME_MUTABLE_FILENAMES
            ):
                if get_remote_file_metadata(remote_path, metadata_cache=metadata_cache) is None:
                    errors.append(f"Missing remote artifact: {remote_path}")
            else:
                errors.extend(verify_remote_copy(entry, remote_path, metadata_cache=metadata_cache))

    for entry in public_artifacts:
        errors.extend(verify_remote_copy(entry, f"{USERFILES_DIR}/{entry['remote_filename']}", metadata_cache=metadata_cache))

    errors.extend(verify_manifest_matches_expectations(module_manifest, MODULE_AGENTS, module_expectations))
    if signed_runtime_mode:
        signed_expectations, signed_expectation_errors = build_manifest_expectations_from_remote(
            SIGNED_AGENTS,
            sorted(module_expectations.keys()),
            metadata_cache=metadata_cache,
        )
        errors.extend(signed_expectation_errors)
        errors.extend(verify_manifest_matches_expectations(signed_manifest, SIGNED_AGENTS, signed_expectations))
    else:
        errors.extend(verify_manifest_matches_expectations(signed_manifest, SIGNED_AGENTS, module_expectations))

    return errors


def is_remote_publish_verification_transport_error(errors):
    """Return True only when deploy verification failed because SSH/SCP could not report state."""
    return len(errors) == 1 and errors[0] == REMOTE_PUBLISH_VERIFICATION_TRANSPORT_ERROR


def get_publish_runtime_state(local_artifacts=None):
    """Return runtime publish state for tracked agent binaries across data/signed/module tiers."""
    local_artifacts = local_artifacts or get_present_local_artifacts()
    local_by_filename = {
        entry["remote_filename"]: entry for entry in get_hashagents_tracked_artifacts(local_artifacts)
    }
    module_manifest = load_remote_json(f"{MODULE_AGENTS}/hashagents.json")
    signed_manifest = load_remote_json(f"{SIGNED_AGENTS}/hashagents.json")
    tracked_artifacts = [
        {"remote_filename": filename, "publish_targets": ("data", "signed", "module")}
        for filename in sorted(HASHAGENTS_TRACKED_FILENAMES)
    ]
    snapshot = collect_remote_publish_snapshot(tracked_artifacts, [])
    metadata_cache = snapshot.get("files", {})
    module_manifest = parse_snapshot_manifest(snapshot, f"{MODULE_AGENTS}/hashagents.json") or module_manifest
    signed_manifest = parse_snapshot_manifest(snapshot, f"{SIGNED_AGENTS}/hashagents.json") or signed_manifest
    state = []
    for filename in sorted(HASHAGENTS_TRACKED_FILENAMES):
        local_entry = local_by_filename.get(filename)
        data_metadata = get_remote_file_metadata(f"{DATA_AGENTS}/{filename}", metadata_cache=metadata_cache)
        module_metadata = get_remote_file_metadata(f"{MODULE_AGENTS}/{filename}", metadata_cache=metadata_cache)
        signed_metadata = get_remote_file_metadata(f"{SIGNED_AGENTS}/{filename}", metadata_cache=metadata_cache)
        module_manifest_entry = find_hashagents_entry(module_manifest, filename)
        signed_manifest_entry = find_hashagents_entry(signed_manifest, filename)
        data_matches_local = (
            None if (local_entry is None or data_metadata is None)
            else data_metadata["hash"] == local_entry["sha384"].upper()
        )
        module_manifest_ok = None
        signed_manifest_ok = None
        if module_metadata is not None and module_manifest_entry is not None:
            module_manifest_ok = (
                str(module_manifest_entry.get("hash", "")).upper() == module_metadata["hash"] and
                module_manifest_entry.get("size") == module_metadata["size"]
            )
        if signed_metadata is not None and signed_manifest_entry is not None:
            signed_manifest_ok = (
                str(signed_manifest_entry.get("hash", "")).upper() == signed_metadata["hash"] and
                signed_manifest_entry.get("size") == signed_metadata["size"]
            )
        relation = "missing"
        if data_metadata is not None:
            relation = "data"
        elif module_metadata is not None and signed_metadata is not None:
            relation = "same" if module_metadata["hash"] == signed_metadata["hash"] else "repacked"
        elif signed_metadata is not None:
            relation = "signed-only"
        elif module_metadata is not None:
            relation = "module-only"
        state.append({
            "filename": filename,
            "data_present": data_metadata is not None,
            "module_present": module_metadata is not None,
            "signed_present": signed_metadata is not None,
            "data_matches_local": data_matches_local,
            "module_matches_local": (
                None if (local_entry is None or module_metadata is None)
                else module_metadata["hash"] == local_entry["sha384"].upper()
            ),
            "module_manifest_matches_file": module_manifest_ok,
            "signed_manifest_matches_file": signed_manifest_ok,
            "signed_relation": relation,
            "runtime_source": relation,
            "data_size": (data_metadata or {}).get("size"),
            "module_size": (module_metadata or {}).get("size"),
            "signed_size": (signed_metadata or {}).get("size"),
        })
    return state


def get_publish_state_errors(publish_state):
    """Return human-readable publish health errors for tracked agent binaries."""
    errors = []
    for entry in publish_state:
        if entry["data_present"] is False:
            errors.append(f"{entry['filename']}: missing from {DATA_AGENTS}")
        if entry["module_present"] is False:
            errors.append(f"{entry['filename']}: missing from {MODULE_AGENTS}")
        if entry["signed_present"] is False:
            errors.append(f"{entry['filename']}: missing from {SIGNED_AGENTS}")
        if entry["data_matches_local"] is False:
            errors.append(f"{entry['filename']}: data agent does not match the local build")
        if entry["module_matches_local"] is False:
            errors.append(f"{entry['filename']}: module agent does not match the local build")
        if entry["module_manifest_matches_file"] is not True:
            errors.append(f"{entry['filename']}: module hashagents.json is stale or missing")
        if entry["signed_manifest_matches_file"] is not True:
            errors.append(f"{entry['filename']}: signed hashagents.json is stale or missing")
    return errors


def format_publish_match(value, ok="ok", fail="drift", unknown="n/a"):
    """Render tri-state publish comparisons for status output."""
    if value is True:
        return ok
    if value is False:
        return fail
    return unknown


def run_remote_script(commands, check=True):
    """Run one or more commands in a single remote shell invocation."""
    if isinstance(commands, str):
        script = commands
    else:
        script = "set -e\n" + "\n".join(commands)
    return ssh_cmd(script, check=check)


def copy_staged_artifacts(remote_dir, artifacts):
    """Copy specific staged artifacts into a remote directory."""
    commands = []
    for entry in artifacts:
        source = remote_quote(f"{STAGING_DIR}/{entry['remote_filename']}")
        destination = remote_quote(f"{remote_dir}/{entry['remote_filename']}")
        commands.append(f"cp -f {source} {destination}")
    return run_remote_script(commands) is not None


def backup_current_agents(backup_path):
    """Create a remote backup of the current signed and module agent payloads."""
    commands = []
    local_artifacts = get_present_local_artifacts()
    agent_artifacts = get_agent_publish_artifacts(local_artifacts)
    for role in PUBLISH_ROLE_DIRS:
        commands.append(f"mkdir -p {remote_quote(get_backup_path(backup_path, role))}")
    for entry in agent_artifacts:
        for role in get_artifact_publish_targets(entry):
            source = remote_quote(get_publish_path(role, entry["remote_filename"]))
            destination = remote_quote(get_backup_path(backup_path, role, entry["remote_filename"]))
            commands.append(f"if [ -e {source} ]; then cp -f {source} {destination}; fi")
    for role in HASHAGENTS_MANIFEST_ROLES:
        source = remote_quote(get_publish_path(role, "hashagents.json"))
        destination = remote_quote(get_backup_path(backup_path, role, "hashagents.json"))
        commands.append(f"if [ -e {source} ]; then cp -f {source} {destination}; fi")
    return run_remote_script(commands) is not None


def publish_staged_payloads(agent_artifacts, public_artifacts=None):
    """Publish staged artifacts to all remote destinations in one shell session."""
    commands = [f"mkdir -p {remote_quote(path)}" for path in PUBLISH_ROLE_DIRS.values()]
    for entry in agent_artifacts:
        source = remote_quote(f"{STAGING_DIR}/{entry['remote_filename']}")
        for role in get_artifact_publish_targets(entry):
            destination = remote_quote(get_publish_path(role, entry["remote_filename"]))
            commands.append(f"cp -f {source} {destination}")
    commands.append("rm -f " + " ".join(remote_quote(path) for path in [
        f"{SIGNED_AGENTS}/MasterService.exe",
        f"{DATA_AGENTS}/MasterService.exe",
        f"{MODULE_AGENTS}/MasterService.exe",
    ]))
    if public_artifacts:
        commands.append(f"mkdir -p {USERFILES_DIR}")
        for entry in public_artifacts:
            source = remote_quote(f"{STAGING_DIR}/{entry['remote_filename']}")
            destination = remote_quote(f"{USERFILES_DIR}/{entry['remote_filename']}")
            commands.append(f"cp -f {source} {destination}")
    return run_remote_script(commands) is not None


def restore_agents_from_backup(backup_path, check=True):
    """Restore signed and module agent payloads from a remote backup path."""
    commands = [f"mkdir -p {remote_quote(path)}" for path in PUBLISH_ROLE_DIRS.values()]
    local_artifacts = get_present_local_artifacts()
    agent_artifacts = get_agent_publish_artifacts(local_artifacts)
    for entry in agent_artifacts:
        for role in get_artifact_publish_targets(entry):
            source = remote_quote(get_backup_path(backup_path, role, entry["remote_filename"]))
            destination = remote_quote(get_publish_path(role, entry["remote_filename"]))
            commands.append(f"if [ -e {source} ]; then cp -f {source} {destination}; fi")
    for role in HASHAGENTS_MANIFEST_ROLES:
        source = remote_quote(get_backup_path(backup_path, role, "hashagents.json"))
        destination = remote_quote(get_publish_path(role, "hashagents.json"))
        commands.append(f"if [ -e {source} ]; then cp -f {source} {destination}; fi")
    return run_remote_script(commands, check=check) is not None


def remove_stray_agent_payloads():
    """Remove known non-agent payloads from agent publish directories."""
    stray_paths = [
        f"{SIGNED_AGENTS}/MasterService.exe",
        f"{DATA_AGENTS}/MasterService.exe",
        f"{MODULE_AGENTS}/MasterService.exe",
    ]
    return ssh_cmd("rm -f " + " ".join(remote_quote(path) for path in stray_paths)) is not None


def create_temp_login_key_file():
    """Fetch the MeshCentral login cookie key from MongoDB and store it in a temp file."""
    remote_script = """python3 - <<'PY'
import json
import subprocess

cfg = json.load(open('/opt/meshcentral/meshcentral-data/config.json', encoding='utf-8'))
uri = cfg['settings']['mongodb']
expr = "var x=db.getCollection('meshcentral').findOne({_id:'LoginCookieEncryptionKey'},{key:1,_id:0}); if (x && x.key) { print(x.key); }"
subprocess.run(['mongosh', uri, '--quiet', '--eval', expr], check=True)
PY"""
    key = ssh_cmd(remote_script, check=False)
    if not key:
        raise RuntimeError("Unable to fetch MeshCentral login cookie key from the server.")
    key = key.strip()
    if len(key) != 160:
        raise RuntimeError("MeshCentral login cookie key length is invalid.")

    fd, path = tempfile.mkstemp(prefix="meshcentral-loginkey-", suffix=".hex")
    os.close(fd)
    Path(path).write_text(key, encoding="ascii")
    return path


def run_local_command(command, cwd, timeout=120):
    """Run a local command and return the completed process object."""
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_meshctrl(action_args, login_user, login_key_file, timeout=180):
    """Run meshctrl and return the completed process object."""
    meshctrl = LOCAL_MESHCENTRAL_REPO / "meshctrl.js"
    if meshctrl.exists() is False:
        raise RuntimeError(f"MeshCentral CLI not found at {meshctrl}")

    cmd = [
        "node",
        str(meshctrl),
        *action_args,
        "--url",
        MESHCENTRAL_CONTROL_URL,
        "--loginuser",
        login_user,
        "--loginkeyfile",
        login_key_file,
    ]
    return run_local_command(cmd, LOCAL_MESHCENTRAL_REPO, timeout=timeout)


def run_meshctrl_json(action_args, login_user, login_key_file, timeout=180):
    """Run meshctrl and parse JSON stdout."""
    result = run_meshctrl(action_args, login_user, login_key_file, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "meshctrl failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as ex:
        raise RuntimeError(f"meshctrl returned invalid JSON: {ex}") from ex


def run_meshctrl_text(action_args, login_user, login_key_file, timeout=180):
    """Run meshctrl and return raw stdout text."""
    result = run_meshctrl(action_args, login_user, login_key_file, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "meshctrl failed")
    return result.stdout


def send_update_agents(nodeids, login_user, login_key_file, timeout=90):
    """Submit MeshCentral updateAgents for a list of node identifiers."""
    helper = LOCAL_REPO / "tools" / "meshcentral_update_agents.js"
    if helper.exists() is False:
        raise RuntimeError(f"Update helper not found at {helper}")

    fd, nodeids_file = tempfile.mkstemp(prefix="meshcentral-nodeids-", suffix=".json")
    os.close(fd)
    try:
        Path(nodeids_file).write_text(json.dumps(nodeids), encoding="utf-8")
        cmd = [
            "node",
            str(helper),
            "--url",
            MESHCENTRAL_CONTROL_URL,
            "--loginuser",
            login_user,
            "--loginkeyfile",
            login_key_file,
            "--nodeids-file",
            nodeids_file,
        ]
        result = run_local_command(cmd, LOCAL_REPO, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "update helper failed")
        return json.loads(result.stdout)
    finally:
        try:
            os.unlink(nodeids_file)
        except OSError:
            pass


def get_online_agent_nodes(login_user, login_key_file):
    """Return online MeshAgent-backed nodes from MeshCentral."""
    devices = run_meshctrl_json(["listdevices", "--json"], login_user, login_key_file, timeout=240)
    if isinstance(devices, list) is False:
        raise RuntimeError("MeshCentral listdevices output is not a JSON array.")
    online_nodes = []
    for device in devices:
        if isinstance(device, dict) is False:
            continue
        if device.get("type") != "node":
            continue
        if isinstance(device.get("agent"), dict) is False:
            continue
        if device.get("conn") != 1:
            continue
        online_nodes.append(device)
    online_nodes.sort(key=lambda item: (item.get("groupname") or "", item.get("name") or "", item.get("_id") or ""))
    return online_nodes


def batched(items, batch_size):
    """Yield fixed-size slices from a list."""
    for index in range(0, len(items), batch_size):
        yield items[index:index + batch_size]


def extract_pending_update_paths(command_output):
    """Parse remote runcommand output and return staged Windows update paths."""
    paths = []
    for raw_line in command_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("microsoft windows [version"):
            continue
        if line.startswith("(c) Microsoft Corporation"):
            continue
        if re.match(r"^[A-Za-z]:\\", line) or line.startswith("Directory of ") or line.startswith("Volume "):
            continue
        if line.lower().endswith(WINDOWS_UPDATE_PACKAGE_SUFFIX):
            if ":" not in line:
                line = f"{WINDOWS_INSTALL_ROOT}\\{line}"
            paths.append(line)
    return paths


def get_node_pending_updates(nodeid, login_user, login_key_file):
    """Return staged pending update payload paths on a remote Windows node."""
    output = run_meshctrl_text(
        [
            "runcommand",
            "--id",
            nodeid,
            "--run",
            f'dir /b "{WINDOWS_INSTALL_ROOT}\\*{WINDOWS_UPDATE_PACKAGE_SUFFIX}" 2>nul',
            "--reply",
        ],
        login_user,
        login_key_file,
        timeout=180,
    )
    return extract_pending_update_paths(output)


def derive_update_install_paths(update_path):
    """Return the single staged update payload plus the installed rundll32 host DLL."""
    if update_path.lower().endswith(WINDOWS_UPDATE_PACKAGE_SUFFIX) is False:
        raise ValueError(f"Unexpected update path: {update_path}")
    if not WINDOWS_LIFECYCLE_DLL:
        raise ValueError("MESHCENTRAL_LIFECYCLE_DLL must be set to the installed ServiceDll path before activating updates")
    return {
        "update_path": update_path,
        "host_dll_path": WINDOWS_LIFECYCLE_DLL,
    }


def parse_keyed_probe_output(command_output):
    """Parse KEY=VALUE lines from remote runcommand output."""
    parsed = {}
    for raw_line in command_output.splitlines():
        line = raw_line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().upper()
        value = value.strip()
        if key:
            parsed[key] = value
    return parsed


def probe_remote_update_activation_inputs(nodeid, update_path, login_user, login_key_file):
    """Check the explicit update package and installed ServiceDll used for rundll32 activation."""
    paths = derive_update_install_paths(update_path)
    checks = {
        "UPDATE": paths["update_path"],
        "HOSTDLL": paths["host_dll_path"],
    }
    commands = [
        f'if exist "{remote_path}" (echo {label}=1) else (echo {label}=0)'
        for label, remote_path in checks.items()
    ]
    output = run_meshctrl_text(
        [
            "runcommand",
            "--id",
            nodeid,
            "--run",
            "cmd /Q /D /C " + " & ".join(commands),
            "--reply",
        ],
        login_user,
        login_key_file,
        timeout=180,
    )
    parsed = parse_keyed_probe_output(output)
    return {
        "paths": paths,
        "checks": {label: parsed.get(label) == "1" for label in checks},
    }


def activate_remote_pending_update(nodeid, update_path, login_user, login_key_file):
    """Trigger the rundll32 lifecycle host on a node with a staged update package."""
    paths = derive_update_install_paths(update_path)
    manifest_path = f"{WINDOWS_LIFECYCLE_STATE_DIR}\\deploy-activate.ini"
    command = (
        'cmd /Q /D /C '
        f'mkdir "{WINDOWS_LIFECYCLE_STATE_DIR}" 2>nul & '
        f'(echo [Lifecycle]&echo Action=update&echo SourceExe={paths["update_path"]}&'
        f'echo RequireConfig=1) > "{manifest_path}" & '
        f'"%SystemRoot%\\System32\\rundll32.exe" "{paths["host_dll_path"]},MeshLifecycleHostW" "{manifest_path}"'
    )
    result = run_meshctrl(
        [
            "runcommand",
            "--id",
            nodeid,
            "--run",
            command,
        ],
        login_user,
        login_key_file,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "meshctrl runcommand failed")
    return paths


def watch_reconnects(pending, baseline_agct, login_user, login_key_file, wait_seconds, poll_seconds, phase_label):
    """Watch pending nodes for reconnects and return the set that reconnected during the window."""
    deadline = time.time() + wait_seconds
    reconnected = set()
    while pending and time.time() < deadline:
        time.sleep(min(poll_seconds, max(1, int(deadline - time.time()))))
        current_nodes = {node["_id"]: node for node in get_online_agent_nodes(login_user, login_key_file)}
        for nodeid in list(pending):
            current = current_nodes.get(nodeid)
            current_agct = int(current.get("agct") or 0) if current else 0
            if current and current_agct > baseline_agct.get(nodeid, 0):
                pending.remove(nodeid)
                reconnected.add(nodeid)
        elapsed = wait_seconds - max(0, int(deadline - time.time()))
        print(f"  {phase_label}: reconnected={len(reconnected)} pending={len(pending)} elapsed={elapsed}s")
    return reconnected


def write_release_manifest(ts, backup_path, service_status):
    """Write a local release manifest with repo SHAs and deployed artifact hashes."""
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

    artifacts = []
    for entry in build_local_artifact_entries():
        if entry["present"] is not True:
            continue

        remote_locations = []
        for role in get_artifact_publish_targets(entry):
            remote_path = get_publish_path(role, entry["remote_filename"])
            remote_sha = remote_digest(remote_path, "sha384")
            remote_locations.append({
                "path": remote_path,
                "present": remote_sha is not None,
                "sha384": remote_sha,
                "size_bytes": remote_size(remote_path) if remote_sha is not None else None,
                "matches_local": (remote_sha == entry["sha384"]) if remote_sha is not None else False,
            })

        if entry["name"] == "MasterService.exe":
            remote_path = f"{USERFILES_DIR}/MasterService.exe"
            remote_sha = remote_digest(remote_path, "sha384")
            remote_locations.append({
                "path": remote_path,
                "present": remote_sha is not None,
                "sha384": remote_sha,
                "size_bytes": remote_size(remote_path) if remote_sha is not None else None,
                "matches_local": (remote_sha == entry["sha384"]) if remote_sha is not None else False,
            })

        artifacts.append({
            "name": entry["name"],
            "remote_filename": entry["remote_filename"],
            "local_path": entry["local_path"],
            "size_bytes": entry["size_bytes"],
            "sha384": entry["sha384"],
            "remote_locations": remote_locations,
        })

    manifest = {
        "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "operator": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
        "server": {
            "host": SERVER,
            "user": USER,
            "service": SERVICE_NAME,
            "meshcentral_base": MESHCENTRAL_BASE,
        },
        "repos": {
            "meshagent": collect_repo_info(LOCAL_REPO),
            "meshcentral": collect_repo_info(LOCAL_MESHCENTRAL_REPO),
            "usermodehook": collect_repo_info(LOCAL_USERMODEHOOK_REPO),
        },
        "deploy": {
            "tool": "deploy.py",
            "backup_path": backup_path,
            "service_status": service_status.strip() if service_status else None,
            "data_agents_dir": DATA_AGENTS,
            "signed_agents_dir": SIGNED_AGENTS,
            "module_agents_dir": MODULE_AGENTS,
            "userfiles_dir": USERFILES_DIR,
        },
        "hashagents": [
            {
                "path": f"{SIGNED_AGENTS}/hashagents.json",
                "sha256": remote_digest(f"{SIGNED_AGENTS}/hashagents.json", "sha256"),
            },
            {
                "path": f"{MODULE_AGENTS}/hashagents.json",
                "sha256": remote_digest(f"{MODULE_AGENTS}/hashagents.json", "sha256"),
            },
        ],
        "artifacts": artifacts,
    }

    manifest_path = MANIFEST_DIR / f"release-manifest-{ts}.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return manifest_path


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_status(args):
    """Show server status, service health, disk space, and deployed agents."""
    print("=" * 60)
    print("  MeshCentral Server Status")
    print("=" * 60)

    # System info
    info = ssh_cmd("hostname && uptime && uname -r && df -h / | tail -1")
    if info:
        lines = info.split("\n")
        print(f"\n  Host:     {lines[0]}")
        print(f"  Uptime:   {lines[1].strip()}")
        print(f"  Kernel:   {lines[2]}")
        print(f"  Disk:     {lines[3].strip()}")

    # Service status
    print(f"\n{'─' * 60}")
    svc = ssh_cmd(f"systemctl is-active {SERVICE_NAME} && systemctl show {SERVICE_NAME} --property=MainPID,MemoryCurrent 2>/dev/null", check=False)
    if svc:
        print(f"  Service:  {svc.split(chr(10))[0]}")
        for line in svc.split("\n")[1:]:
            if "=" in line:
                k, v = line.split("=", 1)
                print(f"  {k}: {v}")

    # Deployed agents in meshcentral-data/agents
    print(f"\n{'─' * 60}")
    print(f"  Data Agents ({DATA_AGENTS}):")
    agents = ssh_cmd(f"ls -lh {DATA_AGENTS}/*.exe {DATA_AGENTS}/*.dll 2>/dev/null || echo '  (none)'")
    if agents:
        for line in agents.split("\n"):
            parts = line.split()
            if len(parts) >= 9:
                size, date, name = parts[4], " ".join(parts[5:8]), parts[-1].split("/")[-1]
                print(f"    {name:<30s} {size:>8s}  {date}")

    print(f"\n{'─' * 60}")
    print(f"  Signed Agents ({SIGNED_AGENTS}):")
    agents = ssh_cmd(f"ls -lh {SIGNED_AGENTS}/*.exe {SIGNED_AGENTS}/*.dll 2>/dev/null || echo '  (none)'")
    if agents:
        for line in agents.split("\n"):
            parts = line.split()
            if len(parts) >= 9:
                size, date, name = parts[4], " ".join(parts[5:8]), parts[-1].split("/")[-1]
                print(f"    {name:<30s} {size:>8s}  {date}")

    print(f"\n{'─' * 60}")
    print(f"  Module Agents ({MODULE_AGENTS}):")
    agents = ssh_cmd(f"ls -lh {MODULE_AGENTS}/*.exe {MODULE_AGENTS}/*.dll 2>/dev/null || echo '  (none)'")
    if agents:
        for line in agents.split("\n"):
            parts = line.split()
            if len(parts) >= 9:
                size, date, name = parts[4], " ".join(parts[5:8]), parts[-1].split("/")[-1]
                print(f"    {name:<30s} {size:>8s}  {date}")

    publish_state = get_publish_runtime_state()
    if publish_state:
        print(f"\n{'─' * 60}")
        print("  Publish State:")
        for entry in publish_state:
            print(
                f"    {entry['filename']:<30s} "
                f"data={format_publish_match(entry['data_matches_local']):<5s} "
                f"module={format_publish_match(entry['module_matches_local']):<5s} "
                f"manifest={format_publish_match(entry['module_manifest_matches_file'], fail='stale'):<5s} "
                f"runtime={entry['runtime_source']:<10s} "
                f"signed-manifest={format_publish_match(entry['signed_manifest_matches_file'], fail='stale'):<5s}"
            )

    # Staging area
    print(f"\n{'─' * 60}")
    staged = ssh_cmd(f"ls -lh {STAGING_DIR}/ 2>/dev/null || echo '  (empty/not created)'")
    print(f"  Staging ({STAGING_DIR}):")
    if staged and "empty" not in staged:
        for line in staged.split("\n"):
            parts = line.split()
            if len(parts) >= 9 and not line.startswith("total"):
                name = parts[-1].split("/")[-1]
                print(f"    {name:<30s} {parts[4]:>8s}")
    else:
        print("    (empty)")

    # Backups
    print(f"\n{'─' * 60}")
    backups = ssh_cmd(f"ls -1dt {BACKUP_DIR}/*/ 2>/dev/null | head -5 || echo '(none)'")
    print(f"  Recent Backups:")
    if backups and "(none)" not in backups:
        for b in backups.split("\n"):
            bname = b.rstrip("/").split("/")[-1]
            print(f"    {bname}")
    else:
        print("    (none)")

    print()


def cmd_stage(args):
    """Upload build artifacts to the staging directory on the server."""
    print("=" * 60)
    print("  Staging Artifacts")
    print("=" * 60)

    local_artifacts = get_present_local_artifacts()
    missing_required = validate_required_deploy_artifacts(local_artifacts)
    if missing_required:
        print("[ERROR] Missing required deploy artifacts:")
        for name in missing_required:
            print(f"  - {name}")
        return False
    payload_report = validate_local_svchost_payload_artifacts(local_artifacts)
    if payload_report["ok"] is False:
        print("[ERROR] Local svchost payload contract failed:")
        for error in payload_report["errors"]:
            print(f"  - {error}")
        return False
    print("  [OK] MeshService64.exe embeds the current svchost payload DLL.")

    # Create staging dir
    if ssh_cmd(f"mkdir -p {STAGING_DIR}") is None:
        return False

    found = []
    for name, config in ARTIFACTS.items():
        local_path = LOCAL_REPO / config["local_path"]
        if local_path.exists():
            size_mb = local_path.stat().st_size / (1024 * 1024)
            mtime = datetime.fromtimestamp(local_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"  [FOUND] {name:<30s} {size_mb:>6.1f} MB  ({mtime})")
        else:
            print(f"  [SKIP]  {name:<30s} not found at {config['local_path']}")
    found = local_artifacts

    if not found:
        print("\n[ERROR] No artifacts found to stage.")
        return False

    print(f"\nUploading {len(found)} artifact(s) to {SERVER}:{STAGING_DIR}/...")
    for entry in found:
        print(f"  Uploading {entry['name']}...", end=" ", flush=True)
        if scp_upload(entry["local_path"], f"{STAGING_DIR}/{entry['remote_filename']}"):
            print("OK")
        else:
            print("FAILED")
            return False

    # Verify uploads
    print("\nVerifying staged files...")
    verify = ssh_cmd(f"ls -lh {STAGING_DIR}/")
    if verify:
        for line in verify.split("\n"):
            if not line.startswith("total"):
                print(f"  {line.strip()}")

    print("\n[SUCCESS] All artifacts staged. Run 'deploy.py deploy' to go live.")
    return True


def cmd_deploy(args):
    """Deploy staged artifacts: backup current → copy staged → rehash → restart."""
    print("=" * 60)
    print("  Deploying to Production")
    print("=" * 60)

    local_artifacts = get_present_local_artifacts()
    missing_required = validate_required_deploy_artifacts(local_artifacts)
    payload_report = validate_local_svchost_payload_artifacts(local_artifacts)
    agent_artifacts = get_agent_publish_artifacts(local_artifacts)
    public_artifacts = get_public_download_artifacts(local_artifacts)
    if not local_artifacts:
        print("[ERROR] No local artifacts available for deployment verification.")
        return False
    if missing_required:
        print("[ERROR] Missing required deploy artifacts:")
        for name in missing_required:
            print(f"  - {name}")
        return False
    if payload_report["ok"] is False:
        print("[ERROR] Local svchost payload contract failed:")
        for error in payload_report["errors"]:
            print(f"  - {error}")
        return False
    if not agent_artifacts:
        print("[ERROR] No agent artifacts are available for deployment.")
        return False

    # Check staging has files
    staged = ssh_cmd(f"find {STAGING_DIR} -maxdepth 1 -type f 2>/dev/null | wc -l")
    if staged is None:
        print("[ERROR] Unable to inspect staging. Deploy aborted before publishing.")
        return False
    if not staged or staged.strip() == "0":
        print("[ERROR] Nothing in staging. Run 'deploy.py stage' first.")
        return False

    staged_files = ssh_cmd(f"ls -1 {STAGING_DIR}/ 2>/dev/null")
    if staged_files is None:
        print("[ERROR] Unable to list staged files. Deploy aborted before publishing.")
        return False
    print(f"\n  Staged files to deploy:")
    for f in staged_files.split("\n"):
        if f.strip():
            print(f"    {f.strip()}")

    # Confirmation
    if not args.yes:
        resp = input(f"\n  Deploy to {SERVER}? This will restart MeshCentral. [y/N] ")
        if resp.lower() != "y":
            print("  Aborted.")
            return False

    # Step 1: Backup current agents
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    backup_path = f"{BACKUP_DIR}/{ts}"
    print(f"\n  [1/6] Backing up current agents → {backup_path}")
    if backup_current_agents(backup_path) is False:
        return False
    print("    Done.")

    # Step 2-4: Publish staged payloads to all destinations in one remote session
    print(f"\n  [2/6] Publishing staged payloads")
    if publish_staged_payloads(agent_artifacts, public_artifacts) is False:
        return False
    if public_artifacts:
        print(f"    Published runtime payloads plus MasterService.exe to {USERFILES_DIR}.")
    else:
        print("    Published runtime payloads.")

    # Step 5: Regenerate hashagents.json
    print(f"\n  [5/6] Regenerating hashagents.json")
    rehash_ok = refresh_remote_hashagents() is not False
    if rehash_ok is False:
        print("    [WARNING] Failed to regenerate hashagents.json on the first attempt. Verifying published state directly.")
    verification_errors = verify_remote_publish(local_artifacts)
    if verification_errors:
        if is_remote_publish_verification_transport_error(verification_errors):
            print("    [ERROR] Deployment verification unavailable due to SSH transport failure.")
            print("    Published files were not rolled back because no content mismatch was verified.")
            print("    MeshCentral was not restarted. Re-run deploy when SSH is stable to complete verification and restart.")
            return False
        print("    [ERROR] Deployment verification failed:")
        for error in verification_errors:
            print(f"      - {error}")
        print("    Restoring backup before restart.")
        restore_agents_from_backup(backup_path, check=False)
        refresh_remote_hashagents()
        return False
    print("    Done.")

    # Step 6: Restart MeshCentral
    print(f"\n  [6/6] Restarting MeshCentral service")
    restart_result = ssh_cmd(f"systemctl restart {SERVICE_NAME}", check=False)
    time.sleep(3)

    # Verify service came back
    status = ssh_cmd(f"systemctl is-active {SERVICE_NAME}", check=False)
    if status and "active" in status:
        if restart_result is None:
            print("    Restart command transport failed, but the service is active after the recovery probe.")
        print(f"    Service status: {status}")
        post_restart_rehash_ok = refresh_remote_hashagents() is not False
        if post_restart_rehash_ok is False:
            print("    [WARNING] Unable to refresh post-restart hashagents.json")
        runtime_errors = verify_remote_publish(local_artifacts, signed_runtime_mode=True)
        publish_state = get_publish_runtime_state(local_artifacts)
        runtime_errors.extend(get_publish_state_errors(publish_state))
        if runtime_errors:
            if is_remote_publish_verification_transport_error(runtime_errors):
                print("\n[ERROR] Post-restart publish verification unavailable due to SSH transport failure.")
                print("  MeshCentral was active after restart, so no rollback was attempted without a verified content mismatch.")
                return False
            print("\n[ERROR] Post-restart publish verification failed:")
            for error in runtime_errors:
                print(f"  - {error}")
            print("  Restoring backup and restarting MeshCentral.")
            restore_agents_from_backup(backup_path, check=False)
            refresh_remote_hashagents()
            ssh_cmd(f"systemctl restart {SERVICE_NAME}", check=False)
            return False
        print("\n[SUCCESS] Deployment complete!")
    else:
        if restart_result is None:
            print("    [WARNING] Restart command transport failed and the recovery probe did not confirm recovery.")
        print(f"    [WARNING] Service status: {status}")
        print("    Check logs with: deploy.py logs 50")
        return False

    manifest_path = None
    try:
        manifest_path = write_release_manifest(ts, backup_path, status)
        print(f"  Release manifest written: {manifest_path}")
    except Exception as ex:
        print(f"  [WARNING] Failed to write release manifest: {ex}")

    # Clean staging
    ssh_cmd(f"rm -rf {STAGING_DIR}/*")
    print(f"  Staging area cleaned.")

    return True


def cmd_rollback(args):
    """Restore agents from the most recent backup."""
    print("=" * 60)
    print("  Rollback")
    print("=" * 60)

    # List backups
    backups = ssh_cmd(f"ls -1dt {BACKUP_DIR}/*/ 2>/dev/null")
    if not backups:
        print("[ERROR] No backups found.")
        return False

    backup_list = [b.rstrip("/") for b in backups.split("\n") if b.strip()]
    print("\n  Available backups:")
    for i, b in enumerate(backup_list[:10]):
        bname = b.split("/")[-1]
        count = ssh_cmd(
            f"find {b}/dataagents {b}/signedagents {b}/moduleagents -maxdepth 1 -type f 2>/dev/null | wc -l",
            check=False,
        ) or "?"
        print(f"    [{i}] {bname}  ({count.strip()} files)")

    # Select backup
    if args.index is not None:
        idx = args.index
    else:
        idx_str = input(f"\n  Select backup to restore [0]: ") or "0"
        idx = int(idx_str)

    if idx >= len(backup_list):
        print("[ERROR] Invalid selection.")
        return False

    selected = backup_list[idx]
    bname = selected.split("/")[-1]
    print(f"\n  Restoring from: {bname}")

    if not args.yes:
        resp = input("  This will overwrite current agents and restart. Continue? [y/N] ")
        if resp.lower() != "y":
            print("  Aborted.")
            return False

    # Restore
    if restore_agents_from_backup(selected) is False:
        return False

    # Rehash
    rehash_ok = refresh_remote_hashagents() is not False
    if rehash_ok is False:
        print("[WARNING] Failed to regenerate hashagents.json on the first rollback attempt. Verifying published state directly.")
    verification_errors = verify_remote_publish(get_present_local_artifacts())
    if verification_errors:
        print("[ERROR] Rollback verification failed:")
        for error in verification_errors:
            print(f"  - {error}")
        return False

    # Restart
    restart_result = ssh_cmd(f"systemctl restart {SERVICE_NAME}", check=False)
    time.sleep(3)

    status = ssh_cmd(f"systemctl is-active {SERVICE_NAME}", check=False)
    if not (status and "active" in status):
        if restart_result is None:
            print("[WARNING] Rollback restart transport failed and the recovery probe did not confirm recovery.")
        print(f"\n  Service status: {status}")
        return False
    if restart_result is None:
        print("  Restart command transport failed, but the service is active after the recovery probe.")
    print(f"\n  Service status: {status}")
    print(f"\n[SUCCESS] Rolled back to {bname}")
    return True


def cmd_config(args):
    """View or edit MeshCentral config.json."""
    if args.action == "edit":
        # Download config
        tmp = LOCAL_REPO / ".tmp_config.json"
        print(f"Downloading config from {SERVER}...")
        if not scp_download(CONFIG_FILE, tmp):
            return False

        # Get original hash
        with open(tmp, "rb") as f:
            orig_hash = hashlib.sha256(f.read()).hexdigest()

        # Open in editor
        editor = os.environ.get("EDITOR", "notepad" if sys.platform == "win32" else "nano")
        print(f"Opening in {editor}...")
        subprocess.run([editor, str(tmp)])

        # Check if changed
        with open(tmp, "rb") as f:
            new_hash = hashlib.sha256(f.read()).hexdigest()

        if orig_hash == new_hash:
            print("No changes made. Skipping upload.")
            tmp.unlink()
            return True

        # Validate JSON
        try:
            with open(tmp) as f:
                json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON: {e}")
            print(f"  Config saved at: {tmp}")
            return False

        # Backup remote config first
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        ssh_cmd(f"cp {CONFIG_FILE} {CONFIG_FILE}.bak.{ts}")

        # Upload
        print("Uploading updated config...")
        if not scp_upload(tmp, CONFIG_FILE):
            return False

        tmp.unlink()

        # Restart
        resp = input("Restart MeshCentral to apply? [y/N] ")
        if resp.lower() == "y":
            ssh_cmd(f"systemctl restart {SERVICE_NAME}")
            time.sleep(3)
            status = ssh_cmd(f"systemctl is-active {SERVICE_NAME}", check=False)
            print(f"Service status: {status}")

        print("[SUCCESS] Config updated.")
    else:
        # View config
        config = ssh_cmd(f"cat {CONFIG_FILE}")
        if config:
            try:
                parsed = json.loads(config)
                print(json.dumps(parsed, indent=2))
            except json.JSONDecodeError:
                print(config)


def cmd_logs(args):
    """View MeshCentral service logs."""
    n = args.lines or 50
    print(f"Last {n} lines of MeshCentral logs:\n")
    logs = ssh_cmd(
        f"journalctl -u {SERVICE_NAME} --no-pager -n {n} 2>/dev/null || "
        f"tail -n {n} {MESHCENTRAL_BASE}/meshcentral-data/*.log 2>/dev/null || "
        f"echo 'No logs found'",
        check=False,
    )
    if logs:
        print(logs)


def cmd_health(args):
    """Post-deploy health check: service, port, connectivity, agent count."""
    print("=" * 60)
    print("  Health Check")
    print("=" * 60)

    checks = [
        ("Service active", f"systemctl is-active {SERVICE_NAME}"),
        ("Port 4430 listening", "ss -tlnp | grep 4430 | head -1"),
        ("Port 4445 listening", "ss -tlnp | grep 4445 | head -1"),
        ("Port 4446 listening", "ss -tlnp | grep 4446 | head -1"),
        ("Node process", "pgrep -a node | grep meshcentral | head -1"),
        ("MongoDB reachable", "__CHECK_MONGO__"),
        ("Disk usage", "df -h / | tail -1"),
        ("Memory", "free -h | grep Mem"),
        ("Recent errors", f"journalctl -u {SERVICE_NAME} --no-pager -n 20 --priority=err 2>/dev/null | tail -5 || echo '(none)'"),
    ]

    payload_json = json.dumps(checks)
    remote_script = f"""python3 - <<'PY'
import json
import subprocess

checks = json.loads('''{payload_json}''')
results = []
for label, command in checks:
    if command == "__CHECK_MONGO__":
        text = ""
        ok = False
        try:
            cfg = json.load(open('/opt/meshcentral/meshcentral-data/config.json', encoding='utf-8'))
            uri = cfg['settings']['mongodb']
            mongo_cmds = [
                ['mongosh', uri, '--quiet', '--eval', 'db.stats()'],
                ['mongo', uri, '--quiet', '--eval', 'db.stats()'],
            ]
            for mongo_cmd in mongo_cmds:
                proc = subprocess.run(mongo_cmd, capture_output=True, text=True)
                output = (proc.stdout or proc.stderr or '').strip()
                if proc.returncode == 0 and output:
                    text = output
                    ok = True
                    break
            if not text:
                text = 'mongo client not found or auth failed'
        except Exception as ex:
            text = str(ex)
            ok = False
    else:
        proc = subprocess.run(command, shell=True, capture_output=True, text=True)
        text = (proc.stdout or proc.stderr or '').strip()
        ok = bool(text) and ('not found' not in text.lower())
    first_line = text.splitlines()[0] if text else ''
    results.append({{
        'label': label,
        'result': first_line,
        'ok': ok,
    }})
print(json.dumps(results))
PY"""
    raw_health = ssh_cmd(remote_script, check=False)
    parsed_health = []
    if raw_health:
        try:
            loaded = json.loads(raw_health)
            if isinstance(loaded, list):
                parsed_health = loaded
        except json.JSONDecodeError:
            parsed_health = []

    all_ok = True
    if not parsed_health:
        parsed_health = [{"label": label, "result": "", "ok": False} for label, _ in checks]

    for entry in parsed_health:
        label = entry.get("label", "")
        result = entry.get("result", "")
        status = "OK" if entry.get("ok") else "WARN"
        if status == "WARN":
            all_ok = False
        indicator = "+" if status == "OK" else "!"
        print(f"  [{indicator}] {label:<25s} {(result or '')[:60]}")

    publish_state = get_publish_runtime_state()
    if publish_state:
        publish_errors = get_publish_state_errors(publish_state)
        publish_ok = len(publish_errors) == 0
        if publish_ok is False:
            all_ok = False
        indicator = "+" if publish_ok else "!"
        summary = ", ".join(
            f"{entry['filename']}={entry.get('signed_relation', entry.get('runtime_source', 'n/a'))}/module-{format_publish_match(entry['module_matches_local'])}"
            for entry in publish_state
        )
        print(f"  [{indicator}] Publish parity             {summary[:60]}")

    print(f"\n{'─' * 60}")
    if all_ok:
        print("  All checks passed.")
    else:
        print("  Some checks returned warnings. Review above.")
    print()


def cmd_update_online(args):
    """Manually trigger agent updates for all currently-online MeshAgent nodes."""
    batch_size = max(1, args.batch_size or 50)
    login_user = args.login_user or MESHCENTRAL_CONTROL_USER
    wait_seconds = max(0, args.wait_seconds or 0)
    poll_seconds = max(5, args.poll_seconds or 10)
    activation_wait_seconds = max(0, args.activation_wait_seconds or 0)

    print("=" * 60)
    print("  Update Online Agents")
    print("=" * 60)

    login_key_file = create_temp_login_key_file()
    try:
        online_nodes = get_online_agent_nodes(login_user, login_key_file)
        if args.limit is not None:
            online_nodes = online_nodes[:args.limit]

        if not online_nodes:
            print("No online MeshAgent nodes found.")
            return True

        baseline_agct = {}
        names_by_id = {}
        print(f"  Online agents targeted: {len(online_nodes)}")
        for node in online_nodes:
            nodeid = node["_id"]
            baseline_agct[nodeid] = int(node.get("agct") or 0)
            names_by_id[nodeid] = node.get("name") or nodeid
            print(
                f"    {node.get('name') or '(unnamed)'}"
                f"  [{node.get('groupname') or 'ungrouped'}]"
                f"  agct={baseline_agct[nodeid] or 'n/a'}"
            )

        if args.dry_run:
            print("\n[DRY RUN] No update commands were submitted.")
            return True

        for index, batch in enumerate(batched([node["_id"] for node in online_nodes], batch_size), start=1):
            response = send_update_agents(batch, login_user, login_key_file)
            print(f"\n  Submitted batch {index}: {response.get('count', len(batch))} node(s)")
            time.sleep(1)

        if wait_seconds == 0:
            print("\n[SUCCESS] Update commands submitted.")
            return True

        pending = {node["_id"] for node in online_nodes}
        reconnected = watch_reconnects(
            pending,
            baseline_agct,
            login_user,
            login_key_file,
            wait_seconds,
            poll_seconds,
            "Initial watch",
        )

        activation_attempts = {}
        activation_errors = {}
        activation_warnings = {}
        if pending and args.native_activate:
            print("\n  Pending nodes still online/stuck after initial watch.")
            print("  Probing staged update payloads and triggering the rundll32 lifecycle host where safe.")
            for nodeid in sorted(pending):
                name = names_by_id.get(nodeid, nodeid)
                try:
                    update_paths = get_node_pending_updates(nodeid, login_user, login_key_file)
                    if not update_paths:
                        activation_errors[nodeid] = f"No staged *{WINDOWS_UPDATE_PACKAGE_SUFFIX} payload found"
                        print(f"    {name}: no staged update payload found")
                        continue
                    chosen_update = sorted(update_paths)[0]
                    probe = probe_remote_update_activation_inputs(nodeid, chosen_update, login_user, login_key_file)
                    missing = [label for label, ok in probe["checks"].items() if ok is not True]
                    if "UPDATE" in missing:
                        activation_errors[nodeid] = "Missing staged update payload"
                        print(f"    {name}: missing staged update payload")
                        continue
                    if "HOSTDLL" in missing:
                        activation_errors[nodeid] = "Missing installed ServiceDll required to host rundll32 lifecycle"
                        print(f"    {name}: missing installed ServiceDll required to host rundll32 lifecycle")
                        continue
                    install_paths = activate_remote_pending_update(nodeid, chosen_update, login_user, login_key_file)
                    activation_attempts[nodeid] = {
                        "update_path": chosen_update,
                        "host_dll_path": install_paths["host_dll_path"],
                        "mode": "rundll32-lifecycle-update",
                    }
                    warning_note = f" ({activation_warnings[nodeid]})" if nodeid in activation_warnings else ""
                    print(f"    {name}: launched rundll32 lifecycle update using {chosen_update}{warning_note}")
                except Exception as ex:
                    activation_errors[nodeid] = str(ex)
                    print(f"    {name}: native activation failed: {ex}")

            if activation_attempts and activation_wait_seconds > 0:
                print("\n  Watching for reconnects after native activation.")
                reconnected_after_activation = watch_reconnects(
                    pending,
                    baseline_agct,
                    login_user,
                    login_key_file,
                    activation_wait_seconds,
                    poll_seconds,
                    "Activation watch",
                )
                reconnected.update(reconnected_after_activation)

        print("\n  Reconnected after update:")
        if reconnected:
            for nodeid in sorted(reconnected):
                print(f"    {names_by_id.get(nodeid, nodeid)}")
        else:
            print("    (none observed during wait window)")

        if pending:
            print("\n  Pending / unchanged during wait window:")
            for nodeid in sorted(pending):
                print(f"    {names_by_id.get(nodeid, nodeid)}")

        if activation_attempts:
            print("\n  Native activation attempts:")
            for nodeid in sorted(activation_attempts):
                attempt = activation_attempts[nodeid]
                print(
                    f"    {names_by_id.get(nodeid, nodeid)}"
                    f"  update={attempt['update_path']}"
                    f"  hostDll={attempt['host_dll_path']}"
                )

        if activation_errors:
            print("\n  Native activation gaps:")
            for nodeid in sorted(activation_errors):
                print(f"    {names_by_id.get(nodeid, nodeid)}  {activation_errors[nodeid]}")

        if activation_warnings:
            print("\n  Native activation warnings:")
            for nodeid in sorted(activation_warnings):
                print(f"    {names_by_id.get(nodeid, nodeid)}  {activation_warnings[nodeid]}")

        print("\n[SUCCESS] Update commands submitted.")
        return True
    finally:
        try:
            os.unlink(login_key_file)
        except OSError:
            pass


def cmd_ssh(args):
    """Run an arbitrary command on the server."""
    command = " ".join(args.command)
    if not command:
        print("Usage: deploy.py ssh <command>")
        return False
    result = ssh_cmd(command, check=False)
    if result is not None:
        print(result)
        return True
    return False


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if not SERVER:
        sys.exit(
            "ERROR: MESHCENTRAL_SERVER environment variable is required.\n"
            "  Set it to the server IP/hostname, e.g.:\n"
            "    export MESHCENTRAL_SERVER=192.0.2.1"
        )
    parser = argparse.ArgumentParser(
        description="MeshAgent Deployment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("status", help="Server status and deployed agents")

    sub.add_parser("stage", help="Upload build artifacts to staging")

    deploy_p = sub.add_parser("deploy", help="Deploy staged artifacts to production")
    deploy_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    rollback_p = sub.add_parser("rollback", help="Rollback to previous backup")
    rollback_p.add_argument("-i", "--index", type=int, default=None, help="Backup index")
    rollback_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    config_p = sub.add_parser("config", help="View or edit MeshCentral config")
    config_p.add_argument("action", nargs="?", default="view", choices=["view", "edit"])

    logs_p = sub.add_parser("logs", help="View MeshCentral logs")
    logs_p.add_argument("lines", nargs="?", type=int, default=50)

    sub.add_parser("health", help="Post-deploy health check")

    update_p = sub.add_parser("update-online", help="Trigger manual updates for currently-online agents")
    update_p.add_argument("--login-user", default=MESHCENTRAL_CONTROL_USER, help="MeshCentral admin username")
    update_p.add_argument("--limit", type=int, default=None, help="Limit number of online agents to update")
    update_p.add_argument("--batch-size", type=int, default=50, help="Number of node IDs per updateAgents request")
    update_p.add_argument("--wait-seconds", type=int, default=90, help="How long to watch for reconnects after submission")
    update_p.add_argument("--poll-seconds", type=int, default=10, help="Polling interval while watching reconnects")
    update_p.add_argument("--native-activate", action=argparse.BooleanOptionalAction, default=True, help="If nodes stay stuck with a staged update payload, trigger the rundll32 lifecycle host remotely")
    update_p.add_argument("--activation-wait-seconds", type=int, default=180, help="How long to watch for reconnects after native activation remediation")
    update_p.add_argument("--dry-run", action="store_true", help="List online targets without submitting updates")

    ssh_p = sub.add_parser("ssh", help="Run a command on the server")
    ssh_p.add_argument("command", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return

    commands = {
        "status": cmd_status,
        "stage": cmd_stage,
        "deploy": cmd_deploy,
        "rollback": cmd_rollback,
        "config": cmd_config,
        "logs": cmd_logs,
        "health": cmd_health,
        "update-online": cmd_update_online,
        "ssh": cmd_ssh,
    }

    result = commands[args.cmd](args)
    if result is False:
        sys.exit(1)


if __name__ == "__main__":
    main()
