"""Build the duplicate layouts.

Layout A reproduces /opt/meshcentral as production has it today:
  1. `npm ci` of the deployment wrapper (MeshCentral/deploy, lockfile integrity-checked), with
     node_modules/meshcentral then replaced by the pinned stock npm package production runs,
  2. deploy.py's own publish map applied to the local tree instead of SCP,
  3. the read-only production capture (layout-a.tar) extracted with its mtimes.
Layout B installs a MeshCentral tarball into node_modules/meshcentral with no overrides.
Layout B-stage1 installs the wrapper's own fork tarball and builds layout A's data and web folders
the same way as A (deploy.py's map without the package roles, then the capture).
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from dup_common import (
    DUP_ROOT, LAYOUT_A_TAR, MESHCENTRAL_VERSION, PRODUCTION_HASHES, PRODUCTION_UNTRACKED, REPORTS, WORKTREE_ROOT,
    DupError, layout_root, log, npm, read_json, sha256_file, write_json,
)

DEPLOY_PY = WORKTREE_ROOT / "deploy.py"
# The .msh manifests carry the production MeshServer, ServerID and MeshID. MeshCentral never serves
# them from the agents folders (only meshAgentsArchitectureNumbers[].localname files are loaded), and
# D8 keeps production identity out of the duplicate, so they are not copied.
EXCLUDED_SUFFIXES = (".msh",)
TAR_PREFIXES = ("meshcentral-web/", "meshcentral-data/")


def source_repo():
    """The MeshAgent checkout whose build outputs and ../MeshCentral sources production was deployed from."""
    configured = os.environ.get("MC_DUP_SOURCE_REPO")
    if configured:
        return Path(configured).resolve()
    common = subprocess.run(["git", "-C", str(WORKTREE_ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                            capture_output=True, text=True)
    if common.returncode != 0:
        raise DupError("Cannot locate the main MeshAgent checkout: " + common.stderr.strip())
    return Path(common.stdout.strip()).resolve().parent


def meshcentral_repo():
    """The MeshCentral checkout: MESHCENTRAL_ROOT (as for the tests), else the source repo's sibling."""
    configured = os.environ.get("MESHCENTRAL_ROOT")
    root = Path(configured).resolve() if configured else source_repo().parent / "MeshCentral"
    if not (root / "meshagent.js").is_file() or not (root / "agents").is_dir():
        raise DupError(f"{root} is not a MeshCentral fork checkout (no meshagent.js and agents/); set MESHCENTRAL_ROOT")
    return root


WRAPPER_PACKAGE_NAME = "meshcentral-deploy"


def wrapper_dir():
    """The deployment wrapper (Stage 1 layout): MeshCentral/deploy, named meshcentral-deploy."""
    directory = meshcentral_repo() / "deploy"
    manifest = directory / "package.json"
    try:
        name = read_json(manifest).get("name")
    except (OSError, ValueError, DupError) as error:
        raise DupError(f"Deployment wrapper not found: {manifest} is not readable ({error}). "
                       "The wrapper moved to deploy/ in Stage 1; use a checkout with that layout.") from error
    if name != WRAPPER_PACKAGE_NAME:
        raise DupError(f"{manifest} is named {name!r}, not {WRAPPER_PACKAGE_NAME!r}")
    return directory


def resolve_source(repo, local_path):
    """Resolve a deploy.py local_path. "../MeshCentral/..." means the MeshCentral checkout (meshcentral_repo),
    everything else is relative to the MeshAgent checkout production was built from."""
    parts = PurePosixPath(local_path.replace("\\", "/")).parts
    if parts[:2] == ("..", "MeshCentral"):
        return meshcentral_repo().joinpath(*parts[2:])
    return (repo / local_path).resolve()


def load_deploy():
    """Import this worktree's deploy.py read-only.

    deploy.py reads branding_config.local.json at import unless both lifecycle paths are given in the
    environment (deploy.py load_windows_branding_defaults). Those paths are used only by remote Windows
    activation, which the duplicate never runs, so explicit placeholders keep the secrets file closed.
    """
    saved = {key: os.environ.get(key) for key in ("MESHCENTRAL_INSTALL_ROOT", "MESHCENTRAL_LIFECYCLE_DLL")}
    os.environ["MESHCENTRAL_INSTALL_ROOT"] = r"C:\mc-dup-not-used\install-root"
    os.environ["MESHCENTRAL_LIFECYCLE_DLL"] = r"C:\mc-dup-not-used\install-root\unused.dll"
    try:
        spec = importlib.util.spec_from_file_location("deploy_readonly", DEPLOY_PY)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return module


def remote_to_local(deploy, remote_path, root):
    """Map a /opt/meshcentral path from deploy.py onto the layout root."""
    base = deploy.MESHCENTRAL_BASE.rstrip("/") + "/"
    if not remote_path.startswith(base):
        raise DupError(f"deploy.py publish path {remote_path} is outside {deploy.MESHCENTRAL_BASE}")
    relative = remote_path[len(base):]
    if not relative or ".." in relative.split("/"):
        raise DupError(f"Unsafe publish path {remote_path}")
    return root.joinpath(*relative.split("/"))


def wrapper_tarball_spec(wrapper):
    """The wrapper's meshcentral dependency when it is a local tarball (file:dist/...), else None."""
    spec = (read_json(wrapper / "package.json").get("dependencies") or {}).get("meshcentral", "")
    if not spec.startswith("file:"):
        return None
    relative = PurePosixPath(spec[len("file:"):])
    if relative.is_absolute() or ".." in relative.parts:
        raise DupError(f"Wrapper meshcentral dependency {spec!r} must stay inside the wrapper")
    return relative


def install_wrapper(name, extra_packages=()):
    """Copy the wrapper package.json and lockfile and run `npm ci` (integrity-checked against the lock).
    Since Stage 1 the wrapper installs the fork package from a tarball packed from the checkout
    (deploy/dist); it is copied beside the layout's package.json so the lockfile pins it.
    extra_packages (a tarball that replaces node_modules/meshcentral) go into the same
    `npm install --no-save` as the Windows-only modules, because a later `npm install` would prune
    packages it did not install."""
    root = layout_root(name)
    wrapper = wrapper_dir()
    root.mkdir(parents=True, exist_ok=True)
    record = {"wrapper": str(wrapper)}
    for filename in ("package.json", "package-lock.json"):
        source = wrapper / filename
        if not source.is_file():
            raise DupError(f"Wrapper file missing: {source}")
        shutil.copyfile(source, root / filename)
        record[filename] = sha256_file(source)
    tarball = wrapper_tarball_spec(wrapper)
    if tarball is not None:
        source = wrapper.joinpath(*tarball.parts)
        if not source.is_file():
            raise DupError(f"The wrapper installs meshcentral from {source}, which does not exist; "
                           "pack it first with `node deploy/scripts/pack.js` in the MeshCentral checkout")
        target = root.joinpath(*tarball.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        record["wrapper_tarball"] = {"path": tarball.as_posix(), "sha256": sha256_file(target)}
    npm(["ci", "--no-audit", "--no-fund"], cwd=root)
    installed = read_json(root / "node_modules" / "meshcentral" / "package.json")
    if installed.get("version") != MESHCENTRAL_VERSION:
        raise DupError(f"npm ci installed meshcentral {installed.get('version')}, expected {MESHCENTRAL_VERSION}")
    record["meshcentral_version"] = installed["version"]
    record["windows_only_modules"] = preinstall_windows_modules(root, extra_packages)
    return record


WINDOWS_MODULES_RE = re.compile(r"if \(require\('os'\)\.platform\(\) == 'win32'\) \{ modules\.push\('(node-windows@[^']+)'\); modules\.push\('(loadavg-windows@[^']+)'\);")


def preinstall_windows_modules(root, extra_packages=()):
    """On win32 MeshCentral's mainStart adds node-windows and loadavg-windows to InstallModules and would
    `npm install --save-exact` them into the wrapper at first start (meshcentral.js mainStart). Linux
    production never needs them. Install the exact versions MeshCentral asks for, without touching
    package.json or the lockfile, so start-up installs nothing (plan 5: pre-install so nothing is
    npm-installed at start)."""
    source = (root / "node_modules" / "meshcentral" / "meshcentral.js").read_text(encoding="utf-8")
    matches = WINDOWS_MODULES_RE.findall(source)
    if len(matches) != 1:
        raise DupError("Cannot find MeshCentral's win32 module list in meshcentral.js")
    modules = list(matches[0])
    before = {name: sha256_file(root / name) for name in ("package.json", "package-lock.json")}
    npm(["install", "--no-save", "--no-audit", "--no-fund", *[str(p) for p in extra_packages], *modules], cwd=root)
    after = {name: sha256_file(root / name) for name in ("package.json", "package-lock.json")}
    if before != after:
        raise DupError("npm install --no-save changed package.json or package-lock.json")
    return modules


def collect_agent_artifacts(deploy, repo):
    """Agent payloads from deploy.ARTIFACTS, resolved against the checkout production was built from."""
    entries, excluded = [], []
    for name, config in deploy.ARTIFACTS.items():
        targets = deploy.get_artifact_publish_targets(config)
        if not targets:
            excluded.append({"name": name, "reason": "deploy.py publishes it to no agent folder"})
            continue
        if config["remote_filename"].endswith(EXCLUDED_SUFFIXES):
            excluded.append({"name": name, "reason": "production identity manifest (D8); MeshCentral does not serve .msh files"})
            continue
        local_path = resolve_source(repo, config["local_path"])
        if not local_path.is_file():
            raise DupError(f"deploy.py artifact {name} is missing at {local_path}; build the agent first")
        entries.append({"name": name, "remote_filename": config["remote_filename"], "local_path": str(local_path),
                        "publish_targets": targets})
    missing = sorted(set(deploy.REQUIRED_AGENT_ARTIFACTS) - {e["name"] for e in entries}
                     - {e["name"] for e in excluded})
    if missing:
        raise DupError("Required deploy artifacts missing: " + ", ".join(missing))
    report = deploy.validate_local_service_bundle_artifacts(entries)
    if report["ok"] is not True:
        raise DupError("deploy.py service bundle contract failed: " + "; ".join(report["errors"]))
    return entries, excluded


def versioned_loader(deploy, staged_path, root):
    """The meshcentral.js deploy.py publishes.

    Since Stage 1 deploy.py stages the fork's committed loader (CORE_ARTIFACTS["meshcentral.js"]), which
    holds production's bytes: production's installed loader had been versioned by an earlier deploy, so
    it keeps CRLF on lines a fresh run on pristine 1.2.5 writes with LF. The file is used only if deploy.py's
    transforms leave it unchanged and it equals a fresh run on the layout's own stock npm copy apart from
    line endings."""
    staged_path = Path(staged_path)
    if not staged_path.is_file():
        raise DupError(f"deploy.py's staged loader is missing at {staged_path}")
    staged = staged_path.read_bytes()
    staged_text = staged.decode("utf-8")
    def transform(text):
        try:
            return deploy.align_proxy_certificate_sni(deploy.version_meshcentral_module_loader(text))
        except ValueError as error:
            raise DupError(f"deploy.py rejected a MeshCentral loader: {error}") from error

    if transform(staged_text) != staged_text:
        raise DupError(f"{staged_path} is not a fully staged loader (deploy.py transforms would change it)")
    installed = (root / "node_modules" / "meshcentral" / "meshcentral.js").read_bytes().decode("utf-8")
    fresh = transform(installed).encode("utf-8")
    if staged.replace(b"\r\n", b"\n") != fresh.replace(b"\r\n", b"\n"):
        raise DupError(f"{staged_path} differs from what deploy.py generates from the installed MeshCentral")
    return staged, {"source": str(staged_path), "sha256": sha256_file(staged_path),
                    "equals_fresh_transform": staged == fresh,
                    "equals_fresh_transform_ignoring_line_endings": True}


def is_package_path(deploy, remote_path):
    """True for publish paths inside the installed package (node_modules/meshcentral)."""
    return remote_path.startswith(deploy.MESHCENTRAL_BASE.rstrip("/") + "/node_modules/meshcentral/")


def collect_core_artifacts(deploy, repo, root, include_package=True):
    entries = []
    for name, config in deploy.CORE_ARTIFACTS.items():
        targets = deploy.get_artifact_publish_targets(config)
        if not include_package:
            targets = tuple(role for role in targets if not is_package_path(
                deploy, deploy.get_core_publish_path(role, config["remote_relative_path"])))
            if not targets:
                continue
        entry = {"name": name, "remote_relative_path": config["remote_relative_path"], "publish_targets": targets}
        if name == "meshcentral.js":
            entry["bytes"], entry["loader"] = versioned_loader(deploy, resolve_source(repo, config["local_path"]), root)
        else:
            local_path = resolve_source(repo, config["local_path"])
            if not local_path.is_file():
                raise DupError(f"deploy.py core artifact {name} is missing at {local_path}")
            entry["local_path"] = str(local_path)
        entries.append(entry)
    return entries


def publish_locally(name, include_package=True):
    """Apply deploy.py's publish map (publish_staged_payloads) to the local tree.

    include_package=False leaves node_modules/meshcentral alone (B-stage1: the package is the fork
    tarball), so only the data and web folders get deploy.py's copies."""
    deploy = load_deploy()
    repo = source_repo()
    root = layout_root(name)
    agents, excluded = collect_agent_artifacts(deploy, repo)
    cores = collect_core_artifacts(deploy, repo, root, include_package)
    copies = []
    skipped_package_paths = []
    for directory in list(deploy.PUBLISH_ROLE_DIRS.values()) + list(deploy.CORE_PUBLISH_ROLE_DIRS.values()):
        if include_package or not is_package_path(deploy, directory.rstrip("/") + "/"):
            remote_to_local(deploy, directory, root).mkdir(parents=True, exist_ok=True)
    for entry in agents:
        for role in entry["publish_targets"]:
            remote_path = deploy.get_publish_path(role, entry["remote_filename"])
            if not include_package and is_package_path(deploy, remote_path):
                skipped_package_paths.append(remote_path)
                continue
            target = remote_to_local(deploy, remote_path, root)
            shutil.copyfile(entry["local_path"], target)
            copies.append({"artifact": entry["name"], "role": role, "target": str(target.relative_to(root)),
                           "sha256": sha256_file(target)})
    for entry in cores:
        for role in entry["publish_targets"]:
            target = remote_to_local(deploy, deploy.get_core_publish_path(role, entry["remote_relative_path"]), root)
            target.parent.mkdir(parents=True, exist_ok=True)
            if "bytes" in entry:
                target.write_bytes(entry["bytes"])
            else:
                shutil.copyfile(entry["local_path"], target)
            copies.append({"artifact": entry["name"], "role": role, "target": str(target.relative_to(root)),
                           "sha256": sha256_file(target)})
    for stray in ("MasterService.exe",):  # publish_staged_payloads removes it from all three agent folders
        for directory in deploy.PUBLISH_ROLE_DIRS.values():
            path = remote_to_local(deploy, f"{directory}/{stray}", root)
            if path.exists():
                path.unlink()
                log(f"  removed stray {path}")
    log(f"  published {len(copies)} files from deploy.py's map; excluded {len(excluded)} artifacts")
    loader = next((e["loader"] for e in cores if e["name"] == "meshcentral.js"), None)
    return {"source_repo": str(repo), "meshcentral_repo": str(meshcentral_repo()), "copies": copies,
            "excluded": excluded, "loader": loader, "include_package": include_package,
            "skipped_package_paths": skipped_package_paths,
            "not_reproduced": [
                "refresh_remote_hashagents (SSH only); MeshCentral 1.2.5 never reads hashagents.json "
                "(const reassignment inside try, meshcentral.js updateMeshAgentsTable)",
                "file owners and modes (Windows)"]}


def extract_production_capture(name):
    """Extract layout-a.tar over the tree, keeping the captured mtimes (module mtimes are module versions)."""
    root = layout_root(name)
    if not LAYOUT_A_TAR.is_file():
        raise DupError(f"Production capture missing: {LAYOUT_A_TAR}")
    extracted = []
    with tarfile.open(LAYOUT_A_TAR) as archive:
        members = archive.getmembers()
        for member in members:
            if not member.name.startswith(TAR_PREFIXES) or ".." in member.name.split("/"):
                raise DupError(f"Unexpected member in {LAYOUT_A_TAR}: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise DupError(f"Unsupported member type in {LAYOUT_A_TAR}: {member.name}")
        archive.extractall(root, members=members, filter="data")
    with tarfile.open(LAYOUT_A_TAR) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = root / member.name
            actual = int(path.stat().st_mtime)
            if actual != int(member.mtime):
                raise DupError(f"mtime not preserved for {member.name}: {actual} != {int(member.mtime)}")
            extracted.append(member.name)
    log(f"  extracted {len(extracted)} files from layout-a.tar with original mtimes")
    return {"tar": str(LAYOUT_A_TAR), "tar_sha256": sha256_file(LAYOUT_A_TAR), "files": len(extracted)}


MODULE_TAR_PREFIXES = ("meshcentral-data/meshcore", "meshcentral-data/modules_meshcore")


def pax_mtime_ns(member):
    """Exact mtime in nanoseconds from a posix (pax) member; the float tarfile exposes is not exact."""
    text = member.pax_headers.get("mtime")
    if text is None:
        raise DupError(f"{member.name} has no pax mtime; the module capture must be a posix-format tar")
    seconds, _, fraction = text.partition(".")
    return int(seconds) * 1_000_000_000 + int((fraction + "000000000")[:9])


def module_timestamps(tar_path=None):
    """{relative path: mtime ns} for every member of the posix module capture."""
    from dup_common import LAYOUT_A_MODULES_TAR
    tar_path = tar_path or LAYOUT_A_MODULES_TAR
    if not Path(tar_path).is_file():
        raise DupError(f"Module capture missing: {tar_path}")
    with tarfile.open(tar_path) as archive:
        return {m.name.rstrip("/"): pax_mtime_ns(m) for m in archive.getmembers()}


def overlay_module_timestamps(name, tar_path=None):
    """Apply the posix capture's nanosecond mtimes to meshcore*.js and modules_meshcore* after layout-a.tar.

    The capture holds the same bytes as layout-a.tar; it exists for the sub-second mtimes, which are the
    module versions agents compare. Content that disagrees with the first capture is an error."""
    import hashlib
    from dup_common import LAYOUT_A_MODULES_TAR
    tar_path = Path(tar_path or LAYOUT_A_MODULES_TAR)
    root = layout_root(name)
    applied = {}
    with tarfile.open(tar_path) as archive:
        members = archive.getmembers()
        for member in members:
            if not member.name.startswith(MODULE_TAR_PREFIXES) or ".." in member.name.split("/"):
                raise DupError(f"Unexpected member in {tar_path}: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise DupError(f"Unsupported member type in {tar_path}: {member.name}")
            path = root / member.name
            if member.isfile():
                if not path.is_file():
                    raise DupError(f"{member.name} is in the module capture but not in the layout")
                expected = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
                if sha256_file(path) != expected:
                    raise DupError(f"{member.name} differs between layout-a.tar and {tar_path.name}")
        # Files first, then folders, so setting a file time cannot disturb its folder's time.
        for member in sorted(members, key=lambda m: m.isdir()):
            path = root / member.name
            mtime_ns = pax_mtime_ns(member)
            os.utime(path, ns=(path.stat().st_atime_ns, mtime_ns))
            actual = path.stat().st_mtime_ns
            # NTFS keeps 100 ns ticks; module versions use milliseconds.
            if actual // 1_000_000 != mtime_ns // 1_000_000 or abs(actual - mtime_ns) >= 100:
                raise DupError(f"mtime not applied to {member.name}: {actual} != {mtime_ns}")
            applied[member.name.rstrip("/")] = mtime_ns
    log(f"  applied nanosecond mtimes to {len(applied)} module entries from {tar_path.name}")
    return {"tar": str(tar_path), "tar_sha256": sha256_file(tar_path), "entries": len(applied)}


def install_bin(name):
    """Production keeps harden-image-size.js and refresh-signed-hashagents.py in /opt/meshcentral/bin."""
    target = layout_root(name) / "bin"
    target.mkdir(parents=True, exist_ok=True)
    record = {}
    for filename in ("harden-image-size.js", "refresh-signed-hashagents.py"):
        source = PRODUCTION_UNTRACKED / filename
        if not source.is_file():
            raise DupError(f"Captured production file missing: {source}")
        shutil.copyfile(source, target / filename)
        record[filename] = sha256_file(target / filename)
    return record


def iso_mtime(stat_result):
    return datetime.fromtimestamp(stat_result.st_mtime_ns / 1e9, tz=timezone.utc).isoformat(timespec="microseconds")


def write_manifest(name, label):
    root = layout_root(name)
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            stat = path.stat()
            rows.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path),
                         "size": stat.st_size, "mtime": iso_mtime(stat), "mtime_epoch": int(stat.st_mtime)})
    manifest = {"layout": name, "label": label, "root": str(root), "created": datetime.now(timezone.utc).isoformat(),
                "files": rows}
    path = REPORTS / f"manifest-{name}-{label}.json"
    write_json(path, manifest)
    log(f"  manifest: {len(rows)} files -> {path}")
    return path


# Production paths compared against the duplicate. The rest of the production data dir is runtime
# state (certificates, databases, logs, backups, config history) that the duplicate never copies.
COMPARED_PREFIXES = (
    "node_modules/meshcentral/", "meshcentral-web/", "bin/",
    "meshcentral-data/meshcore.js", "meshcentral-data/meshcore.min.js", "meshcentral-data/recoverycore.js",
    "meshcentral-data/modules_meshcore/", "meshcentral-data/modules_meshcore_min/",
    "meshcentral-data/agents/", "meshcentral-data/signedagents/", "meshcentral-data/plugins/",
)


def load_production_hashes():
    rows = {}
    for line in PRODUCTION_HASHES.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and len(parts[0]) == 64:
            rows[parts[3]] = {"sha256": parts[0], "size": int(parts[1]), "mtime_epoch": int(parts[2])}
    if len(rows) < 2000:
        raise DupError(f"Production hash inventory looks truncated: {len(rows)} rows in {PRODUCTION_HASHES}")
    return rows


def compare_with_production(manifest_path):
    manifest = read_json(manifest_path)
    local = {row["path"]: row for row in manifest["files"]}
    production = load_production_hashes()
    result = {"equal": [], "content_differs": [], "production_only": [], "duplicate_only": [], "mtime_differs": []}
    for path, prod in sorted(production.items()):
        if not path.startswith(COMPARED_PREFIXES):
            continue
        mine = local.get(path)
        if mine is None:
            result["production_only"].append(path)
        elif mine["sha256"] != prod["sha256"]:
            result["content_differs"].append(path)
        else:
            result["equal"].append(path)
            if path.startswith(("meshcentral-data/modules_meshcore", "meshcentral-data/meshcore")) and \
                    mine["mtime_epoch"] != prod["mtime_epoch"]:
                result["mtime_differs"].append({"path": path, "duplicate": mine["mtime_epoch"],
                                                "production": prod["mtime_epoch"]})
    for path in sorted(local):
        if path.startswith(COMPARED_PREFIXES) and path not in production:
            result["duplicate_only"].append(path)
    summary = {key: len(value) for key, value in result.items()}
    report = {"manifest": str(manifest_path), "production_inventory": str(PRODUCTION_HASHES),
              "summary": summary, **result}
    path = REPORTS / (Path(manifest_path).stem + "-vs-production.json")
    write_json(path, report)
    log(f"  vs production: {summary} -> {path}")
    return report


def verify_package_equals_tarball(root, tgz):
    """node_modules/meshcentral must hold exactly the tarball's files (npm's bin rewrite excepted)."""
    expected, bin_files = tarball_manifest(tgz)
    installed_dir = root / "node_modules" / "meshcentral"
    installed = {p.relative_to(installed_dir).as_posix(): sha256_file(p)
                 for p in installed_dir.rglob("*") if p.is_file()}
    # npm may add nothing to a package folder except a nested node_modules for bundled dependencies.
    extra = sorted(p for p in installed if p not in expected and not p.startswith("node_modules/"))
    missing = sorted(p for p in expected if p not in installed)
    differs = sorted(p for p in expected if p in installed and installed[p] != expected[p])
    if extra or missing or differs:
        raise DupError(f"Installed tree != {tgz}: extra {extra[:5]}, missing {missing[:5]}, differs {differs[:5]}")
    return {"tarball": str(tgz), "tarball_sha256": sha256_file(tgz), "files": len(expected),
            "npm_bin_line_endings_rewritten": bin_files}


def build_layout_a():
    root = layout_root("A")
    if (root / "node_modules").exists():
        raise DupError(f"{root} already has node_modules; run reset/teardown before setup")
    upstream = upstream_tarball()
    record = {"variant": "A", "wrapper": install_wrapper("A", [upstream])}
    # Production runs the stock npm package with deploy.py's copies on top; check the stock part
    # before the copies change it.
    record["upstream_package"] = verify_package_equals_tarball(root, upstream)
    record["publish"] = publish_locally("A")
    record["capture"] = extract_production_capture("A")
    record["module_timestamps"] = overlay_module_timestamps("A")
    record["bin"] = install_bin("A")
    record["manifest"] = str(write_manifest("A", "built"))
    record["vs_production"] = compare_with_production(record["manifest"])["summary"]
    write_json(REPORTS / "layout-A-build.json", record)
    return record


def tarball_manifest(tgz):
    """sha256 of every file under package/ in an npm tarball, as npm installs it.

    npm's bin linker rewrites CRLF to LF in the files a package declares under "bin" (production's
    node_modules/meshcentral/bin/meshcentral carries the rewritten bytes too); every other file must be
    byte-identical."""
    import hashlib
    contents = {}
    with tarfile.open(tgz, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if not member.name.startswith("package/"):
                raise DupError(f"Unexpected tarball member {member.name}")
            contents[member.name[len("package/"):]] = archive.extractfile(member).read()
    if "package.json" not in contents:
        raise DupError(f"{tgz} has no package/package.json")
    bins = __import__("json").loads(contents["package.json"]).get("bin") or {}
    bins = {bins} if isinstance(bins, str) else set(bins.values())
    bins = {b.removeprefix("./") for b in bins}
    rows = {}
    for name, data in contents.items():
        if name in bins:
            data = data.replace(b"\r\n", b"\n")
        rows[name] = hashlib.sha256(data).hexdigest()
    return rows, sorted(bins)


def build_layout_b(tgz=None, stage1=False):
    """Layout B.

    tgz: install that tarball into node_modules/meshcentral with no override copies.
    stage1: B-stage1, the Stage 1 fork as production would run it. The package is the wrapper's own
    fork tarball (npm ci checks it against the lockfile integrity), and the data and web folders are
    built the way layout A builds them: deploy.py's map without its package roles, then the
    production capture with its module mtimes. The config is generated with layout A's profile."""
    if stage1 == (tgz is not None):
        raise DupError("layout B needs exactly one of a tarball or the Stage 1 variant")
    root = layout_root("B")
    if (root / "node_modules").exists():
        raise DupError(f"{root} already has node_modules; run `reset --layout B` first")
    if stage1:
        record = {"variant": "stage1", "wrapper": install_wrapper("B")}
        if "wrapper_tarball" not in record["wrapper"]:
            raise DupError("B-stage1 needs a wrapper that installs the fork from a packed tarball (file:dist/...)")
        tgz = root.joinpath(*PurePosixPath(record["wrapper"]["wrapper_tarball"]["path"]).parts)
    else:
        tgz = Path(tgz).resolve()
        if not tgz.is_file():
            raise DupError(f"Tarball not found: {tgz}")
        record = {"variant": "B", "wrapper": install_wrapper("B", [tgz])}
    record["tarball"], record["tarball_sha256"] = str(tgz), sha256_file(tgz)
    record["tree_equals_tarball"] = verify_package_equals_tarball(root, tgz)
    if stage1:
        record["publish"] = publish_locally("B", include_package=False)
        record["capture"] = extract_production_capture("B")
        record["module_timestamps"] = overlay_module_timestamps("B")
        # deploy.py's package roles were left out, so the package must still equal the tarball.
        verify_package_equals_tarball(root, tgz)
    else:
        for override in (root / "meshcentral-web", root / "meshcentral-data" / "meshcore.js",
                         root / "meshcentral-data" / "modules_meshcore", root / "meshcentral-data" / "agents"):
            if override.exists():
                raise DupError(f"Layout B must not hold override copies: {override}")
    record["bin"] = install_bin("B")
    record["manifest"] = str(write_manifest("B", "built"))
    if stage1:
        record["vs_production"] = compare_with_production(record["manifest"])["summary"]
    write_json(REPORTS / "layout-B-build.json", record)
    log(f"  layout B ({record['variant']}): node_modules/meshcentral equals {tgz.name} "
        f"({record['tree_equals_tarball']['files']} files)")
    return record


def layout_variant(name):
    """"A", "B" or "stage1", from the layout's build record."""
    record = read_json(REPORTS / f"layout-{name}-build.json")
    return record.get("variant", name)


UPSTREAM_PIN = WORKTREE_ROOT / "test" / "lib" / "meshcentral_upstream_reference.json"


def upstream_tarball():
    """The stock npm package production runs, checked against the pin the tests use
    (test/lib/meshcentral_upstream_reference.json). Layout A installs it; `layout-b --standin` too."""
    pin = read_json(UPSTREAM_PIN)
    if pin.get("name") != "meshcentral" or pin.get("version") != MESHCENTRAL_VERSION:
        raise DupError(f"{UPSTREAM_PIN} pins {pin.get('name')}@{pin.get('version')}, expected meshcentral@{MESHCENTRAL_VERSION}")
    algorithm, expected = pin["integrity"].split("-", 1)
    if algorithm != "sha512":
        raise DupError(f"Unexpected upstream integrity algorithm {algorithm}")
    target = DUP_ROOT / "downloads" / "upstream"
    target.mkdir(parents=True, exist_ok=True)
    tgz = target / f"meshcentral-{MESHCENTRAL_VERSION}.tgz"
    if not tgz.is_file():
        npm(["pack", f"meshcentral@{MESHCENTRAL_VERSION}", "--pack-destination", str(target)], cwd=target)
    actual = base64.b64encode(hashlib.sha512(tgz.read_bytes()).digest()).decode("ascii")
    if actual != expected:
        raise DupError(f"Upstream tarball integrity {actual} != pinned {expected} ({UPSTREAM_PIN})")
    log(f"  upstream {tgz} matches the pinned integrity")
    return tgz
