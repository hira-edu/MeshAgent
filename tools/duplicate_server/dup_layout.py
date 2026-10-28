"""Build the duplicate layouts.

Layout A reproduces /opt/meshcentral as production has it until the Stage 4 cutover (stock
MeshCentral 1.2.5 on Node 20):
  1. `npm ci` of the deployment wrapper (MeshCentral/deploy, lockfile integrity-checked), with
     node_modules/meshcentral then replaced by the pinned stock npm package production runs,
  2. deploy.py's own publish map applied to the local tree instead of SCP, with every MeshCentral
     file at production's bytes (found in the MeshCentral checkout's history by production's sha256),
  3. the read-only production capture (layout-a.tar, then the posix module capture) with its mtimes,
  4. production's image-size preload in bin/.
Layout B is the fork package as Stage 6 landed it (MeshCentral 1.3.1 plus the fork, on Node 24):
  1. `npm ci` of the deployment wrapper against its lockfile, which pins the fork tarball packed with
     `deploy/scripts/pack.js --agents <dir>` (optionally packed here, or given as a file),
  2. the served agent binaries checked against agents/agent-defaults.json (size and SHA384),
  3. only the files the fork release keeps outside the package: deploy/meshcentral-web (custom.js)
     and plugins/nativeruntime from the MeshCentral checkout's HEAD. No data-dir cores, no agent or
     signed-agent folders, no agentbuilds/, no view overrides, no bin/ and no image-size preload.
Both get the D6 `daemon` marker in node_modules/meshcentral, as production has it since 2026-10-28.
"""
import base64
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "lib"))
import meshcentral_paths  # noqa: E402  (the shared MeshCentral path helper the tests use)

from dup_common import (
    DUP_ROOT, LAYOUT_A_TAR, MESHCENTRAL_VERSION, PRODUCTION_HASHES, REPORTS, WORKTREE_ROOT,
    DupError, layout_node, layout_root, log, node_env, npm, read_json, run, sha256_file, write_json,
)

DEPLOY_PY = WORKTREE_ROOT / "deploy.py"
# The .msh manifests carry the production MeshServer, ServerID and MeshID. MeshCentral never serves
# them from the agents folders (only meshAgentsArchitectureNumbers[].localname files are loaded), and
# D8 keeps production identity out of the duplicate, so they are not copied.
EXCLUDED_SUFFIXES = (".msh",)
TAR_PREFIXES = ("meshcentral-web/", "meshcentral-data/")
# Production's image-size preload (DEP-21) as install_controller.py installs it into /opt/meshcentral/bin.
# The capture of production's older copy requires '/opt/meshcentral/node_modules/image-size', which no
# Windows layout can resolve; the tracked copy resolves image-size from the running script (A4).
# Production runs this image-size preload until the Stage 4 cutover. The release tooling retired it
# (d28ab4a4), so layout A takes its last tracked version from MeshAgent history, checked by sha256.
HARDEN_IMAGE_SIZE = PurePosixPath("tools/deployment/harden-image-size.js")
HARDEN_IMAGE_SIZE_COMMIT = "ffa5fe804254702e17507ce151ad4ff455b1c9c4"
HARDEN_IMAGE_SIZE_SHA256 = "f07d3b3a5786379cfb5bcda62cd928ff3420433a34cd9b9e390d242b1547995a"
# D6: the marker that turns MeshCentral's self-update off (meshcentral.js: serverSelfWriteAllowed = false
# when <package>/daemon exists). Production has had it since the 2026-10-28 I1 safeguard.
DAEMON_MARKER = "daemon"


def source_repo():
    """The MeshAgent checkout whose build outputs production was deployed from."""
    configured = os.environ.get("MC_DUP_SOURCE_REPO")
    if configured:
        return Path(configured).resolve()
    common = subprocess.run(["git", "-C", str(WORKTREE_ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                            capture_output=True, text=True)
    if common.returncode != 0:
        raise DupError("Cannot locate the main MeshAgent checkout: " + common.stderr.strip())
    return Path(common.stdout.strip()).resolve().parent


def meshcentral_repo():
    """The MeshCentral checkout, resolved by the shared helper exactly as the tests resolve it:
    MESHCENTRAL_ROOT, else the sibling of this MeshAgent checkout. There is no other fallback, so a
    worktree without MESHCENTRAL_ROOT fails loudly instead of using another checkout."""
    try:
        return meshcentral_paths.meshcentral_root()
    except meshcentral_paths.MeshCentralPathError as error:
        raise DupError(str(error)) from error


def wrapper_dir():
    """The deployment wrapper (Stage 1 layout): MeshCentral/deploy, named meshcentral-deploy (shared helper)."""
    try:
        return meshcentral_paths.wrapper_dir()
    except meshcentral_paths.MeshCentralPathError as error:
        raise DupError(str(error)) from error


def meshcentral_repo_path(local_path):
    """The MeshCentral repository path of a deploy.py local_path ("../MeshCentral/<path>"), else None."""
    parts = PurePosixPath(local_path.replace("\\", "/")).parts
    if parts[:2] == ("..", "MeshCentral") and len(parts) > 2:
        return PurePosixPath(*parts[2:]).as_posix()
    return None


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


def locked_meshcentral(wrapper):
    """The meshcentral entry the wrapper's lockfile pins (version, resolved, integrity)."""
    entry = (read_json(wrapper / "package-lock.json").get("packages") or {}).get("node_modules/meshcentral")
    if not entry or not entry.get("integrity") or not entry.get("version"):
        raise DupError(f"{wrapper / 'package-lock.json'} pins no meshcentral integrity")
    return entry


def install_wrapper(name, tarball=None, extra_packages=(), windows_modules_source=None):
    """Copy the wrapper package.json and lockfile and run `npm ci --omit=dev` with the layout's own Node and
    npm (the release image installs the same way; the devDependencies are the regeneration toolchain).

    npm ci checks the fork tarball against the lockfile integrity. tarball replaces the wrapper's own
    packed file (deploy/dist/...) as the file the lock pins; npm ci still refuses it unless its sha512 is
    the locked one. extra_packages (a tarball that replaces node_modules/meshcentral, layout A) go into
    the same `npm install --no-save` as the Windows-only modules, because a later `npm install` would
    prune packages it did not install. windows_modules_source is the meshcentral.js text whose win32
    module list is pre-installed (the package that will run)."""
    root = layout_root(name)
    runtime = layout_node(name)
    wrapper = wrapper_dir()
    root.mkdir(parents=True, exist_ok=True)
    record = {"wrapper": str(wrapper), "node": runtime.version}
    for filename in ("package.json", "package-lock.json"):
        source = wrapper / filename
        if not source.is_file():
            raise DupError(f"Wrapper file missing: {source}")
        shutil.copyfile(source, root / filename)
        record[filename] = sha256_file(source)
    relative = wrapper_tarball_spec(wrapper)
    if relative is None:
        raise DupError(f"{wrapper / 'package.json'} does not install meshcentral from a packed fork tarball (file:dist/...)")
    source = Path(tarball) if tarball else wrapper.joinpath(*relative.parts)
    if not source.is_file():
        raise DupError(f"The wrapper installs meshcentral from {source}, which does not exist; pack it first with "
                       "`node deploy/scripts/pack.js --agents <folder with the pinned agent builds>` in the MeshCentral "
                       "checkout, or pass --agents/--tarball to layout-b")
    target = root.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    locked = locked_meshcentral(wrapper)
    actual = "sha512-" + base64.b64encode(hashlib.sha512(target.read_bytes()).digest()).decode("ascii")
    record["wrapper_tarball"] = {"path": relative.as_posix(), "source": str(source), "sha256": sha256_file(target),
                                 "integrity": actual, "locked_integrity": locked["integrity"]}
    if actual != locked["integrity"]:
        raise DupError(f"{source} has integrity {actual}, but the wrapper lock pins {locked['integrity']}; "
                       "pack the fork with `pack.js --agents` from the commit the lock was made for")
    npm(runtime, ["ci", "--omit=dev", "--no-audit", "--no-fund"], cwd=root)
    installed = read_json(root / "node_modules" / "meshcentral" / "package.json")
    if installed.get("version") != locked["version"]:
        raise DupError(f"npm ci installed meshcentral {installed.get('version')}, the lock pins {locked['version']}")
    record["meshcentral_version"] = installed["version"]
    if windows_modules_source is None:
        windows_modules_source = (root / "node_modules" / "meshcentral" / "meshcentral.js").read_text(encoding="utf-8")
    record["windows_only_modules"] = preinstall_windows_modules(root, runtime, windows_modules_source, extra_packages)
    return record


WINDOWS_MODULES_RE = re.compile(r"if \(require\('os'\)\.platform\(\) == 'win32'\) \{ modules\.push\('(node-windows@[^']+)'\); modules\.push\('(loadavg-windows@[^']+)'\);")


def windows_modules(meshcentral_js):
    """The exact node-windows and loadavg-windows versions a meshcentral.js asks InstallModules for on win32."""
    matches = WINDOWS_MODULES_RE.findall(meshcentral_js)
    if len(matches) != 1:
        raise DupError("Cannot find MeshCentral's win32 module list in meshcentral.js")
    return list(matches[0])


def preinstall_windows_modules(root, runtime, meshcentral_js, extra_packages=()):
    """On win32 MeshCentral's mainStart adds node-windows and loadavg-windows to InstallModules and would
    `npm install --save-exact` them into the wrapper at first start (meshcentral.js mainStart). Linux
    production never needs them. Install the exact versions MeshCentral asks for, without touching
    package.json or the lockfile, so start-up installs nothing (plan 5: pre-install so nothing is
    npm-installed at start)."""
    modules = windows_modules(meshcentral_js)
    before = {name: sha256_file(root / name) for name in ("package.json", "package-lock.json")}
    npm(runtime, ["install", "--no-save", "--omit=dev", "--no-audit", "--no-fund", *[str(p) for p in extra_packages], *modules], cwd=root)
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
        if meshcentral_repo_path(config["local_path"]) is not None:
            raise DupError(f"deploy.py agent artifact {name} comes from the MeshCentral checkout ({config['local_path']}); "
                           "layout A reads only MeshAgent build outputs for agent folders")
        local_path = (repo / config["local_path"]).resolve()
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


PRODUCTION_LOADER = "node_modules/meshcentral/meshcentral.js"
# The three lines deploy.py's first module-version transform wrote. Production's loader was versioned
# by that earlier deploy, which left them with the file's CRLF; the current transform (which also adds
# the preferredModule lines, with LF) writes them with LF on a pristine 1.2.5 file.
FIRST_DEPLOY_CRLF_LINES = (
    "const modulePath = obj.path.join(moduleDirPath, modulesDir[i]);",
    "const moduleVersion = obj.fs.statSync(modulePath).mtime.toISOString();",
    "const moduleData = ['try { addModule(\"', moduleName, '\", \"', obj.escapeCodeString(obj.fs.readFileSync(modulePath).toString('binary')), '\", \"', moduleVersion, '\"); addedModules.push(\"', moduleName, '\"); } catch (ex) { }\\r\\n'];",
)


def production_loader(deploy, upstream_loader, expected_sha256):
    """Production's meshcentral.js, rebuilt from the stock 1.2.5 loader (upstream_loader, bytes) and
    deploy.py's transform helpers, then required to be byte-equal to production (expected_sha256).

    Production runs stock 1.2.5 plus deploy.py's module-version and proxy SNI transforms; the only
    other difference is the first deploy's CRLF on FIRST_DEPLOY_CRLF_LINES, restored here. Any other
    difference fails on the hash."""
    def transform(text):
        try:
            return deploy.align_proxy_certificate_sni(deploy.version_meshcentral_module_loader(text))
        except ValueError as error:
            raise DupError(f"deploy.py rejected the stock MeshCentral loader: {error}") from error

    fresh = transform(upstream_loader.decode("utf-8"))
    lines = fresh.split("\n")
    restored = 0
    for index, line in enumerate(lines):
        if line.strip() in FIRST_DEPLOY_CRLF_LINES and not line.endswith("\r"):
            lines[index] = line + "\r"
            restored += 1
    if restored != len(FIRST_DEPLOY_CRLF_LINES):
        raise DupError(f"expected {len(FIRST_DEPLOY_CRLF_LINES)} transformed loader lines, found {restored}")
    data = "\n".join(lines).encode("utf-8")
    if transform(data.decode("utf-8")).encode("utf-8") != data:
        raise DupError("the rebuilt production loader is not a fixed point of deploy.py's transforms")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise DupError(f"rebuilt production loader sha256 {actual} != production {expected_sha256} ({PRODUCTION_HASHES})")
    return data, {"source": "stock meshcentral 1.2.5 meshcentral.js + deploy.py transforms", "sha256": actual,
                  "equals_production": True, "first_deploy_crlf_lines": restored}


def git_bytes(repo, *args):
    result = subprocess.run(["git", "-c", "core.autocrlf=false", "-C", str(repo), *args], capture_output=True)
    if result.returncode != 0:
        raise DupError(f"git {' '.join(args)} in {repo} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


class ProductionBlobs:
    """Production's bytes for MeshCentral files, found in the MeshCentral checkout's history.

    Since Stage 6 the checkout's files are the 1.3.1 fork, not what production runs. The Stage 1 import
    committed production's files ("Carry production's ..." commits), so every byte production serves from
    the MeshCentral repository is a blob in HEAD's history. A file is looked up by its repository path and
    production's sha256 from evidence/live/hashes.tsv; anything not found fails loudly."""

    def __init__(self, repo):
        self.repo = Path(repo)
        self.blobs = {}

    def _candidates(self, repo_path):
        if repo_path not in self.blobs:
            raw = git_bytes(self.repo, "log", "--format=", "--raw", "--no-abbrev", "--no-renames", "HEAD", "--", repo_path)
            seen = []
            for line in raw.decode("utf-8", errors="replace").splitlines():
                fields = line.split("\t", 1)[0].split()
                if len(fields) >= 5 and fields[0].startswith(":"):
                    for blob in (fields[3], fields[2]):
                        if set(blob) != {"0"} and blob not in seen:
                            seen.append(blob)
            self.blobs[repo_path] = seen
        return self.blobs[repo_path]

    def find(self, repo_path, sha256):
        """(bytes, blob id) of the blob that path had in HEAD's history with this sha256."""
        for blob in self._candidates(repo_path):
            data = git_bytes(self.repo, "cat-file", "blob", blob)
            if hashlib.sha256(data).hexdigest() == sha256:
                return data, blob
        raise DupError(f"No version of {repo_path} in the history of {self.repo} HEAD has production's sha256 {sha256}")


def collect_core_artifacts(deploy, root):
    """deploy.py's MeshCentral files for layout A, each target at production's bytes.

    meshcentral.js is production's loader rebuilt from the stock copy (DEP-38). Every other target's
    bytes come from the MeshCentral history by production's sha256 (ProductionBlobs). A target that is
    not in production's inventory is left out and recorded: production does not have that file."""
    production = load_production_hashes()
    blobs = ProductionBlobs(meshcentral_repo())
    entries, absent = [], []
    for name, config in deploy.CORE_ARTIFACTS.items():
        repo_path = meshcentral_repo_path(config["local_path"])
        if repo_path is None:
            raise DupError(f"deploy.py core artifact {name} does not come from the MeshCentral checkout: {config['local_path']}")
        for role in deploy.get_artifact_publish_targets(config):
            target = remote_to_local(deploy, deploy.get_core_publish_path(role, config["remote_relative_path"]), root)
            relative = target.relative_to(root).as_posix()
            entry = {"name": name, "role": role, "target": relative}
            if relative == PRODUCTION_LOADER:
                upstream = (root / "node_modules" / "meshcentral" / "meshcentral.js").read_bytes()
                entry["bytes"], entry["loader"] = production_loader(deploy, upstream, production[PRODUCTION_LOADER]["sha256"])
            elif relative not in production:
                absent.append({"artifact": name, "target": relative, "reason": "not in production's inventory"})
                continue
            else:
                entry["bytes"], entry["blob"] = blobs.find(repo_path, production[relative]["sha256"])
                entry["repo_path"] = repo_path
            entries.append(entry)
    return entries, absent


def is_package_path(deploy, remote_path):
    """True for publish paths inside the installed package (node_modules/meshcentral)."""
    return remote_path.startswith(deploy.MESHCENTRAL_BASE.rstrip("/") + "/node_modules/meshcentral/")


# Data-dir shadow cores: MeshCentral serves these instead of the package's agents/ copies while they
# exist (meshcentral.js updateMeshCore). The cutover removes them (D18), so layout B has none.
SHADOW_CORE_PREFIXES = ("meshcentral-data/meshcore.js", "meshcentral-data/meshcore.min.js",
                        "meshcentral-data/modules_meshcore/", "meshcentral-data/modules_meshcore_min/")


def is_shadow_core(relative):
    return relative.startswith(SHADOW_CORE_PREFIXES)


# D16 web cutover: production's hand-made default3 overrides (main page, -min and every translation) and
# the r0 canary scripts retire, so the package's own views serve. custom.js stays. Layout B holds none.
D16_RETIRED_WEB = re.compile(r"^meshcentral-web/(views/(translations/)?default3(-min)?(_[a-z]{2}(-[a-z]{2,3})?)?\.handlebars"
                             r"|public/scripts/r0-umair-reconnect-canary(-min)?\.js)$")
D16_RETIRED_DIRS = ("meshcentral-web/views/", "meshcentral-web/views/translations/")


def is_d16_retired(relative):
    return bool(D16_RETIRED_WEB.match(relative)) or relative in D16_RETIRED_DIRS


def publish_locally(name):
    """Apply deploy.py's publish map (publish_staged_payloads) to layout A's tree, at production's bytes."""
    deploy = load_deploy()
    repo = source_repo()
    root = layout_root(name)
    agents, excluded = collect_agent_artifacts(deploy, repo)
    cores, absent = collect_core_artifacts(deploy, root)
    copies = []
    for directory in list(deploy.PUBLISH_ROLE_DIRS.values()) + list(deploy.CORE_PUBLISH_ROLE_DIRS.values()):
        remote_to_local(deploy, directory, root).mkdir(parents=True, exist_ok=True)
    for entry in agents:
        for role in entry["publish_targets"]:
            target = remote_to_local(deploy, deploy.get_publish_path(role, entry["remote_filename"]), root)
            shutil.copyfile(entry["local_path"], target)
            copies.append({"artifact": entry["name"], "role": role, "target": target.relative_to(root).as_posix(),
                           "sha256": sha256_file(target)})
    for entry in cores:
        target = root / entry["target"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(entry["bytes"])
        copies.append({"artifact": entry["name"], "role": entry["role"], "target": entry["target"],
                       "sha256": sha256_file(target), "source": entry.get("blob") and f"{entry['repo_path']}@{entry['blob']}"})
    for stray in ("MasterService.exe",):  # publish_staged_payloads removes it from all three agent folders
        for directory in deploy.PUBLISH_ROLE_DIRS.values():
            path = remote_to_local(deploy, f"{directory}/{stray}", root)
            if path.exists():
                path.unlink()
                log(f"  removed stray {path}")
    log(f"  published {len(copies)} files from deploy.py's map at production's bytes; excluded {len(excluded)} "
        f"artifacts; {len(absent)} targets production does not have")
    loader = next((e["loader"] for e in cores if "loader" in e), None)
    return {"source_repo": str(repo), "meshcentral_repo": str(meshcentral_repo()), "copies": copies,
            "excluded": excluded, "not_in_production": absent, "loader": loader,
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
        for member in members:
            if not member.isfile():
                continue
            actual = int((root / member.name).stat().st_mtime)
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


def harden_image_size_bytes():
    """The image-size preload production runs (DEP-21), from MeshAgent history at HARDEN_IMAGE_SIZE_COMMIT."""
    data = git_bytes(WORKTREE_ROOT, "show", f"{HARDEN_IMAGE_SIZE_COMMIT}:{HARDEN_IMAGE_SIZE}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != HARDEN_IMAGE_SIZE_SHA256:
        raise DupError(f"{HARDEN_IMAGE_SIZE} at {HARDEN_IMAGE_SIZE_COMMIT} has sha256 {actual}, pinned {HARDEN_IMAGE_SIZE_SHA256}")
    return data


def install_bin(name):
    """Layout A only: production's image-size preload in /opt/meshcentral/bin (DEP-21), the path-portable
    version install_controller.py installed until the release tooling retired it. refresh-signed-hashagents.py
    is not reproduced: D16 retires it (production-only, nothing reads its output; DEP-35)."""
    data = harden_image_size_bytes()
    target = layout_root(name) / "bin"
    target.mkdir(parents=True, exist_ok=True)
    (target / HARDEN_IMAGE_SIZE.name).write_bytes(data)
    return {HARDEN_IMAGE_SIZE.name: {"source": f"MeshAgent {HARDEN_IMAGE_SIZE_COMMIT}:{HARDEN_IMAGE_SIZE}", "sha256": HARDEN_IMAGE_SIZE_SHA256}}


def preload_path(name):
    """The NODE_OPTIONS --require file a layout starts with, or None.

    Layout A models production's systemd drop-in (NODE_OPTIONS=--require /opt/meshcentral/bin/harden-image-size.js).
    Layout B has no preload: the fork retires image-size with its preload (D4, DEP-21), and the duplicate
    never installs it for the fork, whether or not the package still lists image-size."""
    if name != "A":
        return None
    path = layout_root(name) / "bin" / HARDEN_IMAGE_SIZE.name
    if not path.is_file():
        raise DupError(f"layout {name} has no image-size preload at {path}; rebuild the layout")
    return path


def write_daemon_marker(name):
    """D6: node_modules/meshcentral/daemon, as production has it since the 2026-10-28 I1 safeguard. The fork
    tarball install does not carry it, so a release writes it after installing, as done here."""
    marker = layout_root(name) / "node_modules" / "meshcentral" / DAEMON_MARKER
    marker.write_bytes(b"")
    return {"path": marker.relative_to(layout_root(name)).as_posix(), "reason": "D6 / I1: blocks self-update and the admin update"}


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


def verify_package_equals_tarball(root, tgz, allowed_extra=()):
    """node_modules/meshcentral must hold exactly the tarball's files (npm's bin rewrite excepted).
    allowed_extra names files the layout adds on purpose (the D6 daemon marker)."""
    expected, bin_files = tarball_manifest(tgz)
    installed_dir = root / "node_modules" / "meshcentral"
    installed = {p.relative_to(installed_dir).as_posix(): sha256_file(p)
                 for p in installed_dir.rglob("*") if p.is_file()}
    # npm may add nothing to a package folder except a nested node_modules for bundled dependencies.
    extra = sorted(p for p in installed if p not in expected and not p.startswith("node_modules/") and p not in allowed_extra)
    missing = sorted(p for p in expected if p not in installed)
    differs = sorted(p for p in expected if p in installed and installed[p] != expected[p])
    if extra or missing or differs:
        raise DupError(f"Installed tree != {tgz}: extra {extra[:5]}, missing {missing[:5]}, differs {differs[:5]}")
    return {"tarball": str(tgz), "tarball_sha256": sha256_file(tgz), "files": len(expected),
            "npm_bin_line_endings_rewritten": bin_files, "allowed_extra": sorted(set(allowed_extra) & set(installed))}


def tarball_manifest(tgz):
    """sha256 of every file under package/ in an npm tarball, as npm installs it.

    npm's bin linker rewrites CRLF to LF in the files a package declares under "bin" (production's
    node_modules/meshcentral/bin/meshcentral carries the rewritten bytes too); every other file must be
    byte-identical."""
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


def tarball_file(tgz, name):
    with tarfile.open(tgz, "r:gz") as archive:
        member = archive.getmember("package/" + name)
        return archive.extractfile(member).read()


def build_layout_a():
    root = layout_root("A")
    if (root / "node_modules").exists():
        raise DupError(f"{root} already has node_modules; run reset/teardown before setup")
    upstream = upstream_tarball()
    stock_loader = tarball_file(upstream, "meshcentral.js").decode("utf-8")
    record = {"variant": "A", "node": layout_node("A").version,
              "wrapper": install_wrapper("A", extra_packages=[upstream], windows_modules_source=stock_loader)}
    # Production runs the stock npm package with deploy.py's copies on top; check the stock part
    # before the copies change it.
    record["upstream_package"] = verify_package_equals_tarball(root, upstream)
    installed = read_json(root / "node_modules" / "meshcentral" / "package.json").get("version")
    if installed != MESHCENTRAL_VERSION:
        raise DupError(f"layout A runs meshcentral {installed}, production runs {MESHCENTRAL_VERSION}")
    record["publish"] = publish_locally("A")
    record["capture"] = extract_production_capture("A")
    record["module_timestamps"] = overlay_module_timestamps("A")
    record["bin"] = install_bin("A")
    record["daemon"] = write_daemon_marker("A")
    record["manifest"] = str(write_manifest("A", "built"))
    record["vs_production"] = compare_with_production(record["manifest"])["summary"]
    write_json(REPORTS / "layout-A-build.json", record)
    return record


# Files the fork release keeps outside the package (D11, D26): custom.js in meshcentral-web and the
# nativeruntime plugin in meshcentral-data/plugins (the package does not ship plugins yet, TST-9).
# Repository folder (MeshCentral HEAD) -> layout folder.
FORK_RELEASE_FILES = (("deploy/meshcentral-web/", "meshcentral-web/"),
                      ("plugins/nativeruntime/", "meshcentral-data/plugins/nativeruntime/"))
# Folders the fork layout must not have: shadow cores (D18), agent and signed-agent copies, upstream
# 1.3.1's release download folder (the fork never downloads agents), and view overrides (D16).
FORK_ABSENT = ("meshcentral-data/meshcore.js", "meshcentral-data/meshcore.min.js", "meshcentral-data/recoverycore.js",
               "meshcentral-data/modules_meshcore", "meshcentral-data/modules_meshcore_min",
               "meshcentral-data/agents", "meshcentral-data/signedagents", "meshcentral-data/agentbuilds",
               "meshcentral-web/views", "bin")


def install_fork_release_files(name):
    """Copy FORK_RELEASE_FILES from the MeshCentral checkout's HEAD (git blobs, so the layout is a
    function of the commit, like the packed tarball)."""
    repo = meshcentral_repo()
    root = layout_root(name)
    copies = []
    for source, destination in FORK_RELEASE_FILES:
        listing = git_bytes(repo, "ls-tree", "-r", "-z", "HEAD", "--", source).decode("utf-8").split("\0")
        files = []
        for line in filter(None, listing):
            meta, path = line.split("\t", 1)
            mode, kind, blob = meta.split()
            if kind != "blob" or mode not in ("100644", "100755"):
                raise DupError(f"{path} in {repo} HEAD is not a regular file ({mode} {kind})")
            files.append((path, blob))
        if not files:
            raise DupError(f"{repo} HEAD has nothing under {source}; the fork release needs it")
        for path, blob in files:
            target = root / (destination + path[len(source):])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git_bytes(repo, "cat-file", "blob", blob))
            copies.append({"source": path, "blob": blob, "target": target.relative_to(root).as_posix(),
                           "sha256": sha256_file(target)})
    commit = git_bytes(repo, "rev-parse", "HEAD").decode().strip()
    log(f"  copied {len(copies)} fork release files from {repo} at {commit[:12]}")
    return {"meshcentral_repo": str(repo), "commit": commit, "copies": copies}


def parse_agent_pins(manifest):
    """Pins from agents/agent-defaults.json (schema meshcentral-fork-agents/1): {filename: (size, sha384)}."""
    if manifest.get("schema") != "meshcentral-fork-agents/1":
        raise DupError(f"agents/agent-defaults.json is not a fork agent manifest: schema {manifest.get('schema')!r}")
    pins = {}
    for entry in manifest.get("files") or []:
        if set(entry) != {"filename", "size", "sha384"} or not re.fullmatch(r"[0-9a-f]{96}", str(entry["sha384"])):
            raise DupError(f"agents/agent-defaults.json has an invalid pin: {entry}")
        pins[entry["filename"]] = (entry["size"], entry["sha384"])
    if not pins:
        raise DupError("agents/agent-defaults.json pins no agent binary, so the fork serves none")
    return pins


def sha384_file(path):
    digest = hashlib.sha384()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_agent_pins(root):
    """Every agent binary agents/agent-defaults.json pins is in the installed package with its size and SHA384."""
    agents = root / "node_modules" / "meshcentral" / "agents"
    manifest = read_json(agents / "agent-defaults.json")
    pins = parse_agent_pins(manifest)
    rows, problems = [], []
    for filename, (size, sha384) in sorted(pins.items()):
        path = agents / filename
        if not path.is_file():
            problems.append(f"{filename}: missing from the package")
            continue
        actual = {"size": path.stat().st_size, "sha384": sha384_file(path)}
        rows.append({"filename": filename, "size": actual["size"], "sha384": actual["sha384"]})
        if actual["size"] != size or actual["sha384"] != sha384:
            problems.append(f"{filename}: {actual['size']} bytes SHA384 {actual['sha384']}, pinned {size} {sha384}")
    if problems:
        raise DupError("Installed agent binaries do not match agents/agent-defaults.json: " + "; ".join(problems))
    return {"build": manifest.get("build"), "files": rows}


def pack_fork(agents_dir):
    """Pack the fork in the MeshCentral checkout with layout B's own Node: `node deploy/scripts/pack.js
    --agents <dir>` stages the pinned agent builds, packs deploy/dist/meshcentral-<version>.tgz and removes
    the staged copies. install_wrapper then requires the lock's integrity."""
    agents_dir = Path(agents_dir).resolve()
    if not agents_dir.is_dir():
        raise DupError(f"--agents folder not found: {agents_dir}")
    repo = meshcentral_repo()
    runtime = layout_node("B")
    result = run([runtime.exe, repo / "deploy" / "scripts" / "pack.js", "--json", "--agents", agents_dir],
                 cwd=repo, env=node_env(runtime), timeout=1800, capture=True)
    text = result.stdout
    record = __import__("json").loads(text[text.index("{"):text.rindex("}") + 1])
    return {"meshcentral_repo": str(repo), "agents_dir": str(agents_dir), "node": runtime.version, "pack": record}


def build_layout_b(tarball=None, agents_dir=None):
    """Layout B: the fork package as Stage 6 landed it, on Node 24.

    The package is the wrapper's packed fork tarball, installed by `npm ci` against the lockfile
    integrity. agents_dir packs it first in the MeshCentral checkout (pack.js --agents); tarball uses an
    already packed file instead of the wrapper's own deploy/dist copy. The served agent binaries must
    equal agents/agent-defaults.json. Only the fork release's own files go outside the package."""
    if tarball is not None and agents_dir is not None:
        raise DupError("layout B takes either --tarball or --agents, not both")
    root = layout_root("B")
    if (root / "node_modules").exists():
        raise DupError(f"{root} already has node_modules; run `reset --layout B` first")
    record = {"variant": "B", "node": layout_node("B").version}
    if agents_dir is not None:
        record["pack"] = pack_fork(agents_dir)
    record["wrapper"] = install_wrapper("B", tarball=tarball)
    tgz = root.joinpath(*PurePosixPath(record["wrapper"]["wrapper_tarball"]["path"]).parts)
    record["tarball"], record["tarball_sha256"] = str(tgz), sha256_file(tgz)
    record["tree_equals_tarball"] = verify_package_equals_tarball(root, tgz)
    record["agent_pins"] = verify_agent_pins(root)
    record["fork_release_files"] = install_fork_release_files("B")
    left = [relative for relative in FORK_ABSENT if (root / relative).exists()]
    if left:
        raise DupError(f"layout B must not have {left}: the fork serves its cores, agents and views from the package")
    record["daemon"] = write_daemon_marker("B")
    record["tree_equals_tarball"] = verify_package_equals_tarball(root, tgz, allowed_extra=(DAEMON_MARKER,))
    record["manifest"] = str(write_manifest("B", "built"))
    write_json(REPORTS / "layout-B-build.json", record)
    log(f"  layout B: node_modules/meshcentral {record['wrapper']['meshcentral_version']} equals {tgz.name} "
        f"({record['tree_equals_tarball']['files']} files); {len(record['agent_pins']['files'])} agent pins verified")
    return record


def layout_variant(name):
    """"A" or "B", from the layout's build record."""
    record = read_json(REPORTS / f"layout-{name}-build.json")
    variant = record.get("variant", name)
    if variant not in ("A", "B"):
        raise DupError(f"layout {name} was built as {variant!r}, which this tooling no longer supports; reset and rebuild it")
    return variant


# Production runs stock npm 1.2.5 until the Stage 4 cutover, while the fork (and the shared test reference)
# moved to 1.3.1 in Stage 6, so layout A has its own pin.
UPSTREAM_PIN = WORKTREE_ROOT / "test" / "lib" / "meshcentral_production_reference.json"


def upstream_tarball():
    """The stock npm package production runs, checked against the pin the tests use
    (test/lib/meshcentral_production_reference.json). Layout A installs it."""
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
        npm(layout_node("A"), ["pack", f"meshcentral@{MESHCENTRAL_VERSION}", "--pack-destination", str(target)], cwd=target)
    actual = base64.b64encode(hashlib.sha512(tgz.read_bytes()).digest()).decode("ascii")
    if actual != expected:
        raise DupError(f"Upstream tarball integrity {actual} != pinned {expected} ({UPSTREAM_PIN})")
    log(f"  upstream {tgz} matches the pinned integrity")
    return tgz
