"""Contract tests for tools/duplicate_server (work package A1).

Runs without the duplicate running and without network. It uses a temporary MC_DUP_ROOT, synthetic
denylists and fixtures, and these read-only inputs, which must exist (missing ones fail loudly):
  - the MeshCentral checkout (MESHCENTRAL_ROOT or the sibling): the deploy/ wrapper's config template
    and lockfile, and its git history, which holds production's MeshCentral files (layout A),
  - the production meshcentral 1.2.5 reference (python test/lib/fetch_upstream_reference.py --pin
    test/lib/meshcentral_production_reference.json),
  - the SSOT evidence folder (summary.txt for the production key set).
"""
import hashlib
import io
import json
import os
import secrets
import sys
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace

TEMP_ROOT = Path(tempfile.mkdtemp(prefix="mc-dup-contract-"))
os.environ["MC_DUP_ROOT"] = str(TEMP_ROOT / "mc-dup")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "duplicate_server"))

sys.path.insert(0, str(ROOT / "test" / "lib"))
import meshcentral_paths  # noqa: E402
import dup_common  # noqa: E402
import dup_config  # noqa: E402
import dup_checklist  # noqa: E402
import dup_install  # noqa: E402
import dup_layout  # noqa: E402
import preflight_agent  # noqa: E402


def expect_error(fn, fragment):
    try:
        fn()
    except dup_common.DupError as error:
        assert fragment in str(error), f"expected {fragment!r} in {error}"
        return
    raise AssertionError(f"expected DupError containing {fragment!r}")


def test_runtime_root_is_isolated():
    assert dup_common.DUP_ROOT == TEMP_ROOT / "mc-dup"
    expect_error(dup_common.safe_root_for_delete, "missing .mc-dup-root")
    dup_common.create_root()
    assert dup_common.safe_root_for_delete() == dup_common.DUP_ROOT.resolve()


def test_deploy_import_keeps_branding_secrets_closed():
    before = {k: os.environ.get(k) for k in ("MESHCENTRAL_INSTALL_ROOT", "MESHCENTRAL_LIFECYCLE_DLL")}
    deploy = dup_layout.load_deploy()
    # The explicit placeholders short-circuit load_windows_branding_defaults before any file is read.
    assert deploy.WINDOWS_BRANDING_DEFAULTS["install_root"].startswith("C:\\mc-dup-not-used")
    assert {k: os.environ.get(k) for k in before} == before, "environment must be restored after import"
    return deploy


def test_publish_paths_map_onto_layout(deploy):
    root = Path("C:/layout")
    for directory in list(deploy.PUBLISH_ROLE_DIRS.values()) + list(deploy.CORE_PUBLISH_ROLE_DIRS.values()):
        local = dup_layout.remote_to_local(deploy, directory, root)
        assert local.is_relative_to(root)
    assert dup_layout.remote_to_local(deploy, deploy.get_core_publish_path("data-core", "modules_meshcore/x.js"), root) == \
        root / "meshcentral-data" / "modules_meshcore" / "x.js"
    assert dup_layout.remote_to_local(deploy, deploy.get_publish_path("module", "MeshService64.exe"), root) == \
        root / "node_modules" / "meshcentral" / "agents" / "MeshService64.exe"
    expect_error(lambda: dup_layout.remote_to_local(deploy, "/etc/passwd", root), "outside")
    expect_error(lambda: dup_layout.remote_to_local(deploy, deploy.MESHCENTRAL_BASE + "/../x", root), "Unsafe")


def test_agent_artifacts_exclude_identity_manifests():
    repo = TEMP_ROOT / "repo"
    (repo / "bin").mkdir(parents=True)
    for name in ("a.exe", "a.msh", "m.exe"):
        (repo / "bin" / name).write_bytes(b"x")
    fake = SimpleNamespace(
        ARTIFACTS={"A.exe": {"local_path": "bin/a.exe", "remote_filename": "A.exe", "publish_targets": ("data",)},
                   "A.msh": {"local_path": "bin/a.msh", "remote_filename": "A.msh", "publish_targets": ("data",)},
                   "M.exe": {"local_path": "bin/m.exe", "remote_filename": "M.exe", "publish_targets": ()}},
        REQUIRED_AGENT_ARTIFACTS={"A.exe", "A.msh"},
        get_artifact_publish_targets=lambda config: tuple(config.get("publish_targets", ())),
        validate_local_service_bundle_artifacts=lambda entries: {"ok": True, "errors": []})
    entries, excluded = dup_layout.collect_agent_artifacts(fake, repo)
    assert [e["name"] for e in entries] == ["A.exe"]
    assert {e["name"] for e in excluded} == {"A.msh", "M.exe"}
    fake.validate_local_service_bundle_artifacts = lambda entries: {"ok": False, "errors": ["mismatch"]}
    expect_error(lambda: dup_layout.collect_agent_artifacts(fake, repo), "mismatch")
    (repo / "bin" / "a.exe").unlink()
    expect_error(lambda: dup_layout.collect_agent_artifacts(fake, repo), "missing")


def test_reset_selects_only_its_own_reports():
    reports = dup_common.REPORTS
    reports.mkdir(parents=True, exist_ok=True)
    names = ["manifest-A-built.json", "manifest-A-built-vs-production.json", "layout-A-build.json", "probe-A.json",
             "checklist-B-stage1-20261028T000000Z.json", "layout-B-build.json", "probe-B.json", "installs.json"]
    for name in names:
        (reports / name).write_text("{}", encoding="utf-8")
    assert [p.name for p in dup_common.layout_reports("B")] == \
        ["checklist-B-stage1-20261028T000000Z.json", "layout-B-build.json", "probe-B.json"]
    assert [p.name for p in dup_common.layout_reports("A")] == \
        ["layout-A-build.json", "manifest-A-built-vs-production.json", "manifest-A-built.json", "probe-A.json"]
    for name in names:
        (reports / name).unlink()


def test_production_loader_rebuild(deploy):
    # Layout A's meshcentral.js is production's: stock 1.2.5 plus deploy.py's transforms, which must
    # reproduce production's sha256 exactly. The fork's committed loader is not used for it.
    pristine = (meshcentral_paths.upstream_package_dir(pin_path=meshcentral_paths.PRODUCTION_REFERENCE_PIN_PATH) / "meshcentral.js").read_bytes()
    production = dup_layout.load_production_hashes()[dup_layout.PRODUCTION_LOADER]["sha256"]
    data, record = dup_layout.production_loader(deploy, pristine, production)
    assert hashlib.sha256(data).hexdigest() == production and record["equals_production"] is True
    assert record["first_deploy_crlf_lines"] == len(dup_layout.FIRST_DEPLOY_CRLF_LINES)
    assert data.replace(b"\r\n", b"\n") == deploy.align_proxy_certificate_sni(
        deploy.version_meshcentral_module_loader(pristine.decode("utf-8"))).encode("utf-8").replace(b"\r\n", b"\n")
    expect_error(lambda: dup_layout.production_loader(deploy, pristine, "0" * 64), "!= production")
    marker = b"// Favor minified meshcore if present."
    assert marker in pristine
    expect_error(lambda: dup_layout.production_loader(deploy, pristine.replace(marker, b"// edited by hand", 1), production), "!= production")
    expect_error(lambda: dup_layout.production_loader(deploy, b"not a loader", production), "deploy.py rejected")
    fork = meshcentral_paths.fork_file("meshcentral.js").read_bytes()
    assert hashlib.sha256(fork).hexdigest() != production, "since S1.6 the fork loader differs from production's"


def test_shadow_cores_and_release_versions():
    for path in ("meshcentral-data/meshcore.js", "meshcentral-data/meshcore.min.js",
                 "meshcentral-data/modules_meshcore/win-terminal.js", "meshcentral-data/modules_meshcore_min/x.min.js",
                 "meshcentral-data/modules_meshcore/"):
        assert dup_layout.is_shadow_core(path), path
    for path in ("meshcentral-data/recoverycore.js", "meshcentral-data/agents/MeshService64.exe",
                 "meshcentral-data/plugins/nativeruntime/client.js", "meshcentral-web/public/scripts/custom.js",
                 "node_modules/meshcentral/agents/modules_meshcore/win-terminal.js"):
        assert not dup_layout.is_shadow_core(path), path
    manifest = {"date": "2026-10-28T09:43:06.000Z", "commit": "c",
                "modules": {"modules_meshcore/a.js": "2026-10-28T09:43:06.000Z", "modules_meshcore/b.js": "2026-10-28T09:43:06.000Z"}}
    probe = {"args": {"minifycore": False}, "cores": {"windows-amt": {"modules": [
        {"name": "a", "kind": "js", "version": "2026-10-28T09:43:06.000Z"},
        {"name": "coretranslations", "kind": "json", "version": None},
        {"name": "b", "kind": "js", "version": "2026-10-28T09:43:06.000Z"}]}}}
    status, detail = dup_checklist.compare_versions_to_release_manifest(probe, manifest)
    assert status == "PASS", detail
    probe["cores"]["windows-amt"]["modules"][2]["version"] = "2026-10-25T19:23:47.081Z"
    status, detail = dup_checklist.compare_versions_to_release_manifest(probe, manifest)
    assert status == "FAIL" and "release manifest" in detail[0], detail
    probe["cores"]["windows-amt"]["modules"].append({"name": "c", "kind": "js", "version": "x"})
    status, detail = dup_checklist.compare_versions_to_release_manifest(probe, manifest)
    assert any("not in the release manifest" in d for d in detail), detail
    probe["args"]["minifycore"] = True
    assert dup_checklist.compare_versions_to_release_manifest(probe, manifest)[0] == "FAIL"


def test_layout_runtimes():
    # Layout A models production until the cutover (Node 20.20.2); layout B is the 1.3.1 fork on Node 24.22.1.
    assert dup_common.LAYOUTS["A"]["node"] == "20.20.2" and dup_common.LAYOUTS["B"]["node"] == "24.22.1"
    assert dup_common.NODE_RUNTIMES == {
        "20.20.2": "dc3700fdd57a63eedb8fd7e3c7baaa32e6a740a1b904167ff4204bc68ed8bf77",
        "24.22.1": "d2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5"}
    b = dup_common.layout_node("B")
    assert b.url == "https://nodejs.org/dist/v24.22.1/node-v24.22.1-win-x64.zip"
    assert b.shasums_url == "https://nodejs.org/dist/v24.22.1/SHASUMS256.txt"
    assert b.exe == dup_common.TOOLS / "node-v24.22.1-win-x64" / "node.exe"
    assert b.npm_cli == b.home / "node_modules" / "npm" / "bin" / "npm-cli.js"
    assert dup_common.layout_node("A").exe == dup_common.TOOLS / "node-v20.20.2-win-x64" / "node.exe"
    assert [r.version for r in dup_common.node_runtimes()] == ["20.20.2", "24.22.1"]
    expect_error(lambda: dup_common.NodeRuntime("22.0.0"), "not a pinned runtime")
    expect_error(lambda: dup_common.layout_node("C"), "Unknown layout")
    env = dup_common.node_env(b, {"NODE_OPTIONS": "--require x"})
    assert env["PATH"].startswith(str(b.home)) and env["NODE_OPTIONS"] == "--require x"
    assert "NODE_OPTIONS" not in dup_common.node_env(b), "a layout gets a preload only when it asks for one"
    # The zip must be listed in that release's SHASUMS256.txt and match the pin.
    shasums = ("aaaa  node-v24.22.1-win-x86.zip\n" + b.zip_sha256 + "  node-v24.22.1-win-x64.zip\n")
    assert dup_install.published_node_sha256(b, shasums) == b.zip_sha256
    expect_error(lambda: dup_install.published_node_sha256(dup_common.layout_node("A"), shasums), "not listed")
    zip_path = TEMP_ROOT / "node.zip"
    zip_path.write_bytes(b"not node")
    expect_error(lambda: dup_install.verify(zip_path, b.zip_sha256, b.zip_sha256), "Checksum mismatch")
    expect_error(lambda: dup_install.verify(zip_path, "0" * 64, b.zip_sha256), "differs from the pin")


def test_mongo_tools_feed():
    entry = {"name": "windows", "arch": "x86_64", "archive": {"url": dup_common.MONGO_TOOLS_URL, "sha256": dup_common.MONGO_TOOLS_ZIP_SHA256.upper()}}
    feed = {"versions": [{"version": dup_common.MONGO_TOOLS_VERSION, "downloads": [entry]}]}
    assert dup_install.published_mongo_tools_sha256(json.dumps(feed)) == dup_common.MONGO_TOOLS_ZIP_SHA256
    feed["versions"][0]["version"] = "1.0.0"
    expect_error(lambda: dup_install.published_mongo_tools_sha256(json.dumps(feed)), "without a sha256")
    expect_error(lambda: dup_install.published_mongo_tools_sha256(json.dumps({"versions": []})), "not listed")
    assert dup_common.MONGODUMP_EXE.name == "mongodump.exe" and dup_common.MONGODUMP_EXE.is_relative_to(dup_common.TOOLS)


def test_layout_a_sources_are_production_bytes(deploy):
    # Since Stage 6 the MeshCentral checkout is the 1.3.1 fork, so layout A must not read its files: every
    # MeshCentral file deploy.py publishes is taken from the checkout's history at production's sha256.
    production = dup_layout.load_production_hashes()
    blobs = dup_layout.ProductionBlobs(dup_layout.meshcentral_repo())
    data, blob = blobs.find("meshagent.js", production["node_modules/meshcentral/meshagent.js"]["sha256"])
    assert hashlib.sha256(data).hexdigest() == production["node_modules/meshcentral/meshagent.js"]["sha256"] and len(blob) == 40
    current = meshcentral_paths.fork_file("meshagent.js").read_bytes()
    assert hashlib.sha256(current).hexdigest() != production["node_modules/meshcentral/meshagent.js"]["sha256"], \
        "the 1.3.1 checkout's meshagent.js is not production's; layout A must not use it"
    expect_error(lambda: blobs.find("meshagent.js", "0" * 64), "No version of meshagent.js")
    root = TEMP_ROOT / "layout-a-sources"
    loader = meshcentral_paths.upstream_package_dir(pin_path=meshcentral_paths.PRODUCTION_REFERENCE_PIN_PATH) / "meshcentral.js"
    (root / "node_modules" / "meshcentral").mkdir(parents=True)
    (root / "node_modules" / "meshcentral" / "meshcentral.js").write_bytes(loader.read_bytes())
    entries, absent = dup_layout.collect_core_artifacts(deploy, root)
    for entry in entries:
        assert hashlib.sha256(entry["bytes"]).hexdigest() == production[entry["target"]]["sha256"], entry["target"]
    assert {e["target"] for e in entries} | {a["target"] for a in absent} == {
        dup_layout.remote_to_local(deploy, deploy.get_core_publish_path(role, config["remote_relative_path"]), root).relative_to(root).as_posix()
        for config in deploy.CORE_ARTIFACTS.values() for role in deploy.get_artifact_publish_targets(config)}
    assert all(a["target"] not in production for a in absent)
    assert dup_layout.meshcentral_repo_path("../MeshCentral/deploy/meshcentral-web/public/scripts/custom.js") == \
        "deploy/meshcentral-web/public/scripts/custom.js"
    assert dup_layout.meshcentral_repo_path("meshservice/x.exe") is None


def test_image_size_preload_per_layout():
    # DEP-39: layout A runs production's preload from the tracked, path-portable copy (no expected-FAIL).
    # DEP-35: refresh-signed-hashagents.py (retired by D16) is not reproduced. Layout B has no preload.
    assert dup_layout.HARDEN_IMAGE_SIZE == ROOT / "tools" / "deployment" / "harden-image-size.js"
    assert "HARDEN_PENDING" not in dup_checklist.__dict__
    expect_error(lambda: dup_layout.preload_path("A"), "no image-size preload")
    record = dup_layout.install_bin("A")
    assert list(record) == ["harden-image-size.js"]
    assert sorted(p.name for p in (dup_common.layout_root("A") / "bin").iterdir()) == ["harden-image-size.js"]
    assert dup_layout.preload_path("A") == dup_common.layout_root("A") / "bin" / "harden-image-size.js"
    assert dup_layout.preload_path("B") is None
    good = "harden-image-size: disabled unpatched parsers: icns, jxl, jxl-stream, heif\nMeshCentral v1.2.5\n"
    assert dup_checklist.check_image_size_preload("A", {"preload": "x"}, good)[1] == "PASS"
    old_copy = "harden-image-size: WARNING - could not harden image-size: Cannot find module '/opt/meshcentral/node_modules/image-size'\n"
    assert dup_checklist.check_image_size_preload("A", {"preload": "x"}, old_copy)[1] == "FAIL"
    assert dup_checklist.check_image_size_preload("A", {"preload": None}, good)[1] == "FAIL"
    assert dup_checklist.check_image_size_preload("B", {"preload": None}, "MeshCentral v1.3.1\n")[1] == "PASS"
    assert dup_checklist.check_image_size_preload("B", {"preload": None}, good)[1] == "FAIL"
    assert dup_checklist.check_image_size_preload("B", {"preload": "x"}, "")[1] == "FAIL"


def test_self_update_check():
    # TST-31: all three D6 settings, including the daemon marker that a fresh tarball install drops.
    on = {"backup": True, "restore": True, "upgrade": False, "errorlog": True, "console": True, "trace": True, "config": True}
    probe = {"args": {"selfupdate": False}, "selfUpdate": {"daemonMarker": True, "myserver": on}}
    assert dup_checklist.check_self_update(probe, "")[0] == "PASS"
    assert dup_checklist.check_self_update(probe, "Checking for update...")[0] == "FAIL"
    for broken in ({"daemonMarker": False, "myserver": on}, {"daemonMarker": True, "myserver": None},
                   {"daemonMarker": True, "myserver": dict(on, upgrade=True)}):
        assert dup_checklist.check_self_update(dict(probe, selfUpdate=broken), "")[0] == "FAIL", broken
    assert dup_checklist.check_self_update(dict(probe, args={"selfupdate": True}), "")[0] == "FAIL"
    root = dup_common.layout_root("B")
    (root / "node_modules" / "meshcentral").mkdir(parents=True, exist_ok=True)
    marker = dup_layout.write_daemon_marker("B")
    assert marker["path"] == "node_modules/meshcentral/daemon" and (root / marker["path"]).is_file()


def write_pins(agents, files):
    agents.mkdir(parents=True, exist_ok=True)
    pins = []
    for name, data in files.items():
        (agents / name).write_bytes(data)
        pins.append({"filename": name, "size": len(data), "sha384": hashlib.sha384(data).hexdigest()})
    manifest = {"schema": "meshcentral-fork-agents/1", "build": {"repository": "o/r", "commit": "a" * 40}, "files": pins}
    (agents / "agent-defaults.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_fork_layout_agents():
    root = TEMP_ROOT / "fork-agents"
    agents = root / "node_modules" / "meshcentral" / "agents"
    files = {"MeshService.exe": b"x86", "MeshService64.exe": b"x64 build", "MeshServiceARM64.exe": b"arm64 build"}
    manifest = write_pins(agents, files)
    assert [f["filename"] for f in dup_layout.verify_agent_pins(root)["files"]] == sorted(files)
    (agents / "MeshService64.exe").write_bytes(b"x64 bUild")
    expect_error(lambda: dup_layout.verify_agent_pins(root), "MeshService64.exe: 9 bytes SHA384")
    (agents / "MeshService64.exe").unlink()
    expect_error(lambda: dup_layout.verify_agent_pins(root), "MeshService64.exe: missing")
    expect_error(lambda: dup_layout.parse_agent_pins(dict(manifest, files=[])), "pins no agent binary")
    expect_error(lambda: dup_layout.parse_agent_pins(dict(manifest, schema="x")), "not a fork agent manifest")
    (agents / "MeshService64.exe").write_bytes(files["MeshService64.exe"])
    probe = {"agentDefaults": {"errors": [], "build": manifest["build"]}, "agentBinaries": {}}
    for archid, name in (("3", "MeshService.exe"), ("4", "MeshService64.exe"), ("43", "MeshServiceARM64.exe")):
        probe["agentBinaries"][archid] = {"localname": name, "relativePath": f"node_modules/meshcentral/agents/{name}",
                                          "size": len(files[name]), "sha384": hashlib.sha384(files[name]).hexdigest(), "unsigned": True}
    assert dup_checklist.check_fork_agents(root, probe)[0] == "PASS"
    probe["agentBinaries"]["4"] = dict(probe["agentBinaries"]["4"], relativePath="meshcentral-data/agents/MeshService64.exe")
    assert dup_checklist.check_fork_agents(root, probe)[0] == "FAIL"
    probe["agentBinaries"]["4"] = dict(probe["agentBinaries"]["4"], relativePath="node_modules/meshcentral/agents/MeshService64.exe", unsigned=False)
    assert dup_checklist.check_fork_agents(root, probe)[0] == "FAIL"
    probe["agentBinaries"]["4"]["unsigned"] = True
    probe["agentDefaults"]["errors"] = ["MeshService.exe: does not match its pin"]
    assert dup_checklist.check_fork_agents(root, probe)[0] == "FAIL"
    assert dup_checklist.check_fork_agents(root, dict(probe, agentDefaults=None))[0] == "FAIL"


def test_fork_layout_rules(deploy):
    # Layout B is the fork as Stage 6 landed it: npm ci against the lock, nothing of production's data or web
    # folders but the fork release's own files, and none of the folders the fork serves from the package.
    for relative in ("meshcentral-data/agentbuilds", "meshcentral-data/agents", "meshcentral-data/signedagents",
                     "meshcentral-data/meshcore.js", "meshcentral-data/modules_meshcore", "meshcentral-web/views", "bin"):
        assert relative in dup_layout.FORK_ABSENT, relative
    assert dup_layout.FORK_RELEASE_FILES == (("deploy/meshcentral-web/", "meshcentral-web/"),
                                             ("plugins/nativeruntime/", "meshcentral-data/plugins/nativeruntime/"))
    expect_error(lambda: dup_layout.build_layout_b(tarball=TEMP_ROOT / "x.tgz", agents_dir=TEMP_ROOT), "not both")
    for retired in ("standin", "stage1", "retire_overrides"):
        assert retired not in dup_layout.build_layout_b.__code__.co_varnames, retired
    import contextlib
    import dupserver
    for option in ("--standin", "--stage1", "--retire-overrides"):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                dupserver.main(["layout-b", option])
        except SystemExit as error:
            assert error.code == 2, option
        else:
            raise AssertionError(f"layout-b {option} must be refused")
    wrapper = dup_layout.wrapper_dir()
    locked = dup_layout.locked_meshcentral(wrapper)
    assert locked["integrity"].startswith("sha512-") and dup_layout.wrapper_tarball_spec(wrapper) is not None
    bogus = TEMP_ROOT / "bogus.tgz"
    bogus.write_bytes(b"not the locked fork tarball")
    expect_error(lambda: dup_layout.install_wrapper("B", tarball=bogus), "but the wrapper lock pins")
    # The D16 helpers stay for layout B's check: 62 default3 overrides and 2 canary scripts in the capture.
    with tarfile.open(dup_layout.LAYOUT_A_TAR) as archive:
        web = [m.name for m in archive.getmembers() if m.isfile() and m.name.startswith("meshcentral-web/")]
    assert sum(1 for name in web if dup_layout.is_d16_retired(name)) == 64
    for kept in ("meshcentral-web/public/scripts/custom.js", "meshcentral-web/views/default.handlebars"):
        assert not dup_layout.is_d16_retired(kept), kept
    package_root = deploy.CORE_PUBLISH_ROLE_DIRS["module-root"]
    assert dup_layout.is_package_path(deploy, package_root + "/meshcentral.js")
    assert not dup_layout.is_package_path(deploy, deploy.get_publish_path("data", "MeshService64.exe"))


def test_tarball_manifest_applies_only_npm_bin_rewrite():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in (("package/package.json", b'{"name":"x","bin":{"x":"bin/x"}}'),
                           ("package/bin/x", b"#!/usr/bin/env node\r\nrequire('../x.js');"),
                           ("package/x.js", b"a\r\nb\r\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    tgz = TEMP_ROOT / "x.tgz"
    tgz.write_bytes(buffer.getvalue())
    rows, bins = dup_layout.tarball_manifest(tgz)
    assert bins == ["bin/x"]
    assert rows["bin/x"] == hashlib.sha256(b"#!/usr/bin/env node\nrequire('../x.js');").hexdigest()
    assert rows["x.js"] == hashlib.sha256(b"a\r\nb\r\n").hexdigest(), "non-bin files must stay byte-exact"


def test_summary_key_parsing_and_flag_coverage():
    sample = "## config flags\nsettings: {2 keys}\nsettings.port: 1\nsettings.plugins: {1 keys}\nsettings.plugins.list: []\n" \
             "domains: {1 keys}\ndomains..title: \"x\"\ndomains..customFiles.a: {}\n## next\nsettings.ignored: 1\n"
    assert dup_config.summary_config_keys(sample) == (["port", "plugins"], ["title"])
    expect_error(lambda: dup_config.summary_config_keys("nothing"), "config flags")
    flags = dup_config.load_flags()  # fails if production_flags.json and summary.txt disagree
    for section in ("settings", "domain"):
        for key, spec in flags[section].items():
            if "value" in spec:
                text = json.dumps(spec["value"]).lower()
                assert "high.support" not in text and "opt/meshcentral" not in text, f"{key} carries a production value"


def test_generated_config(denylist_path):
    configs = {}
    for layout in ("A", "B"):
        config, record = dup_config.generate(layout, "mongodb://u:p@127.0.0.1:27018/x?authSource=admin")
        configs[layout] = config
        settings, domain = config["settings"], config["domains"][""]
        assert settings["port"] == dup_common.LAYOUTS[layout]["port"] and settings["redirPort"] == 0
        assert settings["selfUpdate"] is False and settings["tlsOffload"] is False
        assert settings["agentSignLock"] is True and settings["agentUpdateSystem"] == 1
        assert settings["plugins"] == {"enabled": True, "list": ["nativeruntime"]}
        assert settings["cert"].endswith(".localhost") and settings["portBind"] == "127.0.0.1"
        assert settings["mongoDbName"] == dup_common.LAYOUTS[layout]["db"]
        assert "agentAliasDNS" not in settings and "certurl" not in domain and "agentwebcerthashes" not in domain
        assert any(k.endswith(".agentPort") for k in record["dropped_template_keys"])
        assert not dup_config.scan_text(json.dumps(config), dup_config.load_denylist(denylist_path))
    extra = dup_config.load_extra_values()
    for layout, config in configs.items():
        settings, domain = config["settings"], config["domains"][""]
        assert settings["ciphers"] == extra["ciphers"] and settings["cookieIpCheck"] == extra["cookieIpCheck"]
        assert domain["agentConfig"] == extra["agentConfig"] and domain["auth"] == extra["auth"]
        assert settings["autobackup"]["backupskipfoldersglob"] == extra["backupskipfoldersglob"]
        assert settings["autobackup"]["backuppath"].startswith(str(dup_common.layout_root(layout)))
    assert configs["A"]["domains"][""]["customFiles"] == extra["customFiles"]
    assert "customFiles" not in configs["B"]["domains"][""], "layout B drops the canary entry (D16)"
    # D6 safeguard I2 (after the inventory): both layouts carry production's myServer with upgrade off (TST-31).
    for layout, config in configs.items():
        assert config["domains"][""]["myServer"]["upgrade"] is False, layout
        assert all(value is True for key, value in config["domains"][""]["myServer"].items() if key != "upgrade"), layout
        # Autobackup runs the pinned mongodump (production finds mongodump on PATH; the duplicate changes no PATH).
        assert config["settings"]["autobackup"]["mongodumppath"] == str(dup_common.MONGODUMP_EXE)
    _, record = dup_config.generate("B", "mongodb://x")
    assert any(entry["key"] == "domains[''].myServer" for entry in record["after_inventory"])
    assert any(entry["key"] == "domains[''].customFiles" for entry in record["omitted"])
    assert "mpsPort" not in configs["A"]["settings"] and configs["B"]["settings"]["mpsPort"] == 4434
    assert configs["A"]["settings"]["mpsPortBind"] == "127.0.0.1", "loopback is the default bind"
    hostonly, _ = dup_config.generate("A", "mongodb://x", bind="192.168.56.1")
    assert hostonly["settings"]["portBind"] == hostonly["settings"]["mpsPortBind"] == "192.168.56.1"
    assert "192.168.56.1" in hostonly["domains"][""]["allowedorigin"]
    for bad in ("0.0.0.0", "::", "8.8.8.8", "mc-dup-a.localhost"):
        expect_error(lambda: dup_config.validate_bind(bad), "--bind")
    for key in ("sessionKey", "dbEncryptKey", "dbRecordsEncryptKey"):
        assert configs["A"]["settings"][key] != configs["B"]["settings"][key], f"{key} must be fresh per layout"


def test_denylist_helpers():
    text = "logger x host agents.prod.example 12\nlogger y host prod.example:443 3\n  - hostname: tunnel.prod.example\n" \
           "70:edge.prod.example:4445, edge.prod.example:4446 {\n5:(snippet) {\n7:\tlog {\n"
    assert dup_config.production_hosts(text) == {"agents.prod.example", "prod.example", "tunnel.prod.example", "edge.prod.example"}
    assert dup_config.public_ipv4("127.0.0.1 10.0.0.1 192.168.1.2 8.8.8.8") == {"8.8.8.8"}
    server_id = secrets.token_hex(48).upper()
    values = dup_config.parse_msh(f"MeshID=0x{server_id}\r\nServerID={server_id}\r\nMeshServer=wss://a.prod.example:443/agent.ashx\r\n".encode())
    tokens, hosts = dup_config.msh_identifiers(values)
    assert tokens == {"ServerID": server_id.lower(), "MeshID": server_id.lower()} and hosts == {"a.prod.example"}
    assert dup_config.scan_text("Cert: Agents.Prod.Example", ["prod.example"]) == ["prod.example"]


def write_denylist(path, server_id):
    path.write_text(json.dumps({"hosts": ["prod.example"], "ips": ["203.0.113.9"], "server_ids": [server_id],
                                "mesh_ids": []}), encoding="utf-8")


def test_preflight(denylist_path, production_server_id):
    repo = TEMP_ROOT / "agent-repo"
    repo.mkdir()
    (repo / "MeshAgent.Build.proj").write_bytes((ROOT / "MeshAgent.Build.proj").read_bytes())
    (repo / "WinDiagnosticHost.msh").write_text("must never be opened", encoding="utf-8")
    assert preflight_agent.implicit_defaults(repo, "MeshAgentProvisioningManifest") == ["WinDiagnosticHost.msh", "MeshAgent.msh"]
    assert preflight_agent.implicit_defaults(repo, "MeshAgentBrandingConfig") == ["branding_config.local.json", "branding_config.json"]
    outside = TEMP_ROOT / "dup-agent"
    outside.mkdir()
    branding = outside / "branding.dup.json"
    branding.write_text(json.dumps({"network": {"primaryEndpoint": "wss://mc-dup-a.localhost:4431/agent.ashx"},
                                    "provisioning": {"serverUrl": "wss://REPLACE_WITH_SERVER:443/agent.ashx", "serverId": "REPLACE_WITH_SERVER_ID"}}),
                        encoding="utf-8")
    dup_id = secrets.token_hex(48).upper()
    msh = outside / "dup.msh"

    def write_msh(server_url, server_id=dup_id):
        msh.write_text(f"MeshName=dup\r\nMeshID=0x{secrets.token_hex(48)}\r\nServerID={server_id}\r\nMeshServer={server_url}\r\n", encoding="utf-8")

    write_msh("wss://mc-dup-a.localhost:4431/agent.ashx")
    assert preflight_agent.check(branding, msh, repo, denylist_path) == []
    write_msh("wss://192.168.56.1:4431/agent.ashx")
    assert preflight_agent.check(branding, msh, repo, denylist_path) == []
    errors = preflight_agent.check(branding, None, repo, denylist_path)
    assert len(errors) == 1 and "WinDiagnosticHost.msh" in errors[0], errors
    errors = preflight_agent.check(branding, repo / "WinDiagnosticHost.msh", repo, denylist_path)
    assert any("implicit production defaults" in e for e in errors), errors
    write_msh("wss://agents.prod.example/agent.ashx")
    errors = preflight_agent.check(branding, msh, repo, denylist_path)
    assert any("production identifiers" in e for e in errors) and any("not loopback" in e for e in errors), errors
    write_msh("wss://mc-dup-a.localhost:4431/agent.ashx", server_id=production_server_id)
    assert any("production identifiers" in e for e in preflight_agent.check(branding, msh, repo, denylist_path))
    write_msh("wss://mc-dup-a.localhost:4431/agent.ashx", server_id="abc")
    assert any("96-hex" in e for e in preflight_agent.check(branding, msh, repo, denylist_path))
    inside = repo / "dup.msh"
    inside.write_bytes(msh.read_bytes())
    assert any("inside the repository" in e for e in preflight_agent.check(branding, inside, repo, denylist_path))


def build_posix_tar(path, members, fmt=tarfile.PAX_FORMAT):
    with tarfile.open(path, "w", format=fmt) as archive:
        for name, data, mtime_text in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            info.mtime = float(mtime_text)
            if fmt == tarfile.PAX_FORMAT:
                info.pax_headers = {"mtime": mtime_text}
            archive.addfile(info, io.BytesIO(data) if data is not None else None)


def test_module_timestamp_overlay():
    root = dup_common.layout_root("A")
    modules = root / "meshcentral-data" / "modules_meshcore"
    modules.mkdir(parents=True, exist_ok=True)
    (modules / "umhctl.js").write_bytes(b"module.exports=1;")
    (root / "meshcentral-data" / "meshcore.js").write_bytes(b"// core")
    members = [("meshcentral-data/modules_meshcore", None, "1792048028.123810555"),
               ("meshcentral-data/modules_meshcore/umhctl.js", b"module.exports=1;", "1792956226.818945076"),
               ("meshcentral-data/meshcore.js", b"// core", "1792956226.796945068")]
    tar = TEMP_ROOT / "modules-posix.tar"
    build_posix_tar(tar, members)
    record = dup_layout.overlay_module_timestamps("A", tar)
    assert record["entries"] == 3
    assert (modules / "umhctl.js").stat().st_mtime_ns // 100 == 1792956226818945076 // 100
    assert modules.stat().st_mtime_ns // 1_000_000 == 1792048028123
    stamps = dup_layout.module_timestamps(tar)
    assert stamps["meshcentral-data/modules_meshcore/umhctl.js"] == 1792956226818945076
    build_posix_tar(tar, [("meshcentral-data/modules_meshcore/umhctl.js", b"changed", "1792956226.818945076")])
    expect_error(lambda: dup_layout.overlay_module_timestamps("A", tar), "differs between")
    build_posix_tar(tar, [("meshcentral-web/views/x.handlebars", b"x", "1.5")])
    expect_error(lambda: dup_layout.overlay_module_timestamps("A", tar), "Unexpected member")
    build_posix_tar(tar, members[1:2], fmt=tarfile.GNU_FORMAT)
    expect_error(lambda: dup_layout.overlay_module_timestamps("A", tar), "posix-format")


def test_millisecond_version_comparison():
    # Node 20 builds fs.Stats dates from mtimeMs rounded to the nearest millisecond.
    assert dup_checklist.iso_millis(1792956227002945151) == "2026-10-25T19:23:47.003Z"
    assert dup_checklist.iso_millis(1790937236531453752) == "2026-10-02T10:33:56.531Z"
    assert dup_checklist.iso_millis(1790937236531500000) == "2026-10-02T10:33:56.532Z"
    assert dup_checklist.iso_millis(1790937236999600000) == "2026-10-02T10:33:57.000Z"
    stamps = {"meshcentral-data/modules_meshcore/a.js": 1792956227002945151}
    probe = {"args": {"minifycore": False}, "cores": {"windows-amt": {"modules": [
        {"name": "a", "kind": "js", "version": "2026-10-25T19:23:47.003Z"},
        {"name": "coretranslations", "kind": "json", "version": None}]}}}
    assert dup_checklist.compare_versions_to_capture(probe, stamps)[0] == "PASS"
    probe["cores"]["windows-amt"]["modules"][0]["version"] = "2026-10-25T19:23:47.002Z"
    status, detail = dup_checklist.compare_versions_to_capture(probe, stamps)
    assert status == "FAIL" and "capture 2026-10-25T19:23:47.003Z" in detail[0]
    probe["cores"]["windows-amt"]["modules"].append({"name": "b", "kind": "js", "version": "x"})
    assert any("not in the module capture" in p for p in dup_checklist.compare_versions_to_capture(probe, stamps)[1])
    probe["args"]["minifycore"] = True
    assert dup_checklist.compare_versions_to_capture(probe, stamps)[0] == "FAIL"


def test_view_identification():
    folder = TEMP_ROOT / "views"
    folder.mkdir()
    override = folder / "override.handlebars"
    package = folder / "package.handlebars"
    common = "<div class=\"common-block\">shared static text that both templates carry verbatim</div>\r\n"
    override.write_bytes((common + "<script>overrideOnlyCanaryFunction(); var mobileConnectClick = false;</script>\r\n{{{title}}}\r\n").encode())
    package.write_bytes((common + "<script>packageOnlyUpstreamFunction(); var mobileConnectClick = true;;;</script>\n{{{title}}}\n").encode())
    candidates = {"override": override, "package": package}
    html = (common + "<script>overrideOnlyCanaryFunction(); var mobileConnectClick = false;</script>\r\nDUP\r\n")
    assert dup_checklist.identify_view(html, candidates)[0] == "override"
    assert dup_checklist.identify_view("unrelated page", candidates)[0] is None


def main():
    test_runtime_root_is_isolated()
    deploy = test_deploy_import_keeps_branding_secrets_closed()
    test_publish_paths_map_onto_layout(deploy)
    test_agent_artifacts_exclude_identity_manifests()
    test_reset_selects_only_its_own_reports()
    test_production_loader_rebuild(deploy)
    test_shadow_cores_and_release_versions()
    test_layout_runtimes()
    test_mongo_tools_feed()
    test_layout_a_sources_are_production_bytes(deploy)
    test_image_size_preload_per_layout()
    test_self_update_check()
    test_fork_layout_agents()
    test_fork_layout_rules(deploy)
    test_tarball_manifest_applies_only_npm_bin_rewrite()
    test_summary_key_parsing_and_flag_coverage()
    production_server_id = secrets.token_hex(48)
    denylist_path = TEMP_ROOT / "denylist.json"
    write_denylist(denylist_path, production_server_id)
    test_generated_config(denylist_path)
    test_denylist_helpers()
    test_preflight(denylist_path, production_server_id)
    test_view_identification()
    test_module_timestamp_overlay()
    test_millisecond_version_comparison()
    print("duplicate_server tools contract: OK")


if __name__ == "__main__":
    main()
