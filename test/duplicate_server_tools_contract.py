"""Contract tests for tools/duplicate_server (work package A1).

Runs without the duplicate running and without network. It uses a temporary MC_DUP_ROOT, synthetic
denylists and fixtures, and these read-only inputs, which must exist (missing ones fail loudly):
  - the MeshCentral checkout with the Stage 1 layout (MESHCENTRAL_ROOT or the sibling): the
    deploy/ wrapper's config template,
  - the pinned upstream meshcentral 1.2.5 reference (python test/lib/fetch_upstream_reference.py),
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


def test_staged_loader_rules(deploy):
    # Layout A runs the stock npm package; since Stage 1 the installed wrapper package is the fork.
    pristine = (meshcentral_paths.upstream_package_dir() / "meshcentral.js").read_bytes().decode("utf-8")
    fresh = deploy.align_proxy_certificate_sni(deploy.version_meshcentral_module_loader(pristine))
    layout = TEMP_ROOT / "loader-layout"
    (layout / "node_modules" / "meshcentral").mkdir(parents=True)
    (layout / "node_modules" / "meshcentral" / "meshcentral.js").write_bytes(pristine.encode("utf-8"))
    staged_path = TEMP_ROOT / "loader-repo" / "meshcentral.js"
    staged_path.parent.mkdir(parents=True)
    # Production's staged loader: same text, CRLF where a fresh run writes LF.
    staged_path.write_bytes(fresh.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    data, record = dup_layout.versioned_loader(deploy, staged_path, layout)
    assert data == staged_path.read_bytes() and record["equals_fresh_transform_ignoring_line_endings"] is True
    marker = "// Favor minified meshcore if present."
    assert marker in fresh
    staged_path.write_bytes(fresh.replace(marker, "// edited by hand", 1).encode("utf-8"))
    expect_error(lambda: dup_layout.versioned_loader(deploy, staged_path, layout), "differs")
    staged_path.write_bytes(b"not a loader")
    expect_error(lambda: dup_layout.versioned_loader(deploy, staged_path, layout), "deploy.py rejected")
    staged_path.write_bytes(pristine.encode("utf-8"))
    expect_error(lambda: dup_layout.versioned_loader(deploy, staged_path, layout), "not a fully staged loader")
    staged_path.unlink()
    expect_error(lambda: dup_layout.versioned_loader(deploy, staged_path, layout), "missing")
    # The loader deploy.py stages since Stage 1 is the fork's committed file, which passes the same rules.
    fork_loader = dup_layout.resolve_source(dup_layout.source_repo(), deploy.CORE_ARTIFACTS["meshcentral.js"]["local_path"])
    assert fork_loader == meshcentral_paths.fork_file("meshcentral.js")
    data, record = dup_layout.versioned_loader(deploy, fork_loader, layout)
    assert data == fork_loader.read_bytes()


def test_stage1_sources_and_package_roles(deploy):
    repo = TEMP_ROOT / "resolve-repo"
    root = dup_layout.meshcentral_repo()
    assert root == meshcentral_paths.meshcentral_root()
    assert dup_layout.resolve_source(repo, "../MeshCentral/deploy/meshcentral-web/public/scripts/custom.js") == \
        root / "deploy" / "meshcentral-web" / "public" / "scripts" / "custom.js"
    assert dup_layout.resolve_source(repo, "meshservice/x.exe") == (repo / "meshservice" / "x.exe").resolve()
    assert dup_layout.wrapper_dir() == meshcentral_paths.wrapper_dir()
    assert dup_layout.wrapper_tarball_spec(dup_layout.wrapper_dir()) is not None, "Stage 1 installs the fork from a packed tarball"
    package_root = deploy.CORE_PUBLISH_ROLE_DIRS["module-root"]
    assert dup_layout.is_package_path(deploy, package_root + "/meshcentral.js")
    assert dup_layout.is_package_path(deploy, deploy.get_publish_path("module", "MeshService64.exe"))
    for role in ("data-core", "data-plugin", "web-public"):
        assert not dup_layout.is_package_path(deploy, deploy.CORE_PUBLISH_ROLE_DIRS[role] + "/x.js"), role
    assert not dup_layout.is_package_path(deploy, deploy.get_publish_path("data", "MeshService64.exe"))
    wrapper = TEMP_ROOT / "spec-wrapper"
    wrapper.mkdir()
    for spec, expected in (("file:dist/m.tgz", "dist/m.tgz"), ("1.2.5", None)):
        (wrapper / "package.json").write_text(json.dumps({"dependencies": {"meshcentral": spec}}), encoding="utf-8")
        found = dup_layout.wrapper_tarball_spec(wrapper)
        assert (found.as_posix() if found else None) == expected, spec
    (wrapper / "package.json").write_text(json.dumps({"dependencies": {"meshcentral": "file:../x.tgz"}}), encoding="utf-8")
    expect_error(lambda: dup_layout.wrapper_tarball_spec(wrapper), "inside the wrapper")
    expect_error(lambda: dup_layout.build_layout_b(), "exactly one")
    expect_error(lambda: dup_layout.build_layout_b(TEMP_ROOT / "x.tgz", stage1=True), "exactly one")


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
    # B-stage1 runs production's config (profile A), including customFiles, on layout B's own ports and DB.
    stage1, stage1_record = dup_config.generate("B", "mongodb://x", profile="A")
    assert stage1["domains"][""]["customFiles"] == extra["customFiles"] and stage1_record["profile"] == "A"
    assert stage1["settings"]["port"] == dup_common.LAYOUTS["B"]["port"]
    assert stage1["settings"]["mongoDbName"] == dup_common.LAYOUTS["B"]["db"]
    expect_error(lambda: dup_config.generate("B", "mongodb://x", profile="C"), "profile")
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
    test_staged_loader_rules(deploy)
    test_stage1_sources_and_package_roles(deploy)
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
