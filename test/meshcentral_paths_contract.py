"""Unit tests for test/lib/meshcentral_paths.py on temporary layouts.

They never read the real MeshCentral checkout, so they pass with or without MESHCENTRAL_ROOT.
test/meshcentral_paths_contract.js runs the same cases against the Node helper.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import meshcentral_paths as paths  # noqa: E402

TEMP = Path(tempfile.mkdtemp(prefix="meshcentral-paths-")).resolve()
_counter = [0]


def unique(name):
    _counter[0] += 1
    return TEMP / f"{name}{_counter[0]}"


def make_fork(directory):
    (directory / "agents").mkdir(parents=True, exist_ok=True)
    (directory / "meshagent.js").write_text("// fixture\n", encoding="utf-8")
    return directory


def install_package(root, rel, name="meshcentral"):
    directory = root / rel
    directory.mkdir(parents=True)
    (directory / "package.json").write_text(json.dumps({"name": name, "version": "1.2.5"}), encoding="utf-8")
    return directory


def workspace(with_sibling):
    parent = unique("ws")
    meshagent_root = parent / "MeshAgent"
    meshagent_root.mkdir(parents=True)
    sibling = parent / "MeshCentral"
    if with_sibling:
        make_fork(sibling)
    return meshagent_root, sibling


def raises_with(fn, fragments):
    try:
        fn()
    except paths.MeshCentralPathError as error:
        for fragment in fragments:
            assert str(fragment) in str(error), f"expected {str(fragment)!r} in: {error}"
        return
    raise AssertionError(f"expected MeshCentralPathError containing {fragments!r}")


def env_set_is_used():
    agent, _ = workspace(True)
    other = make_fork(unique("elsewhere") / "MeshCentral")
    assert paths.meshcentral_root({"MESHCENTRAL_ROOT": str(other)}, agent) == other


def env_relative_is_resolved():
    agent, _ = workspace(False)
    other = make_fork(unique("relative"))
    relative = os.path.relpath(other, os.getcwd())
    assert paths.meshcentral_root({"MESHCENTRAL_ROOT": relative}, agent) == other


def env_missing_raises():
    agent, _ = workspace(True)
    missing = TEMP / "no-such-dir"
    raises_with(lambda: paths.meshcentral_root({"MESHCENTRAL_ROOT": str(missing)}, agent),
                ["not found", missing, "from MESHCENTRAL_ROOT", "Set MESHCENTRAL_ROOT"])


def env_not_a_directory_raises():
    agent, _ = workspace(False)
    file = unique("a-file")
    file.write_text("x", encoding="utf-8")
    raises_with(lambda: paths.meshcentral_root({"MESHCENTRAL_ROOT": str(file)}, agent), ["is not a directory", file])


def env_without_markers_raises():
    agent, _ = workspace(True)
    not_fork = unique("not-fork")
    not_fork.mkdir()
    raises_with(lambda: paths.meshcentral_root({"MESHCENTRAL_ROOT": str(not_fork)}, agent),
                ["does not look like the MeshCentral fork", "meshagent.js (file)", "agents (directory)"])


def empty_env_falls_back_to_sibling():
    agent, sibling = workspace(True)
    assert paths.meshcentral_root({"MESHCENTRAL_ROOT": ""}, agent) == sibling


def sibling_present_is_used():
    agent, sibling = workspace(True)
    assert paths.meshcentral_root({}, agent) == sibling


def sibling_absent_raises():
    agent, sibling = workspace(False)
    raises_with(lambda: paths.meshcentral_root({}, agent),
                ["not found", sibling, "MESHCENTRAL_ROOT is not set", "Set MESHCENTRAL_ROOT"])


def default_meshagent_root_is_two_levels_up():
    assert paths.MESHAGENT_ROOT == Path(__file__).resolve().parents[1]
    assert (paths.MESHAGENT_ROOT / "AGENTS.md").is_file(), "MESHAGENT_ROOT must be the MeshAgent checkout"


def deploy_package():
    agent, sibling = workspace(True)
    directory = install_package(sibling, paths.PACKAGE_DIR)
    assert directory == sibling / "deploy" / "node_modules" / "meshcentral"
    assert paths.installed_package_dir({}, agent) == directory


def stale_root_install_is_refused_without_env():
    # The local case: no MESHCENTRAL_ROOT, and the sibling checkout still has a pre-Stage-1 root install.
    agent, sibling = workspace(True)
    install_package(sibling, paths.PACKAGE_DIR)
    stale = install_package(sibling, paths.STALE_ROOT_PACKAGE_DIR)
    raises_with(lambda: paths.installed_package_dir({}, agent),
                ["Stale pre-Stage-1", stale, "MESHCENTRAL_ROOT is not set",
                 sibling / "deploy" / "node_modules" / "meshcentral", "Set MESHCENTRAL_ROOT"])


def stale_root_install_is_refused_with_env():
    agent, _ = workspace(False)
    other = make_fork(unique("stale") / "MeshCentral")
    stale = install_package(other, paths.STALE_ROOT_PACKAGE_DIR)
    raises_with(lambda: paths.installed_package_dir({"MESHCENTRAL_ROOT": str(other)}, agent),
                ["Stale pre-Stage-1", stale, f"MESHCENTRAL_ROOT points at {other}"])


def root_install_is_never_used():
    # A root install alone is not a fallback: it is refused, not returned.
    agent, sibling = workspace(True)
    install_package(sibling, paths.STALE_ROOT_PACKAGE_DIR)
    raises_with(lambda: paths.installed_package_dir({}, agent), ["Stale pre-Stage-1"])


def no_package_raises():
    agent, sibling = workspace(True)
    raises_with(lambda: paths.installed_package_dir({}, agent),
                ["not found", sibling / "deploy" / "node_modules" / "meshcentral", "npm ci"])


def package_without_manifest_raises():
    agent, sibling = workspace(True)
    (sibling / "deploy" / "node_modules" / "meshcentral").mkdir(parents=True)
    raises_with(lambda: paths.installed_package_dir({}, agent), ["no readable package.json"])


def package_with_other_name_raises():
    agent, sibling = workspace(True)
    install_package(sibling, paths.PACKAGE_DIR, "not-meshcentral")
    raises_with(lambda: paths.installed_package_dir({}, agent), ['"not-meshcentral"', 'not "meshcentral"'])


def installed_package_needs_root():
    agent, _ = workspace(False)
    raises_with(lambda: paths.installed_package_dir({}, agent), ["Set MESHCENTRAL_ROOT"])


def fork_file_is_under_root():
    agent, sibling = workspace(True)
    assert paths.fork_file("meshagent.js", {}, agent) == sibling / "meshagent.js"
    assert paths.fork_file("agents/meshcore.js", {}, agent) == sibling / "agents" / "meshcore.js"


def fork_file_rejects_escapes():
    agent, sibling = workspace(True)
    raises_with(lambda: paths.fork_file("../MeshAgent/x.js", {}, agent), ["leaves the MeshCentral checkout"])
    raises_with(lambda: paths.fork_file("agents/../..", {}, agent), ["leaves the MeshCentral checkout"])
    raises_with(lambda: paths.fork_file(".", {}, agent), ["leaves the MeshCentral checkout"])
    raises_with(lambda: paths.fork_file(str(sibling / "meshagent.js"), {}, agent), ["needs a relative path"])
    raises_with(lambda: paths.fork_file("", {}, agent), ["needs a relative path"])


def fork_file_needs_root():
    agent, _ = workspace(False)
    raises_with(lambda: paths.fork_file("meshagent.js", {}, agent), ["Set MESHCENTRAL_ROOT"])


def write_wrapper(root, name):
    (root / "deploy").mkdir(parents=True, exist_ok=True)
    (root / "deploy" / "package.json").write_text(json.dumps({"name": name}), encoding="utf-8")


def wrapper_file_is_under_deploy():
    agent, sibling = workspace(True)
    write_wrapper(sibling, "meshcentral-deploy")
    assert paths.wrapper_dir({}, agent) == sibling / "deploy"
    assert paths.wrapper_file("meshcentral-web/public/scripts/custom.js", {}, agent) == \
        sibling / "deploy" / "meshcentral-web" / "public" / "scripts" / "custom.js"
    raises_with(lambda: paths.wrapper_file("../meshagent.js", {}, agent), ["leaves the deployment wrapper"])
    raises_with(lambda: paths.wrapper_file("", {}, agent), ["needs a relative path"])


def wrapper_missing_names_stage1():
    agent, sibling = workspace(True)
    (sibling / "package.json").write_text(json.dumps({"name": "meshcentral-deploy"}), encoding="utf-8")
    raises_with(lambda: paths.wrapper_dir({}, agent), ["deployment wrapper not found", "Stage 1"])


def wrapper_with_other_name_raises():
    agent, sibling = workspace(True)
    write_wrapper(sibling, "meshcentral")
    raises_with(lambda: paths.wrapper_file("x", {}, agent), ['is named "meshcentral"'])


# The same tree and digest are checked in meshcentral_paths_contract.js, so both helpers compute
# one value. "Z/" sorts before "a/" by UTF-8 bytes.
TINY_DIGEST = "sha256:63dc7f5b4d9481f89b76e3cc2b6367567dd8b24b803cf747542ff6d80d19ce65"
TINY_FILES = {"package.json": b'{"name":"meshcentral","version":"9.9.9"}', "a/b.txt": b"hello\n", "Z/c.txt": b"x"}


def tiny_tree(directory):
    for rel, data in TINY_FILES.items():
        (directory / rel).parent.mkdir(parents=True, exist_ok=True)
        (directory / rel).write_bytes(data)
    return directory


def tiny_tarball(target, extra=None):
    """Write an npm-style tarball (package/ prefix) of the tiny tree; extra(tar) may add members."""
    import io
    import tarfile
    with tarfile.open(target, "w:gz") as archive:
        for rel, data in TINY_FILES.items():
            info = tarfile.TarInfo("package/" + rel)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if extra:
            extra(archive)
    return target


def upstream_fixture(populate=True, marker=None, integrity="sha512-AA=="):
    base = unique("upstream")
    cache = base / "cache"
    pin = {"name": "meshcentral", "version": "9.9.9", "tarball": "https://example.invalid/m.tgz",
           "integrity": integrity, "treeDigest": TINY_DIGEST, "fileCount": 3}
    base.mkdir(parents=True)
    pin_path = base / "pin.json"
    pin_path.write_text(json.dumps(pin), encoding="utf-8")
    ref_dir = cache / "meshcentral-9.9.9"
    package = ref_dir / "package"
    if populate:
        tiny_tree(package)
        (ref_dir / "reference.json").write_text(json.dumps({**pin, **(marker or {})}), encoding="utf-8")
    return {"env": {"MESHCENTRAL_UPSTREAM_CACHE": str(cache)}, "pin": pin, "pin_path": pin_path,
            "ref_dir": ref_dir, "package": package, "base": base}


def upstream(fixture):
    return paths.upstream_package_dir(fixture["env"], None, fixture["pin_path"])


def tree_digest_matches_node_fixture():
    assert paths.tree_digest(tiny_tree(unique("digest"))) == (TINY_DIGEST, 3)


def upstream_default_cache_is_under_artifacts():
    agent, _ = workspace(False)
    assert paths.upstream_cache_root({}, agent) == agent / "artifacts" / "meshcentral-upstream"


def upstream_verified_reference_is_returned():
    fixture = upstream_fixture()
    assert upstream(fixture) == fixture["package"]


def upstream_missing_names_the_command():
    fixture = upstream_fixture(populate=False)
    raises_with(lambda: upstream(fixture), ["is missing", paths.FETCH_COMMAND, "MESHCENTRAL_UPSTREAM_CACHE"])


def upstream_changed_file_fails_integrity():
    fixture = upstream_fixture()
    (fixture["package"] / "a" / "b.txt").write_bytes(b"hellO\n")
    raises_with(lambda: upstream(fixture), ["fails its integrity check", paths.FETCH_COMMAND])


def upstream_extra_file_fails_integrity():
    fixture = upstream_fixture()
    (fixture["package"] / "extra.js").write_bytes(b"")
    raises_with(lambda: upstream(fixture), ["fails its integrity check", "with 4 files"])


def upstream_other_pin_fails():
    fixture = upstream_fixture(marker={"treeDigest": "sha256:00"})
    raises_with(lambda: upstream(fixture), ["made from another pin", paths.FETCH_COMMAND])


def upstream_missing_marker_fails():
    fixture = upstream_fixture()
    (fixture["ref_dir"] / "reference.json").unlink()
    raises_with(lambda: upstream(fixture), ["no readable reference.json"])


def upstream_pin_is_complete():
    import re
    pin = paths.load_reference_pin()
    assert pin["name"] == "meshcentral" and pin["version"] == "1.3.1"
    assert re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", pin["integrity"]), pin["integrity"]
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", pin["treeDigest"]), pin["treeDigest"]
    assert isinstance(pin["fileCount"], int) and pin["fileCount"] > 0


def _fetch_tool():
    import importlib
    return importlib.import_module("fetch_upstream_reference")


def _fetch_fixture(extra=None):
    """A pin whose integrity matches a freshly written tiny tarball, and an empty cache."""
    tool = _fetch_tool()
    base = unique("fetchtgz")
    base.mkdir(parents=True)
    tarball = tiny_tarball(base / "m.tgz", extra)
    fixture = upstream_fixture(populate=False, integrity=tool.integrity_of(tarball))
    return tool, fixture, tarball


def fetch_populates_and_verifies():
    tool, fixture, tarball = _fetch_fixture()
    tool.populate(fixture["pin"], str(tarball), fixture["env"], None, fixture["pin_path"])
    assert upstream(fixture) == fixture["package"]
    marker = json.loads((fixture["ref_dir"] / "reference.json").read_text(encoding="utf-8"))
    assert marker["integrity"] == fixture["pin"]["integrity"]
    assert sorted(p.name for p in fixture["ref_dir"].parent.iterdir()) == ["meshcentral-9.9.9"], "no work folders left behind"


def fetch_replaces_a_tampered_cache():
    tool, fixture, tarball = _fetch_fixture()
    tool.populate(fixture["pin"], str(tarball), fixture["env"], None, fixture["pin_path"])
    (fixture["package"] / "a" / "b.txt").write_bytes(b"changed")
    paths._VERIFIED_UPSTREAM.clear()
    tool.populate(fixture["pin"], str(tarball), fixture["env"], None, fixture["pin_path"])
    assert (fixture["package"] / "a" / "b.txt").read_bytes() == b"hello\n"


def _fetch_raises(fixture_args, fragment):
    tool, fixture, tarball = fixture_args
    try:
        tool.populate(fixture["pin"], str(tarball), fixture["env"], None, fixture["pin_path"])
    except tool.FetchError as error:
        assert fragment in str(error), f"expected {fragment!r} in: {error}"
        assert not fixture["ref_dir"].exists(), "a failed fetch must not leave a reference behind"
        return
    raise AssertionError(f"expected FetchError containing {fragment!r}")


def fetch_rejects_wrong_integrity():
    tool, fixture, tarball = _fetch_fixture()
    fixture["pin"]["integrity"] = "sha512-" + "A" * 86 + "=="
    _fetch_raises((tool, fixture, tarball), "does not match the pinned")


def fetch_rejects_links_and_escapes():
    import io
    import tarfile

    def add_link(archive):
        info = tarfile.TarInfo("package/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        archive.addfile(info)

    def add_escape(archive):
        info = tarfile.TarInfo("package/../evil.txt")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    def add_outside(archive):
        info = tarfile.TarInfo("other/file.txt")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    _fetch_raises(_fetch_fixture(add_link), "not a regular file or folder")
    _fetch_raises(_fetch_fixture(add_escape), "unsafe name")
    _fetch_raises(_fetch_fixture(add_outside), "outside package/")


def fetch_rejects_wrong_tree():
    import io

    def add_extra(archive):
        import tarfile
        info = tarfile.TarInfo("package/extra.txt")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    _fetch_raises(_fetch_fixture(add_extra), "does not match the pinned")


def fetch_refuses_a_folder_it_did_not_make():
    tool, fixture, tarball = _fetch_fixture()
    (fixture["ref_dir"]).mkdir(parents=True)
    (fixture["ref_dir"] / "someone-elses.txt").write_bytes(b"keep")
    try:
        tool.populate(fixture["pin"], str(tarball), fixture["env"], None, fixture["pin_path"])
    except tool.FetchError as error:
        assert "did not make it" in str(error), str(error)
        assert (fixture["ref_dir"] / "someone-elses.txt").read_bytes() == b"keep"
        return
    raise AssertionError("expected the fetch tool to refuse a foreign folder")


CASES = [
    env_set_is_used, env_relative_is_resolved, env_missing_raises, env_not_a_directory_raises,
    env_without_markers_raises, empty_env_falls_back_to_sibling, sibling_present_is_used,
    sibling_absent_raises, default_meshagent_root_is_two_levels_up, deploy_package,
    stale_root_install_is_refused_without_env, stale_root_install_is_refused_with_env,
    root_install_is_never_used, no_package_raises, package_without_manifest_raises,
    package_with_other_name_raises, installed_package_needs_root, fork_file_is_under_root, fork_file_rejects_escapes, fork_file_needs_root,
    wrapper_file_is_under_deploy, wrapper_missing_names_stage1, wrapper_with_other_name_raises,
    tree_digest_matches_node_fixture, upstream_default_cache_is_under_artifacts,
    upstream_verified_reference_is_returned, upstream_missing_names_the_command,
    upstream_changed_file_fails_integrity, upstream_extra_file_fails_integrity, upstream_other_pin_fails,
    upstream_missing_marker_fails, upstream_pin_is_complete, fetch_populates_and_verifies,
    fetch_replaces_a_tampered_cache, fetch_rejects_wrong_integrity, fetch_rejects_links_and_escapes,
    fetch_rejects_wrong_tree, fetch_refuses_a_folder_it_did_not_make,
]


def main():
    failures = []
    try:
        for case in CASES:
            try:
                case()
            except Exception as error:  # report every case, then fail
                failures.append(f"{case.__name__}: {type(error).__name__}: {error}")
    finally:
        shutil.rmtree(TEMP, ignore_errors=False)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        print(f"FAIL meshcentral paths helper ({len(failures)}/{len(CASES)} failed)")
        sys.exit(1)
    print(f"PASS meshcentral paths helper ({len(CASES)} cases)")


if __name__ == "__main__":
    main()
