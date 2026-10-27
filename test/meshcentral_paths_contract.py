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


def install_package(root, layout_name, name="meshcentral"):
    rel = dict(paths.PACKAGE_LAYOUTS)[layout_name]
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


def wrapper_root_layout():
    agent, sibling = workspace(True)
    directory = install_package(sibling, "wrapper-root")
    assert directory == sibling / "node_modules" / "meshcentral"
    assert paths.installed_package_dir({}, agent) == ("wrapper-root", directory)


def deploy_layout():
    agent, sibling = workspace(True)
    directory = install_package(sibling, "deploy")
    assert directory == sibling / "deploy" / "node_modules" / "meshcentral"
    found = paths.installed_package_dir({}, agent)
    assert found.layout == "deploy" and found.path == directory


def both_layouts_raise():
    agent, sibling = workspace(True)
    a = install_package(sibling, "wrapper-root")
    b = install_package(sibling, "deploy")
    raises_with(lambda: paths.installed_package_dir({}, agent), ["ambiguous", "wrapper-root", a, "deploy", b])


def no_layout_raises():
    agent, sibling = workspace(True)
    raises_with(lambda: paths.installed_package_dir({}, agent),
                ["not found", "wrapper-root", sibling / "node_modules" / "meshcentral",
                 "deploy", sibling / "deploy" / "node_modules" / "meshcentral"])


def layout_without_manifest_raises():
    agent, sibling = workspace(True)
    (sibling / "deploy" / "node_modules" / "meshcentral").mkdir(parents=True)
    raises_with(lambda: paths.installed_package_dir({}, agent), ["layout deploy", "package.json"])


def layout_with_other_package_raises():
    agent, sibling = workspace(True)
    install_package(sibling, "wrapper-root", "not-meshcentral")
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


CASES = [
    env_set_is_used, env_relative_is_resolved, env_missing_raises, env_not_a_directory_raises,
    env_without_markers_raises, empty_env_falls_back_to_sibling, sibling_present_is_used,
    sibling_absent_raises, default_meshagent_root_is_two_levels_up, wrapper_root_layout, deploy_layout,
    both_layouts_raise, no_layout_raises, layout_without_manifest_raises, layout_with_other_package_raises,
    installed_package_needs_root, fork_file_is_under_root, fork_file_rejects_escapes, fork_file_needs_root,
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
