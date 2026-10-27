"""Check that deploy.py verifies, backs up and restores the declared set, never a disk-filtered one.

Runs against the local fake remote in test/deploy_fake_remote.py; no network I/O.
"""

import inspect
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from deploy_fake_remote import DeployFixture, deploy, deploy_args, rollback_args, run_quiet  # noqa: E402


def test_helpers_take_an_explicit_artifact_list():
    for function in (
        deploy.get_agent_publish_artifacts,
        deploy.get_public_download_artifacts,
        deploy.get_hashagents_tracked_artifacts,
        deploy.verify_remote_core_publish,
    ):
        parameter = next(iter(inspect.signature(function).parameters.values()))
        assert parameter.default is inspect.Parameter.empty, f"{function.__name__} must not default to today's disk"
    for function in (deploy.backup_current_agents, deploy.restore_agents_from_backup, deploy.cmd_rollback):
        source = inspect.getsource(function)
        assert "get_present_local" not in source, f"{function.__name__} must not filter by today's disk"


def test_core_state_reports_a_declared_file_missing_locally():
    with DeployFixture() as fixture:
        fixture.write_release("v1")
        fixture.seed_remote("v1")
        missing = deploy.build_local_core_artifact_entries()[-1]
        pathlib.Path(missing["local_path"]).unlink()
        state = deploy.get_core_publish_state()
        assert missing["name"] in [entry["name"] for entry in state], "a missing local file must not drop out"
        errors = deploy.get_core_publish_state_errors(state)
        assert f"{missing['name']}: local source missing; cannot verify the published copies" in errors, errors
        assert len(errors) == 1, errors


def test_publish_state_reports_a_tracked_binary_missing_locally():
    with DeployFixture() as fixture:
        fixture.write_release("v1")
        fixture.seed_remote("v1")
        assert deploy.get_publish_state_errors(deploy.get_publish_runtime_state()) == []
        (fixture.build / "MeshService.exe").unlink()
        errors = deploy.get_publish_state_errors(deploy.get_publish_runtime_state())
        assert errors == ["MeshService.exe: no local baseline to compare with the server"], errors


def test_rollback_restores_a_file_dropped_from_the_map():
    with DeployFixture() as fixture:
        fixture.seed_remote("v1")
        before = fixture.remote.snapshot()
        fixture.write_release("v2")
        fixture.stage()
        ok, output = run_quiet(deploy.cmd_deploy, deploy_args())
        assert ok is True, output
        # The next release drops a module from the map and from the local tree.
        dropped = "modules_meshcore/clipboard.js"
        del deploy.CORE_ARTIFACTS[dropped]
        fixture.remove_local_build()
        ok, output = run_quiet(deploy.cmd_rollback, rollback_args())
        assert ok is True, output
        for role in ("data-core", "module-core"):
            path = deploy.get_core_publish_path(role, dropped)
            assert fixture.remote.read(path) == before[path], path
        assert fixture.remote.snapshot() == before


def test_deploy_still_refuses_missing_required_artifacts():
    with DeployFixture() as fixture:
        fixture.seed_remote("v1")
        fixture.write_release("v2")
        fixture.stage()
        (fixture.build / "service_bundle.dll").unlink()
        ok, output = run_quiet(deploy.cmd_deploy, deploy_args())
        assert ok is False
        assert "Missing required deploy artifacts" in output and "service_bundle.dll" in output, output
        assert not fixture.remote.exists(deploy.BACKUP_DIR), "nothing may be backed up or published"


TESTS = [
    test_helpers_take_an_explicit_artifact_list,
    test_core_state_reports_a_declared_file_missing_locally,
    test_publish_state_reports_a_tracked_binary_missing_locally,
    test_rollback_restores_a_file_dropped_from_the_map,
    test_deploy_still_refuses_missing_required_artifacts,
]


def main():
    for test in TESTS:
        test()
        print(f"ok {test.__name__}")
    print(f"PASS deploy artifact selection runtime tests={len(TESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
