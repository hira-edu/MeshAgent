"""Exercise deploy.py backup, restore, deploy recovery and rollback against a local fake remote.

No network I/O: deploy.run_remote_process is replaced by test/deploy_fake_remote.py, which runs
the remote shell commands against a temp directory standing in for /opt/meshcentral.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from deploy_fake_remote import DeployFixture, deploy, deploy_args, rollback_args, run_quiet  # noqa: E402

NEW_IN_RELEASE = "modules_meshcore/clipboard.js"


def diff(before, after):
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


def deploy_release(fixture, adds_files=True):
    """Seed v1 (by default without the module the release adds), stage v2 and deploy it."""
    fixture.seed_remote("v1", skip=(NEW_IN_RELEASE,) if adds_files else ())
    before = fixture.remote.snapshot()
    fixture.write_release("v2")
    fixture.stage()
    ok, output = run_quiet(deploy.cmd_deploy, deploy_args())
    assert ok is True, output
    return before


def test_backup_records_every_target_including_absent():
    with DeployFixture() as fixture:
        before = deploy_release(fixture)
        backup = fixture.latest_backup()
        manifest = fixture.remote.read_json(f"{backup}/{deploy.BACKUP_MANIFEST_FILENAME}")
        entries = {entry["path"]: entry for entry in manifest["entries"]}
        assert manifest["schema"] == deploy.BACKUP_MANIFEST_SCHEMA

        added = [
            deploy.get_core_publish_path(role, NEW_IN_RELEASE)
            for role in ("data-core", "module-core")
        ]
        for path in added:
            assert entries[path] == {"path": path, "state": "absent"}, entries[path]
        for path in deploy.get_stray_agent_payload_paths():
            assert entries[path]["state"] == "absent"
        for path, data in before.items():
            if path == deploy.CONFIG_FILE:
                continue
            entry = entries[path]
            assert entry["state"] == "present", entry
            copy = fixture.remote.read(f"{backup}/{deploy.BACKUP_FILES_DIRNAME}/{entry['copy']}")
            assert copy == data, path
            assert entry["size"] == len(data)
        assert deploy.CONFIG_FILE not in entries
        assert set(entries) == set(before) - {deploy.CONFIG_FILE} | set(added) | set(deploy.get_stray_agent_payload_paths())


def test_restore_returns_every_path_to_its_recorded_state():
    with DeployFixture() as fixture:
        before = deploy_release(fixture)
        after_deploy = fixture.remote.snapshot()
        assert diff(before, after_deploy), "the release changed nothing"
        assert fixture.remote.exists(deploy.get_core_publish_path("module-core", NEW_IN_RELEASE))

        # The restore needs only the backup: the local build and the artifact map are gone.
        fixture.remove_local_build()
        deploy.ARTIFACTS = {}
        deploy.CORE_ARTIFACTS = {}
        summary, output = run_quiet(deploy.restore_agents_from_backup, fixture.latest_backup())
        assert summary is not None, output
        assert summary["removed"] == 2, summary
        assert summary["errors"] == []
        assert diff(before, fixture.remote.snapshot()) == []


def test_restore_without_a_manifest_fails_loudly():
    with DeployFixture() as fixture:
        fixture.seed_remote("v1")
        legacy = f"{deploy.BACKUP_DIR}/20260101_000000"
        fixture.remote.write(f"{legacy}/dataagents/MeshService.exe", "legacy")
        before = fixture.remote.snapshot()
        summary, output = run_quiet(deploy.restore_agents_from_backup, legacy)
        assert summary is None
        assert "predates manifest-driven restore" in output, output
        assert diff(before, fixture.remote.snapshot()) == []


def test_restore_reports_a_tampered_copy_and_still_restores_the_rest():
    with DeployFixture() as fixture:
        before = deploy_release(fixture)
        backup = fixture.latest_backup()
        manifest = fixture.remote.read_json(f"{backup}/{deploy.BACKUP_MANIFEST_FILENAME}")
        tampered = next(entry for entry in manifest["entries"] if entry["state"] == "present")
        fixture.remote.write(f"{backup}/{deploy.BACKUP_FILES_DIRNAME}/{tampered['copy']}", "tampered")
        summary, output = run_quiet(deploy.restore_agents_from_backup, backup)
        assert summary is None
        assert "backup copy digest does not match the manifest" in output, output
        assert diff(before, fixture.remote.snapshot()) == [tampered["path"]]


def test_backup_refuses_an_existing_backup_directory():
    with DeployFixture() as fixture:
        fixture.seed_remote("v1")
        fixture.write_release("v2")
        backup = f"{deploy.BACKUP_DIR}/20260101_000000"
        fixture.remote.write(f"{backup}/marker", "existing")
        agents = deploy.get_agent_publish_artifacts(deploy.get_present_local_artifacts())
        result, output = run_quiet(
            deploy.backup_current_agents, backup, agents, [], deploy.get_present_local_core_artifacts()
        )
        assert result is None
        assert "backup directory already exists" in output, output


def test_rollback_after_a_successful_deploy():
    with DeployFixture() as fixture:
        before = deploy_release(fixture, adds_files=False)
        assert fixture.remote.restart_count() == 1
        # The local build still holds the release being rolled back; rollback must verify
        # against the backup, not against these bytes.
        ok, output = run_quiet(deploy.cmd_rollback, rollback_args())
        assert ok is True, output
        assert "Restored state matches the backup manifest." in output, output
        assert diff(before, fixture.remote.snapshot()) == []
        assert fixture.remote.restart_count() == 2, "rollback must restart MeshCentral on the restored files"


def test_rollback_removes_files_the_release_added():
    with DeployFixture() as fixture:
        before = deploy_release(fixture)
        added = [deploy.get_core_publish_path(role, NEW_IN_RELEASE) for role in ("data-core", "module-core")]
        assert all(fixture.remote.exists(path) for path in added)
        # Rollback needs only the backup manifest, not the local build.
        fixture.remove_local_build()
        ok, output = run_quiet(deploy.cmd_rollback, rollback_args())
        assert ok is True, output
        assert "removed 2 file(s)" in output, output
        assert not any(fixture.remote.exists(path) for path in added)
        assert diff(before, fixture.remote.snapshot()) == []
        assert fixture.remote.restart_count() == 2


def test_rollback_does_not_restart_when_the_restore_fails():
    with DeployFixture() as fixture:
        deploy_release(fixture)
        backup = fixture.latest_backup()
        manifest = fixture.remote.read_json(f"{backup}/{deploy.BACKUP_MANIFEST_FILENAME}")
        tampered = next(entry for entry in manifest["entries"] if entry["state"] == "present")
        fixture.remote.write(f"{backup}/{deploy.BACKUP_FILES_DIRNAME}/{tampered['copy']}", "tampered")
        ok, output = run_quiet(deploy.cmd_rollback, rollback_args())
        assert ok is False, output
        assert fixture.remote.restart_count() == 1, output


def test_backup_state_verification_reports_drift():
    with DeployFixture() as fixture:
        before = deploy_release(fixture)
        backup = fixture.latest_backup()
        errors = deploy.verify_backup_state(backup)
        assert len(errors) == len(diff(before, fixture.remote.snapshot())), errors
        assert any("recorded absent, but present" in error for error in errors), errors
        assert any("does not match the backed-up bytes" in error for error in errors), errors
        run_quiet(deploy.restore_agents_from_backup, backup)
        assert deploy.verify_backup_state(backup) == []


def stage_release(fixture):
    """Seed v1 without the module the release adds and stage v2, without deploying."""
    fixture.seed_remote("v1", skip=(NEW_IN_RELEASE,))
    before = fixture.remote.snapshot()
    fixture.write_release("v2")
    fixture.stage()
    return before


def test_partial_publish_is_restored_automatically():
    with DeployFixture() as fixture:
        before = stage_release(fixture)
        # Break the publish on the last core copy: every agent copy, meshagent.js and the new
        # data-core module have already been written by then.
        late_target = deploy.get_core_publish_path("module-core", NEW_IN_RELEASE)
        fixture.remote.fail_cp_to(late_target[len(deploy.MESHCENTRAL_BASE):])
        ok, output = run_quiet(deploy.cmd_deploy, deploy_args())
        assert ok is False, output
        assert "Publishing stopped part-way" in output, output
        assert "Deployment failed and was rolled back" in output, output
        assert "1 file(s) the release added removed" in output, output
        assert "MeshCentral was not restarted" in output, output
        assert diff(before, fixture.remote.snapshot()) == []
        assert fixture.remote.restart_count() == 0


def test_failed_restart_is_restored_and_restarted():
    with DeployFixture() as fixture:
        before = stage_release(fixture)
        fixture.remote.plan_restarts(["failed", "active"])
        ok, output = run_quiet(deploy.cmd_deploy, deploy_args())
        assert ok is False, output
        assert "MeshCentral did not come back after the restart (status: failed)" in output, output
        assert "Deployment failed and was rolled back" in output, output
        assert "restarted on the restored files and is active" in output, output
        assert diff(before, fixture.remote.snapshot()) == []
        assert fixture.remote.restart_count() == 2
        assert not list(deploy.MANIFEST_DIR.glob("release-manifest-*.json")), "a failed deploy must not write a release manifest"


def test_failed_restart_reports_when_the_restored_release_stays_down():
    with DeployFixture() as fixture:
        before = stage_release(fixture)
        fixture.remote.plan_restarts(["failed", "failed"])
        ok, output = run_quiet(deploy.cmd_deploy, deploy_args())
        assert ok is False, output
        assert "Deployment failed and was rolled back" in output, output
        assert "did not come back on the restored files either (status: failed)" in output, output
        assert diff(before, fixture.remote.snapshot()) == []
        assert fixture.remote.restart_count() == 2


TESTS = [
    test_backup_records_every_target_including_absent,
    test_restore_returns_every_path_to_its_recorded_state,
    test_restore_without_a_manifest_fails_loudly,
    test_restore_reports_a_tampered_copy_and_still_restores_the_rest,
    test_backup_refuses_an_existing_backup_directory,
    test_rollback_after_a_successful_deploy,
    test_rollback_removes_files_the_release_added,
    test_rollback_does_not_restart_when_the_restore_fails,
    test_backup_state_verification_reports_drift,
    test_partial_publish_is_restored_automatically,
    test_failed_restart_is_restored_and_restarted,
    test_failed_restart_reports_when_the_restored_release_stays_down,
]


def main():
    for test in TESTS:
        test()
        print(f"ok {test.__name__}")
    print(f"PASS deploy backup/restore/rollback runtime tests={len(TESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
