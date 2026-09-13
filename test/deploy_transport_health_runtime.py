"""Exercise deployment retry classification and fail-closed health reporting without network I/O."""

import contextlib
import io
import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deploy  # noqa: E402


LABELS = [
    "Service active",
    "Port 4430 listening",
    "Port 443 listening",
    "Port 4445 listening",
    "Port 4446 listening",
    "Node process",
    "MongoDB reachable",
    "Disk usage",
    "Memory",
    "Recent errors",
]


def run_health(raw_health):
    original_ssh_cmd = deploy.ssh_cmd
    original_baseline = deploy.get_publish_baseline_from_latest_manifest
    original_runtime_state = deploy.get_publish_runtime_state
    original_core_state = deploy.get_core_publish_state
    try:
        deploy.ssh_cmd = lambda *args, **kwargs: raw_health
        deploy.get_publish_baseline_from_latest_manifest = lambda: ([], [], "fixture")
        deploy.get_publish_runtime_state = lambda unused: []
        deploy.get_core_publish_state = lambda unused: []
        with contextlib.redirect_stdout(io.StringIO()):
            return deploy.cmd_health(None)
    finally:
        deploy.ssh_cmd = original_ssh_cmd
        deploy.get_publish_baseline_from_latest_manifest = original_baseline
        deploy.get_publish_runtime_state = original_runtime_state
        deploy.get_core_publish_state = original_core_state


def run_ssh_cmd_with_result(result, check):
    original_runner = deploy.run_remote_process
    try:
        deploy.run_remote_process = lambda *args, **kwargs: (result, None)
        with contextlib.redirect_stdout(io.StringIO()):
            return deploy.ssh_cmd("fixture", check=check)
    finally:
        deploy.run_remote_process = original_runner


def main():
    healthy = json.dumps([{"label": label, "result": "ok", "ok": True} for label in LABELS])
    assert run_health(healthy) is True
    assert run_health(None) is False
    assert run_health("not-json") is False
    assert run_health(json.dumps([{"label": LABELS[0], "result": "ok", "ok": True}])) is False

    one_bad = json.dumps([
        {"label": label, "result": "bad" if index == 0 else "ok", "ok": index != 0}
        for index, label in enumerate(LABELS)
    ])
    assert run_health(one_bad) is False

    completed = subprocess.CompletedProcess
    assert deploy.should_retry_remote_result(
        completed([], 255, "", "ssh: connect to host fixture port 22: Connection timed out")
    ) is True
    assert deploy.should_retry_remote_result(completed([], 255, "", "Permission denied (publickey).")) is False
    assert deploy.should_retry_remote_result(completed([], 255, "", "Bad configuration option: fixture")) is False
    assert deploy.should_retry_remote_result(completed([], 1, "application timed out", "")) is False

    failed_results = [
        completed([], 255, "misleading-output", "Permission denied (publickey)."),
        completed([], 255, "misleading-output", "Bad configuration option: fixture"),
        completed([], 255, "misleading-output", "unknown ssh failure"),
        completed([], 255, "misleading-output", "Connection timed out"),
        completed([], 1, "misleading-output", "application failure"),
    ]
    for failed_result in failed_results:
        assert run_ssh_cmd_with_result(failed_result, check=True) is None
        assert run_ssh_cmd_with_result(failed_result, check=False) is None
    assert run_ssh_cmd_with_result(completed([], 0, "", ""), check=False) == ""
    assert run_ssh_cmd_with_result(completed([], 0, " fixture-output \n", ""), check=False) == "fixture-output"

    deploy_source = (ROOT / "deploy.py").read_text(encoding="utf-8")
    assert deploy_source.count("if restore_agents_from_backup(backup_path, check=False) is False:") == 2
    assert deploy_source.count("if refresh_remote_hashagents() is False:") >= 2
    assert "if ssh_cmd(f\"systemctl restart {SERVICE_NAME}\", check=False) is None:" in deploy_source

    original_runner = deploy.run_remote_process
    try:
        deploy.run_remote_process = lambda *args, **kwargs: (failed_results[0], None)
        with contextlib.redirect_stdout(io.StringIO()):
            assert deploy.refresh_remote_hashagents() is False
            assert deploy.restore_agents_from_backup("/fixture", check=False) is False
            assert deploy.cmd_ssh(type("Args", (), {"command": ["false"]})()) is False
    finally:
        deploy.run_remote_process = original_runner

    assert deploy.read_nonnegative_finite_env_float("MESHCENTRAL_TEST_UNSET_DELAY", 0) == 0
    for invalid in ("-1", "nan", "inf", "-inf", "bad", ""):
        old_value = deploy.os.environ.get("MESHCENTRAL_TEST_DELAY")
        deploy.os.environ["MESHCENTRAL_TEST_DELAY"] = invalid
        try:
            try:
                deploy.read_nonnegative_finite_env_float("MESHCENTRAL_TEST_DELAY", 0)
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"invalid success delay accepted: {invalid!r}")
        finally:
            if old_value is None:
                deploy.os.environ.pop("MESHCENTRAL_TEST_DELAY", None)
            else:
                deploy.os.environ["MESHCENTRAL_TEST_DELAY"] = old_value

    original_run = deploy.subprocess.run
    original_sleep = deploy.time.sleep
    original_retries = deploy.REMOTE_COMMAND_RETRIES
    original_success_delay = deploy.REMOTE_SUCCESS_DELAY_SECONDS
    sleeps = []

    def successful_remote(command, stdout, stderr, stdin, timeout):
        stdout.write("fixture-output")
        return completed(command, 0)

    call_count = 0

    def authentication_failure(command, stdout, stderr, stdin, timeout):
        nonlocal call_count
        call_count += 1
        stderr.write("Permission denied (publickey).")
        return completed(command, 255)

    def transient_failure(command, stdout, stderr, stdin, timeout):
        nonlocal call_count
        call_count += 1
        stderr.write("Connection timed out")
        return completed(command, 255)

    try:
        deploy.subprocess.run = successful_remote
        deploy.time.sleep = sleeps.append
        deploy.REMOTE_COMMAND_RETRIES = 1
        deploy.REMOTE_SUCCESS_DELAY_SECONDS = 7
        paced_result, paced_timeout = deploy.run_remote_process(["ssh", "fixture"], timeout=1)
        assert paced_timeout is None
        assert paced_result.returncode == 0
        assert paced_result.stdout == "fixture-output"
        assert sleeps == [7]

        deploy.REMOTE_COMMAND_RETRIES = 3
        deploy.REMOTE_SUCCESS_DELAY_SECONDS = 0
        sleeps.clear()
        call_count = 0
        deploy.subprocess.run = authentication_failure
        auth_result, auth_timeout = deploy.run_remote_process(["ssh", "fixture"], timeout=1)
        assert auth_timeout is None
        assert auth_result.returncode == 255
        assert call_count == 1
        assert sleeps == []

        call_count = 0
        deploy.subprocess.run = transient_failure
        transient_result, transient_timeout = deploy.run_remote_process(["ssh", "fixture"], timeout=1)
        assert transient_timeout is None
        assert transient_result.returncode == 255
        assert call_count == 3
        assert sleeps == [deploy.REMOTE_RETRY_DELAY_SECONDS, deploy.REMOTE_RETRY_DELAY_SECONDS * 2]
    finally:
        deploy.subprocess.run = original_run
        deploy.time.sleep = original_sleep
        deploy.REMOTE_COMMAND_RETRIES = original_retries
        deploy.REMOTE_SUCCESS_DELAY_SECONDS = original_success_delay

    original_ssh_cmd = deploy.ssh_cmd
    try:
        deploy.ssh_cmd = lambda *args, **kwargs: None
        assert deploy.collect_remote_file_metadata(["/fixture"]) is None
    finally:
        deploy.ssh_cmd = original_ssh_cmd
    assert deploy.get_publish_state_errors(None) == [deploy.REMOTE_PUBLISH_VERIFICATION_TRANSPORT_ERROR]
    assert deploy.get_core_publish_state_errors(None) == [deploy.REMOTE_PUBLISH_VERIFICATION_TRANSPORT_ERROR]
    assert deploy.summarize_core_publish_state(None) == "unavailable"

    original_baseline = deploy.get_publish_baseline_from_latest_manifest
    original_runtime_state = deploy.get_publish_runtime_state
    original_core_state = deploy.get_core_publish_state
    original_ssh_cmd = deploy.ssh_cmd
    try:
        deploy.ssh_cmd = lambda *args, **kwargs: healthy
        deploy.get_publish_baseline_from_latest_manifest = lambda: ([{"name": "agent"}], [{"name": "core"}], "fixture")
        deploy.get_publish_runtime_state = lambda unused: None
        deploy.get_core_publish_state = lambda unused: None
        with contextlib.redirect_stdout(io.StringIO()):
            assert deploy.cmd_health(None) is False
    finally:
        deploy.get_publish_baseline_from_latest_manifest = original_baseline
        deploy.get_publish_runtime_state = original_runtime_state
        deploy.get_core_publish_state = original_core_state
        deploy.ssh_cmd = original_ssh_cmd

    print("PASS health, retry, pacing, recovery, command-result, and transport-state controls=45")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
