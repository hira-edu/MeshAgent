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
    deploy.ssh_cmd = lambda *args, **kwargs: raw_health
    deploy.get_publish_baseline_from_latest_manifest = lambda: ([], [], "fixture")
    deploy.get_publish_runtime_state = lambda unused: []
    deploy.get_core_publish_state = lambda unused: []
    with contextlib.redirect_stdout(io.StringIO()):
        return deploy.cmd_health(None)


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

    print("PASS health, retry, pacing, and transport-state controls=21")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
