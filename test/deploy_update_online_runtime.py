"""Exercise deploy.py update-online reporting and its break-glass activation flag with fakes.

update-online succeeds only when every targeted node reconnects with the update during the
watch. Nodes left pending fail the command (exit status 1) and are named. The lifecycle-host
activation (--native-activate) is off unless the operator asks for it. No network I/O: the
meshctrl-level helpers are replaced, and the import reads no branding file.
"""

import pathlib
import sys
import tempfile
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from deploy_fake_remote import Args, deploy, run_quiet  # noqa: E402

NODES = [
    {"_id": "node//a", "name": "alpha", "agct": 100},
    {"_id": "node//b", "name": "bravo", "agct": 200},
]


class FakeServer:
    """The meshctrl-level helpers update-online calls, with scripted reconnects."""

    def __init__(self, reconnect_initial=(), reconnect_after_activation=(), staged=None):
        self.reconnect_initial = set(reconnect_initial)
        self.reconnect_after_activation = set(reconnect_after_activation)
        self.staged = staged or {}
        self.submitted = []
        self.activated = []
        self.phases = []

    def watch_reconnects(self, pending, baseline_agct, login_user, login_key_file, wait_seconds,
                         poll_seconds, phase_label, device_filter=None):
        self.phases.append(phase_label)
        wanted = self.reconnect_initial if phase_label == "Initial watch" else self.reconnect_after_activation
        reconnected = {nodeid for nodeid in pending if nodeid in wanted}
        pending.difference_update(reconnected)
        return reconnected

    def get_node_pending_updates(self, nodeid, login_user, login_key_file):
        return list(self.staged.get(nodeid, []))

    def probe_remote_update_activation_inputs(self, nodeid, update_path, login_user, login_key_file):
        return {"paths": {}, "checks": {"UPDATE": True, "HOSTDLL": True}}

    def activate_remote_pending_update(self, nodeid, update_path, login_user, login_key_file):
        self.activated.append((nodeid, update_path))
        return {"update_path": update_path, "host_dll_path": deploy.WINDOWS_LIFECYCLE_DLL}


def run_update_online(server, **overrides):
    values = dict(batch_size=50, login_user="admin", wait_seconds=90, poll_seconds=10,
                  activation_wait_seconds=180, filter=None, limit=None, dry_run=False,
                  native_activate=False)
    values.update(overrides)
    key_dir = tempfile.mkdtemp(prefix="update-online-key-")
    key_file = pathlib.Path(key_dir) / "loginkey.hex"

    def create_key():
        key_file.write_text("ab" * 80, encoding="ascii")
        return str(key_file)

    replacements = {
        "require_local_meshcentral_cli": lambda: None,
        "create_temp_login_key_file": create_key,
        "get_online_agent_nodes": lambda user, key, device_filter=None: [dict(node) for node in NODES],
        "send_update_agents": lambda batch, user, key: server.submitted.append(list(batch)) or {"count": len(batch)},
        "watch_reconnects": server.watch_reconnects,
        "get_node_pending_updates": server.get_node_pending_updates,
        "probe_remote_update_activation_inputs": server.probe_remote_update_activation_inputs,
        "activate_remote_pending_update": server.activate_remote_pending_update,
        "time": types.SimpleNamespace(sleep=lambda seconds: None, time=deploy.time.time),
    }
    saved = {name: getattr(deploy, name) for name in replacements}
    for name, value in replacements.items():
        setattr(deploy, name, value)
    try:
        ok, output = run_quiet(deploy.cmd_update_online, Args(**values))
    finally:
        for name, value in saved.items():
            setattr(deploy, name, value)
    assert not key_file.exists(), "the local login key file must be removed"
    return ok, output


def test_all_nodes_reconnecting_is_success():
    server = FakeServer(reconnect_initial={"node//a", "node//b"})
    ok, output = run_update_online(server)
    assert ok is True, output
    assert "[SUCCESS]" in output and "[FAILED]" not in output, output
    assert server.submitted == [["node//a", "node//b"]]


def test_pending_nodes_fail_without_activation_by_default():
    server = FakeServer(reconnect_initial={"node//a"}, staged={"node//b": ["C:\\x\\agent.update.exe"]})
    ok, output = run_update_online(server)
    assert ok is False, output
    assert "[SUCCESS]" not in output, output
    assert "[FAILED] 1 of 2 node(s) still pending" in output, output
    assert "bravo" in output.split("[FAILED]", 1)[1], output
    assert server.activated == [] and server.phases == ["Initial watch"], "activation must be opt-in"


def test_failed_break_glass_activation_is_failure():
    server = FakeServer(reconnect_initial={"node//a"})  # bravo has no staged payload
    ok, output = run_update_online(server, native_activate=True)
    assert ok is False, output
    assert "[SUCCESS]" not in output, output
    assert "No staged" in output and "[FAILED] 1 of 2 node(s) still pending" in output, output
    assert server.activated == []


def test_break_glass_activation_still_pending_is_failure():
    server = FakeServer(reconnect_initial={"node//a"}, staged={"node//b": ["C:\\x\\agent.update.exe"]})
    ok, output = run_update_online(server, native_activate=True)
    assert ok is False, output
    assert server.activated == [("node//b", "C:\\x\\agent.update.exe")]
    assert server.phases == ["Initial watch", "Activation watch"]
    assert "[FAILED] 1 of 2 node(s) still pending" in output, output


def test_break_glass_activation_that_reconnects_is_success():
    server = FakeServer(reconnect_initial={"node//a"}, reconnect_after_activation={"node//b"},
                        staged={"node//b": ["C:\\x\\agent.update.exe"]})
    ok, output = run_update_online(server, native_activate=True)
    assert ok is True, output
    assert "[SUCCESS]" in output and "[FAILED]" not in output, output
    assert server.activated == [("node//b", "C:\\x\\agent.update.exe")]


def run_main(argv, command):
    saved = (sys.argv, deploy.SERVER, deploy.cmd_update_online)
    sys.argv = ["deploy.py"] + argv
    deploy.SERVER = "fake-remote.invalid"
    deploy.cmd_update_online = command
    try:
        deploy.main()
    except SystemExit as exit_:
        return exit_.code
    finally:
        sys.argv, deploy.SERVER, deploy.cmd_update_online = saved
    return 0


def test_cli_default_is_off_and_failure_exits_nonzero():
    seen = []
    assert run_main(["update-online"], lambda args: seen.append(args.native_activate) or True) == 0
    assert run_main(["update-online", "--native-activate"], lambda args: seen.append(args.native_activate) or True) == 0
    assert seen == [False, True], seen
    assert run_main(["update-online"], lambda args: False) == 1, "a failed update-online must exit 1"


TESTS = [
    test_all_nodes_reconnecting_is_success,
    test_pending_nodes_fail_without_activation_by_default,
    test_failed_break_glass_activation_is_failure,
    test_break_glass_activation_still_pending_is_failure,
    test_break_glass_activation_that_reconnects_is_success,
    test_cli_default_is_off_and_failure_exits_nonzero,
]


def main():
    failures = 0
    for test in TESTS:
        try:
            test()
            print(f"ok {test.__name__}")
        except AssertionError as error:
            failures += 1
            print(f"FAIL {test.__name__}: {error}")
    if failures:
        print(f"FAIL deploy update-online runtime failures={failures}/{len(TESTS)}")
        return 1
    print(f"PASS deploy update-online runtime tests={len(TESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
