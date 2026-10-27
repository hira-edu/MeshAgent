"""Exercise deploy.py's meshctrl and updateAgents helpers with the local fake remote.

meshctrl and the updateAgents helper run only on the workstation: missing prerequisites fail
before anything touches the server, and the login key is never uploaded. No network I/O.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from deploy_fake_remote import Args, DeployFixture, deploy, run_quiet  # noqa: E402

FAKE_MESHCTRL = "console.log(JSON.stringify({ cwd: process.cwd(), args: process.argv.slice(2) }));\n"
FAKE_UPDATE_HELPER = r"""const fs = require('fs');
const args = process.argv.slice(2);
const nodeids = JSON.parse(fs.readFileSync(args[args.indexOf('--nodeids-file') + 1], 'utf8'));
console.log(JSON.stringify({ ok: true, count: nodeids.length, keyfile: args[args.indexOf('--loginkeyfile') + 1] }));
"""


def login_key_file(fixture):
    path = fixture.local / "loginkey.hex"
    path.write_text("ab" * 80, encoding="ascii")
    return str(path)


def install_local_cli(fixture, skip=()):
    """Lay out meshctrl.js, its Node modules and the update helper, leaving out `skip`."""
    if "meshctrl" not in skip:
        (fixture.meshcentral_repo / "meshctrl.js").write_text(FAKE_MESHCTRL, encoding="utf-8")
    for module in ("minimist", "ws"):
        if module not in skip:
            package = fixture.meshcentral_repo / "node_modules" / module / "package.json"
            package.parent.mkdir(parents=True, exist_ok=True)
            package.write_text(json.dumps({"name": module}), encoding="utf-8")
    if "helper" not in skip:
        helper = fixture.repo / "tools" / "meshcentral_update_agents.js"
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text(FAKE_UPDATE_HELPER, encoding="utf-8")


def expect_not_ready(function, *args):
    try:
        function(*args)
    except RuntimeError as error:
        return str(error)
    raise AssertionError(f"{function.__name__} ran without its local prerequisites")


def test_missing_prerequisites_fail_before_touching_the_server():
    for missing in ("meshctrl", "minimist", "ws", "helper"):
        with DeployFixture() as fixture:
            install_local_cli(fixture, skip=(missing,))
            key = login_key_file(fixture)
            for function, args in (
                (deploy.run_meshctrl, (["serverinfo"], "admin", key)),
                (deploy.send_update_agents, (["node//a"], "admin", key)),
            ):
                message = expect_not_ready(function, *args)
                assert "The local MeshCentral CLI is not ready" in message, message
                assert "npm ci" in message, message
            assert fixture.remote.calls == [], f"missing {missing}: the server was contacted"


def test_update_online_stops_before_fetching_the_login_key():
    with DeployFixture() as fixture:
        install_local_cli(fixture, skip=("ws",))
        args = Args(batch_size=50, login_user="admin", wait_seconds=0, poll_seconds=10,
                    activation_wait_seconds=0, filter=None, limit=None, dry_run=True,
                    native_activate=False)
        ok, output = run_quiet(deploy.cmd_update_online, args)
        assert ok is False
        assert "missing Node module ws" in output, output
        assert fixture.remote.calls == [], "the login key must not be fetched when the CLI cannot run"


def test_meshctrl_and_update_helper_run_locally_with_the_local_key():
    with DeployFixture() as fixture:
        install_local_cli(fixture)
        key = login_key_file(fixture)
        result = deploy.run_meshctrl(["serverinfo"], "admin", key)
        assert result.returncode == 0, result.stderr
        ran = json.loads(result.stdout)
        assert ran["args"][0] == "serverinfo"
        assert ran["args"][ran["args"].index("--loginkeyfile") + 1] == key
        assert pathlib.Path(ran["cwd"]).resolve() == fixture.meshcentral_repo.resolve()
        response = deploy.send_update_agents(["node//a", "node//b"], "admin", key)
        assert response == {"ok": True, "count": 2, "keyfile": key}, response
        assert fixture.remote.calls == [], "meshctrl must not run on, or upload anything to, the server"


TESTS = [
    test_missing_prerequisites_fail_before_touching_the_server,
    test_update_online_stops_before_fetching_the_login_key,
    test_meshctrl_and_update_helper_run_locally_with_the_local_key,
]


def main():
    for test in TESTS:
        test()
        print(f"ok {test.__name__}")
    print(f"PASS deploy meshctrl runtime tests={len(TESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
