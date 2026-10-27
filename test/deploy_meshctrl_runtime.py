"""Exercise deploy.py's meshctrl and updateAgents helpers against the local fake remote.

No network I/O: the fake remote replaces deploy.run_remote_process.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from deploy_fake_remote import DeployFixture, deploy, run_quiet  # noqa: E402


def login_key_file(fixture):
    path = fixture.local / "loginkey.hex"
    path.write_text("ab" * 80, encoding="ascii")
    return str(path)


def test_remote_key_file_is_removed_after_remote_meshctrl():
    with DeployFixture() as fixture:
        result, output = run_quiet(deploy.run_meshctrl, ["serverinfo"], "admin", login_key_file(fixture))
        assert result.returncode != 0, "the fake server has no meshctrl.js"
        assert any(call[0] == "scp" for call in fixture.remote.calls), "fixture must take the remote path"
        assert fixture.remote.temp_files() == [], fixture.remote.temp_files()


def test_failed_key_removal_fails_loudly():
    with DeployFixture() as fixture:
        fixture.remote.fail_command("rm", "meshcentral-loginkey-")
        try:
            run_quiet(deploy.run_meshctrl, ["serverinfo"], "admin", login_key_file(fixture))
        except RuntimeError as error:
            message = str(error)
        else:
            raise AssertionError("a login key left on the server must raise")
        left = fixture.remote.temp_files()
        assert len(left) == 1 and left[0].startswith("meshcentral-loginkey-"), left
        assert "delete them by hand" in message and left[0] in message, message


TESTS = [
    test_remote_key_file_is_removed_after_remote_meshctrl,
    test_failed_key_removal_fails_loudly,
]


def main():
    for test in TESTS:
        test()
        print(f"ok {test.__name__}")
    print(f"PASS deploy meshctrl runtime tests={len(TESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
