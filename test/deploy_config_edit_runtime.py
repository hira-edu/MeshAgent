"""Exercise `deploy.py config edit` against the local fake remote.

The server config is edited in a private temp directory outside the repository that is
removed on every path, and nothing is uploaded unless the remote .bak copy succeeded.
No network I/O; the editor is a local script selected through $EDITOR.
"""

import builtins
import contextlib
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from deploy_fake_remote import Args, DeployFixture, deploy, run_quiet  # noqa: E402

ORIGINAL = {"settings": {"noagentupdate": True}, "domains": {"": {"title": "original"}}}

EDITOR_SCRIPT = r'''import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
pathlib.Path(os.environ["FAKE_EDITOR_LOG"]).write_text(str(path), encoding="utf-8")
mode = os.environ["FAKE_EDITOR_MODE"]
if mode == "invalid":
    path.write_text('{"settings": {', encoding="utf-8")
elif mode == "valid":
    config = json.loads(path.read_text(encoding="utf-8"))
    config["domains"][""]["title"] = "edited"
    path.write_text(json.dumps(config), encoding="utf-8")
'''


@contextlib.contextmanager
def config_editor(fixture, mode):
    """Point $EDITOR at a script that rewrites the file; yield the file recording its argument."""
    tools = fixture.remote.workdir / "editor"
    tools.mkdir(exist_ok=True)
    script = tools / "editor.py"
    script.write_text(EDITOR_SCRIPT, encoding="utf-8")
    if os.name == "nt":
        launcher = tools / "editor.cmd"
        launcher.write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        launcher = tools / "editor"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        launcher.chmod(0o755)
    log = tools / "edited-path.txt"
    saved = {name: os.environ.get(name) for name in ("EDITOR", "FAKE_EDITOR_MODE", "FAKE_EDITOR_LOG")}
    os.environ.update({"EDITOR": str(launcher), "FAKE_EDITOR_MODE": mode, "FAKE_EDITOR_LOG": str(log)})
    try:
        yield log
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextlib.contextmanager
def answer_prompts(answer):
    original = builtins.input
    builtins.input = lambda prompt="": answer
    try:
        yield
    finally:
        builtins.input = original


def repo_files(fixture):
    return sorted(path for path in fixture.repo.rglob("*"))


def remote_backups(fixture):
    config_dir = fixture.remote.path(deploy.CONFIG_FILE).parent
    return sorted(path.name for path in config_dir.glob("config.json.bak.*"))


def assert_private_copy_removed(fixture, log):
    edited = pathlib.Path(log.read_text(encoding="utf-8"))
    assert not edited.parent.exists(), f"temp config directory left behind: {edited.parent}"
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    for root in (repo_root, fixture.repo):
        assert root not in edited.parents, f"config was downloaded inside the repository: {edited}"


def run_edit(fixture, mode, answer="n"):
    fixture.remote.write(deploy.CONFIG_FILE, json.dumps(ORIGINAL))
    before_repo = repo_files(fixture)
    with config_editor(fixture, mode) as log, answer_prompts(answer):
        result, output = run_quiet(deploy.cmd_config, Args(action="edit"))
    assert repo_files(fixture) == before_repo, "config edit must not write into the repository"
    assert not (fixture.repo / ".tmp_config.json").exists()
    return result, output, log


def test_invalid_json_uploads_nothing_and_leaves_no_copy():
    with DeployFixture() as fixture:
        result, output, log = run_edit(fixture, "invalid")
        assert result is False, output
        assert "Invalid JSON" in output, output
        assert json.loads(fixture.remote.read(deploy.CONFIG_FILE)) == ORIGINAL
        assert remote_backups(fixture) == []
        assert not [call for call in fixture.remote.scp_calls() if call[2].endswith(deploy.CONFIG_FILE)]
        assert_private_copy_removed(fixture, log)


def test_failed_remote_backup_stops_the_upload():
    with DeployFixture() as fixture:
        fixture.remote.fail_cp_to("config.json.bak.")
        result, output, log = run_edit(fixture, "valid")
        assert result is False, output
        assert "Could not back up the server config; nothing was uploaded." in output, output
        assert json.loads(fixture.remote.read(deploy.CONFIG_FILE)) == ORIGINAL
        assert_private_copy_removed(fixture, log)


def test_valid_edit_is_backed_up_then_uploaded():
    with DeployFixture() as fixture:
        result, output, log = run_edit(fixture, "valid")
        assert result is True, output
        uploaded = json.loads(fixture.remote.read(deploy.CONFIG_FILE))
        assert uploaded["domains"][""]["title"] == "edited"
        backups = remote_backups(fixture)
        assert len(backups) == 1, backups
        config_dir = fixture.remote.path(deploy.CONFIG_FILE).parent
        assert json.loads((config_dir / backups[0]).read_text(encoding="utf-8")) == ORIGINAL
        assert fixture.remote.restart_count() == 0
        assert_private_copy_removed(fixture, log)


def test_unchanged_config_uploads_nothing():
    with DeployFixture() as fixture:
        result, output, log = run_edit(fixture, "unchanged")
        assert result is True, output
        assert "No changes made" in output, output
        assert remote_backups(fixture) == []
        assert_private_copy_removed(fixture, log)


TESTS = [
    test_invalid_json_uploads_nothing_and_leaves_no_copy,
    test_failed_remote_backup_stops_the_upload,
    test_valid_edit_is_backed_up_then_uploaded,
    test_unchanged_config_uploads_nothing,
]


def main():
    for test in TESTS:
        test()
        print(f"ok {test.__name__}")
    print(f"PASS deploy config edit runtime tests={len(TESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
