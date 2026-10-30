"""Local stand-in for the deploy.py SSH/SCP remote, used by the deploy_* runtime tests.

The fake replaces deploy.run_remote_process, the one function every ssh/scp call in
deploy.py goes through. Remote shell commands run in a local POSIX shell against a temp
directory that stands in for /opt/meshcentral; remote paths are rewritten on the way in
and back on the way out, so deploy.py sees its usual remote paths. Nothing here opens a
network connection: any command that is not ssh or scp to the fake host fails the test.
"""

import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE_HOST = "fake-remote.invalid"

# Explicit lifecycle paths keep the deploy import from reading any branding file.
os.environ.setdefault("MESHCENTRAL_INSTALL_ROOT", "C:\\FakeInstall")
os.environ.setdefault("MESHCENTRAL_LIFECYCLE_DLL", "C:\\FakeInstall\\fake.dll")
os.environ.setdefault("MESHCENTRAL_LIFECYCLE_STATE_DIR", "C:\\FakeInstall\\state")
os.environ["MESHCENTRAL_SSH_HOST"] = FAKE_HOST
os.environ["MESHCENTRAL_SSH_RETRIES"] = "1"

sys.path.insert(0, str(ROOT))
import deploy  # noqa: E402

REMOTE_BASE = deploy.MESHCENTRAL_BASE

SYSTEMCTL_SHIM = r"""#!/bin/sh
echo "$*" >> "$FAKE_STATE/systemctl.log"
case "$1" in
  restart)
    n=$(cat "$FAKE_STATE/restart-count" 2>/dev/null || echo 0)
    n=$((n + 1))
    echo "$n" > "$FAKE_STATE/restart-count"
    outcome=$(sed -n "${n}p" "$FAKE_STATE/restart-plan" 2>/dev/null)
    [ -z "$outcome" ] && outcome=active
    echo "$outcome" > "$FAKE_STATE/service-state"
    ;;
  is-active)
    state=$(cat "$FAKE_STATE/service-state" 2>/dev/null || echo active)
    echo "$state"
    [ "$state" = active ]
    ;;
  *)
    echo "fake systemctl: unsupported $*" >&2
    exit 2
    ;;
esac
"""

# Fails the command when its last argument contains one of the newline-separated patterns
# in $FAKE_STATE/<command>-fail (used to break a publish part-way through, and so on).
FAILING_COMMAND_SHIM = r"""#!/bin/sh
if [ -f "$FAKE_STATE/@NAME@-fail" ]; then
  for last; do :; done
  while IFS= read -r pattern; do
    [ -n "$pattern" ] || continue
    case "$last" in
      *"$pattern"*) echo "fake @NAME@: injected failure for $last" >&2; exit 1 ;;
    esac
  done < "$FAKE_STATE/@NAME@-fail"
fi
[ -x /usr/bin/@NAME@ ] && exec /usr/bin/@NAME@ "$@"
exec /bin/@NAME@ "$@"
"""


def find_posix_shell():
    """Return a POSIX shell; on Windows use Git's bash, never WSL's."""
    if os.name != "nt":
        return shutil.which("sh") or "/bin/sh"
    exec_path = subprocess.run(["git", "--exec-path"], capture_output=True, text=True, check=True).stdout.strip()
    git_root = pathlib.Path(exec_path).parents[2]
    bash = git_root / "bin" / "bash.exe"
    if not bash.is_file():
        raise RuntimeError(f"Git bash not found at {bash}")
    return str(bash)


class FakeRemote:
    """A temp directory standing in for the deployment server."""

    def __init__(self):
        self.workdir = pathlib.Path(tempfile.mkdtemp(prefix="meshagent-fake-remote-")).resolve()
        self.base = self.workdir / "opt" / "meshcentral"
        self.base.mkdir(parents=True)
        self.state = self.workdir / "state"
        self.state.mkdir()
        self.shims = self.workdir / "shims"
        self.shims.mkdir()
        self.fake_base = self.base.as_posix()
        self.shell = find_posix_shell()
        self.calls = []
        self._write_shim("systemctl", SYSTEMCTL_SHIM)
        self._write_shim("cp", FAILING_COMMAND_SHIM.replace("@NAME@", "cp"))
        python = pathlib.Path(sys.executable).as_posix()
        self._write_shim("python3", f'#!/bin/sh\nexec "{python}" "$@"\n')

    def _write_shim(self, name, body):
        path = self.shims / name
        path.write_text(body, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    # Path translation between deploy.py's remote paths and the temp directory.
    def to_fake(self, text):
        return text.replace(REMOTE_BASE, self.fake_base)

    def from_fake(self, text):
        return text.replace(self.fake_base, REMOTE_BASE).replace(str(self.base), REMOTE_BASE)

    def path(self, remote_path):
        """Return the local file standing in for a remote path."""
        if remote_path != REMOTE_BASE and not remote_path.startswith(REMOTE_BASE + "/"):
            raise ValueError(f"Remote path outside the fake server: {remote_path}")
        return pathlib.Path(self.to_fake(remote_path))

    def write(self, remote_path, data):
        target = self.path(remote_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))

    def read(self, remote_path):
        return self.path(remote_path).read_bytes()

    def read_json(self, remote_path):
        """Read a JSON file the remote wrote, translating its paths back to remote paths."""
        return json.loads(self.from_fake(self.read(remote_path).decode("utf-8")))

    def exists(self, remote_path):
        return self.path(remote_path).exists()

    def snapshot(self, exclude=("backups", "staging")):
        """Return {remote path: bytes} for every file outside the excluded top-level dirs."""
        files = {}
        for item in sorted(self.base.rglob("*")):
            relative = item.relative_to(self.base)
            if relative.parts[0] in exclude or not item.is_file():
                continue
            files[f"{REMOTE_BASE}/{relative.as_posix()}"] = item.read_bytes()
        return files

    # systemctl and cp controls
    def plan_restarts(self, outcomes):
        (self.state / "restart-plan").write_text("\n".join(outcomes) + "\n", encoding="utf-8", newline="\n")

    def fail_command(self, name, *patterns):
        (self.state / f"{name}-fail").write_text("\n".join(patterns) + "\n", encoding="utf-8", newline="\n")

    def fail_cp_to(self, *patterns):
        self.fail_command("cp", *patterns)

    def clear_cp_failures(self):
        with contextlib.suppress(FileNotFoundError):
            (self.state / "cp-fail").unlink()

    def systemctl_calls(self):
        log = self.state / "systemctl.log"
        return log.read_text(encoding="utf-8").split() if log.exists() else []

    def restart_count(self):
        return self.systemctl_calls().count("restart")

    # Transport
    def _posix_path(self, path):
        """Return a path in the form the POSIX shell uses inside PATH."""
        text = path.as_posix()
        if os.name == "nt" and len(text) > 1 and text[1] == ":":
            text = "/" + text[0].lower() + text[2:]
        return text

    def _run_shell(self, script):
        env = dict(os.environ)
        env["FAKE_STATE"] = self.state.as_posix()
        # Git bash puts /usr/bin first, so the shims are prepended inside the shell.
        prologue = f'PATH="{self._posix_path(self.shims)}:$PATH"; export PATH\n'
        # The script goes in on stdin, as "sh -s" receives it over ssh: a long script passed as a
        # -c argument is cut at the Windows command-line limit.
        completed = subprocess.run(
            [self.shell, "-s"],
            input=prologue + self.to_fake(script),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=120,
        )
        return completed.returncode, self.from_fake(completed.stdout), self.from_fake(completed.stderr)

    def _remote_file(self, spec):
        prefix = f"{deploy.get_remote_target()}:"
        if spec.startswith(prefix):
            return self.path(spec[len(prefix):])
        return None

    def run_remote_process(self, full_cmd, timeout, stdin_text=None):
        binary = pathlib.Path(full_cmd[0]).name
        target = deploy.get_remote_target()
        if binary == "ssh":
            if target not in full_cmd or not target.endswith(FAKE_HOST):
                raise AssertionError(f"ssh outside the fake remote: {full_cmd}")
            command = full_cmd[full_cmd.index(target) + 1]
            script = stdin_text if command == "sh -s" else command
            self.calls.append(("ssh", script))
            returncode, stdout, stderr = self._run_shell(script)
            return subprocess.CompletedProcess(full_cmd, returncode, stdout, stderr), None
        if binary == "scp":
            source, destination = full_cmd[-2], full_cmd[-1]
            remote_source = self._remote_file(source)
            remote_destination = self._remote_file(destination)
            if (remote_source is None) == (remote_destination is None):
                raise AssertionError(f"scp must have exactly one fake-remote side: {full_cmd}")
            self.calls.append(("scp", source, destination))
            local_source = remote_source or pathlib.Path(source)
            local_destination = remote_destination or pathlib.Path(destination)
            if not local_source.is_file() or not local_destination.parent.is_dir():
                return subprocess.CompletedProcess(full_cmd, 1, "", f"scp: no such file: {source}"), None
            shutil.copyfile(local_source, local_destination)
            return subprocess.CompletedProcess(full_cmd, 0, "", ""), None
        raise AssertionError(f"Unexpected remote process: {full_cmd}")

    def scp_calls(self):
        return [call for call in self.calls if call[0] == "scp"]

    def close(self):
        shutil.rmtree(self.workdir, ignore_errors=True)


HASHAGENTS_FIXTURE = """var agents = {
    'MeshService.exe': 3,
    'MeshService64.exe': 4,
};
"""


class DeployFixture:
    """A fake remote plus a small local release, patched into the deploy module."""

    AGENTS = {
        "MeshService64.exe": ("data", "signed", "module"),
        "MeshService.exe": ("data", "signed", "module"),
        "service_bundle.dll": ("signed", "module"),
    }
    CORE = {
        "meshagent.js": ("meshagent.js", ("module-root",)),
        "modules_meshcore/clipboard.js": ("modules_meshcore/clipboard.js", ("data-core", "module-core")),
    }

    def __init__(self):
        self.remote = FakeRemote()
        self.local = self.remote.workdir / "local"
        self.repo = self.local / "MeshAgent"
        self.repo.mkdir(parents=True)
        self.meshcentral_repo = self.local / "MeshCentral"
        (self.meshcentral_repo / "agents").mkdir(parents=True)
        (self.meshcentral_repo / "agents" / "hashagents.js").write_text(HASHAGENTS_FIXTURE, encoding="utf-8")
        self.build = self.local / "build"
        self.build.mkdir()
        self._saved = {}

    def __enter__(self):
        artifacts = {
            name: {
                "local_path": str(self.build / name),
                "remote_filename": name,
                "publish_targets": targets,
            }
            for name, targets in self.AGENTS.items()
        }
        core = {
            name: {
                "local_path": str(self.build / "core" / relative),
                "remote_relative_path": relative,
                "publish_targets": targets,
            }
            for name, (relative, targets) in self.CORE.items()
        }
        self._patch("run_remote_process", self.remote.run_remote_process)
        self._patch("SSH_HOST", FAKE_HOST)
        self._patch("ARTIFACTS", artifacts)
        self._patch("CORE_ARTIFACTS", core)
        self._patch("REQUIRED_AGENT_ARTIFACTS", set(self.AGENTS))
        self._patch("HASHAGENTS_TRACKED_FILENAMES", {"MeshService.exe", "MeshService64.exe"})
        self._patch("SIGNED_RUNTIME_MUTABLE_FILENAMES", {"MeshService.exe", "MeshService64.exe"})
        self._patch("LOCAL_REPO", self.repo)
        self._patch("LOCAL_MESHCENTRAL_REPO", self.meshcentral_repo)
        self._patch("MANIFEST_DIR", self.repo / "artifacts" / "deployment")
        self._patch("USERFILES_DIR", "")
        self._patch("REMOTE_RETRY_DELAY_SECONDS", 0)
        # The fixture binaries are not PE files; the PE bundle contract has its own tests.
        self._patch("validate_local_service_bundle_artifacts", lambda unused: {"ok": True, "errors": []})
        return self

    def __exit__(self, *exc):
        for name, value in self._saved.items():
            setattr(deploy, name, value)
        self.remote.close()
        return False

    def _patch(self, name, value):
        if name not in self._saved:
            self._saved[name] = getattr(deploy, name)
        setattr(deploy, name, value)

    def write_release(self, label, skip=()):
        """Write a local build whose bytes are tagged with label."""
        for name in self.AGENTS:
            if name not in skip:
                (self.build / name).write_bytes(f"{name} {label}\n".encode("utf-8"))
        for name, (relative, unused) in self.CORE.items():
            if name in skip:
                continue
            path = self.build / "core" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"// {name} {label}\n".encode("utf-8"))

    def remove_local_build(self):
        shutil.rmtree(self.build)
        self.build.mkdir()

    def seed_remote(self, label, skip=()):
        """Install a previous release on the fake server, then generate its hashagents.json."""
        for name, targets in self.AGENTS.items():
            if name in skip:
                continue
            for role in targets:
                self.remote.write(deploy.get_publish_path(role, name), f"{name} {label}\n")
        for name, (relative, targets) in self.CORE.items():
            if name in skip:
                continue
            for role in targets:
                self.remote.write(deploy.get_core_publish_path(role, relative), f"// {name} {label}\n")
        self.remote.write(deploy.CONFIG_FILE, json.dumps({"settings": {"noagentupdate": True}}))
        if deploy.refresh_remote_hashagents() is False:
            raise RuntimeError("fixture hashagents refresh failed")

    def stage(self):
        """Stage the local release on the fake server exactly as cmd_stage leaves it: agent binaries
        only, because MeshCentral files are refused (deploy.MESHCENTRAL_PUBLISH_REFUSAL)."""
        local_artifacts = deploy.get_present_local_artifacts()
        entries = deploy.get_agent_publish_artifacts(local_artifacts)
        for entry in entries:
            self.remote.write(
                f"{deploy.STAGING_DIR}/{deploy.get_staging_filename(entry)}",
                pathlib.Path(entry["local_path"]).read_bytes(),
            )
        manifest = deploy.build_stage_manifest(entries)
        self.remote.write(
            f"{deploy.STAGING_DIR}/{deploy.STAGING_MANIFEST_FILENAME}",
            json.dumps(manifest, indent=2) + "\n",
        )

    def latest_backup(self):
        backups = sorted((self.remote.base / "backups").iterdir())
        return f"{deploy.BACKUP_DIR}/{backups[-1].name}"


class Args:
    def __init__(self, **values):
        self.__dict__.update(values)


def run_quiet(function, *args):
    """Run a deploy command, returning (result, captured stdout)."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        result = function(*args)
    return result, output.getvalue()


def deploy_args():
    # The fake server has no jq; the noagentupdate gate is not what these tests cover.
    return Args(yes=True, allow_fleet_update=True)


def rollback_args(index=0):
    return Args(index=index, yes=True)
