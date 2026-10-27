"""User-level process control for mongod and the MeshCentral layouts (no services)."""
import json
import socket
import subprocess
import time
from pathlib import Path

from dup_common import DUP_ROOT, RUN_DIR, TOOLS, DupError, log, read_json, write_json

CREATE_NEW_PROCESS_GROUP = 0x00000200
DETACHED_PROCESS = 0x00000008
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def list_processes():
    """Return every process whose executable lives under the runtime tools folder."""
    tools_prefix = str(TOOLS.resolve()).lower().replace("'", "''")
    script = (
        "$p = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and "
        f"$_.ExecutablePath.ToLower().StartsWith('{tools_prefix}') }} | "
        "Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine; "
        "ConvertTo-Json -InputObject @($p) -Compress"
    )
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise DupError("Process listing failed: " + result.stderr.strip())
    text = result.stdout.strip()
    if not text:
        return []
    data = json.loads(text)
    return data if isinstance(data, list) else [data]


def processes_for(tag_path):
    """Processes whose command line references tag_path (a layout or the mongo data dir)."""
    needle = str(Path(tag_path).resolve()).lower()
    return [p for p in list_processes() if needle in (p.get("CommandLine") or "").lower()]


def spawn(name, command, cwd, env, log_path):
    """Start a detached user process with stdout/stderr in log_path and record its pid."""
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(log_path, "ab")
    flags = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    try:
        process = subprocess.Popen([str(c) for c in command], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                   stdout=handle, stderr=subprocess.STDOUT, creationflags=flags | CREATE_BREAKAWAY_FROM_JOB,
                                   close_fds=True)
        breakaway = True
    except OSError as error:
        # The caller's job object may forbid breakaway; the process then lives as long as that job.
        log(f"  note: {name} started without job breakaway ({error})")
        process = subprocess.Popen([str(c) for c in command], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                   stdout=handle, stderr=subprocess.STDOUT, creationflags=flags, close_fds=True)
        breakaway = False
    handle.close()
    write_json(RUN_DIR / f"{name}.json", {"pid": process.pid, "command": [str(c) for c in command],
                                           "log": str(log_path), "breakaway": breakaway, "started": time.time()})
    return process.pid


def read_pidfile(name):
    path = RUN_DIR / f"{name}.json"
    return read_json(path) if path.is_file() else None


def clear_pidfile(name):
    path = RUN_DIR / f"{name}.json"
    if path.exists():
        path.unlink()


def port_open(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((host, port)) == 0


def wait_for_port(port, timeout, alive=None, what="process"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_open(port):
            return
        if alive is not None and not alive():
            raise DupError(f"{what} exited before listening on {port}")
        time.sleep(1)
    raise DupError(f"{what} did not listen on 127.0.0.1:{port} within {timeout}s")


def pid_alive(pid):
    return any(p["ProcessId"] == pid for p in list_processes())


def kill_tree(pid):
    """Kill one of our processes and its children; refuse anything outside the tools folder."""
    owned = {p["ProcessId"]: p for p in list_processes()}
    if pid not in owned:
        raise DupError(f"pid {pid} is not a process from {TOOLS}; refusing to kill it")
    result = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True)
    if result.returncode != 0:
        raise DupError(f"taskkill {pid} failed: {result.stdout.strip()} {result.stderr.strip()}")


def wait_gone(tag_path, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not processes_for(tag_path):
            return
        time.sleep(1)
    remaining = [p["ProcessId"] for p in processes_for(tag_path)]
    raise DupError(f"{what} still running after {timeout}s: pids {remaining}")


def assert_port_free(port, what):
    if port_open(port):
        raise DupError(f"Port 127.0.0.1:{port} for {what} is already in use")


def runtime_root_processes():
    root = str(DUP_ROOT.resolve()).lower()
    return [p for p in list_processes() if root in (p.get("CommandLine") or "").lower()
            or (p.get("ExecutablePath") or "").lower().startswith(root)]
