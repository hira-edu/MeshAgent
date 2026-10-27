"""mongod as a user process on 127.0.0.1:27018 with auth and freshly generated users."""
import secrets as pysecrets
from urllib.parse import quote

from dup_common import (
    DUP_ROOT, LAYOUTS, MONGO_DATA, MONGO_DIR, MONGO_HOST, MONGO_PORT, MONGOD_EXE, NODE_EXE, SECRETS, TOOL_DIR,
    DupError, log, layout_root, node_env, read_json, run, write_json,
)
import dup_process

SECRETS_FILE = SECRETS / "mongo.json"
INIT_MARKER = SECRETS / "mongo.initialized"


def ensure_secrets():
    if SECRETS_FILE.is_file():
        return read_json(SECRETS_FILE)
    data = {
        "host": MONGO_HOST,
        "port": MONGO_PORT,
        "adminUser": "dupadmin",
        "adminPassword": pysecrets.token_urlsafe(24),
        "appUser": "dupapp",
        "appPassword": pysecrets.token_urlsafe(24),
    }
    write_json(SECRETS_FILE, data)
    return data


def connection_uri(layout):
    data = ensure_secrets()
    db = LAYOUTS[layout]["db"]
    return (f"mongodb://{quote(data['appUser'], safe='')}:{quote(data['appPassword'], safe='')}"
            f"@{MONGO_HOST}:{MONGO_PORT}/{db}?authSource=admin")


def driver_dir():
    """The wrapper's own mongodb driver (4.17.2), from whichever layout is installed."""
    for name in ("A", "B"):
        candidate = layout_root(name) / "node_modules"
        if (candidate / "mongodb" / "package.json").is_file():
            return candidate
    raise DupError("No layout has node_modules/mongodb yet; install layout A first")


def admin(*args, timeout=120, capture=True):
    return run([NODE_EXE, TOOL_DIR / "mongo_admin.js", driver_dir(), SECRETS_FILE, *args],
               env=node_env(), timeout=timeout, capture=capture)


def running():
    return bool(dup_process.processes_for(MONGO_DATA))


def start():
    if running():
        log("  mongod already running")
        return
    if not MONGOD_EXE.is_file():
        raise DupError(f"mongod is not installed at {MONGOD_EXE}; run setup")
    dup_process.assert_port_free(MONGO_PORT, "mongod")
    MONGO_DATA.mkdir(parents=True, exist_ok=True)
    command = [MONGOD_EXE, "--dbpath", MONGO_DATA, "--bind_ip", MONGO_HOST, "--port", str(MONGO_PORT), "--auth",
               "--logpath", MONGO_DIR / "mongod.log", "--logappend"]
    pid = dup_process.spawn("mongod", command, cwd=DUP_ROOT, env=None, log_path=MONGO_DIR / "mongod.stdout.log")
    dup_process.wait_for_port(MONGO_PORT, 60, alive=lambda: dup_process.pid_alive(pid), what="mongod")
    log(f"  mongod pid {pid} listening on {MONGO_HOST}:{MONGO_PORT} (auth on)")


def initialize_users():
    ensure_secrets()
    if INIT_MARKER.is_file():
        return
    result = admin("init", *[cfg["db"] for cfg in LAYOUTS.values()])
    log("  " + result.stdout.strip())
    INIT_MARKER.write_text("users created\n", encoding="utf-8")


def ping():
    return admin("ping").stdout.strip()


def drop_database(layout):
    result = admin("dropdb", LAYOUTS[layout]["db"])
    log("  " + result.stdout.strip())


def stop():
    if not running():
        log("  mongod not running")
        dup_process.clear_pidfile("mongod")
        return
    if not INIT_MARKER.is_file():
        raise DupError("mongod is running but its users were never created; stop it with taskkill after checking why")
    admin("shutdown")
    dup_process.wait_gone(MONGO_DATA, 60, "mongod")
    dup_process.clear_pidfile("mongod")
    log("  mongod stopped cleanly")
