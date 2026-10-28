#!/usr/bin/env python3
"""Local duplicate of the production MeshCentral server (work package A1).

    python tools/duplicate_server/dupserver.py setup [--bind 127.0.0.1]   # installs + layout A + config + users
    python tools/duplicate_server/dupserver.py start [--layout A|B]
    python tools/duplicate_server/dupserver.py checklist [--layout A|B]
    python tools/duplicate_server/dupserver.py status
    python tools/duplicate_server/dupserver.py stop [--layout A|B|all]
    python tools/duplicate_server/dupserver.py layout-b (--tarball <tgz> | --standin | --stage1) [--bind 127.0.0.1]
    python tools/duplicate_server/dupserver.py reset [--layout A|B|all]
    python tools/duplicate_server/dupserver.py teardown

Everything lives under C:\\mc-dup (MC_DUP_ROOT). No services, no PATH changes, no production access.
See tools/duplicate_server/README.md.
"""
import argparse
import secrets as pysecrets
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dup_common import (  # noqa: E402
    DUP_ROOT, LAYOUTS, MONGO_DATA, NODE_EXE, REPORTS, SECRETS, DupError, create_root, ensure_windows, layout_root,
    log, node_env, read_json, require_root_marker, run, safe_root_for_delete, write_json,
)
import dup_checklist  # noqa: E402
import dup_config  # noqa: E402
import dup_install  # noqa: E402
import dup_layout  # noqa: E402
import dup_mongo  # noqa: E402
import dup_process  # noqa: E402


def selected(layout_arg, default):
    value = layout_arg or default
    return list(LAYOUTS) if value == "all" else [value]


def mc_command(layout, *extra):
    return [NODE_EXE, layout_root(layout) / "node_modules" / "meshcentral" / "meshcentral.js", *extra]


def create_web_admin(layout):
    """A duplicate-only site administrator, used by the checklist to render default3."""
    path = SECRETS / f"web-{layout}.json"
    if path.is_file():
        return read_json(path)
    creds = {"user": "dupadmin", "password": pysecrets.token_urlsafe(18), "email": "dupadmin@dup.localhost"}
    root = layout_root(layout)
    run(mc_command(layout, "--createaccount", creds["user"], "--pass", creds["password"], "--email", creds["email"]),
        cwd=root, env=node_env(), timeout=300, capture=True)
    run(mc_command(layout, "--adminaccount", creds["user"]), cwd=root, env=node_env(), timeout=300, capture=True)
    write_json(path, creds)
    log(f"  created site admin {creds['user']} for layout {layout} (credentials in {path})")
    return creds


def configure_layout(layout, bind, profile=None):
    """bind is the address MeshCentral listens on (portBind, mpsPortBind). mongod stays on 127.0.0.1.
    profile picks which layout's production config values apply (B-stage1 uses A's)."""
    dup_config.validate_bind(bind)
    dup_mongo.start()
    dup_mongo.initialize_users()
    dup_config.write_config(layout, dup_mongo.connection_uri(layout), bind, profile)
    create_web_admin(layout)


def cmd_setup(args):
    ensure_windows()
    dup_config.validate_bind(args.bind)
    create_root()
    installs = [dup_install.install_node(), dup_install.install_mongo()]
    write_json(REPORTS / "installs.json", installs)
    for item in installs:
        log(f"  {item['name']} {item['version']} sha256 {item['sha256']} (checked against {item['checksum_source']})")
    dup_config.build_denylist()
    dup_layout.build_layout_a()
    configure_layout("A", args.bind)
    log("setup complete: run `start` then `checklist`")


def cmd_layout_b(args):
    require_root_marker()
    dup_config.validate_bind(args.bind)
    if args.stage1:
        dup_layout.build_layout_b(stage1=True)
        configure_layout("B", args.bind, profile="A")
    else:
        dup_layout.build_layout_b(dup_layout.upstream_tarball() if args.standin else Path(args.tarball))
        configure_layout("B", args.bind)
    log("layout B ready: run `start --layout B` then `checklist --layout B`")


def is_running(layout):
    return bool(dup_process.processes_for(layout_root(layout)))


def cmd_start(args):
    require_root_marker()
    for layout in selected(args.layout, "A"):
        root = layout_root(layout)
        if not (root / "meshcentral-data" / "config.json").is_file():
            raise DupError(f"layout {layout} is not configured; run setup (A) or layout-b (B)")
        if is_running(layout):
            log(f"  layout {layout} already running")
            continue
        dup_mongo.start()
        port = LAYOUTS[layout]["port"]
        host = dup_config.configured_bind(layout)
        dup_process.assert_port_free(port, f"layout {layout}", host)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log_path = root / "logs" / f"meshcentral-{stamp}.log"
        # The production systemd drop-in: NODE_OPTIONS=--require /opt/meshcentral/bin/harden-image-size.js
        env = node_env({"NODE_OPTIONS": "--require " + str(root / "bin" / "harden-image-size.js")})
        pid = dup_process.spawn(f"meshcentral-{layout}", mc_command(layout), cwd=root, env=env, log_path=log_path)
        dup_process.wait_for_port(port, 300, alive=lambda: dup_process.pid_alive(pid), what=f"layout {layout}", host=host)
        write_json(REPORTS / f"start-{layout}.json", {"pid": pid, "log": str(log_path), "port": port, "bind": host,
                                                      "started": datetime.now(timezone.utc).isoformat()})
        log(f"  layout {layout} pid {pid} on https://{host}:{port} ({LAYOUTS[layout]['cert']}); log {log_path}")


def stop_layout(layout):
    procs = dup_process.processes_for(layout_root(layout))
    if not procs:
        log(f"  layout {layout} not running")
        return
    pids = {p["ProcessId"] for p in procs}
    for proc in procs:
        if proc["ParentProcessId"] not in pids:  # top of this layout's tree (MeshCentral re-launches itself)
            dup_process.kill_tree(proc["ProcessId"])
    dup_process.wait_gone(layout_root(layout), 60, f"layout {layout}")
    dup_process.clear_pidfile(f"meshcentral-{layout}")
    log(f"  layout {layout} stopped")


def cmd_stop(args):
    require_root_marker()
    for layout in selected(args.layout, "all"):
        stop_layout(layout)
    if (args.layout or "all") == "all":
        dup_mongo.stop()


def cmd_status(args):
    require_root_marker()
    status = {"root": str(DUP_ROOT), "mongod": {"running": dup_mongo.running(), "port": 27018}}
    if status["mongod"]["running"]:
        status["mongod"]["ping"] = dup_mongo.ping()
    for layout, cfg in LAYOUTS.items():
        root = layout_root(layout)
        procs = dup_process.processes_for(root)
        configured = (root / "meshcentral-data" / "config.json").is_file()
        host = dup_config.configured_bind(layout) if configured else None
        status[layout] = {"configured": configured, "running": bool(procs), "pids": [p["ProcessId"] for p in procs],
                          "bind": host, "port": cfg["port"],
                          "listening": dup_process.port_open(cfg["port"], host) if host else False}
    print(__import__("json").dumps(status, indent=2))


def cmd_checklist(args):
    require_root_marker()
    for layout in selected(args.layout, "A"):
        if not is_running(layout):
            raise DupError(f"layout {layout} is not running; start it first")
        report = dup_checklist.run_checklist(layout, args.label)
        counts = {}
        for item in report["results"]:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        log(f"layout {layout}: {counts}")


def cmd_reset(args):
    """Drop the duplicate databases and delete the layout trees (data dirs, certs, config). Keep tools,
    downloads, mongod and its users. Rebuild with setup (A) or layout-b (B)."""
    require_root_marker()
    layouts = selected(args.layout, "all")
    for layout in layouts:
        stop_layout(layout)
    dup_mongo.start()
    for layout in layouts:
        dup_mongo.drop_database(layout)
        root = layout_root(layout)
        if root.exists():
            shutil.rmtree(root)
            log(f"  deleted {root}")
        for name in (f"web-{layout}.json",):
            if (SECRETS / name).exists():
                (SECRETS / name).unlink()
        for report in REPORTS.glob(f"*-{layout}*.json") if REPORTS.exists() else []:
            report.unlink()
    log("reset complete")


def cmd_teardown(args):
    root = safe_root_for_delete()
    for layout in LAYOUTS:
        stop_layout(layout)
    dup_mongo.stop()
    leftovers = dup_process.runtime_root_processes()
    if leftovers:
        raise DupError(f"processes still use {root}: {[p['ProcessId'] for p in leftovers]}")
    shutil.rmtree(root)
    log(f"teardown complete: {root} removed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    bind_help = "address MeshCentral listens on: 127.0.0.1 (default) or a host-only/private address for the VM"
    sub.add_parser("setup").add_argument("--bind", default="127.0.0.1", help=bind_help)
    b = sub.add_parser("layout-b")
    b.add_argument("--bind", default="127.0.0.1", help=bind_help)
    group = b.add_mutually_exclusive_group(required=True)
    group.add_argument("--tarball")
    group.add_argument("--standin", action="store_true", help="use the pinned stock `npm pack meshcentral@1.2.5`")
    group.add_argument("--stage1", action="store_true",
                       help="B-stage1: the wrapper's fork tarball plus layout A's data and web folders and A's config")
    for name in ("start", "stop", "checklist", "reset"):
        p = sub.add_parser(name)
        p.add_argument("--layout", choices=list(LAYOUTS) + ["all"])
        if name == "checklist":
            p.add_argument("--label")
    sub.add_parser("status")
    sub.add_parser("teardown")
    args = parser.parse_args(argv)
    handler = {"setup": cmd_setup, "layout-b": cmd_layout_b, "start": cmd_start, "stop": cmd_stop,
               "status": cmd_status, "checklist": cmd_checklist, "reset": cmd_reset, "teardown": cmd_teardown}[args.command]
    try:
        handler(args)
    except DupError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
