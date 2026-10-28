"""plan-v2-full.md section 5 checklist (as amended by SSOT section 5), automated where no agent is needed.

Layout A is production until the Stage 4 cutover and is compared with the production inventory; layout B
is the fork at MeshCentral 1.3.1 and is compared with its own locked tarball and agent pins.

Every result is PASS, FAIL, INFO or PENDING-VM. Nothing here talks to production; production values
come from the read-only inventory (evidence/live/hashes.tsv, summary.txt) and plan section 2.6.
"""
import base64
import http.client
import json
import os
import re
import ssl
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from dup_common import (
    LAYOUTS, REPORTS, SECRETS, TOOL_DIR, DupError, layout_node, layout_root, log, node_env, read_json, write_json,
)
import dup_config
import dup_layout

LANGUAGES = ("en", "de", "fr")
PENDING_VM = [
    ("3", "Agent online with the expected core hash"),
    ("4", "Desktop and KVM via test/run_umh_playwright.js (desktop and mobile; no input on Connect), plus the coupling contracts"),
    ("5", "Terminal: command, resize, disconnect"),
    ("6", "File transfer, small and over 50 MB, with hashes compared"),
    ("7c", "An agent receives a changed data-dir module; parity contract against the delivered core"),
    ("8", "Agent update (Windows two-phase), then rollback"),
    ("9", "Recording and playback"),
    ("10b", "nativeruntime Activate and Unload; native file actions (open, delete, Run, Run privileged); desktop audio plays"),
]


class Results:
    def __init__(self, layout):
        self.layout = layout
        self.items = []

    def add(self, item, title, status, detail=None):
        if status not in ("PASS", "FAIL", "INFO", "PENDING-VM"):
            raise DupError(f"bad status {status}")
        self.items.append({"item": item, "title": title, "status": status, "detail": detail})
        log(f"  [{status}] {item} {title}" + (f": {detail}" if isinstance(detail, str) else ""))


# --------------------------------------------------------------------------- TLS/HTTP against the layout

def tls_context(layout):
    root_cert = layout_root(layout) / "meshcentral-data" / "root-cert-public.crt"
    if not root_cert.is_file():
        raise DupError(f"{root_cert} missing; start the layout first")
    context = ssl.create_default_context(cafile=str(root_cert))
    # The certificate is checked against the layout's own root and its name is checked below, because
    # the connection goes to the bind address while the certificate names the *.localhost host.
    context.check_hostname = False
    # MeshCentral's generated certificates carry no Authority Key Identifier, which Python 3.13+ rejects
    # under VERIFY_X509_STRICT. The chain is still verified against the layout's own root.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def check_peer_name(sock, expected):
    cert = sock.getpeercert()
    names = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    names += [value for field in cert.get("subject", ()) for key, value in field if key == "commonName"]
    if expected not in names:
        raise DupError(f"server certificate names {names}, expected {expected}")


def connection(layout):
    port = LAYOUTS[layout]["port"]
    host = dup_config.configured_bind(layout)
    conn = http.client.HTTPSConnection(host, port, context=tls_context(layout), timeout=60)
    conn.connect()
    check_peer_name(conn.sock, LAYOUTS[layout]["cert"])
    return conn


def request(layout, method, path, body=None, headers=None, cookies=None):
    conn = connection(layout)
    headers = dict(headers or {})
    headers["Host"] = f"{LAYOUTS[layout]['cert']}:{LAYOUTS[layout]['port']}"
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    set_cookies = response.headers.get_all("Set-Cookie") or []
    conn.close()
    return response.status, data, set_cookies


def merge_cookies(jar, set_cookies):
    for header in set_cookies:
        name, _, rest = header.partition("=")
        jar[name.strip()] = rest.split(";", 1)[0]


def websocket_upgrade_status(layout, path):
    conn = connection(layout)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request_text = (f"GET {path} HTTP/1.1\r\nHost: {LAYOUTS[layout]['cert']}:{LAYOUTS[layout]['port']}\r\n"
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    conn.sock.sendall(request_text.encode("ascii"))
    status_line = conn.sock.recv(4096).split(b"\r\n", 1)[0].decode("latin-1")
    conn.close()
    match = re.match(r"HTTP/1\.1 (\d{3})", status_line)
    if not match:
        raise DupError(f"unexpected upgrade response: {status_line!r}")
    return int(match.group(1)), status_line


def login(layout):
    creds = read_json(SECRETS / f"web-{layout}.json")
    jar = {}
    status, _, cookies = request(layout, "GET", "/")
    merge_cookies(jar, cookies)
    body = urllib.parse.urlencode({"action": "login", "username": creds["user"], "password": creds["password"]})
    status, data, cookies = request(layout, "POST", "/login", body=body,
                                    headers={"Content-Type": "application/x-www-form-urlencoded"}, cookies=jar)
    merge_cookies(jar, cookies)
    if status not in (200, 302):
        raise DupError(f"login returned HTTP {status}")
    return jar


# --------------------------------------------------------------------------- view fingerprinting

HBS_EXPR = re.compile(r"\{\{\{?[^{}]*\}?\}\}")


def chunks(text):
    return {piece.strip() for piece in HBS_EXPR.split(text) if len(piece.strip()) >= 40}


def view_candidates(root, minify, lang):
    """Every file getRenderPage/render could pick for default3 (webserver.js getRenderPage, render)."""
    dirs = {"override": root / "meshcentral-web" / "views", "package": root / "node_modules" / "meshcentral" / "views"}
    names = ["default3-min", "default3"] if minify else ["default3"]
    found = {}
    for origin, directory in dirs.items():
        for name in names:
            options = [directory / f"{name}.handlebars"]
            if lang != "en":
                options.insert(0, directory / "translations" / f"{name}_{lang}.handlebars")
            for option in options:
                if option.is_file():
                    found[option.relative_to(root).as_posix()] = option
    return found


def identify_view(html, candidates, sample=300):
    # Decode the bytes as they are: the served page keeps the template's CRLF or LF line endings.
    texts = {name: chunks(path.read_bytes().decode("utf-8", errors="replace")) for name, path in candidates.items()}
    scores = {}
    for name, own in texts.items():
        others = set().union(*(texts[o] for o in texts if o != name)) if len(texts) > 1 else set()
        unique = sorted(own - others, key=lambda c: (-len(c), c))[:sample]
        if not unique:
            scores[name] = None
            continue
        scores[name] = sum(1 for c in unique if c in html) / len(unique)
    ranked = sorted((s, n) for n, s in scores.items() if s is not None)
    if not ranked:
        return None, scores
    best_score, best = ranked[-1]
    runner_up = ranked[-2][0] if len(ranked) > 1 else 0.0
    if best_score >= 0.9 and runner_up < 0.5:
        return best, scores
    return None, scores


def production_view_paths():
    return {p for p in dup_layout.load_production_hashes() if p.startswith("meshcentral-web/views/")}


def expected_production_view(minify, lang):
    """Per plan 2.3/2.6: the override wins per file and language, and a non-min override beats the package -min."""
    present = production_view_paths()
    order = []
    names = ["default3-min", "default3"] if minify else ["default3"]
    for name in names:
        if lang != "en":
            order.append(f"meshcentral-web/views/translations/{name}_{lang}.handlebars")
        order.append(f"meshcentral-web/views/{name}.handlebars")
    for candidate in order:
        if candidate in present:
            return candidate
    return "node_modules/meshcentral/views (package)"


def package_view(minify, lang):
    """The package file webserver.js getRenderPage/render pick when no override exists."""
    name = "default3-min" if minify else "default3"
    if lang != "en":
        return f"node_modules/meshcentral/views/translations/{name}_{lang}.handlebars"
    return f"node_modules/meshcentral/views/{name}.handlebars"


# --------------------------------------------------------------------------- checklist

def latest_start_log(layout):
    record = read_json(REPORTS / f"start-{layout}.json")
    return Path(record["log"]), record


def run_probe(layout):
    runtime = layout_node(layout)
    result = subprocess.run([str(runtime.exe), str(TOOL_DIR / "probe_meshcentral.js"), str(layout_root(layout))],
                            capture_output=True, text=True, env=node_env(runtime), timeout=300)
    if result.returncode != 0:
        raise DupError("probe failed: " + (result.stderr or result.stdout)[-4000:])
    return json.loads(result.stdout[result.stdout.index("{"):])


def production_data_modules():
    """Module name -> mtime epoch for production's meshcentral-data/modules_meshcore (minifycore false)."""
    modules = {}
    for path, row in dup_layout.load_production_hashes().items():
        if path.startswith("meshcentral-data/modules_meshcore/") and path.endswith(".js"):
            modules[path.rsplit("/", 1)[1][:-3]] = row["mtime_epoch"]
    return modules


def version_epoch(version):
    return int(datetime.fromisoformat(version.replace("Z", "+00:00")).timestamp())


def iso_millis(mtime_ns):
    """What fs.statSync(path).mtime.toISOString() gives for an mtime in Node 20: the Date is built from
    mtimeMs rounded to the nearest millisecond (seen on the pinned Node: mtimeMs 1792956226985.945 gives
    .986Z), the same on production's Linux Node 20.20.2."""
    millis = (mtime_ns + 500_000) // 1_000_000
    seconds = datetime.fromtimestamp(millis // 1000, tz=timezone.utc)
    return seconds.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis % 1000:03d}Z"


def compare_versions_to_capture(probe, timestamps=None):
    """Every module version in every served core must equal the capture's mtime for the file served.

    The versioned loader picks <name>.js from modules_meshcore when minifycore is false (deploy.py
    version_meshcentral_module_loader), which is production's setting."""
    timestamps = timestamps if timestamps is not None else dup_layout.module_timestamps()
    if probe["args"]["minifycore"] is not False:
        return "FAIL", [f"minifycore is {probe['args']['minifycore']!r}; production serves modules_meshcore (false)"]
    problems, checked = [], 0
    for core_name, core in sorted(probe["cores"].items()):
        for module in core["modules"]:
            if module["kind"] != "js":
                continue
            path = f"meshcentral-data/modules_meshcore/{module['name']}.js"
            if path not in timestamps:
                problems.append(f"{core_name}/{module['name']}: {path} is not in the module capture")
                continue
            expected = iso_millis(timestamps[path])
            checked += 1
            if module["version"] != expected:
                problems.append(f"{core_name}/{module['name']}: served {module['version']}, capture {expected}")
    if checked == 0:
        problems.append("no module versions were compared")
    return ("PASS" if not problems else "FAIL"), (problems or f"{checked} module entries match")


def compare_versions_to_release_manifest(probe, manifest):
    """Every module version in every served core must equal the release manifest's entry for the
    file served (agents/module-versions.json in the package; minifycore false serves modules_meshcore)."""
    if probe["args"]["minifycore"] is not False:
        return "FAIL", [f"minifycore is {probe['args']['minifycore']!r}; production serves modules_meshcore (false)"]
    versions = manifest.get("modules") or {}
    problems, checked = [], 0
    for core_name, core in sorted(probe["cores"].items()):
        for module in core["modules"]:
            if module["kind"] != "js":
                continue
            key = f"modules_meshcore/{module['name']}.js"
            checked += 1
            if versions.get(key) is None:
                problems.append(f"{core_name}/{module['name']}: {key} is not in the release manifest")
            elif module["version"] != versions[key]:
                problems.append(f"{core_name}/{module['name']}: served {module['version']}, release manifest {versions[key]}")
    if checked == 0:
        problems.append("no module versions were compared")
    detail = problems or f"{checked} module entries match release {manifest.get('date')} (commit {manifest.get('commit')})"
    return ("PASS" if not problems else "FAIL"), detail


def check_image_size_preload(layout, start_record, log_text):
    """2c. Layout A: production's preload ran and proved the parsers disabled (the tracked shim prints the
    line only after probing each one, and stops the server otherwise). Layout B: no preload at all."""
    harden = [l for l in log_text.splitlines() if l.startswith("harden-image-size:")]
    if layout == "A":
        ok = bool(start_record.get("preload")) and any("disabled unpatched parsers: icns, jxl, jxl-stream, heif" in l for l in harden)
        return ("harden-image-size preload took effect (production's systemd drop-in)", "PASS" if ok else "FAIL",
                {"preload": start_record.get("preload"), "log": harden})
    ok = start_record.get("preload") is None and not harden
    return ("no image-size preload (the fork retires it with image-size, D4/DEP-21)", "PASS" if ok else "FAIL",
            {"preload": start_record.get("preload"), "log": harden})


def check_self_update(probe, log_text):
    """2f. D6 needs all three: selfUpdate false, the daemon marker in the package, myServer.upgrade false."""
    selfupdate_lines = [l for l in log_text.splitlines() if re.search(r"self.?update|Checking for update|npm view meshcentral", l, re.I)]
    state = probe.get("selfUpdate") or {}
    myserver = state.get("myserver")
    problems = []
    if probe["args"]["selfupdate"] is not False:
        problems.append(f"settings.selfUpdate is {probe['args']['selfupdate']!r}")
    if state.get("daemonMarker") is not True:
        problems.append("node_modules/meshcentral/daemon is missing, so the server may rewrite itself")
    if not isinstance(myserver, dict) or myserver.get("upgrade") is not False:
        problems.append(f"domains[''].myServer.upgrade is not false ({myserver!r})")
    if selfupdate_lines:
        problems.append("the log mentions an update check")
    return "PASS" if not problems else "FAIL", {"args.selfupdate": probe["args"]["selfupdate"], "daemon": state.get("daemonMarker"),
                                                 "myServer": myserver, "log": selfupdate_lines, "problems": problems}


BACKUP_ERRORS = re.compile(r"Unable to perform MongoDB backup|Backup failed|Zipbackup failed|Zip error|Mongodump error|fs\.promises\.glob")


def server_console(layout, command, timeout=300):
    """One "My Server" console command as the duplicate's site admin (server_console.js); returns its replies."""
    runtime = layout_node(layout)
    result = subprocess.run([str(runtime.exe), str(TOOL_DIR / "server_console.js"), str(layout_root(layout)),
                             dup_config.configured_bind(layout), str(LAYOUTS[layout]["port"]), LAYOUTS[layout]["cert"],
                             str(SECRETS / f"web-{layout}.json"), command, str(timeout)],
                            capture_output=True, text=True, env=node_env(runtime), timeout=timeout + 60)
    if result.returncode != 0:
        raise DupError(f"server console {command!r} on layout {layout} failed: {(result.stderr or result.stdout)[-2000:]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def check_autobackup(layout, start_record):
    """2g. MeshCentral runs autobackup from its hourly maintenance tick, so the check asks for one through
    the server's own console command ("autobackup"), which calls the same db.performBackup: mongodump into an
    archive, then a zip of the data folder that takes the archive in. The new zip must hold the archive and
    neither the replies nor the log may report a backup error."""
    import time
    import zipfile
    config = read_json(layout_root(layout) / "meshcentral-data" / "config.json")
    backup_dir = Path(config["settings"]["autobackup"]["backuppath"])
    log_path = Path(start_record["log"])
    before = time.time() - 2
    console = server_console(layout, "autobackup")
    errors = [l for l in log_path.read_text(encoding="utf-8", errors="replace").splitlines() if BACKUP_ERRORS.search(l)]
    errors += [str(r) for r in console["replies"] if BACKUP_ERRORS.search(str(r))]
    zips = sorted(p for p in backup_dir.glob("*.zip") if p.stat().st_mtime >= before) if backup_dir.is_dir() else []
    detail = {"backuppath": str(backup_dir), "mongodumppath": config["settings"]["autobackup"].get("mongodumppath"),
              "console": console, "errors": errors, "zips": [p.name for p in zips],
              "left_archives": [p.name for p in backup_dir.glob("*.archive")] if backup_dir.is_dir() else []}
    if errors or not zips:
        return "FAIL", detail
    try:
        with zipfile.ZipFile(zips[-1]) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile as error:
        detail["zip_error"] = str(error)
        return "FAIL", detail
    dumps = [n for n in names if n.endswith(".archive")]
    detail.update({"entries": len(names), "mongodump_archives": dumps, "bytes": zips[-1].stat().st_size})
    return ("PASS" if dumps else "FAIL"), detail


def check_fork_agents(root, probe):
    """bin (layout B): arch 3/4/43 are served from the package, unsigned, and equal their pins (size and SHA384)."""
    pins = dup_layout.parse_agent_pins(read_json(root / "node_modules" / "meshcentral" / "agents" / "agent-defaults.json"))
    defaults = probe.get("agentDefaults") or {}
    problems = list(defaults.get("errors") or [])
    if not defaults:
        problems.append("the probe found no agentbuilds.js; this is not the fork 1.3.1 package")
    binaries = {}
    for archid in ("3", "4", "43"):
        info = (probe.get("agentBinaries") or {}).get(archid) or {}
        name = info.get("localname")
        binaries[archid] = {k: info.get(k) for k in ("localname", "relativePath", "size", "sha384", "unsigned")}
        if name not in pins:
            problems.append(f"arch {archid}: {name} is not pinned in agents/agent-defaults.json")
            continue
        if info.get("relativePath") != f"node_modules/meshcentral/agents/{name}":
            problems.append(f"arch {archid}: served from {info.get('relativePath')}, not the package's pinned file")
        if (info.get("size"), info.get("sha384")) != pins[name]:
            problems.append(f"arch {archid}: {info.get('size')} bytes SHA384 {info.get('sha384')}, pinned {pins[name][0]} {pins[name][1]}")
        if info.get("unsigned") is not True:
            problems.append(f"arch {archid}: not served unsigned (D12)")
    return "PASS" if not problems else "FAIL", {"binaries": binaries, "build": defaults.get("build"),
                                                 "pinned": {k: {"size": v[0], "sha384": v[1]} for k, v in pins.items()},
                                                 "problems": problems}


def run_checklist(layout, label=None):
    results = Results(layout)
    root = layout_root(layout)
    variant = dup_layout.layout_variant(layout)
    production = variant == "A"
    label = label or ("production-today" if production else "fork-1.3.1")
    log_path, start_record = latest_start_log(layout)
    log_text = log_path.read_text(encoding="utf-8", errors="replace")

    # 0. Runtime per layout (SSOT 5: Node versions per layout).
    expected_node = layout_node(layout).version
    results.add("0", f"runs on the layout's pinned Node {expected_node}",
                "PASS" if start_record.get("node") == expected_node else "FAIL", start_record.get("node"))

    # 1. Tree and sha256 manifest equality.
    built = read_json(REPORTS / f"layout-{layout}-build.json")
    now_manifest = dup_layout.write_manifest(layout, "checklist")
    before = {r["path"]: r["sha256"] for r in read_json(built["manifest"])["files"] if r["path"].startswith("node_modules/")}
    after = {r["path"]: r["sha256"] for r in read_json(now_manifest)["files"] if r["path"].startswith("node_modules/")}
    drift = sorted(set(before.items()) ^ set(after.items()))
    results.add("1a", "node_modules unchanged since setup (no runtime install)", "PASS" if not drift else "FAIL",
                {"files": len(after), "drift": [p for p, _ in drift][:50]})
    for name in ("package.json", "package-lock.json"):
        current = dup_layout.sha256_file(root / name)
        results.add("1b", f"{name} unchanged since setup", "PASS" if current == built["wrapper"][name] else "FAIL", current)
    if production:
        comparison = dup_layout.compare_with_production(now_manifest)
        results.add("1c", "tree vs production inventory (hashes.tsv)", "INFO",
                    {"summary": comparison["summary"], "content_differs": comparison["content_differs"],
                     "production_only": comparison["production_only"], "duplicate_only": comparison["duplicate_only"],
                     "mtime_differs": comparison["mtime_differs"]})
    else:
        tgz = Path(built["tarball"])
        try:
            equal = dup_layout.verify_package_equals_tarball(root, tgz, allowed_extra=(dup_layout.DAEMON_MARKER,))
            status = "PASS"
        except DupError as error:
            equal, status = str(error), "FAIL"
        results.add("1c", "node_modules/meshcentral equals the locked fork tarball (plus the D6 daemon marker)", status,
                    {"tarball": built["tarball"], "integrity": built["wrapper"]["wrapper_tarball"]["integrity"],
                     "locked": built["wrapper"]["wrapper_tarball"]["locked_integrity"], "result": equal})
        left = [relative for relative in dup_layout.FORK_ABSENT if (root / relative).exists()]
        results.add("1d", "no data-dir cores, agent folders, agentbuilds/, view overrides or bin/ after start",
                    "PASS" if not left else "FAIL", left or list(dup_layout.FORK_ABSENT))

    # 2. Clean start.
    install_lines = [l for l in log_text.splitlines() if "Installing modules" in l or "npm install" in l.lower()]
    results.add("2a", "no runtime npm install (InstallModules output)", "PASS" if not install_lines else "FAIL", install_lines)
    error_lines = [l for l in log_text.splitlines()
                   if re.search(r"\bERROR\b|Unhandled|TypeError|ReferenceError|^\s+at .+\(.+:\d+:\d+\)", l)]
    warning_lines = [l for l in log_text.splitlines() if "WARNING" in l and not l.startswith("harden-image-size:")]
    results.add("2b", "clean start (no errors or stack traces in this start's log)", "PASS" if not error_lines else "FAIL",
                {"log": str(log_path), "lines": error_lines[:40], "warnings": warning_lines[:40]})
    title, status, detail = check_image_size_preload(layout, start_record, log_text)
    results.add("2c", title, status, detail)

    status, body, _ = request(layout, "GET", "/")
    results.add("2d", "GET / returns 200", "PASS" if status == 200 else "FAIL", f"HTTP {status}, {len(body)} bytes")
    code, line = websocket_upgrade_status(layout, "/agent.ashx")
    results.add("2e", "agent.ashx upgrades with 101", "PASS" if code == 101 else "FAIL", line)

    probe = run_probe(layout)
    write_json(REPORTS / f"probe-{layout}.json", probe)
    status, detail = check_self_update(probe, log_text)
    results.add("2f", "self-update off: selfUpdate false, daemon marker, myServer.upgrade false (D6)", status, detail)
    status, detail = check_autobackup(layout, start_record)
    results.add("2g", "autobackup (server console autobackup = db.performBackup): mongodump archive in a new zip, no backup error", status, detail)
    plugin_errors = [l for l in log_text.splitlines() if "Error loading plugin" in l]
    loaded = "nativeruntime" in probe["plugins"]["loaded"]
    results.add("10a", "nativeruntime loaded", "PASS" if loaded and not plugin_errors else "FAIL",
                {"loaded": probe["plugins"]["loaded"], "pluginPath": probe["plugins"]["pluginPath"], "log": plugin_errors})

    # 7. Served core composition (Windows core = meshAgentsArchitectureNumbers[4].core).
    windows_core = (probe.get("agentBinaries") or {}).get("4", {}).get("core") or "windows-amt"
    core = probe["cores"][windows_core]
    names = [m["name"] for m in core["modules"]]
    composition = {"core": windows_core, "source": probe["coreSource"], "bytes": core["bytes"], "sha384": core["sha384"],
                   "coreTextSha256": core["coreTextSha256"],
                   "modules": [{"name": m["name"], "version": m["version"]} for m in core["modules"]]}
    results.add("7a", f"served {windows_core} core composition", "INFO", composition)
    if production:
        expected = production_data_modules()
        windows_expected = {n: e for n, e in expected.items() if not n.startswith("linux-")}
        problems = []
        if probe["coreSource"] != str(root / "meshcentral-data"):
            problems.append(f"core source {probe['coreSource']} is not the data dir")
        if sorted(names) != sorted(windows_expected):
            problems.append(f"modules {sorted(names)} != production data-dir modules {sorted(windows_expected)}")
        for module in core["modules"]:
            if module["name"] in windows_expected:
                if module["version"] is None or version_epoch(module["version"]) != windows_expected[module["name"]]:
                    problems.append(f"{module['name']} version {module['version']} != production mtime {windows_expected[module['name']]}")
        for required in ("win-dispatcher",):
            if required not in names:
                problems.append(f"{required} missing")
        for absent in ("sysinfo", "win-info"):
            if absent in names:
                problems.append(f"{absent} present")
        prod_core = dup_layout.load_production_hashes()["meshcentral-data/meshcore.js"]["sha256"]
        if core["coreTextSha256"] != prod_core:
            problems.append(f"core text sha256 {core['coreTextSha256']} != production meshcore.js {prod_core}")
        results.add("7b", "Windows core = production (data-dir modules and versions, win-dispatcher present, sysinfo/win-info absent, meshcore.js text)",
                    "PASS" if not problems else "FAIL", problems or "matches production 2.6")
        status, detail = compare_versions_to_capture(probe)
        results.add("7d", "served module versions = posix capture mtimes, to the millisecond", status, detail)
    else:
        package_agents = root / "node_modules" / "meshcentral" / "agents"
        problems = []
        if probe["coreSource"] != str(package_agents):
            problems.append(f"core source {probe['coreSource']} is not the package agents/ (shadow core in the data dir?)")
        package_core = dup_layout.sha256_file(package_agents / "meshcore.js")
        results.add("7b", "Windows core comes from the package (no data-dir shadow core, D18)", "PASS" if not problems else "FAIL",
                    problems or {"source": probe["coreSource"], "package meshcore.js sha256": package_core,
                                 "win-dispatcher": "win-dispatcher" in names, "sysinfo": "sysinfo" in names, "win-info": "win-info" in names})
        manifest = read_json(package_agents / "module-versions.json")
        status, detail = compare_versions_to_release_manifest(probe, manifest)
        results.add("7d", "served module versions = release manifest (agents/module-versions.json)", status, detail)

    # Agent binaries for architectures 3, 4, 43 as MeshCentral selects them.
    if production:
        hashes = dup_layout.load_production_hashes()
        binaries, problems = {}, []
        for archid in ("3", "4", "43"):
            info = probe["agentBinaries"].get(archid) or {}
            binaries[archid] = {k: info.get(k) for k in ("localname", "relativePath", "sha256", "size", "unsigned")}
            expected_path = f"meshcentral-data/agents/{info.get('localname')}"
            prod = hashes.get(expected_path)
            binaries[archid]["production"] = {"path": expected_path, "sha256": prod["sha256"] if prod else None}
            if info.get("relativePath") != expected_path:
                problems.append(f"arch {archid}: selected {info.get('relativePath')}, production serves {expected_path}")
            elif prod is None or info.get("sha256") != prod["sha256"]:
                problems.append(f"arch {archid}: sha256 {info.get('sha256')} != production {prod and prod['sha256']}")
        results.add("bin", "agent binaries for arch 3/4/43 = production selection and hash", "PASS" if not problems else "FAIL",
                    {"binaries": binaries, "problems": problems})
    else:
        status, detail = check_fork_agents(root, probe)
        results.add("bin", "agent binaries for arch 3/4/43 = the package's pinned fork builds (size, SHA384), unsigned", status, detail)

    # default3 view selection.
    jar = login(layout)
    views = []
    problems = []
    for minify in (0, 1):
        for lang in LANGUAGES:
            status, body, _ = request(layout, "GET", f"/?sitestyle=3&lang={lang}&minify={minify}", cookies=jar)
            html = body.decode("utf-8", errors="replace")
            candidates = view_candidates(root, bool(minify), lang)
            served, scores = identify_view(html, candidates)
            entry = {"lang": lang, "minify": minify, "http": status, "served": served,
                     "scores": {k: (round(v, 3) if v is not None else None) for k, v in scores.items()}}
            if production:
                entry["production_expected"] = expected_production_view(bool(minify), lang)
                if served != entry["production_expected"]:
                    problems.append(f"lang={lang} minify={minify}: served {served}, production {entry['production_expected']}")
            else:
                # D16: no override is left, so the package's own page (with #8104) must serve.
                entry["expected"] = package_view(bool(minify), lang)
                if served != entry["expected"]:
                    problems.append(f"lang={lang} minify={minify}: served {served}, expected the package view {entry['expected']}")
            if status != 200:
                problems.append(f"lang={lang} minify={minify}: HTTP {status}")
            views.append(entry)
    title = "default3 view selection = production" if production else "default3 view selection = the package page (D16)"
    results.add("views", title, "PASS" if not problems else "FAIL", {"views": views, "problems": problems})

    if not production:
        # D16 web cutover: nothing of the overrides or the r0 canary is left on disk, in the config record
        # or in the served page.
        problems = []
        web = root / "meshcentral-web"
        left = sorted(p.relative_to(root).as_posix() for p in web.rglob("*")
                      if p.is_file() and dup_layout.is_d16_retired(p.relative_to(root).as_posix()))
        if left or (web / "views").exists():
            problems.append(f"retired web files or the views override folder remain: {left[:5]}")
        config_record = read_json(REPORTS / f"config-{layout}-differences.json")
        omitted = [entry["key"] for entry in config_record.get("omitted", [])]
        if "domains[''].customFiles" not in omitted:
            problems.append(f"the config keeps customFiles (omitted: {omitted})")
        status, body, _ = request(layout, "GET", "/?sitestyle=3&lang=en&minify=0", cookies=jar)
        if b"r0-umair-reconnect-canary" in body or b"R0UmairCanary" in body:
            problems.append("the served page still references the r0 canary")
        results.add("d16", "D16 web cutover: no default3 override, r0 canary script or customFiles entry; served page has no canary",
                    "PASS" if not problems else "FAIL", problems or {"customFiles": "omitted", "views_override": "absent"})

    for item, title in PENDING_VM:
        results.add(item, title, "PENDING-VM", "needs the test agent on the throwaway VM")

    report = {"layout": layout, "variant": variant, "label": label, "node": expected_node,
              "created": datetime.now(timezone.utc).isoformat(), "start": start_record, "results": results.items}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORTS / f"checklist-{layout}-{label}-{stamp}.json"
    write_json(path, report)
    write_json(REPORTS / f"checklist-{layout}-latest.json", report)
    failed = [r for r in results.items if r["status"] == "FAIL"]
    log(f"  checklist -> {path} ({len(failed)} FAIL)")
    return report


PIN_FAILURE_LINE = "ERROR: fork agent binaries: "


def run_pin_failure_check(layout, command, timeout=120):
    """The fork server must refuse to serve when a pinned agent binary no longer matches its pin (OD6), and
    start again once the file is restored. One pinned file is changed by one byte (same size, so the SHA384
    check, not the size check, has to catch it) and the server is started exactly as `start` does. The
    serving child must print MeshCentral's own error line and exit before it listens. MeshCentral's
    launcher (meshcentral.js launchChildServer) restarts a child that exits with an error every 5 seconds,
    so the check waits for two such exits, never sees the port open, and then stops the process tree. The
    original bytes are restored and verified against the pin whatever happens."""
    import time
    import dup_process
    root = layout_root(layout)
    agents = root / "node_modules" / "meshcentral" / "agents"
    pins = dup_layout.parse_agent_pins(read_json(agents / "agent-defaults.json"))
    name = sorted(pins)[0]
    target = agents / name
    original = target.read_bytes()
    if (len(original), dup_layout.sha384_file(target)) != pins[name]:
        raise DupError(f"{target} does not match its pin before the check; rebuild layout B")
    port = LAYOUTS[layout]["port"]
    host = dup_config.configured_bind(layout)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = root / "logs" / f"pin-check-{stamp}.log"
    detail = {"file": target.relative_to(root).as_posix(), "change": "last byte inverted (size unchanged)", "log": str(log_path)}
    status = "FAIL"
    try:
        target.write_bytes(original[:-1] + bytes([original[-1] ^ 0xFF]))
        runtime = layout_node(layout)
        pid = dup_process.spawn(f"meshcentral-{layout}-pincheck", command, cwd=root, env=node_env(runtime), log_path=log_path)
        deadline = time.time() + timeout
        listened, errors, restarts = False, [], []
        while time.time() < deadline:
            if dup_process.port_open(port, host):
                listened = True
                break
            text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
            errors = [l for l in text.splitlines() if l.startswith(PIN_FAILURE_LINE)]
            restarts = [l for l in text.splitlines() if "MeshCentral failed with critical error" in l]
            if len(restarts) >= 2 or not dup_process.processes_for(root):
                break
            time.sleep(1)
        for proc in dup_process.processes_for(root):
            if proc["ParentProcessId"] not in {p["ProcessId"] for p in dup_process.processes_for(root)}:
                dup_process.kill_tree(proc["ProcessId"])
        dup_process.wait_gone(root, 60, f"layout {layout} (pin check)")
        dup_process.clear_pidfile(f"meshcentral-{layout}-pincheck")
        detail.update({"pid": pid, "listened": listened, "child_exits_restarted_by_launcher": len(restarts),
                       "error_lines": sorted(set(errors))})
        if not listened and errors and all(name in l and "SHA384" in l for l in errors):
            status = "PASS"
    finally:
        target.write_bytes(original)
        restored = (len(target.read_bytes()), dup_layout.sha384_file(target)) == pins[name]
        detail["restored"] = restored
        if not restored:
            status = "FAIL"
    report = {"layout": layout, "item": "pin", "title": "the fork server exits at start on a changed pinned agent binary (OD6)",
              "status": status, "detail": detail, "created": datetime.now(timezone.utc).isoformat()}
    write_json(REPORTS / f"pin-check-{layout}-{stamp}.json", report)
    write_json(REPORTS / f"pin-check-{layout}-latest.json", report)
    log(f"  [{status}] pin check: {detail}")
    return report
