"""plan-v2-full.md section 5 checklist (as amended by SSOT section 5), automated where no agent is needed.

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
    LAYOUTS, NODE_EXE, REPORTS, SECRETS, TOOL_DIR, DupError, layout_root, log, node_env, read_json, write_json,
)
import dup_config
import dup_layout

LANGUAGES = ("en", "de", "fr")
HARDEN_PENDING = (
    "Expected to fail until work package A4's branch is merged. The duplicate runs the production capture "
    "of bin/harden-image-size.js byte for byte, and that copy requires "
    "'/opt/meshcentral/node_modules/image-size', which cannot resolve on Windows, so the ICNS/JXL/HEIF "
    "parsers stay enabled. A4 fixes path resolution in its tracked copy, tools/deployment/harden-image-size.js. "
    "Once that is merged, dup_layout.install_bin should copy the tracked file; the duplicate does not stub or "
    "bypass the preload.")
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


# --------------------------------------------------------------------------- checklist

def latest_start_log(layout):
    record = read_json(REPORTS / f"start-{layout}.json")
    return Path(record["log"]), record


def run_probe(layout):
    result = subprocess.run([str(NODE_EXE), str(TOOL_DIR / "probe_meshcentral.js"), str(layout_root(layout))],
                            capture_output=True, text=True, env=node_env(), timeout=300)
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
    """What fs.statSync(path).mtime.toISOString() gives for an mtime: milliseconds, truncated."""
    millis = mtime_ns // 1_000_000
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


def run_checklist(layout, label=None):
    results = Results(layout)
    root = layout_root(layout)
    label = label or ("production-today" if layout == "A" else "target")
    log_path, start_record = latest_start_log(layout)
    log_text = log_path.read_text(encoding="utf-8", errors="replace")

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
    if layout == "A":
        comparison = dup_layout.compare_with_production(now_manifest)
        results.add("1c", "tree vs production inventory (hashes.tsv)", "INFO",
                    {"summary": comparison["summary"], "content_differs": comparison["content_differs"],
                     "production_only": comparison["production_only"], "duplicate_only": comparison["duplicate_only"],
                     "mtime_differs": comparison["mtime_differs"]})
    else:
        results.add("1c", "node_modules/meshcentral equals the tarball", "PASS", built["tree_equals_tarball"])

    # 2. Clean start.
    install_lines = [l for l in log_text.splitlines() if "Installing modules" in l or "npm install" in l.lower()]
    results.add("2a", "no runtime npm install (InstallModules output)", "PASS" if not install_lines else "FAIL", install_lines)
    error_lines = [l for l in log_text.splitlines()
                   if re.search(r"\bERROR\b|Unhandled|TypeError|ReferenceError|^\s+at .+\(.+:\d+:\d+\)", l)]
    warning_lines = [l for l in log_text.splitlines() if "WARNING" in l and not l.startswith("harden-image-size:")]
    results.add("2b", "clean start (no errors or stack traces in this start's log)", "PASS" if not error_lines else "FAIL",
                {"log": str(log_path), "lines": error_lines[:40], "warnings": warning_lines[:40]})
    harden = [l for l in log_text.splitlines() if l.startswith("harden-image-size:")]
    hardened = any("disabled unpatched parsers" in l for l in harden)
    detail = {"log": harden}
    if not hardened:
        detail["why"] = (HARDEN_PENDING if harden else "no harden-image-size output in this start's log; the preload did not run")
    results.add("2c", "harden-image-size preload took effect", "PASS" if hardened else "FAIL", detail)

    status, body, _ = request(layout, "GET", "/")
    results.add("2d", "GET / returns 200", "PASS" if status == 200 else "FAIL", f"HTTP {status}, {len(body)} bytes")
    code, line = websocket_upgrade_status(layout, "/agent.ashx")
    results.add("2e", "agent.ashx upgrades with 101", "PASS" if code == 101 else "FAIL", line)

    probe = run_probe(layout)
    write_json(REPORTS / f"probe-{layout}.json", probe)
    selfupdate_lines = [l for l in log_text.splitlines() if re.search(r"self.?update|Checking for update|npm view meshcentral", l, re.I)]
    results.add("2f", "selfUpdate off", "PASS" if probe["args"]["selfupdate"] is False and not selfupdate_lines else "FAIL",
                {"args.selfupdate": probe["args"]["selfupdate"], "log": selfupdate_lines})
    plugin_errors = [l for l in log_text.splitlines() if "Error loading plugin" in l]
    loaded = "nativeruntime" in probe["plugins"]["loaded"]
    results.add("10a", "nativeruntime loaded", "PASS" if loaded and not plugin_errors else "FAIL",
                {"loaded": probe["plugins"]["loaded"], "pluginPath": probe["plugins"]["pluginPath"], "log": plugin_errors})

    # 7. Served core composition (Windows core = meshAgentsArchitectureNumbers[4].core).
    windows_core = probe["agentBinaries"]["4"]["core"] if probe["agentBinaries"].get("4", {}).get("core") else "windows-amt"
    core = probe["cores"][windows_core]
    names = [m["name"] for m in core["modules"]]
    composition = {"core": windows_core, "source": probe["coreSource"], "bytes": core["bytes"], "sha384": core["sha384"],
                   "coreTextSha256": core["coreTextSha256"],
                   "modules": [{"name": m["name"], "version": m["version"]} for m in core["modules"]]}
    results.add("7a", f"served {windows_core} core composition", "INFO", composition)
    if layout == "A":
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
        results.add("7b", "Windows core comes from the package (no data-dir shadow core)",
                    "PASS" if probe["coreSource"] == str(root / "node_modules" / "meshcentral" / "agents") else "FAIL",
                    {"source": probe["coreSource"], "win-dispatcher": "win-dispatcher" in names,
                     "sysinfo": "sysinfo" in names, "win-info": "win-info" in names})

    # Agent binaries for architectures 3, 4, 43 as MeshCentral selects them.
    production = dup_layout.load_production_hashes()
    binaries = {}
    problems = []
    for archid in ("3", "4", "43"):
        info = probe["agentBinaries"].get(archid) or {}
        binaries[archid] = {k: info.get(k) for k in ("localname", "relativePath", "sha256", "size", "unsigned")}
        if layout == "A":
            expected_path = f"meshcentral-data/agents/{info.get('localname')}"
            prod = production.get(expected_path)
            binaries[archid]["production"] = {"path": expected_path, "sha256": prod["sha256"] if prod else None}
            if info.get("relativePath") != expected_path:
                problems.append(f"arch {archid}: selected {info.get('relativePath')}, production serves {expected_path}")
            elif prod is None or info.get("sha256") != prod["sha256"]:
                problems.append(f"arch {archid}: sha256 {info.get('sha256')} != production {prod and prod['sha256']}")
    if layout == "A":
        results.add("bin", "agent binaries for arch 3/4/43 = production selection and hash", "PASS" if not problems else "FAIL",
                    {"binaries": binaries, "problems": problems})
    else:
        results.add("bin", "agent binaries for arch 3/4/43 (selection and hash)", "INFO", binaries)

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
            if layout == "A":
                entry["production_expected"] = expected_production_view(bool(minify), lang)
                if served != entry["production_expected"]:
                    problems.append(f"lang={lang} minify={minify}: served {served}, production {entry['production_expected']}")
            elif served is None:
                problems.append(f"lang={lang} minify={minify}: served file not identified")
            if status != 200:
                problems.append(f"lang={lang} minify={minify}: HTTP {status}")
            views.append(entry)
    title = "default3 view selection = production" if layout == "A" else "default3 view selection"
    results.add("views", title, "PASS" if not problems else "FAIL", {"views": views, "problems": problems})

    for item, title in PENDING_VM:
        results.add(item, title, "PENDING-VM", "needs the test agent on the throwaway VM")

    report = {"layout": layout, "label": label, "created": datetime.now(timezone.utc).isoformat(),
              "start": start_record, "results": results.items}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORTS / f"checklist-{layout}-{label}-{stamp}.json"
    write_json(path, report)
    write_json(REPORTS / f"checklist-{layout}-latest.json", report)
    failed = [r for r in results.items if r["status"] == "FAIL"]
    log(f"  checklist -> {path} ({len(failed)} FAIL)")
    return report
