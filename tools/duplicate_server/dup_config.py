"""config.json generation for the duplicate layouts, and the production-identifier denylist.

config.json = the wrapper's config.json.template, reduced to the key set production actually has
(summary.txt), with production's non-secret values and fresh local values for hosts and secrets.
"""
import ipaddress
import json
import re
import secrets as pysecrets
from datetime import datetime, timezone
from pathlib import Path

from dup_common import (
    DENYLIST_PATH, LAYOUTS, PRODUCTION_SUMMARY, REPORTS, SSOT_ROOT, TOOL_DIR, WORKTREE_ROOT,
    DupError, layout_root, log, read_json, write_json,
)

FLAGS_PATH = TOOL_DIR / "production_flags.json"


# --------------------------------------------------------------------------- production key set

def summary_config_keys(summary_text):
    """Top-level settings and default-domain keys listed in summary.txt's 'config flags' section."""
    lines = summary_text.splitlines()
    try:
        start = lines.index("## config flags")
    except ValueError:
        raise DupError(f"{PRODUCTION_SUMMARY} has no '## config flags' section")
    settings, domain = [], []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        key = line.split(":", 1)[0]
        if key.startswith("settings.") and key.count(".") == 1:
            settings.append(key.split(".", 1)[1])
        elif key.startswith("domains..") and key.count(".") == 2:
            domain.append(key.split(".", 2)[2])
    if not settings or not domain:
        raise DupError("Could not read the production config key list from summary.txt")
    return settings, domain


def load_flags():
    flags = read_json(FLAGS_PATH)
    settings, domain = summary_config_keys(PRODUCTION_SUMMARY.read_text(encoding="utf-8"))
    for section, expected in (("settings", settings), ("domain", domain)):
        listed = list(flags[section])
        if sorted(listed) != sorted(expected):
            raise DupError(f"production_flags.json {section} keys differ from summary.txt: "
                           f"missing {sorted(set(expected) - set(listed))}, extra {sorted(set(listed) - set(expected))}")
        for key, spec in flags[section].items():
            if len({"value", "dup", "omit"} & set(spec)) != 1:
                raise DupError(f"production_flags.json {section}.{key} must have exactly one of value/dup/omit")
    return flags


# --------------------------------------------------------------------------- generation

def template_path():
    from dup_layout import wrapper_repo
    return wrapper_repo() / "meshcentral-data" / "config.json.template"


def dup_value(kind, key, layout, spec, context):
    cfg = LAYOUTS[layout]
    root = layout_root(layout)
    if kind == "port":
        return cfg["port"]
    if kind == "cert":
        return cfg["cert"]
    if kind == "datapath":
        return str(root / "meshcentral-data")
    if kind == "random":
        return pysecrets.token_hex(32)
    if kind == "mongodb":
        return context["mongodb"]
    if kind == "loopback":
        return "127.0.0.1"
    if kind == "false":
        return False
    if kind == "autobackup":
        value = {"backuppath": str(root / "meshcentral-backups")}
        value.update(spec["known"])
        return value
    if kind == "origins":
        return [cfg["cert"], "127.0.0.1"]
    if kind == "title":
        return f"MeshCentral DUP {layout}"
    if kind == "customfiles":
        return spec["assumed"] if layout in spec["layouts"] else None
    raise DupError(f"Unknown dup kind {kind!r} for {key}")


def generate(layout, mongodb_uri):
    """Build the config dict and a record of every key that differs from production."""
    flags = load_flags()
    template = json.loads(template_path().read_text(encoding="utf-8"))
    record = {"template": str(template_path()), "dropped_template_keys": [], "substituted": [], "omitted": [],
              "duplicate_only": []}
    context = {"mongodb": mongodb_uri}

    def build(section_template, section_flags, label):
        result = {}
        production_lower = {key.lower(): key for key in section_flags}
        for key in section_template:
            if key.lower() not in production_lower:
                record["dropped_template_keys"].append(f"{label}.{key}")
        for key, spec in section_flags.items():
            if "value" in spec:
                result[key] = spec["value"]
            elif "omit" in spec:
                record["omitted"].append({"key": f"{label}.{key}", "reason": spec["omit"]})
            else:
                value = dup_value(spec["dup"], key, layout, spec, context)
                if value is None:
                    record["omitted"].append({"key": f"{label}.{key}", "reason": spec["reason"]})
                    continue
                result[key] = value
                entry = {"key": f"{label}.{key}", "reason": spec.get("reason", "")}
                if spec.get("assumed") is not None:
                    entry["assumed_value"] = True
                if spec["dup"] != "random":
                    entry["value"] = value if spec["dup"] != "mongodb" else "<local URI>"
                record["substituted"].append(entry)
        return result

    settings = build(template.get("settings", {}), flags["settings"], "settings")
    domain = build(template.get("domains", {}).get("", {}), flags["domain"], "domains['']")
    settings["mongoDbName"] = LAYOUTS[layout]["db"]
    record["duplicate_only"].append({"key": "settings.mongoDbName", "value": LAYOUTS[layout]["db"],
                                     "reason": flags["duplicate_only_settings"]["mongoDbName"]})
    if LAYOUTS[layout]["mpsport"] is not None:
        settings["mpsPort"] = LAYOUTS[layout]["mpsport"]
        record["duplicate_only"].append({"key": "settings.mpsPort", "value": LAYOUTS[layout]["mpsport"],
                                         "reason": flags["duplicate_only_settings"]["mpsPort"]})
    config = {"settings": settings, "domains": {"": domain}}
    return config, record


def write_config(layout, mongodb_uri):
    config, record = generate(layout, mongodb_uri)
    text = json.dumps(config, indent=2) + "\n"
    hits = scan_text(text, load_denylist())
    if hits:
        raise DupError(f"Generated config for layout {layout} names production identifiers: {hits}")
    target = layout_root(layout) / "meshcentral-data" / "config.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise DupError(f"{target} already exists; reset the layout to regenerate it")
    target.write_text(text, encoding="utf-8")
    record["config"] = str(target)
    record["denylist_hits"] = []
    write_json(REPORTS / f"config-{layout}-differences.json", record)
    log(f"  wrote {target}; denylist clean; differences -> {REPORTS / f'config-{layout}-differences.json'}")
    return target, record


# --------------------------------------------------------------------------- denylist

HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def production_hosts(summary_text):
    """Hostnames production serves: access-log hosts, Caddy site blocks and cloudflared ingress."""
    hosts = set()
    for match in re.finditer(r"\bhost ([a-z0-9.-]+)(?::\d+)?\s+\d+\s*$", summary_text, re.I | re.M):
        hosts.add(match.group(1).lower())
    for match in re.finditer(r"hostname:\s*([a-z0-9.-]+)", summary_text, re.I):
        hosts.add(match.group(1).lower())
    for match in re.finditer(r"^\d+:([a-z0-9.,:\s-]+)\{\s*$", summary_text, re.I | re.M):
        for part in match.group(1).split(","):
            name = part.strip().split(":")[0].lower()
            if "." in name:
                hosts.add(name)
    if not hosts:
        raise DupError("No production hostnames found in evidence/live/*.txt")
    return hosts


def registrable(host):
    return ".".join(host.split(".")[-2:])


def public_ipv4(text):
    found = set()
    for value in IPV4_RE.findall(text):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global:
            found.add(value)
    return found


def parse_msh(data):
    text = data.decode("utf-8", errors="strict").replace("\r\n", "\n")
    values = {}
    for line in text.split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def msh_identifiers(values):
    tokens = {}
    for key in ("ServerID", "MeshID"):
        value = values.get(key, "")
        if value:
            tokens[key] = value.lower().removeprefix("0x")
    server = values.get("MeshServer", "")
    hosts = set()
    for url in server.split(","):
        match = re.match(r"\s*wss?://([^/:]+)", url)
        if match:
            hosts.add(match.group(1).lower())
    return tokens, hosts


def build_denylist():
    """Collect production identifiers from the read-only inventory (evidence/live/*.txt), the MeshAgent docs and the
    production .msh that deploy.py publishes (WinDiagnosticHost.msh). Stored outside the repo."""
    from dup_layout import load_deploy, source_repo
    live_files = sorted(PRODUCTION_SUMMARY.parent.glob("*.txt"))
    summary_text = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in live_files)
    hosts = production_hosts(summary_text)
    domains = {registrable(h) for h in hosts}
    docs_hosts = set()
    for doc in (WORKTREE_ROOT / "docs").rglob("*.md"):
        for host in HOST_RE.findall(doc.read_text(encoding="utf-8", errors="replace")):
            if registrable(host.lower()) in domains:
                docs_hosts.add(host.lower())
    plan = SSOT_ROOT / "plan-v2-full.md"
    ips = public_ipv4(summary_text) | public_ipv4(plan.read_text(encoding="utf-8"))
    deploy = load_deploy()
    msh_source = (source_repo() / deploy.ARTIFACTS["WinDiagnosticHost.msh"]["local_path"]).resolve()
    msh_tokens, msh_hosts = msh_identifiers(parse_msh(msh_source.read_bytes()))
    if "ServerID" not in msh_tokens:
        raise DupError(f"No ServerID in the production manifest {msh_source}")
    denylist = {
        "created": datetime.now(timezone.utc).isoformat(),
        "sources": [str(f) for f in live_files] + [str(WORKTREE_ROOT / "docs"), str(plan), str(msh_source)],
        "hosts": sorted(hosts | docs_hosts | msh_hosts | domains),
        "ips": sorted(ips),
        "server_ids": [msh_tokens["ServerID"]],
        "mesh_ids": [msh_tokens["MeshID"]] if "MeshID" in msh_tokens else [],
    }
    write_json(DENYLIST_PATH, denylist)
    log(f"  denylist: {len(denylist['hosts'])} hosts, {len(denylist['ips'])} IPs, "
        f"{len(denylist['server_ids'])} ServerID, {len(denylist['mesh_ids'])} MeshID -> {DENYLIST_PATH}")
    return denylist


def load_denylist(path=None):
    data = read_json(path or DENYLIST_PATH)
    tokens = data["hosts"] + data["ips"] + data["server_ids"] + data["mesh_ids"]
    if not data["hosts"] or not data["server_ids"]:
        raise DupError("Denylist has no hosts or no ServerID; rebuild it")
    return [t.lower() for t in tokens if t]


def scan_text(text, tokens):
    lowered = text.lower()
    return sorted({token for token in tokens if token in lowered})


def scan_config_file(path, tokens=None):
    tokens = tokens if tokens is not None else load_denylist()
    return scan_text(Path(path).read_text(encoding="utf-8"), tokens)
