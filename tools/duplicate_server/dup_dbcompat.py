"""D27/D29a database compatibility on the duplicate: MeshCentral 1.2.5 -> the 1.3.1 fork -> 1.2.5 -> 1.3.1,
then the rollback drop list, on a production-sized scratch database (synthetic data only, D8).

Each phase runs dbcompat.js with a layout's own db.js and Node: layout A (stock 1.2.5, Node 20) and
layout B (the fork at 1.3.1, Node 24), on the duplicate's mongod (MongoDB 7.0.31) and the scratch database
meshcentral_dupcompat, which is dropped before and after. The report records per phase the time until the
index set settles, mongod's own index-build lines, the index set, the "Resetting" lines and reads that
every version must answer the same way, then checks the expectations of the s6-c review.
"""
import json
import re
import subprocess
from datetime import datetime, timezone

from dup_common import MONGO_DIR, REPORTS, TOOL_DIR, DupError, layout_node, layout_root, log, node_env, write_json
import dup_mongo

SCRATCH_DB = "meshcentral_dupcompat"

# The index sets each version leaves (names; TTL and collation suffixes as dbcompat.js prints them).
SET_125 = {
    "meshcentral": ["AmtUuid1", "Email1", "Mesh1", "TypeDomainMesh1", "_id_"],
    "events": ["DomainNodeTime1", "ExpireTime1(ttl 1728000)", "IdsAndTime1", "UseridAction1", "_id_"],
    "power": ["ExpireTime1(ttl 864000)", "NodeIdAndTime1", "_id_"],
    "serverstats": ["ExpireTime1(ttl 2592000)", "ExpireTime2(ttl 0)", "_id_"],
}
ADDED_131 = {
    "meshcentral": ["Domain1", "TypeDomainIdNameCollation1(en/2)", "TypeDomainMeshNameCollation1(en/2)", "TypeDomainNode1"],
    "events": ["DomainIdsTime1", "DomainUserActionTime1", "DomainUserTime1"],
    "power": ["Domain1"],
    "plugins": ["TypeAndName1", "_id_"],
}
RESET_LINES = ["Resetting main indexes...", "Resetting events indexes...", "Resetting power events indexes..."]
# Reads every phase must answer identically.
STABLE_READS = ("users", "nodeCount", "nodeDigest", "deviceListPage1", "deviceCount", "meshEventsLimited",
                "userEventsLimited", "nodeEventsLimited", "powerNode3")


def expected_set(with_131, plugins=None):
    """The index set a version leaves. plugins: what is left of 1.3.1's plugins collection under 1.2.5,
    which never touches it (None when the collection does not exist)."""
    result = {k: sorted(v) for k, v in SET_125.items()}
    if with_131:
        for col, names in ADDED_131.items():
            result[col] = sorted(set(result.get(col, [])) | set(names))
    elif plugins is not None:
        result["plugins"] = sorted(plugins)
    return result


# Node prints driver deprecation warnings through console.error; they are reported, not failures.
DRIVER_WARNING = re.compile(r"^ERR \(node:\d+\) \[MONGODB DRIVER\] Warning: ")


def problems_in(logs):
    return [l for l in logs if l.startswith(("UNHANDLED", "ERR")) and not DRIVER_WARNING.match(l)]


def phase_run(name, layout, report_dir, extra):
    runtime = layout_node(layout)
    dbjs = layout_root(layout) / "node_modules" / "meshcentral"
    out = report_dir / f"{name}.json"
    command = [str(runtime.exe), str(TOOL_DIR / "dbcompat.js"), str(dup_mongo.SECRETS_FILE), str(out), str(dbjs), name,
               "--mongolog", str(MONGO_DIR / "mongod.log"), *extra]
    log(f"  phase {name}: layout {layout} db.js on Node {runtime.version}")
    result = subprocess.run(command, capture_output=True, text=True, env=node_env(runtime), timeout=3600)
    if result.returncode != 0:
        raise DupError(f"dbcompat phase {name} failed: {(result.stderr or result.stdout)[-3000:]}")
    data = json.loads(out.read_text(encoding="utf-8"))
    log(f"    {data['version']} settled in {data['indexSettleMs']} ms; reset lines {data['resetLines']}")
    return data


def run(nodes=312, days=20, events_per_day=10000, power_per_day=4000, serverstats_minutes=5):
    for layout in ("A", "B"):
        if not (layout_root(layout) / "node_modules" / "meshcentral" / "db.js").is_file():
            raise DupError(f"layout {layout} is not installed; dbcompat uses its db.js")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = REPORTS / f"dbcompat-{stamp}"
    report_dir.mkdir(parents=True)
    dup_mongo.admin("grant", SCRATCH_DB)
    dup_mongo.admin("dropdb", SCRATCH_DB)
    seed = f"{nodes},{days},{events_per_day},{power_per_day},{serverstats_minutes}"
    phases = {}
    try:
        phases["P0"] = phase_run("P0-seed-1.2.5", "A", report_dir, ["--seed", seed])
        phases["P1"] = phase_run("P1-upgrade-1.3.1", "B", report_dir, ["--filter", "--write131field"])
        phases["P2"] = phase_run("P2-rollback-1.2.5", "A", report_dir, [])
        phases["P3"] = phase_run("P3-reupgrade-1.3.1", "B", report_dir, ["--filter"])
        phases["P4"] = phase_run("P4-droplist-then-1.2.5", "A", report_dir, ["--drop-list"])
    finally:
        dup_mongo.admin("dropdb", SCRATCH_DB)
    checks = evaluate(phases)
    summary = {"created": datetime.now(timezone.utc).isoformat(), "database": SCRATCH_DB,
               "seed": {"nodes": nodes, "days": days, "events_per_day": events_per_day, "power_per_day": power_per_day,
                        "serverstats_minutes": serverstats_minutes, "written": {**phases["P0"].get("seededRaw", {}),
                                                                               **phases["P0"].get("seededRecords", {})}},
               "mongod": dup_mongo.ping(),
               "timings_ms": {key: {"layer": data["version"], "node": data["node"], "createDb": data["createDbMs"],
                                    "indexSettle": data["indexSettleMs"], "dropList": data.get("dropListMs"),
                                    "mongodIndexWindow": data.get("mongodIndexWindowMs"), "mongodIndexBuilds": data.get("mongodIndexBuilds"),
                                    "resetLines": data["resetLines"],
                                    "slowestBuildSteps": sorted(({"ns": l.get("ns"), "msg": l.get("msg"), "ms": l["durationMillis"]}
                                                                 for l in (data.get("mongodIndexLog") or [])
                                                                 if l.get("durationMillis") is not None and l.get("msg", "").startswith("Index build")),
                                                                key=lambda x: -x["ms"])[:6]}
                              for key, data in phases.items()},
               "plans": {key: {"deviceList": data["deviceListPlan"], "eventList": data["eventListPlan"]} for key, data in phases.items()},
               "checks": checks, "phases": {key: str(report_dir / (data["phase"] + ".json")) for key, data in phases.items()}}
    write_json(report_dir / "summary.json", summary)
    write_json(REPORTS / "dbcompat-latest.json", summary)
    failed = [c for c in checks if c["status"] != "PASS"]
    log(f"  dbcompat -> {report_dir / 'summary.json'} ({len(failed)} FAIL)")
    if failed:
        raise DupError("dbcompat expectations failed: " + "; ".join(c["check"] for c in failed))
    return summary


def evaluate(phases):
    checks = []

    def check(name, ok, detail=None):
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    p0, p1, p2, p3, p4 = (phases[k] for k in ("P0", "P1", "P2", "P3", "P4"))
    check("P0: 1.2.5 leaves its own index set", p0["indexes"] == expected_set(False), p0["indexes"])
    check("P1: 1.3.1 adds its indexes without a reset", p1["indexes"] == expected_set(True) and not p1["resetLines"],
          {"indexes": p1["indexes"], "reset": p1["resetLines"]})
    check("P1: device list uses TypeDomainMeshNameCollation1", p1["deviceListPlan"]["index"] == "TypeDomainMeshNameCollation1",
          p1["deviceListPlan"])
    check("P1: name filter works (case-insensitive, regex metacharacters literal)",
          isinstance(p1.get("filterGolf"), int) and p1["filterGolf"] > 0 and p1.get("filterRegexMeta") == 0,
          {"GOLF": p1.get("filterGolf"), ".*(": p1.get("filterRegexMeta")})
    check("P2: rollback 1.2.5 logs the three resets and rebuilds its set (plugins.TypeAndName1 stays)",
          sorted(p2["resetLines"]) == sorted(RESET_LINES) and p2["indexes"] == expected_set(False, ADDED_131["plugins"]),
          {"reset": p2["resetLines"], "indexes": p2["indexes"]})
    check("P2: 1.2.5 reads the node field 1.3.1 wrote", p2["firstNodeDefaultRouteIp"] == "10.9.9.9", p2["firstNodeDefaultRouteIp"])
    check("P3: re-upgrade adds the 1.3.1 indexes again without a reset", p3["indexes"] == expected_set(True) and not p3["resetLines"],
          {"indexes": p3["indexes"], "reset": p3["resetLines"]})
    check("P4: with the drop list applied first, 1.2.5 starts with no reset",
          not p4["resetLines"] and p4["indexes"] == expected_set(False, ["_id_"]) and all(d["present"] for d in p4["dropped"]),
          {"dropped": p4["dropped"], "reset": p4["resetLines"], "indexes": p4["indexes"]})
    reads = {key: {name: data.get(name) for name in STABLE_READS} for key, data in phases.items()}
    check("reads are equal in every phase", all(reads[k] == reads["P0"] for k in reads), reads)
    check("no unhandled rejection or db.js error in any phase (driver deprecation warnings listed, not failures)",
          not any(problems_in(data["logs"]) for data in phases.values()),
          {k: {"problems": problems_in(d["logs"]), "driver_warnings": sorted({l[l.index("Warning"):][:120] for l in d["logs"] if DRIVER_WARNING.match(l)})}
           for k, d in phases.items()})
    return checks
