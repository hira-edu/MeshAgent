"""Validate core generation carries module versions and preserves source bytes."""
from pathlib import Path
import importlib.util
import hashlib
import json
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deployment", root / "deploy.py")
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)
source = (root.parent / "MeshCentral/node_modules/meshcentral/meshcentral.js").read_text(encoding="utf-8")
patched = deployment.version_meshcentral_module_loader(source)
assert deployment.version_meshcentral_module_loader(patched) == patched
begin = patched.index("const modulePath = obj.path.join(moduleDirPath, modulesDir[i]);")
end = patched.index("\n", patched.index("const moduleData =", begin))
statement = patched[begin:end]
fixture = r'''
const assert = require('assert');
const vm = require('vm');
const content = "module.exports = 'Unicode \u2713; quote\"; backslash\\\\';\n";
const version = new Date('2026-10-03T10:30:00.000Z');
let added;
const obj = {path:require('path'), fs:{statSync:() => ({mtime:version}), readFileSync:() => Buffer.from(content)},
    escapeCodeString:value => JSON.stringify(value).slice(1,-1)};
const moduleDirPath='modules', modulesDir=['probe.js'], i=0, moduleName='probe';
STATEMENT
const context = {addModule:(...args)=>{added=args;}, addedModules:[]};
vm.runInNewContext(moduleData.join(''), context);
assert.equal(added[0], 'probe');
assert.equal(added[1], Buffer.from(content).toString('binary'));
assert.equal(added[2], version.toISOString());
assert.equal(context.addedModules[0], 'probe');
console.log('Core module source, registration and explicit version survive generation.');
'''.replace("STATEMENT", statement)
with tempfile.TemporaryDirectory() as temp:
    file = Path(temp) / "module-versions.js"
    file.write_text(fixture, encoding="utf-8")
    subprocess.run(["node", str(file)], check=True)
for name in ("clipboard", "process-manager", "service-manager", "user-sessions"):
    assert f"modules_meshcore/{name}.js" in deployment.CORE_ARTIFACTS
    assert f"modules_meshcore_min/{name}.min.js" in deployment.CORE_ARTIFACTS

with tempfile.TemporaryDirectory() as temp:
    deployment.LOCAL_REPO = Path(temp)
    original_hash = hashlib.sha384(source.encode("utf-8")).hexdigest().upper()
    deployment.ssh_cmd = lambda command: json.dumps({"source": source, "sha384": original_hash})
    deployment.prepare_versioned_core_loader()
    generated = Path(temp) / deployment.CORE_ARTIFACTS["meshcentral.js"]["local_path"]
    assert generated.read_bytes() == patched.encode("utf-8")
    entry = next(item for item in deployment.build_local_core_artifact_entries() if item["name"] == "meshcentral.js")
    assert entry["source_sha384"] == original_hash
    assert deployment.build_stage_manifest_artifacts([entry])[0]["source_sha384"] == original_hash
    # Status/deploy metadata must leave staged bytes intact, even if a local npm copy changes.
    before = generated.stat().st_mtime_ns
    deployment.build_local_core_artifact_entries()
    assert generated.stat().st_mtime_ns == before
    publish_path = deployment.get_core_publish_path("module-root", "meshcentral.js")
    writes = []
    deployment.run_remote_script = lambda commands: writes.append(commands) or "ok"
    for current_hash in (original_hash, entry["sha384"].upper()):
        deployment.collect_remote_file_metadata = lambda paths, algorithm: {publish_path: {"hash": current_hash}}
        assert deployment.publish_staged_payloads([], core_artifacts=[entry])
    writes.clear()
    deployment.collect_remote_file_metadata = lambda paths, algorithm: {publish_path: {"hash": "CHANGED"}}
    assert not deployment.publish_staged_payloads([], core_artifacts=[entry])
    assert not writes, "loader drift must stop before any payload mutation"
    deployment.ssh_cmd = lambda command: None
    try:
        deployment.prepare_versioned_core_loader()
        raise AssertionError("failed loader read must abort staging")
    except RuntimeError:
        pass
print("PASS source override deployment manifest and loader versioning")
