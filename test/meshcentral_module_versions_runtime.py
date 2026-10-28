"""Validate core generation carries module versions and preserves source bytes."""
from pathlib import Path
import importlib.util
import hashlib
import json
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "test" / "lib"))
import meshcentral_paths  # noqa: E402

spec = importlib.util.spec_from_file_location("deployment", root / "deploy.py")
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)
# The patches are checked on stock upstream: since Stage 1 the installed package is the fork,
# whose committed meshcentral.js must already be upstream plus exactly these patches.
source = (meshcentral_paths.upstream_package_dir() / "meshcentral.js").read_text(encoding="utf-8")
patched = deployment.align_proxy_certificate_sni(deployment.version_meshcentral_module_loader(source))
assert deployment.version_meshcentral_module_loader(patched) == patched
fork_bytes = meshcentral_paths.fork_file("meshcentral.js").read_bytes()
fork_source = fork_bytes.decode("utf-8")
assert deployment.align_proxy_certificate_sni(deployment.version_meshcentral_module_loader(fork_source)) == fork_source, \
    "the fork meshcentral.js must already carry the module-version and SNI changes"
# Production's copy was patched in two steps, so line endings on the patched lines differ.
assert fork_source.replace("\r\n", "\n") == patched.replace("\r\n", "\n"), \
    "the fork meshcentral.js must equal upstream plus exactly the module-version and SNI changes"
older_versioned = re.sub(r"(?m)^\s*const preferredModule = moduleName[^\n]+\n\s*if \(modulesDir\[i\] !== preferredModule[^\n]+\n", "", patched, count=1)
assert older_versioned != patched
assert deployment.version_meshcentral_module_loader(older_versioned) == patched
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
builder = patched[patched.index("obj.updateMeshCore = function"):patched.index("// Update the default meshcmd")]
selection_fixture = r'''
const assert = require('assert'), vm = require('vm');
for (const minifycore of [false, true]) for (const files of [['probe.js','probe.min.js'],['probe.min.js','probe.js'],['probe.js'],['probe.min.js']]) {
    const obj = {args:{minifycore},datapath:'data',path:require('path'),crypto:require('crypto'),
        common:{IntToStr:()=> '\0\0\0\0'}, debug:()=>{},
        defaultMeshCores:{},defaultMeshCoresHash:{},defaultMeshCoresDeflate:{},
        escapeCodeString:value=>JSON.stringify(value).slice(1,-1),
        fs:{existsSync:file=>file.endsWith('meshcore.js'),readdirSync:()=>files,
            statSync:()=>({mtime:new Date('2026-10-03T10:30:00.000Z')}),
            readFileSync:file=>Buffer.from(file.endsWith('meshcore.js') || file.endsWith('meshcore.min.js') ? '//core' : file.endsWith('.min.js') ? 'module.exports="min";' : 'module.exports="plain";')}};
    vm.runInNewContext(BUILDER, {obj,Buffer,__dirname:'package',require:name=>({constants:{Z_BEST_COMPRESSION:9},deflate:(data,options,callback)=>callback(null,data)})});
    obj.updateMeshCore();
    const registrations=[];
    vm.runInNewContext(obj.defaultMeshCores['windows-amt'].slice(4).toString(),{addModule:(...args)=>registrations.push(args)});
    assert.equal(registrations.length,1,'duplicate files must register one authoritative module');
    const preferMin = files.includes('probe.min.js') && (minifycore || !files.includes('probe.js'));
    assert.equal(registrations[0][1], preferMin ? 'module.exports="min";' : 'module.exports="plain";');
}
console.log('Core module selection is stable across minification modes, file order and missing counterparts.');
'''.replace("BUILDER", json.dumps(builder))
with tempfile.TemporaryDirectory() as temp:
    file = Path(temp) / "module-selection.js"
    file.write_text(selection_fixture, encoding="utf-8")
    subprocess.run(["node", str(file)], check=True)
for name in ("clipboard", "process-manager", "service-manager", "user-sessions", "win-registry"):
    assert f"modules_meshcore/{name}.js" in deployment.CORE_ARTIFACTS
    assert f"modules_meshcore_min/{name}.min.js" in deployment.CORE_ARTIFACTS

# Stage 1: deploy.py stages the fork's committed loader as is. Nothing is read from the server
# to build it, and it may only replace a loader of the same package version.
assert deployment.CORE_ARTIFACTS["meshcentral.js"]["local_path"] == "../MeshCentral/meshcentral.js"
assert deployment.CORE_ARTIFACTS["meshcentral.js"]["publish_targets"] == ("module-root",)
assert not hasattr(deployment, "prepare_versioned_core_loader"), "the loader is no longer patched at stage time"
fork_version = json.loads(meshcentral_paths.fork_file("package.json").read_text(encoding="utf-8"))["version"]


def no_server(*unused):
    raise AssertionError("building the staged loader must not contact the server")


with tempfile.TemporaryDirectory() as temp:
    local_repo, fork_repo = Path(temp) / "MeshAgent", Path(temp) / "MeshCentral"
    local_repo.mkdir()
    fork_repo.mkdir()
    (fork_repo / "meshcentral.js").write_bytes(fork_bytes)
    (fork_repo / "package.json").write_text(json.dumps({"name": "meshcentral", "version": fork_version}), encoding="utf-8")
    deployment.LOCAL_REPO, deployment.LOCAL_MESHCENTRAL_REPO = local_repo, fork_repo
    deployment.ssh_cmd = deployment.run_remote_process = no_server
    entry = next(item for item in deployment.build_local_core_artifact_entries() if item["name"] == "meshcentral.js")
    assert entry["present"] and Path(entry["local_path"]) == (fork_repo / "meshcentral.js").resolve()
    assert entry["sha384"] == hashlib.sha384(fork_bytes).hexdigest()
    assert entry["package_version"] == fork_version and "source_sha384" not in entry
    assert deployment.build_stage_manifest_artifacts([entry])[0]["package_version"] == fork_version
    # Status/deploy metadata must leave the staged bytes intact.
    before = (fork_repo / "meshcentral.js").stat().st_mtime_ns
    deployment.build_local_core_artifact_entries()
    assert (fork_repo / "meshcentral.js").stat().st_mtime_ns == before
    assert (fork_repo / "meshcentral.js").read_bytes() == fork_bytes
    package_path = deployment.get_core_publish_path("module-root", "package.json")
    writes = []
    deployment.run_remote_script = lambda commands: writes.append(commands) or "ok"
    deployment.load_remote_json = lambda path: {"name": "meshcentral", "version": fork_version} if path == package_path else None
    assert deployment.publish_staged_payloads([], core_artifacts=[entry])
    assert writes, "a matching installed package version publishes the loader"
    writes.clear()
    for installed in ({"name": "meshcentral", "version": fork_version + "-other"}, {"name": "other", "version": fork_version}, None, []):
        deployment.load_remote_json = lambda path, installed=installed: installed
        assert not deployment.publish_staged_payloads([], core_artifacts=[entry])
        assert not writes, f"installed package {installed!r} must stop before any payload mutation"
    (fork_repo / "package.json").write_text("{", encoding="utf-8")
    try:
        deployment.build_local_core_artifact_entries()
        raise AssertionError("an unreadable fork package version must abort staging")
    except RuntimeError:
        pass
print("PASS source override deployment manifest and loader versioning")
