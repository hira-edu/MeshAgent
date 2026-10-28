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
# deploy.py's patch helpers (still used by tools/prepare_release_image.py and the duplicate's layout A,
# which rebuilds production's loader) are checked on the pinned stock upstream loader.
source = (meshcentral_paths.upstream_package_dir() / "meshcentral.js").read_text(encoding="utf-8")
patched = deployment.align_proxy_certificate_sni(deployment.version_meshcentral_module_loader(source))
assert deployment.version_meshcentral_module_loader(patched) == patched
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

# Since Stage 1 deploy.py refuses every MeshCentral publish role before any SSH: the fork's loader
# needs the release manifest only the packed tarball carries, and data-dir copies would be shadow
# cores (D18). The map still declares the files; agent binaries are still published.
assert deployment.CORE_ARTIFACTS["meshcentral.js"]["publish_targets"] == ("module-root",)
assert not hasattr(deployment, "prepare_versioned_core_loader"), "the loader is not patched at stage time"
assert deployment.MESHCENTRAL_PUBLISH_ROLES == frozenset(deployment.CORE_PUBLISH_ROLE_DIRS)
refused = dict(deployment.declared_meshcentral_refusals())
assert set(refused) == set(deployment.CORE_ARTIFACTS), "every declared MeshCentral file is refused"
assert "Stage 4 tarball install" in deployment.MESHCENTRAL_PUBLISH_REFUSAL and "docs/DEPLOYMENT.md" in deployment.MESHCENTRAL_PUBLISH_REFUSAL


def no_server(*unused, **unused_keywords):
    raise AssertionError("a refused MeshCentral publish must not contact the server")


with tempfile.TemporaryDirectory() as temp:
    staged = Path(temp) / "meshcentral.js"
    staged.write_bytes(patched.encode("utf-8"))
    entry = {"name": "meshcentral.js", "remote_filename": "meshcentral.js", "remote_relative_path": "meshcentral.js",
             "staging_filename": "meshcentral.js", "local_path": str(staged), "present": True,
             "publish_targets": ("module-root",), "size_bytes": staged.stat().st_size,
             "sha384": hashlib.sha384(staged.read_bytes()).hexdigest()}
    saved = {name: getattr(deployment, name) for name in ("ssh_cmd", "run_remote_process", "run_remote_script", "collect_remote_file_metadata")}
    for name in saved:
        setattr(deployment, name, no_server)
    assert not deployment.publish_staged_payloads([], core_artifacts=[entry])
    errors = deployment.verify_remote_core_publish([entry])
    assert errors and deployment.MESHCENTRAL_PUBLISH_REFUSAL in errors[0], errors
    state = deployment.get_core_publish_state([entry])
    assert state[0]["refused"] is True and deployment.get_core_publish_state_errors(state) == []
    # The agent-binary path still publishes, with no MeshCentral copy among its commands.
    writes = []
    deployment.run_remote_script = lambda commands: writes.append(commands) or "ok"
    agent = {"name": "MeshService64.exe", "remote_filename": "MeshService64.exe", "staging_filename": "MeshService64.exe",
             "publish_targets": ("data", "signed", "module")}
    assert deployment.publish_staged_payloads([agent], core_artifacts=[])
    copies = [command for command in writes[0] if command.startswith("cp -f")]
    assert len(copies) == 3 and all("MeshService64.exe" in command for command in copies), copies
    for name, value in saved.items():
        setattr(deployment, name, value)
print("PASS source override deployment manifest and loader versioning")
