"""Run the fork's core builder for module bytes and selection, and check deploy.py's refusal.

The fork's obj.updateMeshCore (with its module-version helpers) is taken from the committed
meshcentral.js and run under Node over a fake package tree: each module keeps its source text
and its agents/module-versions.json release date, never a file time (SRV-17: upstream 1.3.1
e02866e7a / #8191 dates modules by file mtime, and the fork's manifest wins), and a module that
is a .js or a .min.js file registers once in each minification mode. The package ships no
.js/.min.js twins since D24, so the loader has no twin selector (SRV-18); MeshAgent
test/meshcentral_core_loader_contract.js checks the package for twins. MeshCentral's
deploy/tests/module-versions.test.js covers the manifest's fail-closed exits.

deploy.py refuses every MeshCentral publish role before any SSH and still publishes agent
binaries. Its import reads no branding file (deploy_fake_remote sets the lifecycle paths).
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "test"))
sys.path.insert(0, str(root / "test" / "lib"))
import meshcentral_paths  # noqa: E402
from deploy_fake_remote import deploy as deployment  # noqa: E402

START = "    // Agent core module versions are release dates"
END = "    // Update the default meshcmd"

fork_bytes = meshcentral_paths.fork_file("meshcentral.js").read_bytes()
source = fork_bytes.decode("utf-8").replace("\r\n", "\n")
assert source.count(START) == 1 and source.count(END) == 1, "the fork meshcentral.js must carry the versioned core builder"
builder = source[source.index(START):source.index(END)]
escape_begin = source.index("    obj.escapeCodeString = function (str, keepUtf8) {")
escape_source = source[escape_begin:source.index(START)]

fixture = r'''
const assert = require('assert'), path = require('path'), vm = require('vm');
const packageDir = path.join(path.sep, 'pkg'), agents = path.join(packageDir, 'agents');

function buildCores(minifycore, files) {
    const tree = { [path.join(agents, 'meshcore.js')]: '// core', [path.join(agents, 'meshcore.min.js')]: '// core' };
    const modules = {};
    for (const [rel, [content, version]] of Object.entries(files)) { tree[path.join(agents, rel)] = content; modules[rel] = version; }
    tree[path.join(agents, 'module-versions.json')] = JSON.stringify({ modules });
    const obj = {
        args: { minifycore }, datapath: path.join(path.sep, 'data'), path, crypto: require('crypto'),
        common: { IntToStr: () => '\0\0\0\0' }, debug: () => { },
        defaultMeshCores: {}, defaultMeshCoresHash: {}, defaultMeshCoresDeflate: {},
        fs: {
            existsSync: file => Object.prototype.hasOwnProperty.call(tree, file),
            readdirSync: dir => {
                const names = Object.keys(tree).filter(file => path.dirname(file) === dir).map(file => path.basename(file));
                if (names.length === 0) { throw new Error('ENOENT ' + dir); }
                return names;
            },
            readFileSync: file => {
                if (!Object.prototype.hasOwnProperty.call(tree, file)) { throw new Error('ENOENT: ' + file); }
                return Buffer.from(tree[file]);
            },
            statSync: () => { throw new Error('the core builder must not read file times (SRV-17, not #8191 mtimes)'); }
        }
    };
    const context = {
        obj, Buffer, __dirname: packageDir,
        console: { error: message => { throw new Error('unexpected builder error: ' + message); }, log: () => { } },
        process: { exit: code => { throw new Error('unexpected exit ' + code); } },
        require: () => ({ constants: { Z_BEST_COMPRESSION: 9 }, deflate: (data, options, callback) => callback(null, data) })
    };
    vm.runInNewContext(ESCAPE + BUILDER, context);
    obj.updateMeshCore();
    const registrations = [];
    const core = obj.defaultMeshCores['windows-amt'].slice(4).toString('binary');
    vm.runInNewContext(core, { addModule: (...args) => registrations.push(args), addedModules: [] });
    return registrations;
}

// Source text and the manifest version survive generation. obj.escapeCodeString (as upstream) keeps
// printable ASCII and escapes quotes, backslashes, tabs and line breaks; other bytes are dropped.
const content = "module.exports = 'quote\" '; apostrophe \\' backslash \\\\ tab\t';\r\n// end\n";
const version = '2026-10-03T10:30:00.000Z';
for (const minifycore of [false, true]) {
    const folder = minifycore ? 'modules_meshcore_min' : 'modules_meshcore';
    const registrations = buildCores(minifycore, { [folder + '/probe.js']: [content, version] });
    assert.strictEqual(registrations.length, 1);
    assert.strictEqual(registrations[0][0], 'probe');
    assert.strictEqual(registrations[0][1], Buffer.from(content).toString('binary'));
    assert.strictEqual(registrations[0][2], version);
}
console.log('Core module source, registration and manifest version survive generation.');

// A module shipped as a .js or a .min.js file registers once, under its name without ".min".
const plain = ['module.exports="plain";', '2026-10-01T00:00:00.000Z'], min = ['module.exports="min";', '2026-10-02T00:00:00.000Z'];
for (const minifycore of [false, true]) {
    const folder = minifycore ? 'modules_meshcore_min' : 'modules_meshcore';
    for (const name of ['probe.js', 'probe.min.js']) {
        const registrations = buildCores(minifycore, { [folder + '/' + name]: name.endsWith('.min.js') ? min : plain });
        assert.strictEqual(registrations.length, 1, 'a module file registers one module');
        assert.strictEqual(registrations[0][0], 'probe');
        assert.deepStrictEqual(registrations[0].slice(1), name.endsWith('.min.js') ? min : plain);
    }
}
console.log('A .js or .min.js module registers once in both minification modes, with its manifest version.');
'''.replace("ESCAPE", json.dumps(escape_source)).replace("BUILDER", json.dumps(builder))
with tempfile.TemporaryDirectory() as temp:
    file = Path(temp) / "module-versions.js"
    file.write_text(fixture, encoding="utf-8")
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
    staged.write_bytes(fork_bytes)
    entry = {"name": "meshcentral.js", "remote_filename": "meshcentral.js", "remote_relative_path": "meshcentral.js",
             "staging_filename": "meshcentral.js", "local_path": str(staged), "present": True,
             "publish_targets": ("module-root",), "size_bytes": staged.stat().st_size,
             "sha384": hashlib.sha384(staged.read_bytes()).hexdigest()}
    saved = {name: getattr(deployment, name) for name in ("ssh_cmd", "run_remote_process", "run_remote_script", "collect_remote_file_metadata")}
    for name in saved:
        setattr(deployment, name, no_server)
    try:
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
    finally:
        for name, value in saved.items():
            setattr(deployment, name, value)
print("PASS fork core builder module bytes, selection and versions; deploy.py MeshCentral publish refusal")
