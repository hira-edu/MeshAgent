'use strict';
// Stage 6 (D11/D12): the MeshCentral fork serves its own MeshAgent service builds from its package, pinned by
// size and SHA384 in MeshCentral agents/agent-defaults.json. test/release_bundle_gate.js writes that manifest
// from a passing gate's verified records. This contract checks the builder, and that its output is what the
// fork's own reader (agentbuilds.js), pin writer (agents/release-manifest.js) and release gate
// (agents/check-releases.js) expect, in the MeshCentral checkout MESHCENTRAL_ROOT names.
const assert = require('assert').strict;
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { MESHCENTRAL_AGENT_MANIFEST, MESHCENTRAL_SERVED_AGENTS, buildMeshCentralAgentManifest } = require('./release_bundle_gate');
const { forkFile, meshcentralRoot } = require('./lib/meshcentral_paths');

const BUILD = { repository: 'hira-edu/MeshAgent', commit: '0123456789abcdef0123456789abcdef01234567' };
const MACHINES = { 'MeshService.exe': 0x014c, 'MeshService64.exe': 0x8664, 'MeshServiceARM64.exe': 0xaa64 };
const bytes = (id) => Buffer.from('MZ fixture build of ' + id + '\n');
const sha = (data, algorithm) => crypto.createHash(algorithm).update(data).digest('hex');

function record(id, overrides = {}) {
    const data = bytes(id);
    return Object.assign({
        id, required: true, peArtifact: true, found: true, path: 'dist/' + id,
        file: { size: data.length, mtimeUtc: '2026-10-29T00:00:00.000Z' },
        digests: { sha256: sha(data, 'sha256'), sha384: sha(data, 'sha384'), sha512: sha(data, 'sha512') },
        signature: { isPe: true, machine: MACHINES[id], hasCertificateTable: false },
        expectedMachine: MACHINES[id], machineMatches: true
    }, overrides);
}
const verified = () => ['diagsvc.dll', ...MESHCENTRAL_SERVED_AGENTS, 'WinDiagnosticHost.msh'].map((id) => MACHINES[id] ? record(id) : { id, found: true });

// The builder pins exactly the three service builds, in order, from the verified records.
assert.equal(MESHCENTRAL_AGENT_MANIFEST, 'meshcentral-agent-defaults.json');
assert.deepEqual(MESHCENTRAL_SERVED_AGENTS, ['MeshService.exe', 'MeshService64.exe', 'MeshServiceARM64.exe']);
const manifest = buildMeshCentralAgentManifest(verified(), BUILD);
assert.deepEqual(manifest, {
    schema: 'meshcentral-fork-agents/1',
    build: BUILD,
    files: MESHCENTRAL_SERVED_AGENTS.map((id) => ({ filename: id, size: bytes(id).length, sha384: sha(bytes(id), 'sha384') }))
});

// An unverified record never becomes a pin.
const refusals = [
    [verified().filter((item) => item.id !== 'MeshServiceARM64.exe'), /MeshServiceARM64\.exe is missing/],
    [verified().map((item) => item.id === 'MeshService.exe' ? record(item.id, { found: false, digests: null, file: undefined }) : item), /MeshService\.exe is missing/],
    [verified().map((item) => item.id === 'MeshService.exe' ? record(item.id, { machineMatches: false }) : item), /MeshService\.exe is not a verified PE build/],
    [verified().map((item) => item.id === 'MeshService64.exe' ? record(item.id, { signature: { isPe: false } }) : item), /MeshService64\.exe is not a verified PE build/],
    [verified().map((item) => item.id === 'MeshService64.exe' ? record(item.id, { digests: { sha384: 'abc' } }) : item), /MeshService64\.exe has no valid size and SHA384/]
];
for (const [records, message] of refusals) {
    assert.throws(() => buildMeshCentralAgentManifest(records, BUILD), message);
}
for (const build of [null, { repository: 'MeshAgent', commit: BUILD.commit }, { repository: BUILD.repository, commit: 'main' }, { repository: BUILD.repository, commit: BUILD.commit.toUpperCase() }]) {
    assert.throws(() => buildMeshCentralAgentManifest(verified(), build), /needs the MeshAgent repository/);
}

// The fork MeshCentral accepts it: the server's parser, the pin writer's output for the same bytes, and the
// release gate against those bytes. The gate's three names are exactly what agenttypes.js serves unsigned.
const root = meshcentralRoot();
const agentbuilds = require(forkFile('agentbuilds.js'));
const types = require(forkFile('agenttypes.js'))();
const unsigned = new Set(Object.keys(types).filter((id) => types[id].unsigned === true).map((id) => types[id].localname));
assert.deepEqual([...unsigned].sort(), [...MESHCENTRAL_SERVED_AGENTS].sort(), 'the gate pins exactly the builds MeshCentral serves unsigned');
const parsed = agentbuilds.parseManifest(manifest, agentbuilds.agentNames(types));
assert.deepEqual([...parsed.files.keys()], MESHCENTRAL_SERVED_AGENTS);
assert.deepEqual(parsed.build, BUILD);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'release-agent-manifest-'));
try {
    const pkg = path.join(temp, 'package');
    for (const rel of ['agentbuilds.js', 'agenttypes.js', 'agents/check-releases.js', 'agents/release-manifest.js']) {
        fs.mkdirSync(path.dirname(path.join(pkg, rel)), { recursive: true });
        fs.copyFileSync(path.join(root, rel), path.join(pkg, rel));
    }
    const built = path.join(temp, 'build');
    fs.mkdirSync(built);
    for (const id of MESHCENTRAL_SERVED_AGENTS) { fs.writeFileSync(path.join(built, id), bytes(id)); }
    const run = (script, args) => childProcess.spawnSync(process.execPath, [path.join(pkg, 'agents', script), ...args], { cwd: pkg, encoding: 'utf8' });

    const written = run('release-manifest.js', ['--repository', BUILD.repository, '--commit', BUILD.commit, ...MESHCENTRAL_SERVED_AGENTS.map((id) => path.join(built, id))]);
    assert.equal(written.status, 0, written.stderr);
    assert.deepEqual(JSON.parse(written.stdout), manifest, 'release-manifest.js writes the same pins for the same bytes');

    fs.writeFileSync(path.join(pkg, 'agents', 'agent-defaults.json'), JSON.stringify(manifest, null, 2) + '\n');
    const gate = run('check-releases.js', ['--directory', built]);
    assert.equal(gate.status, 0, gate.stderr);
    fs.appendFileSync(path.join(built, 'MeshService64.exe'), 'rebuilt');
    const changed = run('check-releases.js', ['--directory', built]);
    assert.equal(changed.status, 1, 'a rebuilt binary no longer matches the gate pins');
    assert.match(changed.stderr, /MeshService64\.exe: .* does not match its pin/);
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

console.log('release_agent_manifest_contract: PASS (the release gate pins the three service builds the MeshCentral fork serves)');
