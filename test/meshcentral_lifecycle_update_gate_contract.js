'use strict';
// S2: MeshCentral pushes the native Windows package to a Windows service agent only when the agent
// advertises lifecycle update support (0x400). The streaming ZIP bit (0x200) is no evidence of it:
// MeshAgent_Create always sets 0x200, and MeshServer_AdvertisedCapabilities clears 0x400 for a
// process that cannot run the lifecycle host (not a service, or built without the runtime).
// The selector is executed from the fork's meshagent.js, and the agent side is read from agentcore.c.
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { forkFile } = require('./lib/meshcentral_paths');

function read(filePath) {
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing function: ${signature}`);
    const bodyStart = source.indexOf('{', start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`unterminated function: ${signature}`);
}

const repo = path.resolve(__dirname, '..');
const server = read(forkFile('meshagent.js'));
const agentcore = read(path.join(repo, 'meshcore', 'agentcore.c'));
const agentcoreHeader = read(path.join(repo, 'meshcore', 'agentcore.h'));

// Agent side: the facts the gate relies on.
assert(/MeshCommand_AuthInfo_CapabilitiesMask_STREAMING_COMPRESSION = 0x200/.test(agentcoreHeader), 'agentcore.h must define 0x200 as streaming compression');
assert(/MeshCommand_AuthInfo_CapabilitiesMask_LIFECYCLE_UPDATE = 0x400/.test(agentcoreHeader), 'agentcore.h must define 0x400 as lifecycle update');
assert(/retVal->capabilities = capabilities \|[^;]*MeshCommand_AuthInfo_CapabilitiesMask_STREAMING_COMPRESSION;/.test(agentcore),
    'MeshAgent_Create sets 0x200 on every agent, so 0x200 cannot mean lifecycle support');
const advertised = extractFunction(agentcore, 'static int MeshServer_AdvertisedCapabilities(MeshAgentHostContainer *agent)');
assert(advertised.includes('capabilities &= ~MeshCommand_AuthInfo_CapabilitiesMask_LIFECYCLE_UPDATE;'),
    'the agent clears 0x400 when it cannot run the lifecycle host');
assert(advertised.includes('if (agent->JSRunningAsService != 0) { capabilities |= MeshCommand_AuthInfo_CapabilitiesMask_LIFECYCLE_UPDATE; }'),
    'only a service process advertises 0x400');

// Server side: execute the fork's selector.
const compareSource = extractFunction(server, 'function compareAgentBinaryHash(agentExeInfo, agentHash)');
assert(compareSource.includes('(obj.agentInfo.capabilities & 0x400) == 0'), 'the lifecycle gate must test 0x400');
assert(!compareSource.includes('0x600'), 'the lifecycle gate must not accept 0x200 in place of 0x400');
const selectorFactory = new Function('obj', 'args', 'domain', 'parent', [
    extractFunction(server, 'function isWindowsServiceAgentArchitecture(agentId)'),
    extractFunction(server, 'function isWindowsAgentArchitecture(agentId)'),
    compareSource,
    'return compareAgentBinaryHash;'
].join('\n'));

function select(id, capabilities, options = {}) {
    const debug = [];
    const obj = { nodeid: '0123456789abcdef0123', agentInfo: (capabilities === null) ? null : { capabilities } };
    const args = { agentupdatetest: options.test, agentupdatesystem: options.system };
    const parent = { parent: { meshAgentBinaries: {}, debug: function (source, message) { debug.push(message); } } };
    const result = selectorFactory(obj, args, {}, parent)({ id, hash: 'NEW' }, 'OLD');
    return { result, debug };
}

for (const id of [3, 4, 22, 43]) {
    for (const caps of [0x400, 0x418, 0x600, 0x700, 0x71f]) {
        assert.strictEqual(select(id, caps).result, 1, `Windows service ${id} with 0x${caps.toString(16)} gets the native package`);
    }
    for (const caps of [0, 0x18, 0x1f, 0x100, 0x200, 0x300, 0x318]) {
        const { result, debug } = select(id, caps);
        assert.strictEqual(result, 0, `Windows service ${id} with 0x${caps.toString(16)} (no 0x400) is withheld`);
        assert(debug.some((line) => line.includes('Native update withheld') && line.includes('capabilities=0x' + caps.toString(16))),
            'a withheld update is logged with the advertised capabilities');
    }
    const unknown = select(id, null);
    assert.strictEqual(unknown.result, 0, `Windows service ${id} without agentInfo is withheld`);
    assert(unknown.debug.some((line) => line.includes('capabilities=unknown')), 'a withheld update without agentInfo says so');
}

// Neither test mode nor forced recovery mode bypasses the gate.
assert.strictEqual(select(4, 0x300, { test: 1 }).result, 0, 'agentupdatetest must not push to an agent without 0x400');
assert.strictEqual(select(4, 0x300, { test: 2 }).result, 0, 'agentupdatetest 2 must not push to an agent without 0x400');
assert.strictEqual(select(4, 0x300, { system: 2 }).result, 0, 'agentupdatesystem 2 must not push to an agent without 0x400');
assert.strictEqual(select(4, 0x400, { test: 1 }).result, 1, 'test mode still works for lifecycle-capable agents');

// The gate applies to Windows service architectures only.
assert.strictEqual(select(6, 0).result, 1, 'Linux agents are not affected by the Windows lifecycle gate');
assert.strictEqual(select(6, 0x300).result, 1, 'Linux agents with 0x300 are not affected');
assert.strictEqual(select(1, 0x400).result, 0, 'Windows console binaries stay excluded');

console.log('meshcentral_lifecycle_update_gate_contract: PASS');
