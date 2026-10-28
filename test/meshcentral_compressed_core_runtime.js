'use strict';
// MeshCentral 1.3.1 (e6804c380, #8160) sends the agent core compressed, as MeshCommand_CompressedCoreModule
// (20), to every agent that advertises compression (0x100). Fork agents advertise it, so this is the path
// they take after Stage 6. The server compresses each core with zlib.deflate (meshcentral.js) and strips
// the 2-byte zlib header and the 4-byte Adler-32 trailer, leaving raw DEFLATE.
//
// Server side, executed: the fork's meshagent.js (CreateMeshAgent) is driven through its websocket handler
// with a core compressed exactly as meshcentral.js does it. A 0x100 agent gets command 20 whose payload
// raw-inflates to the core and whose hash is the SHA-384 of the uncompressed core; an agent without 0x100
// gets command 10 with the core as is.
// Agent side, read: agentcore.c takes command 20 through ILibInflate, which inflates raw DEFLATE
// (inflateInit2 with -MAX_WBITS), and verifies the SHA-384 of the inflated core before storing or running
// it, keeping the previous core on a mismatch (fail closed).
// No server, socket or agent is used.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { EventEmitter } = require('events');
const { forkFile } = require('./lib/meshcentral_paths');

function read(filePath) { return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n'); }

const repo = path.resolve(__dirname, '..');
const LINUX_X64 = 6;
const CORE_NAME = 'linux-noamt';
const short = (v) => String.fromCharCode((v >> 8) & 0xFF, v & 0xFF);

// The server compresses each core like this (meshcentral.js updateMeshCore).
const loader = read(forkFile('meshcentral.js'));
assert(loader.includes("require('zlib').deflate(obj.defaultMeshCores[i], { level: require('zlib').constants.Z_BEST_COMPRESSION }, callback);"),
    'meshcentral.js must compress each core with zlib.deflate at Z_BEST_COMPRESSION');

// A core as meshcentral.js builds it: four leading bytes, then the script.
const core = Buffer.concat([Buffer.alloc(4), Buffer.from('// fixture core\r\n' + 'var x = "compressible";\r\n'.repeat(200))]);
const coreHash = crypto.createHash('sha384').update(core).digest('binary');
const coreDeflate = zlib.deflateSync(core, { level: zlib.constants.Z_BEST_COMPRESSION });

function connect(capabilities) {
    const common = require(forkFile('common.js'));
    const ws = new EventEmitter();
    ws._socket = { remotePort: 4433, bytesRead: 0, bytesWritten: 0, setTimeout() {} };
    ws.sent = [];
    ws.send = (data) => { ws.sent.push(Buffer.from(data)); };
    ws.close = () => {};
    const parent = {
        agentStats: { updatingCoreCount: 0, clearingCoreCount: 0 }, trafficStats: { AgentCtrlIn: 0, AgentCtrlOut: 0 }, crypto,
        meshes: {}, webCertificateFullHashs: {}, setAgentIssue() {}, fs,
        parent: {
            common, debug() {}, certificateOperations: { forge: {} }, meshAgentBinaries: {},
            meshAgentsArchitectureNumbers: { [LINUX_X64]: { core: CORE_NAME } },
            defaultMeshCores: { [CORE_NAME]: core }, defaultMeshCoresHash: { [CORE_NAME]: coreHash },
            defaultMeshCoresDeflate: { [CORE_NAME]: coreDeflate },
            taskLimiter: { launch(fn, argument) { fn(argument, 1, null); }, completed() {} }
        }
    };
    const agent = require(forkFile('meshagent.js')).CreateMeshAgent(parent, {}, ws, { clientIp: '127.0.0.1' }, { agentidletimeout: 0 }, { id: '' });
    agent.authenticated = 2;
    agent.nodeid = 'node//fixture';
    agent.agentInfo = { agentId: LINUX_X64, capabilities };
    // Command 11: the agent reports the hash of a different core.
    ws.emit('message', Buffer.from(short(11) + short(0) + 'O'.repeat(48), 'binary'));
    const sent = ws.sent.filter((m) => m[0] !== 123);
    assert.strictEqual(sent.length, 1, 'one core is sent');
    return sent[0];
}

const cases = [];

// A compression-capable agent (fork agents always advertise 0x100) gets raw DEFLATE as command 20.
for (const capabilities of [0x100 | 16, 0x300 | 16, 0x700 | 16]) {
    const message = connect(capabilities);
    assert.strictEqual(message.readUInt16BE(0), 20, 'MeshCommand_CompressedCoreModule');
    assert.strictEqual(message.readUInt16BE(2), 0);
    assert.strictEqual(message.subarray(4, 52).toString('binary'), coreHash, 'the hash is the uncompressed core hash');
    const payload = message.subarray(52);
    assert(payload.length < core.length, 'the payload is compressed');
    const inflated = zlib.inflateRawSync(payload);
    assert(inflated.equals(core), 'the payload raw-inflates to the core');
    assert.strictEqual(crypto.createHash('sha384').update(inflated).digest('binary'), coreHash, 'the agent-side hash check passes');
    cases.push('0x' + capabilities.toString(16) + ': command 20, raw DEFLATE');
}

// Without 0x100 the core goes uncompressed as command 10.
{
    const message = connect(16);
    assert.strictEqual(message.readUInt16BE(0), 10, 'MeshCommand_CoreModule');
    assert.strictEqual(message.subarray(4, 52).toString('binary'), coreHash);
    assert(message.subarray(52).equals(core), 'the core is sent as is');
    cases.push('0x10: command 10, uncompressed');
}

// Agent side: command 20 is inflated as raw DEFLATE and verified before it replaces the running core.
const agentcore = read(path.join(repo, 'meshcore', 'agentcore.c'));
const agentcoreHeader = read(path.join(repo, 'meshcore', 'agentcore.h'));
const compressedStream = read(path.join(repo, 'microscript', 'ILibDuktape_CompressedStream.c'));
assert(/MeshCommand_CompressedCoreModule\s*=\s*20/.test(agentcoreHeader), 'agentcore.h defines command 20');
assert(/MeshCommand_AuthInfo_CapabilitiesMask_COMPRESSION\s*=\s*0x100/.test(agentcoreHeader), 'agentcore.h defines 0x100 as compression');
assert(/retVal->capabilities = capabilities \| [^;]*MeshCommand_AuthInfo_CapabilitiesMask_COMPRESSION/.test(agentcore), 'fork agents advertise compression');
const coreCase = agentcore.indexOf('case MeshCommand_CompressedCoreModule:');
assert(coreCase >= 0, 'agentcore.c handles command 20');
const coreBlock = agentcore.slice(coreCase, agentcore.indexOf('break;\n\t\t}', agentcore.indexOf('module hash mismatch, keeping previous core', coreCase)));
const inflateAt = coreBlock.indexOf('ILibInflate(coremodule, coremoduleLen, decompressedModule');
const verifyAt = coreBlock.indexOf('util_sha384(coremodule, (size_t)coremoduleLen, verifyHash)');
const mismatchAt = coreBlock.indexOf('module hash mismatch, keeping previous core');
assert(inflateAt >= 0 && verifyAt > inflateAt && mismatchAt > verifyAt, 'the agent inflates, then verifies the SHA-384 of the inflated core and keeps the old core on a mismatch');
assert(/"MeshCore: INFLATE error"\);\s*break;/.test(coreBlock), 'an inflate error leaves the running core alone');
const inflateFunction = compressedStream.slice(compressedStream.indexOf('int ILibInflate(char *buffer'));
assert(/inflateInit2\(&Z, -MAX_WBITS\)/.test(inflateFunction.slice(0, 800)), 'ILibInflate inflates raw DEFLATE');
cases.push('agentcore.c: raw inflate, hash verified before use');

console.log(JSON.stringify({ ok: true, test: 'meshcentral_compressed_core_runtime', cases }));
