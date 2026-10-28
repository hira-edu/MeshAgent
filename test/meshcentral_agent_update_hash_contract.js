'use strict';
// Drives the server's agent connection (meshagent.js CreateMeshAgent) through its websocket handler
// and checks which hash the agent update uses, in the tracked fork file and in the installed package
// copy the server runs:
// - an agent that reports the served file hash (fileHash, with the appended .msh) or the normalised
//   executable hash is current, so no transfer starts;
// - any other hash starts the native transfer, which ends (command 13) with the normalised
//   executable hash the agent verifies, or the compressed hash for a compressed transfer;
// - the HTTP update command advertises fileHashHex when the served file has one, else hashhex.
// No server, socket or agent is used.
const assert = require('assert');
const path = require('path');
const { EventEmitter } = require('events');
const { forkFile, installedPackageDir } = require('./lib/meshcentral_paths');
const { readSource, evidenceDirFromArgs, writeEvidence, runCases } = require('./lib/source_extract');

const copies = {
    fork: forkFile('meshagent.js'),
    installed: path.join(installedPackageDir().dir, 'meshagent.js')
};
const commonPath = forkFile('common.js');

const BLOCK = 16;
const hash48 = (ch) => ch.repeat(48);
const short = (v) => String.fromCharCode((v >> 8) & 0xFF, v & 0xFF);
const LINUX_X64 = 6;

function exeInfo(options = {}) {
    const info = {
        id: LINUX_X64, update: true, desc: 'fixture agent',
        data: Buffer.alloc(40, 0x41), hash: hash48('H'), hashhex: Buffer.from(hash48('H'), 'binary').toString('hex'),
        url: 'https://server.invalid/meshagents?id=6'
    };
    if (options.fileHash !== false) { info.fileHash = hash48('F'); info.fileHashHex = Buffer.from(info.fileHash, 'binary').toString('hex'); }
    if (options.compressed) { info.zdata = Buffer.alloc(24, 0x5A); info.zhash = hash48('Z'); }
    return info;
}

function connect(createMeshAgent, info, capabilities) {
    readSource(commonPath, 'MeshCentral common helpers used by meshagent.js');
    const common = require(commonPath);
    const ws = new EventEmitter();
    ws._socket = { remotePort: 4433, bytesRead: 0, bytesWritten: 0, setTimeout() {} };
    ws.sent = [];
    ws.send = (data) => { ws.sent.push(Buffer.from(data).toString('binary')); };
    ws.close = () => {};
    const parent = {
        agentStats: {}, trafficStats: { AgentCtrlIn: 0, AgentCtrlOut: 0 }, crypto: require('crypto'),
        meshes: {}, webCertificateFullHashs: {}, setAgentIssue() {},
        fs: require('fs'),
        parent: {
            common, debug() {}, certificateOperations: { forge: {} }, agentUpdateBlockSize: BLOCK, meshAgentBinaries: {},
            meshAgentsArchitectureNumbers: { [LINUX_X64]: { core: null } },
            taskLimiter: { launch(fn, argument) { fn(argument, 1, null); }, completed() {} }
        }
    };
    const agent = createMeshAgent(parent, {}, ws, { clientIp: '127.0.0.1' }, { agentidletimeout: 0 }, { id: '' });
    agent.authenticated = 2;
    agent.nodeid = 'node//fixture';
    agent.agentInfo = { agentId: LINUX_X64, capabilities };
    agent.agentExeInfo = info;
    const receive = (text) => ws.emit('message', Buffer.from(text, 'binary'));
    return { agent, ws, receive };
}

// Command 12: the agent reports the hash of the binary it runs.
const reportHash = (receive, hash) => receive(short(12) + short(0) + hash);
const commands = (ws) => ws.sent.filter((m) => m.charCodeAt(0) !== 123).map((m) => (m.charCodeAt(0) << 8) + m.charCodeAt(1));

function transferEnd(session) {
    const { ws, receive } = session;
    for (let guard = 0; guard < 100 && session.agent.agentUpdate != null; ++guard) { receive(short(14) + short(1)); }
    assert.strictEqual(session.agent.agentUpdate, undefined, 'the transfer completes');
    const last = ws.sent[ws.sent.length - 1];
    assert.strictEqual(last.substring(0, 4), short(13) + short(0), 'the transfer ends with command 13');
    return last.substring(4);
}

function casesFor(createMeshAgent) {
    return {
        servedFileHashIsCurrent() {
            const session = connect(createMeshAgent, exeInfo(), 0);
            reportHash(session.receive, hash48('F'));
            assert.deepStrictEqual(commands(session.ws).filter((c) => c === 13 || c === 14), [], 'no transfer for the served file hash');
        },
        normalisedHashIsCurrent() {
            const session = connect(createMeshAgent, exeInfo(), 0);
            reportHash(session.receive, hash48('H'));
            assert.deepStrictEqual(commands(session.ws).filter((c) => c === 13 || c === 14), [], 'no transfer for the executable hash');
        },
        otherHashTransfersAndEndsWithNormalisedHash() {
            const session = connect(createMeshAgent, exeInfo(), 0);
            reportHash(session.receive, hash48('O'));
            assert.deepStrictEqual(commands(session.ws).slice(0, 3), [10, 13, 14], 'clear core, start, first block');
            assert.strictEqual(transferEnd(session), hash48('H'), 'command 13 carries the normalised executable hash, not the file hash');
        },
        compressedTransferEndsWithCompressedHash() {
            const session = connect(createMeshAgent, exeInfo({ compressed: true }), 0x300);
            reportHash(session.receive, hash48('O'));
            assert.strictEqual(transferEnd(session), hash48('Z'));
        },
        httpUpdateAdvertisesFileHash() {
            const session = connect(createMeshAgent, exeInfo(), 0);
            session.agent.agentCoreUpdate = true;
            session.receive('{"action":"coreinfo"}');
            const update = session.ws.sent.filter((m) => m.charCodeAt(0) === 123).map((m) => JSON.parse(m)).find((c) => c.action === 'agentupdate');
            assert(update, 'the agent is told to update over HTTP');
            assert.strictEqual(update.hash, exeInfo().fileHashHex);
            assert.strictEqual(update.url, '*/meshagents?id=6');
        },
        httpUpdateWithoutFileHashAdvertisesExecutableHash() {
            const session = connect(createMeshAgent, exeInfo({ fileHash: false }), 0);
            session.agent.agentCoreUpdate = true;
            session.receive('{"action":"coreinfo"}');
            const update = session.ws.sent.filter((m) => m.charCodeAt(0) === 123).map((m) => JSON.parse(m)).find((c) => c.action === 'agentupdate');
            assert(update, 'the agent is told to update over HTTP');
            assert.strictEqual(update.hash, exeInfo().hashhex);
        }
    };
}

const report = { copies, results: {} };
let failed = 0;
for (const [name, filePath] of Object.entries(copies)) {
    readSource(filePath, name + ' meshagent.js whose agent update hash handling is driven');
    const run = runCases('meshcentral_agent_update_hash_contract ' + name, casesFor(require(filePath).CreateMeshAgent));
    report.results[name] = run.results;
    failed += run.failed;
}
if (failed) { process.exitCode = 1; }

const evidenceDir = evidenceDirFromArgs(process.argv);
if (evidenceDir) {
    writeEvidence(evidenceDir, 'meshcentral_agent_update_hash_contract', report, [
        'FORK_MESHAGENT=' + copies.fork,
        'INSTALLED_MESHAGENT=' + copies.installed,
        'SUCCESS=' + (failed === 0)
    ]);
}
