'use strict';
// SRV-1 / NAT-8 at Stage 6: MeshCentral 1.3.1 (4baeee5a2, #8254) re-reads the agent binary table after the
// server reloads its agent binaries, through obj.updateAgentExeInfo() on every connected agent, and asks an
// agent that connected before its binary loaded for its binary hash (command 12). The fork's update state
// machine needs two things on that path:
// - agentupdatefailurecapability goes out before command 12, as on connect, so a fork agent whose update
//   fails reports it and gets its core back instead of falling back to the old-server mode (reconnect
//   after each failure, no hash during backoff);
// - a pending native transfer (agentUpdateTransferPending, from the hash decision until obj.agentUpdate
//   exists) keeps the binary it was decided for.
// And on the command-12 reply for such an agent: the core was checked when it connected, so a current
// agent is not asked for its core hash again, and the pending flags are cleared.
// The fork's meshagent.js (CreateMeshAgent) is driven directly. No server, socket or agent is used.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const { EventEmitter } = require('events');
const { forkFile } = require('./lib/meshcentral_paths');

const LINUX_X64 = 6;
const short = (v) => String.fromCharCode((v >> 8) & 0xFF, v & 0xFF);
const hash48 = (ch) => ch.repeat(48);

function binary(tag) {
    return { id: LINUX_X64, update: true, amt: false, desc: 'fixture ' + tag, hash: hash48(tag), hashhex: Buffer.from(hash48(tag), 'binary').toString('hex'),
        data: Buffer.alloc(40, 0x41), url: 'https://server.invalid/meshagents?id=6' };
}

function connect(table) {
    const common = require(forkFile('common.js'));
    const ws = new EventEmitter();
    ws._socket = { remotePort: 4433, bytesRead: 0, bytesWritten: 0, setTimeout() {} };
    ws.sent = [];
    ws.send = (data) => { ws.sent.push(Buffer.from(data).toString('binary')); };
    ws.close = () => {};
    const launched = [];
    const parent = {
        agentStats: {}, trafficStats: { AgentCtrlIn: 0, AgentCtrlOut: 0 }, crypto,
        meshes: {}, webCertificateFullHashs: {}, setAgentIssue() {}, fs,
        parent: {
            common, debug() {}, certificateOperations: { forge: {} }, agentUpdateBlockSize: 16, meshAgentBinaries: table,
            meshAgentsArchitectureNumbers: { [LINUX_X64]: { core: 'linux-noamt' } },
            taskLimiter: { launch(fn, argument) { launched.push(() => fn(argument, 1, null)); }, completed() {} }
        }
    };
    const agent = require(forkFile('meshagent.js')).CreateMeshAgent(parent, {}, ws, { clientIp: '127.0.0.1' }, { agentidletimeout: 0 }, { id: '' });
    agent.authenticated = 2;
    agent.nodeid = 'node//fixture';
    agent.agentInfo = { agentId: LINUX_X64, capabilities: 16 };
    const json = () => ws.sent.filter((m) => m.charCodeAt(0) === 123).map((m) => JSON.parse(m).action);
    const commands = () => ws.sent.filter((m) => m.charCodeAt(0) !== 123).map((m) => (m.charCodeAt(0) << 8) + m.charCodeAt(1));
    const receive = (text) => ws.emit('message', Buffer.from(text, 'binary'));
    return { agent, ws, json, commands, receive, launched };
}

const cases = [];
const sentNames = (s) => s.ws.sent.map((m) => (m.charCodeAt(0) === 123) ? JSON.parse(m).action : (m.charCodeAt(0) << 8) + m.charCodeAt(1));
// An agent that connected while its default binary was still loading.
function lateAgent(table) {
    const s = connect(table);
    s.agent.agentExeInfo = null;
    s.agent.agentExeMissing = true;
    return s;
}

// Still no binary after the reload: nothing is sent.
{
    const s = lateAgent({});
    s.agent.updateAgentExeInfo();
    assert.strictEqual(s.agent.agentExeInfo, undefined, 'no binary for this agent id');
    assert.deepStrictEqual(s.ws.sent, [], 'no binary yet, no check');
    cases.push('no binary yet: nothing sent');
}

// The binary loaded: agentupdatefailurecapability, then command 12.
const loaded = binary('N');
{
    const s = lateAgent({ [LINUX_X64]: loaded });
    s.agent.updateAgentExeInfo();
    assert.strictEqual(s.agent.agentExeInfo, loaded, 'the agent uses the loaded binary');
    assert.deepStrictEqual(sentNames(s), ['agentupdatefailurecapability', 12], 'agentupdatefailurecapability goes out before command 12');
    cases.push('late binary: capability, then command 12');

    // The agent is current: its core was checked at connect, so no command 11, and no transfer.
    s.ws.sent.length = 0;
    s.receive(short(12) + short(0) + loaded.hash);
    assert.deepStrictEqual(s.commands(), [], 'a current late agent is not asked for its core hash again');
    assert.strictEqual(s.agent.agentUpdateTransferPending, undefined, 'no transfer is pending');
    assert.strictEqual(s.launched.length, 0, 'no transfer for a current agent');
    cases.push('late binary, current agent: no second core check');
}

// The agent is out of date: the native transfer is queued, and a reload before it runs keeps the binary.
{
    const table = { [LINUX_X64]: loaded };
    const s = lateAgent(table);
    s.agent.updateAgentExeInfo();
    s.ws.sent.length = 0;
    s.receive(short(12) + short(0) + hash48('O'));
    assert.strictEqual(s.agent.agentUpdateTransferPending, true, 'the transfer is pending');
    assert.strictEqual(s.launched.length, 1, 'one transfer is queued');
    table[LINUX_X64] = binary('R');
    s.agent.updateAgentExeInfo();
    assert.strictEqual(s.agent.agentExeInfo, loaded, 'a pending transfer keeps the binary it was decided for');
    assert.deepStrictEqual(s.ws.sent, [], 'nothing is sent while a transfer is pending');
    cases.push('outdated late agent: a reload before the transfer runs keeps its binary');
}

// An agent that had its binary at connect switches to the reloaded entry and is not asked again.
{
    const table = { [LINUX_X64]: loaded };
    const s = connect(table);
    s.agent.agentExeInfo = loaded;
    table[LINUX_X64] = binary('R');
    s.agent.updateAgentExeInfo();
    assert.strictEqual(s.agent.agentExeInfo, table[LINUX_X64], 'the reloaded entry is used');
    assert.deepStrictEqual(s.ws.sent, [], 'no new hash request');
    cases.push('agent with a binary: entry switched, no request');
}

console.log(JSON.stringify({ ok: true, test: 'meshcentral_agent_exe_reload_runtime', cases }));
