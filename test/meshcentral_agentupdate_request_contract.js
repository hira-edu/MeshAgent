'use strict';
// SRV-11 (S11): an explicit agent update request ('agentupdate' from the agent console) that the
// server refuses is answered with the reason, on the route the agent's own console replies take
// (routeAgentCommand to the requesting session), instead of a silent break. An accepted Windows
// service request re-enters native hash negotiation (command 12) and sends no refusal.
// The fork's 'agentupdate' case is executed from meshagent.js with the real architecture table.
const assert = require('assert');
const fs = require('fs');
const { forkFile } = require('./lib/meshcentral_paths');
const { readArchitectureTable } = require('./lib/meshcentral_architecture_table');

function read(filePath) { return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n'); }

function extractBraced(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing: ${signature}`);
    const bodyStart = source.indexOf('{', start + signature.length - 1);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`unterminated: ${signature}`);
}

const server = read(forkFile('meshagent.js'));
const architectures = readArchitectureTable(); // agenttypes.js, as meshcentral.js loads it (MeshCentral 1.3.1)
const caseStart = server.indexOf("                case 'agentupdate': {");
const caseEnd = server.indexOf("                case 'agentupdatefailure': {", caseStart);
assert(caseStart >= 0 && caseEnd > caseStart, "the agent command switch must handle 'agentupdate'");
const handlerFactory = new Function('obj', 'parent', 'common', 'domain', 'isIgnoreHashCheck', [
    extractBraced(server, 'function isWindowsServiceAgentArchitecture(agentId)'),
    extractBraced(server, 'function isWindowsAgentArchitecture(agentId)'),
    extractBraced(server, 'function refuseAgentUpdateRequest(command, reason)'),
    'return function (command) { switch (command.action) {',
    server.slice(caseStart, caseEnd),
    '} };'
].join('\n'));

function run(agentId, state = {}, command = { action: 'agentupdate', sessionid: 'user/domain/admin/session' }) {
    const routed = [], sent = [], binary = [], launched = [], debug = [];
    const obj = Object.assign({
        nodeid: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', dbNodeKey: 'node/domain/abc', dbMeshKey: 'mesh/domain/group', domain: { id: 'domain' },
        authenticated: 2, agentInfo: { agentId, capabilities: 0x71f },
        agentExeInfo: { url: 'https://server/meshagents?id=' + agentId, hashhex: 'aa' },
        send(text) { sent.push(JSON.parse(text)); }, sendBinary(data) { binary.push(data); }
    }, state);
    const parent = {
        routeAgentCommand(cmd, domainid, nodeid, meshid) { routed.push({ cmd, domainid, nodeid, meshid }); },
        webCertificateFullHashs: {},
        parent: { meshAgentsArchitectureNumbers: architectures, debug(source, message) { debug.push(source + ': ' + message); },
            taskLimiter: { launch(func) { launched.push(func); }, completed() {} } }
    };
    const common = { ShortToStr: n => String.fromCharCode((n >> 8) & 255, n & 255) };
    handlerFactory(obj, parent, common, { id: 'domain' }, () => false)(command);
    return { obj, routed, sent, binary, launched, debug };
}

function assertRefused(result, reasonPattern, sessionid, label) {
    assert.strictEqual(result.routed.length, 1, label + ': exactly one reply');
    const { cmd, domainid, nodeid, meshid } = result.routed[0];
    assert.deepStrictEqual([cmd.action, cmd.type, cmd.sessionid], ['msg', 'console', sessionid], label + ': a console reply to the requester');
    assert.deepStrictEqual([domainid, nodeid, meshid], ['domain', 'node/domain/abc', 'mesh/domain/group'], label + ': routed for this node');
    assert(/^Agent update refused: /.test(cmd.value) && reasonPattern.test(cmd.value), label + ': states the reason: ' + cmd.value);
    assert(result.debug.some(line => line.startsWith('agentupdate: ') && reasonPattern.test(line)), label + ': the refusal is debug-logged');
    assert.strictEqual(result.binary.length + result.sent.length + result.launched.length, 0, label + ': nothing is sent to the agent');
}

// Accepted: a Windows service agent re-enters native negotiation and gets no refusal.
for (const id of [3, 4, 22, 43]) {
    const accepted = run(id);
    assert.strictEqual(accepted.routed.length, 0, `Windows service ${id}: no refusal`);
    assert.deepStrictEqual(accepted.sent, [{ action: 'agentupdatefailurecapability' }], `Windows service ${id}: capability first`);
    assert.deepStrictEqual(accepted.binary, ['\u0000\u000c\u0000\u0000'], `Windows service ${id}: command 12`);
    assert.strictEqual(accepted.obj.agentUpdateRequestPending, true);
}
// Accepted: other platforms take the agent's JavaScript updater through the task limiter.
const linux = run(6);
assert.strictEqual(linux.routed.length, 0, 'a Linux request is not refused');
assert.strictEqual(linux.launched.length, 1, 'a Linux request launches the update task');

// Refused: Windows console agents have no supported self-update.
for (const id of [1, 2, 21, 42]) {
    assertRefused(run(id), /console/i, 'user/domain/admin/session', `Windows console ${id}`);
}
// Refused: an update is already requested, transferring or in progress.
for (const state of [{ agentUpdateRequestPending: true }, { agentUpdateTransferPending: true }, { agentUpdate: { taskid: 1 } }]) {
    const result = run(4, state);
    assertRefused(result, /already in progress/i, 'user/domain/admin/session', 'pending ' + Object.keys(state)[0]);
}
// Refused: no agent binary for this architecture.
assertRefused(run(4, { agentExeInfo: null }), /no agent binary/i, 'user/domain/admin/session', 'no binary');
assertRefused(run(6, { agentExeInfo: { hashhex: 'aa' } }), /no agent binary/i, 'user/domain/admin/session', 'binary without url');
// A request without a session (fleet update from the device list) is answered like the agent's own
// console output: routed without a session id.
const fleet = run(2, {}, { action: 'agentupdate' });
assertRefused(fleet, /console/i, undefined, 'request without session');

console.log('meshcentral_agentupdate_request_contract: PASS (refused agentupdate requests reply with the reason; accepted ones do not)');
