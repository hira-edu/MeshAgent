'use strict';
// Drives the fork's desktop multiplexor (meshdesktopmultiplex.js) in a vm and checks the agent send
// queue by behaviour: writes are serialised and delivered in order, a backlog of more than 10
// pauses every viewer and draining resumes them, a late write completion from a replaced agent does
// not touch the new agent's queue, and a departing viewer's relay log counts its agent-out traffic
// as bytes out. No server, socket or endpoint is used.
const assert = require('assert');
const path = require('path');
const vm = require('vm');
const { EventEmitter } = require('events');
const { createRequire } = require('module');
const { forkFile } = require('./lib/meshcentral_paths');
const { readSource, evidenceDirFromArgs, writeEvidence, runCases } = require('./lib/source_extract');

const multiplexPath = forkFile('meshdesktopmultiplex.js');
const source = readSource(multiplexPath, 'MeshCentral desktop multiplexor whose agent send queue is driven');

function loadMultiplexor() {
    const serverRequire = createRequire(multiplexPath);
    const sandbox = {
        module: { exports: {} }, Buffer, console, Date,
        setTimeout() { return {}; }, clearTimeout() {}, setInterval() { return { unref() {} }; }, clearInterval() {}, setImmediate() {},
        require: (name) => (name === 'image-size') ? { imageSize() { return { width: 16, height: 16 }; } } : serverRequire(name)
    };
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox, { filename: multiplexPath });
    assert.strictEqual(typeof sandbox.CreateDesktopMultiplexor, 'function', 'CreateDesktopMultiplexor must be defined');
    return sandbox.CreateDesktopMultiplexor;
}

function fakeSocket() {
    return { bytesRead: 0, bytesWritten: 0, paused: false, pause() { this.paused = true; }, resume() { this.paused = false; }, setKeepAlive() {}, destroy() {} };
}

// An agent whose writes complete only when the test says so.
function slowAgent() {
    const ws = new EventEmitter();
    ws._socket = fakeSocket();
    ws.sent = [];
    ws.pending = [];
    ws.send = (data, cb) => { ws.sent.push(Buffer.isBuffer(data) ? data.toString('hex') : String(data)); ws.pending.push(cb); };
    ws.complete = () => { const cb = ws.pending.shift(); assert(cb, 'no write in flight'); cb(); };
    ws.close = () => {};
    return { req: { query: {} }, ws, close() {} };
}

function viewer(name) {
    const ws = new EventEmitter();
    ws._socket = fakeSocket();
    ws.send = (data, cb) => { if (cb) { cb(); } };
    ws.close = () => {};
    return { req: { query: { browser: 1 } }, user: { _id: 'user//' + name, name }, ws, close() {} };
}

function makeSession() {
    const events = [];
    const debug = [];
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } }, users: {}, meshes: {}, wsagents: {}, userGroups: {}, desktoprelays: {},
        db: { Get(id, cb) { cb(null, [{ meshid: 'mesh//group', name: 'device', icon: 1 }]); }, SetUser() {} }, common: { zeroPad: (n) => String(n) },
        parent: { debug(area, message) { debug.push(message); }, DispatchEvent(targets, source, event) { events.push(event); }, args: {} }
    };
    let mux = null;
    loadMultiplexor()(parent, { id: '' }, 'node//device', 'session', (created) => { mux = created; });
    assert(mux, 'multiplexor created');
    return { mux, events, debug };
}

function agentBacklog() {
    const { mux, debug, events } = makeSession();
    const viewers = [viewer('a'), viewer('b')];
    for (const v of viewers) { assert.strictEqual(mux.addPeer(v), true); }
    const agent = slowAgent();
    assert.strictEqual(mux.addPeer(agent), true);
    return { mux, debug, events, viewers, agent };
}

const report = { multiplexPath };
const { results, failed } = runCases('meshcentral_agent_send_queue_contract', {
    writesAreSerialisedInOrder() {
        const { mux, agent } = agentBacklog();
        const first = agent.ws.sent.length;
        assert.strictEqual(agent.ws.pending.length, 1, 'the connect message is in flight');
        for (let i = 0; i < 5; ++i) { mux.sendToAgent('q' + i); }
        assert.strictEqual(agent.ws.sent.length, first, 'nothing more is written while a write is in flight');
        assert.strictEqual(mux.agent.sendQueue.length, 5);
        while (agent.ws.pending.length) { agent.ws.complete(); }
        assert.deepStrictEqual(agent.ws.sent.slice(first), ['q0', 'q1', 'q2', 'q3', 'q4'], 'queued writes go out one at a time, in order');
        assert.strictEqual(mux.agent.sending, false, 'the agent is idle once the queue drains');
    },
    backlogOverTenPausesViewersAndDrainResumes() {
        const { mux, debug, viewers, agent } = agentBacklog();
        for (let i = 0; i < 10; ++i) { mux.sendToAgent('b' + i); }
        assert.strictEqual(mux.agent.sendQueue.length, 10);
        assert(viewers.every((v) => v.ws._socket.paused === false), 'a backlog of 10 does not pause viewers');
        mux.sendToAgent('b10');
        assert.strictEqual(mux.agent.overflow, true, 'a backlog over 10 sets overflow');
        assert(viewers.every((v) => v.paused === true && v.ws._socket.paused === true), 'every viewer socket is paused');
        assert(debug.some((line) => line.includes('Pausing viewers, agent send backlog=11')), 'the pause is logged with the backlog');
        agent.ws.complete();
        assert(viewers.every((v) => v.ws._socket.paused === true), 'viewers stay paused while the queue is not empty');
        while (agent.ws.pending.length) { agent.ws.complete(); }
        assert.strictEqual(mux.agent.sendQueue.length, 0);
        assert.strictEqual(mux.agent.overflow, false, 'overflow clears when the queue drains');
        assert(viewers.every((v) => v.paused === false && v.ws._socket.paused === false), 'every viewer socket is resumed');
    },
    lateCompletionFromReplacedAgentIsIgnored() {
        const { mux, agent } = agentBacklog();
        mux.sendToAgent('old');
        const staleCompletion = agent.ws.pending.shift(); // The first agent's write never completed.
        const replacement = slowAgent();
        replacement.sending = true;
        replacement.overflow = false;
        replacement.sendQueue = ['new0', 'new1'];
        replacement.paused = false;
        mux.agent = replacement; // The session moved to another agent tunnel.
        staleCompletion();
        assert.deepStrictEqual(replacement.ws.sent, [], 'the old agent completion must not send from the new queue');
        assert.deepStrictEqual(replacement.sendQueue, ['new0', 'new1']);
        assert.strictEqual(replacement.sending, true, 'the new agent keeps its in-flight state');
    },
    departingViewerCountsAgentOutTraffic() {
        const { mux, events, viewers, agent } = agentBacklog();
        while (agent.ws.pending.length) { agent.ws.complete(); }
        const [leaving] = viewers;
        leaving.ws._socket.bytesRead = 10;
        leaving.ws._socket.bytesWritten = 20;
        leaving.agentInTraffic = 100;
        leaving.agentOutTraffic = 500;
        mux.removePeer(leaving);
        const left = events.find((event) => event.msgid === 144);
        assert(left, 'leaving the session is logged');
        assert.strictEqual(left.bytesin, 110, 'bytes in = viewer bytes read + its agent-in share');
        assert.strictEqual(left.bytesout, 520, 'bytes out = viewer bytes written + its agent-out share');
    }
});
report.cases = results;
report.failed = failed;

const evidenceDir = evidenceDirFromArgs(process.argv);
if (evidenceDir) {
    writeEvidence(evidenceDir, 'meshcentral_agent_send_queue_contract', report, [
        'MULTIPLEX_PATH=' + multiplexPath,
        'SUCCESS=' + (failed === 0)
    ]);
}
