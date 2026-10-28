// Exercise the desktop multiplexor relay lifecycle with controllable timers, DB and fs completions.
// Covers: peers waiting on a multiplexor that is being created (S9: a callback list, no polling), agent
// liveness by WebSocket ping/pong (S9: no silence or stall thresholds, one agent per session), cookie
// expire timer cleanup, recording descriptors opened for a session that already ended, recording write
// errors (S8), and table entry ownership.
// No server, endpoint session, credentials, or real user input is needed.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const EventEmitter = require('events');
const { createRequire } = require('module');
const { forkFile } = require('./lib/meshcentral_paths');

const sourcePath = path.resolve(process.argv[2] || forkFile('meshdesktopmultiplex.js'));
let now = 1000000;
const timers = [];
const sandbox = {
    module: { exports: {} }, Buffer, console,
    setTimeout(fn, ms) { const t = { fn, ms, interval: false, cleared: false }; timers.push(t); return t; },
    clearTimeout(t) { if (t) t.cleared = true; },
    setInterval(fn, ms) { const t = { fn, ms, interval: true, cleared: false, unref() { t.unrefd = true; } }; timers.push(t); return t; },
    clearInterval(t) { if (t) t.cleared = true; },
    setImmediate(fn) { const t = { fn, ms: 0, interval: false, cleared: false }; timers.push(t); return t; },
};
class FakeDate extends Date { constructor(...a) { super(...(a.length ? a : [now])); } static now() { return now; } }
sandbox.Date = FakeDate;
sandbox.require = createRequire(sourcePath); // So './mcrec.js' (the tile size reader) is the fork's.
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath });

function runOnce() { const pending = timers.filter(t => !t.cleared && !t.interval); for (const t of pending) { t.cleared = true; t.fn(); } return pending.length; }

function makeParent(opts) {
    opts = opts || {};
    const writes = [], opens = [], closedFds = [], events = [], debugLines = [];
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } }, relaySessionCount: 0, relaySessionErrorCount: 0,
        parent: {
            args: opts.args || {}, debug(category, text) { debugLines.push(category + ': ' + text); }, DispatchEvent(targets, source, event) { events.push({ targets, event }); }, AddEventDispatch() {}, RemoveAllEventDispatch() {},
            decodeCookie() { return { ruserid: 'user/test/u', nodeid: 'node/test/device' }; },
            fs: {
                mkdirSync() {}, open(f, m, cb) { opens.push({ f, cb }); if (opts.openSync) { cb(null, 9); } },
                write(fd, block, off, len, cb) { writes.push({ fd, len, cb }); if (opts.writeSync) { cb(null, len); } },
                close(fd) { closedFds.push(fd); }
            },
            path: path, recordpath: '/rec', certificateOperations: { acceleratorPerformOperation() {} }
        },
        common: { zeroPad(n) { return String(n); } },
        db: { Get(id, cb) { if (opts.dbGet) { opts.dbGet(id, cb); } else { cb(null, [{ meshid: 'mesh/test/group', name: 'test', icon: 1 }]); } }, SetUser() {} },
        users: {}, wsagents: {}, meshes: {}, desktoprelays: {}, userGroups: {}
    };
    return { parent, writes, opens, closedFds, events, debugLines };
}

function fakeWs() {
    const ws = new EventEmitter();
    ws._socket = { bytesRead: 0, bytesWritten: 0, paused: false, setKeepAlive() {}, pause() { this.paused = true; }, resume() { this.paused = false; }, destroy() { this.destroyed = true; } };
    ws.closed = false;
    ws.close = () => { ws.closed = true; };
    ws.send = (d, cb) => { if (cb) cb(); };
    ws.pings = 0;
    ws.ping = () => { ws.pings++; };
    return ws;
}

function agentRelay(parent, domain, id) {
    const ws = fakeWs();
    const req = { query: { id: id || 'sess', nodeid: 'node/test/device', p: '2', rauth: 'x' }, clientIp: '127.0.0.1' };
    const relay = sandbox.CreateMeshRelayEx2(parent, ws, req, domain || { id: '' }, null, null);
    return { ws, relay, req };
}

function viewerRelay(parent) {
    const ws = fakeWs();
    const req = { query: { id: 'sess', nodeid: 'node/test/device', p: '2', rauth: 'x', browser: 1 }, clientIp: '127.0.0.1' };
    const relay = sandbox.CreateMeshRelayEx2(parent, ws, req, { id: '' }, null, null);
    return { ws, relay, req };
}

const NODE = { meshid: 'mesh/test/group', name: 't', icon: 1 };
const liveTimers = () => timers.filter(t => !t.cleared);
const heartbeat = () => { const beats = timers.filter(t => t.interval && !t.cleared); assert.strictEqual(beats.length, 1, 'one agent ping interval'); return beats[0]; };

function recordingViewer(mux) {
    const viewer = { req: { query: { browser: 1 } }, user: { _id: 'user/test/v', name: 'v', flags: 2 }, ws: fakeWs(), close() { this.closed = true; mux.removePeer(this); } };
    viewer.deskMultiplexor = mux;
    return viewer;
}

const tests = {
    'a message arriving while the multiplexor is being created must not throw'() {
        const { parent } = makeParent({ dbGet() { /* never completes */ } });
        agentRelay(parent, { id: '' });
        assert.strictEqual(parent.desktoprelays['node/test/device'], 1, 'creation pending marker set');
        const waiter = viewerRelay(parent);
        assert.strictEqual(waiter.relay.deskMultiplexor, undefined, 'a waiting peer is not attached yet');
        assert.doesNotThrow(() => waiter.ws.emit('message', Buffer.from([0, 1, 0, 4])));
    },
    'peers arriving during a slow creation wait without polling and join when it completes'() {
        let complete = null;
        const { parent } = makeParent({ dbGet(id, cb) { complete = cb; } });
        const agent = agentRelay(parent, { id: '' });
        const viewers = [viewerRelay(parent), viewerRelay(parent)];
        const leaver = viewerRelay(parent);
        leaver.ws.emit('close'); // Gives up while waiting
        now += 600000; // However long the creation takes, nothing expires and nothing polls.
        assert.deepStrictEqual(liveTimers(), [], 'no retry or watchdog timer while waiting');
        assert.strictEqual(parent.desktoprelays['node/test/device'], 1);
        complete(null, [NODE]);
        const mux = parent.desktoprelays['node/test/device'];
        assert(mux && typeof mux == 'object', 'the created multiplexor is installed');
        assert.strictEqual(mux.agent, agent.relay, 'the creating agent joined');
        assert.deepStrictEqual(Array.from(mux.viewers), viewers.map(v => v.relay), 'every waiting viewer joined, in order');
        for (const peer of [agent].concat(viewers)) {
            assert.strictEqual(peer.relay.deskMultiplexor, mux);
            assert.strictEqual(peer.ws.closed, false);
        }
        assert.strictEqual(leaver.relay.deskMultiplexor, undefined, 'a peer that left while waiting is not attached');
    },
    'a creating peer that leaves does not stop the peers still waiting'() {
        let complete = null;
        const { parent } = makeParent({ dbGet(id, cb) { complete = cb; } });
        const creator = viewerRelay(parent);
        const agent = agentRelay(parent, { id: '' });
        creator.ws.emit('close');
        complete(null, [NODE]);
        const mux = parent.desktoprelays['node/test/device'];
        assert(mux && typeof mux == 'object');
        assert.strictEqual(mux.agent, agent.relay);
        assert.strictEqual(mux.viewers.length, 0);
    },
    'a creation where every peer left leaves no multiplexor behind'() {
        let complete = null;
        const { parent } = makeParent({ dbGet(id, cb) { complete = cb; } });
        const a = agentRelay(parent, { id: '' }), v = viewerRelay(parent);
        a.ws.emit('close'); v.ws.emit('close');
        complete(null, [NODE]);
        assert.strictEqual(parent.desktoprelays['node/test/device'], undefined);
    },
    'a failed creation closes every waiting peer and frees the node'() {
        let complete = null, calls = 0;
        const { parent } = makeParent({ dbGet(id, cb) { if (calls++ == 0) { complete = cb; } else { cb(null, [NODE]); } } });
        const peers = [agentRelay(parent, { id: '' }), viewerRelay(parent), viewerRelay(parent)];
        complete(new Error('db unavailable'), null);
        for (const peer of peers) { assert.strictEqual(peer.ws.closed, true); }
        assert.strictEqual(parent.desktoprelays['node/test/device'], undefined, 'the node is free again');
        const next = agentRelay(parent, { id: '' });
        assert.strictEqual(parent.desktoprelays['node/test/device'].agent, next.relay, 'the next connection creates a multiplexor');
    },
    'a second agent tunnel is refused however long the agent has been silent'() {
        // Replaces "a silent agent is replaced" (TST-17): there is no silence or stall threshold. A session
        // gets a new agent only after its agent closed or failed, and that ends the session.
        const { parent } = makeParent();
        const first = agentRelay(parent, { id: '' });
        const mux = parent.desktoprelays['node/test/device'];
        const viewer = viewerRelay(parent);
        now += 3600000;
        const second = agentRelay(parent, { id: '' });
        assert.strictEqual(second.ws.closed, true, 'the second tunnel is closed');
        assert.strictEqual(mux.agent, first.relay, 'the session keeps its agent');
        assert.strictEqual(first.ws.closed, false);
        assert.deepStrictEqual(Array.from(mux.viewers), [viewer.relay]);
        first.ws.emit('close');
        assert.strictEqual(viewer.ws.closed, true, 'the agent closing ends the session');
        const third = agentRelay(parent, { id: '' });
        const next = parent.desktoprelays['node/test/device'];
        assert.notStrictEqual(next, mux, 'a new tunnel after the close starts a new session');
        assert.strictEqual(next.agent, third.relay);
    },
    'an agent that does not answer a ping is closed and its session ends'() {
        const { parent } = makeParent({ args: { agentidletimeout: 150000 } });
        const agent = agentRelay(parent, { id: '' });
        const viewer = viewerRelay(parent);
        const mux = parent.desktoprelays['node/test/device'];
        const beat = heartbeat();
        assert.strictEqual(beat.ms, 150000, 'pinged every --agentidletimeout');
        beat.fn();
        assert.strictEqual(agent.ws.pings, 1);
        agent.ws.emit('pong');
        beat.fn();
        assert.strictEqual(agent.ws.pings, 2, 'an answered ping is followed by the next one');
        assert.strictEqual(agent.ws.closed, false);
        beat.fn(); // The second ping was not answered
        assert.strictEqual(agent.ws._socket.destroyed, true, 'the unresponsive agent socket is destroyed');
        assert.strictEqual(viewer.ws.closed, true, 'the session ends');
        assert.strictEqual(mux.viewers, undefined);
        assert.strictEqual(parent.desktoprelays['node/test/device'], undefined);
        assert.strictEqual(beat.cleared, true, 'the ping interval stops with the session');
        assert.strictEqual(viewer.ws.pings, 0, 'viewers are not pinged');
    },
    'no ping is judged while flow control has paused the agent'() {
        const { parent } = makeParent({ args: { agentidletimeout: 150000 } });
        const agent = agentRelay(parent, { id: '' });
        const viewer = viewerRelay(parent);
        const mux = parent.desktoprelays['node/test/device'];
        const beat = heartbeat();
        beat.fn(); // Ping sent, not yet answered
        const held = [];
        viewer.ws.send = (d, cb) => { if (cb) held.push(cb); };
        for (let i = 0; i < 8; i++) { mux.sendToViewer(viewer.relay, Buffer.from([0, 88, 0, 5, i])); }
        held.shift()(); // The first send completes with the rest still queued
        assert.strictEqual(agent.relay.paused, true, 'the only viewer backs up, so reading from the agent is paused');
        for (let i = 0; i < 3; i++) { beat.fn(); }
        assert.strictEqual(agent.ws.closed, false, 'a pong cannot be read while paused, so the agent is not judged');
        assert.strictEqual(agent.ws.pings, 1, 'and not pinged');
        while (held.length) { held.shift()(); }
        assert.strictEqual(agent.relay.paused, false);
        beat.fn();
        assert.strictEqual(agent.ws.closed, false, 'the ping sent before the pause is not held against the agent');
        assert.strictEqual(agent.ws.pings, 2);
        agent.ws.emit('pong');
        beat.fn();
        assert.strictEqual(agent.ws.closed, false);
    },
    'with --agentidletimeout 0 the agent is not pinged'() {
        const { parent } = makeParent({ args: { agentidletimeout: 0 } });
        agentRelay(parent, { id: '' });
        assert(parent.desktoprelays['node/test/device'].agent);
        assert.deepStrictEqual(timers.filter(t => t.interval && !t.cleared), []);
    },
    'closing a relay clears its cookie expire timer'() {
        const { parent } = makeParent();
        const ws = fakeWs();
        const req = { query: { id: 'sess', nodeid: 'node/test/device', p: '2', rauth: 'x' }, clientIp: '127.0.0.1' };
        sandbox.CreateMeshRelayEx2(parent, ws, req, { id: '' }, null, { expire: now + 3600000 });
        const expire = timers.filter(t => !t.interval && !t.cleared && t.ms == 3600000);
        assert.strictEqual(expire.length, 1, 'expire timer armed');
        ws.emit('close');
        assert.strictEqual(expire[0].cleared, true, 'expire timer must be cleared on close');
    },
    'recording file opened for a viewer that already left is closed, not leaked'() {
        const { parent, opens, closedFds } = makeParent({ writeSync: true });
        const domain = { id: '', sessionrecording: { onlyselectedusers: true } };
        let mux = null;
        sandbox.CreateDesktopMultiplexor(parent, domain, 'node/test/device', 'sess', m => { mux = m; });
        assert(mux);
        parent.desktoprelays['node/test/device'] = mux;
        const viewer = recordingViewer(mux);
        assert.strictEqual(mux.addPeer(viewer), true);
        assert.strictEqual(opens.length, 1, 'recording file open requested');
        viewer.close(); // last viewer leaves, the session is disposed while the file is still opening
        assert.strictEqual(mux.viewers, undefined, 'disposed');
        opens[0].cb(null, 9);
        assert(closedFds.indexOf(9) >= 0, 'descriptor must be closed when the session is already gone');
        assert(mux.recordingFile == null, 'no recording may be attached to a disposed session');
    },
    'recording header still writing when the session ends closes the descriptor'() {
        const { parent, writes, closedFds } = makeParent({ openSync: true });
        const domain = { id: '', sessionrecording: { onlyselectedusers: true } };
        let mux = null;
        sandbox.CreateDesktopMultiplexor(parent, domain, 'node/test/device', 'sess', m => { mux = m; });
        parent.desktoprelays['node/test/device'] = mux;
        const viewer = recordingViewer(mux);
        mux.addPeer(viewer);
        assert.strictEqual(writes.length, 1, 'header write in flight');
        viewer.close();
        assert.strictEqual(mux.viewers, undefined);
        const w = writes.shift(); w.cb(null, w.len);
        assert(closedFds.indexOf(9) >= 0, 'descriptor closed after the late header write');
        assert(mux.recordingFile == null, 'no recording attached after late header write');
    },
    'a recording write error stops the recording, closes the file once and raises an event'() {
        const { parent, writes, closedFds, events } = makeParent({ openSync: true });
        const domain = { id: '', sessionrecording: { onlyselectedusers: true } };
        let mux = null;
        sandbox.CreateDesktopMultiplexor(parent, domain, 'node/test/device', 'sess', m => { mux = m; });
        parent.desktoprelays['node/test/device'] = mux;
        const viewer = recordingViewer(mux), out = [];
        viewer.ws.send = (d, cb) => { out.push(d); if (cb) cb(); };
        mux.addPeer(viewer);
        const header = writes.shift(); header.cb(null, header.len);
        assert.strictEqual(out[0], 'cr', 'the viewer is told the session is recorded');
        const agent = { req: { query: {} }, ws: fakeWs(), deskMultiplexor: mux, close() {} };
        mux.addPeer(agent);
        for (let i = 0; i < 70; i++) { mux.processData(agent, Buffer.from([0, 88, 0, 5, i])); }
        assert.strictEqual(agent.paused, true, 'a backed up recording queue pauses the agent');
        const failed = writes.shift();
        failed.cb(Object.assign(new Error('EIO: i/o error, write'), { code: 'EIO' }), 0);
        assert.deepStrictEqual(closedFds, [9], 'the recording file is closed');
        assert.strictEqual(mux.recordingFile, null, 'the session is no longer recorded');
        assert.strictEqual(mux.recordingQueue.length, 0, 'queued blocks for the failed file are dropped');
        assert.strictEqual(writes.length, 0, 'nothing more is written to the failed file');
        assert.strictEqual(agent.paused, false, 'the agent is no longer held for the recording');
        const failure = events.filter(e => /write error/.test(e.event.msg || ''));
        assert.strictEqual(failure.length, 1, 'one failure event');
        assert.strictEqual(failure[0].event.nodeid, 'node/test/device');
        assert(/EIO/.test(failure[0].event.msg) && /\.mcrec$/.test(failure[0].event.filename), JSON.stringify(failure[0].event));
        assert(failure[0].targets.indexOf('recording') >= 0);
        mux.processData(agent, Buffer.from([0, 88, 0, 5, 99]));
        assert.strictEqual(writes.length, 0, 'later agent data is not recorded');
        viewer.close();
        assert.deepStrictEqual(closedFds, [9], 'disposing the session does not close the file again');
        assert.strictEqual(writes.length, 0, 'no end block is written to the failed file');
        assert(!events.some(e => e.event.msgid === 146), 'no finished recording event for a failed recording');
    },
    'a failed recording header write leaves the viewer connected and unrecorded'() {
        const { parent, writes, closedFds, events } = makeParent({ openSync: true });
        const domain = { id: '', sessionrecording: { onlyselectedusers: true } };
        let mux = null;
        sandbox.CreateDesktopMultiplexor(parent, domain, 'node/test/device', 'sess', m => { mux = m; });
        parent.desktoprelays['node/test/device'] = mux;
        const viewer = recordingViewer(mux), out = [];
        viewer.ws.send = (d, cb) => { out.push(d); if (cb) cb(); };
        mux.addPeer(viewer);
        const header = writes.shift(); header.cb(null, 0); // A write that reports no bytes written is a failure
        assert.strictEqual(out[0], 'c', 'the viewer connects without the recording flag');
        assert.strictEqual(mux.recordingFile, null);
        assert.deepStrictEqual(closedFds, [9]);
        assert.strictEqual(events.filter(e => /write error/.test(e.event.msg || '')).length, 1);
    },
    'screen size packets are not debug-logged one by one'() {
        const { parent, debugLines } = makeParent();
        let mux = null;
        sandbox.CreateDesktopMultiplexor(parent, { id: '' }, 'node/test/device', 'sess', m => { mux = m; });
        const viewer = recordingViewer(mux);
        mux.addPeer(viewer);
        runOnce();
        debugLines.length = 0;
        for (let i = 0; i < 50; i++) { mux.processAgentData(Buffer.from([0, 7, 0, 8, 0, 16, 0, (i % 2) ? 32 : 16])); }
        assert.deepStrictEqual(debugLines, [], 'screen packets, resized or not, add no debug lines');
        assert.strictEqual(mux.height, 32, 'the last packet (32 high) is applied');
    },
    'desktop audio availability reaches current viewers and viewers that join later'() {
        const { parent } = makeParent();
        let mux = null;
        sandbox.CreateDesktopMultiplexor(parent, { id: '' }, 'node/test/device', 'sess', m => { mux = m; });
        parent.desktoprelays['node/test/device'] = mux;
        const sent = v => { const out = []; v.ws.send = (d, cb) => { out.push(typeof d == 'string' ? d : null); if (cb) cb(); }; return out; };
        const first = recordingViewer(mux), firstOut = sent(first);
        mux.addPeer(first);
        runOnce();
        const available = '{"ctrlChannel":"102938","type":"audio","state":"available","protocol":20}';
        mux.processAgentData('{"ctrlChannel":"102938","type":"audio","state":"started"}');
        mux.processAgentData('{"ctrlChannel":"102938","type":"webrtc0"}');
        mux.processAgentData(available);
        assert.deepStrictEqual(firstOut.filter(d => d && d.indexOf('"audio"') >= 0), [available], 'only the availability message is forwarded');
        const late = recordingViewer(mux), lateOut = sent(late);
        mux.addPeer(late);
        runOnce();
        assert(lateOut.indexOf(available) >= 0, 'a viewer joining later receives the cached availability message');
        const agent = { req: { query: {} }, ws: fakeWs(), deskMultiplexor: mux };
        assert.strictEqual(mux.addPeer(agent), true);
        now += 3600000;
        assert.strictEqual(mux.addPeer({ req: { query: {} }, ws: fakeWs(), deskMultiplexor: mux }), false, 'a second agent tunnel is refused');
        assert.strictEqual(mux.lastAudioMessage, available, 'the session keeps its agent and its audio offer');
    },
    'a peer closing on a disposed multiplexor does not remove a newer one for the same node'() {
        const { parent } = makeParent();
        const a = agentRelay(parent, { id: '' });
        const muxA = parent.desktoprelays['node/test/device'];
        assert(muxA && typeof muxA == 'object');
        const muxB = { marker: 'B' }; // A newer multiplexor has taken the slot
        parent.desktoprelays['node/test/device'] = muxB;
        a.ws.emit('close');
        assert.strictEqual(muxA.viewers, undefined, 'old multiplexor disposed');
        assert.strictEqual(parent.desktoprelays['node/test/device'], muxB, 'newer multiplexor must survive');
    }
};

let failed = 0;
for (const name of Object.keys(tests)) {
    timers.length = 0;
    try { tests[name](); console.log('PASS ' + name); }
    catch (ex) { failed++; console.error('FAIL ' + name + ': ' + (ex.stack || ex).toString().split('\n').slice(0, 3).join('\n  ')); }
}
console.log(JSON.stringify({ sourcePath, total: Object.keys(tests).length, failed }));
process.exitCode = failed ? 1 : 0;
