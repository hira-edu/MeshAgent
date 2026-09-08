// Exercise the actual multiplexer with controllable WebSocket send completions.
// No server, endpoint session, credentials, or real user input is needed.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const sourcePath = path.resolve(process.argv[2] || '../MeshCentral/meshdesktopmultiplex.js');
const sandbox = { require, module: { exports: {} }, Buffer, console, setTimeout, clearTimeout, setInterval, clearInterval };
// Only dimensions affect the linked image cache in these flow-control cases.
sandbox.require = name => name === 'image-size' ? { imageSize() { return { width: 16, height: 16 }; } } : require(name);
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath });

function createHarness() {
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } },
        parent: { debug() {}, DispatchEvent() {} },
        db: { Get(id, cb) { cb(null, [{ meshid: 'mesh/test/group', name: 'test', icon: 1 }]); } },
        users: {}, wsagents: {}, meshes: {}
    };
    const mux = sandbox.CreateDesktopMultiplexor(parent, { id: '' }, 'node/test/device', 'test', () => {});
    function peer(browser) {
        const callbacks = [];
        const sent = [];
        const socket = { paused: false, pauses: 0, resumes: 0, bytesRead: 0, bytesWritten: 0,
            pause() { this.paused = true; this.pauses++; },
            resume() { this.paused = false; this.resumes++; } };
        return { req: { query: browser ? { browser: 1 } : {} }, user: { _id: 'user/test/viewer', name: 'viewer' },
            ws: { _socket: socket, send(data, cb) { sent.push(data); if (cb) callbacks.push(cb); } },
            sent,
            closed: false, close() { this.closed = true; },
            drainOne() { const cb = callbacks.shift(); if (cb) cb(); },
            drain() {
                let count = 0;
                while (callbacks.length && count++ < 1000) this.drainOne();
                assert.strictEqual(callbacks.length, 0, 'send queue must reach idle');
            }
        };
    }
    const slow = peer(true), agent = peer(false);
    mux.addPeer(slow); slow.drain(); mux.addPeer(agent); agent.drain(); slow.drain();
    function overflow(viewer) {
        for (let i = 0; i < 9; i++) mux.sendToViewer(viewer, Buffer.from([0, 88, 0, 5, i]));
        viewer.drainOne();
        assert.strictEqual(viewer.overflow, true);
    }
    function join() { const viewer = peer(true); mux.addPeer(viewer); viewer.drain(); agent.drain(); return viewer; }
    function screen(withPicture) {
        mux.processAgentData(Buffer.from([0, 7, 0, 8, 0, 16, 0, 16]));
        if (withPicture) mux.processAgentData(Buffer.from([0, 3, 0, 10, 0, 0, 0, 0, 1, 2]));
        slow.drain();
    }
    return { mux, agent, slow, overflow, join, screen, parent };
}

const tests = {
    'queued input pauses viewers and drains once in order'() {
        const { mux, agent, slow, join } = createHarness();
        const fast = join();
        agent.sent.length = 0;
        const commands = Array.from({ length: 12 }, (_, i) => Buffer.from([0, 88, 0, 5, i]));
        for (const command of commands) mux.sendToAgent(command);
        assert.strictEqual(agent.sent.length, 1, 'only one agent write may be in flight');
        assert.strictEqual(agent.sendQueue.length, 11);
        assert.strictEqual(agent.overflow, true, 'queue length must trigger input backpressure');
        for (const viewer of [slow, fast]) assert.strictEqual(viewer.ws._socket.paused, true);
        agent.drainOne();
        assert.strictEqual(agent.sent.length, 2);
        for (const viewer of [slow, fast]) assert.strictEqual(viewer.ws._socket.paused, true, 'input must stay paused until the queue drains');
        agent.drain();
        assert.deepStrictEqual(agent.sent, commands, 'every command must be sent exactly once in order');
        assert.strictEqual(agent.sending, false);
        assert.strictEqual(agent.overflow, false);
        for (const viewer of [slow, fast]) assert.strictEqual(viewer.ws._socket.paused, false);
    },
    'healthy reconnect resumes a stream held at a screen reset by a slow viewer'() {
        const { mux, agent, slow, overflow, join, screen } = createHarness();
        screen(false);
        overflow(slow);
        assert.strictEqual(agent.paused, true, 'all viewers backing up must pause the producer');
        for (let i = 0; i < 3; i++) {
            const fast = join();
            assert.strictEqual(fast.overflow, false);
            assert.strictEqual(agent.paused, false, 'a new healthy viewer must resume the producer');
            assert.strictEqual(agent.ws._socket.paused, false);
            assert.strictEqual(mux.viewersOverflowCount, 1);
            mux.removePeer(fast);
            assert.strictEqual(agent.paused, true, 'removing the only healthy viewer must restore backpressure');
        }
        slow.drain();
        assert.strictEqual(agent.paused, false, 'draining the remaining slow viewer must resume');
        assert.strictEqual(mux.viewersOverflowCount, 0);
    },
    'reconnecting with an existing picture cache still drains and resumes'() {
        const { mux, agent, slow, overflow, join, screen } = createHarness();
        screen(true);
        overflow(slow);
        assert.strictEqual(agent.paused, true);
        const fast = join();
        assert.strictEqual(agent.paused, false);
        assert.strictEqual(fast.dataPtr, null);
        assert.strictEqual(fast.overflow, false);
        assert.strictEqual(mux.viewersOverflowCount, 1);
    },
    'removing the fastest viewer pauses the remaining overloaded viewers'() {
        const { mux, agent, slow, overflow, join } = createHarness();
        const fast = join();
        overflow(slow);
        assert.strictEqual(agent.paused, false);
        mux.removePeer(fast);
        assert.strictEqual(agent.paused, true);
        assert.strictEqual(agent.ws._socket.paused, true);
        slow.drain();
        assert.strictEqual(agent.paused, false);
    },
    'joining does not resume while a recording write is pending'() {
        const { mux, agent, slow, overflow, join } = createHarness();
        overflow(slow);
        mux.recordingFileWriting = true;
        join();
        assert.strictEqual(agent.paused, true);
        // processData's recording completion clears the flag and reevaluates flow.
        mux.processData(agent, Buffer.from([0, 88, 0, 5, 0]));
        assert.strictEqual(mux.recordingFileWriting, false);
        assert.strictEqual(agent.paused, false);
    },
    'duplicate adds and removes preserve overflow accounting'() {
        const { mux, agent, slow, overflow, join } = createHarness();
        const fast = join();
        overflow(slow);
        mux.addPeer(fast);
        assert.strictEqual(mux.viewers.length, 2);
        mux.removePeer(slow);
        assert.strictEqual(mux.viewersOverflowCount, 0);
        assert.strictEqual(agent.paused, false);
        assert.strictEqual(mux.removePeer(slow), false);
        assert.strictEqual(mux.viewersOverflowCount, 0);
        mux.removePeer(fast);
        assert.strictEqual(agent.closed, true);
    },
    'agent disconnect closes every viewer despite synchronous removal callbacks'() {
        for (const count of [2, 3, 4]) {
            const { mux, agent, slow, join } = createHarness();
            const viewers = [slow];
            while (viewers.length < count) viewers.push(join());
            // CreateMeshRelayEx2.close synchronously removes itself from the mux.
            for (const viewer of viewers) viewer.close = function () {
                assert.strictEqual(this.closed, false, 'a viewer must close only once');
                this.closed = true;
                mux.removePeer(this);
            };
            // Closing the final viewer can reenter the agent's close path.
            agent.close = function () { this.closed = true; mux.removePeer(this); };
            mux.removePeer(agent);
            assert(viewers.every(viewer => viewer.closed), 'no viewer may remain connected to the disposed image cache');
            assert.strictEqual(mux.viewers, undefined);
            assert.strictEqual(mux.agent, null);
        }
    },
    'expired or invalid relay cookies close without throwing or granting a session'() {
        for (const decoded of [null, undefined, {}]) {
            let closed = false;
            const parent = { trafficStats: {}, relaySessionCount: 0,
                parent: { decodeCookie() { return decoded; }, debug() {} } };
            const ws = { _socket: {}, close() { closed = true; } };
            sandbox.CreateMeshRelayEx2(parent, ws,
                { query: { id: 'test', nodeid: 'node/test/device', rauth: 'invalid' }, clientIp: '127.0.0.1' },
                { id: '' }, null, null);
            assert.strictEqual(closed, true);
            assert.strictEqual(parent.relaySessionCount, 0);
        }
    },
    'a rejected duplicate agent relay closes without disturbing the shared session'() {
        const { mux, agent, slow, parent } = createHarness();
        parent.parent.args = {};
        parent.parent.decodeCookie = () => ({ ruserid: 'user/test/viewer', nodeid: mux.nodeid });
        parent.desktoprelays = { [mux.nodeid]: mux };
        parent.relaySessionCount = 0;
        const ws = new (require('events').EventEmitter)();
        ws._socket = { bytesRead: 0, bytesWritten: 0, setKeepAlive() {}, resume() {} };
        ws.closed = false;
        ws.close = () => { ws.closed = true; };
        sandbox.CreateMeshRelayEx2(parent, ws,
            { query: { id: 'duplicate', nodeid: mux.nodeid, rauth: 'test' }, clientIp: '127.0.0.1' },
            { id: '' }, null, null);
        assert.strictEqual(ws.closed, true, 'the rejected socket must not remain attached to the multiplexer');
        assert.strictEqual(parent.relaySessionCount, 0);
        assert.strictEqual(mux.agent, agent);
        assert.strictEqual(mux.viewers.length, 1);
        assert.strictEqual(slow.closed, false);
        assert.strictEqual(parent.desktoprelays[mux.nodeid], mux);
    }
};
let failed = 0;
for (const [name, test] of Object.entries(tests)) {
    try { test(); console.log('PASS ' + name); }
    catch (error) { failed++; console.error('FAIL ' + name + ': ' + error.message); }
}
console.log(JSON.stringify({ sourcePath, total: Object.keys(tests).length, failed }));
process.exitCode = failed ? 1 : 0;
