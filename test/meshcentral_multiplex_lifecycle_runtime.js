// Exercise the desktop multiplexor relay lifecycle with controllable timers, DB and fs completions.
// Covers: pending-creation marker handling, late creation results, cookie expire timer cleanup,
// recording descriptors opened for a session that already ended, and table entry ownership.
// No server, endpoint session, credentials, or real user input is needed.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const EventEmitter = require('events');

const sourcePath = path.resolve(process.argv[2] || path.join(__dirname, '..', '..', 'MeshCentral', 'meshdesktopmultiplex.js'));
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
sandbox.require = name => name === 'image-size' ? { imageSize() { return { width: 16, height: 16 }; } } : require(name);
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath });

function runOnce() { const pending = timers.filter(t => !t.cleared && !t.interval); for (const t of pending) { t.cleared = true; t.fn(); } return pending.length; }

function makeParent(opts) {
    opts = opts || {};
    const writes = [], opens = [], closedFds = [];
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } }, relaySessionCount: 0, relaySessionErrorCount: 0,
        parent: {
            args: {}, debug() {}, DispatchEvent() {}, AddEventDispatch() {}, RemoveAllEventDispatch() {},
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
    return { parent, writes, opens, closedFds };
}

function fakeWs() {
    const ws = new EventEmitter();
    ws._socket = { bytesRead: 0, bytesWritten: 0, paused: false, setKeepAlive() {}, pause() { this.paused = true; }, resume() { this.paused = false; }, destroy() { this.destroyed = true; } };
    ws.closed = false;
    ws.close = () => { ws.closed = true; };
    ws.send = (d, cb) => { if (cb) cb(); };
    return ws;
}

function agentRelay(parent, domain, id) {
    const ws = fakeWs();
    const req = { query: { id: id || 'sess', nodeid: 'node/test/device', p: '2', rauth: 'x' }, clientIp: '127.0.0.1' };
    const relay = sandbox.CreateMeshRelayEx2(parent, ws, req, domain || { id: '' }, null, null);
    return { ws, relay, req };
}

function recordingViewer(mux) {
    const viewer = { req: { query: { browser: 1 } }, user: { _id: 'user/test/v', name: 'v', flags: 2 }, ws: fakeWs(), close() { this.closed = true; mux.removePeer(this); } };
    viewer.deskMultiplexor = mux;
    return viewer;
}

const tests = {
    'message arriving while the multiplexor is still pending must not throw'() {
        const { parent } = makeParent({ dbGet() { /* never completes */ } });
        agentRelay(parent, { id: '' });
        assert.strictEqual(parent.desktoprelays['node/test/device'], 1, 'creation pending marker set');
        const waiter = agentRelay(parent, { id: '' }); // Holds the pending marker as its multiplexor reference
        assert.strictEqual(waiter.relay.deskMultiplexor, 1);
        assert.doesNotThrow(() => waiter.ws.emit('message', Buffer.from([0, 1, 0, 4])));
    },
    'a creation that never completes releases the node after the retry budget and a late result is discarded'() {
        let lateCb = null, calls = 0;
        const { parent } = makeParent({ dbGet(id, cb) { calls++; if (calls == 1) { lateCb = cb; } else { cb(null, [{ meshid: 'mesh/test/group', name: 't', icon: 1 }]); } } });
        agentRelay(parent, { id: '' });
        assert.strictEqual(parent.desktoprelays['node/test/device'], 1);
        const second = agentRelay(parent, { id: '' });
        // The second peer polls every 50ms until it gives up after 200 retries.
        let guard = 0;
        while (!second.ws.closed && guard++ < 400) { assert(runOnce() > 0, 'retry timer must be scheduled'); }
        assert.strictEqual(second.ws.closed, true, 'waiting peer closes after the retry budget');
        assert.notStrictEqual(parent.desktoprelays['node/test/device'], 1, 'stale pending marker must be released');
        // A fresh connection can now create a working multiplexor.
        const third = agentRelay(parent, { id: '' });
        const mux = parent.desktoprelays['node/test/device'];
        assert(mux && typeof mux == 'object', 'new multiplexor installed');
        assert.strictEqual(mux.agent, third.relay);
        // The original creation finally completes: it must not replace the newer multiplexor.
        lateCb(null, [{ meshid: 'mesh/test/group', name: 't', icon: 1 }]);
        assert.strictEqual(parent.desktoprelays['node/test/device'], mux, 'late multiplexor must not clobber the live one');
        assert.strictEqual(mux.viewers.length, 0); assert.strictEqual(mux.agent, third.relay);
        assert.strictEqual(timers.filter(t => t.interval && !t.cleared).length, 1, 'only the live multiplexor keeps a watchdog');
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
