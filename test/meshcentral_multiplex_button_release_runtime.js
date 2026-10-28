// Exercise the desktop multiplexer's per-viewer mouse button tracking: a viewer that leaves while
// holding a button must not leave it held on the remote for the other viewers.
// No server, endpoint session, credentials, or real user input is needed.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { createRequire } = require('module');
const { forkFile } = require('./lib/meshcentral_paths');

const sourcePath = path.resolve(process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : forkFile('meshdesktopmultiplex.js'));
// The multiplexor's own require, so './mcrec.js' (the tile size reader) is the fork's.
const sandbox = { require: createRequire(sourcePath), module: { exports: {} }, Buffer, console, setTimeout, clearTimeout, setInterval, clearInterval };
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath });

const mouse = (button, x, y) => Buffer.from([0, 2, 0, 10, 0, button, x >> 8, x & 255, y >> 8, y & 255]);
const hex = b => Buffer.from(b).toString('hex');

function harness(options) {
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } },
        parent: { debug() {}, DispatchEvent() {} },
        db: { Get(id, cb) { cb(null, [{ meshid: 'mesh/test/group', name: 'test', icon: 1 }]); } },
        users: {}, wsagents: {}, meshes: {}
    };
    const mux = sandbox.CreateDesktopMultiplexor(parent, { id: '' }, 'node/test/device', 'test', () => {});
    function peer(browser, viewOnly, deferred) {
        const sent = [], pending = [];
        const socket = { paused: false, bytesRead: 0, bytesWritten: 0, pause() { this.paused = true; }, resume() { this.paused = false; } };
        const p = {
            req: { query: browser ? { browser: 1 } : {} }, user: { _id: 'user/test/v', name: 'v' }, viewOnly: !!viewOnly,
            ws: { _socket: socket, send(data, cb) { if (p.closed) { p.afterClose.push(data); return; } sent.push(data); if (cb) { if (p.deferred) pending.push(cb); else cb(); } } },
            sent, afterClose: [], closed: false, deferred: !!deferred,
            complete() { while (pending.length) pending.shift()(); },
            close() { if (p.closed) return; p.closed = true; mux.removePeer(p); }
        };
        return p;
    }
    const agent = peer(false, false, options && options.slowAgent);
    const a = peer(true), b = peer(true), watcher = peer(true, true);
    if (options && options.viewerFirst) { mux.addPeer(a); return { mux, agent, a, b, watcher, toAgent: () => agent.sent.filter(d => Buffer.isBuffer(d) && d.length >= 4 && d.readUInt16BE(0) === 2).map(hex), clear: () => { agent.sent.length = 0; } }; }
    mux.addPeer(a); mux.addPeer(agent); mux.addPeer(b); mux.addPeer(watcher);
    const toAgent = () => agent.sent.filter(d => Buffer.isBuffer(d) && d.length >= 4 && d.readUInt16BE(0) === 2).map(hex);
    const clear = () => { agent.sent.length = 0; };
    return { mux, agent, a, b, watcher, toAgent, clear };
}

const tests = {
    'a viewer that leaves mid-drag releases the button at its last position'() {
        const h = harness(); h.clear();
        h.mux.processViewerData(h.a, mouse(0x02, 100, 200));
        h.mux.processViewerData(h.a, mouse(0x00, 150, 220));
        h.clear();
        h.a.close();
        assert.deepStrictEqual(h.toAgent(), [hex(mouse(0x04, 150, 220))]);
    },
    'right and middle are released too, each once'() {
        const h = harness();
        h.mux.processViewerData(h.a, mouse(0x08, 10, 10));
        h.mux.processViewerData(h.a, mouse(0x20, 11, 10));
        h.clear();
        h.a.close(); h.a.close();
        assert.deepStrictEqual(h.toAgent(), [hex(mouse(0x10, 11, 10)), hex(mouse(0x40, 11, 10))]);
    },
    'a button another viewer still holds is not released'() {
        const h = harness();
        h.mux.processViewerData(h.a, mouse(0x02, 10, 10));
        h.mux.processViewerData(h.b, mouse(0x02, 20, 20));
        h.clear();
        h.a.close();
        assert.deepStrictEqual(h.toAgent(), [], 'b still holds left');
        h.b.close();
        assert.deepStrictEqual(h.toAgent(), [hex(mouse(0x04, 20, 20))], 'the last holder releases');
    },
    'a viewer that released normally sends nothing on leaving'() {
        const h = harness();
        h.mux.processViewerData(h.a, mouse(0x02, 10, 10));
        h.mux.processViewerData(h.a, mouse(0x04, 10, 10));
        h.mux.processViewerData(h.a, Buffer.from([0, 2, 0, 10, 0, 0x06, 0, 1, 0, 1]));
        h.clear();
        h.a.close();
        assert.deepStrictEqual(h.toAgent(), []);
    },
    'the double-click indication is not a press'() {
        const h = harness();
        h.mux.processViewerData(h.a, mouse(0x88, 10, 10));
        h.clear();
        h.a.close();
        assert.deepStrictEqual(h.toAgent(), []);
    },
    'view-only viewers are neither forwarded nor tracked'() {
        const h = harness(); h.clear();
        h.mux.processViewerData(h.watcher, mouse(0x02, 10, 10));
        assert.deepStrictEqual(h.toAgent(), []);
        h.watcher.close();
        assert.deepStrictEqual(h.toAgent(), []);
    },
    'wheel packets pass through and are not presses'() {
        const h = harness(); h.clear();
        const wheel = Buffer.from([0, 2, 0, 12, 0, 0, 0, 5, 0, 6, 0xff, 0x88]);
        h.mux.processViewerData(h.a, wheel);
        assert.deepStrictEqual(h.toAgent(), [hex(wheel)]);
        h.clear(); h.a.close();
        assert.deepStrictEqual(h.toAgent(), []);
    },
    'nothing is sent to an agent that is going away'() {
        const h = harness();
        h.mux.processViewerData(h.a, mouse(0x02, 10, 10));
        h.clear();
        h.agent.close();
        assert.deepStrictEqual(h.toAgent(), [], 'no release written');
        // (Leaving viewers still trigger an image-settings update to the closed agent, which predates this.)
        assert.deepStrictEqual(h.agent.afterClose.filter(d => d.readUInt16BE(0) === 2), [], 'no mouse packet written after close');
    },
    'the last viewer leaving mid-drag on a busy agent link still delivers the release'() {
        const h = harness({ slowAgent: true });
        h.mux.processViewerData(h.b, mouse(0x00, 1, 1)); h.b.close(); h.watcher.close();
        h.mux.processViewerData(h.a, mouse(0x02, 100, 100));   // written, completion pending
        h.mux.processViewerData(h.a, mouse(0x00, 120, 110));   // queued behind it
        h.a.close();
        assert.strictEqual(h.agent.closed, false, 'the agent stays until its queue drains');
        h.agent.complete(); h.agent.complete(); h.agent.complete();
        const wire = h.toAgent();
        assert.deepStrictEqual(wire.slice(-1), [hex(mouse(0x04, 120, 110))], 'the release reached the wire');
        assert.strictEqual(h.agent.closed, true, 'then the agent is closed');
    },
    'a viewer joining while the agent drains keeps the session'() {
        const h = harness({ slowAgent: true });
        h.b.close(); h.watcher.close();
        h.mux.processViewerData(h.a, mouse(0x02, 100, 100));
        h.mux.processViewerData(h.a, mouse(0x00, 101, 100));
        h.a.close();
        const c = { req: { query: { browser: 1 } }, user: { _id: 'user/test/c', name: 'c' }, viewOnly: false, ws: { _socket: { pause() {}, resume() {}, bytesRead: 0, bytesWritten: 0 }, send(d, cb) { if (cb) cb(); } }, close() { h.mux.removePeer(c); } };
        h.mux.addPeer(c);
        h.agent.complete(); h.agent.complete(); h.agent.complete();
        assert.strictEqual(h.agent.closed, false);
    },
    'input before the agent connects is not tracked'() {
        const h = harness({ viewerFirst: true });
        h.mux.processViewerData(h.a, mouse(0x02, 10, 10));
        assert.strictEqual(h.a.heldButtons == null || h.a.heldButtons[2] !== true, true);
    },
    'a short mouse packet is forwarded unchanged and not tracked'() {
        const h = harness(); h.clear();
        const short = Buffer.from([0, 2, 0, 6, 0, 2]);
        h.mux.processViewerData(h.a, short);
        h.clear(); h.a.close();
        assert.deepStrictEqual(h.toAgent(), []);
    }
};

let failed = 0;
for (const [name, fn] of Object.entries(tests)) {
    try { fn(); console.log(`PASS ${name}`); } catch (error) { failed++; console.log(`FAIL ${name}: ${error.message}`); }
}
if (failed) process.exitCode = 1;
