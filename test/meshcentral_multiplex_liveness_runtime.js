// Loopback integration for desktop multiplexor agent liveness (S9, SRV-38).
// The server pings the agent tunnel every --agentidletimeout; an agent that has not answered by the next
// ping is closed, which ends the session. Here the period is 200 ms and the peers are real ws sockets:
//   - an idle agent whose WebSocket layer answers pings stays connected across many periods;
//   - an agent that stops reading its socket (a hung or half-open tunnel) is closed, and so are the viewers.
// No server, endpoint session, credentials, or real user input is needed.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { once } = require('events');
const { createRequire } = require('module');
const { forkFile, installedPackageDir } = require('./lib/meshcentral_paths');

const sourcePath = path.resolve(process.argv[2] || forkFile('meshdesktopmultiplex.js'));
const serverRequire = createRequire(path.resolve(process.argv[3] || path.join(installedPackageDir().dir, 'package.json')));
const WebSocket = serverRequire('ws');
// Relative modules ('./mcrec.js') come from the fork beside the multiplexor, packages from the installed server.
const sourceRequire = createRequire(sourcePath);
const sandbox = { require: name => name.startsWith('./') ? sourceRequire(name) : serverRequire(name),
    module: { exports: {} }, Buffer, console, setTimeout, clearTimeout, setInterval, clearInterval, setImmediate };
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath });

const PERIOD = 200;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(check, message, limit) {
    const deadline = Date.now() + (limit || 3000);
    while (!check()) {
        assert(Date.now() < deadline, message);
        await sleep(5);
    }
}

async function session(server, parent) {
    const mux = sandbox.CreateDesktopMultiplexor(parent, { id: '' }, 'node/test/device', 'test', () => {});
    const peers = new Map(), clients = [];
    server.removeAllListeners('connection');
    server.on('connection', (ws, req) => {
        const name = req.url.slice(1);
        const peer = { ws, req: { query: name === 'agent' ? {} : { browser: 1 } }, user: { _id: 'user/test/' + name, name },
            closed: false, close() { if (peer.closed) return; peer.closed = true; ws.close(); mux.removePeer(peer); } };
        peers.set(name, peer);
        ws.on('message', (data, binary) => mux.processData(peer, binary === false ? data.toString() : data));
        ws.on('close', () => peer.close());
        mux.addPeer(peer);
    });
    async function connect(name) {
        const ws = new WebSocket('ws://127.0.0.1:' + server.address().port + '/' + name);
        ws.pings = 0;
        ws.on('ping', () => { ws.pings++; });
        ws.on('error', () => {});
        clients.push(ws);
        await once(ws, 'open');
        await until(() => peers.has(name), name + ' must join');
        return ws;
    }
    return { mux, peers, clients, connect };
}

async function main() {
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } },
        parent: { args: { agentidletimeout: PERIOD }, debug() {}, DispatchEvent() {} },
        db: { Get(id, cb) { cb(null, [{ meshid: 'mesh/test/group', name: 'test', icon: 1 }]); } },
        users: {}, wsagents: {}, meshes: {}
    };
    const server = new WebSocket.Server({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening');
    const all = [];
    let failed = 0;
    async function check(name, fn) {
        try { await fn(); console.log('PASS ' + name); } catch (ex) { failed++; console.error('FAIL ' + name + ': ' + ex.message); }
    }
    try {
        await check('an idle agent that answers pings keeps its session', async () => {
            const s = await session(server, parent); all.push(s);
            await s.connect('viewer');
            const agent = await s.connect('agent');
            await sleep(PERIOD * 6);
            assert(agent.pings >= 4, 'the agent was pinged every period (' + agent.pings + ')');
            assert.strictEqual(agent.readyState, WebSocket.OPEN, 'the agent is still connected');
            assert.strictEqual(s.mux.agent, s.peers.get('agent'));
            assert.strictEqual(s.mux.viewers.length, 1);
            agent.close();
            await until(() => s.clients.every(c => c.readyState === WebSocket.CLOSED), 'closing the agent ends the session');
        });
        await check('an agent that stops reading its tunnel is closed and the session ends', async () => {
            const s = await session(server, parent); all.push(s);
            const viewer = await s.connect('viewer');
            const agent = await s.connect('agent');
            agent._socket.pause(); // Hung: pings are no longer read, so no pong is sent
            const start = Date.now();
            await until(() => viewer.readyState === WebSocket.CLOSED, 'the viewer is closed when the agent is', PERIOD * 10);
            const elapsed = Date.now() - start;
            assert(elapsed >= PERIOD, 'not before one unanswered period (' + elapsed + ' ms)');
            assert.strictEqual(s.mux.viewers, undefined, 'the session is disposed');
            assert.strictEqual(s.peers.get('agent').closed, true);
            assert.strictEqual(s.peers.get('agent').ws._socket.destroyed, true, 'the agent socket is destroyed');
        });
    } finally {
        for (const s of all) { for (const c of s.clients) c.terminate(); }
        for (const ws of server.clients) ws.terminate();
        await new Promise(resolve => server.close(resolve));
    }
    console.log(JSON.stringify({ sourcePath, period: PERIOD, failed }));
    process.exitCode = failed ? 1 : 0;
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
