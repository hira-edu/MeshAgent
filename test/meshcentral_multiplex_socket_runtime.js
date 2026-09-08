// Loopback integration: an agent's queued desktop command must reach a newly
// connected viewer even while the existing viewer's sends remain blocked.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { once } = require('events');
const { createRequire } = require('module');
const sourcePath = path.resolve(process.argv[2] || '../MeshCentral/meshdesktopmultiplex.js');
const serverRequire = createRequire(path.resolve(process.argv[3] || '../MeshCentral/package.json'));
const WebSocket = serverRequire('ws');
const sandbox = { require: serverRequire, module: { exports: {} }, Buffer, console, setTimeout, clearTimeout, setInterval, clearInterval };
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath });

async function until(check, message) {
    const deadline = Date.now() + 3000;
    while (!check()) {
        assert(Date.now() < deadline, message);
        await new Promise(resolve => setTimeout(resolve, 5));
    }
}

async function main() {
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } },
        parent: { args: {}, debug() {}, DispatchEvent() {},
            decodeCookie() { return { ruserid: 'user/test/viewer', nodeid: 'node/test/device' }; } },
        db: { Get(id, cb) { cb(null, [{ meshid: 'mesh/test/group', name: 'test', icon: 1 }]); } },
        users: {}, wsagents: {}, meshes: {}
    };
    const mux = sandbox.CreateDesktopMultiplexor(parent, { id: '' }, 'node/test/device', 'test', () => {});
    parent.desktoprelays = { [mux.nodeid]: mux };
    parent.relaySessionCount = 0;
    const peers = new Map(), clients = [];
    const server = new WebSocket.Server({ host: '127.0.0.1', port: 0 });
    let protocolError = null;
    server.on('connection', (ws, req) => {
        const name = req.url.slice(1);
        if (name === 'duplicate') {
            sandbox.CreateMeshRelayEx2(parent, ws,
                { query: { id: 'duplicate', nodeid: mux.nodeid, rauth: 'test' }, clientIp: '127.0.0.1' },
                { id: '' }, null, null);
            return;
        }
        const peer = { ws, req: { query: name === 'agent' ? {} : { browser: 1 } },
            user: { _id: 'user/test/' + name, name }, held: [], hold: false, closed: false,
            close() {
                if (peer.closed) return;
                peer.closed = true;
                ws.close();
                mux.removePeer(peer);
            } };
        const send = ws.send.bind(ws);
        ws.send = (data, cb) => send(data, error => {
            if (error) { protocolError = error; return; }
            if (!cb) return;
            if (peer.hold) peer.held.push(cb); else cb();
        });
        peers.set(name, peer);
        mux.addPeer(peer);
        ws.on('message', (data, binary) => {
            // ws 7 already returns text as strings; ws 8 adds the binary flag.
            try { mux.processData(peer, binary === false ? data.toString() : data); }
            catch (error) { protocolError = error; }
        });
        ws.on('error', error => { protocolError = error; });
        ws.on('close', () => peer.close());
    });
    await once(server, 'listening');
    async function connect(name) {
        const ws = new WebSocket('ws://127.0.0.1:' + server.address().port + '/' + name);
        ws.messages = [];
        ws.on('message', data => ws.messages.push(Buffer.from(data)));
        ws.on('error', error => { protocolError = error; });
        clients.push(ws);
        await once(ws, 'open');
        await until(() => peers.has(name) && peers.get(name).sending === false, name + ' initial sends must drain');
        return ws;
    }
    try {
        await connect('slow');
        const agentClient = await connect('agent');
        const slow = peers.get('slow'), agent = peers.get('agent');
        await until(() => !slow.sending, 'initial viewer metadata must drain');
        // A size announcement has reset the image cache; the next picture has
        // not arrived yet. This is distinct from replaying an existing picture.
        mux.processAgentData(Buffer.from([0, 7, 0, 8, 0, 16, 0, 16]));
        await until(() => !slow.sending, 'screen reset must drain');
        slow.hold = true;
        for (let i = 0; i < 9; i++) mux.sendToViewer(slow, Buffer.from([0, 88, 0, 5, i]));
        await until(() => slow.held.length > 0, 'first slow socket send must complete');
        slow.held.shift()();
        assert.strictEqual(slow.overflow, true);
        assert.strictEqual(agent.paused, true);
        assert.strictEqual(agent.ws._socket.isPaused(), true);

        const marker = Buffer.from([0, 88, 0, 5, 42]);
        agentClient.send(marker);
        const fastClient = await connect('fast');
        await until(() => fastClient.messages.some(data => data.equals(marker)), 'fresh desktop command must reach the new viewer');
        assert.strictEqual(agent.paused, false);
        assert.strictEqual(agent.ws._socket.isPaused(), false);
        assert.strictEqual(slow.overflow, true, 'the old slow viewer must still be blocked');
        assert.strictEqual(protocolError, null);
        const duplicateClient = new WebSocket('ws://127.0.0.1:' + server.address().port + '/duplicate');
        duplicateClient.on('error', error => { protocolError = error; });
        clients.push(duplicateClient);
        await until(() => duplicateClient.readyState === WebSocket.CLOSED, 'rejected duplicate agent socket must close');
        assert.strictEqual(mux.agent, agent);
        assert.strictEqual(mux.viewers.length, 2);
        assert.strictEqual(parent.relaySessionCount, 0);
        assert.strictEqual(protocolError, null);
        agentClient.close();
        await until(() => clients.every(client => client.readyState === WebSocket.CLOSED),
            'agent disconnect must close every viewer socket');
        assert.strictEqual(mux.viewers, undefined);
        console.log(JSON.stringify({ success: true, sourcePath, receivedFreshDesktopCommand: true,
            oldViewerBlockedUntilAgentDisconnect: true, rejectedDuplicateSocketClosed: true, allViewerSocketsClosed: true }));
    } finally {
        for (const client of clients) client.terminate();
        for (const ws of server.clients) ws.terminate();
        await new Promise(resolve => server.close(resolve));
    }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
