'use strict';
// WEB-7 / TST-16: when the desktop session becomes end-to-end connected (state 3).
//
// The relay accepting the tunnel ('c') is not the desktop being ready. A module that sets
// deferConnectedState (the remote desktop) declares the connection itself with parent.connected()
// once its stream starts (the agent's first SCREEN message). Until then the agent's reply decides:
// a console error (msgid 2: consent denied, desktop failed to start) ends the session, a consent
// prompt (msgid 1) hands the wait to the agent's own consent timeout, and only a session that gets
// no reply at all ends after the transport's last-resort connectTimeout, with a visible "Timeout".
// Other modules (terminal, files) are connected as soon as the relay accepts.
//
// Drives the real agent-redir-ws-0.1.1.js and agent-desktop-0.0.2.js with a fake WebSocket and a
// controllable clock.
const fs = require('fs');
const vm = require('vm');
const { forkFile } = require('./lib/meshcentral_paths');

const redirSource = fs.readFileSync(forkFile('public/scripts/agent-redir-ws-0.1.1.js'), 'utf8');
const desktopSource = fs.readFileSync(forkFile('public/scripts/agent-desktop-0.0.2.js'), 'utf8');

function harness() {
    let now = 0, nextId = 1;
    const timers = new Map();
    const sockets = [];
    class FakeWebSocket {
        constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); }
        send(data) { this.sent.push(data); }
        close() { this.readyState = 3; }
    }
    FakeWebSocket.OPEN = 1;
    const canvas = { style: {}, clientWidth: 800, clientHeight: 600, getContext() { return { canvas: { width: 800, height: 600 }, setTransform() {}, clearRect() {}, drawImage() {} }; } };
    const sandbox = {
        console: { log() {} }, navigator: { platform: 'Win32', userAgent: 'Mozilla/5.0' }, document: {}, urlargs: {},
        location: { protocol: 'https:', host: 'mesh.test', pathname: '/' }, WebSocket: FakeWebSocket,
        setTimeout(fn, ms) { const id = nextId++; timers.set(id, { fn, at: now + ms }); return id; },
        clearTimeout(id) { timers.delete(id); },
        setInterval() { return 0; }, clearInterval() {}, Uint8Array, ArrayBuffer, JSON, Math, Date, String, Object
    };
    sandbox.window = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(redirSource, sandbox);
    vm.runInContext(desktopSource, sandbox);
    const states = [];
    function open(module) {
        const redir = sandbox.CreateAgentRedirect({ send() {} }, module, null, 'auth', 'rauth', '/');
        redir.onStateChanged = (r, s) => states.push(s);
        redir.Start('node//1');
        const socket = sockets[sockets.length - 1];
        socket.readyState = 1;
        socket.onopen();
        return { redir, socket };
    }
    return {
        sandbox, states, canvas,
        desktop() { return open(sandbox.CreateAgentRemoteDesktop(canvas)); },
        terminal() { return open({ protocol: 1, xxStateChange() {}, ProcessData() {} }); },
        accept(socket, word) { socket.onmessage({ data: word || 'c' }); },
        control(socket, msg) { socket.onmessage({ data: JSON.stringify(Object.assign({ ctrlChannel: '102938' }, msg)) }); },
        screen(socket, w, h) { socket.onmessage({ data: new Uint8Array([0, 7, 0, 8, w >> 8, w & 255, h >> 8, h & 255]).buffer }); },
        pending() { return timers.size; },
        advance(ms) {
            now += ms;
            for (const [id, t] of [...timers].sort((a, b) => a[1].at - b[1].at)) { if (t.at <= now && timers.has(id)) { timers.delete(id); t.fn(); } }
        }
    };
}

const results = [];
function check(name, fn) {
    try { fn(); results.push('PASS ' + name); } catch (error) { results.push('FAIL ' + name + ': ' + error.message); }
}
function equal(actual, expected, what) { if (actual !== expected) throw new Error(what + ': expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual)); }

check('the transport hard-codes no protocol number for the connect deferral', () => {
    equal(/obj\.protocol\s*!=\s*2/.test(redirSource), false, 'agent-redir-ws compares obj.protocol with 2');
    const h = harness();
    equal(h.sandbox.CreateAgentRemoteDesktop(h.canvas).deferConnectedState, true, 'the desktop module declares deferConnectedState');
});

check('ready: state 3 follows the first SCREEN, not the relay accept', () => {
    const h = harness(); const { redir, socket } = h.desktop();
    h.accept(socket);
    equal(redir.State, 2, 'state after the relay accepted');
    equal(socket.sent.includes(2), true, 'the protocol byte is still sent on accept');
    equal(h.pending(), 1, 'the last-resort timer runs while waiting for the desktop');
    h.screen(socket, 800, 600);
    equal(redir.State, 3, 'state after the first SCREEN');
    equal(h.pending(), 0, 'the timer is cleared once connected');
    h.screen(socket, 1024, 768);
    equal(JSON.stringify(h.states), JSON.stringify([1, 2, 3]), 'state transitions');
});

check('ready on a recorded session (cr)', () => {
    const h = harness(); const { redir, socket } = h.desktop();
    h.accept(socket, 'cr');
    equal(redir.State, 2, 'state after accept'); equal(redir.serverIsRecording, true, 'recording flag');
    h.screen(socket, 800, 600);
    equal(redir.State, 3, 'state after SCREEN');
});

check('denied: the agent console error ends the session with its message', () => {
    const h = harness(); const { redir, socket } = h.desktop();
    h.accept(socket);
    h.control(socket, { type: 'console', msg: 'Waiting for user to grant access...', msgid: 1 });
    equal(redir.State, 2, 'state while consent is pending');
    equal(h.pending(), 0, 'the agent owns the consent wait (its consent timeout), so no page timer runs');
    h.control(socket, { type: 'console', msg: 'Denied', msgid: 2 });
    equal(redir.State, 0, 'state after the agent denied');
    equal(redir.consoleMessage, 'Denied', 'the agent message stays visible');
    equal(h.pending(), 0, 'no timer left behind');
    equal(h.states.includes(3), false, 'never reported connected');
});

check('consent granted: the wait for the stream starts again', () => {
    const h = harness(); const { redir, socket } = h.desktop();
    h.accept(socket);
    h.control(socket, { type: 'console', msg: 'Waiting for user to grant access...', msgid: 1 });
    h.advance(10 * 60 * 1000);
    equal(redir.State, 2, 'a long consent wait is not a timeout');
    h.control(socket, { type: 'console', msg: null, msgid: 0 });
    equal(h.pending(), 1, 'the last-resort timer runs again after consent');
    h.screen(socket, 800, 600);
    equal(redir.State, 3, 'state after SCREEN');
});

check('no reply: only the last-resort timeout ends the session, as a visible error', () => {
    const h = harness(); const { redir, socket } = h.desktop();
    h.accept(socket);
    h.advance(redir.connectTimeout - 1);
    equal(redir.State, 2, 'still waiting just before the timeout');
    h.advance(1);
    equal(redir.State, 0, 'state after the timeout');
    equal(redir.consoleMessage, 'Timeout', 'timeout message'); equal(redir.consoleMessageId, 4, 'timeout message id (agentConsoleMessages[4])');
    equal(redir.connectTimeout >= 30000, true, 'the timeout is a last resort (>= 30 s), got ' + redir.connectTimeout);
});

check('a user stop while waiting leaves no timer behind', () => {
    const h = harness(); const { redir, socket } = h.desktop();
    h.accept(socket);
    redir.Stop();
    equal(h.pending(), 0, 'pending timers after Stop');
    equal(redir.State, 0, 'state after Stop');
});

check('other modules are connected when the relay accepts', () => {
    const h = harness(); const { redir, socket } = h.terminal();
    h.accept(socket);
    equal(redir.State, 3, 'terminal state after accept');
    equal(h.pending(), 0, 'no timer for a module that does not defer');
});

check('a module whose parent is not a relay transport (WebRTC soft desktop) handles SCREEN', () => {
    const h = harness();
    const module = h.sandbox.CreateAgentRemoteDesktop(h.canvas);
    module.parent = { send() {} };
    module.ProcessScreenMsg(800, 600);
    equal(module.ScreenWidth, 800, 'screen processed');
});

for (const line of results) { console.log(line); }
const failed = results.filter((line) => line.startsWith('FAIL')).length;
console.log((failed ? 'FAIL' : 'PASS') + ' agent redirector initial KVM state (' + (results.length - failed) + '/' + results.length + ')');
if (failed) { process.exitCode = 1; }
