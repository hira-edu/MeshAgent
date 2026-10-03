'use strict';
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const {EventEmitter} = require('events');
const source = fs.readFileSync(require('path').join(__dirname, '../modules/win-terminal.js'), 'utf8');
async function run(scenario) {
    const servers = [], child = new EventEmitter();
    let killed = 0, closed = 0;
    child.kill = () => ++killed;
    const context = {process: {platform: 'win32', pid: 123}, module: {exports: {}}, Buffer, Date,
        setTimeout, clearTimeout, setImmediate,
        require(name) {
            if (name === 'stream') return require('stream');
            if (name === 'child_process') return {execFile: () => child};
            if (name === 'net') return {createServer(callback) {
                const server = new EventEmitter(); server.listen = () => {};
                server.close = () => ++closed;
                server.connect = callback; servers.push(server); return server;
            }};
            if (name === 'win-system-paths') return {system32Path: () => 'C:\\Windows\\System32\\rundll32.exe',
                installedServiceRuntimeDll() { if (scenario === 'path') throw Error('invalid service runtime'); return 'C:\\Agent\\agent.dll'; }};
            throw Error(name);
        }};
    vm.runInNewContext(source, context);
    const stream = context.module.exports.Start(80,25);
    let error, closes = 0;
    stream.on('error', value => { error = value; });
    stream.on('close', () => ++closes);
    assert.equal(error, undefined, 'construction must allow listeners to attach');
    await new Promise(resolve => setImmediate(resolve));
    if (scenario === 'output') {
        const socket = new EventEmitter(); socket.end = () => {};
        servers[1].connect(socket); socket.emit('close');
    }
    assert.match(error.message, scenario === 'path' ? /invalid service/ : /output closed before ready/);
    assert.equal(closes, 1);
    assert.equal(closed, 2);
    assert.equal(killed, scenario === 'path' ? 0 : 1);
    assert.equal(stream._meshTerminalReady, false);
}
(async () => { await run('path'); await run('output'); console.log('Terminal startup failures reach listeners and close all resources exactly once.'); })().catch(error => { console.error(error); process.exitCode = 1; });
