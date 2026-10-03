'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const {EventEmitter} = require('events');
const source = fs.readFileSync(path.join(__dirname, '../modules/clipboard.js'), 'utf8');
const functionSource = source.slice(source.indexOf('function windowsClipboardCommand('), source.indexOf('function nativeAddCompressedModule('));
function agentPromise(executor) {
    const holder = this;
    const promise = new Promise((resolve, reject) => executor.call(holder, resolve, reject));
    return Object.assign(promise, holder);
}
function load(terminalModule, timers = {setTimeout, clearTimeout}) {
    return vm.runInNewContext('(' + functionSource.trim() + ')', {promise: agentPromise, Buffer,
        setTimeout: timers.setTimeout, clearTimeout: timers.clearTimeout,
        require: name => { assert.equal(name, 'win-terminal'); return terminalModule; }});
}
async function unit() {
    for (const scenario of ['read', 'empty', 'write', 'shell-error', 'path-error', 'timeout']) {
        const terminal = new EventEmitter();
        let command = '', timer, closed = 0;
        terminal.onBridgeData = callback => { terminal.data = callback; };
        terminal.writeBridgeInput = value => { command = value; };
        terminal.closeInput = () => {};
        terminal.closeBridge = () => { ++closed; terminal.emit('close'); };
        const run = load({RunPowerShellCommandAsUser(cols, rows, session) {
            assert.equal(session, 7);
            if (scenario === 'path-error') throw Error('invalid runtime');
            return terminal;
        }}, {setTimeout: callback => { timer = callback; return 1; }, clearTimeout: () => { timer = null; }});
        const writing = scenario === 'write';
        const data = "quote' ; hostile $()\nUnicode \u2713";
        const result = run(writing ? 'write' : 'read', 7, data);
        if (scenario === 'path-error') { await assert.rejects(result, /invalid runtime/); continue; }
        if (scenario === 'timeout') { timer(); await assert.rejects(result, /timed out/); assert.equal(closed,1); continue; }
        if (scenario === 'shell-error') {
            terminal.data(Buffer.from('Access denied')); terminal.emit('close');
            await assert.rejects(result, /Access denied/); continue;
        }
        const expected = scenario === 'empty' ? '' : 'Unicode \u2713\nsecond line';
        terminal.data(Buffer.from('MESH_CLIPBOARD_OK:' + (writing ? '' : Buffer.from(expected).toString('base64'))));
        terminal.emit('close');
        assert.equal(await result, writing ? undefined : expected);
        assert.equal(timer, null);
        if (writing) { assert(command.includes(Buffer.from(data).toString('base64'))); assert(!command.includes(data)); }
    }
    console.log('Clipboard shared bridge: Unicode, empty content, safe writes, failure and timeout cleanup passed.');
}
async function live() {
    assert.equal(process.platform, 'win32');
    const args = process.argv;
    const session = Number(args[args.indexOf('--session') + 1]);
    assert(session > 0, 'pass the active interactive --session ID');
    const Module = require('module'), original = Module._load;
    const dll = path.resolve('meshservice/x64/MeshServiceBundle/MeshService-2022.dll');
    Module._load = function(name) {
        if (name === 'win-system-paths') return {system32Path: file => path.join(process.env.SystemRoot, 'System32', file), installedServiceRuntimeDll: () => dll};
        return original.apply(this, arguments);
    };
    try {
        const run = load(require('../modules/win-terminal'));
        const value = await run('read', session);
        assert.equal(typeof value, 'string');
        console.log(JSON.stringify({success:true, session, characters:value.length}));
    } finally { Module._load = original; }
}
(process.argv.includes('--live-read') ? live() : unit()).catch(error => { console.error(error); process.exitCode = 1; });
