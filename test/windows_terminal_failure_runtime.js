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
(async () => {
    await run('path'); await run('output');
    console.log('Terminal startup failures reach listeners and close all resources exactly once.');
    if (process.argv.includes('--native')) {
        assert.equal(process.platform, 'win32');
        const path = require('path'), root = path.resolve(__dirname, '..');
        for (const scenario of ['path', 'policy']) {
            const paths = "exports.system32Path=function(){return process.env.SystemRoot+'\\\\System32\\\\rundll32.exe';};exports.installedServiceRuntimeDll=function(){" +
                (scenario === 'path' ? "throw Error('invalid service runtime');" : "return 'C:\\\\missing-agent-runtime\\\\missing.dll';") + "};";
            const code = "global._noMessagePump=true;addModule('win-system-paths'," + JSON.stringify(paths) + ");" +
                "addModule('win-terminal',require('fs').readFileSync(" + JSON.stringify(path.join(root, 'modules/win-terminal.js')) + ").toString());" +
                "var error=null,closes=0;var term=require('win-terminal').Start(80,25);" +
                "term.on('error',function(e){error=''+e;});term.on('close',function(){++closes;console.log(JSON.stringify({error:error,closes:closes,closed:term.isBridgeClosed()}));process.exit();});";
            const result = require('child_process').spawnSync(path.join(root, 'meshconsole/Release/MeshConsole64.exe'),
                ['-b64exec', Buffer.from(code).toString('base64')], {encoding:'utf8', timeout:15000, windowsHide:true});
            assert.ifError(result.error);
            assert.equal(result.status, 0, result.stdout + result.stderr);
            const report = JSON.parse(result.stdout.trim());
            assert(report.error, scenario + ' must report an error');
            assert.equal(report.closes, 1);
            assert.equal(report.closed, true);
            console.log(JSON.stringify({scenario, ...report}));
        }
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
