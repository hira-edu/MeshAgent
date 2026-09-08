// Run only on an authorized interactive Windows test desktop. Captured pixels
// travel over loopback and are discarded; no keyboard or mouse input is sent.
// Usage: node test/kvm_capture_reconnect_runtime.js <MeshConsole64.exe> <evidence-dir>
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { createRequire } = require('module');

if (process.platform !== 'win32' || !process.argv[2] || !process.argv[3]) {
    throw new Error('Requires Windows, an explicit MeshConsole executable, and an evidence directory');
}
const runner = path.resolve(process.argv[2]);
const evidence = path.resolve(process.argv[3]);
const WebSocket = createRequire(path.resolve(__dirname, '../../MeshCentral/package.json'))('ws');
fs.mkdirSync(evidence, { recursive: true });
const started = Date.now();
const report = { runner, connections: 0, closed: 0, pictures: 0, bytes: 0, lastPictureMs: 0, errors: [] };
const timers = new Set();
const server = new WebSocket.Server({ host: '127.0.0.1', port: 0 });
server.on('error', error => { throw error; });
server.on('connection', (ws, request) => {
    const index = ++report.connections;
    let configured = false;
    ws.on('error', error => report.errors.push(String(error)));
    ws.on('message', (data, binary) => {
        if (!binary) { return; }
        report.bytes += data.length;
        if (data.length >= 4 && [3, 27].includes(data.readUInt16BE(0))) {
            ++report.pictures;
            report.lastPictureMs = Date.now() - started;
        }
        if (!configured) {
            configured = true;
            ws.send(Buffer.from([0, 5, 0, 10, 1, 30, 4, 0, 0, 100]));
            ws.send(Buffer.from([0, 8, 0, 5, 0]));
        }
    });
    const ping = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) { ws.send('{"ctrlChannel":"102938","type":"ping"}'); }
    }, 100);
    timers.add(ping);
    ws.on('close', () => { ++report.closed; clearInterval(ping); timers.delete(ping); });
    if (request.url !== '/primary') {
        const close = setTimeout(() => {
            timers.delete(close);
            if (index % 2 === 0) { ws.close(); } else { ws.terminate(); }
        }, 140);
        timers.add(close);
    }
});
server.on('listening', () => {
    const script = `
var source = require('meshDesktop').getRemoteDesktopStream();
var http = require('http'), refs = {}, nextId = 0, ended = 0;
process.on('uncaughtException', function(e) { console.log('UNCAUGHT ' + e + ' ' + e.stack); });
function connect(primary) {
    var id = ++nextId;
    var request = http.request({ protocol: 'ws:', host: '127.0.0.1', port: ${server.address().port},
        path: primary ? '/primary' : '/other', method: 'GET', headers: { Host: '127.0.0.1' }, perMessageDeflate: false });
    refs[id] = request;
    request.on('error', function(e) { console.log('REQUEST_ERROR ' + e); });
    request.on('upgrade', function(response, stream) {
        request.stream = stream;
        stream.httprequest = request;
        stream.setTimeout(300);
        stream.on('timeout', function() { this.ping(); this.setTimeout(300); });
        stream.on('data', function(data) {
            if (typeof data === 'string' && JSON.parse(data).type === 'ping') {
                stream.write('{"ctrlChannel":"102938","type":"pong"}');
            }
        });
        source.pipe(stream, { dataTypeSkip: 1 });
        stream.pipe(source, { dataTypeSkip: 1, end: false });
        stream.end = function() {
            ++ended;
            source.unpipe(stream);
            stream.unpipe(source);
            delete refs[id];
            this.httprequest = null;
        };
    });
    request.end();
}
connect(true);
var churn = setInterval(function() { connect(false); if (nextId >= 61) { clearInterval(churn); } }, 200);
var gc = setInterval(function() { Duktape.gc(); }, 500);
var done = setTimeout(function() {
    clearInterval(churn);
    clearInterval(gc);
    source.end();
    console.log('KVM_RECONNECT_DONE created=' + nextId + ' ended=' + ended);
    process.exit(0);
}, 14000);
`;
    fs.writeFileSync(path.join(evidence, 'probe.js'), script);
    const child = spawn(runner, ['-exec', script], { cwd: evidence, windowsHide: true });
    report.pid = child.pid;
    let stdout = '', stderr = '', finished = false;
    child.stdout.on('data', data => { stdout = (stdout + data).slice(-200000); });
    child.stderr.on('data', data => { stderr = (stderr + data).slice(-200000); });
    const watchdog = setTimeout(() => { report.errors.push('Native chain failed to complete within 25 seconds'); child.kill(); }, 25000);
    function finish(code, signal, error) {
        if (finished) { return; }
        finished = true;
        clearTimeout(watchdog);
        for (const timer of timers) { clearTimeout(timer); }
        for (const ws of server.clients) { ws.terminate(); }
        server.close();
        if (error) { report.errors.push(String(error)); }
        Object.assign(report, { code, signal, stdout, stderr });
        report.success = code === 0 && report.connections >= 10 && report.pictures >= 5 &&
            report.lastPictureMs >= 8000 && /KVM_RECONNECT_DONE/.test(stdout) &&
            !/UNCAUGHT|REQUEST_ERROR/.test(stdout) && report.errors.length === 0;
        fs.writeFileSync(path.join(evidence, 'result.json'), JSON.stringify(report, null, 2));
        console.log(JSON.stringify({ ...report, stdout: undefined, stderr: undefined }));
        process.exitCode = report.success ? 0 : 1;
    }
    child.on('error', error => finish(null, null, error));
    child.on('exit', (code, signal) => finish(code, signal));
});
