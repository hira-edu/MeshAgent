// Run one MeshCentral "My Server" console command on a running duplicate layout, as its site admin.
//
// node server_console.js <layoutRoot> <host> <port> <certName> <credsFile> <command> [timeoutSeconds]
//
// Logs in over HTTPS (POST /login, the layout's own root certificate, the certificate name checked), opens the
// control channel (wss://<host>:<port>/control.ashx) with the session cookie using the layout's own `ws`
// package, sends {action: 'serverconsole', value: <command>} and prints every 'serverconsole' reply carrying
// its tag as one JSON object. Used for "autobackup", which MeshCentral otherwise runs only at its hourly
// maintenance tick: the console command calls the same db.performBackup and reports its result.
// Credentials are read from the duplicate's secrets file, never from the command line.
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const querystring = require('querystring');

function fail(message) { process.stderr.write('server_console: ' + message + '\n'); process.exit(1); }

const [layoutRoot, host, port, certName, credsFile, command, timeoutArg] = process.argv.slice(2);
if (!layoutRoot || !host || !port || !certName || !credsFile || !command) { fail('usage: server_console.js <layoutRoot> <host> <port> <certName> <credsFile> <command> [timeoutSeconds]'); }
const timeoutMs = 1000 * Number(timeoutArg || 300);
const creds = JSON.parse(fs.readFileSync(credsFile, 'utf8'));
const ca = fs.readFileSync(path.join(layoutRoot, 'meshcentral-data', 'root-cert-public.crt'));
const WebSocket = require(require.resolve('ws', { paths: [path.join(layoutRoot, 'node_modules', 'meshcentral')] }));
const tls = { ca, servername: certName, checkServerIdentity: (name, cert) => require('tls').checkServerIdentity(certName, cert) };

function login() {
    return new Promise((resolve, reject) => {
        const body = querystring.stringify({ action: 'login', username: creds.user, password: creds.password });
        const req = https.request({ host, port: Number(port), method: 'POST', path: '/login', ...tls,
            headers: { 'Host': certName + ':' + port, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, (res) => {
            res.resume();
            const cookies = (res.headers['set-cookie'] || []).map(c => c.split(';')[0]);
            if (!cookies.some(c => c.startsWith('xid='))) { reject(new Error('login returned HTTP ' + res.statusCode + ' without a session cookie')); return; }
            resolve(cookies.join('; '));
        });
        req.on('error', reject);
        req.end(body);
    });
}

(async function main() {
    const cookie = await login();
    const tag = 'dup-' + Date.now();
    const replies = [];
    const ws = new WebSocket('wss://' + host + ':' + port + '/control.ashx', { ...tls, headers: { Cookie: cookie, Host: certName + ':' + port } });
    const timer = setTimeout(() => { finish('timeout'); }, timeoutMs);
    function finish(reason) {
        clearTimeout(timer);
        process.stdout.write(JSON.stringify({ command, end: reason, replies }) + '\n');
        try { ws.close(); } catch (ex) { process.stderr.write('server_console: close: ' + ex.message + '\n'); }
        process.exit(reason === 'timeout' ? 2 : 0);
    }
    ws.on('error', (ex) => fail('control channel: ' + ex.message));
    ws.on('message', (data) => {
        let message;
        try { message = JSON.parse(data.toString('utf8')); } catch (ex) { return; }
        if (message.action === 'serverinfo') { ws.send(JSON.stringify({ action: 'serverconsole', value: command, tag })); return; }
        if (message.action !== 'serverconsole' || message.tag !== tag) { return; }
        replies.push(message.value);
        // performBackup reports through its callback, which createBackupfile and removeExpiredBackupfiles may
        // each call; collect replies until none has arrived for 10 seconds.
        clearTimeout(quiet);
        quiet = setTimeout(() => finish('replied'), 10000);
    });
    let quiet = null;
})().catch((ex) => fail((ex && ex.stack) || String(ex)));
