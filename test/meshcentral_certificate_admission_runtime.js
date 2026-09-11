'use strict';

// A fresh server-authentication check. Sends only commands 5 and 1: no agent
// identity, enrollment, AuthConfirm shortcut, core download, or remote command.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createRequire } = require('module');
const { parseKvText } = require('./lib/provisioning_identity');

async function probe(policy, WebSocket, timeoutMs) {
    const endpoint = new URL(policy.MeshServer);
    if (endpoint.protocol !== 'wss:' || endpoint.username || endpoint.password || endpoint.hash) {
        throw new Error('MeshServer must be a single wss URL without user information or a fragment');
    }
    if (!/^[a-f0-9]{96}$/i.test(policy.ServerID || '')) {
        throw new Error('ServerID must be a SHA384 public-key hash (96 hex characters)');
    }
    const expectedPin = policy.ServerID.toLowerCase();
    const result = {
        utc: new Date().toISOString(),
        endpoint: endpoint.origin + endpoint.pathname,
        enrolled: false,
        hashAdmitted: false,
        signedServerProof: false
    };
    return new Promise(resolve => {
        const nonce = crypto.randomBytes(48);
        let webHash, serverNonce, proof, finished = false;
        const ws = new WebSocket(endpoint.href, {
            rejectUnauthorized: true,
            handshakeTimeout: timeoutMs,
            perMessageDeflate: false,
            maxPayload: 65536
        });
        const timer = setTimeout(() => finish('Timed out before complete server certificate proof'), timeoutMs);
        function finish(error) {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            result.ok = !error;
            if (error) result.error = error;
            ws.terminate();
            resolve(result);
        }
        function verify() {
            if (!proof || !serverNonce) return;
            const certLength = proof.readUInt16BE(2);
            if (certLength === 0 || proof.length <= certLength + 4) throw new Error('Invalid server proof length');
            const cert = new crypto.X509Certificate(proof.subarray(4, 4 + certLength));
            if (cert.publicKey.asymmetricKeyType !== 'rsa') throw new Error('Non-RSA agent server identity');
            const key = cert.publicKey.export({ type: 'pkcs1', format: 'der' });
            result.serverId = crypto.createHash('sha384').update(key).digest('hex');
            if (result.serverId !== expectedPin) throw new Error('ServerID mismatch');
            const signedData = Buffer.concat([webHash, nonce, serverNonce]);
            if (!crypto.verify('sha384', signedData, cert.publicKey, proof.subarray(4 + certLength))) {
                throw new Error('Invalid server signature');
            }
            result.signedServerProof = true;
            finish();
        }
        ws.on('open', () => {
            try {
                const cert = ws._socket.getPeerCertificate();
                webHash = crypto.createHash('sha384').update(cert.raw).digest();
                result.tlsCertSha384 = webHash.toString('hex');
                result.tlsSubject = cert.subject;
                result.tlsIssuer = cert.issuer;
                result.tls = ws._socket.getProtocol();
                const onSend = error => { if (error) finish(error.message); };
                ws.send(Buffer.concat([Buffer.from([0, 5]), Buffer.from(expectedPin, 'hex')]), onSend);
                ws.send(Buffer.concat([Buffer.from([0, 1]), webHash, nonce]), onSend);
            } catch (error) { finish(error.message); }
        });
        ws.on('message', data => {
            if (finished) return;
            try {
                data = Buffer.isBuffer(data) ? data : Buffer.from(data);
                if (data.length < 2) throw new Error('Short protocol message');
                const cmd = data.readUInt16BE(0);
                if (cmd === 1) {
                    if (serverNonce || data.length !== 98 || !webHash || !data.subarray(2, 50).equals(webHash)) {
                        throw new Error('Invalid server TLS hash response');
                    }
                    serverNonce = data.subarray(50);
                    result.hashAdmitted = true;
                } else if (cmd === 2) {
                    if (proof || data.length < 5) throw new Error('Invalid server proof message');
                    proof = data;
                }
                verify();
            } catch (error) { finish(error.message); }
        });
        ws.on('error', error => finish(error.message));
        ws.on('close', () => { if (!finished) finish('Connection closed before server certificate proof'); });
    });
}

async function main(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i += 2) {
        if (!['--msh', '--meshcentral-package', '--evidence', '--timeout-ms'].includes(argv[i]) || !argv[i + 1]) {
            throw new Error('Usage: node test/meshcentral_certificate_admission_runtime.js --msh <policy> [--meshcentral-package <package.json>] [--evidence <directory>] [--timeout-ms <milliseconds>]');
        }
        if (args[argv[i]]) throw new Error('Duplicate argument: ' + argv[i]);
        args[argv[i]] = argv[i + 1];
    }
    if (!args['--msh']) throw new Error('--msh is required');
    const timeoutMs = Number(args['--timeout-ms'] || 12000);
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) throw new Error('Invalid timeout');
    const packagePath = path.resolve(args['--meshcentral-package'] || path.join(__dirname, '../../MeshCentral/node_modules/meshcentral/package.json'));
    const WebSocket = createRequire(packagePath)('ws');
    const policy = parseKvText(fs.readFileSync(path.resolve(args['--msh']), 'utf8'));
    const result = await probe(policy, WebSocket, timeoutMs);
    const output = JSON.stringify(result, null, 2) + '\n';
    if (args['--evidence']) {
        fs.mkdirSync(path.resolve(args['--evidence']), { recursive: true });
        fs.writeFileSync(path.resolve(args['--evidence'], 'certificate_admission.json'), output);
    }
    process.stdout.write(output);
    process.exitCode = result.ok ? 0 : 1;
}

if (require.main === module) {
    main(process.argv.slice(2)).catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    });
}
module.exports = { probe };
