'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const tls = require('tls');
const crypto = require('crypto');
const vm = require('vm');
const {EventEmitter} = require('events');
const {spawnSync} = require('child_process');
const forge = require('../../MeshCentral/node_modules/node-forge');
const {certificateHashes, endpointCertificate} = require('../tools/configure_agent_certificate_history');

async function main() {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'certificate-history-'));
    let server;
    try {
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const cert = forge.pki.createCertificate();
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date(Date.now() - 60000);
        cert.validity.notAfter = new Date(Date.now() + 86400000);
        cert.setSubject([{name: 'commonName', value: 'localhost'}]);
        cert.setIssuer(cert.subject.attributes);
        cert.setExtensions([{name: 'subjectAltName', altNames: [{type: 2, value: 'localhost'}]}]);
        cert.sign(keys.privateKey, forge.md.sha256.create());
        const pem = forge.pki.certificateToPem(cert), privatePem = forge.pki.privateKeyToPem(keys.privateKey);
        const hashes = certificateHashes(pem);
        assert.equal(hashes.length, 2);
        const x509 = new crypto.X509Certificate(pem);
        assert.equal(hashes[0], crypto.createHash('sha384').update(x509.raw).digest('hex'));
        assert.equal(hashes[1], crypto.createHash('sha384').update(x509.publicKey.export({type: 'pkcs1', format: 'der'})).digest('hex'));
        assert.throws(() => certificateHashes(pem + privatePem), /private key/);
        assert.throws(() => endpointCertificate('http://localhost/'), /HTTPS/);
        server = tls.createServer({cert: pem, key: privatePem}, socket => socket.end());
        server.on('tlsClientError', () => {});
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        await assert.rejects(endpointCertificate('https://localhost:' + server.address().port), /self-signed/);
        await new Promise(resolve => server.close(resolve));
        server = null;

        let requests = 0;
        const testModule = {exports: {}};
        const fakeRequire = name => name === 'tls' ? {connect(options, callback) {
            requests++;
            assert.equal(options.rejectUnauthorized, true);
            assert.equal(options.servername, options.host);
            const socket = new EventEmitter();
            socket.authorized = options.host === 'trusted.example';
            socket.setTimeout = () => socket;
            socket.end = () => {};
            socket.destroy = () => {};
            socket.getPeerCertificate = () => ({raw: x509.raw});
            queueMicrotask(() => callback());
            return socket;
        }} : require(name);
        vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, '../tools/configure_agent_certificate_history.js'), 'utf8'),
            {require: fakeRequire, module: testModule, Buffer, URL, process, console: {log() {}}, queueMicrotask, setTimeout, clearTimeout});
        const domain = {id: 'fixture', agentwebcerthashes: [], agentwebcerturls: ['https://trusted.example/']};
        const refresh = testModule.exports.refreshDomain;
        const firstRefresh = refresh(domain);
        assert.equal(await refresh(domain), false, 'coalesce concurrent refreshes');
        assert.equal(await firstRefresh, true);
        assert.deepEqual([...domain.agentwebcerthashes].sort(), hashes.slice().sort());
        assert.equal(await refresh(domain), false, 'rate limit repeated requests');
        assert.equal(requests, 1);
        const rejected = {id: 'denied', agentwebcerthashes: [], agentwebcerturls: ['https://untrusted.example/']};
        assert.equal(await refresh(rejected), false);
        assert.equal(rejected.agentwebcerthashes.length, 0, 'failed CA admission does not add a pin');
        assert.equal(await refresh({agentwebcerturls: Array(17).fill('https://trusted.example/')}), false);

        const configPath = path.join(temp, 'config.json');
        const history = path.join(temp, 'certificates');
        fs.mkdirSync(history);
        fs.writeFileSync(path.join(history, 'webserver-cert-public.crt-old'), pem);
        fs.writeFileSync(path.join(history, 'unrelated-cert.pem'), privatePem);
        const oldPin = crypto.randomBytes(48).toString('hex');
        const config = {settings: {ignoreAgentHashCheck: false, untouched: 'retained'}, domains: {'': {agentwebcerthashes: [oldPin]}, other: {}}};
        fs.writeFileSync(configPath, JSON.stringify(config));
        const tool = path.resolve(__dirname, '../tools/configure_agent_certificate_history.js');
        const run = (...args) => spawnSync(process.execPath, [tool, '--config', configPath, ...args], {encoding: 'utf8', timeout: 20000});
        let result = run('--history-dir', history);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(JSON.parse(result.stdout).changed, true);
        const updated = JSON.parse(fs.readFileSync(configPath));
        assert.deepEqual(updated.domains[''].agentwebcerthashes, [oldPin, ...hashes].sort());
        assert.deepEqual(updated.domains.other, {});
        assert.equal(updated.settings.untouched, 'retained');
        const backups = path.join(temp, 'certificate-history-backups');
        assert.equal(fs.readdirSync(backups).length, 1);
        assert.deepEqual(JSON.parse(fs.readFileSync(path.join(backups, fs.readdirSync(backups)[0]))), config);
        result = run('--history-dir', history);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(JSON.parse(result.stdout).changed, false);
        assert.equal(fs.readdirSync(backups).length, 1);
        const baseline = fs.readFileSync(configPath, 'utf8');
        for (const input of [privatePem, 'malformed certificate']) {
            const filename = path.join(temp, 'invalid.crt');
            fs.writeFileSync(filename, input);
            assert.notEqual(run('--certificate', filename).status, 0);
            assert.equal(fs.readFileSync(configPath, 'utf8'), baseline);
        }
        assert.notEqual(run('--endpoint', 'http://localhost').status, 0);
        assert.equal(fs.readFileSync(configPath, 'utf8'), baseline);
        for (const pin of ['*', '0'.repeat(96), 'short']) {
            const invalid = JSON.parse(baseline);
            invalid.domains[''].agentwebcerthashes = [pin];
            fs.writeFileSync(configPath, JSON.stringify(invalid));
            assert.notEqual(run('--history-dir', history).status, 0);
        }
        const bypass = JSON.parse(baseline);
        bypass.settings.ignoreAgentHashCheck = true;
        fs.writeFileSync(configPath, JSON.stringify(bypass));
        assert.notEqual(run('--history-dir', history).status, 0);
        assert.equal(fs.readdirSync(backups).length, 1, 'failed collection never changes configuration or adds a backup');
        console.log('PASS: real certificate/key hashes, CA rejection, bounded/coalesced endpoint refresh, private-key rejection, scoped config, backup, idempotence and failure atomicity');
    } finally {
        if (server) await new Promise(resolve => server.close(resolve));
        fs.rmSync(temp, {recursive: true, force: true});
    }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
