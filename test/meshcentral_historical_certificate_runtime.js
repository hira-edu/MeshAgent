'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');
const source = fs.readFileSync(path.resolve(__dirname, '../../MeshCentral/meshagent.js'), 'utf8');
function extract(name) {
    const start = source.indexOf('    function ' + name + '(');
    const end = source.indexOf('\n    }', start);
    assert(start >= 0 && end > start, name);
    return source.slice(start, end + 6);
}
const agent = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
const current = crypto.randomBytes(48).toString('binary');
const historical = crypto.randomBytes(48).toString('binary');
const historicalHex = Buffer.from(historical, 'binary').toString('hex');
const other = crypto.randomBytes(48).toString('binary');
const common = {ShortToStr: n => String.fromCharCode(n >> 8, n & 255)};
const requestStart = source.indexOf('            if (cmd == 1) {');
const requestEnd = source.indexOf('\n            else if (cmd == 2)', requestStart);
assert(requestStart >= 0 && requestEnd > requestStart);
const functions = ['getWebCertHash', 'getWebCertFullHash', 'isHistoricalWebCertHash', 'processAgentSignature'].map(extract).join('\n');

function fixture(pins) {
    const sent = [], issues = [], audits = [];
    const domain = {id: 'test', agentwebcerthashes: pins};
    const parent = {crypto, webCertificateHashs: {}, webCertificateFullHashs: {}, webCertificateHash: current, webCertificateFullHash: current,
        defaultWebCertificateHash: current, defaultWebCertificateFullHash: current, agentCertificateAsn1: 'certificate', agentStats: {},
        setAgentIssue: (obj, issue) => issues.push(issue), parent: {supportsProxyCertificatesRequest: false, debug() {},
            certificateOperations: {acceleratorPerformSignature(id, data, tag, callback) { callback(tag, 'server-proof'); }}}};
    const obj = {nonce: crypto.randomBytes(48).toString('binary'), receivedCommands: 0, authenticated: 0, remoteaddrport: 'probe',
        sendBinary: data => sent.push(data), unauth: {nodeid: 'known-agent', nodeCertPem: agent.publicKey.export({type: 'spki', format: 'pem'})}};
    const context = {Buffer, parent, domain, obj, common, forge: {}, isIgnoreHashCheck: () => false, completeAgentConnection() {},
        console: {log: message => audits.push(message)}};
    vm.createContext(context);
    vm.runInContext(functions + '\nfunction request(msg) { const cmd = 1; ' + source.slice(requestStart, requestEnd) + '\n}', context);
    return {context, obj, sent, issues, audits, domain};
}

for (const hash of [current, historical]) {
    const f = fixture([historicalHex.toUpperCase()]);
    const nonce = crypto.randomBytes(48).toString('binary');
    f.context.request(common.ShortToStr(1) + hash + nonce);
    assert.equal(f.sent.length, 2, 'TLS hash response and signed server proof');
    assert.equal(f.obj.authenticated, 0, 'historical TLS admission is not authentication');
    const signature = crypto.sign('sha384', Buffer.from(hash + f.obj.nonce + nonce, 'binary'), agent.privateKey);
    assert.equal(f.context.processAgentSignature(signature.toString('binary')), true);
    assert.equal(f.obj.authenticated, 1);
    assert.equal(f.audits.filter(x => x.startsWith('[AGENT_CERT_COMPAT]')).length, hash === historical ? 1 : 0);
}
for (const pins of [undefined, true, '*', ['*'], [null], [historicalHex.slice(2)], ['0'.repeat(96)], [other]]) {
    const f = fixture(pins);
    f.context.request(common.ShortToStr(1) + historical + crypto.randomBytes(48).toString('binary'));
    assert.equal(f.sent.length, 0, 'untrusted TLS hash remains blocked');
    assert.equal(f.obj.authenticated, 0);
    assert.equal(f.issues.length, 1);
}
const foreign = fixture([historicalHex]);
foreign.context.request(common.ShortToStr(1) + other + crypto.randomBytes(48).toString('binary'));
assert.equal(foreign.sent.length, 0, 'unknown certificate is never auto-trusted');
foreign.domain.agentwebcerthashes = [];
assert.equal(foreign.context.isHistoricalWebCertHash(foreign.domain, historical), false, 'pins stay domain-scoped');
const invalid = fixture([historicalHex]);
invalid.context.request(common.ShortToStr(1) + historical + crypto.randomBytes(48).toString('binary'));
assert.equal(invalid.context.processAgentSignature(crypto.randomBytes(256).toString('binary')), false, 'invalid agent proof rejected');
assert.equal(invalid.obj.authenticated, 0);
assert.equal(invalid.audits.filter(x => x.startsWith('[AGENT_CERT_COMPAT]')).length, 0);
const replay = fixture([historicalHex]);
const msg = common.ShortToStr(1) + historical + crypto.randomBytes(48).toString('binary');
replay.context.request(msg); replay.context.request(msg);
assert.equal(replay.sent.length, 2, 'duplicate authentication request remains blocked');
assert.equal(replay.context.isHistoricalWebCertHash(replay.domain, '\0'.repeat(48)), false);
assert.equal(replay.context.isHistoricalWebCertHash(replay.domain, historical + 'x'), false);
console.log('PASS: current/historical TLS admission, actual RSA proof, invalid signatures, unknown/malformed/zero pins, domain isolation and replay guard');
