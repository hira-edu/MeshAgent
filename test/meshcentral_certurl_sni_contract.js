'use strict';
// SRV-16: MeshCentral reads a domain's certurl certificate with the SNI name the front answers.
// An SNI-strict front only presents its certificate for its own name, so an https certurl is asked
// for its URL host. TLS SNI cannot carry an IP address (RFC 6066), so an IP certurl (upstream's
// documented reverse-proxy form, sample-config-advanced.json) keeps the domain DNS name, as stock
// MeshCentral does. A file: certurl always keeps the domain DNS name.
// The fork's own statements from updateProxyCertificates are executed here.
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { forkFile } = require('./lib/meshcentral_paths');

const source = fs.readFileSync(forkFile('meshcentral.js'), 'utf8').replace(/\r\n?/g, '\n');
const start = source.indexOf('                var dnsname = obj.config.domains[i].dns;');
const call = '                obj.certificateOperations.loadCertificate(obj.config.domains[i].certurl, ';
const callStart = source.indexOf(call, start);
assert(start >= 0 && callStart > start, 'updateProxyCertificates must compute dnsname and then call loadCertificate');
const callEnd = source.indexOf(', function (url, cert, xhostname, xdomain) {', callStart);
assert(callEnd > callStart, 'loadCertificate call must pass the certificate callback');
const statements = source.slice(start, callEnd) + ');';
assert.strictEqual(source.split(call).length, 2, 'exactly one certurl loadCertificate call');

function loadedHostname(certurl, domainDns, settingsCert) {
    let seen = null;
    const domain = { certurl, dns: domainDns };
    const obj = {
        config: { domains: { '': domain }, settings: { cert: settingsCert } },
        certificateOperations: { loadCertificate(url, hostname, tag) { seen = { url, hostname, tag }; } }
    };
    vm.runInNewContext(statements, { obj, i: '', URL, require });
    assert(seen, 'loadCertificate was called');
    assert.strictEqual(seen.url, certurl, 'the configured certurl is loaded unchanged');
    assert.strictEqual(seen.tag, domain, 'the domain is passed through');
    return seen.hostname;
}

// An https certurl with a DNS host: its own host is the SNI name (the SNI-strict front case).
assert.strictEqual(loadedHostname('https://agents.high.support/', undefined, 'high.support'), 'agents.high.support');
assert.strictEqual(loadedHostname('https://agents.high.support:443/path', undefined, 'high.support'), 'agents.high.support');
assert.strictEqual(loadedHostname('https://Front.Example:8443/', 'mesh.example', 'cert.example'), 'front.example');

// An IP certurl keeps the domain DNS name, then settings.cert, as upstream does.
assert.strictEqual(loadedHostname('https://192.168.2.106:443/', undefined, 'high.support'), 'high.support', 'IPv4 certurl uses settings.cert');
assert.strictEqual(loadedHostname('https://192.168.2.106/', 'mesh.example', 'high.support'), 'mesh.example', 'IPv4 certurl uses the domain dns first');
assert.strictEqual(loadedHostname('https://[::1]:4443/', undefined, 'high.support'), 'high.support', 'IPv6 certurl uses settings.cert');
assert.strictEqual(loadedHostname('https://[fe80::1]/', 'mesh.example', undefined), 'mesh.example', 'IPv6 certurl uses the domain dns');
assert.strictEqual(loadedHostname('https://10.0.0.5/', undefined, undefined), undefined, 'with no name configured, loadCertificate picks its default as upstream');

// A file certurl keeps the domain DNS name.
assert.strictEqual(loadedHostname('file:///etc/meshcentral/front.crt', undefined, 'high.support'), 'high.support');
assert.strictEqual(loadedHostname('file:///etc/meshcentral/front.crt', 'mesh.example', 'high.support'), 'mesh.example');

console.log('meshcentral_certurl_sni_contract: PASS (DNS certurl host as SNI; IP and file certurls keep the domain DNS name)');
