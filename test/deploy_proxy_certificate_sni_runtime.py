"""Run the fork's obj.updateProxyCertificates and check which hostname each certificate load uses.

An HTTPS certurl is read with the URL's own hostname (SNI, incident I3); an HTTPS certurl whose host
is an IP address, which SNI cannot carry (RFC 6066, SRV-16), and a file certurl keep the domain's DNS
name, or settings.cert when the domain has none. The function is taken from the fork's committed
meshcentral.js and run under Node with a fake certificate loader. No network I/O.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "test" / "lib"))
import meshcentral_paths  # noqa: E402

START = "    obj.updateProxyCertificates = function (force) {"
END = "\n    // Perform maintenance operations"

source = meshcentral_paths.fork_file("meshcentral.js").read_bytes().decode("utf-8").replace("\r\n", "\n")
assert source.count(START) == 1, "the fork meshcentral.js must define obj.updateProxyCertificates once"
begin = source.index(START)
end = source.index(END, begin)
function_source = source[begin:end]
assert "loadCertificate(" in function_source, "updateProxyCertificates must load the domain certificates"

fixture = r"""
const assert = require('assert');
const vm = require('vm');
const loads = [];
const domains = {
    '': { id: '', dns: 'portal.example.test', certurl: 'https://agents.example.test/' },
    port: { id: 'port', dns: 'portal.example.test', certurl: 'https://agents.example.test:443/path' },
    file: { id: 'file', dns: 'files.example.test', certurl: 'file:/public/cert.pem' },
    nodns: { id: 'nodns', certurl: 'file:/public/other.pem' },
    ipv4: { id: 'ipv4', dns: 'portal.example.test', certurl: 'https://192.0.2.10/' },
    ipv6: { id: 'ipv6', certurl: 'https://[2001:db8::1]:8443/cert' },
    nocert: { id: 'nocert', dns: 'plain.example.test' }
};
const logs = [];
const obj = {
    config: { domains, settings: { cert: 'settings.example.test' } },
    pendingProxyCertificatesRequests: 0,
    certificateOperations: {
        loadCertificate: (url, hostname, domain, callback) => { loads.push({ url, hostname, domain }); callback(url, null, hostname, domain); }
    },
    common: { format: (text, ...args) => text.replace(/\{(\d+)\}/g, (match, index) => args[index]) }
};
vm.runInNewContext(FUNCTION, { obj, URL, Buffer, require, console: { log: message => logs.push(message) } });
obj.updateProxyCertificates(true);
assert.deepStrictEqual(loads.map(load => [load.domain.id, load.url, load.hostname]), [
    ['', 'https://agents.example.test/', 'agents.example.test'],
    ['port', 'https://agents.example.test:443/path', 'agents.example.test'],
    ['file', 'file:/public/cert.pem', 'files.example.test'],
    ['nodns', 'file:/public/other.pem', 'settings.example.test'],
    ['ipv4', 'https://192.0.2.10/', 'portal.example.test'],
    ['ipv6', 'https://[2001:db8::1]:8443/cert', 'settings.example.test']
]);
for (const load of loads) { assert.strictEqual(load.domain, domains[load.domain.id]); }
assert.strictEqual(obj.pendingProxyCertificatesRequests, 0, 'every load callback must settle its pending request');
assert.strictEqual(logs.length, loads.length, 'a failed certificate load is logged');
console.log('Proxy certificate SNI follows an HTTPS URL host name; IP and file certurls keep the domain or settings hostname.');
""".replace("FUNCTION", json.dumps(function_source))

with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / "sni.js"
    path.write_text(fixture, encoding="utf-8")
    subprocess.run(["node", str(path)], check=True)
