'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { EMBEDDED_MSH_GUID } = require('./lib/provisioning_identity');
const out = path.resolve(process.argv[2] || path.join(__dirname, '../artifacts/validation/provisioning-validation-' + Date.now()));
fs.mkdirSync(out, { recursive: true });
const identity = { meshName: 'Test', meshId: 'ab'.repeat(48), serverId: 'cd'.repeat(48), serverUrl: 'wss://example.invalid/agent.ashx' };
const policy = Buffer.from(`MeshName=${identity.meshName}\nMeshID=${identity.meshId}\nServerID=${identity.serverId}\nMeshServer=${identity.serverUrl}\n`);
const brand = path.join(out, 'branding.json');
const msh = path.join(out, 'policy.msh');
fs.writeFileSync(brand, JSON.stringify({ provisioning: identity }));
fs.writeFileSync(msh, policy);
const trailer = Buffer.alloc(20);
trailer.writeUInt32BE(policy.length);
EMBEDDED_MSH_GUID.copy(trailer, 4);
const valid = path.join(out, 'valid.exe');
const invalid = path.join(out, 'unprovisioned.exe');
fs.writeFileSync(valid, Buffer.concat([Buffer.alloc(128), policy, trailer]));
fs.writeFileSync(invalid, Buffer.alloc(128));
const missing = path.join(out, 'missing');
const rows = [];
for (const [name, extra, expected] of [
    ['valid-policy', ['--package-exe', valid, '--package-msh', msh], 0],
    ['unprovisioned-exe', ['--package-exe', invalid], 1],
    ['missing-exe', ['--package-exe', missing], 1],
    ['missing-sidecar', ['--package-msh', missing], 1]
]) {
    const result = spawnSync(process.execPath, [path.join(__dirname, 'provisioning-ssot-check.js'), '--evidence', path.join(out, name), '--branding-json', brand, '--meshcentral-msh', msh, ...extra], { encoding: 'utf8', timeout: 10000, windowsHide: true });
    fs.writeFileSync(path.join(out, name + '.log'), (result.stdout || '') + (result.stderr || ''));
    if (result.error) throw result.error;
    assert.strictEqual(result.status, expected, name + ': unexpected exit status');
    rows.push({ name, passed: true });
}
fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(rows, null, 2));
console.log('PASS: ' + rows.length + ' provisioning validation cases');
