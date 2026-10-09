const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { buildChecks, buildLegacyChecks } = require('./service_bundle_embedding_contract.js');

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; ++i) {
        if (argv[i] === '--evidence' && i + 1 < argv.length) { args.evidence = argv[++i]; }
    }
    return args;
}

const args = parseArgs(process.argv.slice(2));
const checks = buildChecks({ size: 123, sha256: 'ABC' }, 'ABC', 123);
const legacyChecks = buildLegacyChecks({ size: 123, sha256: 'ABC' }, 'ABC', 123);
assert.deepStrictEqual(Object.keys(checks), [
    'embeddedServiceBundlePresent',
    'embeddedServiceBundleMatchesDllHash',
    'embeddedServiceBundleMatchesDllSize'
]);
assert.deepStrictEqual(Object.keys(legacyChecks), [
    'embeddedPayloadPresent',
    'embeddedPayloadMatchesDllHash',
    'embeddedPayloadMatchesDllSize'
]);
assert.strictEqual(checks.embeddedServiceBundlePresent, true);
assert.strictEqual(checks.embeddedServiceBundleMatchesDllHash, true);
assert.strictEqual(checks.embeddedServiceBundleMatchesDllSize, true);
assert.strictEqual(legacyChecks.embeddedPayloadPresent, checks.embeddedServiceBundlePresent);
assert.strictEqual(legacyChecks.embeddedPayloadMatchesDllHash, checks.embeddedServiceBundleMatchesDllHash);
assert.strictEqual(legacyChecks.embeddedPayloadMatchesDllSize, checks.embeddedServiceBundleMatchesDllSize);

if (args.evidence) {
    const evidenceDir = path.resolve(args.evidence);
    fs.mkdirSync(evidenceDir, { recursive: true });
    fs.writeFileSync(path.join(evidenceDir, 'service_bundle_evidence_schema_contract.txt'),
        'SUCCESS=true\n' +
        'CURRENT_KEYS=' + Object.keys(checks).join(',') + '\n' +
        'LEGACY_KEYS=' + Object.keys(legacyChecks).join(',') + '\n');
}
console.log('service bundle evidence schema: current and exact legacy schemas agree');
