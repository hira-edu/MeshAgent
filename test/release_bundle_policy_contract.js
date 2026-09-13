const assert = require('assert').strict;
const {
    buildChecklist,
    collectFailures,
    parseSigningPolicy,
    signingRequiredForArtifact
} = require('./release_bundle_gate');

function peRecord({ enforceSigning = false, found = true, isPe = true, hasCertificateTable = false } = {}) {
    return {
        id: 'fixture.exe',
        required: true,
        peArtifact: true,
        signedRequired: signingRequiredForArtifact({ signed: true }, enforceSigning),
        found,
        digests: found ? { sha256: 'fixture' } : null,
        signature: found ? { isPe, hasCertificateTable } : null
    };
}

function checklist(artifactManifest, overrides = {}) {
    return buildChecklist({
        artifactManifest,
        missingReleaseDocuments: overrides.missingReleaseDocuments || [],
        bundleExported: overrides.bundleExported !== false
    });
}

assert.deepEqual(
    parseSigningPolicy({ security: { enforceSigning: false } }, 'fixture.json'),
    { source: 'fixture.json', enforceSigning: false }
);
assert.throws(
    () => parseSigningPolicy({ security: { enforceSigning: 'false' } }, 'fixture.json'),
    /must be a boolean/
);
assert.throws(
    () => parseSigningPolicy({}, 'fixture.json'),
    /Missing branding security policy/
);

assert.equal(signingRequiredForArtifact({ signed: true }, false), false);
assert.equal(signingRequiredForArtifact({ signed: true }, true), true);
assert.equal(signingRequiredForArtifact({ signed: false }, true), false);

const unsignedPolicy = checklist([peRecord()]);
assert.equal(unsignedPolicy.release_ready, true, 'valid unsigned PE must be accepted when signing enforcement is disabled');
assert.equal(unsignedPolicy.signed_artifacts_have_pe_certificate_table, true, 'the signing check is vacuously satisfied when policy requires no signed artifacts');

const enforcedUnsigned = checklist([peRecord({ enforceSigning: true })]);
assert.equal(enforcedUnsigned.release_ready, false, 'unsigned PE must be rejected when signing enforcement is enabled');
assert.match(collectFailures(enforcedUnsigned).join('; '), /certificate table/);

const malformedPe = checklist([peRecord({ isPe: false })]);
assert.equal(malformedPe.release_ready, false, 'disabled signing must not conceal malformed PE inputs');
assert.match(collectFailures(malformedPe).join('; '), /malformed or not PE/);

assert.equal(checklist([peRecord({ found: false })]).release_ready, false, 'missing required artifacts must remain blocking');
assert.equal(checklist([peRecord()], { missingReleaseDocuments: ['missing.md'] }).release_ready, false, 'missing documents must remain blocking');
assert.equal(checklist([peRecord()], { bundleExported: false }).release_ready, false, 'archive export failure must remain blocking');

const missingDigest = peRecord();
missingDigest.digests = null;
assert.equal(checklist([missingDigest]).release_ready, false, 'missing digests must remain blocking');

process.stdout.write('release bundle signing policy contract passed\n');
