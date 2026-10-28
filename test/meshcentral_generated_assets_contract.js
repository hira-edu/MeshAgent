'use strict';
// G5: every generated or minified file tracked in MeshCentral (agents/meshcore.min.js,
// agents/modules_meshcore_min/**, public/scripts/*-min.js and any other *.min.js) must be
// listed in fixtures/meshcentral-fork-hunks/generated-assets.json with how it is produced.
//   builders        each reproducible builder runs with --check and must report no drift.
//   built           the file is fully produced by one of those builders.
//   no-builder-yet  nothing regenerates the file yet. It is reported as PENDING with its
//                   size and line count next to its source, plus the work package that
//                   adds a builder. A copy-of-source file must still equal its source,
//                   except for a recorded known drift, which is reported as DRIFT.
//   vendored        third-party build output with no source here.
//   upstreamPublished  npm build output the fork ships unchanged; it must stay byte-equal to the
//                   pinned upstream package (test/lib/meshcentral_upstream_reference.json), so a
//                   later edit cannot slip through.
// An unlisted generated file, a listed file that is not tracked, or a file listed twice fails.
// Builder scripts live in the deployment wrapper (deploy/scripts) since Stage 1.
//
// MeshCentral is located by test/lib/meshcentral_paths.js (MESHCENTRAL_ROOT, or the sibling
// ../MeshCentral checkout).
// Options:
//   --print-drift <path>  print the current normalised diff from a file's source to it
//                         (to review and record a known drift); nothing is written
//   --evidence <dir>      write the full report as JSON into <dir>
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { meshcentralRoot, readWorkingFile, normalisedDiff, parseDiff, git } = require('./meshcentral_upstream_base_contract');
const meshcentralPaths = require('./lib/meshcentral_paths');

const fixtureDir = path.join(__dirname, 'fixtures', 'meshcentral-fork-hunks');
const manifestPath = path.join(fixtureDir, 'generated-assets.json');
// Served trees only: deploy/scripts holds the builders themselves (build-viewer-min.js).
const GENERATED = /^(agents|public)\/(.+\/)?[^/]+[.-]min\.js$/;
const MODULES_MIN = 'agents/modules_meshcore_min/';

function loadManifest() {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    for (const key of ['builders', 'pending', 'files', 'vendored', 'upstreamPublished']) {
        assert(manifest[key] && typeof manifest[key] === 'object', 'generated-assets.json needs ' + key);
    }
    for (const [id, builder] of Object.entries(manifest.builders)) {
        assert(typeof builder.script === 'string' && Array.isArray(builder.args) && builder.args.includes('--check'), 'builder ' + id + ' needs script and --check args');
        assert(Array.isArray(builder.covers) && builder.covers.length, 'builder ' + id + ' needs covers');
    }
    for (const [id, pending] of Object.entries(manifest.pending)) {
        assert(typeof pending.reason === 'string' && pending.reason && typeof pending.workPackage === 'string' && pending.workPackage, 'pending ' + id + ' needs reason and workPackage');
    }
    for (const [file, entry] of Object.entries(manifest.files)) {
        assert(typeof entry.producedBy === 'string' && entry.producedBy, file + ': producedBy is required');
        assert(['built', 'no-builder-yet'].includes(entry.state), file + ': state must be built or no-builder-yet');
        if (entry.state === 'built') { assert(manifest.builders[entry.builder], file + ': built needs a known builder'); }
        if (entry.state === 'no-builder-yet') { assert(manifest.pending[entry.pending], file + ': no-builder-yet needs a known pending record'); }
        assert(['copy-of-source', 'minified', 'hand-edited'].includes(entry.relation), file + ': relation must be copy-of-source, minified or hand-edited');
        if (entry.knownDrift) {
            assert(entry.relation === 'copy-of-source' && typeof entry.knownDrift.diff === 'string' && entry.knownDrift.id && entry.knownDrift.description, file + ': knownDrift needs id, description and diff on a copy-of-source file');
        }
    }
    for (const [file, reason] of Object.entries(manifest.vendored)) {
        assert(typeof reason === 'string' && reason, file + ': vendored needs a reason');
        assert(!manifest.files[file], file + ' is both generated and vendored');
    }
    for (const [file, producedBy] of Object.entries(manifest.upstreamPublished)) {
        assert(typeof producedBy === 'string' && producedBy, file + ': upstreamPublished needs how upstream produced it');
        assert(!manifest.files[file] && !manifest.vendored[file], file + ' is listed as upstreamPublished and in another section');
    }
    return manifest;
}

function sizeOf(root, file) {
    const bytes = fs.statSync(path.join(root, file)).size;
    const text = readWorkingFile(root, file);
    const lines = text.length === 0 ? 0 : text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
    return { bytes, lines, text };
}

function runBuilder(root, id, builder) {
    const script = path.join(root, builder.script);
    const result = spawnSync(process.execPath, [script].concat(builder.args), { cwd: root, encoding: 'utf8', windowsHide: true });
    if (result.error) { throw new Error('builder ' + id + ' could not run: ' + result.error.message); }
    const reason = String(result.stderr || '').split('\n').find((line) => /^\w*Error\b/.test(line)) || String(result.stderr || '').trim();
    return { status: result.status, reason };
}

function main() {
    const argv = process.argv.slice(2);
    const root = meshcentralRoot();
    const manifest = loadManifest();
    const printIndex = argv.indexOf('--print-drift');
    if (printIndex >= 0) {
        const file = argv[printIndex + 1];
        assert(manifest.files[file] && manifest.files[file].source, '--print-drift needs a listed file with a source');
        process.stdout.write(normalisedDiff(readWorkingFile(root, manifest.files[file].source), readWorkingFile(root, file), file));
        return;
    }

    const failures = [];
    const report = { meshcentral: root, builders: {}, files: {} };

    // Coverage: every tracked generated file must be listed.
    const tracked = git(root, ['ls-files', '-z']).stdout.split('\0').filter(Boolean);
    const generated = tracked.filter((file) => GENERATED.test(file) || file.startsWith(MODULES_MIN)).sort();
    assert(generated.length > 0, 'No generated file is tracked in ' + root + '; the checkout layout changed');
    for (const file of generated) {
        if (!manifest.files[file] && !manifest.vendored[file] && !manifest.upstreamPublished[file]) { failures.push('unlisted ' + file + ': generated file with no generated-assets.json entry'); }
    }
    const trackedSet = new Set(tracked);
    for (const file of Object.keys(manifest.files).concat(Object.keys(manifest.vendored), Object.keys(manifest.upstreamPublished))) {
        if (!trackedSet.has(file)) { failures.push('stale ' + file + ': listed in generated-assets.json but not tracked in MeshCentral'); }
    }

    for (const id of Object.keys(manifest.builders).sort()) {
        const builder = manifest.builders[id];
        const outcome = runBuilder(root, id, builder);
        report.builders[id] = Object.assign({ command: [builder.script].concat(builder.args).join(' ') }, outcome);
        const label = 'builder ' + id + ' (node ' + report.builders[id].command + '; covers ' + builder.covers.join(', ') + ')';
        if (outcome.status === 0) { console.log('PASS ' + label); } else {
            failures.push(label + ' reports drift or failed (exit ' + outcome.status + '): ' + outcome.reason);
        }
    }

    let knownDrifts = 0;
    for (const file of Object.keys(manifest.files).sort()) {
        if (!trackedSet.has(file)) { continue; }
        const entry = manifest.files[file];
        const current = sizeOf(root, file);
        const result = { state: entry.state, relation: entry.relation, producedBy: entry.producedBy, bytes: current.bytes, lines: current.lines };
        report.files[file] = result;
        let comparison = '';
        let source = null;
        if (entry.source) {
            source = sizeOf(root, entry.source);
            result.source = { file: entry.source, bytes: source.bytes, lines: source.lines };
            comparison = ' vs source ' + entry.source + ' ' + source.bytes + ' B/' + source.lines + ' lines';
        }

        if (entry.relation === 'copy-of-source') {
            assert(source, file + ': copy-of-source needs a source');
            const drift = normalisedDiff(source.text, current.text, file);
            const expected = entry.knownDrift ? readFixture(entry.knownDrift.diff) : '';
            if (drift !== expected) {
                const hunks = parseDiff(drift).hunks;
                failures.push(file + ': ' + (drift === '' ? 'known drift ' + entry.knownDrift.id + ' is resolved; remove knownDrift from generated-assets.json' :
                    'differs from its source ' + entry.source + ' by ' + hunks.length + ' unrecorded hunk(s): ' + hunks.map((hunk) => hunk.header).join(' ')));
            } else if (entry.knownDrift) {
                knownDrifts++;
                const parsed = parseDiff(drift);
                result.knownDrift = { id: entry.knownDrift.id, added: parsed.added, removed: parsed.removed };
                console.log('DRIFT ' + file + ' (known ' + entry.knownDrift.id + ', recorded in ' + entry.knownDrift.diff + '): ' + entry.knownDrift.description);
                for (const line of parsed.removed) { console.log('  missing from generated: ' + line.trim().slice(0, 160)); }
                for (const line of parsed.added) { console.log('  only in generated: ' + line.trim().slice(0, 160)); }
            }
        }

        const size = current.bytes + ' B/' + current.lines + ' lines';
        if (entry.state === 'built') {
            console.log('BUILT ' + file + ' ' + size + comparison + ' (builder ' + entry.builder + ')');
        } else {
            const pending = manifest.pending[entry.pending];
            result.pending = pending;
            console.log('PENDING ' + file + ' no-builder-yet, ' + entry.relation + ' [' + entry.pending + ']: ' + size + comparison);
        }
    }
    for (const file of Object.keys(manifest.vendored).sort()) {
        console.log('VENDORED ' + file + ': ' + manifest.vendored[file]);
    }
    const upstreamFiles = Object.keys(manifest.upstreamPublished).filter((file) => trackedSet.has(file)).sort();
    if (upstreamFiles.length) {
        const reference = meshcentralPaths.upstreamPackageDir();
        const pin = meshcentralPaths.loadReferencePin();
        let equalCount = 0;
        for (const file of upstreamFiles) {
            const upstreamPath = path.join(reference, file);
            if (!fs.existsSync(upstreamPath)) { failures.push(file + ': upstream-published but not in the ' + pin.name + '@' + pin.version + ' package'); continue; }
            if (!fs.readFileSync(path.join(root, file)).equals(fs.readFileSync(upstreamPath))) {
                failures.push(file + ': upstream-published but not byte-equal to ' + pin.name + '@' + pin.version + '; review the change and list it under files');
                continue;
            }
            equalCount++;
        }
        report.upstreamPublished = { reference: pin.name + '@' + pin.version, files: upstreamFiles.length, byteEqual: equalCount };
        console.log('UPSTREAM ' + equalCount + ' of ' + upstreamFiles.length + ' npm-published generated files byte-equal to ' + pin.name + '@' + pin.version);
    }
    for (const [id, pending] of Object.entries(manifest.pending)) {
        console.log('PENDING [' + id + '] flips at ' + pending.workPackage + ': ' + pending.reason);
    }

    const evidenceIndex = argv.indexOf('--evidence');
    if (evidenceIndex >= 0) {
        assert(argv[evidenceIndex + 1], '--evidence needs a directory');
        const dir = path.resolve(argv[evidenceIndex + 1]);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'meshcentral_generated_assets_contract.json'), JSON.stringify(Object.assign(report, { failures }), null, 2));
    }
    const states = Object.values(report.files);
    const summary = Object.keys(report.builders).length + ' builders, ' + states.filter((entry) => entry.state === 'built').length + ' built, ' +
        states.filter((entry) => entry.state === 'no-builder-yet').length + ' no-builder-yet, ' + knownDrifts + ' known drift, ' + Object.keys(manifest.vendored).length + ' vendored, ' +
        Object.keys(manifest.upstreamPublished).length + ' upstream-published';
    for (const failure of failures) { console.log('FAIL ' + failure); }
    console.log((failures.length ? 'FAIL' : 'PASS') + ' MeshCentral generated assets (' + summary + ')');
    if (failures.length) { process.exitCode = 1; }
}

function readFixture(relative) {
    const file = path.join(fixtureDir, relative);
    try { return fs.readFileSync(file, 'utf8').replace(/\r\n?/g, '\n'); } catch (error) {
        throw new Error('known-drift fixture is unreadable (' + file + '): ' + error.message);
    }
}

main();
