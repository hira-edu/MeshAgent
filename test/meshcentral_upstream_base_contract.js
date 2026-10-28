'use strict';
// G1: the MeshCentral fork package must equal stock upstream plus reviewed changes.
// The reference is the npm meshcentral package pinned in test/lib/meshcentral_upstream_reference.json
// (verified by integrity), because since Stage 1 the fork's base is the npm bytes.
//
// Scope: the files the package ships, i.e. tracked files the package.json "files" field packs
// (plus package.json, readme and licence), minus the paths and names excluded in the fixture.
// Every reference file must be covered by that scope or listed as removed, which checks the
// scope definition itself.
//
// Rule, from fixtures/meshcentral-fork-hunks/upstream-base.json:
//   a file byte-equal to the reference needs no entry, and an entry for one fails (stale);
//   a file that differs must be listed as
//     enforced        the CRLF-normalised diff against the reference must equal the reviewed
//                     diff saved under upstream-base/<path>.diff; any other hunk fails;
//     pending-rebase  the file still starts from an older upstream base (forkBase). It is reported
//                     as PENDING with its diff counts and the upstream lines it lacks, until the
//                     named stage rebases it and flips it to enforced;
//     generated       a derived copy (minified or copied from a listed source). Its content is
//                     governed by test/meshcentral_generated_assets_contract.js, which must list it;
//   a file absent from the reference must be listed as fork-only;
//   a reference file the fork does not ship must be listed under removed;
//   anything unlisted fails.
//
// MeshCentral is located by test/lib/meshcentral_paths.js (MESHCENTRAL_ROOT, or the sibling
// ../MeshCentral checkout). Stage 1 layout only: the old wrapper layout had no package tree.
// Options:
//   --print-diff <path>  print the current normalised diff of one file against the reference (to
//                        review it and save it as its fixture); nothing is written
//   --full               print every missing upstream line of pending files
//   --evidence <dir>     write the full report as JSON into <dir>
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const meshcentralPaths = require('./lib/meshcentral_paths');

const fixtureDir = path.join(__dirname, 'fixtures', 'meshcentral-fork-hunks');
const manifestPath = path.join(fixtureDir, 'upstream-base.json');
const generatedManifestPath = path.join(fixtureDir, 'generated-assets.json');
const reviewedDiffDir = path.join(fixtureDir, 'upstream-base');
const PENDING_SAMPLE_LINES = 12;
const STATES = ['enforced', 'pending-rebase', 'generated', 'fork-only'];

const normalise = (text) => text.replace(/\r\n?/g, '\n');
const samePath = (a, b) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;

function git(root, args, allowedStatus) {
    // core.autocrlf=false keeps blobs byte-exact; normalisation happens here, not in git.
    const result = spawnSync('git', ['-C', root, '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false', ...args], { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024, windowsHide: true });
    if (result.error) { throw new Error('git ' + args.join(' ') + ' could not run: ' + result.error.message); }
    if (!(allowedStatus || [0]).includes(result.status)) {
        throw new Error('git ' + args.join(' ') + ' failed (exit ' + result.status + '): ' + String(result.stderr).trim());
    }
    return result;
}

// Returns the MeshCentral checkout root from the shared helper, which must also be the git top
// level, or throws with the reason.
function meshcentralRoot() {
    const root = meshcentralPaths.meshcentralRoot();
    const top = path.resolve(git(root, ['rev-parse', '--show-toplevel']).stdout.trim());
    assert(samePath(top, root), 'MeshCentral path ' + root + ' is not a git checkout root (git reports ' + top + ')');
    return root;
}

// Proves the tag exists and is the upstream MeshCentral release of that version.
function verifyTag(root, tag) {
    const resolved = spawnSync('git', ['-C', root, 'rev-parse', '--verify', '--quiet', 'refs/tags/' + tag + '^{commit}'], { encoding: 'utf8', windowsHide: true });
    if (resolved.error) { throw new Error('git rev-parse could not run: ' + resolved.error.message); }
    assert(resolved.status === 0, 'Upstream tag ' + tag + ' is missing from ' + root + ' (fetch the upstream tags)');
    const pkg = JSON.parse(showAt(root, tag, 'package.json'));
    assert(pkg.name === 'meshcentral' && pkg.version === tag, 'Tag ' + tag + ' in ' + root + ' is not upstream MeshCentral ' + tag + ' (package.json is ' + pkg.name + '@' + pkg.version + ')');
    return resolved.stdout.trim();
}

function showAt(root, rev, file) {
    return normalise(git(root, ['show', rev + ':' + file]).stdout);
}

function readWorkingFile(root, file) {
    return normalise(fs.readFileSync(path.join(root, file), 'utf8'));
}

// Unified diff of two normalised texts, with stable headers and no git-config or
// diff-driver influence: fixed prefixes, myers, 3 lines of context, and hunk headers
// reduced to their line ranges. Returns '' when the texts are equal.
function normalisedDiff(before, after, label) {
    if (before === after) { return ''; }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshcentral-diff-'));
    try {
        fs.writeFileSync(path.join(dir, 'a'), before);
        fs.writeFileSync(path.join(dir, 'b'), after);
        const result = git(dir, ['diff', '--no-index', '--no-color', '--no-ext-diff', '--no-textconv', '--diff-algorithm=myers', '--indent-heuristic', '--inter-hunk-context=0', '-U3', 'a', 'b'], [1]);
        const lines = normalise(result.stdout).split('\n');
        const first = lines.findIndex((line) => line.startsWith('@@'));
        assert(first > 0, 'git diff produced no hunks for ' + label);
        const body = lines.slice(first).map((line) => line.startsWith('@@') ? line.replace(/^(@@ [^@]+ @@).*$/, '$1') : line);
        return ['--- a/' + label, '+++ b/' + label].concat(body).join('\n').replace(/\n*$/, '\n');
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

function parseDiff(diff) {
    const added = [];
    const removed = [];
    const hunks = [];
    for (const line of diff.split('\n')) {
        if (line.startsWith('--- a/') || line.startsWith('+++ b/')) { continue; }
        if (line.startsWith('@@')) { hunks.push({ header: line, body: [] }); continue; }
        if (!hunks.length) { continue; }
        hunks[hunks.length - 1].body.push(line);
        if (line.startsWith('+')) { added.push(line.slice(1)); } else if (line.startsWith('-')) { removed.push(line.slice(1)); }
    }
    return { added, removed, hunks: hunks.map((hunk) => ({ header: hunk.header, text: hunk.body.join('\n') })) };
}

// Lines upstream added between the fork's base and the tag that the fork still lacks.
function missingUpstreamChanges(root, tag, forkBase, file, removedFromTag) {
    const upstreamAdded = parseDiff(normalisedDiff(showAt(root, forkBase, file), showAt(root, tag, file), file)).added;
    const pool = new Map();
    for (const line of removedFromTag) { pool.set(line, (pool.get(line) || 0) + 1); }
    const missing = [];
    for (const line of upstreamAdded) {
        const count = pool.get(line) || 0;
        if (count > 0 && line.trim() !== '') { missing.push(line); pool.set(line, count - 1); }
    }
    return { upstreamAdded: upstreamAdded.length, missing };
}

// "dir/**" matches everything under dir; any other pattern is one exact path.
function pathPatternMatches(pattern, file) {
    return pattern.endsWith('/**') ? file.startsWith(pattern.slice(0, -2)) : file === pattern;
}

function loadManifest() {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    assert(typeof manifest.defaultUpstreamTag === 'string' && manifest.defaultUpstreamTag, 'upstream-base.json needs defaultUpstreamTag');
    for (const key of ['files', 'excluded', 'excludedPaths', 'removed']) {
        assert(manifest[key] && typeof manifest[key] === 'object', 'upstream-base.json needs ' + key);
    }
    for (const [file, entry] of Object.entries(manifest.files)) {
        assert(STATES.includes(entry.state), file + ': state must be one of ' + STATES.join(', '));
        assert(typeof entry.reviewed === 'string' && entry.reviewed, file + ': reviewed needs a description of the fork change');
        if (entry.state === 'pending-rebase') {
            assert(typeof entry.flipStage === 'string' && entry.flipStage, file + ': pending-rebase needs flipStage');
            assert(typeof entry.forkBase === 'string' && entry.forkBase, file + ': pending-rebase needs forkBase');
        }
        if (entry.state === 'generated') {
            assert(typeof entry.source === 'string' && entry.source, file + ': generated needs source');
        }
    }
    for (const section of ['excluded', 'excludedPaths', 'removed']) {
        for (const [file, reason] of Object.entries(manifest[section])) {
            assert(typeof reason === 'string' && reason, file + ': ' + section + ' needs a reason');
            assert(!manifest.files[file], file + ' is both listed in files and in ' + section);
        }
    }
    return manifest;
}

// The package.json "files" field as npm applies it here: "*.js" matches top-level .js files, any
// other entry is a top-level file or folder. npm always adds package.json, readme* and licen[cs]e*.
function packageMatcher(root) {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    assert(pkg.name === 'meshcentral', root + '/package.json is ' + JSON.stringify(pkg.name) + ', not the meshcentral package (Stage 1 layout needed)');
    assert(Array.isArray(pkg.files) && pkg.files.length, root + '/package.json has no files list');
    for (const entry of pkg.files) {
        assert(entry === '*.js' || /^[^*?/[\]!]+$/.test(entry), 'package.json files entry ' + JSON.stringify(entry) + ' is not a form this contract understands');
    }
    return (file) => {
        if (/^(package\.json|readme[^/]*|licen[cs]e[^/]*)$/i.test(file)) { return true; }
        const top = file.split('/')[0];
        return pkg.files.some((entry) => entry === '*.js' ? (!file.includes('/') && file.endsWith('.js')) : (file === entry || top === entry));
    };
}

function listTree(dir) {
    const files = [];
    const stack = [dir];
    while (stack.length) {
        const current = stack.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const full = path.join(current, entry.name);
            if (entry.isDirectory()) { stack.push(full); } else { files.push(path.relative(dir, full).split(path.sep).join('/')); }
        }
    }
    return files;
}

function hunkReport(expected, actual) {
    const expectedHunks = parseDiff(expected).hunks;
    const actualHunks = parseDiff(actual).hunks;
    const expectedTexts = new Set(expectedHunks.map((hunk) => hunk.text));
    const actualTexts = new Set(actualHunks.map((hunk) => hunk.text));
    return {
        unreviewed: actualHunks.filter((hunk) => !expectedTexts.has(hunk.text)),
        gone: expectedHunks.filter((hunk) => !actualTexts.has(hunk.text))
    };
}

function main() {
    const argv = process.argv.slice(2);
    const root = meshcentralRoot();
    const reference = meshcentralPaths.upstreamPackageDir();
    const pin = meshcentralPaths.loadReferencePin();
    const manifest = loadManifest();
    const referenceText = (file) => normalise(fs.readFileSync(path.join(reference, file), 'utf8'));
    const printIndex = argv.indexOf('--print-diff');
    if (printIndex >= 0) {
        const file = argv[printIndex + 1];
        assert(file, '--print-diff needs a file path');
        process.stdout.write(normalisedDiff(referenceText(file), readWorkingFile(root, file), file));
        return;
    }

    const failures = [];
    const report = { meshcentral: root, reference: { dir: reference, pin: pin.name + '@' + pin.version, integrity: pin.integrity }, tags: {}, files: {}, counts: {} };
    const tagCommit = (tag) => report.tags[tag] || (report.tags[tag] = verifyTag(root, tag));

    // Scope: tracked files the package ships, minus the fixture's exclusions.
    const tracked = git(root, ['ls-files', '-z']).stdout.split('\0').filter(Boolean);
    const trackedSet = new Set(tracked);
    for (const pattern of Object.keys(manifest.excludedPaths)) {
        if (!tracked.some((file) => pathPatternMatches(pattern, file))) { failures.push('stale excludedPaths ' + pattern + ': matches no tracked file'); }
    }
    for (const file of Object.keys(manifest.excluded)) {
        if (!trackedSet.has(file)) { failures.push('stale excluded ' + file + ': not tracked in MeshCentral'); }
    }
    const inPackage = packageMatcher(root);
    const pathExcluded = (file) => Object.keys(manifest.excludedPaths).some((pattern) => pathPatternMatches(pattern, file));
    const scope = tracked.filter((file) => !pathExcluded(file) && !manifest.excluded[file] && inPackage(file)).sort();
    const scopeSet = new Set(scope);
    const referenceFiles = listTree(reference).sort();
    const referenceSet = new Set(referenceFiles);
    assert(scope.length > 0, 'No tracked MeshCentral file is in the package tree; the checkout layout changed');
    report.counts = { tracked: tracked.length, scope: scope.length, reference: referenceFiles.length,
        outsidePackage: tracked.filter((file) => !pathExcluded(file) && !manifest.excluded[file] && !inPackage(file)).length };

    // Every reference file is shipped by the fork, excluded by name, or listed as removed.
    for (const file of referenceFiles) {
        if (scopeSet.has(file) || manifest.excluded[file]) { continue; }
        if (!manifest.removed[file]) { failures.push('unlisted removal ' + file + ': in the upstream package but not shipped by the fork; list it under removed'); }
    }
    for (const file of Object.keys(manifest.removed)) {
        if (!referenceSet.has(file)) { failures.push('stale removed ' + file + ': not in the upstream package'); }
        else if (scopeSet.has(file)) { failures.push('stale removed ' + file + ': the fork ships it again'); }
    }
    for (const file of Object.keys(manifest.files)) {
        if (!scopeSet.has(file)) { failures.push('stale ' + file + ': listed but not a tracked file of the package tree'); }
    }

    let equal = 0;
    const equalFiles = new Set();
    for (const file of scope) {
        const entry = manifest.files[file];
        if (!referenceSet.has(file)) {
            if (!entry) { failures.push('unlisted ' + file + ': not in the upstream package; list it as fork-only'); }
            else if (entry.state !== 'fork-only') { failures.push(file + ': not in the upstream package, so its state must be fork-only, not ' + entry.state); }
            continue;
        }
        if (fs.readFileSync(path.join(root, file)).equals(fs.readFileSync(path.join(reference, file)))) {
            equal++;
            equalFiles.add(file);
            if (entry) { failures.push('stale ' + file + ': byte-equal to the upstream package; remove its entry'); }
            continue;
        }
        if (!entry) { failures.push('unlisted ' + file + ': differs from the upstream package but has no manifest entry'); continue; }
        if (entry.state === 'fork-only') { failures.push(file + ': is in the upstream package, so it cannot be fork-only'); }
    }
    report.counts.equal = equal;

    let generatedFiles = null;
    for (const file of Object.keys(manifest.files).sort()) {
        if (!scopeSet.has(file) || equalFiles.has(file)) { continue; }
        const entry = manifest.files[file];
        if (entry.state === 'fork-only') {
            report.files[file] = { state: entry.state };
            continue;
        }
        if (!referenceSet.has(file)) { continue; }
        if (entry.state === 'generated') {
            generatedFiles = generatedFiles || JSON.parse(fs.readFileSync(generatedManifestPath, 'utf8')).files;
            report.files[file] = { state: entry.state, source: entry.source };
            if (!generatedFiles[file]) { failures.push('generated ' + file + ': not listed in generated-assets.json, which governs its content'); }
            else if (generatedFiles[file].source !== entry.source) { failures.push('generated ' + file + ': source ' + entry.source + ' differs from generated-assets.json (' + generatedFiles[file].source + ')'); }
            if (!manifest.files[entry.source] && !scopeSet.has(entry.source)) { failures.push('generated ' + file + ': source ' + entry.source + ' is not a file of the package tree'); }
            console.log('GENERATED ' + file + ' (from ' + entry.source + '; content checked by meshcentral_generated_assets_contract)');
            continue;
        }
        const diff = normalisedDiff(referenceText(file), readWorkingFile(root, file), file);
        const parsed = parseDiff(diff);
        const result = { state: entry.state, added: parsed.added.length, removed: parsed.removed.length, hunks: parsed.hunks.length };
        report.files[file] = result;
        const counts = pin.version + ' +' + result.added + '/-' + result.removed + ', ' + result.hunks + ' hunks';

        if (entry.state === 'enforced') {
            const expectedPath = path.join(reviewedDiffDir, file + '.diff');
            let expected;
            try { expected = normalise(fs.readFileSync(expectedPath, 'utf8')); } catch (error) {
                throw new Error(file + ': reviewed diff fixture is unreadable (' + expectedPath + '): ' + error.message);
            }
            if (expected === diff) {
                console.log('PASS enforced ' + file + ' (' + counts + ' reviewed)');
                continue;
            }
            const hunks = hunkReport(expected, diff);
            result.unreviewed = hunks.unreviewed;
            result.reviewedHunksGone = hunks.gone;
            failures.push('enforced ' + file + ': diff against the upstream package differs from the reviewed hunks');
            console.log('FAIL enforced ' + file + ' (' + counts + '): ' + hunks.unreviewed.length + ' unreviewed hunk(s), ' + hunks.gone.length + ' reviewed hunk(s) no longer present');
            for (const hunk of hunks.unreviewed) { console.log('  unreviewed ' + hunk.header + '\n' + hunk.text.split('\n').map((line) => '    ' + line).join('\n')); }
            for (const hunk of hunks.gone) { console.log('  gone ' + hunk.header); }
            if (!hunks.unreviewed.length && !hunks.gone.length) { console.log('  hunk positions moved; compare with --print-diff ' + file); }
            continue;
        }

        // pending-rebase: which upstream changes between forkBase and the tag are still missing.
        const tag = entry.upstreamTag || manifest.defaultUpstreamTag;
        tagCommit(tag);
        const missing = missingUpstreamChanges(root, tag, entry.forkBase, file, parsed.removed);
        result.flipStage = entry.flipStage;
        result.forkBase = entry.forkBase;
        result.missingFromUpstream = parsed.removed;
        result.upstreamChangesMissing = missing.missing;
        console.log('PENDING ' + file + ' (' + counts + '; flips at ' + entry.flipStage + '): ' + parsed.removed.length + ' upstream line(s) missing, ' +
            missing.missing.length + ' of ' + missing.upstreamAdded + ' upstream addition(s) ' + entry.forkBase + '..' + tag + ' absent');
        // The sample skips short lines such as '}' or 'break;'; --full and --evidence list every line.
        const shown = argv.includes('--full') ? missing.missing : missing.missing.filter((line) => line.trim().length >= 16).slice(0, PENDING_SAMPLE_LINES);
        for (const line of shown) { console.log('  missing upstream: ' + line.trim().slice(0, 160)); }
        if (shown.length < missing.missing.length) { console.log('  ... ' + (missing.missing.length - shown.length) + ' more (--full or --evidence for all)'); }
    }
    for (const file of Object.keys(manifest.excluded).sort()) { console.log('EXCLUDED ' + file + ': ' + manifest.excluded[file]); }
    for (const pattern of Object.keys(manifest.excludedPaths).sort()) { console.log('EXCLUDED ' + pattern + ': ' + manifest.excludedPaths[pattern]); }
    for (const file of Object.keys(manifest.removed).sort()) { console.log('REMOVED ' + file + ': ' + manifest.removed[file]); }

    const evidenceIndex = argv.indexOf('--evidence');
    if (evidenceIndex >= 0) {
        assert(argv[evidenceIndex + 1], '--evidence needs a directory');
        const dir = path.resolve(argv[evidenceIndex + 1]);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'meshcentral_upstream_base_contract.json'), JSON.stringify(Object.assign(report, { failures }), null, 2));
    }
    const states = Object.values(manifest.files).map((entry) => entry.state);
    const count = (state) => states.filter((value) => value === state).length;
    const summary = report.counts.scope + ' package files: ' + equal + ' equal, ' + count('enforced') + ' enforced, ' + count('pending-rebase') + ' pending-rebase, ' +
        count('generated') + ' generated, ' + count('fork-only') + ' fork-only, ' + Object.keys(manifest.removed).length + ' removed, ' +
        Object.keys(manifest.excluded).length + ' excluded by name, ' + Object.keys(manifest.excludedPaths).length + ' excluded paths; reference ' + pin.name + '@' + pin.version;
    for (const failure of failures) { console.log('FAIL ' + failure); }
    console.log((failures.length ? 'FAIL' : 'PASS') + ' MeshCentral upstream base (' + summary + ')');
    if (failures.length) { process.exitCode = 1; }
}

module.exports = { meshcentralRoot, verifyTag, showAt, readWorkingFile, normalise, normalisedDiff, parseDiff, git };

if (require.main === module) {
    main();
}
