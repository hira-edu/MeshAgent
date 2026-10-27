'use strict';
// G1: every MeshCentral file that replaces an upstream file must equal the upstream
// git tag plus reviewed hunks. The manifest in fixtures/meshcentral-fork-hunks lists
// each file with its tag and state:
//   enforced        the CRLF-normalised diff against the tag must equal the reviewed
//                   diff saved under upstream-base/<path>.diff; any other hunk fails.
//   pending-rebase  the file still starts from an older upstream base. It is reported
//                   as PENDING with its diff counts and the upstream lines it lacks,
//                   until the named stage rebases it and flips it to enforced.
// Every tracked file that also exists at the tag must be listed, either in files or
// in excluded with a reason, so a new override cannot go unchecked.
//
// MeshCentral is read from MESHCENTRAL_ROOT, or the sibling ../MeshCentral checkout.
// Options:
//   --print-diff <path>  print the current normalised diff of one file (to review it and
//                        save it as its fixture); nothing is written
//   --full               print every missing upstream line of pending files
//   --evidence <dir>     write the full report as JSON into <dir>
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const fixtureDir = path.join(__dirname, 'fixtures', 'meshcentral-fork-hunks');
const manifestPath = path.join(fixtureDir, 'upstream-base.json');
const reviewedDiffDir = path.join(fixtureDir, 'upstream-base');
const PENDING_SAMPLE_LINES = 12;

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

// Returns the validated MeshCentral checkout root, or throws with the reason.
function meshcentralRoot() {
    const root = path.resolve(process.env.MESHCENTRAL_ROOT || path.join(__dirname, '..', '..', 'MeshCentral'));
    let stat;
    try { stat = fs.statSync(root); } catch (error) {
        throw new Error('MeshCentral checkout not found at ' + root + ' (set MESHCENTRAL_ROOT): ' + error.message);
    }
    assert(stat.isDirectory(), 'MeshCentral path is not a directory: ' + root);
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

function loadManifest() {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    assert(typeof manifest.defaultUpstreamTag === 'string' && manifest.defaultUpstreamTag, 'upstream-base.json needs defaultUpstreamTag');
    assert(manifest.files && typeof manifest.files === 'object', 'upstream-base.json needs files');
    assert(manifest.excluded && typeof manifest.excluded === 'object', 'upstream-base.json needs excluded');
    for (const [file, entry] of Object.entries(manifest.files)) {
        assert(['enforced', 'pending-rebase'].includes(entry.state), file + ': state must be enforced or pending-rebase');
        assert(typeof entry.reviewed === 'string' && entry.reviewed, file + ': reviewed needs a description of the fork hunks');
        if (entry.state === 'pending-rebase') {
            assert(typeof entry.flipStage === 'string' && entry.flipStage, file + ': pending-rebase needs flipStage');
            assert(typeof entry.forkBase === 'string' && entry.forkBase, file + ': pending-rebase needs forkBase');
        }
    }
    for (const [file, reason] of Object.entries(manifest.excluded)) {
        assert(typeof reason === 'string' && reason, file + ': excluded needs a reason');
        assert(!manifest.files[file], file + ' is both checked and excluded');
    }
    return manifest;
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
    const manifest = loadManifest();
    const printIndex = argv.indexOf('--print-diff');
    if (printIndex >= 0) {
        const file = argv[printIndex + 1];
        assert(file, '--print-diff needs a file path');
        const tag = (manifest.files[file] && manifest.files[file].upstreamTag) || manifest.defaultUpstreamTag;
        verifyTag(root, tag);
        process.stdout.write(normalisedDiff(showAt(root, tag, file), readWorkingFile(root, file), file));
        return;
    }

    const failures = [];
    const report = { meshcentral: root, defaultUpstreamTag: manifest.defaultUpstreamTag, tags: {}, files: {} };
    const tagCommit = (tag) => report.tags[tag] || (report.tags[tag] = verifyTag(root, tag));
    tagCommit(manifest.defaultUpstreamTag);

    // Coverage: every tracked file that the tag also has must be listed.
    const tracked = git(root, ['ls-files', '-z']).stdout.split('\0').filter(Boolean);
    const upstream = new Set(git(root, ['ls-tree', '-r', '-z', '--name-only', manifest.defaultUpstreamTag]).stdout.split('\0').filter(Boolean));
    const overlap = tracked.filter((file) => upstream.has(file)).sort();
    assert(overlap.length > 0, 'No tracked MeshCentral file exists at ' + manifest.defaultUpstreamTag + '; the checkout layout changed');
    for (const file of overlap) {
        if (!manifest.files[file] && !manifest.excluded[file]) { failures.push('unlisted ' + file + ': replaces an upstream file but has no manifest entry'); }
    }
    const trackedSet = new Set(tracked);
    for (const file of Object.keys(manifest.files).concat(Object.keys(manifest.excluded))) {
        if (!trackedSet.has(file)) { failures.push('stale ' + file + ': listed in the manifest but not tracked in MeshCentral'); }
    }

    for (const file of Object.keys(manifest.files).sort()) {
        if (!trackedSet.has(file)) { continue; }
        const entry = manifest.files[file];
        const tag = entry.upstreamTag || manifest.defaultUpstreamTag;
        tagCommit(tag);
        const diff = normalisedDiff(showAt(root, tag, file), readWorkingFile(root, file), file);
        const parsed = parseDiff(diff);
        const result = { state: entry.state, upstreamTag: tag, added: parsed.added.length, removed: parsed.removed.length, hunks: parsed.hunks.length };
        report.files[file] = result;
        const counts = tag + ' +' + result.added + '/-' + result.removed + ', ' + result.hunks + ' hunks';

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
            failures.push('enforced ' + file + ': diff against ' + tag + ' differs from the reviewed hunks');
            console.log('FAIL enforced ' + file + ' (' + counts + '): ' + hunks.unreviewed.length + ' unreviewed hunk(s), ' + hunks.gone.length + ' reviewed hunk(s) no longer present');
            for (const hunk of hunks.unreviewed) { console.log('  unreviewed ' + hunk.header + '\n' + hunk.text.split('\n').map((line) => '    ' + line).join('\n')); }
            for (const hunk of hunks.gone) { console.log('  gone ' + hunk.header); }
            if (!hunks.unreviewed.length && !hunks.gone.length) { console.log('  hunk positions moved; compare with --print-diff ' + file); }
            continue;
        }

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
    for (const file of Object.keys(manifest.excluded).sort()) {
        console.log('EXCLUDED ' + file + ': ' + manifest.excluded[file]);
    }

    const evidenceIndex = argv.indexOf('--evidence');
    if (evidenceIndex >= 0) {
        assert(argv[evidenceIndex + 1], '--evidence needs a directory');
        const dir = path.resolve(argv[evidenceIndex + 1]);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'meshcentral_upstream_base_contract.json'), JSON.stringify(Object.assign(report, { failures }), null, 2));
    }
    const states = Object.values(report.files);
    const summary = states.filter((entry) => entry.state === 'enforced').length + ' enforced, ' +
        states.filter((entry) => entry.state === 'pending-rebase').length + ' pending-rebase, ' + Object.keys(manifest.excluded).length + ' excluded';
    for (const failure of failures) { console.log('FAIL ' + failure); }
    console.log((failures.length ? 'FAIL' : 'PASS') + ' MeshCentral upstream base (' + summary + ', upstream ' + manifest.defaultUpstreamTag + ')');
    if (failures.length) { process.exitCode = 1; }
}

module.exports = { meshcentralRoot, verifyTag, showAt, readWorkingFile, normalise, normalisedDiff, parseDiff, git };

if (require.main === module) {
    main();
}
