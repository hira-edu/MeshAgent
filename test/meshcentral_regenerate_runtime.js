'use strict';
// Behaviour of MeshCentral's generator entry point, deploy/scripts/regenerate.js, that a --check run
// cannot show:
//   DEP-4  no pending-skip switches remain (--allow-pending, --no-delete); a stale file always fails.
//   DEP-5  when a write fails, apply() restores every original; a restore that fails too is reported
//          with each path named, and the backup that still holds the original is kept.
// regenerate.js runs main() only as a script, so requiring it here generates nothing.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { wrapperFile } = require('./lib/meshcentral_paths');

const regeneratePath = wrapperFile('scripts/regenerate.js');
const source = fs.readFileSync(regeneratePath, 'utf8');
assert(/if \(require\.main === module\)/.test(source), 'regenerate.js must run main() only when it is the script, so its functions can be tested');
const regenerate = require(regeneratePath);
for (const name of ['parseArgs', 'apply', 'RegenerateError']) { assert.strictEqual(typeof regenerate[name], 'function', 'regenerate.js must export ' + name); }

const results = [];
function check(name, fn) {
    try { fn(); results.push('PASS ' + name); } catch (error) { results.push('FAIL ' + name + ': ' + error.message); }
}

check('DEP-4: the pending-skip switches are gone', () => {
    for (const argv of [['--allow-pending', 'ja-jp'], ['--allow-pending=ja-jp'], ['--no-delete']]) {
        assert.throws(() => regenerate.parseArgs(argv), (error) => error instanceof regenerate.RegenerateError && /unknown argument/.test(error.message), argv.join(' ') + ' must be rejected');
    }
    assert(!/PENDING|ja-jp|allowPending|noDelete/.test(source), 'regenerate.js still carries the pending mechanism or the ja-jp entry');
    const options = regenerate.parseArgs(['--check', '--only', 'viewer']);
    assert.deepStrictEqual(options.categories, ['viewer']);
});

// One category with three files: a.txt is rewritten, gone.txt is deleted, and the write of
// sub/c.txt fails because sub is a file. Both earlier changes must be undone.
function applyFixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'regen-apply-'));
    fs.writeFileSync(path.join(root, 'a.txt'), 'original a');
    fs.writeFileSync(path.join(root, 'gone.txt'), 'original gone');
    fs.writeFileSync(path.join(root, 'sub'), 'a file where a directory is needed');
    const generated = new Map([['a.txt', Buffer.from('new a')], ['sub/c.txt', Buffer.from('new c')]]);
    const results = { views: { generated, committed: ['a.txt', 'gone.txt'] } };
    const report = { views: { files: { 'a.txt': 'differ', 'gone.txt': 'missing', 'sub/c.txt': 'extra' } } };
    return { root, results, report };
}

check('DEP-5: a failed write restores every original', () => {
    const f = applyFixture();
    try {
        assert.throws(() => regenerate.apply(f.results, f.report, f.root), (error) => error instanceof regenerate.RegenerateError && /every file restored/.test(error.message));
        assert.strictEqual(fs.readFileSync(path.join(f.root, 'a.txt'), 'utf8'), 'original a');
        assert.strictEqual(fs.readFileSync(path.join(f.root, 'gone.txt'), 'utf8'), 'original gone');
        assert(!fs.existsSync(path.join(f.root, 'a.txt.regen-tmp')), 'temporary file left behind');
    } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

check('DEP-5: a failed restore is reported by path and its backup is kept', () => {
    const f = applyFixture();
    const copy = fs.copyFileSync;
    let backupDir = null;
    // The restore of a.txt (a copy out of the backup directory onto a.txt) fails.
    fs.copyFileSync = function (from, to) {
        if (path.resolve(to) === path.join(f.root, 'a.txt') && path.basename(path.dirname(from)).startsWith('meshcentral-regen-backup-')) {
            backupDir = path.dirname(from);
            throw new Error('simulated restore failure');
        }
        return copy.apply(this, arguments);
    };
    try {
        let message = '';
        assert.throws(() => regenerate.apply(f.results, f.report, f.root), (error) => { message = error.message; return error instanceof regenerate.RegenerateError; });
        assert(!/every file restored/.test(message), 'a failed restore must not be reported as success: ' + message);
        assert(message.includes(path.join(f.root, 'a.txt')), 'the message must name the path that was not restored: ' + message);
        assert(backupDir && message.includes(backupDir), 'the message must name the kept backup: ' + message);
        assert(fs.existsSync(backupDir), 'the backup holding the unrestored original must be kept');
        assert.strictEqual(fs.readFileSync(path.join(f.root, 'gone.txt'), 'utf8'), 'original gone', 'the other files are still restored');
    } finally {
        fs.copyFileSync = copy;
        fs.rmSync(f.root, { recursive: true, force: true });
        if (backupDir) { fs.rmSync(backupDir, { recursive: true, force: true }); }
    }
});

for (const line of results) { console.log(line); }
const failed = results.filter((line) => line.startsWith('FAIL')).length;
console.log((failed ? 'FAIL' : 'PASS') + ' regenerate.js runtime (' + (results.length - failed) + '/' + results.length + ')');
if (failed) { process.exitCode = 1; }
