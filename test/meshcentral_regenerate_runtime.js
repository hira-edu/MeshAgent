'use strict';
// Behaviour of MeshCentral's generator entry point, deploy/scripts/regenerate.js, that a --check run
// cannot show:
//   DEP-4  no pending-skip switches remain (--allow-pending, --no-delete); a stale file always fails.
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

for (const line of results) { console.log(line); }
const failed = results.filter((line) => line.startsWith('FAIL')).length;
console.log((failed ? 'FAIL' : 'PASS') + ' regenerate.js runtime (' + (results.length - failed) + '/' + results.length + ')');
if (failed) { process.exitCode = 1; }
