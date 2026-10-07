#!/usr/bin/env python3
"""Verify that a pending setTimeout fires even when the caller drops the returned object.

The embedded runtime collects unreferenced objects, and a collected timer object used to
remove its timer, so `setTimeout(fn, ms)` without keeping the result could silently never
fire. This happened reliably for timeouts created in setImmediate callbacks and promise
handlers. Runs the built agent on a small script; no network, service or desktop access.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, required=True)
args = parser.parse_args()

script = r'''
var fired = [], keep = [];
function note(name) { return function () { fired.push(name); }; }
setImmediate(function () {
    setTimeout(note('immediate-unreferenced'), 50);
    keep.push(setTimeout(note('immediate-referenced'), 50));
});
new (require('promise'))(function (res) { res(1); }).then(function () {
    setTimeout(note('then-unreferenced'), 50);
    var cancelled = setTimeout(note('then-cleared'), 50);
    clearTimeout(cancelled);
});
setTimeout(function () { setTimeout(note('timeout-in-timeout'), 50); }, 10);
setTimeout(note('top-level-unreferenced'), 50);
var ticks = 0, iv = setInterval(function () { if (++ticks == 2) { clearInterval(iv); fired.push('interval-twice'); } }, 50);
setTimeout(function () { console.log('FIRED ' + JSON.stringify(fired.sort())); process.exit(0); }, 4000);
'''
expected = ['immediate-referenced', 'immediate-unreferenced', 'interval-twice', 'then-unreferenced',
            'timeout-in-timeout', 'top-level-unreferenced']

with tempfile.TemporaryDirectory(prefix='mesh-timers-') as directory:
    probe = Path(directory) / 'timers.js'
    probe.write_text(script)
    result = subprocess.run([str(args.agent.resolve()), str(probe)], cwd=directory, capture_output=True, text=True, timeout=30)
    line = next((l for l in result.stdout.splitlines() if l.startswith('FIRED ')), None)
    assert result.returncode == 0 and line is not None, result
    import json
    fired = json.loads(line[len('FIRED '):])
    assert fired == sorted(expected), fired
print('PASS: unreferenced timeouts fire from immediates, promise handlers, timers and top level; cleared timeouts do not; intervals unchanged')
