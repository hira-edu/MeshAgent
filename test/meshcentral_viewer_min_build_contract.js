// The served viewer -min files (agent-desktop-0.0.2-min.js and agent-redir-ws-0.1.1-min.js) must be
// exactly what MeshCentral's single generator, deploy/scripts/regenerate.js (viewer category, pinned
// toolchain in deploy/node_modules), produces from their sources, so a source change cannot ship with
// a stale or hand-edited min file.
const { spawnSync } = require('child_process');
const fs = require('fs');
const { meshcentralRoot, wrapperFile } = require('./lib/meshcentral_paths');

const meshcentral = meshcentralRoot();
const failures = [];
// regenerate.js is the one entry point; a second viewer builder would drift from it.
if (fs.existsSync(wrapperFile('scripts/build-viewer-min.js'))) { failures.push('deploy/scripts/build-viewer-min.js still exists; regenerate.js --only viewer is the only viewer builder'); }
const result = spawnSync(process.execPath, [wrapperFile('scripts/regenerate.js'), '--check', '--only', 'viewer'], { cwd: meshcentral, encoding: 'utf8', windowsHide: true });
if (result.error) { failures.push('regenerate.js could not run: ' + result.error.message); }
else if (result.status !== 0) {
    const lines = (String(result.stdout) + String(result.stderr)).split(/\r?\n/).filter((line) => /^\s+(differ|missing|extra)\s|^regenerate/.test(line));
    failures.push('regenerate.js --check --only viewer exited ' + result.status + ': ' + lines.join(' | '));
} else if (!/^viewer\s+match\s+2\s+differ\s+0\s+missing\s+0\s+extra\s+0/m.test(String(result.stdout))) {
    failures.push('regenerate.js --check --only viewer did not report both viewer files matching: ' + String(result.stdout).trim());
}
if (failures.length) {
    for (const failure of failures) { console.log('FAIL viewer min build: ' + failure); }
    process.exitCode = 1;
} else {
    console.log('PASS viewer min build (regenerate.js --check --only viewer: both viewer -min files match)');
}
