// The served agent-desktop-0.0.2-min.js must be exactly what the MeshCentral build script produces
// from agent-desktop-0.0.2.js, so a source change cannot ship with a stale or hand-edited min file.
const { execFileSync } = require('child_process');
const path = require('path');
const { meshcentralRoot, wrapperFile } = require('./lib/meshcentral_paths');

// The builder lives in the deployment wrapper since Stage 1 and takes uglify-js from deploy/node_modules.
const meshcentral = meshcentralRoot();
try {
    execFileSync(process.execPath, [wrapperFile('scripts/build-viewer-min.js'), '--check'], { cwd: meshcentral, stdio: 'pipe' });
    console.log('PASS viewer min build');
} catch (error) {
    const reason = String(error.stderr || '').split('\n').find(line => line.startsWith('Error')) || error.message;
    console.log('FAIL viewer min build: ' + reason);
    process.exitCode = 1;
}
