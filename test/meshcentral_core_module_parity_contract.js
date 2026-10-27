'use strict';
// MeshCentral sends its agents/modules_meshcore* copies inside the agent core
// via an undated addModule(), which replaces only modules that an agent build
// does not embed or embeds undated (umhctl is never embedded, so every agent
// runs the server copy). Each copy with an agent counterpart must match
// modules/ byte for byte, so those agents run current install/update code.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { forkFile } = require('./lib/meshcentral_paths');

const root = path.resolve(__dirname, '..');
const agents = forkFile('agents');
const read = (file) => fs.readFileSync(file, 'utf8').replace(/\r\n?/g, '\n');
// Deliberate exceptions, each with the reason the server copy must differ.
const retained = {
    // Builds that do not embed clipboard (before 2026-10-07) also lack the
    // MeshClipboardBridgeW export the current module requires. The server copy
    // keeps their in-process clipboard; every newer build embeds a dated copy.
    'clipboard': ',MeshClipboardBridgeW'
};

function main() {
    const compared = [];
    const retainedCopies = [];
    const drifted = [];
    for (const folder of ['modules_meshcore', 'modules_meshcore_min']) {
        const directory = path.join(agents, folder);
        assert(fs.existsSync(directory), 'MeshCentral checkout missing: ' + directory);
        for (const name of fs.readdirSync(directory).filter((entry) => entry.endsWith('.js')).sort()) {
            const module = name.replace(/\.min\.js$/, '.js').replace(/\.js$/, '');
            const source = path.join(root, 'modules', module + '.js');
            if (!fs.existsSync(source)) { continue; }
            const relative = folder + '/' + name;
            const copy = read(path.join(directory, name));
            if (retained[module]) {
                // The exception holds only while the server copy avoids the export.
                if (copy.includes(retained[module])) { drifted.push(relative); }
                retainedCopies.push(relative);
                continue;
            }
            compared.push(relative);
            if (copy !== read(source)) { drifted.push(relative); }
        }
    }
    const checks = {
        // Guards against a vacuous pass if the directory layout changes.
        publishedCopiesFound: compared.length >= 20 && retainedCopies.length === 3,
        everyPublishedCopyMatchesAgentModule: drifted.length === 0
    };
    const failed = Object.keys(checks).filter((name) => !checks[name]);
    process.stdout.write(JSON.stringify({ success: failed.length === 0, compared: compared.length, retained: retainedCopies, drifted, checks }, null, 2) + '\n');
    assert(failed.length === 0, 'MeshCentral core module parity failed: ' + failed.join(', '));
}

main();
