'use strict';
// Module policy for the agent core modules the MeshCentral fork package serves (D22, G7).
//
// MeshCentral sends every file in agents/modules_meshcore (or modules_meshcore_min when minifycore
// is on) inside the agent core as addModule(name, source, releaseDate). An agent replaces its own
// copy of a module when the server's date is newer, so the package decides which code agents run.
// Every package module file falls in exactly one class:
//   - MeshAgent-owned (D22): modules both projects carry, shipped as MeshAgent's own copy. The
//     package bytes equal MeshAgent's modules/<name>.js as git stores it (LF), byte for byte. This
//     holds in modules_meshcore_min too: with minifycore on, MeshCentral serves that folder instead.
//   - fork: modules upstream does not ship, or that the fork replaces. They equal MeshAgent's
//     modules/<name>.js apart from line endings (the package keeps production's CRLF bytes), except
//     the retained copies below.
//   - upstream: everything else equals the pinned upstream package (test/lib/meshcentral_upstream_
//     reference.json) byte for byte, and every upstream module is present.
// A file that fits none of these is unknown and fails.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { forkFile, upstreamPackageDir } = require('./lib/meshcentral_paths');

const root = path.resolve(__dirname, '..');
const FOLDERS = ['modules_meshcore', 'modules_meshcore_min'];

// D22: the modules MeshAgent and upstream both carry, which the package ships as MeshAgent's copy.
const MESHAGENT_OWNED = [
    'amt-lme', 'amt-mei', 'monitor-border', 'smbios', 'util-agentlog', 'wifi-scanner',
    'wifi-scanner-windows', 'win-console', 'win-deskutils', 'win-securitycenter', 'win-volumes'
];
// Upstream ships these, and the fork replaces them with MeshAgent's copy.
const FORK_REPLACES_UPSTREAM = ['win-terminal', 'win-virtual-terminal'];
// Deliberate exceptions, each with the reason the server copy must differ from modules/.
const retained = {
    // Builds that do not embed clipboard (before 2026-10-07) also lack the
    // MeshClipboardBridgeW export the current module requires. The server copy
    // keeps their in-process clipboard.
    'clipboard': ',MeshClipboardBridgeW'
};

const lf = (buffer) => buffer.toString('latin1').replace(/\r\n?/g, '\n');
const moduleName = (file) => file.replace(/\.min\.js$/, '.js').replace(/\.(js|json)$/, '');
const listModules = (directory) => fs.readdirSync(directory).filter((entry) => /\.(js|json)$/.test(entry)).sort();

function main() {
    const agents = forkFile('agents');
    const upstreamAgents = path.join(upstreamPackageDir(), 'agents');
    const result = { owned: [], fork: [], retained: [], upstream: [], drifted: [], minifiedDrifted: [], unknown: [], missingUpstream: [], missingOwned: [] };

    for (const folder of FOLDERS) {
        const directory = path.join(agents, folder);
        const upstreamDirectory = path.join(upstreamAgents, folder);
        assert(fs.statSync(directory).isDirectory(), 'MeshCentral package folder missing: ' + directory);
        assert(fs.statSync(upstreamDirectory).isDirectory(), 'upstream reference folder missing: ' + upstreamDirectory);
        const names = listModules(directory);
        for (const name of listModules(upstreamDirectory)) {
            if (!names.includes(name)) { result.missingUpstream.push(folder + '/' + name); }
        }
        for (const name of names) {
            const relative = folder + '/' + name;
            const module = moduleName(name);
            const bytes = fs.readFileSync(path.join(directory, name));
            const source = path.join(root, 'modules', module + '.js');
            const hasSource = fs.existsSync(source);
            const upstreamFile = path.join(upstreamDirectory, name);
            const inUpstream = fs.existsSync(upstreamFile);
            if (MESHAGENT_OWNED.includes(module)) {
                result.owned.push(relative);
                if (!hasSource || !bytes.equals(Buffer.from(lf(fs.readFileSync(source)), 'latin1'))) {
                    (folder === 'modules_meshcore' ? result.drifted : result.minifiedDrifted).push(relative + ' (MeshAgent-owned: must equal modules/' + module + '.js)');
                }
            } else if (!inUpstream || FORK_REPLACES_UPSTREAM.includes(module)) {
                if (!hasSource) { result.unknown.push(relative); continue; }
                if (retained[module]) {
                    // The exception holds only while the server copy avoids the export.
                    result.retained.push(relative);
                    if (lf(bytes).includes(retained[module])) { result.drifted.push(relative + ' (retained copy uses ' + retained[module] + ')'); }
                    continue;
                }
                result.fork.push(relative);
                if (lf(bytes) !== lf(fs.readFileSync(source))) { result.drifted.push(relative + ' (fork: must equal modules/' + module + '.js)'); }
            } else {
                result.upstream.push(relative);
                if (!bytes.equals(fs.readFileSync(upstreamFile))) { result.drifted.push(relative + ' (must equal upstream)'); }
            }
        }
    }
    for (const module of MESHAGENT_OWNED) {
        if (!result.owned.includes('modules_meshcore/' + module + '.js')) { result.missingOwned.push('modules_meshcore/' + module + '.js'); }
    }

    const checks = {
        // Guards against a vacuous pass if the layout changes.
        everyClassPopulated: result.owned.length >= MESHAGENT_OWNED.length && result.fork.length >= 20 && result.retained.length === 3 && result.upstream.length >= 15,
        everyMeshAgentOwnedModulePresent: result.missingOwned.length === 0,
        everyUpstreamModulePresent: result.missingUpstream.length === 0,
        noUnknownModule: result.unknown.length === 0,
        everyCopyMatchesItsSource: result.drifted.length === 0,
        // Reported on its own: the minified folder is served only with minifycore on (production has it off).
        everyMinifiedOwnedCopyMatchesModules: result.minifiedDrifted.length === 0
    };
    const failed = Object.keys(checks).filter((name) => !checks[name]);
    const counts = { owned: result.owned.length, fork: result.fork.length, upstream: result.upstream.length };
    process.stdout.write(JSON.stringify({ success: failed.length === 0, counts, retained: result.retained, drifted: result.drifted, minifiedDrifted: result.minifiedDrifted,
        unknown: result.unknown, missingUpstream: result.missingUpstream, missingOwned: result.missingOwned, checks }, null, 2) + '\n');
    assert(failed.length === 0, 'MeshCentral core module policy failed: ' + failed.join(', '));
}

main();
